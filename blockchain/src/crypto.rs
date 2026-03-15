// =============================================================================
// crypto.rs — Post-Quantum Cryptographic Primitives
// =============================================================================
//
// This is the security foundation of the entire blockchain. Every operation
// that requires trust — owning coins, authorizing transactions, linking blocks
// together — ultimately depends on the functions in this file.
//
// WHAT THIS FILE PROVIDES:
//   1. SHA-256 hashing    — produces a unique fixed-length fingerprint of any
//                           data. Used for block hashing, mining (proof of work),
//                           Merkle trees, and deriving wallet addresses.
//
//   2. Wallet key pairs   — every user has a private key (secret, never shared)
//                           and a public key (freely shareable). The public key
//                           is hashed to produce a compact wallet address.
//
//   3. Signing            — proves you authorized a transaction without revealing
//                           your private key. Only the holder of the private key
//                           can produce a valid signature.
//
//   4. Verification       — lets anyone confirm a signature is genuine using only
//                           the signer's public key. No trusted third party needed.
//
// WHY POST-QUANTUM (DILITHIUM3)?
//   Classical ECDSA (secp256k1, used by Bitcoin) relies on the elliptic curve
//   discrete logarithm problem. A quantum computer running Shor's Algorithm
//   could solve this in polynomial time, meaning it could derive any private key
//   from its public key — completely breaking wallet security.
//
//   CRYSTALS-Dilithium3 is based on the Module Learning With Errors (MLWE)
//   lattice problem. No known quantum algorithm solves lattice problems
//   significantly faster than classical computers, making Dilithium resistant
//   to both current and future quantum attacks. It was standardized by NIST
//   in 2024 as FIPS 204.
//
// SIZE COST OF QUANTUM RESISTANCE:
//   ┌─────────────┬──────────────┬────────────────┐
//   │             │ ECDSA        │ Dilithium3     │
//   ├─────────────┼──────────────┼────────────────┤
//   │ Public key  │ 33 bytes     │ 1,952 bytes    │
//   │ Private key │ 32 bytes     │ 4,000 bytes    │
//   │ Signature   │ 64 bytes     │ 3,293 bytes    │
//   └─────────────┴──────────────┴────────────────┘
//   Transactions and wallet files are larger as a result.
//   This is the accepted tradeoff for quantum resistance today.
//
// NOTE ON SHA-256:
//   SHA-256 (used for hashing/mining) is NOT replaced. Grover's Algorithm
//   gives quantum computers only a quadratic speedup against hash functions,
//   halving the effective security level to 128 bits — still secure.
// =============================================================================

use sha2::{Sha256, Digest};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{PublicKey, SecretKey, DetachedSignature};

// =============================================================================
// Hashing
// =============================================================================

/// Hashes any slice of bytes using SHA-256, returning a fixed 32-byte array.
///
/// SHA-256 has two critical properties we rely on throughout the blockchain:
///
///   Deterministic:    the same input ALWAYS produces the same output.
///                     sha256("hello") → 2cf24dba... every single time.
///
///   Avalanche effect: changing even one bit of input produces a COMPLETELY
///                     different output. This is what makes blocks tamper-evident —
///                     if you change one transaction, the block hash changes,
///                     which breaks every subsequent block in the chain.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Converts a byte slice into a lowercase hex string for display and storage.
///
/// Raw bytes like [0x2c, 0xf2, 0x4d] are hard to read and can't be stored in
/// JSON cleanly. This converts them to "2cf24d..." — printable, comparable,
/// and JSON-safe. Used everywhere hashes and keys need to be shown or saved.
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

// =============================================================================
// Wallet
// =============================================================================

/// A wallet holding a Dilithium3 post-quantum key pair.
///
/// HOW OWNERSHIP WORKS:
///   Your private key is a secret random number. Anyone with your private key
///   can spend your coins — it must never be shared or stored in plaintext.
///
///   Your public key is mathematically derived from the private key. It can
///   be shared freely and is what others use to verify your signatures.
///
///   Your address is SHA-256(public_key) — a compact 64-char hex string that
///   you give to others so they can send you coins.
///
///   The relationship is one-way: private key → public key → address.
///   You cannot reverse any step. This is the mathematical guarantee of security.
///
/// STORAGE FORMAT:
///   Both keys are stored as raw byte vectors (Vec<u8>) rather than
///   library-specific types. This makes them easy to serialize, hex-encode,
///   encrypt, and save to disk without depending on Dilithium internals.
///   When loading from disk, we just decode the hex back to bytes.
pub struct Wallet {
    /// The Dilithium3 secret key — 4,000 bytes.
    /// Used to produce signatures that prove you authorized a transaction.
    /// Encrypted with AES-256-GCM and saved to a .dat file by wallet_store.rs.
    /// The raw bytes are NEVER written to disk or transmitted over the network.
    pub private_key: Vec<u8>,

    /// The Dilithium3 public key — 1,952 bytes.
    /// Stored in every transaction you send (in the `from` field) so that
    /// anyone receiving the transaction can verify your signature without
    /// contacting any central authority.
    /// Hashed via SHA-256 to produce your compact wallet address.
    pub public_key: Vec<u8>,
}

impl Wallet {
    /// Generates a brand new wallet with a randomly generated Dilithium3 key pair.
    ///
    /// Uses the operating system's cryptographically secure random number
    /// generator (CSPRNG). The private key cannot be predicted or reproduced.
    /// Every call produces a completely unique wallet.
    pub fn new() -> Self {
        let (pk, sk) = dilithium3::keypair();
        Wallet {
            public_key:  pk.as_bytes().to_vec(),
            private_key: sk.as_bytes().to_vec(),
        }
    }

    /// Reconstructs a wallet from the combined private+public key hex string
    /// that was saved to disk by wallet_store.rs.
    ///
    /// WHY STORE BOTH KEYS?
    ///   Unlike ECDSA, Dilithium does not allow re-deriving the public key
    ///   from the private key after the fact (the crate doesn't expose this
    ///   function). So we store both keys concatenated when saving:
    ///     private key: 4,000 bytes = 8,000 hex chars  (positions 0..8000)
    ///     public key:  1,952 bytes = 3,904 hex chars  (positions 8000..11904)
    ///
    /// The combined hex string is what wallet_store.rs encrypts and saves.
    /// This function splits them back apart when loading.
    pub fn from_hex(combined_hex: &str) -> Self {
        // Split at the known boundary: private key is exactly 8,000 hex chars
        let sk_hex = &combined_hex[..8000];
        let pk_hex = &combined_hex[8000..];

        Wallet {
            private_key: hex::decode(sk_hex).expect("Invalid private key hex"),
            public_key:  hex::decode(pk_hex).expect("Invalid public key hex"),
        }
    }

    /// Returns this wallet's address as a compact 64-character hex string.
    ///
    /// Address = SHA-256(public_key_bytes)
    ///
    /// WHY HASH THE PUBLIC KEY?
    ///   1. Compactness: the raw public key is 1,952 bytes. The hash is 32 bytes.
    ///      Addresses are what you share with others — shorter is better.
    ///
    ///   2. Extra quantum protection: even if lattice cryptography were broken
    ///      in the future, an attacker would also need to reverse a SHA-256 hash
    ///      to determine your public key from your address. Two layers of security.
    ///
    /// This is the address you share with others to receive coins.
    /// The blockchain's UTXO set maps addresses → balances.
    pub fn address(&self) -> String {
        to_hex(&sha256(&self.public_key))
    }

    /// Signs arbitrary data with this wallet's Dilithium3 private key.
    ///
    /// Returns a "detached signature" — the signature bytes are separate from
    /// the message (as opposed to Dilithium's combined signed-message format).
    /// Detached signatures are what we store in Transaction.signature.
    ///
    /// The signature mathematically binds:
    ///   - This specific data (what was signed)
    ///   - This specific private key (who signed it)
    ///
    /// Anyone can verify the signature is genuine using only the public key —
    /// the private key is never needed for verification.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let sk = dilithium3::SecretKey::from_bytes(&self.private_key)
            .expect("Invalid private key bytes");
        let sig = dilithium3::detached_sign(data, &sk);
        sig.as_bytes().to_vec()
    }
}

// =============================================================================
// Signature Verification
// =============================================================================

/// Verifies that a Dilithium3 detached signature was produced by the owner
/// of the given public key over the given data.
///
/// Called by Transaction::is_valid() to confirm that whoever sent a transaction
/// actually holds the private key corresponding to the `from` public key.
///
/// This is what makes it impossible to forge transactions — only the holder
/// of the correct private key can produce a signature that passes this check.
///
/// Takes raw byte slices so callers don't need to import Dilithium types.
/// Returns false cleanly on any error rather than panicking.
///
/// `public_key_bytes` — the signer's raw public key bytes (from tx.from)
/// `data`             — the exact bytes that were originally signed
/// `sig_bytes`        — the detached signature bytes to verify
pub fn verify_signature(
    public_key_bytes: &[u8],
    data: &[u8],
    sig_bytes: &[u8],
) -> bool {
    // Attempt to reconstruct the public key from raw bytes — fail gracefully
    let pk = match dilithium3::PublicKey::from_bytes(public_key_bytes) {
        Ok(pk)  => pk,
        Err(_)  => return false, // malformed public key
    };

    // Attempt to reconstruct the detached signature from raw bytes
    let sig = match dilithium3::DetachedSignature::from_bytes(sig_bytes) {
        Ok(sig) => sig,
        Err(_)  => return false, // malformed signature
    };

    // Verify: returns Ok if the signature is valid, Err if it doesn't match
    dilithium3::verify_detached_signature(&sig, data, &pk).is_ok()
}
