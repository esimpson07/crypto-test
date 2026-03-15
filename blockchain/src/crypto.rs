// =============================================================================
// crypto.rs — Post-Quantum Cryptographic Primitives
// =============================================================================
//
// Every operation that requires trust in this blockchain — owning coins,
// authorizing transactions, linking blocks together — depends on this file.
//
// WHAT THIS FILE PROVIDES:
//
//   SHA-256 hashing
//     Produces a unique 32-byte fingerprint of any data. Two critical
//     properties make it useful here:
//       Deterministic  — same input always produces the same output
//       Avalanche      — changing one bit produces a completely different hash
//     Used for block hashing, proof-of-work mining, Merkle trees, and
//     deriving compact wallet addresses from public keys.
//
//   Post-quantum key pairs (CRYSTALS-Dilithium3)
//     Every wallet has a private key (secret, never shared) and a public
//     key (freely shareable). The private key signs transactions; the public
//     key lets anyone verify those signatures.
//
//   Signing
//     Proves you authorized a transaction without revealing your private key.
//     Only the holder of the private key can produce a valid signature.
//
//   Verification
//     Lets anyone confirm a signature is genuine using only the signer's
//     public key. No trusted third party is needed.
//
// WHY DILITHIUM3 INSTEAD OF ECDSA?
//
//   Bitcoin uses ECDSA on the secp256k1 elliptic curve. Security relies on
//   the elliptic curve discrete logarithm problem (ECDLP). A quantum computer
//   running Shor's Algorithm solves ECDLP in polynomial time — meaning it
//   could derive any private key from its public key, breaking every wallet.
//
//   Dilithium3 is based on the Module Learning With Errors (MLWE) lattice
//   problem. No known quantum algorithm solves lattice problems significantly
//   faster than classical computers. It was standardized by NIST in 2024
//   (FIPS 204) as the recommended post-quantum signature scheme.
//
// KEY SIZE COMPARISON:
//
//   ┌─────────────┬──────────────┬────────────────┐
//   │             │ ECDSA        │ Dilithium3     │
//   ├─────────────┼──────────────┼────────────────┤
//   │ Public key  │ 33 bytes     │ 1,952 bytes    │
//   │ Private key │ 32 bytes     │ 4,032 bytes    │
//   │ Signature   │ 64 bytes     │ 3,293 bytes    │
//   └─────────────┴──────────────┴────────────────┘
//
//   Larger keys and signatures are the accepted cost of quantum resistance.
//   Transactions and wallet files are proportionally larger as a result.
//
// WHY SHA-256 IS NOT REPLACED:
//
//   SHA-256 (used for hashing and mining) is not vulnerable to Shor's
//   Algorithm. Grover's Algorithm provides only a quadratic speedup against
//   hash functions, effectively halving security from 256 to 128 bits.
//   128-bit security is still computationally infeasible to attack and
//   sufficient for all mining and hashing purposes here.
// =============================================================================

use sha2::{Sha256, Digest};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{PublicKey, SecretKey, DetachedSignature};

// =============================================================================
// Hashing
// =============================================================================

/// Hashes any byte slice with SHA-256, returning a fixed 32-byte array.
///
/// The avalanche effect means even a one-bit change in input produces a
/// completely different output — this is what makes blocks tamper-evident.
/// If you alter any transaction in a block, the block hash changes, which
/// breaks its link to the next block, cascading invalidation forward.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Converts a byte slice into a lowercase hex string for display and storage.
///
/// Raw bytes are hard to read and don't serialize cleanly to JSON.
/// Hex encoding turns [0x2c, 0xf2] into "2cf2..." — readable and JSON-safe.
/// Used everywhere hashes, addresses, and keys need to be displayed or saved.
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

// =============================================================================
// Wallet — Dilithium3 Key Pair
// =============================================================================

/// A wallet holding a Dilithium3 post-quantum key pair.
///
/// KEY OWNERSHIP MODEL:
///   private_key  →  used to sign transactions (prove authorization)
///   public_key   →  used to verify signatures (shared freely)
///   address      →  SHA-256(public_key), compact 64-char hex (shared with others)
///
///   The chain is one-way: you cannot reverse any step.
///   Private key → public key → address, but never backwards.
///
/// WHY BOTH KEYS ARE STORED:
///   Unlike ECDSA, Dilithium3 does not support re-deriving the public key
///   from the private key after generation (the crate does not expose this).
///   Both keys are stored as raw byte vectors and saved together in the
///   wallet file. On load, from_hex() splits them back apart using the
///   crate's reported key size rather than a hardcoded constant.
pub struct Wallet {
    /// The Dilithium3 secret key (~4,032 bytes depending on crate version).
    /// Used to produce signatures. Encrypted with AES-256-GCM before being
    /// written to disk. Never transmitted over the network.
    pub private_key: Vec<u8>,

    /// The Dilithium3 public key (1,952 bytes).
    /// Included in every transaction in the `from` field so recipients can
    /// verify the signature without contacting any central authority.
    /// Hashed with SHA-256 to produce the compact wallet address.
    pub public_key: Vec<u8>,
}

impl Wallet {
    /// Generates a new wallet with a randomly generated Dilithium3 key pair.
    ///
    /// Uses the OS cryptographically secure random number generator (CSPRNG).
    /// Every call produces a completely unique, unpredictable key pair.
    pub fn new() -> Self {
        let (pk, sk) = dilithium3::keypair();
        Wallet {
            public_key:  pk.as_bytes().to_vec(),
            private_key: sk.as_bytes().to_vec(),
        }
    }

    /// Reconstructs a wallet from the combined private+public key hex string
    /// saved to disk by wallet_store.rs.
    ///
    /// The wallet file stores both keys concatenated:
    ///   [private key bytes][public key bytes]  →  hex encoded as one string
    ///
    /// The split point is determined at runtime by querying the crate:
    ///   dilithium3::secret_key_bytes() → the actual private key byte length
    ///
    /// We do NOT hardcode the split point because the private key size varies
    /// between crate versions (e.g. 4,032 bytes in pqcrypto-dilithium v0.5).
    /// Hardcoding caused a runtime panic when the assumed size was wrong.
    pub fn from_hex(combined_hex: &str) -> Self {
        // Ask the crate how large the secret key actually is in this version
        let sk_byte_len = dilithium3::secret_key_bytes();
        let sk_hex_len  = sk_byte_len * 2; // 2 hex chars per byte

        let sk_hex = &combined_hex[..sk_hex_len];
        let pk_hex = &combined_hex[sk_hex_len..];

        Wallet {
            private_key: hex::decode(sk_hex).expect("Invalid private key hex"),
            public_key:  hex::decode(pk_hex).expect("Invalid public key hex"),
        }
    }

    /// Returns this wallet's address as a compact 64-character hex string.
    ///
    /// Address = SHA-256(public_key_bytes)
    ///
    /// Hashing the public key serves two purposes:
    ///   1. Compactness — 1,952 raw bytes becomes 32 bytes (64 hex chars)
    ///   2. Extra quantum protection — even if lattice cryptography were
    ///      broken in the future, an attacker would still need to reverse
    ///      a SHA-256 hash to learn the public key from the address alone
    ///
    /// This address is what you share with others to receive coins.
    /// The blockchain UTXO set uses addresses as keys to track balances.
    pub fn address(&self) -> String {
        to_hex(&sha256(&self.public_key))
    }

    /// Signs arbitrary data using this wallet's Dilithium3 private key.
    ///
    /// Returns a detached signature — the signature bytes are separate from
    /// the message, which is what Transaction.signature stores. "Detached"
    /// contrasts with Dilithium's combined signed-message format where the
    /// signature and message are concatenated.
    ///
    /// The signature mathematically binds two things:
    ///   - The specific data that was signed
    ///   - The specific private key that signed it
    ///
    /// Anyone can verify authenticity using only the public key.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let sk  = dilithium3::SecretKey::from_bytes(&self.private_key)
            .expect("Invalid private key bytes");
        let sig = dilithium3::detached_sign(data, &sk);
        sig.as_bytes().to_vec()
    }
}

// =============================================================================
// Signature Verification
// =============================================================================

/// Verifies a Dilithium3 detached signature against a public key and message.
///
/// Called by Transaction::is_valid() to confirm the sender actually holds
/// the private key corresponding to the public key stored in Transaction.from.
/// This is the mathematical guarantee that prevents transaction forgery.
///
/// Returns false cleanly on any error (malformed key, malformed signature,
/// or signature mismatch) rather than panicking — invalid data from peers
/// is expected and should be handled gracefully.
///
/// `public_key_bytes` — raw public key bytes from the transaction's `from` field
/// `data`             — the exact bytes that were signed (signing_data())
/// `sig_bytes`        — the detached signature bytes to verify
pub fn verify_signature(public_key_bytes: &[u8], data: &[u8], sig_bytes: &[u8]) -> bool {
    let pk = match dilithium3::PublicKey::from_bytes(public_key_bytes) {
        Ok(pk)  => pk,
        Err(_)  => return false,
    };
    let sig = match dilithium3::DetachedSignature::from_bytes(sig_bytes) {
        Ok(sig) => sig,
        Err(_)  => return false,
    };
    dilithium3::verify_detached_signature(&sig, data, &pk).is_ok()
}
