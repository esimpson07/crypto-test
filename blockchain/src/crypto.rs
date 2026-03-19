// =============================================================================
// crypto.rs — Post-Quantum Cryptographic Primitives
// =============================================================================
//
// Every operation that requires trust in this blockchain depends on this file.
//
// WHAT THIS FILE PROVIDES:
//
//   SHA-256 hashing
//     Used for block hashing, proof-of-work, Merkle trees, and deriving
//     compact wallet addresses from public keys.
//
//   Post-quantum key pairs (CRYSTALS-Dilithium3)
//     Every wallet has a private key (never shared) and a public key
//     (freely shareable). The private key signs transactions; the public
//     key lets anyone verify those signatures.
//
//     Crucially, this crate supports DETERMINISTIC keypair generation:
//       Keypair::generate(Some(&seed)) always produces the same keypair
//       from the same 32-byte seed — the foundation of phrase recovery.
//
// WHY CRYSTALS-DILITHIUM (crystals-dilithium crate):
//
//   pqcrypto-dilithium only exposes keypair() which uses OS randomness —
//   it has no way to supply a seed for deterministic generation.
//   crystals-dilithium exposes Keypair::generate(Some(&seed)), which is
//   required for 24-word phrase recovery to work.
//
// KEY SIZES (dilithium3, fixed by the algorithm spec):
//
//   Public key:  1,952 bytes  (3,904 hex chars)
//   Secret key:  4,000 bytes  (8,000 hex chars)
//   Signature:   3,293 bytes
//
//   These are compile-time constants of the algorithm — they do not change
//   between crate versions. We use them to split the combined key hex in
//   from_hex() rather than relying on a runtime size query function
//   (which this crate does not expose).
//
// WHY SHA-256 IS NOT REPLACED:
//
//   SHA-256 is not vulnerable to Shor's Algorithm. Grover's Algorithm
//   gives only a quadratic speedup, effectively halving security to 128
//   bits — still completely infeasible to attack.
// =============================================================================

use sha2::{Sha256, Digest};
use crystals_dilithium::dilithium3::{Keypair, PublicKey, SecretKey};

// Dilithium3 key sizes in bytes — fixed by the algorithm specification.
// Used to split the combined hex string in Wallet::from_hex().
const DILITHIUM3_SECRET_KEY_BYTES: usize = 4000;
const DILITHIUM3_PUBLIC_KEY_BYTES: usize = 1952;

// =============================================================================
// Hashing
// =============================================================================

/// Hashes any byte slice with SHA-256, returning a fixed 32-byte array.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Converts a byte slice into a lowercase hex string.
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

// =============================================================================
// Wallet — Dilithium3 Key Pair
// =============================================================================

/// A wallet holding a Dilithium3 post-quantum key pair.
///
/// KEY OWNERSHIP MODEL:
///   private_key  — used to sign transactions
///   public_key   — used to verify signatures, shared freely
///   address      — SHA-256(public_key), compact 64-char hex
///
/// DETERMINISTIC GENERATION:
///   Wallet::from_seed(&seed) always produces the same keypair from the
///   same 32-byte seed. This is the foundation of phrase recovery:
///     phrase -> PBKDF2 -> 32-byte seed -> Wallet::from_seed -> same keypair
pub struct Wallet {
    /// The Dilithium3 secret key (4,000 bytes).
    /// Encrypted before being written to disk. Never transmitted.
    pub private_key: Vec<u8>,

    /// The Dilithium3 public key (1,952 bytes).
    /// Included in every transaction for signature verification.
    /// Hashed with SHA-256 to produce the compact wallet address.
    pub public_key: Vec<u8>,
}

impl Wallet {
    /// Generates a new wallet with a randomly generated Dilithium3 key pair.
    pub fn new() -> Self {
        let keypair = Keypair::generate(None)
            .expect("Failed to generate Dilithium3 keypair");
        Wallet {
            public_key:  keypair.public.to_bytes().to_vec(),
            private_key: keypair.secret.to_bytes().to_vec(),
        }
    }

    /// Deterministically generates a wallet from a 32-byte seed.
    ///
    /// The same seed always produces the same keypair. Called by
    /// seed_phrase::wallet_from_phrase() during both wallet creation and
    /// recovery — the phrase derives a seed via PBKDF2, this function
    /// expands it into a full Dilithium3 keypair.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let keypair = Keypair::generate(Some(seed))
            .expect("Failed to generate Dilithium3 keypair from seed");
        Wallet {
            public_key:  keypair.public.to_bytes().to_vec(),
            private_key: keypair.secret.to_bytes().to_vec(),
        }
    }

    /// Reconstructs a wallet from the combined private+public key hex string
    /// saved by wallet_store.rs.
    ///
    /// The wallet file stores both keys concatenated:
    ///   [secret key bytes][public key bytes] -> hex encoded as one string
    ///
    /// We split at the known secret key boundary (4,000 bytes = 8,000 hex
    /// chars). This is a fixed algorithm constant, not a crate-version detail.
    pub fn from_hex(combined_hex: &str) -> Self {
        let sk_hex_len = DILITHIUM3_SECRET_KEY_BYTES * 2; // 8,000 hex chars
        let pk_hex_len = DILITHIUM3_PUBLIC_KEY_BYTES * 2; // 3,904 hex chars

        assert!(
            combined_hex.len() == sk_hex_len + pk_hex_len,
            "Combined key hex has unexpected length {} (expected {})",
            combined_hex.len(),
            sk_hex_len + pk_hex_len
        );

        let sk_hex = &combined_hex[..sk_hex_len];
        let pk_hex = &combined_hex[sk_hex_len..];

        Wallet {
            private_key: hex::decode(sk_hex).expect("Invalid private key hex"),
            public_key:  hex::decode(pk_hex).expect("Invalid public key hex"),
        }
    }

    /// Returns this wallet's address as a compact 64-character hex string.
    /// Address = SHA-256(public_key_bytes).
    pub fn address(&self) -> String {
        to_hex(&sha256(&self.public_key))
    }

    /// Signs arbitrary data using this wallet's Dilithium3 private key.
    /// Returns a detached signature stored in Transaction.signature.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let sk = SecretKey::from_bytes(&self.private_key)
            .expect("Invalid private key bytes");
        let pk = PublicKey::from_bytes(&self.public_key)
            .expect("Invalid public key bytes");
        // crystals-dilithium puts sign() on Keypair, so both keys are needed.
        let keypair = Keypair { public: pk, secret: sk };
        keypair.sign(data).to_vec()
    }
}

// =============================================================================
// Signature Verification
// =============================================================================

/// Verifies a Dilithium3 signature against a public key and message.
///
/// Called by Transaction::is_valid(). Returns false cleanly on any error
/// rather than panicking — invalid data from peers must be handled gracefully.
///
/// NOTE: crystals-dilithium's PublicKey::verify() returns bool directly,
/// not Result — a true means valid, false means invalid or malformed input.
pub fn verify_signature(public_key_bytes: &[u8], data: &[u8], sig_bytes: &[u8]) -> bool {
    let pk = match PublicKey::from_bytes(public_key_bytes) {
        Ok(pk)  => pk,
        Err(_)  => return false,
    };
    pk.verify(data, sig_bytes)
}
