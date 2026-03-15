// =============================================================================
// wallet_store.rs — Encrypted Wallet File Storage
// =============================================================================
//
// Handles saving and loading wallet private keys securely to disk.
//
// WHY ENCRYPTION IS NECESSARY:
//
//   Your private key is the only proof that you own your coins. Anyone who
//   obtains it can drain your wallet instantly and irreversibly. Storing it
//   in plaintext — even temporarily — means any malware, nosy person, or
//   stolen laptop could take everything with no recourse.
//
// ENCRYPTION SCHEME (two steps):
//
//   Step 1 — PBKDF2-HMAC-SHA256 (key derivation)
//     Converts your password into a 256-bit AES encryption key.
//     100,000 iterations means each password guess requires 100,000 SHA-256
//     operations — brute-forcing even a weak password is expensive.
//     A random 16-byte salt is mixed in so the same password produces a
//     different key each save, defeating precomputed dictionary attacks.
//
//   Step 2 — AES-256-GCM (authenticated encryption)
//     Encrypts the private key using the PBKDF2-derived key.
//     GCM mode appends a 16-byte authentication tag. If the wrong password
//     is used, decryption fails with a clear error rather than silently
//     returning garbled bytes. Tampering with the file also causes failure.
//
// QUANTUM SAFETY:
//
//   AES-256 and SHA-256 (used in PBKDF2) are not broken by quantum computers.
//   Grover's Algorithm halves AES-256's effective security to 128 bits —
//   still completely infeasible to attack. No changes needed here.
//
// WALLET FILE FORMAT (stored as JSON):
//
//   {
//     "salt":       "<hex>",   16 random bytes, regenerated on every save
//     "nonce":      "<hex>",   12 random bytes, regenerated on every save
//     "ciphertext": "<hex>"    AES-256-GCM encrypted private+public key bytes
//   }
//
//   The salt and nonce are not secret — they're needed to re-derive the
//   encryption key on load. The ciphertext is useless without the password.
// =============================================================================

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use rand::RngCore;
use std::fs;
use std::path::Path;
use serde::{Serialize, Deserialize};

// =============================================================================
// File Format
// =============================================================================

/// The JSON structure written to the .dat wallet file on disk.
/// All fields are hex strings for clean JSON serialization.
#[derive(Serialize, Deserialize)]
struct WalletFile {
    salt:       String, // PBKDF2 salt — 16 random bytes, hex encoded
    nonce:      String, // AES-GCM nonce — 12 random bytes, hex encoded
    ciphertext: String, // Encrypted private+public key, hex encoded
}

// =============================================================================
// Internal Key Derivation
// =============================================================================

/// Derives a 32-byte AES encryption key from a password and salt via PBKDF2.
///
/// 100,000 iterations slow down brute-force attacks significantly — each
/// password guess costs 100,000 SHA-256 computations. The salt ensures the
/// same password produces a different key each time it's used.
fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 100_000, &mut key);
    key
}

// =============================================================================
// Public API
// =============================================================================

/// Encrypts the wallet's key material and saves it to a .dat file.
///
/// Stores the Dilithium3 private and public keys concatenated as one hex
/// string. Both keys are needed on load since Dilithium3 doesn't support
/// re-deriving the public key from the private key.
///
/// Fresh random salt and nonce are generated on every call — saving the
/// same keys twice with the same password produces different ciphertext
/// each time. This is correct and expected behavior.
///
/// `combined_key_hex` — private key hex + public key hex concatenated
/// `password`         — user's password (never stored, only used for key derivation)
/// `path`             — file path to write to (e.g. "alice.dat")
pub fn save_wallet(combined_key_hex: &str, password: &str, path: &str) -> Result<(), String> {
    let mut salt  = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    let key_bytes = derive_key(password, &salt);
    let key       = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher    = Aes256Gcm::new(key);
    let nonce_obj = Nonce::from_slice(&nonce);

    let ciphertext = cipher
        .encrypt(nonce_obj, combined_key_hex.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let wallet_file = WalletFile {
        salt:       hex::encode(salt),
        nonce:      hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
    };

    let json = serde_json::to_string_pretty(&wallet_file)
        .map_err(|e| e.to_string())?;
    fs::write(path, json).map_err(|e| e.to_string())?;

    println!("Wallet saved to {}", path);
    Ok(())
}

/// Decrypts a wallet file and returns the combined key material as hex.
///
/// The returned string is private key hex + public key hex concatenated,
/// which is passed to Wallet::from_hex() to reconstruct the full Wallet.
///
/// Fails with a clear error if:
///   - The file doesn't exist (wrong --wallet name or file deleted)
///   - The password is wrong (AES-GCM authentication tag mismatch)
///   - The file has been corrupted or tampered with
///
/// `password` — must match the password used when save_wallet() was called
/// `path`     — path to the .dat file (e.g. "alice.dat")
pub fn load_wallet(password: &str, path: &str) -> Result<String, String> {
    if !Path::new(path).exists() {
        return Err(format!(
            "Wallet '{}' not found. Create one with: new-wallet --wallet <name>",
            path
        ));
    }

    let json = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let wf: WalletFile = serde_json::from_str(&json).map_err(|e| e.to_string())?;

    let salt       = hex::decode(&wf.salt).map_err(|e| e.to_string())?;
    let nonce      = hex::decode(&wf.nonce).map_err(|e| e.to_string())?;
    let ciphertext = hex::decode(&wf.ciphertext).map_err(|e| e.to_string())?;

    let key_bytes = derive_key(password, &salt);
    let key       = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher    = Aes256Gcm::new(key);
    let nonce_obj = Nonce::from_slice(&nonce);

    let plaintext = cipher
        .decrypt(nonce_obj, ciphertext.as_ref())
        .map_err(|_| "Wrong password or corrupted wallet file".to_string())?;

    Ok(String::from_utf8(plaintext).map_err(|e| e.to_string())?)
}
