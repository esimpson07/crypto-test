// =============================================================================
// wallet_store.rs — Encrypted Wallet File Storage
// =============================================================================
//
// This file handles saving and loading wallet private keys securely to disk.
//
// WHY ENCRYPTION MATTERS:
//   Your private key is the only thing that proves you own your coins. Anyone
//   with your private key can spend every coin in your wallet, instantly and
//   irreversibly. Storing it in plaintext (like a text file) would mean anyone
//   who accessed your computer — malware, a curious person, a stolen laptop —
//   could drain your wallet with no recourse.
//
// ENCRYPTION SCHEME:
//   We use two industry-standard algorithms in sequence:
//
//   Step 1 — PBKDF2 (Password-Based Key Derivation Function 2):
//     Converts your human-readable password into a 256-bit cryptographic key.
//     Uses HMAC-SHA256 with 100,000 iterations — meaning each password guess
//     requires 100,000 SHA-256 computations. Brute-forcing even a moderately
//     strong password becomes computationally infeasible.
//     A random 16-byte salt is mixed in so the same password produces a
//     different key each time — defeating precomputed dictionary attacks.
//
//   Step 2 — AES-256-GCM (Advanced Encryption Standard, Galois/Counter Mode):
//     Encrypts the private key using the PBKDF2-derived key.
//     GCM is an "authenticated encryption" mode — it appends a 16-byte
//     authentication tag that detects tampering. If the wrong password is
//     provided, decryption fails cleanly rather than returning garbage data.
//
// QUANTUM SAFETY:
//   AES-256 and SHA-256 (used in PBKDF2) are NOT broken by quantum computers.
//   Grover's Algorithm gives a quadratic speedup against symmetric ciphers,
//   which effectively halves the key length — but 256-bit AES halved to 128
//   bits is still completely secure. No changes needed here for quantum safety.
//
// WALLET FILE FORMAT (JSON on disk):
//   {
//     "salt":       "a3f9c2d8...",   ← random 16 bytes, new on every save
//     "nonce":      "7f2a91c3...",   ← random 12 bytes, new on every save
//     "ciphertext": "8b3d92f1..."    ← AES-256-GCM encrypted private+public key
//   }
//   All values are hex-encoded. Without the correct password this file is
//   computationally useless — no information about the private key is leaked.
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
// Wallet File Format
// =============================================================================

/// The structure serialized to JSON and written to the .dat wallet file.
///
/// All three fields are hex-encoded strings for clean, portable JSON storage.
/// None of these values are secret — they're needed to re-derive the key and
/// decrypt the ciphertext, but without the password they reveal nothing.
#[derive(Serialize, Deserialize)]
struct WalletFile {
    /// Random 16 bytes mixed into the password before key derivation (PBKDF2 salt).
    /// Ensures two users with the same password produce different encryption keys.
    /// Stored in the file because we need it to re-derive the same key on load.
    salt: String,

    /// Random 12 bytes used as the AES-GCM initialization vector.
    /// Must be unique per encryption operation to maintain security.
    /// Stored alongside ciphertext — needed for decryption.
    nonce: String,

    /// The AES-256-GCM encrypted payload containing the combined private+public key.
    /// For Dilithium3 keys: ~11,904 hex chars (5,952 bytes of key data + 16-byte GCM tag).
    /// Completely opaque without the correct password.
    ciphertext: String,
}

// =============================================================================
// Key Derivation
// =============================================================================

/// Derives a 32-byte (256-bit) AES encryption key from a password and salt.
///
/// PBKDF2-HMAC-SHA256 with 100,000 iterations is used. The high iteration
/// count is the defense against brute force: each password guess requires
/// 100,000 SHA-256 operations, slowing attackers to a crawl even with
/// dedicated hardware.
///
/// The salt ensures the same password produces a different key each time
/// it's used, defeating precomputed (rainbow table) attacks.
fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 100_000, &mut key);
    key
}

// =============================================================================
// Public API
// =============================================================================

/// Encrypts the wallet's combined key material and saves it to a .dat file.
///
/// The `private_key_hex` argument should be the concatenation of the
/// Dilithium3 private key hex (8,000 chars) and public key hex (3,904 chars),
/// as produced in main.rs's new-wallet command. Both are needed on load since
/// Dilithium3 doesn't support re-deriving the public key from the private key.
///
/// Each call generates fresh random salt and nonce — so saving the same keys
/// with the same password twice produces completely different ciphertext.
/// This is correct behavior, not a bug.
///
/// `private_key_hex` — combined private+public key as hex (11,904 chars)
/// `password`        — the user's password (used for key derivation, never stored)
/// `path`            — file path to write to (e.g. "alice.dat")
pub fn save_wallet(private_key_hex: &str, password: &str, path: &str) -> Result<(), String> {
    // Generate fresh random bytes for salt and nonce on every save
    // These MUST be different each time for AES-GCM to remain secure
    let mut salt  = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    // Turn the password + salt into a 256-bit AES key via PBKDF2
    let key_bytes = derive_key(password, &salt);
    let key       = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher    = Aes256Gcm::new(key);
    let nonce_obj = Nonce::from_slice(&nonce);

    // Encrypt the key material. AES-GCM appends a 16-byte authentication tag
    // that will cause decryption to fail if the wrong password is used —
    // there's no way to get plausible-looking garbage out of a wrong password.
    let ciphertext = cipher
        .encrypt(nonce_obj, private_key_hex.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Serialize to JSON with all values hex-encoded
    let wallet_file = WalletFile {
        salt:       hex::encode(salt),
        nonce:      hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
    };
    let json = serde_json::to_string_pretty(&wallet_file).map_err(|e| e.to_string())?;

    // Write to disk — the file is now encrypted and safe to store anywhere
    fs::write(path, json).map_err(|e| e.to_string())?;
    println!("Wallet saved to {}", path);
    Ok(())
}

/// Decrypts and loads a wallet file, returning the combined key material as hex.
///
/// The returned string is the concatenated private+public key hex, which is
/// passed to Wallet::from_hex() in main.rs to reconstruct the full Wallet.
///
/// Fails clearly with an error message if:
///   - The wallet file doesn't exist (wrong --wallet name or file deleted)
///   - The password is incorrect (AES-GCM authentication tag mismatch)
///   - The file is corrupted or has been tampered with
///
/// `password` — the user's password (must match the one used when saving)
/// `path`     — path to the .dat wallet file (e.g. "alice.dat")
pub fn load_wallet(password: &str, path: &str) -> Result<String, String> {
    // Check the file exists before attempting to open it
    if !Path::new(path).exists() {
        return Err(format!(
            "Wallet file '{}' not found. Create one with: new-wallet --wallet <name>",
            path
        ));
    }

    // Read the JSON wallet file from disk
    let json = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let wallet_file: WalletFile = serde_json::from_str(&json).map_err(|e| e.to_string())?;

    // Decode all three hex fields back to raw bytes
    let salt       = hex::decode(&wallet_file.salt).map_err(|e| e.to_string())?;
    let nonce      = hex::decode(&wallet_file.nonce).map_err(|e| e.to_string())?;
    let ciphertext = hex::decode(&wallet_file.ciphertext).map_err(|e| e.to_string())?;

    // Re-derive the same encryption key using the stored salt + provided password
    // If the password is wrong, the derived key will be different and decryption fails
    let key_bytes = derive_key(password, &salt);
    let key       = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher    = Aes256Gcm::new(key);
    let nonce_obj = Nonce::from_slice(&nonce);

    // Attempt decryption — the GCM auth tag check happens here
    // Wrong password → "Wrong password or corrupted wallet file" error
    let plaintext = cipher
        .decrypt(nonce_obj, ciphertext.as_ref())
        .map_err(|_| "Wrong password or corrupted wallet file".to_string())?;

    // Convert the decrypted bytes back to the combined key hex string
    Ok(String::from_utf8(plaintext).map_err(|e| e.to_string())?)
}
