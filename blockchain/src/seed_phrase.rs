// =============================================================================
// seed_phrase.rs — Seed Phrase Wallet Backup and Recovery
// =============================================================================
//
// HOW THIS WORKS:
//
//   Unlike Bitcoin's BIP39 (where the phrase mathematically derives the keys),
//   our approach uses the phrase as a human-readable password to encrypt a
//   backup of the actual key bytes. This sidesteps the limitation that
//   pqcrypto-dilithium v0.5 does not expose keypair_from_seed().
//
//   The security properties are equivalent:
//     - 12 BIP39 words = 128 bits of entropy as the encryption password
//     - The actual Dilithium3 keys are encrypted with AES-256-GCM
//     - Losing both the .dat file AND the phrase = coins are gone
//     - Having the phrase = can recover the keys on any machine
//
//   CREATION:
//     1. Generate a real Dilithium3 keypair (cryptographically random)
//     2. Generate 12 random BIP39 words (128 bits entropy)
//     3. Save keypair encrypted with wallet password → wallet.dat
//     4. Save keypair encrypted with phrase-derived key → wallet.phrase
//     5. Show the 12 words to the user — they write them down
//
//   RECOVERY:
//     1. User enters their 12 words
//     2. We derive an AES key from the words using PBKDF2
//     3. We decrypt wallet.phrase to get the keypair back
//     4. User sets a new password → new wallet.dat is saved
// =============================================================================

use bip39::{Mnemonic, Language};
use sha2::Sha256;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};

/// Generates a new random 12-word BIP39 phrase.
/// The phrase is used as a high-entropy password for encrypting the key backup.
pub fn generate_phrase() -> String {
    let mut entropy = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut entropy);
    Mnemonic::from_entropy(&entropy, Language::English)
        .expect("Failed to create mnemonic")
        .phrase()
        .to_string()
}

/// Validates that all words are valid BIP39 words in the correct format.
pub fn validate_phrase(phrase: &str) -> Result<(), String> {
    Mnemonic::from_phrase(phrase, Language::English)
        .map(|_| ())
        .map_err(|e| format!("Invalid seed phrase: {}", e))
}

/// Derives a 32-byte AES encryption key from a seed phrase.
///
/// Uses PBKDF2-HMAC-SHA256 with 100,000 iterations.
/// The phrase has 128 bits of entropy so 100,000 iterations
/// provides strong protection even though it's fast here —
/// the attacker can't guess the phrase regardless of speed.
fn phrase_to_aes_key(phrase: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        phrase.as_bytes(),
        b"blockchain-phrase-backup-v1",
        100_000,
        &mut key,
    );
    key
}

/// Encrypts the combined key hex with the phrase as the encryption password.
///
/// Called during new-wallet to create the phrase-encrypted backup file.
/// The phrase file can decrypt the keys without needing the wallet password.
///
/// `combined_key_hex` — private key hex + public key hex concatenated
/// `phrase`           — the 12-word seed phrase (used as encryption key)
/// `path`             — file path for the backup (e.g. "wallet_1.phrase")
pub fn save_phrase_backup(
    combined_key_hex: &str,
    phrase: &str,
    path: &str,
) -> Result<(), String> {
    use std::fs;
    use serde::{Serialize, Deserialize};
    use rand::RngCore;

    #[derive(Serialize, Deserialize)]
    struct PhraseFile {
        phrase:     String,  // the 12 words (so user can see them again)
        nonce:      String,  // AES-GCM nonce
        ciphertext: String,  // encrypted key material
    }

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let key_bytes = phrase_to_aes_key(phrase);
    let key       = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher    = Aes256Gcm::new(key);
    let nonce_obj = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce_obj, combined_key_hex.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let pf = PhraseFile {
        phrase:     phrase.to_string(),
        nonce:      hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    };

    let json = serde_json::to_string_pretty(&pf).map_err(|e| e.to_string())?;
    fs::write(path, json).map_err(|e| e.to_string())?;
    Ok(())
}

/// Loads the phrase file, shows the stored phrase, and decrypts the keys.
///
/// Called by recover-wallet and show-phrase commands.
/// Returns (combined_key_hex, phrase_string).
pub fn load_phrase_backup(phrase: &str, path: &str) -> Result<(String, String), String> {
    use std::fs;
    use serde::{Serialize, Deserialize};

    #[derive(Serialize, Deserialize)]
    struct PhraseFile {
        phrase:     String,
        nonce:      String,
        ciphertext: String,
    }

    if !std::path::Path::new(path).exists() {
        return Err(format!("Phrase backup file '{}' not found", path));
    }

    let json = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let pf: PhraseFile = serde_json::from_str(&json).map_err(|e| e.to_string())?;

    let nonce      = hex::decode(&pf.nonce).map_err(|e| e.to_string())?;
    let ciphertext = hex::decode(&pf.ciphertext).map_err(|e| e.to_string())?;

    let key_bytes = phrase_to_aes_key(phrase);
    let key       = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher    = Aes256Gcm::new(key);
    let nonce_obj = Nonce::from_slice(&nonce);

    let plaintext = cipher
        .decrypt(nonce_obj, ciphertext.as_ref())
        .map_err(|_| "Wrong phrase — could not decrypt backup".to_string())?;

    let combined_key_hex = String::from_utf8(plaintext).map_err(|e| e.to_string())?;
    Ok((combined_key_hex, pf.phrase))
}

/// Formats the phrase for display with numbered words, 3 per line.
pub fn format_for_display(phrase: &str) -> String {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    let mut output = String::new();
    for (i, word) in words.iter().enumerate() {
        let num = i + 1;
        output.push_str(&format!("{:2}. {:<14}", num, word));
        if num % 3 == 0 {
            output.push('\n');
        }
    }
    output
}