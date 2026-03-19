// =============================================================================
// seed_phrase.rs — 24-Word Deterministic Wallet Recovery
// =============================================================================
//
// HOW THIS WORKS (TRUE REGENERATION):
//
//   Unlike the previous 12-word system (which encrypted a backup of the key
//   bytes), this system DERIVES the keypair mathematically from the phrase.
//   No .phrase backup file is needed — the phrase IS the wallet.
//
//   CREATION:
//     1. Generate 32 random bytes (256 bits of entropy)
//     2. Encode as a 24-word BIP-39 mnemonic (2048-word list, 11 bits/word,
//        256 bits entropy + 8-bit SHA-256 checksum)
//     3. Derive the Dilithium3 keypair from the phrase via PBKDF2
//     4. Save the encrypted keypair to wallet.dat (for fast daily use)
//     5. Show the 24 words — user writes them down
//
//   RECOVERY (no backup file required):
//     1. User enters their 24 words
//     2. BIP-39 checksum is validated — typos caught immediately
//     3. PBKDF2-HMAC-SHA512 (2048 rounds) derives 64 bytes from the phrase
//     4. First 32 bytes become the Dilithium3 seed
//     5. Keypair::generate(Some(&seed)) deterministically regenerates
//        the exact same public key, private key, and wallet address
//     6. User sets a new password → new wallet.dat is saved
//
//   DERIVATION PATH:
//     24-word BIP-39 phrase
//       → PBKDF2-HMAC-SHA512 (2048 rounds, passphrase = "")
//       → 64 bytes
//       → first 32 bytes = Dilithium3 seed
//       → Keypair::generate(Some(&seed))
//       → (public_key, private_key, address)
//
// KEY PROPERTIES:
//   - Same 24 words always produce the same address — recovery is exact
//   - Different words produce a completely different, unrelated address
//   - Word order matters — shuffling the words gives a different wallet
//   - The BIP-39 checksum catches most typos before they derive a wrong key
//   - The optional BIP-39 passphrase (hardcoded "" here) can be exposed
//     as a CLI flag in the future for a two-factor recovery system
// =============================================================================

use bip39::{Mnemonic, Language};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use rand::RngCore;
use crate::crypto::Wallet;

// =============================================================================
// Core Derivation
// =============================================================================

/// Derives a Dilithium3 wallet deterministically from a 24-word BIP-39 phrase.
///
/// This is the central function of the regeneration system. Every other
/// function in this file is either a helper to produce a phrase or a
/// wrapper that calls this after validating the input.
///
/// Derivation path:
///   phrase → PBKDF2-HMAC-SHA512(2048 rounds) → 64 bytes
///           → first 32 bytes → Wallet::from_seed → Dilithium3 keypair
///
/// The BIP-39 standard defines the passphrase as an optional second factor.
/// We use "" (empty) by default, which is the standard BIP-39 behaviour.
/// All 64 PBKDF2 output bytes are equally strong; we take the first 32
/// because Dilithium3 requires exactly 32 bytes of seed input.
pub fn wallet_from_phrase(phrase: &str) -> Wallet {
    // PBKDF2-HMAC-SHA512 with 2048 rounds — the standard BIP-39 KDF.
    // This is far more brute-force-resistant than a bare hash.
    // "mnemonic" prefix + passphrase is the BIP-39 standard salt format.
    let salt = format!("mnemonic{}", ""); // passphrase = "" (standard BIP-39)
    let mut seed_bytes = [0u8; 64];
    pbkdf2_hmac::<Sha512>(
        phrase.as_bytes(),
        salt.as_bytes(),
        2048,
        &mut seed_bytes,
    );

    // Take the first 32 bytes as the Dilithium3 seed.
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes[..32]);

    Wallet::from_seed(&seed)
}

// =============================================================================
// Phrase Generation and Validation
// =============================================================================

/// Generates a new random 24-word BIP-39 mnemonic.
///
/// Uses 32 bytes (256 bits) of OS-provided cryptographically secure entropy.
/// BIP-39 encodes this as 24 words: 11 bits/word × 24 = 264 bits total,
/// where 256 bits are entropy and the remaining 8 bits are a SHA-256 checksum.
///
/// Returns the phrase as a space-separated string of 24 lowercase words,
/// all from the standard 2048-word BIP-39 English wordlist.
pub fn generate_phrase() -> String {
    let mut entropy = [0u8; 32]; // 256 bits → 24 words
    rand::thread_rng().fill_bytes(&mut entropy);
    Mnemonic::from_entropy_in(Language::English, &entropy)
        .expect("Failed to create mnemonic from entropy")
        .to_string()
}

/// Validates that a phrase is a valid BIP-39 mnemonic.
///
/// Checks two things:
///   1. Every word is in the standard 2048-word English wordlist
///   2. The embedded 8-bit SHA-256 checksum is correct
///
/// The checksum check catches most single-word typos and wrong word orders,
/// providing immediate feedback before an incorrect key is derived.
pub fn validate_phrase(phrase: &str) -> Result<(), String> {
    Mnemonic::parse_in(Language::English, phrase)
        .map(|_| ())
        .map_err(|e| format!("Invalid seed phrase: {}", e))
}

// =============================================================================
// Display
// =============================================================================

/// Formats a phrase for display with numbered words, 4 per line.
///
/// Example output:
///    1. abandon        2. ability        3. able           4. about
///    5. above          6. absent         7. absorb         8. abstract
///   ...
pub fn format_for_display(phrase: &str) -> String {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    let mut output = String::new();
    for (i, word) in words.iter().enumerate() {
        let num = i + 1;
        output.push_str(&format!("{:2}. {:<14}", num, word));
        if num % 4 == 0 {
            output.push('\n');
        }
    }
    // Final newline if the last row was incomplete
    if words.len() % 4 != 0 {
        output.push('\n');
    }
    output
}
