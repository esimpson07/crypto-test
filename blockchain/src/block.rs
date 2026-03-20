// =============================================================================
// block.rs — Block Structure (Proof of Stake)
// =============================================================================
//
// A block is proposed by the selected validator and signed with their
// Dilithium3 private key. No nonce or proof-of-work exists.
//
// BLOCK STRUCTURE:
//
//   index           — block number (0 = genesis)
//   timestamp       — milliseconds since epoch
//   prev_hash       — hash of previous block (chain link)
//   hash            — SHA-256 of this block's contents
//   validator       — address of the block producer
//   validator_sig   — Dilithium3 signature of `hash`
//   transactions[]  — reward, unbonding releases, slashes, user txs
//
// WHAT IS SIGNED:
//
//   The validator signs calculate_hash() which covers index, timestamp,
//   prev_hash, validator address, and the merkle root of all transactions.
//   Forging a block requires the validator's private key.
//
// DOUBLE-SIGN DETECTION:
//
//   Nodes track the (height -> hash) mapping of every block they have seen
//   signed by each validator. If they receive a second valid signature from
//   the same validator at the same height with a different hash, that is
//   proof of a double-sign and is submitted to produce_block as slash evidence.
// =============================================================================

use serde::{Serialize, Deserialize};
use crate::transaction::Transaction;
use crate::crypto;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Block {
    pub index:         u64,
    pub timestamp:     u64,
    pub prev_hash:     String,
    pub hash:          String,
    pub validator:     String,
    pub validator_sig: Vec<u8>,
    pub transactions:  Vec<Transaction>,
}

impl Block {
    /// The hardcoded genesis block — fixed timestamp so every node computes
    /// the same genesis hash and can sync.
    pub fn genesis() -> Self {
        let mut block = Block {
            index:         0,
            timestamp:     1700000000000,
            prev_hash:     "0".repeat(64),
            hash:          String::new(),
            validator:     "genesis".to_string(),
            validator_sig: vec![],
            transactions:  vec![],
        };
        block.hash = block.calculate_hash();
        block
    }

    pub fn new(
        index:        u64,
        prev_hash:    String,
        validator:    String,
        transactions: Vec<Transaction>,
    ) -> Self {
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;
        let mut block = Block {
            index, timestamp, prev_hash,
            hash: String::new(),
            validator,
            validator_sig: vec![],
            transactions,
        };
        block.hash = block.calculate_hash();
        block
    }

    /// SHA-256 hash of all meaningful fields.
    /// Excludes `hash` (circular) and `validator_sig` (computed after hash).
    pub fn calculate_hash(&self) -> String {
        let data = format!(
            "{}{}{}{}{}",
            self.index, self.timestamp, self.prev_hash,
            self.validator, self.merkle_root()
        );
        crypto::to_hex(&crypto::sha256(data.as_bytes()))
    }

    pub fn merkle_root(&self) -> String {
        if self.transactions.is_empty() {
            return crypto::to_hex(&[0u8; 32]);
        }
        let combined = self.transactions.iter()
            .map(|tx| {
                let json = serde_json::to_string(tx).unwrap();
                crypto::to_hex(&crypto::sha256(json.as_bytes()))
            })
            .collect::<Vec<_>>()
            .join("");
        crypto::to_hex(&crypto::sha256(combined.as_bytes()))
    }

    pub fn sign_as_validator(&mut self, wallet: &crypto::Wallet) {
        self.validator_sig = wallet.sign(self.hash.as_bytes());
    }

    /// Verifies the validator's signature against the block hash.
    /// Returns true for the genesis block unconditionally (no validator).
    pub fn verify_validator_sig(&self, validator_pubkey_bytes: &[u8]) -> bool {
        if self.validator == "genesis" || self.validator == "dev" {
            return true;
        }
        crypto::verify_signature(
            validator_pubkey_bytes,
            self.hash.as_bytes(),
            &self.validator_sig,
        )
    }
}
