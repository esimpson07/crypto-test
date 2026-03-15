// =============================================================================
// block.rs — Block Structure and Proof-of-Work Mining
// =============================================================================
//
// A block permanently records a group of transactions on the blockchain.
// Once mined and accepted by the network, it cannot be altered without
// redoing all the computational work for every block that follows it.
//
// THE CHAINING MECHANISM:
//
//   Each block stores the hash of the block before it in `prev_hash`.
//   This creates a chain of cryptographic dependencies:
//
//     [Genesis] ← [Block 1] ← [Block 2] ← [Block 3] ← ...
//
//   If you alter anything in Block 1, its hash changes. That makes Block 2's
//   `prev_hash` wrong, which changes Block 2's hash, which breaks Block 3,
//   and so on. An attacker must redo all the mining from the tampered block
//   forward, faster than the honest network produces new blocks — infeasible
//   on any network with meaningful mining power.
//
// PROOF OF WORK:
//
//   Mining means finding a `nonce` value such that the block's SHA-256 hash
//   starts with N leading zeros (N = difficulty). There is no shortcut —
//   the miner tries nonces sequentially until one works. This costs real
//   computation and electricity.
//
//   The asymmetry is what secures the chain:
//     Finding a valid nonce  →  millions of hash computations (slow)
//     Verifying a valid nonce →  one hash computation (instant)
//
//   Anyone can instantly verify a mined block is legitimate. Nobody can
//   fake one without doing the actual work.
//
// BLOCK STRUCTURE:
//
//   ┌──────────────────────────────────────┐
//   │  index       block number (0, 1, 2…) │
//   │  timestamp   milliseconds since epoch │
//   │  prev_hash   hash of previous block   │ ← the chain link
//   │  hash        SHA-256 of this block    │
//   │  nonce       proof-of-work solution   │
//   ├──────────────────────────────────────┤
//   │  transactions[]                       │
//   │    [0]  coinbase (mining reward)      │
//   │    [1…] user transactions from pool   │
//   └──────────────────────────────────────┘
// =============================================================================

use serde::{Serialize, Deserialize};
use crate::transaction::Transaction;
use crate::crypto;

/// A single block in the blockchain.
///
/// Serializable for saving to chain.json and sending to peers over the network.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Block {
    /// Position in the chain. Genesis = 0, then 1, 2, 3...
    pub index: u64,

    /// Unix timestamp in milliseconds when this block was mined.
    pub timestamp: u64,

    /// Hash of the previous block — the cryptographic chain link.
    /// Any modification to a past block changes its hash, making this
    /// field incorrect and invalidating every subsequent block.
    pub prev_hash: String,

    /// SHA-256 hash of this block's contents.
    /// Computed by calculate_hash() and verified by every peer that
    /// receives this block. If the hash doesn't match, the block is rejected.
    pub hash: String,

    /// The number found by proof-of-work mining.
    /// Incremented from 0 until calculate_hash() produces a hash that
    /// starts with the required number of leading zeros.
    pub nonce: u64,

    /// Transactions confirmed by this block.
    /// First entry is always the coinbase (mining reward).
    /// Remaining entries are user transactions from the mempool.
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Returns the hardcoded genesis block — the shared starting point
    /// that every node on the network must begin from.
    ///
    /// WHY HARDCODE IT:
    ///   If each node generated a genesis block using the current time,
    ///   every node would have a different genesis hash. They would
    ///   immediately disagree on the chain and could never sync.
    ///
    ///   A fixed timestamp means every node always computes the same
    ///   genesis hash. This single shared fact makes the network possible.
    ///
    /// Never change the timestamp — doing so changes the genesis hash,
    /// making your chain incompatible with every existing node.
    pub fn genesis() -> Self {
        let mut block = Block {
            index:        0,
            timestamp:    1700000000000, // fixed — must never change
            prev_hash:    "0".repeat(64),
            hash:         String::new(),
            nonce:        0,
            transactions: vec![],
        };
        block.hash = block.calculate_hash();
        block
    }

    /// Creates a new unmined block ready for proof-of-work.
    ///
    /// The initial hash won't meet the difficulty target. Call mine()
    /// after this to find a valid nonce.
    ///
    /// `index`        — this block's position (chain.len() at creation time)
    /// `prev_hash`    — hash of the current chain tip
    /// `transactions` — coinbase first, then all mempool transactions
    pub fn new(index: u64, prev_hash: String, transactions: Vec<Transaction>) -> Self {
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;
        let mut block = Block {
            index,
            timestamp,
            prev_hash,
            hash: String::new(),
            nonce: 0,
            transactions,
        };
        block.hash = block.calculate_hash();
        block
    }

    /// Computes the SHA-256 hash of this block's contents.
    ///
    /// Includes all meaningful fields: index, timestamp, prev_hash, nonce,
    /// and the Merkle root (which represents all transactions). The `hash`
    /// field itself is excluded since that's what we're computing.
    ///
    /// Called once per nonce attempt during mining (millions of times)
    /// and once by validating nodes when they receive a block.
    pub fn calculate_hash(&self) -> String {
        let data = format!(
            "{}{}{}{}{}",
            self.index,
            self.timestamp,
            self.prev_hash,
            self.nonce,
            self.merkle_root()
        );
        crypto::to_hex(&crypto::sha256(data.as_bytes()))
    }

    /// Summarizes all transactions in this block into a single 32-byte hash.
    ///
    /// Each transaction is serialized to JSON and hashed individually.
    /// All those hashes are then concatenated and hashed together into
    /// one root hash. This is a simplified Merkle tree — a production
    /// blockchain uses a proper binary tree but this achieves the same
    /// tamper-evidence property: any change to any transaction changes
    /// the root, which changes the block hash.
    ///
    /// Returns a placeholder hash of 32 zero bytes for empty blocks
    /// (only the genesis block has no transactions).
    pub fn merkle_root(&self) -> String {
        if self.transactions.is_empty() {
            return crypto::to_hex(&[0u8; 32]);
        }
        let tx_hashes: Vec<String> = self.transactions
            .iter()
            .map(|tx| {
                let json = serde_json::to_string(tx).unwrap();
                crypto::to_hex(&crypto::sha256(json.as_bytes()))
            })
            .collect();
        let combined = tx_hashes.join("");
        crypto::to_hex(&crypto::sha256(combined.as_bytes()))
    }

    /// Mines this block by incrementing the nonce until the hash meets
    /// the proof-of-work difficulty target.
    ///
    /// The target requires the hash to start with `difficulty` leading zeros.
    /// Each additional zero makes mining ~16x harder on average:
    ///
    ///   Difficulty 3  ≈ 4,096 attempts    (instant)
    ///   Difficulty 5  ≈ 1,048,576 attempts (few seconds)
    ///   Difficulty 7  ≈ 268 million attempts (minutes)
    ///
    /// This function blocks until a valid nonce is found — on high difficulty
    /// settings this may take many seconds. Mining on the real Bitcoin network
    /// currently requires difficulty 23+.
    pub fn mine(&mut self, difficulty: usize) {
        let target = "0".repeat(difficulty);
        println!("Mining block {}...", self.index);
        loop {
            self.hash = self.calculate_hash();
            if self.hash.starts_with(&target) {
                println!("Mined! Nonce: {}, Hash: {}", self.nonce, self.hash);
                break;
            }
            self.nonce += 1;
        }
    }
}
