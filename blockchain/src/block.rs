// =============================================================================
// block.rs — Block Structure and Mining
// =============================================================================
//
// A block is a container that permanently records a group of transactions
// on the blockchain. Once mined and accepted by the network, it cannot be
// altered without redoing all the computational work for every subsequent block.
//
// WHAT MAKES BLOCKS TAMPER-EVIDENT (THE CHAINING MECHANISM):
//   Each block stores the hash of the block before it in `prev_hash`.
//   If you alter anything in an old block, its hash changes. That invalidates
//   the next block's `prev_hash` reference, which changes THAT block's hash,
//   which breaks the block after that... all the way to the tip. An attacker
//   would need to redo the proof-of-work mining for every block from the
//   tampered point forward — faster than the entire honest network. On any
//   meaningful network this is computationally impossible.
//
// BLOCK STRUCTURE:
//   ┌────────────────────────────────────┐
//   │  index       block number (0, 1, 2…) │
//   │  timestamp   milliseconds since epoch │
//   │  prev_hash   hash of previous block  │ ← the "chain" in blockchain
//   │  hash        fingerprint of this block│
//   │  nonce       proof-of-work solution   │
//   ├────────────────────────────────────┤
//   │  transactions[]                      │
//   │    [0] coinbase (mining reward)      │
//   │    [1…] user transactions            │
//   └────────────────────────────────────┘
//
// PROOF OF WORK (MINING):
//   To add a block, the miner must find a `nonce` value such that the block's
//   SHA-256 hash starts with N leading zeros (N = difficulty). There is no
//   shortcut — the miner tries nonces sequentially until one works. This costs
//   real electricity and time, making the chain expensive to forge.
// =============================================================================

use serde::{Serialize, Deserialize};
use crate::transaction::Transaction;
use crate::crypto;

/// A single block in the blockchain.
///
/// Serializable so blocks can be saved to disk (chain.json) and transmitted
/// to peers over the P2P network as JSON.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Block {
    /// Position of this block in the chain.
    /// Genesis block is index 0, then 1, 2, 3... in order.
    pub index: u64,

    /// Unix timestamp in milliseconds recording when this block was mined.
    /// Used for display purposes and future difficulty adjustment.
    pub timestamp: u64,

    /// The hash of the immediately preceding block in the chain.
    /// This field is what links blocks together — any change to a past block
    /// changes its hash, which makes this field incorrect, which cascades
    /// forward and invalidates every later block.
    pub prev_hash: String,

    /// This block's own SHA-256 hash — a fingerprint of all its contents.
    /// Computed by calculate_hash() after mining. When other nodes receive
    /// this block, they recompute the hash and reject it if it doesn't match.
    pub hash: String,

    /// The number that miners brute-force to satisfy the difficulty requirement.
    /// Mining tries nonce = 0, 1, 2, 3... until calculate_hash() produces
    /// a hash starting with the required number of leading zeros.
    pub nonce: u64,

    /// The list of transactions confirmed by this block.
    /// Always starts with the coinbase transaction (the miner's reward),
    /// followed by all user transactions that were waiting in the mempool.
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Returns the hardcoded genesis block — the identical starting point
    /// that every node on the network must begin from.
    ///
    /// WHY HARDCODE IT?
    ///   If each node generated its own genesis block using the current time,
    ///   every genesis block would have a different timestamp and therefore
    ///   a different hash. Nodes would immediately disagree on the chain's
    ///   starting point and could never validate each other's blocks.
    ///
    ///   By hardcoding a fixed timestamp, every node produces the exact same
    ///   genesis hash. This shared starting point is what makes the network
    ///   possible — it's the one fact every participant agrees on without
    ///   needing to communicate first.
    pub fn genesis() -> Self {
        let mut block = Block {
            index:        0,
            timestamp:    1700000000000, // fixed forever — never change this
            prev_hash:    "0".repeat(64), // no predecessor, so 64 zeros by convention
            hash:         String::new(),  // computed below
            nonce:        0,
            transactions: vec![],         // genesis carries no transactions
        };
        // Compute and store the hash — same result on every machine, every time
        block.hash = block.calculate_hash();
        block
    }

    /// Creates a new block with the given transactions, ready to be mined.
    ///
    /// After calling this, the block's hash won't yet meet the difficulty
    /// target. Call mine() to find the nonce that makes it valid.
    ///
    /// `index`        — this block's position (chain.len() at time of creation)
    /// `prev_hash`    — the hash of the chain's current tip block
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
        // Initial hash — will change as nonce is incremented during mining
        block.hash = block.calculate_hash();
        block
    }

    /// Computes the SHA-256 hash of this block's contents.
    ///
    /// All meaningful fields are included: index, timestamp, prev_hash, nonce,
    /// and the merkle root (which represents all transactions). The `hash`
    /// field itself is excluded since that's what we're computing.
    ///
    /// This is called once per nonce attempt during mining (potentially
    /// millions of times) and once by validating nodes to verify the block.
    pub fn calculate_hash(&self) -> String {
        let data = format!(
            "{}{}{}{}{}",
            self.index,
            self.timestamp,
            self.prev_hash,
            self.nonce,
            self.merkle_root() // a single hash representing ALL transactions
        );
        crypto::to_hex(&crypto::sha256(data.as_bytes()))
    }

    /// Summarizes all transactions in this block into a single 32-byte hash
    /// known as the Merkle root.
    ///
    /// HOW IT WORKS:
    ///   Each transaction is hashed individually. Then all those hashes are
    ///   concatenated and hashed together into one final root hash.
    ///   (A production blockchain uses a proper binary Merkle tree, but this
    ///   simplified approach achieves the same tamper-evidence property.)
    ///
    /// WHY IT MATTERS:
    ///   - Any change to any transaction in the block changes the Merkle root
    ///   - The Merkle root is included in calculate_hash(), so it affects the block hash
    ///   - Therefore, altering any transaction invalidates the block entirely
    ///   - The root is also used in light clients to prove a tx is in a block
    ///     without downloading all transactions
    pub fn merkle_root(&self) -> String {
        if self.transactions.is_empty() {
            // Empty block — use a placeholder hash of 32 zero bytes
            return crypto::to_hex(&[0u8; 32]);
        }

        // Step 1: hash each transaction individually by serializing it to JSON
        let tx_hashes: Vec<String> = self.transactions
            .iter()
            .map(|tx| {
                let json = serde_json::to_string(tx).unwrap();
                crypto::to_hex(&crypto::sha256(json.as_bytes()))
            })
            .collect();

        // Step 2: combine all transaction hashes into one root hash
        let combined = tx_hashes.join("");
        crypto::to_hex(&crypto::sha256(combined.as_bytes()))
    }

    /// Mines this block by trying nonces until the hash meets the difficulty target.
    ///
    /// The difficulty target requires the block hash to start with `difficulty`
    /// leading zeros. For example, difficulty 5 means the hash must start with
    /// "00000". Since we can't predict which nonce will produce a valid hash,
    /// we try them sequentially: 0, 1, 2, 3...
    ///
    /// This is Proof of Work — it proves that real computational effort was
    /// spent. Verifying the result takes one hash computation; finding it
    /// takes millions. This asymmetry is what secures the blockchain.
    ///
    /// DIFFICULTY SCALE:
    ///   Each additional leading zero makes mining ~16x harder on average.
    ///   Difficulty 3 ≈ 4,096 attempts     (instant)
    ///   Difficulty 5 ≈ 1,048,576 attempts (few seconds)
    ///   Difficulty 7 ≈ 268 million attempts (minutes)
    pub fn mine(&mut self, difficulty: usize) {
        // Build the target string once — e.g. "00000" for difficulty 5
        let target = "0".repeat(difficulty);
        println!("Mining block {}...", self.index);

        loop {
            self.hash = self.calculate_hash();

            if self.hash.starts_with(&target) {
                // A valid nonce was found — this block is now ready to broadcast
                println!("Mined! Nonce: {}, Hash: {}", self.nonce, self.hash);
                break;
            }

            // This nonce didn't work — increment and try again
            self.nonce += 1;
        }
    }
}
