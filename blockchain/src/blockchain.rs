// =============================================================================
// blockchain.rs — The Blockchain and Consensus Rules
// =============================================================================
//
// This is the heart of the system. The Blockchain struct ties everything together:
//
//   chain        — the permanent, ordered record of every confirmed block
//   mempool      — transactions waiting to be picked up by a miner
//   utxo_set     — each address's current spendable balance
//   total_supply — running total of all coins ever created
//
// THE UTXO SET EXPLAINED:
//   UTXO stands for "Unspent Transaction Output." Real blockchains like Bitcoin
//   don't store balances directly. Instead they track individual coin outputs
//   that haven't been spent yet — your balance is the sum of all outputs
//   pointing to your address that nobody has used as an input yet.
//
//   We simplify this to a HashMap<address, balance> which achieves the same
//   effect: balances are always derived from the transaction history, never
//   stored directly. If the file is lost or corrupted, we can always rebuild
//   exact balances by replaying every transaction from genesis (chain_store.rs).
//
// SUPPLY SCHEDULE:
//   Like Bitcoin, this blockchain has a fixed maximum supply and a halving
//   schedule. The block reward starts at INITIAL_REWARD and halves every
//   HALVING_INTERVAL blocks, eventually reaching zero. Once MAX_SUPPLY coins
//   exist, no more are ever created — miners would earn only fees (not yet
//   implemented) to continue securing the network.
//
// CUSTOMIZATION:
//   Change the constants below to define your cryptocurrency's economics.
// =============================================================================

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::block::Block;
use crate::transaction::Transaction;

// =============================================================================
// Economic Constants — Edit these to customize your cryptocurrency
// =============================================================================

/// Number of leading zeros required in a block's SHA-256 hash.
/// This is the proof-of-work difficulty. Each additional zero makes mining
/// roughly 16x harder. Adjust to target your desired block time.
///   3 = instant  |  4 = <1 second  |  5 = few seconds  |  6 = ~30 seconds
pub const DIFFICULTY: usize = 5;

/// Coins awarded to the miner of the first block.
/// Halves every HALVING_INTERVAL blocks until it reaches zero.
pub const INITIAL_REWARD: u64 = 50;

/// How many blocks between each reward halving.
/// Bitcoin uses 210,000 (roughly 4 years). Use a smaller number for testing.
/// Schedule: 50 → 25 → 12 → 6 → 3 → 1 → 0
pub const HALVING_INTERVAL: u64 = 10;

/// The absolute hard cap on total coins that will ever exist.
/// Once total_supply reaches this, mining produces no further rewards.
/// Miners can still mine blocks to confirm transactions (fee-only mining).
pub const MAX_SUPPLY: u64 = 1_000;

// =============================================================================
// Blockchain Struct
// =============================================================================

/// The main blockchain — holds all state for one network instance.
///
/// Serializable so the chain can be saved/loaded via chain_store.rs.
/// Only `chain` and `mempool` are actually written to disk. The `utxo_set`
/// and `total_supply` are derived fields rebuilt from the chain on load —
/// this guarantees they're always consistent with the transaction history.
#[derive(Serialize, Deserialize)]
pub struct Blockchain {
    /// The ordered, immutable record of all confirmed blocks.
    /// Index 0 is always the hardcoded genesis block. New blocks are appended
    /// to the end. Blocks are never removed or reordered once added.
    pub chain: Vec<Block>,

    /// The current proof-of-work difficulty (leading zeros required).
    /// Loaded from the DIFFICULTY constant on startup.
    pub difficulty: usize,

    /// Unconfirmed transactions waiting to be included in the next block.
    /// Populated by add_transaction(). Drained by mine_block().
    /// Saved to a separate .mempool file so pending transactions survive
    /// program restarts (see chain_store.rs).
    pub mempool: Vec<Transaction>,

    /// Maps each address to its current spendable coin balance.
    /// Rebuilt by replaying all transactions whenever the chain loads from disk.
    /// Keys are compact addresses (SHA-256 of public key, 64 hex chars).
    pub utxo_set: HashMap<String, u64>,

    /// The total number of coins that currently exist across all wallets.
    /// Starts at 0 and increases by the block reward each time a block is mined.
    /// Never exceeds MAX_SUPPLY.
    pub total_supply: u64,
}

impl Blockchain {
    /// Creates a fresh blockchain beginning from the hardcoded genesis block.
    ///
    /// The genesis block is identical on every node — this shared starting
    /// point allows nodes to validate each other's blocks and agree on
    /// the canonical chain.
    pub fn new() -> Self {
        Blockchain {
            chain:        vec![Block::genesis()],
            difficulty:   DIFFICULTY,
            mempool:      vec![],
            utxo_set:     HashMap::new(),
            total_supply: 0,
        }
    }

    /// Returns a reference to the most recently confirmed block.
    ///
    /// Used when building new blocks (to get prev_hash) and when validating
    /// incoming blocks from peers (to check their prev_hash matches ours).
    /// Safe to unwrap — the chain always contains at least the genesis block.
    pub fn latest_block(&self) -> &Block {
        self.chain.last().unwrap()
    }

    /// Returns the current spendable balance for a given address.
    ///
    /// Returns 0 for unknown addresses rather than an error, making balance
    /// checks simpler at all call sites. An address with no received coins
    /// is indistinguishable from an unknown address.
    pub fn get_balance(&self, address: &str) -> u64 {
        *self.utxo_set.get(address).unwrap_or(&0)
    }

    /// Calculates the block reward for the next block to be mined.
    ///
    /// The reward halves every HALVING_INTERVAL blocks using bit-shifting:
    ///   INITIAL_REWARD >> halvings  =  divide by 2 for each halving
    ///
    /// Example with INITIAL_REWARD=50, HALVING_INTERVAL=10:
    ///   Blocks  0- 9:  50 >> 0 = 50 coins
    ///   Blocks 10-19:  50 >> 1 = 25 coins
    ///   Blocks 20-29:  50 >> 2 = 12 coins
    ///   Blocks 30-39:  50 >> 3 =  6 coins  ... and so on
    ///
    /// Also capped at the remaining supply so total_supply never exceeds
    /// MAX_SUPPLY, even if the calculated reward would push it over.
    pub fn current_reward(&self) -> u64 {
        let halvings  = self.chain.len() as u64 / HALVING_INTERVAL;
        let reward    = INITIAL_REWARD >> halvings;
        let remaining = MAX_SUPPLY.saturating_sub(self.total_supply);
        reward.min(remaining) // never give out more than what's left
    }

    /// Returns true when all coins have been mined (total_supply >= MAX_SUPPLY).
    ///
    /// After this point, mine_block() still creates blocks to confirm
    /// transactions, but issues no coinbase reward.
    pub fn supply_exhausted(&self) -> bool {
        self.total_supply >= MAX_SUPPLY
    }

    /// Applies a list of confirmed transactions to the UTXO set.
    ///
    /// Called internally after a block is successfully mined or accepted from
    /// a peer. For each transaction:
    ///   - Coinbase: credit the recipient only (new coins enter circulation)
    ///   - Regular:  deduct from sender AND credit recipient
    ///
    /// Private — should only be called after full block validation so we never
    /// apply transactions that haven't been properly confirmed.
    fn apply_transactions(&mut self, transactions: &[Transaction]) {
        for tx in transactions {
            if tx.from != "coinbase" {
                // Deduct from sender — balance check already passed in add_transaction()
                let sender = self.utxo_set.entry(tx.sender_address()).or_insert(0);
                *sender -= tx.amount;
            }
            // Credit recipient — creates their entry in the map if it doesn't exist
            let recipient = self.utxo_set.entry(tx.to.clone()).or_insert(0);
            *recipient += tx.amount;
        }
    }

    /// Validates and adds a transaction to the mempool (the pending queue).
    ///
    /// REJECTION REASONS:
    ///   1. Invalid signature — the sender didn't authorize this transfer
    ///   2. Insufficient confirmed balance — sender can't cover the amount
    ///   3. Insufficient available balance — sender has enough confirmed coins
    ///      but has already committed them in other pending mempool transactions
    ///      (this prevents double-spending before a block is mined)
    ///
    /// Accepted transactions wait in the mempool until mine_block() picks them
    /// up, includes them in a block, and confirms them on the chain.
    pub fn add_transaction(&mut self, tx: Transaction) -> Result<(), String> {
        // Check 1 — Dilithium3 signature must be valid for the sender's public key
        if !tx.is_valid() {
            return Err("Invalid transaction signature".to_string());
        }

        // Check 2 — sender must have enough CONFIRMED coins
        // sender_address() hashes tx.from (full public key) to get the address
        // used as the key in utxo_set
        let sender_addr = tx.sender_address();
        let balance = self.get_balance(&sender_addr);
        if balance < tx.amount {
            return Err(format!(
                "Insufficient funds — {} has {} coins but tried to send {}",
                &sender_addr[..8], balance, tx.amount
            ));
        }

        // Check 3 — account for coins already committed in other pending transactions
        // Two sends from the same wallet could both pass check 2 individually
        // but together exceed the balance. This prevents that.
        let pending_spend: u64 = self.mempool
            .iter()
            .filter(|t| t.from == tx.from) // compare full public keys to identify same sender
            .map(|t| t.amount)
            .sum();

        if balance < tx.amount + pending_spend {
            return Err(format!(
                "Insufficient funds — {} coins balance but {} already pending in mempool",
                balance, pending_spend
            ));
        }

        // All checks passed — add to the waiting queue
        self.mempool.push(tx);
        Ok(())
    }

    /// Mines a new block, awarding the miner's address the current block reward.
    ///
    /// STEPS:
    ///   1. Calculate the current reward (may be 0 if supply is exhausted)
    ///   2. Create a coinbase transaction crediting the miner
    ///   3. Pull all pending transactions from the mempool into the block
    ///   4. Build and mine the block (proof-of-work — the slow part)
    ///   5. Update total_supply and all wallet balances
    ///   6. Append the confirmed block to the chain
    ///
    /// `miner_address` — the compact address (SHA-256 of public key) that
    ///                   receives the block reward. Passed in from main.rs
    ///                   as wallet.address().
    pub fn mine_block(&mut self, miner_address: String) {
        if self.supply_exhausted() {
            println!("Max supply of {} coins reached — mining with no reward", MAX_SUPPLY);
            println!("Blocks still confirm transactions but produce no new coins");
        }

        let reward = self.current_reward();

        // Show the miner what they're working toward before the slow part starts
        println!("Block reward:    {} coins", reward);
        println!("Total supply:    {}/{}", self.total_supply, MAX_SUPPLY);
        println!("Difficulty:      {} leading zeros required", self.difficulty);

        // Build the transaction list: coinbase reward first, then mempool transactions
        let mut transactions = vec![];
        if reward > 0 {
            // The coinbase transaction creates new coins — "coinbase" as sender
            // means no signature is required (validated by is_valid() in transaction.rs)
            transactions.push(Transaction::new(
                "coinbase".to_string(),
                miner_address,
                reward,
            ));
        }
        // drain(..) moves all mempool transactions into this block and empties the mempool
        transactions.extend(self.mempool.drain(..));

        // Build the block structure (nonce=0, not yet valid)
        let prev_hash = self.latest_block().hash.clone();
        let index     = self.chain.len() as u64;
        let mut block = Block::new(index, prev_hash, transactions.clone());

        // ← THE SLOW PART: try nonces until hash starts with `difficulty` zeros
        block.mine(self.difficulty);

        // Update supply counter and all wallet balances
        self.total_supply += reward;
        self.apply_transactions(&transactions);

        // The block is now confirmed — add it to the permanent chain
        self.chain.push(block);

        println!("New total supply: {}/{}", self.total_supply, MAX_SUPPLY);
    }

    /// Validates the entire chain from genesis to the current tip.
    ///
    /// For each block after genesis, verifies three things:
    ///   1. HASH INTEGRITY   — the stored hash matches recalculating it now
    ///                         (detects any modification to block contents)
    ///   2. CHAIN LINKAGE    — prev_hash matches the actual previous block's hash
    ///                         (detects insertions, deletions, or reordering)
    ///   3. TRANSACTION SIGS — every non-coinbase transaction has a valid signature
    ///                         (detects unauthorized coin transfers)
    ///
    /// Returns true if everything is consistent, false if any check fails.
    /// Used by the `chain` command and could be used to reject a peer's chain.
    pub fn is_valid(&self) -> bool {
        for i in 1..self.chain.len() {
            let current  = &self.chain[i];
            let previous = &self.chain[i - 1];

            // Check 1: block contents unchanged since mining
            if current.hash != current.calculate_hash() {
                return false;
            }

            // Check 2: this block correctly references the one before it
            if current.prev_hash != previous.hash {
                return false;
            }

            // Check 3: every transaction in this block was properly authorized
            if !current.transactions.iter().all(|tx| tx.is_valid()) {
                return false;
            }
        }
        true
    }
}
