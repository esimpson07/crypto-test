// =============================================================================
// blockchain.rs — Chain State, Consensus Rules, and Supply Schedule
// =============================================================================
//
// This is the heart of the system. The Blockchain struct manages:
//
//   chain         the permanent ordered record of every confirmed block
//   mempool       transactions waiting to be picked up by a miner
//   utxo_set      each address's current spendable balance
//   total_supply  running count of all coins ever created
//
// THE UTXO SET:
//
//   UTXO stands for "Unspent Transaction Output." Instead of storing balances
//   like a bank account, we track outputs from transactions that haven't been
//   spent yet. Your balance is the sum of all outputs pointing to your address.
//
//   We simplify this to HashMap<address, balance> rather than tracking
//   individual outputs. The simplification is safe because balances are
//   never stored directly — they are always rebuilt from the transaction
//   history when the chain loads. Corrupt or tampered balance data is
//   automatically corrected on the next startup.
//
// SUPPLY SCHEDULE:
//
//   Like Bitcoin, this chain has a fixed maximum supply and a halving
//   schedule. The block reward starts at INITIAL_REWARD and halves every
//   HALVING_INTERVAL blocks. Once MAX_SUPPLY coins exist, no more are
//   created — miners would earn only transaction fees to keep running.
//
// TO CUSTOMIZE YOUR CRYPTOCURRENCY:
//
//   Edit the four constants directly below. After changing any constant,
//   delete chain.json and any .mempool files before running — the old
//   chain was built under different rules and will be inconsistent.
// =============================================================================

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::block::Block;
use crate::transaction::Transaction;

// =============================================================================
// Supply Constants
// =============================================================================

/// Proof-of-work difficulty — how many leading zeros the block hash needs.
/// Each additional zero makes mining roughly 16x harder.
///   3 = instant  |  5 = few seconds  |  6 = ~30 seconds  |  7 = minutes
pub const DIFFICULTY: usize = 5;

/// Coins awarded to the miner of each block, starting value.
/// Halves every HALVING_INTERVAL blocks until it eventually reaches zero.
pub const INITIAL_REWARD: u64 = 50;

/// Blocks between each reward halving.
/// Bitcoin uses 210,000 (~4 years). Smaller values are useful for testing.
/// Reward schedule: 50 → 25 → 12 → 6 → 3 → 1 → 0
pub const HALVING_INTERVAL: u64 = 10;

/// Hard cap — the maximum coins that will ever exist.
/// Once total_supply reaches this, mining produces no further rewards.
pub const MAX_SUPPLY: u64 = 1_000;

// =============================================================================
// Blockchain
// =============================================================================

/// The complete blockchain state for one network instance.
///
/// Only `chain` and `mempool` are written to disk. The `utxo_set` and
/// `total_supply` are derived fields always rebuilt from the chain on load,
/// guaranteeing they stay consistent with the transaction history.
#[derive(Serialize, Deserialize)]
pub struct Blockchain {
    /// All confirmed blocks in order, starting with the genesis block.
    /// Blocks are appended and never removed or reordered.
    pub chain: Vec<Block>,

    /// Current proof-of-work difficulty. Loaded from the DIFFICULTY constant.
    pub difficulty: usize,

    /// Signed transactions waiting to be included in the next block.
    /// Populated by add_transaction(). Drained and cleared by mine_block().
    /// Saved to a .mempool sidecar file so pending transactions survive restarts.
    pub mempool: Vec<Transaction>,

    /// Address → balance map (the simplified UTXO set).
    /// Keys are compact 64-char addresses (SHA-256 of public key).
    /// Rebuilt from scratch on every chain load — never trusted from disk.
    pub utxo_set: HashMap<String, u64>,

    /// Total coins in existence. Increases by the block reward each mine.
    /// Never exceeds MAX_SUPPLY.
    pub total_supply: u64,
}

impl Blockchain {
    /// Creates a fresh blockchain starting from the hardcoded genesis block.
    ///
    /// The genesis block is identical on every node. This shared starting
    /// point is what allows nodes to validate each other's blocks and
    /// agree on a canonical chain without any prior communication.
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
    /// Safe to unwrap — the chain always contains at least the genesis block.
    pub fn latest_block(&self) -> &Block {
        self.chain.last().unwrap()
    }

    /// Returns the current spendable balance for an address.
    ///
    /// Returns 0 for unknown addresses rather than an error — an address
    /// with no received coins is treated the same as an unknown address.
    pub fn get_balance(&self, address: &str) -> u64 {
        *self.utxo_set.get(address).unwrap_or(&0)
    }

    /// Calculates the block reward for the next block to be mined.
    ///
    /// Uses bit-shifting to implement halving efficiently:
    ///   INITIAL_REWARD >> halvings  =  divide by 2 for each halving
    ///
    ///   Blocks  0- 9:  50 >> 0 = 50 coins
    ///   Blocks 10-19:  50 >> 1 = 25 coins
    ///   Blocks 20-29:  50 >> 2 = 12 coins
    ///   Blocks 30-39:  50 >> 3 =  6 coins  (and so on)
    ///
    /// Also capped at remaining supply so total_supply never exceeds MAX_SUPPLY.
    pub fn current_reward(&self) -> u64 {
        let halvings  = self.chain.len() as u64 / HALVING_INTERVAL;
        let reward    = INITIAL_REWARD >> halvings;
        let remaining = MAX_SUPPLY.saturating_sub(self.total_supply);
        reward.min(remaining)
    }

    /// Returns true when the maximum supply has been reached.
    pub fn supply_exhausted(&self) -> bool {
        self.total_supply >= MAX_SUPPLY
    }

    /// Updates UTXO balances by applying a confirmed list of transactions.
    ///
    /// For each transaction:
    ///   Coinbase   →  credit recipient only (new coins enter circulation)
    ///   Regular    →  deduct from sender AND credit recipient
    ///
    /// Private — only called internally after a block has been fully validated,
    /// never on individual unconfirmed transactions.
    fn apply_transactions(&mut self, transactions: &[Transaction]) {
        for tx in transactions {
            if tx.from != "coinbase" {
                let sender = self.utxo_set.entry(tx.sender_address()).or_insert(0);
                *sender -= tx.amount;
            }
            let recipient = self.utxo_set.entry(tx.to.clone()).or_insert(0);
            *recipient += tx.amount;
        }
    }

    /// Validates and adds a transaction to the mempool.
    ///
    /// A transaction is rejected if:
    ///   1. Its Dilithium3 signature is invalid
    ///   2. The sender's confirmed balance is less than the amount
    ///   3. The sender's balance minus other pending transactions is insufficient
    ///      (prevents queuing multiple sends that together exceed the balance)
    ///
    /// Accepted transactions wait until mine_block() picks them up.
    pub fn add_transaction(&mut self, tx: Transaction) -> Result<(), String> {
        if !tx.is_valid() {
            return Err("Invalid transaction signature".to_string());
        }

        let sender_addr = tx.sender_address();
        let balance     = self.get_balance(&sender_addr);

        if balance < tx.amount {
            return Err(format!(
                "Insufficient funds — {} has {} coins, tried to send {}",
                &sender_addr[..8], balance, tx.amount
            ));
        }

        // Sum coins already committed in other pending transactions from this sender
        let pending: u64 = self.mempool
            .iter()
            .filter(|t| t.from == tx.from)
            .map(|t| t.amount)
            .sum();

        if balance < tx.amount + pending {
            return Err(format!(
                "Insufficient funds — {} coins balance, {} already pending",
                balance, pending
            ));
        }

        self.mempool.push(tx);
        Ok(())
    }

    /// Mines a new block and awards the block reward to `miner_address`.
    ///
    /// Steps:
    ///   1. Calculate the current reward (0 if supply exhausted)
    ///   2. Create a coinbase transaction crediting the miner
    ///   3. Bundle coinbase + all mempool transactions into a new block
    ///   4. Run proof-of-work mining (the slow part — tries nonces until valid)
    ///   5. Update total_supply and all balances via apply_transactions()
    ///   6. Append the confirmed block to the chain
    ///
    /// `miner_address` — compact address (wallet.address()) that receives the reward
    pub fn mine_block(&mut self, miner_address: String) {
        if self.supply_exhausted() {
            println!("Max supply of {} coins reached — mining with no reward", MAX_SUPPLY);
            println!("Blocks still confirm transactions but produce no new coins");
        }

        let reward = self.current_reward();
        println!("Block reward:    {} coins", reward);
        println!("Total supply:    {}/{}", self.total_supply, MAX_SUPPLY);
        println!("Difficulty:      {} leading zeros required", self.difficulty);

        // Build transaction list: coinbase reward first, then all pending transactions
        let mut transactions = vec![];
        if reward > 0 {
            transactions.push(Transaction::new(
                "coinbase".to_string(),
                miner_address,
                reward,
            ));
        }
        transactions.extend(self.mempool.drain(..));

        // Build and mine the block
        let prev_hash = self.latest_block().hash.clone();
        let index     = self.chain.len() as u64;
        let mut block = Block::new(index, prev_hash, transactions.clone());
        block.mine(self.difficulty); // ← expensive — may take seconds

        // Update state and append to chain
        self.total_supply += reward;
        self.apply_transactions(&transactions);
        self.chain.push(block);

        println!("New total supply: {}/{}", self.total_supply, MAX_SUPPLY);
    }

    /// Validates the entire chain from genesis to the current tip.
    ///
    /// For each block after genesis, checks:
    ///   1. Hash integrity   — stored hash matches recalculating it now
    ///   2. Chain linkage    — prev_hash matches the actual previous block's hash
    ///   3. Transaction sigs — every non-coinbase transaction is properly signed
    ///
    /// Returns true if everything is consistent. Used by the `chain` command
    /// and when deciding whether to adopt a chain received from a peer.
    pub fn is_valid(&self) -> bool {
        for i in 1..self.chain.len() {
            let current  = &self.chain[i];
            let previous = &self.chain[i - 1];
            if current.hash != current.calculate_hash()    { return false; }
            if current.prev_hash != previous.hash          { return false; }
            if !current.transactions.iter().all(|tx| tx.is_valid()) { return false; }
        }
        true
    }
}
