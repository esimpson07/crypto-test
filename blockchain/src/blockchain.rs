// =============================================================================
// blockchain.rs — Chain State, Consensus Rules, and Supply Schedule
// =============================================================================
//
// This is the heart of the system. The Blockchain struct manages:
//
//   chain         the permanent ordered record of every confirmed block
//   mempool       transactions waiting to be picked up by a miner
//   utxo_set      each address's current spendable balance
//   tx_nonces     the last confirmed transaction nonce for each address
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
// NONCE TRACKING — REPLAY ATTACK PREVENTION:
//
//   tx_nonces maps each sender address to the highest nonce confirmed on chain.
//   When a new transaction arrives, its nonce must be exactly last + 1.
//   This means a replayed transaction (with an old, already-used nonce) is
//   rejected before it even reaches the mempool.
//
//   Like the UTXO set, tx_nonces is rebuilt by replaying the chain on load —
//   it is never stored directly, guaranteeing it always matches the chain.
//
// SUPPLY SCHEDULE:
//
//   Like Bitcoin, this chain has a fixed maximum supply and a halving
//   schedule. The block reward starts at INITIAL_REWARD and halves every
//   HALVING_INTERVAL blocks. Once MAX_SUPPLY coins exist, no more are
//   created — miners earn only transaction fees to keep running.
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
pub const DIFFICULTY: usize = 3;

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
/// Only `chain` and `mempool` are written to disk. All other fields are
/// derived by replaying the chain on load, guaranteeing they always stay
/// consistent with the transaction history.
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

    /// Address → last confirmed nonce map (replay attack prevention).
    ///
    /// Tracks the highest nonce that has been confirmed on chain for each
    /// sender address. When a new transaction arrives, its nonce must be
    /// exactly last_confirmed_nonce + 1. Replayed transactions have old
    /// nonces that fail this check and are rejected.
    ///
    /// Rebuilt from scratch on every chain load alongside the UTXO set.
    /// Never stored directly to disk.
    pub tx_nonces: HashMap<String, u64>,

    /// Total coins in existence. Increases by the block reward each mine.
    /// Never exceeds MAX_SUPPLY.
    pub total_supply: u64,
}

impl Blockchain {
    /// Creates a fresh blockchain starting from the hardcoded genesis block.
    pub fn new() -> Self {
        Blockchain {
            chain:        vec![Block::genesis()],
            difficulty:   DIFFICULTY,
            mempool:      vec![],
            utxo_set:     HashMap::new(),
            tx_nonces:    HashMap::new(),
            total_supply: 0,
        }
    }

    /// Returns a reference to the most recently confirmed block.
    /// Safe to unwrap — the chain always contains at least the genesis block.
    pub fn latest_block(&self) -> &Block {
        self.chain.last().unwrap()
    }

    /// Returns the current spendable balance for an address.
    /// Returns 0 for unknown addresses rather than an error.
    pub fn get_balance(&self, address: &str) -> u64 {
        *self.utxo_set.get(address).unwrap_or(&0)
    }

    /// Returns the next valid nonce for a given sender address.
    ///
    /// This is what main.rs calls before building a new transaction:
    ///   let nonce = chain.next_nonce(&wallet.address());
    ///   let tx = Transaction::new(from, to, amount, nonce);
    ///
    /// Returns last_confirmed_nonce + 1, or 1 if the address has never sent.
    /// (Nonce 0 is reserved — the first transaction from any address uses 1.)
    pub fn next_nonce(&self, address: &str) -> u64 {
        self.tx_nonces.get(address).copied().unwrap_or(0) + 1
    }

    /// Calculates the block reward for the next block to be mined.
    ///
    /// Uses bit-shifting to implement halving:
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

    /// Updates UTXO balances and confirmed nonces from a list of transactions.
    ///
    /// Called internally after a block has been fully validated. Updates:
    ///   - utxo_set: deduct from sender, credit recipient
    ///   - tx_nonces: record the confirmed nonce for each sender
    ///
    /// Private — only called after block validation, never on unconfirmed txs.
    fn apply_transactions(&mut self, transactions: &[Transaction]) {
        for tx in transactions {
            if tx.from != "coinbase" {
                // Deduct from sender
                let sender = self.utxo_set.entry(tx.sender_address()).or_insert(0);
                *sender -= tx.amount;

                // Record the confirmed nonce for this sender address.
                // This is what future nonce checks compare against.
                self.tx_nonces.insert(tx.sender_address(), tx.nonce);
            }
            // Credit recipient
            let recipient = self.utxo_set.entry(tx.to.clone()).or_insert(0);
            *recipient += tx.amount;
        }
    }

    /// Validates and adds a transaction to the mempool.
    ///
    /// REJECTION REASONS (checked in order):
    ///   1. Invalid Dilithium3 signature
    ///   2. Wrong nonce — must be exactly last_confirmed_nonce + 1
    ///      Catches replay attacks: any replayed tx has a stale nonce
    ///   3. Insufficient confirmed balance
    ///   4. Insufficient available balance accounting for other pending sends
    ///      (prevents queuing multiple sends that together exceed the balance)
    ///
    /// Accepted transactions wait until mine_block() confirms them.
    pub fn add_transaction(&mut self, tx: Transaction) -> Result<(), String> {
        // Check 1 — signature must be valid
        if !tx.is_valid() {
            return Err("Invalid transaction signature".to_string());
        }

        let sender_addr = tx.sender_address();

        // Check 2 — nonce must be exactly last confirmed nonce + 1
        // This is the replay attack prevention check.
        // Any transaction that was already confirmed has its nonce recorded in
        // tx_nonces. Rebroadcasting it produces a nonce that is too low.
        let expected_nonce = self.next_nonce(&sender_addr);
        if tx.nonce != expected_nonce {
            return Err(format!(
                "Invalid nonce for {} — expected {}, got {} \
                 (replay attack prevention: each transaction must use the next nonce)",
                &sender_addr[..8], expected_nonce, tx.nonce
            ));
        }

        // Check 3 — sender must have enough confirmed coins
        let balance = self.get_balance(&sender_addr);
        if balance < tx.amount {
            return Err(format!(
                "Insufficient funds — {} has {} coins, tried to send {}",
                &sender_addr[..8], balance, tx.amount
            ));
        }

        // Check 4 — account for coins already committed in other pending sends
        // Prevents queuing two sends from the same wallet that together exceed
        // the available balance (each would pass check 3 independently)
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

    /// Mines a new block, awarding the block reward to `miner_address`.
    ///
    /// Steps:
    ///   1. Calculate the current reward (0 if supply exhausted)
    ///   2. Create a coinbase transaction crediting the miner
    ///   3. Bundle coinbase + all mempool transactions into a new block
    ///   4. Run proof-of-work (the slow part — tries nonces until valid hash)
    ///   5. Update total_supply, UTXO balances, and confirmed nonces
    ///   6. Append the confirmed block to the chain
    ///
    /// `miner_address` — compact address (wallet.address()) receiving the reward
    pub fn mine_block(&mut self, miner_address: String) {
        if self.supply_exhausted() {
            println!("Max supply of {} coins reached — mining with no reward", MAX_SUPPLY);
            println!("Blocks still confirm transactions but produce no new coins");
        }

        let reward = self.current_reward();
        println!("Block reward:    {} coins", reward);
        println!("Total supply:    {}/{}", self.total_supply, MAX_SUPPLY);
        println!("Difficulty:      {} leading zeros required", self.difficulty);

        // Build transaction list: coinbase first, then all pending transactions
        let mut transactions = vec![];
        if reward > 0 {
            // Coinbase nonce is 0 — coinbase transactions are not nonce-tracked
            transactions.push(Transaction::new(
                "coinbase".to_string(),
                miner_address,
                reward,
                0,
            ));
        }
        transactions.extend(self.mempool.drain(..));

        // Build and mine the block (proof-of-work happens here)
        let prev_hash = self.latest_block().hash.clone();
        let index     = self.chain.len() as u64;
        let mut block = Block::new(index, prev_hash, transactions.clone());
        block.mine(self.difficulty);

        // Update all state: supply, UTXO balances, and confirmed nonces
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
    /// Returns true if everything is consistent.
    pub fn is_valid(&self) -> bool {
        for i in 1..self.chain.len() {
            let current  = &self.chain[i];
            let previous = &self.chain[i - 1];
            if current.hash != current.calculate_hash()              { return false; }
            if current.prev_hash != previous.hash                    { return false; }
            if !current.transactions.iter().all(|tx| tx.is_valid()) { return false; }
        }
        true
    }
}
