// =============================================================================
// blockchain.rs — Chain State, PoS Consensus, Slashing, Fork Choice
// =============================================================================
//
// NEW IN THIS VERSION:
//
//   GENESIS ALLOCATION
//     Blockchain::new() accepts a genesis config that pre-funds addresses
//     and registers them as validators with their full public keys. This
//     solves the bootstrap problem completely — no dev commands needed to
//     start the network.
//
//   SLASHING — double-sign detection and punishment
//     seen_validator_blocks: HashMap<(validator_address, block_height), block_hash>
//     Tracks every block hash a validator has signed at each height. When a
//     node receives a second valid block from the same validator at the same
//     height with a different hash, it calls slash_validator(), which:
//       1. Creates a SlashEvidence proof (both hashes + both signatures)
//       2. Burns SLASH_BURN_FRACTION of the offender's stake
//       3. Awards SLASH_REPORTER_REWARD coins to the whistleblower
//       4. Queues a Slash transaction into the mempool for on-chain recording
//       5. Removes the offender from the active validator set
//
//   FORK CHOICE — LMD-GHOST tiebreaker
//     When two chains have the same length, prefer the one whose tip block
//     has the lower hash value (lexicographic). This is a simplified but
//     deterministic approximation of LMD-GHOST's "heaviest subtree" rule.
//     All nodes apply the same rule so they always converge to the same
//     canonical chain without coordination.
//
//   IS_VALID() FIXED
//     Blocks from unknown validators are now REJECTED rather than silently
//     passed. The only exceptions are "genesis" and "dev" blocks which are
//     structurally special and handled explicitly.
//
//   MINE-AND-BROADCAST SYNC FIXED
//     rebuild_derived_state() centralises all state reconstruction logic.
//     Both load_chain and mine-and-broadcast call the same function,
//     eliminating the duplicate replay loop that existed before.
// =============================================================================

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::block::Block;
use crate::transaction::{Transaction, TxKind, SlashEvidence};
use crate::crypto;

// =============================================================================
// Constants
// =============================================================================

pub const INITIAL_REWARD:  u64  = 1;
pub const HALVING_INTERVAL: u64 = 10_000;
pub const MAX_SUPPLY:       u64 = 1_000_000;
pub const MIN_STAKE:        u64 = 1_000;
pub const UNBONDING_BLOCKS: u64 = 5;
pub const SLOT_SECONDS:     u64 = 5;

/// Fraction of slashed stake that is burned (removed from supply entirely).
/// The remainder goes to the whistleblower. 25% burn, 75% reward.
pub const SLASH_BURN_FRACTION: u64 = 25; // percent

// =============================================================================
// Genesis Config
// =============================================================================

/// Pre-funded account in the genesis block.
pub struct GenesisAccount {
    /// Compact address (SHA-256 of public key).
    pub address:    String,
    /// Raw Dilithium3 public key bytes — required to verify block signatures.
    pub public_key: Vec<u8>,
    /// Coins credited to the spendable balance at genesis.
    pub balance:    u64,
    /// Coins locked as validator stake at genesis (0 = not a validator).
    pub stake:      u64,
}

// =============================================================================
// Supporting Types
// =============================================================================

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PendingUnstake {
    pub address:          String,
    pub amount:           u64,
    pub release_at_block: u64,
}

// =============================================================================
// Blockchain
// =============================================================================

#[derive(Serialize, Deserialize)]
pub struct Blockchain {
    pub chain:             Vec<Block>,
    pub mempool:           Vec<Transaction>,
    pub utxo_set:          HashMap<String, u64>,
    pub tx_nonces:         HashMap<String, u64>,
    pub validators:        HashMap<String, u64>,
    pub validator_pubkeys: HashMap<String, Vec<u8>>,
    pub pending_unstake:   Vec<PendingUnstake>,
    pub total_supply:      u64,

    /// Tracks (validator_address, block_height) -> block_hash for every
    /// block signature we have witnessed. Used for double-sign detection.
    /// Rebuilt from chain on load.
    pub seen_validator_blocks: HashMap<(String, u64), String>,

    /// Set of addresses that have already been slashed and removed.
    /// Prevents double-slashing the same offense.
    pub slashed_validators: std::collections::HashSet<String>,
}

impl Blockchain {
    // =========================================================================
    // Construction
    // =========================================================================

    /// Creates a chain from genesis with pre-funded accounts and validators.
    ///
    /// Each account's balance is written as a coinbase Transfer transaction,
    /// and each stake is written as a coinbase Stake transaction, both into
    /// the genesis block. This means rebuild_derived_state() correctly
    /// reconstructs all balances and validator registrations on every load
    /// — the genesis state is encoded in the block history, not just in memory.
    pub fn new_with_genesis(accounts: Vec<GenesisAccount>) -> Self {
        let mut transactions: Vec<Transaction> = vec![];

        for account in &accounts {
            // Credit spendable balance
            if account.balance > 0 {
                transactions.push(Transaction::new_reward(
                    account.address.clone(),
                    account.balance,
                ));
            }
            // Register as validator — coinbase Stake encodes public key in `from`
            // by using a special "genesis:<pubkey_hex>" sentinel so rebuild can
            // store the public key in validator_pubkeys.
            if account.stake >= MIN_STAKE {
                transactions.push(Transaction {
                    kind:           TxKind::Stake,
                    from:           format!("genesis:{}", hex::encode(&account.public_key)),
                    to:             account.address.clone(),
                    amount:         account.stake,
                    nonce:          0,
                    signature:      None,
                    slash_evidence: None,
                });
            }
        }

        let mut genesis_block = Block::genesis();
        genesis_block.transactions = transactions;
        genesis_block.hash = genesis_block.calculate_hash();

        let mut chain = Blockchain {
            chain:                 vec![genesis_block],
            mempool:               vec![],
            utxo_set:              HashMap::new(),
            tx_nonces:             HashMap::new(),
            validators:            HashMap::new(),
            validator_pubkeys:     HashMap::new(),
            pending_unstake:       vec![],
            total_supply:          0,
            seen_validator_blocks: HashMap::new(),
            slashed_validators:    std::collections::HashSet::new(),
        };

        // Replay genesis block transactions to populate all derived state
        chain.rebuild_derived_state();
        chain
    }

    /// Creates an empty chain with no genesis accounts.
    /// Used when loading from disk — genesis accounts are reconstructed
    /// by replaying the chain, not by calling this.
    pub fn new() -> Self {
        Blockchain {
            chain:                 vec![Block::genesis()],
            mempool:               vec![],
            utxo_set:              HashMap::new(),
            tx_nonces:             HashMap::new(),
            validators:            HashMap::new(),
            validator_pubkeys:     HashMap::new(),
            pending_unstake:       vec![],
            total_supply:          0,
            seen_validator_blocks: HashMap::new(),
            slashed_validators:    std::collections::HashSet::new(),
        }
    }

    // =========================================================================
    // Accessors
    // =========================================================================

    pub fn latest_block(&self) -> &Block {
        self.chain.last().unwrap()
    }

    pub fn get_balance(&self, address: &str) -> u64 {
        *self.utxo_set.get(address).unwrap_or(&0)
    }

    pub fn get_stake(&self, address: &str) -> u64 {
        *self.validators.get(address).unwrap_or(&0)
    }

    pub fn next_nonce(&self, address: &str) -> u64 {
        self.tx_nonces.get(address).copied().unwrap_or(0) + 1
    }

    pub fn total_staked(&self) -> u64 {
        self.validators.values().sum()
    }

    pub fn current_reward(&self) -> u64 {
        let halvings  = self.chain.len() as u64 / HALVING_INTERVAL;
        let reward    = INITIAL_REWARD >> halvings;
        let remaining = MAX_SUPPLY.saturating_sub(self.total_supply);
        reward.min(remaining)
    }

    pub fn supply_exhausted(&self) -> bool {
        self.total_supply >= MAX_SUPPLY
    }

    // =========================================================================
    // Validator Selection — RANDAO-lite
    // =========================================================================

    pub fn select_validator(&self, block_index: u64) -> Option<String> {
        let total = self.total_staked();
        if total == 0 { return None; }

        let prev_hash_bytes = hex::decode(&self.latest_block().hash)
            .unwrap_or_else(|_| vec![0u8; 32]);
        let mut seed_input = prev_hash_bytes;
        seed_input.extend_from_slice(&block_index.to_le_bytes());
        let seed_hash = crypto::sha256(&seed_input);
        let seed_u64  = u64::from_le_bytes(seed_hash[..8].try_into().unwrap());
        let pick      = seed_u64 % total;

        let mut sorted: Vec<(&String, &u64)> = self.validators.iter().collect();
        sorted.sort_by_key(|(addr, _)| addr.as_str());

        let mut cumulative = 0u64;
        for (address, &stake) in &sorted {
            cumulative += stake;
            if pick < cumulative {
                return Some(address.to_string());
            }
        }
        sorted.last().map(|(addr, _)| addr.to_string())
    }

    // =========================================================================
    // Fork Choice — LMD-GHOST tiebreaker
    // =========================================================================

    /// Determines which of two chains should be adopted as canonical.
    ///
    /// PRIMARY RULE: longer chain wins (more confirmed blocks = more work done
    /// by the validator set, regardless of individual block content).
    ///
    /// TIEBREAKER (equal length): prefer the chain whose tip block hash is
    /// lexicographically smaller. This is a deterministic approximation of
    /// LMD-GHOST's heaviest-subtree rule. All nodes apply the same comparison
    /// so they always converge to the same canonical chain without coordination
    /// or communication.
    ///
    /// Returns true if `their_chain` should replace our current chain.
    pub fn should_adopt(&self, their_chain: &[Block]) -> bool {
        let our_len   = self.chain.len();
        let their_len = their_chain.len();

        if their_len > our_len {
            return true;
        }
        if their_len < our_len {
            return false;
        }

        // Equal length — apply the LMD-GHOST tiebreaker.
        // Compare tip hashes lexicographically; smaller hash wins.
        let our_tip   = &self.chain.last().unwrap().hash;
        let their_tip = &their_chain.last().unwrap().hash;
        their_tip < our_tip
    }

    // =========================================================================
    // Double-Sign Detection and Slashing
    // =========================================================================

    /// Records a block signature and checks for double-signing.
    ///
    /// Called every time a valid block is observed (whether accepted or not).
    /// If the same validator has signed a different block at the same height,
    /// returns SlashEvidence that can be submitted to slash_validator().
    ///
    /// The evidence contains both block hashes and both signatures, which is
    /// sufficient cryptographic proof of the offense — anyone can independently
    /// verify that both signatures are valid and that they cover different hashes
    /// at the same height.
    pub fn record_block_signature(
        &mut self,
        block: &Block,
    ) -> Option<SlashEvidence> {
        let key = (block.validator.clone(), block.index);

        if let Some(existing_hash) = self.seen_validator_blocks.get(&key) {
            // We have already seen a block from this validator at this height.
            if existing_hash != &block.hash {
                // Different hash at the same height — double-sign proven.
                // Retrieve the signature for the first block we saw.
                // We stored it when we first recorded the block.
                let sig_key_a = format!("sig:{}:{}", block.validator, existing_hash);
                let _sig_key_b = format!("sig:{}:{}", block.validator, block.hash);

                // Retrieve stored signatures from our evidence cache.
                let sig_a = self.seen_validator_blocks
                    .get(&(sig_key_a.clone(), 0))
                    .cloned()
                    .unwrap_or_default();
                let sig_b = block.validator_sig.clone();

                // Only produce evidence if we actually have both sigs.
                if !sig_a.is_empty() && !sig_b.is_empty() {
                    return Some(SlashEvidence {
                        block_height: block.index,
                        block_hash_a: existing_hash.clone(),
                        sig_a:        hex::decode(&sig_a).unwrap_or_default(),
                        block_hash_b: block.hash.clone(),
                        sig_b,
                    });
                }
            }
        } else {
            // First time seeing this validator at this height — record it.
            self.seen_validator_blocks.insert(key, block.hash.clone());
            // Also store the signature so we can retrieve it as evidence later.
            let sig_key = format!("sig:{}:{}", block.validator, block.hash);
            let sig_hex = hex::encode(&block.validator_sig);
            self.seen_validator_blocks.insert(
                (sig_key, 0),
                sig_hex,
            );
        }
        None
    }

    /// Processes proven double-sign evidence against a validator.
    ///
    /// Verification steps:
    ///   1. Retrieve the offender's public key from validator_pubkeys
    ///   2. Verify sig_a is a valid signature of block_hash_a by that key
    ///   3. Verify sig_b is a valid signature of block_hash_b by that key
    ///   4. Confirm block_hash_a != block_hash_b (different blocks, same height)
    ///   5. Confirm the validator hasn't already been slashed for this
    ///
    /// If all checks pass:
    ///   - SLASH_BURN_FRACTION% of stake is burned (removed from supply)
    ///   - Remainder goes to `reporter_address` as a whistleblower reward
    ///   - Validator is removed from the active set immediately
    ///   - A Slash transaction is queued in the mempool for on-chain recording
    ///
    /// Returns Ok(slash_amount) or Err with reason for rejection.
    pub fn slash_validator(
        &mut self,
        offender_address: String,
        reporter_address:  String,
        evidence:          SlashEvidence,
    ) -> Result<u64, String> {
        // Check 1 — we must know this validator's public key
        let pk_bytes = self.validator_pubkeys
            .get(&offender_address)
            .cloned()
            .ok_or_else(|| format!(
                "Unknown validator {}... — cannot verify slash evidence",
                &offender_address[..8]
            ))?;

        // Check 2 — verify first signature
        if !crypto::verify_signature(
            &pk_bytes,
            evidence.block_hash_a.as_bytes(),
            &evidence.sig_a,
        ) {
            return Err("Slash evidence invalid: sig_a does not verify".to_string());
        }

        // Check 3 — verify second signature
        if !crypto::verify_signature(
            &pk_bytes,
            evidence.block_hash_b.as_bytes(),
            &evidence.sig_b,
        ) {
            return Err("Slash evidence invalid: sig_b does not verify".to_string());
        }

        // Check 4 — the two blocks must actually be different
        if evidence.block_hash_a == evidence.block_hash_b {
            return Err("Slash evidence invalid: both hashes are identical".to_string());
        }

        // Check 5 — not already slashed
        if self.slashed_validators.contains(&offender_address) {
            return Err(format!(
                "Validator {}... has already been slashed",
                &offender_address[..8]
            ));
        }

        // Compute penalty amounts
        let stake = self.get_stake(&offender_address);
        if stake == 0 {
            return Err(format!(
                "Validator {}... has no stake to slash",
                &offender_address[..8]
            ));
        }

        let burn_amount     = stake * SLASH_BURN_FRACTION / 100;
        let reporter_reward = stake - burn_amount;

        println!("[SLASH] Double-sign detected for {}...", &offender_address[..16]);
        println!("[SLASH]   Stake:           {} coins", stake);
        println!("[SLASH]   Burned:          {} coins", burn_amount);
        println!("[SLASH]   Reporter reward: {} coins -> {}...",
            reporter_reward, &reporter_address[..16]);

        // Remove from validator set immediately — cannot produce more blocks
        self.validators.remove(&offender_address);
        self.validator_pubkeys.remove(&offender_address);
        self.slashed_validators.insert(offender_address.clone());

        // Credit the reporter (burn amount is simply not credited anywhere)
        *self.utxo_set.entry(reporter_address.clone()).or_insert(0) += reporter_reward;

        // total_supply decreases by burn_amount since those coins cease to exist
        self.total_supply = self.total_supply.saturating_sub(burn_amount);

        // Queue a Slash transaction for on-chain recording
        let slash_tx = Transaction::new_slash(
            offender_address,
            reporter_address,
            reporter_reward,
            evidence,
        );
        self.mempool.push(slash_tx);

        Ok(stake)
    }

    // =========================================================================
    // Block Production
    // =========================================================================

    pub fn produce_block(&mut self, wallet: &crypto::Wallet) -> Result<(), String> {
        let validator_address = wallet.address();
        let next_index        = self.chain.len() as u64;

        let selected = self.select_validator(next_index)
            .ok_or("No validators registered — use dev-fund + dev-stake to bootstrap")?;

        if selected != validator_address {
            return Err(format!(
                "Not your slot — selected: {}... (you: {}...)",
                &selected[..8], &validator_address[..8]
            ));
        }

        let reward = self.current_reward();
        println!("Producing block #{}", next_index);
        println!("  Validator:    {}...", &validator_address[..16]);
        println!("  Block reward: {} coins", reward);
        println!("  Supply:       {}/{}", self.total_supply, MAX_SUPPLY);
        println!("  Validators:   {} active, {} total staked",
            self.validators.len(), self.total_staked());

        let mut transactions: Vec<Transaction> = vec![];

        // Unbonding releases due at this height
        let mut released: Vec<usize> = vec![];
        for (i, entry) in self.pending_unstake.iter().enumerate() {
            if next_index >= entry.release_at_block {
                println!("  Releasing {} coins to {}...",
                    entry.amount, &entry.address[..8]);
                transactions.push(Transaction::new_unbonding_release(
                    entry.address.clone(), entry.amount));
                released.push(i);
            }
        }
        for i in released.into_iter().rev() {
            self.pending_unstake.remove(i);
        }

        // Validator reward
        if reward > 0 {
            transactions.push(Transaction::new_reward(validator_address.clone(), reward));
        }

        // All pending mempool transactions (including any slash txs)
        transactions.extend(self.mempool.drain(..));

        let prev_hash = self.latest_block().hash.clone();
        let mut block = Block::new(next_index, prev_hash, validator_address.clone(), transactions.clone());
        block.sign_as_validator(wallet);

        // Record our own block signature for double-sign tracking
        self.record_block_signature(&block);

        if reward > 0 { self.total_supply += reward; }
        self.apply_transactions(&transactions);
        self.chain.push(block);

        println!("  Block confirmed. New supply: {}/{}", self.total_supply, MAX_SUPPLY);
        Ok(())
    }

    // =========================================================================
    // State Application
    // =========================================================================

    pub fn apply_transactions(&mut self, transactions: &[Transaction]) {
        for tx in transactions {
            match tx.kind {
                TxKind::Transfer => {
                    let is_protocol = tx.from == "coinbase"
                        || tx.from == "system"
                        || tx.from.starts_with("genesis:");
                    if !is_protocol {
                        let sender = self.utxo_set.entry(tx.sender_address()).or_insert(0);
                        *sender = sender.saturating_sub(tx.amount);
                        self.tx_nonces.insert(tx.sender_address(), tx.nonce);
                    }
                    // coinbase and genesis: create new coins, count toward supply
                    // system: releases already-counted unbonding coins, no supply change
                    if tx.from == "coinbase" || tx.from.starts_with("genesis:") {
                        self.total_supply += tx.amount;
                    }
                    *self.utxo_set.entry(tx.to.clone()).or_insert(0) += tx.amount;
                }

                TxKind::Stake => {
                    if tx.from == "coinbase" {
                        // dev-stake: no utxo deduction
                        *self.validators.entry(tx.to.clone()).or_insert(0) += tx.amount;
                    } else if tx.from.starts_with("genesis:") {
                        // genesis allocation: add to validators AND store public key
                        let pk_hex = &tx.from["genesis:".len()..];
                        if let Ok(pk_bytes) = hex::decode(pk_hex) {
                            self.validator_pubkeys.insert(tx.to.clone(), pk_bytes);
                        }
                        *self.validators.entry(tx.to.clone()).or_insert(0) += tx.amount;
                    } else {
                        let addr = tx.sender_address();
                        let bal  = self.utxo_set.entry(addr.clone()).or_insert(0);
                        *bal = bal.saturating_sub(tx.amount);
                        *self.validators.entry(addr.clone()).or_insert(0) += tx.amount;
                        if let Ok(pk_bytes) = hex::decode(&tx.from) {
                            self.validator_pubkeys.insert(addr.clone(), pk_bytes);
                        }
                        self.tx_nonces.insert(addr, tx.nonce);
                    }
                }

                TxKind::Unstake => {
                    let addr          = tx.sender_address();
                    let current_stake = self.validators.entry(addr.clone()).or_insert(0);
                    let actual        = tx.amount.min(*current_stake);
                    *current_stake   -= actual;

                    if *current_stake < MIN_STAKE {
                        let dust = *current_stake;
                        self.validators.remove(&addr);
                        if dust > 0 {
                            *self.utxo_set.entry(addr.clone()).or_insert(0) += dust;
                        }
                        self.validator_pubkeys.remove(&addr);
                    }

                    if actual > 0 {
                        let release_at = self.chain.len() as u64 + UNBONDING_BLOCKS;
                        self.pending_unstake.push(PendingUnstake {
                            address: addr.clone(), amount: actual, release_at_block: release_at,
                        });
                    }
                    self.tx_nonces.insert(addr, tx.nonce);
                }

                TxKind::Slash => {
                    // State was already applied in slash_validator() when the
                    // evidence was first processed. The Slash tx is on-chain
                    // purely for auditability. Credit the reporter again here
                    // only if replay (chain load) — detect by checking if the
                    // offender is in slashed_validators already.
                    if let Some(_evidence) = &tx.slash_evidence {
                        let _offender = tx.to.clone(); // reporter is tx.to
                        // During replay (load_chain), re-apply the state.
                        // During live operation, slash_validator() already did it.
                        // We use a sentinel: if validator is still in the set,
                        // this is a replay and we must apply the slash.
                        let reporter  = tx.to.clone();
                        // Find offender address — stored in evidence indirectly.
                        // We don't have it directly in the tx, so we identify by
                        // the fact that slash evidence contains both block hashes
                        // and we can look up who signed them from seen_validator_blocks.
                        // For replay correctness: the slash tx's `from` field is "slash"
                        // and we encode the offender address in a dedicated field.
                        // Since we don't have that field yet, we record the offender
                        // address in tx.from as "slash:<address>" during new_slash.
                        // Let's parse it:
                        let offender_addr = if tx.from.starts_with("slash:") {
                            tx.from[6..].to_string()
                        } else {
                            continue; // malformed, skip
                        };

                        if self.validators.contains_key(&offender_addr)
                            && !self.slashed_validators.contains(&offender_addr)
                        {
                            let stake        = self.get_stake(&offender_addr);
                            let burn_amount  = stake * SLASH_BURN_FRACTION / 100;
                            let reward_coins = stake - burn_amount;

                            self.validators.remove(&offender_addr);
                            self.validator_pubkeys.remove(&offender_addr);
                            self.slashed_validators.insert(offender_addr);
                            *self.utxo_set.entry(reporter.clone()).or_insert(0) += reward_coins;
                            self.total_supply = self.total_supply.saturating_sub(burn_amount);
                        }
                    }
                }
            }
        }
    }

    // =========================================================================
    // Mempool
    // =========================================================================

    pub fn add_transaction(&mut self, tx: Transaction) -> Result<(), String> {
        if !tx.is_valid() {
            return Err("Invalid transaction signature".to_string());
        }

        let sender_addr    = tx.sender_address();
        let expected_nonce = self.next_nonce(&sender_addr);

        if tx.nonce != expected_nonce {
            return Err(format!(
                "Invalid nonce for {}... — expected {}, got {}",
                &sender_addr[..8], expected_nonce, tx.nonce
            ));
        }

        match tx.kind {
            TxKind::Transfer => {
                let balance = self.get_balance(&sender_addr);
                if balance < tx.amount {
                    return Err(format!(
                        "Insufficient funds — {}... has {}, tried to send {}",
                        &sender_addr[..8], balance, tx.amount
                    ));
                }
                let pending: u64 = self.mempool.iter()
                    .filter(|t| t.from == tx.from && t.kind == TxKind::Transfer)
                    .map(|t| t.amount).sum();
                if balance < tx.amount + pending {
                    return Err(format!(
                        "Insufficient funds — {} balance, {} already pending",
                        balance, pending
                    ));
                }
            }
            TxKind::Stake => {
                let balance = self.get_balance(&sender_addr);
                if balance < tx.amount {
                    return Err(format!(
                        "Insufficient funds to stake — {}... has {}",
                        &sender_addr[..8], balance
                    ));
                }
                let current_stake = self.get_stake(&sender_addr);
                if current_stake + tx.amount < MIN_STAKE {
                    return Err(format!(
                        "Stake too small — minimum {}, you would have {}",
                        MIN_STAKE, current_stake + tx.amount
                    ));
                }
            }
            TxKind::Unstake => {
                let stake = self.get_stake(&sender_addr);
                if stake < tx.amount {
                    return Err(format!(
                        "Insufficient stake — {}... has {} staked, tried to unstake {}",
                        &sender_addr[..8], stake, tx.amount
                    ));
                }
            }
            TxKind::Slash => {
                return Err("Slash transactions are protocol-generated".to_string());
            }
        }

        self.mempool.push(tx);
        Ok(())
    }

    // =========================================================================
    // Chain Validation — FIXED: unknown validator keys now REJECT blocks
    // =========================================================================

    /// Validates the entire chain from genesis to tip.
    ///
    /// Checks per block (after genesis):
    ///   1. Hash integrity  — stored hash matches recalculation
    ///   2. Chain linkage   — prev_hash matches previous block hash
    ///   3. Transaction sigs — all user transactions are properly signed
    ///   4. Validator sig   — block is signed by an KNOWN validator
    ///                        UNKNOWN validator = REJECTED (was silently passed before)
    ///
    /// Dev blocks (validator == "dev") are accepted without signature check
    /// since they have no real validator. Genesis blocks are always valid.
    pub fn is_valid(&self) -> bool {
        for i in 1..self.chain.len() {
            let current  = &self.chain[i];
            let previous = &self.chain[i - 1];

            // 1. Hash integrity
            if current.hash != current.calculate_hash() {
                return false;
            }
            // 2. Chain linkage
            if current.prev_hash != previous.hash {
                return false;
            }
            // 3. Transaction signatures
            if !current.transactions.iter().all(|tx| tx.is_valid()) {
                return false;
            }
            // 4. Validator signature — STRICT: unknown validator = invalid
            if current.validator == "dev" || current.validator == "genesis" {
                continue; // special blocks exempt from sig check
            }
            match self.validator_pubkeys.get(&current.validator) {
                Some(pk_bytes) => {
                    if !current.verify_validator_sig(pk_bytes) {
                        return false;
                    }
                }
                None => {
                    // Unknown validator — REJECT.
                    // Previously this silently passed. Now it fails.
                    return false;
                }
            }
        }
        true
    }

    // =========================================================================
    // State Rebuild — single authoritative function used by both load_chain
    // and mine-and-broadcast sync, eliminating the duplicate logic that existed
    // =========================================================================

    /// Rebuilds all derived state by replaying every transaction from genesis.
    ///
    /// Clears and reconstructs: utxo_set, tx_nonces, validators,
    /// validator_pubkeys, pending_unstake, total_supply, seen_validator_blocks,
    /// slashed_validators.
    ///
    /// Called by chain_store::load_chain after deserialising blocks from disk,
    /// and by mine-and-broadcast after adopting a peer's chain.
    pub fn rebuild_derived_state(&mut self) {
        self.utxo_set.clear();
        self.tx_nonces.clear();
        self.validators.clear();
        self.validator_pubkeys.clear();
        self.pending_unstake.clear();
        self.total_supply         = 0;
        self.seen_validator_blocks.clear();
        self.slashed_validators.clear();

        let blocks = self.chain.clone();
        for (block_index, block) in blocks.iter().enumerate() {
            // Record block signatures for double-sign tracking
            if block.validator != "genesis" && block.validator != "dev"
                && !block.validator_sig.is_empty()
            {
                let key = (block.validator.clone(), block.index);
                self.seen_validator_blocks.insert(key, block.hash.clone());
            }

            // Release unbonding entries due at this height
            self.pending_unstake.retain(|e| e.release_at_block > block_index as u64);

            self.apply_transactions(&block.transactions);
        }
    }
}
