// =============================================================================
// chain_store.rs — Blockchain Persistence (Save/Load)
// =============================================================================
//
// This file handles saving the blockchain to disk and loading it back so that
// the chain, pending transactions, and wallet balances survive program restarts.
//
// WHAT GETS SAVED:
//   Two files are written:
//     <path>         — the confirmed blocks as JSON  (e.g. "chain.json")
//     <path>.mempool — pending transactions as JSON  (e.g. "chain.json.mempool")
//
// WHAT GETS REBUILT (NOT SAVED):
//   The UTXO set (address → balance map) and total_supply are NOT written to disk.
//   Instead, they are reconstructed on every load by replaying every transaction
//   in every block from genesis to the tip.
//
//   WHY REPLAY INSTEAD OF SAVE?
//     If we saved the UTXO set directly and the file was corrupted or manually
//     edited, balances could become inconsistent with the actual transaction
//     history — someone could give themselves extra coins without a valid block.
//     Replaying from the immutable chain is slower but guarantees correctness:
//     the balances will always exactly match what the signed transactions say.
//
// THE MEMPOOL FILE:
//   The mempool (pending transactions) IS saved because it contains real user
//   transactions that have been signed and submitted but not yet mined. Losing
//   them on restart would require users to resubmit every send command.
//   The mempool file is deleted by clear_mempool() after mining confirms the txs.
// =============================================================================

use std::fs;
use std::path::Path;
use std::collections::HashMap;
use crate::blockchain::{Blockchain, DIFFICULTY};
use crate::block::Block;
use crate::transaction::Transaction;

/// Saves the blockchain's confirmed blocks and pending mempool to disk.
///
/// Writes two files:
///   `path`          — JSON array of all confirmed Block structs
///   `path`.mempool  — JSON array of all pending Transaction structs
///
/// The UTXO set and total_supply are not saved — they are always rebuilt
/// from the block data on the next load call.
///
/// `chain` — the blockchain to persist
/// `path`  — base file path (e.g. "chain.json" or "mainnet_chain.json")
pub fn save_chain(chain: &Blockchain, path: &str) -> Result<(), String> {
    // Write confirmed blocks to the main chain file
    let chain_json = serde_json::to_string_pretty(&chain.chain)
        .map_err(|e| e.to_string())?;
    fs::write(path, chain_json).map_err(|e| e.to_string())?;

    // Write pending transactions to the mempool sidecar file
    // This preserves user-submitted transactions across program restarts
    let mempool_path = format!("{}.mempool", path);
    let mempool_json = serde_json::to_string_pretty(&chain.mempool)
        .map_err(|e| e.to_string())?;
    fs::write(mempool_path, mempool_json).map_err(|e| e.to_string())?;

    Ok(())
}

/// Loads the blockchain from disk, rebuilding all derived state from scratch.
///
/// PROCESS:
///   1. If no chain file exists, return a fresh blockchain from genesis
///      (handles first run automatically — no setup needed)
///   2. Deserialize the block list from JSON
///   3. Replay every transaction in every block to rebuild the UTXO set
///      and recount total_supply — ensures balances are always trustworthy
///   4. Load any pending mempool transactions from the sidecar file
///      (or start with an empty mempool if the file doesn't exist)
///
/// `path` — base file path (e.g. "chain.json" or "mainnet_chain.json")
pub fn load_chain(path: &str) -> Result<Blockchain, String> {
    // No chain file yet — this is a first run, start from genesis block
    if !Path::new(path).exists() {
        return Ok(Blockchain::new());
    }

    // Read and deserialize the confirmed block list
    let chain_json = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let blocks: Vec<Block> = serde_json::from_str(&chain_json)
        .map_err(|e| e.to_string())?;

    // Replay all transactions to reconstruct the UTXO set and supply count.
    // We process every block in chronological order, just as they were mined.
    // This is the authoritative way to determine balances — derived from the
    // signed transaction record, not stored independently.
    let mut utxo_set:     HashMap<String, u64> = HashMap::new();
    let mut total_supply: u64 = 0;

    for block in &blocks {
        for tx in &block.transactions {
            if tx.from == "coinbase" {
                // Coinbase transactions create new coins — count toward total supply
                total_supply += tx.amount;
                // Note: coinbase has no sender to deduct from, only a recipient to credit
            } else {
                // Regular transaction — deduct from the sender's balance
                // sender_address() hashes tx.from (full public key) to get the address key
                let sender = utxo_set.entry(tx.sender_address()).or_insert(0);
                *sender -= tx.amount;
            }
            // Credit the recipient for both coinbase and regular transactions
            let recipient = utxo_set.entry(tx.to.clone()).or_insert(0);
            *recipient += tx.amount;
        }
    }

    // Load pending mempool transactions, or start empty if none were saved
    let mempool_path = format!("{}.mempool", path);
    let mempool: Vec<Transaction> = if Path::new(&mempool_path).exists() {
        let mempool_json = fs::read_to_string(&mempool_path)
            .map_err(|e| e.to_string())?;
        serde_json::from_str(&mempool_json).map_err(|e| e.to_string())?
    } else {
        vec![] // no mempool file — no pending transactions
    };

    // Report what was loaded so the user knows the state on startup
    if !mempool.is_empty() {
        println!("Loaded {} pending transaction(s) from mempool", mempool.len());
    }
    println!("Loaded chain with {} blocks", blocks.len());

    // Assemble the complete Blockchain struct with all rebuilt state
    Ok(Blockchain {
        chain:        blocks,
        difficulty:   DIFFICULTY, // always use the current constant, not whatever was stored
        mempool,
        utxo_set,
        total_supply,
    })
}

/// Deletes the mempool sidecar file after its transactions are confirmed on chain.
///
/// Called by main.rs after every successful mine or mine-and-broadcast command.
/// Once transactions are permanently recorded in a mined block, the pending
/// mempool file is no longer needed and should be cleaned up.
///
/// Silently succeeds if the file doesn't exist — no error if already clean.
pub fn clear_mempool(path: &str) {
    let mempool_path = format!("{}.mempool", path);
    if Path::new(&mempool_path).exists() {
        let _ = fs::remove_file(&mempool_path);
    }
}
