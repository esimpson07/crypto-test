// =============================================================================
// chain_store.rs — Blockchain Persistence
// =============================================================================
//
// Saves the blockchain to disk and loads it back so the chain, pending
// transactions, and wallet state survive program restarts.
//
// WHAT GETS SAVED:
//
//   Two files are written per network:
//     chain.json          — all confirmed blocks as a JSON array
//     chain.json.mempool  — pending unconfirmed transactions as a JSON array
//
// WHAT GETS REBUILT ON LOAD (NOT SAVED):
//
//   Three derived fields are NOT written to disk and are always reconstructed
//   by replaying every transaction in the chain from genesis:
//
//     utxo_set    — address → balance map
//     tx_nonces   — address → last confirmed nonce (replay attack prevention)
//     total_supply — total coins ever created
//
//   Why replay instead of saving directly?
//     If these files were corrupted or manually edited, state could diverge
//     from the actual transaction history — someone could grant themselves
//     coins or reset their nonce to enable replays. Replaying the immutable
//     chain guarantees all derived state is always provably correct.
//
// THE MEMPOOL FILE:
//
//   The mempool IS saved because it contains real signed transactions that
//   users submitted but that haven't been mined yet. Losing them on restart
//   would require users to resubmit. The mempool file is deleted by
//   clear_mempool() after those transactions are confirmed in a mined block.
// =============================================================================

use std::fs;
use std::path::Path;
use std::collections::HashMap;
use crate::blockchain::{Blockchain, DIFFICULTY};
use crate::block::Block;
use crate::transaction::Transaction;

/// Saves the chain and mempool to disk.
///
/// Writes:
///   `path`          — confirmed blocks as pretty-printed JSON
///   `path`.mempool  — pending transactions as pretty-printed JSON
///
/// utxo_set, tx_nonces, and total_supply are NOT saved — rebuilt on load.
pub fn save_chain(chain: &Blockchain, path: &str) -> Result<(), String> {
    let chain_json = serde_json::to_string_pretty(&chain.chain)
        .map_err(|e| e.to_string())?;
    fs::write(path, chain_json)
        .map_err(|e| e.to_string())?;

    let mempool_json = serde_json::to_string_pretty(&chain.mempool)
        .map_err(|e| e.to_string())?;
    fs::write(format!("{}.mempool", path), mempool_json)
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// Loads the blockchain from disk, rebuilding all derived state from scratch.
///
/// If no chain file exists, returns a fresh chain from genesis (first run).
///
/// Process:
///   1. Deserialize the block list from chain.json
///   2. Replay every transaction in every block to rebuild:
///        utxo_set    — address → balance
///        tx_nonces   — address → last confirmed nonce
///        total_supply — total coins ever minted
///   3. Load pending mempool transactions (or start empty)
pub fn load_chain(path: &str) -> Result<Blockchain, String> {
    if !Path::new(path).exists() {
        return Ok(Blockchain::new());
    }

    let chain_json = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let blocks: Vec<Block> = serde_json::from_str(&chain_json)
        .map_err(|e| e.to_string())?;

    // Replay all transactions to reconstruct derived state.
    // Process in chronological order, exactly as originally mined.
    let mut utxo_set:     HashMap<String, u64> = HashMap::new();
    let mut tx_nonces:    HashMap<String, u64> = HashMap::new();
    let mut total_supply: u64 = 0;

    for block in &blocks {
        for tx in &block.transactions {
            if tx.from == "coinbase" {
                // Coinbase creates new coins — credit recipient, count toward supply
                total_supply += tx.amount;
            } else {
                // Regular transaction — deduct from sender
                let sender = utxo_set.entry(tx.sender_address()).or_insert(0);
                *sender -= tx.amount;

                // Record the confirmed nonce for this sender.
                // next_nonce() returns this value + 1, which is what the next
                // transaction from this address must use.
                tx_nonces.insert(tx.sender_address(), tx.nonce);
            }
            // Credit recipient for both coinbase and regular transactions
            let recipient = utxo_set.entry(tx.to.clone()).or_insert(0);
            *recipient += tx.amount;
        }
    }

    // Load pending mempool, or start empty if no mempool file exists
    let mempool_path = format!("{}.mempool", path);
    let mempool: Vec<Transaction> = if Path::new(&mempool_path).exists() {
        let mempool_json = fs::read_to_string(&mempool_path)
            .map_err(|e| e.to_string())?;
        serde_json::from_str(&mempool_json).map_err(|e| e.to_string())?
    } else {
        vec![]
    };

    if !mempool.is_empty() {
        println!("Loaded {} pending transaction(s) from mempool", mempool.len());
    }
    println!("Loaded chain with {} blocks", blocks.len());

    Ok(Blockchain {
        chain:        blocks,
        difficulty:   DIFFICULTY,
        mempool,
        utxo_set,
        tx_nonces,
        total_supply,
    })
}

/// Deletes the mempool sidecar file after its transactions are confirmed.
///
/// Called after every successful mine or mine-and-broadcast.
/// Silently succeeds if the file doesn't exist.
pub fn clear_mempool(path: &str) {
    let mempool_path = format!("{}.mempool", path);
    if Path::new(&mempool_path).exists() {
        let _ = fs::remove_file(&mempool_path);
    }
}
