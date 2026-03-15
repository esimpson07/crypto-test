// =============================================================================
// chain_store.rs — Blockchain Persistence
// =============================================================================
//
// Saves the blockchain to disk and loads it back so the chain, pending
// transactions, and wallet balances survive program restarts.
//
// WHAT GETS SAVED:
//
//   Two files are written per network:
//     chain.json          — all confirmed blocks as a JSON array
//     chain.json.mempool  — pending unconfirmed transactions as a JSON array
//
// WHAT GETS REBUILT ON LOAD (NOT SAVED):
//
//   The UTXO set (address → balance) and total_supply are NOT written to disk.
//   They are always reconstructed by replaying every transaction in the chain.
//
//   Why replay instead of saving directly?
//     If the balance file were corrupted or manually edited, balances could
//     diverge from the actual transaction history — someone could grant
//     themselves coins without a valid signed block. Replaying the immutable
//     chain guarantees balances always match what the transaction record says.
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
/// UTXO set and total_supply are NOT saved — rebuilt from blocks on load.
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
/// If no chain file exists, returns a fresh chain starting from genesis
/// (handles first run automatically).
///
/// Process:
///   1. Deserialize the block list from chain.json
///   2. Replay every transaction in every block to rebuild the UTXO set
///      and recount total_supply — guarantees correctness
///   3. Load any pending mempool transactions, or start empty if none saved
pub fn load_chain(path: &str) -> Result<Blockchain, String> {
    if !Path::new(path).exists() {
        return Ok(Blockchain::new());
    }

    let chain_json = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let blocks: Vec<Block> = serde_json::from_str(&chain_json)
        .map_err(|e| e.to_string())?;

    // Replay all transactions to reconstruct UTXO set and supply count.
    // Process blocks in chronological order, exactly as they were originally mined.
    let mut utxo_set:     HashMap<String, u64> = HashMap::new();
    let mut total_supply: u64 = 0;

    for block in &blocks {
        for tx in &block.transactions {
            if tx.from == "coinbase" {
                // Coinbase creates new coins — credit recipient, count toward supply
                total_supply += tx.amount;
            } else {
                // Regular transaction — deduct from sender
                // sender_address() hashes the full public key to get the address key
                let sender = utxo_set.entry(tx.sender_address()).or_insert(0);
                *sender -= tx.amount;
            }
            // Credit recipient (applies to both coinbase and regular transactions)
            let recipient = utxo_set.entry(tx.to.clone()).or_insert(0);
            *recipient += tx.amount;
        }
    }

    // Load pending mempool transactions — or start with empty mempool if none saved
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
        difficulty:   DIFFICULTY, // always use the current constant
        mempool,
        utxo_set,
        total_supply,
    })
}

/// Deletes the mempool sidecar file after its transactions are confirmed on chain.
///
/// Called after every successful mine or mine-and-broadcast. Once transactions
/// are permanently recorded in a block, the pending mempool file is stale
/// and should be cleaned up. Silently succeeds if the file doesn't exist.
pub fn clear_mempool(path: &str) {
    let mempool_path = format!("{}.mempool", path);
    if Path::new(&mempool_path).exists() {
        let _ = fs::remove_file(&mempool_path);
    }
}
