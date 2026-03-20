// =============================================================================
// chain_store.rs — Blockchain Persistence
// =============================================================================
//
// WHAT GETS SAVED:
//   chain.json         — confirmed blocks
//   chain.json.mempool — pending transactions
//
// WHAT GETS REBUILT ON LOAD:
//   All derived state is rebuilt by calling blockchain.rebuild_derived_state()
//   which replays every transaction from genesis. This is the single
//   authoritative state reconstruction function — chain_store no longer
//   has its own replay loop, eliminating the previous duplication with
//   mine-and-broadcast.
// =============================================================================

use std::fs;
use std::path::Path;
use crate::blockchain::Blockchain;
use crate::block::Block;
use crate::transaction::Transaction;

pub fn save_chain(chain: &Blockchain, path: &str) -> Result<(), String> {
    let chain_json = serde_json::to_string_pretty(&chain.chain)
        .map_err(|e| e.to_string())?;
    fs::write(path, chain_json).map_err(|e| e.to_string())?;

    let mempool_json = serde_json::to_string_pretty(&chain.mempool)
        .map_err(|e| e.to_string())?;
    fs::write(format!("{}.mempool", path), mempool_json)
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// Loads the blockchain from disk and rebuilds all derived state.
///
/// Uses blockchain.rebuild_derived_state() — the single authoritative
/// replay function shared with mine-and-broadcast sync. No duplicate
/// replay loop here.
pub fn load_chain(path: &str) -> Result<Blockchain, String> {
    if !Path::new(path).exists() {
        return Ok(Blockchain::new());
    }

    let chain_json = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let blocks: Vec<Block> = serde_json::from_str(&chain_json)
        .map_err(|e| e.to_string())?;

    let mempool_path = format!("{}.mempool", path);
    let mempool: Vec<Transaction> = if Path::new(&mempool_path).exists() {
        let json = fs::read_to_string(&mempool_path).map_err(|e| e.to_string())?;
        serde_json::from_str(&json).map_err(|e| e.to_string())?
    } else {
        vec![]
    };

    let mut chain   = Blockchain::new();
    chain.chain     = blocks;
    chain.mempool   = mempool.clone();

    // Single call to rebuild everything — same function used by sync
    chain.rebuild_derived_state();

    if !mempool.is_empty() {
        println!("Loaded {} pending transaction(s) from mempool", mempool.len());
    }
    println!("Chain: {} blocks | {} validators | {} staked | supply {}/{}",
        chain.chain.len(),
        chain.validators.len(),
        chain.total_staked(),
        chain.total_supply,
        crate::blockchain::MAX_SUPPLY,
    );

    Ok(chain)
}

pub fn clear_mempool(path: &str) {
    let p = format!("{}.mempool", path);
    if Path::new(&p).exists() { let _ = fs::remove_file(&p); }
}
