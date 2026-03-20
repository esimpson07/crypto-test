// =============================================================================
// main.rs — Command Line Interface
// =============================================================================
//
// COMMANDS:
//   new-wallet                    Generate wallet from 24-word phrase
//   recover-wallet                Regenerate wallet from 24-word phrase
//   list-wallets                  Show all .dat wallet files
//   balance                       Show address, balances, validator status
//   stake <amount>                Lock coins to become a validator
//   unstake <amount>              Begin unbonding your stake
//   validators                    List all registered validators
//   validate                      Run continuous slot loop as a validator
//   send <to> <amount> [peer]     Send coins
//   chain                         Print all blocks
//   node <port> [peer]            Start a P2P node
//   mine-and-broadcast <peer>     Sync, produce block, broadcast
//   dev-fund <address> <amount>   [TESTING] credit coins directly
//   dev-stake <address> <amount>  [TESTING] register validator directly
//
// GLOBAL OPTIONS:
//   --wallet <n>      use <n>.dat           (default: wallet.dat)
//   --network <n>     use <n>_chain.json    (default: chain.json)
//   --seed <ip:port>  seed node for peer discovery
//
// GENESIS:
//   On first run, if no chain.json exists, the program looks for
//   genesis.json in the current directory. If found, it pre-funds the
//   listed accounts and registers them as validators. If not found,
//   it starts with an empty chain requiring dev-fund + dev-stake.
//
//   genesis.json format:
//   [
//     { "address": "<64-char hex>", "public_key": "<hex>",
//       "balance": 500, "stake": 100 },
//     ...
//   ]
// =============================================================================

#![allow(unused_imports, dead_code)]

mod crypto;
mod transaction;
mod block;
mod blockchain;
mod wallet_store;
mod chain_store;
mod network;
mod seed_phrase;

use crate::blockchain::{Blockchain, GenesisAccount, MAX_SUPPLY, MIN_STAKE, UNBONDING_BLOCKS, SLOT_SECONDS};
use crate::transaction::{Transaction, TxKind};
use crate::network::{start_node, send_message, Message};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::net::TcpStream;
use std::io::{self, Write};

// =============================================================================
// Helpers
// =============================================================================

fn ask_password(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn get_wallet_file(args: &[String]) -> String {
    for i in 0..args.len() {
        if args[i] == "--wallet" {
            if let Some(name) = args.get(i + 1) {
                return format!("{}.dat", name);
            }
        }
    }
    "wallet.dat".to_string()
}

fn get_chain_file(args: &[String]) -> String {
    for i in 0..args.len() {
        if args[i] == "--network" {
            if let Some(name) = args.get(i + 1) {
                return format!("{}_chain.json", name);
            }
        }
    }
    "chain.json".to_string()
}

fn public_key_hex(wallet: &crypto::Wallet) -> String {
    hex::encode(&wallet.public_key)
}

/// Loads the chain from disk, or initialises from genesis.json if it's the
/// first run and genesis.json exists.
fn load_or_init_chain(chain_file: &str) -> Blockchain {
    if std::path::Path::new(chain_file).exists() {
        return chain_store::load_chain(chain_file).expect("Failed to load chain");
    }

    // First run — check for genesis.json
    if std::path::Path::new("genesis.json").exists() {
        let raw = std::fs::read_to_string("genesis.json")
            .expect("Failed to read genesis.json");
        let trimmed = raw.trim();

        if trimmed.is_empty() || trimmed == "[]" {
            println!("genesis.json is empty — starting with empty chain.");
            println!("Populate genesis.json or use dev-fund + dev-stake to bootstrap.");
            return Blockchain::new();
        }

        println!("No chain found. Initialising from genesis.json...");

        #[derive(serde::Deserialize)]
        struct GenesisEntry {
            address:    String,
            public_key: String,
            balance:    u64,
            stake:      u64,
        }

        let entries: Vec<GenesisEntry> = serde_json::from_str(trimmed)
            .unwrap_or_else(|e| {
                eprintln!("ERROR: genesis.json is not valid JSON: {}", e);
                eprintln!();
                eprintln!("Expected format:");
                eprintln!("[");
                eprintln!("  {{");
                eprintln!("    \"address\":    \"<64-char hex address>\",");
                eprintln!("    \"public_key\": \"<hex Dilithium3 public key>\",");
                eprintln!("    \"balance\":    500,");
                eprintln!("    \"stake\":      100");
                eprintln!("  }}");
                eprintln!("]");
                eprintln!();
                eprintln!("Run 'new-wallet' and copy the address and public key shown.");
                std::process::exit(1);
            });

        let accounts: Vec<GenesisAccount> = entries.into_iter().map(|e| {
            let pk_bytes = hex::decode(&e.public_key).unwrap_or_else(|_| {
                eprintln!("ERROR: invalid public_key hex in genesis.json for address {}", e.address);
                eprintln!("Copy the full public key printed by 'new-wallet' or 'balance'.");
                std::process::exit(1);
            });
            GenesisAccount {
                address:    e.address,
                public_key: pk_bytes,
                balance:    e.balance,
                stake:      e.stake,
            }
        }).collect();

        let total_balance: u64 = accounts.iter().map(|a| a.balance).sum();
        let total_stake:   u64 = accounts.iter().map(|a| a.stake).sum();
        println!("Genesis: {} accounts | {} coins allocated | {} staked",
            accounts.len(), total_balance, total_stake);

        let chain = Blockchain::new_with_genesis(accounts);
        chain_store::save_chain(&chain, chain_file)
            .expect("Failed to save genesis chain");
        return chain;
    }

    // No genesis.json — start empty
    println!("No chain found. Starting empty chain (use dev-fund + dev-stake to bootstrap).");
    Blockchain::new()
}

// =============================================================================
// Entry Point
// =============================================================================

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command     = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    let wallet_file = get_wallet_file(&args);
    let chain_file  = get_chain_file(&args);

    match command {

        // =====================================================================
        // new-wallet
        // =====================================================================
        "new-wallet" => {
            if std::path::Path::new(wallet_file.as_str()).exists() {
                println!("Wallet '{}' already exists!", wallet_file);
                println!("Use a different name: cargo run -- new-wallet --wallet <n>");
                return;
            }
            let password = ask_password("Choose a password: ");
            let confirm  = ask_password("Confirm password: ");
            if password != confirm { println!("Passwords don't match."); return; }

            let phrase = seed_phrase::generate_phrase();
            let wallet = seed_phrase::wallet_from_phrase(&phrase);
            let combined = format!("{}{}", hex::encode(&wallet.private_key), hex::encode(&wallet.public_key));

            println!("\n╔══════════════════════════════════════════════════════════════╗");
            println!(  "║         YOUR 24-WORD RECOVERY PHRASE — WRITE THIS DOWN       ║");
            println!(  "╠══════════════════════════════════════════════════════════════╣");
            println!(  "{}", seed_phrase::format_for_display(&phrase));
            println!(  "╠══════════════════════════════════════════════════════════════╣");
            println!(  "║  These 24 words regenerate your wallet on any machine.       ║");
            println!(  "╚══════════════════════════════════════════════════════════════╝\n");

            wallet_store::save_wallet(&combined, &password, &wallet_file)
                .expect("Failed to save wallet");
            println!("Wallet created: {}", wallet_file);
            println!("Your address:   {}", wallet.address());
            println!("Your public key (for genesis.json): {}", public_key_hex(&wallet));
        }

        // =====================================================================
        // recover-wallet
        // =====================================================================
        "recover-wallet" => {
            if std::path::Path::new(wallet_file.as_str()).exists() {
                println!("Wallet '{}' already exists. Use --wallet <n> for a different name.", wallet_file);
                return;
            }
            println!("Enter your 24 recovery words:");
            let phrase = ask_password("Recovery phrase: ");
            if let Err(e) = seed_phrase::validate_phrase(&phrase) {
                println!("Error: {}", e); return;
            }
            let wallet = seed_phrase::wallet_from_phrase(&phrase);
            println!("\nRecovered address: {}", wallet.address());
            println!("Is this your address? (yes/no)");
            if ask_password("").trim().to_lowercase() != "yes" {
                println!("Address mismatch."); return;
            }
            let pw  = ask_password("New password: ");
            let pw2 = ask_password("Confirm: ");
            if pw != pw2 { println!("Passwords don't match."); return; }
            let combined = format!("{}{}", hex::encode(&wallet.private_key), hex::encode(&wallet.public_key));
            wallet_store::save_wallet(&combined, &pw, &wallet_file)
                .expect("Failed to save wallet");
            println!("Wallet recovered: {} ({})", wallet_file, wallet.address());
        }

        // =====================================================================
        // list-wallets
        // =====================================================================
        "list-wallets" => {
            println!("Available wallets:");
            for entry in std::fs::read_dir(".").unwrap() {
                let name = entry.unwrap().file_name();
                let name = name.to_string_lossy();
                if name.ends_with(".dat") {
                    println!("  {}  ->  --wallet {}", name, name.replace(".dat", ""));
                }
            }
        }

        // =====================================================================
        // balance
        // =====================================================================
        "balance" => {
            let pw      = ask_password("Password: ");
            let key     = wallet_store::load_wallet(&pw, &wallet_file).expect("Failed to load wallet");
            let wallet  = crypto::Wallet::from_hex(&key);
            let chain   = load_or_init_chain(&chain_file);
            let addr    = wallet.address();

            println!("Address:      {}", addr);
            println!("Public key:   {}", public_key_hex(&wallet));
            println!("  (copy the above into genesis.json's public_key field)");
            println!("Spendable:    {} coins", chain.get_balance(&addr));
            println!("Staked:       {} coins", chain.get_stake(&addr));
            for p in chain.pending_unstake.iter().filter(|e| e.address == addr) {
                println!("  Unbonding:  {} coins (block #{})", p.amount, p.release_at_block);
            }
            println!("Next nonce:   {}", chain.next_nonce(&addr));
            println!("Supply:       {}/{}", chain.total_supply, MAX_SUPPLY);
            println!("Total staked: {} ({} validators)",
                chain.total_staked(), chain.validators.len());

            if chain.get_stake(&addr) >= MIN_STAKE {
                let next = chain.chain.len() as u64;
                match chain.select_validator(next) {
                    Some(sel) if sel == addr =>
                        println!("*** YOU ARE SELECTED for block #{} — run: validate", next),
                    Some(sel) =>
                        println!("Selected for block #{}: {}...", next, &sel[..16]),
                    None => println!("No validators registered."),
                }
            }
        }

        // =====================================================================
        // validators
        // =====================================================================
        "validators" => {
            let chain = load_or_init_chain(&chain_file);
            if chain.validators.is_empty() {
                println!("No validators. Use: stake <amount> --wallet <n>");
                return;
            }
            let total = chain.total_staked();
            let next  = chain.chain.len() as u64;
            let sel   = chain.select_validator(next);
            println!("Validators ({} total, {} coins staked):", chain.validators.len(), total);
            let mut sorted: Vec<_> = chain.validators.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));
            for (addr, stake) in sorted {
                let pct    = (*stake as f64 / total as f64) * 100.0;
                let marker = if sel.as_deref() == Some(addr) { " <- NEXT" } else { "" };
                println!("  {}...  {:>6} staked  ({:5.1}%){}",
                    &addr[..16], stake, pct, marker);
            }
        }

        // =====================================================================
        // stake <amount>
        // =====================================================================
        "stake" => {
            let amount: u64 = args.get(2).expect("Usage: stake <amount>")
                .parse().expect("Amount must be a number");
            let pw     = ask_password("Password: ");
            let key    = wallet_store::load_wallet(&pw, &wallet_file).expect("Failed to load wallet");
            let wallet = crypto::Wallet::from_hex(&key);
            let mut chain = load_or_init_chain(&chain_file);
            let addr  = wallet.address();
            let nonce = chain.next_nonce(&addr);
            let mut tx = Transaction::new_stake(public_key_hex(&wallet), addr, amount, nonce);
            tx.sign(&wallet);
            match chain.add_transaction(tx) {
                Ok(_) => {
                    chain_store::save_chain(&chain, &chain_file).expect("Failed to save");
                    println!("Stake queued ({} coins). A validator must produce a block to confirm it.", amount);
                }
                Err(e) => println!("Stake rejected: {}", e),
            }
        }

        // =====================================================================
        // unstake <amount>
        // =====================================================================
        "unstake" => {
            let amount: u64 = args.get(2).expect("Usage: unstake <amount>")
                .parse().expect("Amount must be a number");
            let pw     = ask_password("Password: ");
            let key    = wallet_store::load_wallet(&pw, &wallet_file).expect("Failed to load wallet");
            let wallet = crypto::Wallet::from_hex(&key);
            let mut chain = load_or_init_chain(&chain_file);
            let addr  = wallet.address();
            let nonce = chain.next_nonce(&addr);
            let mut tx = Transaction::new_unstake(public_key_hex(&wallet), addr, amount, nonce);
            tx.sign(&wallet);
            match chain.add_transaction(tx) {
                Ok(_) => {
                    chain_store::save_chain(&chain, &chain_file).expect("Failed to save");
                    println!("Unstake queued. Coins released after {} blocks.", UNBONDING_BLOCKS);
                }
                Err(e) => println!("Unstake rejected: {}", e),
            }
        }

        // =====================================================================
        // validate — continuous slot loop
        //
        // Runs forever. Every SLOT_SECONDS seconds:
        //   1. Reload the chain from disk (picks up any blocks peers produced)
        //   2. Check if this wallet is the selected validator for the next slot
        //   3. If yes: produce a block, save, clear mempool
        //   4. If no: print who is selected and wait for the next slot
        //
        // Press Ctrl+C to stop.
        // =====================================================================
        "validate" => {
            let pw     = ask_password("Password: ");
            let key    = wallet_store::load_wallet(&pw, &wallet_file).expect("Failed to load wallet");
            let wallet = crypto::Wallet::from_hex(&key);
            let addr   = wallet.address();

            println!("Starting validator loop for {}...", &addr[..16]);
            println!("Slot interval: {}s | Press Ctrl+C to stop", SLOT_SECONDS);

            let mut interval = tokio::time::interval(Duration::from_secs(SLOT_SECONDS));

            loop {
                interval.tick().await;

                // Always reload from disk so we see blocks other validators produced
                let mut chain = match chain_store::load_chain(&chain_file) {
                    Ok(c)  => c,
                    Err(e) => { eprintln!("Failed to load chain: {}", e); continue; }
                };

                let next_index = chain.chain.len() as u64;

                match chain.select_validator(next_index) {
                    None => {
                        println!("[slot {}] No validators registered.", next_index);
                    }
                    Some(selected) if selected != addr => {
                        println!("[slot {}] Selected: {}... (waiting)",
                            next_index, &selected[..16]);
                    }
                    Some(_) => {
                        // It's our turn
                        match chain.produce_block(&wallet) {
                            Ok(()) => {
                                chain_store::save_chain(&chain, &chain_file)
                                    .expect("Failed to save chain");
                                chain_store::clear_mempool(&chain_file);
                                println!("[slot {}] Block produced. Balance: {} | Staked: {}",
                                    next_index,
                                    chain.get_balance(&addr),
                                    chain.get_stake(&addr));
                            }
                            Err(e) => eprintln!("[slot {}] Block production failed: {}", next_index, e),
                        }
                    }
                }
            }
        }

        // =====================================================================
        // send <address> <amount> [peer]
        // =====================================================================
        "send" => {
            let to_address = args.get(2).expect("Usage: send <address> <amount> [peer]");
            let amount: u64 = args.get(3).expect("Usage: send <address> <amount> [peer]")
                .parse().expect("Amount must be a number");
            let pw     = ask_password("Password: ");
            let key    = wallet_store::load_wallet(&pw, &wallet_file).expect("Failed to load wallet");
            let wallet = crypto::Wallet::from_hex(&key);
            let mut chain = load_or_init_chain(&chain_file);
            let nonce = chain.next_nonce(&wallet.address());
            let mut tx = Transaction::new(public_key_hex(&wallet), to_address.clone(), amount, nonce);
            tx.sign(&wallet);
            match chain.add_transaction(tx.clone()) {
                Ok(_) => {
                    chain_store::save_chain(&chain, &chain_file).expect("Failed to save");
                    println!("Transaction queued (nonce: {}). Awaiting validator confirmation.", nonce);
                    if let Some(peer) = args.get(4).filter(|a| !a.starts_with("--")) {
                        match TcpStream::connect(peer).await {
                            Ok(mut s) => match send_message(&mut s, &Message::NewTransaction(tx)).await {
                                Ok(_)  => println!("Broadcast to {}", peer),
                                Err(e) => println!("Broadcast failed: {}", e),
                            },
                            Err(e) => println!("Could not reach {}: {}", peer, e),
                        }
                    }
                }
                Err(e) => println!("Transaction rejected: {}", e),
            }
        }

        // =====================================================================
        // chain
        // =====================================================================
        "chain" => {
            let chain = load_or_init_chain(&chain_file);
            println!("Blocks: {} | Supply: {}/{} | Valid: {}",
                chain.chain.len(), chain.total_supply, MAX_SUPPLY, chain.is_valid());
            for block in &chain.chain {
                let v = if block.validator == "genesis" || block.validator == "dev" {
                    block.validator.clone()
                } else {
                    format!("{}...", &block.validator[..16])
                };
                println!("\nBlock #{} | {} | Hash: {}...", block.index, v, &block.hash[..16]);
                for tx in &block.transactions {
                    let from = tx.sender_address();
                    let kind = match tx.kind {
                        TxKind::Transfer => "",
                        TxKind::Stake    => " [STAKE]",
                        TxKind::Unstake  => " [UNSTAKE]",
                        TxKind::Slash    => " [SLASH]",
                    };
                    let fd = match from.as_str() {
                        "coinbase" | "system" => format!("{:<16}", from),
                        s if s.starts_with("slash") => "slash           ".to_string(),
                        _ => format!("{}...", &from[..8]),
                    };
                    println!("  {} -> {}...  {} coins{}", fd, &tx.to[..8], tx.amount, kind);
                }
            }
        }

        // =====================================================================
        // node <port> [peer] [--seed <ip:port>]
        // =====================================================================
        "node" => {
            let port: u16 = args.get(2).expect("Usage: node <port> [peer]")
                .parse().expect("Port must be a number");
            let connect_to = args.get(3).filter(|a| !a.starts_with("--")).cloned();
            let seed_addr  = args.iter().position(|a| a == "--seed")
                .and_then(|i| args.get(i + 1)).cloned();

            let pw     = ask_password("Password: ");
            let key    = wallet_store::load_wallet(&pw, &wallet_file).expect("Failed to load wallet");
            let wallet = crypto::Wallet::from_hex(&key);
            println!("Node: {} ({}...)", wallet_file, &wallet.address()[..16]);

            let chain = load_or_init_chain(&chain_file);
            let chain = Arc::new(Mutex::new(chain));

            if let Some(ref seed) = seed_addr {
                let our_ip   = network::get_public_ip().await;
                let our_addr = format!("{}:{}", our_ip, port);
                println!("Registering with seed {}...", seed);
                let peer_list = network::register_with_seed(seed, &our_addr).await;
                let seed_c = seed.clone(); let addr_c = our_addr.clone();
                tokio::spawn(async move { network::heartbeat_loop(seed_c, addr_c).await; });
                let peers = network::new_peer_map();
                for peer_addr in peer_list {
                    let cc = Arc::clone(&chain); let pc = Arc::clone(&peers);
                    let path = chain_file.clone();
                    tokio::spawn(async move {
                        if let Ok(mut s) = TcpStream::connect(&peer_addr).await {
                            let _ = network::send_message(&mut s, &network::Message::RequestChain).await;
                            network::handle_peer_public(s, cc, pc, peer_addr, path).await;
                        }
                    });
                }
            }

            println!("Starting node on port {}...", port);
            start_node(port, connect_to, chain, chain_file.clone()).await;
        }

        // =====================================================================
        // mine-and-broadcast — FIXED: uses rebuild_derived_state(), no
        // duplicate replay loop.
        // =====================================================================
        "mine-and-broadcast" => {
            let peer = args.get(2).expect("Usage: mine-and-broadcast <peer_ip:port>");
            let pw     = ask_password("Password: ");
            let key    = wallet_store::load_wallet(&pw, &wallet_file).expect("Failed to load wallet");
            let wallet = crypto::Wallet::from_hex(&key);
            let mut chain = load_or_init_chain(&chain_file);

            // Sync — adopt peer chain if better using fork choice rule
            println!("Syncing from {}...", peer);
            match TcpStream::connect(peer).await {
                Ok(mut stream) => {
                    if send_message(&mut stream, &Message::RequestChain).await.is_ok() {
                        match network::receive_message(&mut stream).await {
                            Ok(Message::ResponseChain(their_chain)) => {
                                if chain.should_adopt(&their_chain) {
                                    println!("Adopting peer chain ({} blocks, our: {})",
                                        their_chain.len(), chain.chain.len());
                                    chain.chain = their_chain;
                                    // Single call — no duplicate loop
                                    chain.rebuild_derived_state();
                                    chain_store::save_chain(&chain, &chain_file)
                                        .expect("Failed to save synced chain");
                                } else {
                                    println!("Our chain is canonical ({} blocks)", chain.chain.len());
                                }
                            }
                            _ => println!("Sync incomplete — using local chain"),
                        }
                    }
                }
                Err(e) => println!("Could not reach peer: {} — using local chain", e),
            }

            // Produce block
            match chain.produce_block(&wallet) {
                Ok(()) => {
                    chain_store::save_chain(&chain, &chain_file).expect("Failed to save");
                    chain_store::clear_mempool(&chain_file);
                    let latest = chain.latest_block().clone();
                    match TcpStream::connect(peer).await {
                        Ok(mut s) => match send_message(&mut s, &Message::NewBlock(latest)).await {
                            Ok(_)  => println!("Block broadcast to {}", peer),
                            Err(e) => println!("Broadcast failed (saved locally): {}", e),
                        },
                        Err(e) => println!("Could not reach peer (saved locally): {}", e),
                    }
                    println!("Balance: {} | Staked: {}",
                        chain.get_balance(&wallet.address()),
                        chain.get_stake(&wallet.address()));
                }
                Err(e) => println!("Block production failed: {}", e),
            }
        }

        // =====================================================================
        // dev-fund <address> <amount>
        // =====================================================================
        "dev-fund" => {
            let address = args.get(2).expect("Usage: dev-fund <address> <amount>");
            let amount: u64 = args.get(3).expect("Usage: dev-fund <address> <amount>")
                .parse().expect("Amount must be a number");
            if address.len() != 64 || hex::decode(address).is_err() {
                println!("Invalid address — must be 64 hex chars."); return;
            }
            let mut chain = load_or_init_chain(&chain_file);
            let remaining = MAX_SUPPLY.saturating_sub(chain.total_supply);
            if amount > remaining {
                println!("Cannot fund {} — only {} remain before MAX_SUPPLY.", amount, remaining);
                return;
            }
            let tx = Transaction::new_reward(address.clone(), amount);
            let prev  = chain.latest_block().hash.clone();
            let index = chain.chain.len() as u64;
            let mut block = crate::block::Block::new(index, prev, "dev".to_string(), vec![tx.clone()]);
            block.validator_sig = vec![];
            chain.total_supply += amount;
            chain.apply_transactions(&[tx]);
            chain.chain.push(block);
            chain_store::save_chain(&chain, &chain_file).expect("Failed to save");
            println!("[DEV] Funded {} coins -> {}...", amount, &address[..16]);
            println!("[DEV] Spendable: {} | Supply: {}/{}",
                chain.get_balance(address), chain.total_supply, MAX_SUPPLY);
        }

        // =====================================================================
        // dev-stake <address> <amount>
        // =====================================================================
        "dev-stake" => {
            let address = args.get(2).expect("Usage: dev-stake <address> <amount>");
            let amount: u64 = args.get(3).expect("Usage: dev-stake <address> <amount>")
                .parse().expect("Amount must be a number");
            if address.len() != 64 || hex::decode(address).is_err() {
                println!("Invalid address — must be 64 hex chars."); return;
            }
            if amount < MIN_STAKE {
                println!("Amount {} below MIN_STAKE ({}).", amount, MIN_STAKE); return;
            }
            let mut chain = load_or_init_chain(&chain_file);
            let tx = Transaction {
                kind: crate::transaction::TxKind::Stake,
                from: "coinbase".to_string(),
                to:   address.clone(),
                amount, nonce: 0, signature: None, slash_evidence: None,
            };
            let prev  = chain.latest_block().hash.clone();
            let index = chain.chain.len() as u64;
            let mut block = crate::block::Block::new(index, prev, "dev".to_string(), vec![tx.clone()]);
            block.validator_sig = vec![];
            *chain.validators.entry(address.clone()).or_insert(0) += amount;
            chain.chain.push(block);
            chain_store::save_chain(&chain, &chain_file).expect("Failed to save");
            println!("[DEV] Registered {}... as validator with {} staked.", &address[..16], amount);
            println!("[DEV] Total validators: {} | Total staked: {}",
                chain.validators.len(), chain.total_staked());
            println!("NOTE: run 'stake' + 'validate' to register your public key for sig verification.");
        }

        // =====================================================================
        // dev-genesis
        //
        // TESTING ONLY — creates genesis.json and chain.json from one or more
        // wallet files in one command. No manual hex copying required.
        //
        // Usage:
        //   cargo run -- dev-genesis --wallet alice
        //   cargo run -- dev-genesis --wallet alice --also bob --also carol
        //
        // Each wallet gets GENESIS_BALANCE spendable coins and GENESIS_STAKE
        // staked coins. The chain.json is written immediately so the next
        // command (validate, balance, etc.) works straight away.
        //
        // If chain.json already exists this command refuses to run — delete
        // it first if you want to reset the network.
        // =====================================================================
        "dev-genesis" => {
            // Refuse to overwrite an existing chain
            if std::path::Path::new(&chain_file).exists() {
                println!("'{}' already exists — delete it first to reset the network.", chain_file);
                println!("  del {}     (Windows)", chain_file);
                println!("  rm {}      (Linux/Mac)", chain_file);
                return;
            }

            const GENESIS_BALANCE: u64 = 500;
            const GENESIS_STAKE:   u64 = 100;

            // Collect all wallet names: primary --wallet plus any --also flags
            let mut wallet_names: Vec<String> = vec![wallet_file.clone()];
            let mut i = 0;
            while i < args.len() {
                if args[i] == "--also" {
                    if let Some(name) = args.get(i + 1) {
                        wallet_names.push(format!("{}.dat", name));
                    }
                }
                i += 1;
            }

            println!("Building genesis from {} wallet(s)...", wallet_names.len());

            let pw = ask_password("Password (same for all wallets): ");

            let mut accounts: Vec<GenesisAccount> = vec![];

            for wf in &wallet_names {
                let key = match wallet_store::load_wallet(&pw, wf) {
                    Ok(k)  => k,
                    Err(e) => {
                        println!("Could not load '{}': {}", wf, e);
                        println!("Make sure the wallet exists and the password is correct.");
                        return;
                    }
                };
                let w       = crypto::Wallet::from_hex(&key);
                let address = w.address();
                let pk      = w.public_key.clone();

                println!("  {} -> {}...", wf, &address[..16]);

                accounts.push(GenesisAccount {
                    address,
                    public_key: pk,
                    balance:    GENESIS_BALANCE,
                    stake:      GENESIS_STAKE,
                });
            }

            // Write genesis.json so it can be inspected / shared with peers
            #[derive(serde::Serialize)]
            struct GenesisEntry<'a> {
                address:    &'a str,
                public_key: String,
                balance:    u64,
                stake:      u64,
            }

            let entries: Vec<GenesisEntry> = accounts.iter().map(|a| GenesisEntry {
                address:    &a.address,
                public_key: hex::encode(&a.public_key),
                balance:    a.balance,
                stake:      a.stake,
            }).collect();

            let genesis_json = serde_json::to_string_pretty(&entries)
                .expect("Failed to serialise genesis.json");
            std::fs::write("genesis.json", &genesis_json)
                .expect("Failed to write genesis.json");

            // Build and save the chain immediately
            let total_balance: u64 = accounts.iter().map(|a| a.balance).sum();
            let total_stake:   u64 = accounts.iter().map(|a| a.stake).sum();

            let chain = Blockchain::new_with_genesis(accounts);
            chain_store::save_chain(&chain, &chain_file)
                .expect("Failed to save genesis chain");

            println!();
            println!("Genesis complete!");
            println!("  Wallets:       {}", wallet_names.len());
            println!("  Each balance:  {} coins spendable", GENESIS_BALANCE);
            println!("  Each stake:    {} coins staked", GENESIS_STAKE);
            println!("  Total supply:  {} coins", total_balance);
            println!("  Total staked:  {} coins", total_stake);
            println!("  genesis.json:  written");
            println!("  {}:  written", chain_file);
            println!();
            println!("Next step:");
            println!("  cargo run -- validate --wallet alice");
        }

        // =====================================================================
        // help
        // =====================================================================
        _ => {
            println!("Commands:");
            println!("  new-wallet                        create wallet (24-word phrase)");
            println!("  recover-wallet                    regenerate from phrase");
            println!("  list-wallets                      show all wallets");
            println!("  balance                           address, balances, validator status");
            println!("  validators                        list all validators");
            println!("  stake <amount>                    lock coins as a validator");
            println!("  unstake <amount>                  begin unbonding");
            println!("  validate                          continuous slot loop (Ctrl+C to stop)");
            println!("  send <to> <amount> [peer]         send coins");
            println!("  chain                             print all blocks");
            println!("  node <port> [peer]                start P2P node");
            println!("  mine-and-broadcast <peer>         sync, produce block, broadcast");
            println!();
            println!("Testing commands:");
            println!("  dev-genesis                       create genesis from wallet file(s)");
            println!("  dev-genesis --also bob            include multiple wallets");
            println!("  dev-fund <address> <amount>       credit coins directly");
            println!("  dev-stake <address> <amount>      register validator directly");
            println!();
            println!("Options:");
            println!("  --wallet <n>   (default: wallet.dat)");
            println!("  --network <n>  (default: chain.json)");
            println!();
            println!("Quickstart (one command to bootstrap):");
            println!("  cargo run -- new-wallet --wallet alice");
            println!("  cargo run -- dev-genesis --wallet alice");
            println!("  cargo run -- validate --wallet alice");
            println!();
            println!("Multi-validator bootstrap:");
            println!("  cargo run -- new-wallet --wallet alice");
            println!("  cargo run -- new-wallet --wallet bob");
            println!("  cargo run -- dev-genesis --wallet alice --also bob");
            println!("  # Terminal 1:"); 
            println!("  cargo run -- validate --wallet alice");
            println!("  # Terminal 2:");
            println!("  cargo run -- validate --wallet bob");
        }
    }
}
