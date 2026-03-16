// =============================================================================
// main.rs — Command Line Interface
// =============================================================================
//
// Entry point for the program. Reads the user's command, resolves which wallet
// and chain files to use, and routes to the appropriate handler.
//
// COMMANDS:
//
//   new-wallet              Generate a new post-quantum wallet, encrypted with a password
//   list-wallets            Show all .dat wallet files in the current directory
//   balance                 Show your address, balance, and current nonce
//   mine                    Mine a block locally and earn the block reward
//   mine-and-broadcast      Sync chain, mine a block, broadcast to a peer
//   send <to> <amount>      Sign a transaction and submit it to the mempool
//   chain                   Print every block and its transactions
//   node <port> [peer]      Start a persistent P2P node (runs until Ctrl+C)
//   recover-wallet          Recover wallet from 12-word phrase + .phrase file
//   show-phrase             Display your 12-word recovery phrase
//
// GLOBAL OPTIONS (append to any command):
//
//   --wallet <n>     use wallet file <n>.dat          (default: wallet.dat)
//   --network <n>    use chain file <n>_chain.json    (default: chain.json)
//   --seed <ip:port> register with a seed node for peer discovery
//
// BLOCK PROPAGATION:
//
//   The node command now maintains a shared PeerMap — a registry of all
//   connected peers. When a block or transaction arrives from any peer,
//   it is automatically forwarded to all other connected peers. This means
//   broadcasting to ANY one peer propagates to the whole network.
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

use crate::blockchain::MAX_SUPPLY;
use crate::transaction::Transaction;
use crate::network::{start_node, send_message, Message};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::net::TcpStream;
use std::io::{self, Write};

// =============================================================================
// Helpers
// =============================================================================

/// Prints a prompt and reads one line from stdin.
/// Input is visible as the user types. Trailing newline is trimmed.
fn ask_password(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

/// Finds "--wallet <n>" in args and returns "<n>.dat".
/// Defaults to "wallet.dat" if the flag is absent.
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

/// Finds "--network <n>" in args and returns "<n>_chain.json".
/// Defaults to "chain.json" if the flag is absent.
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

/// Returns the wallet's full Dilithium3 public key as hex.
///
/// Used as Transaction.from — distinct from wallet.address():
///   wallet.address()  =  SHA-256(public_key)  64 chars, for display/receiving
///   public_key_hex()  =  hex(public_key)       3,904 chars, stored in transactions
fn public_key_hex(wallet: &crypto::Wallet) -> String {
    hex::encode(&wallet.public_key)
}

// =============================================================================
// Entry Point
// =============================================================================

/// Async main — #[tokio::main] is required for the networking layer.
#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command     = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    let wallet_file = get_wallet_file(&args);
    let chain_file  = get_chain_file(&args);

    match command {

        // =====================================================================
        // new-wallet
        // Generate a Dilithium3 key pair, show 12-word recovery phrase,
        // encrypt with password, save to disk.
        // =====================================================================
        "new-wallet" => {
            if std::path::Path::new(wallet_file.as_str()).exists() {
                println!("Wallet '{}' already exists!", wallet_file);
                println!("Use a different name: cargo run -- new-wallet --wallet <n>");
                return;
            }

            let password = ask_password("Choose a password: ");
            let confirm  = ask_password("Confirm password: ");
            if password != confirm {
                println!("Passwords don't match — wallet not created");
                return;
            }

            let wallet = crypto::Wallet::new();
            let combined_key_hex = format!(
                "{}{}",
                hex::encode(&wallet.private_key),
                hex::encode(&wallet.public_key)
            );

            let phrase = seed_phrase::generate_phrase();

            println!("\n╔══════════════════════════════════════════════════════════════╗");
            println!("║           YOUR RECOVERY PHRASE — WRITE THIS DOWN            ║");
            println!("╠══════════════════════════════════════════════════════════════╣");
            println!("{}", seed_phrase::format_for_display(&phrase));
            println!("╠══════════════════════════════════════════════════════════════╣");
            println!("║  These 12 words can restore your wallet if you lose your    ║");
            println!("║  password or wallet file. Write them on paper. Never store  ║");
            println!("║  them digitally. Anyone with these words owns your coins.   ║");
            println!("╚══════════════════════════════════════════════════════════════╝\n");

            let confirm_word = ask_password("Type word #4 to confirm you wrote them down: ");
            let word_4 = phrase.split_whitespace().nth(3).unwrap_or("");
            if confirm_word.trim() != word_4 {
                println!("Wrong word — wallet not created. Try again and write them down first.");
                return;
            }

            wallet_store::save_wallet(&combined_key_hex, &password, wallet_file.as_str())
                .expect("Failed to save wallet");

            let phrase_file = wallet_file.replace(".dat", ".phrase");
            seed_phrase::save_phrase_backup(&combined_key_hex, &phrase, &phrase_file)
                .expect("Failed to save phrase backup");

            println!("Wallet created: {}", wallet_file);
            println!("Your address:   {}", wallet.address());
            println!("KEEP BOTH YOUR PASSWORD AND YOUR 12 WORDS SAFE");
        }

        // =====================================================================
        // list-wallets
        // =====================================================================
        "list-wallets" => {
            let entries = std::fs::read_dir(".").unwrap();
            println!("Available wallets:");
            for entry in entries {
                let entry = entry.unwrap();
                let name  = entry.file_name();
                let name  = name.to_string_lossy();
                if name.ends_with(".dat") {
                    println!("  {}  →  use: --wallet {}", name, name.replace(".dat", ""));
                }
            }
        }

        // =====================================================================
        // balance
        // =====================================================================
        "balance" => {
            let password     = ask_password("Password: ");
            let combined_key = wallet_store::load_wallet(&password, wallet_file.as_str())
                .expect("Failed to load wallet");
            let wallet = crypto::Wallet::from_hex(&combined_key);
            let chain  = chain_store::load_chain(chain_file.as_str())
                .expect("Failed to load chain");

            let addr       = wallet.address();
            let balance    = chain.get_balance(&addr);
            let next_nonce = chain.next_nonce(&addr);

            println!("Address:    {}", addr);
            println!("Balance:    {} coins", balance);
            println!("Next nonce: {} (used automatically when sending)", next_nonce);
            println!("Supply:     {}/{} coins in circulation", chain.total_supply, MAX_SUPPLY);
        }

        // =====================================================================
        // mine
        // =====================================================================
        "mine" => {
            let password     = ask_password("Password: ");
            let combined_key = wallet_store::load_wallet(&password, wallet_file.as_str())
                .expect("Failed to load wallet");
            let wallet    = crypto::Wallet::from_hex(&combined_key);
            let mut chain = chain_store::load_chain(chain_file.as_str())
                .expect("Failed to load chain");

            chain.mine_block(wallet.address());

            chain_store::save_chain(&chain, chain_file.as_str())
                .expect("Failed to save chain");
            chain_store::clear_mempool(chain_file.as_str());

            println!("Your balance: {} coins", chain.get_balance(&wallet.address()));
        }

        // =====================================================================
        // send <recipient_address> <amount> [peer_ip:port]
        // =====================================================================
        "send" => {
            let to_address = args.get(2).expect("Usage: send <address> <amount> [peer]");
            let amount: u64 = args.get(3)
                .expect("Usage: send <address> <amount> [peer]")
                .parse()
                .expect("Amount must be a whole number");

            let password     = ask_password("Password: ");
            let combined_key = wallet_store::load_wallet(&password, wallet_file.as_str())
                .expect("Failed to load wallet");
            let wallet    = crypto::Wallet::from_hex(&combined_key);
            let mut chain = chain_store::load_chain(chain_file.as_str())
                .expect("Failed to load chain");

            let nonce = chain.next_nonce(&wallet.address());
            let from  = public_key_hex(&wallet);

            let mut tx = Transaction::new(from, to_address.clone(), amount, nonce);
            tx.sign(&wallet);

            println!("Transaction nonce: {} (replay protection)", nonce);

            match chain.add_transaction(tx.clone()) {
                Ok(_) => {
                    chain_store::save_chain(&chain, chain_file.as_str())
                        .expect("Failed to save");
                    println!("Transaction added to mempool — mine a block to confirm it");

                    if let Some(peer) = args.get(4).filter(|a| !a.starts_with("--")) {
                        match TcpStream::connect(peer).await {
                            Ok(mut stream) => {
                                match send_message(&mut stream, &Message::NewTransaction(tx)).await {
                                    Ok(_)  => println!("Transaction broadcast to {}", peer),
                                    Err(e) => println!("Broadcast failed: {}", e),
                                }
                            }
                            Err(e) => println!("Could not reach peer {}: {}", peer, e),
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
            let chain = chain_store::load_chain(chain_file.as_str())
                .expect("Failed to load chain");

            println!("Blocks: {} | Supply: {}/{} | Valid: {}",
                chain.chain.len(), chain.total_supply, MAX_SUPPLY, chain.is_valid());

            for block in &chain.chain {
                println!("\nBlock #{} | Hash: {}...", block.index, &block.hash[..16]);
                for tx in &block.transactions {
                    let from = tx.sender_address();
                    let from_display = if from == "coinbase" {
                        "coinbase ".to_string()
                    } else {
                        format!("{}...", &from[..8])
                    };
                    if tx.from == "coinbase" {
                        println!("  {} → {}... : {} coins",
                            from_display, &tx.to[..8], tx.amount);
                    } else {
                        println!("  {} → {}... : {} coins  [nonce: {}]",
                            from_display, &tx.to[..8], tx.amount, tx.nonce);
                    }
                }
            }
        }

        // =====================================================================
        // node <port> [direct_peer] [--seed <seed_ip:port>]
        //
        // Starts a persistent P2P node. Runs forever until Ctrl+C.
        //
        // A shared PeerMap is created here and passed to every peer handler
        // (both direct connections and seed-discovered connections). This means
        // all peers share the same propagation registry — a block arriving from
        // any peer is forwarded to all others automatically.
        // =====================================================================
        "node" => {
            let port: u16 = args.get(2)
                .expect("Usage: node <port> [peer] [--seed <ip:port>]")
                .parse()
                .expect("Port must be a number");

            let connect_to = args.get(3)
                .filter(|a| !a.starts_with("--"))
                .cloned();

            let seed_addr = args.iter()
                .position(|a| a == "--seed")
                .and_then(|i| args.get(i + 1))
                .cloned();

            let password     = ask_password("Password: ");
            let combined_key = wallet_store::load_wallet(&password, wallet_file.as_str())
                .expect("Failed to load wallet");
            let wallet = crypto::Wallet::from_hex(&combined_key);

            println!("Wallet: {} ({}...)", wallet_file, &wallet.address()[..16]);
            println!("Chain:  {}", chain_file);

            let chain = chain_store::load_chain(chain_file.as_str())
                .expect("Failed to load chain");
            let chain = Arc::new(Mutex::new(chain));

            // Seed node peer discovery
            if let Some(ref seed) = seed_addr {
                let our_ip   = network::get_public_ip().await;
                let our_addr = format!("{}:{}", our_ip, port);

                println!("Registering with seed node {}...", seed);
                println!("Our listen address: {}", our_addr);

                let peer_list = network::register_with_seed(seed, &our_addr).await;

                let seed_clone = seed.clone();
                let addr_clone = our_addr.clone();
                tokio::spawn(async move {
                    network::heartbeat_loop(seed_clone, addr_clone).await;
                });

                // Create the shared peer map here so seed-discovered peers
                // share the same map as peers connected via start_node.
                // We pass it into handle_peer_public for each seed peer,
                // and start_node creates its own internally — they share
                // the same Arc so both sets of peers are in one registry.
                let peers = network::new_peer_map();

                for peer_addr in peer_list {
                    let chain_clone = Arc::clone(&chain);
                    let peers_clone = Arc::clone(&peers);
                    let path_clone  = chain_file.clone();
                    tokio::spawn(async move {
                        match TcpStream::connect(&peer_addr).await {
                            Ok(mut stream) => {
                                println!("[seed] Connecting to peer: {}", peer_addr);
                                let _ = network::send_message(
                                    &mut stream,
                                    &network::Message::RequestChain
                                ).await;
                                network::handle_peer_public(
                                    stream, chain_clone, peers_clone,
                                    peer_addr, path_clone
                                ).await;
                            }
                            Err(e) => println!("[seed] Could not reach peer {}: {}", peer_addr, e),
                        }
                    });
                }
            }

            println!("Starting node on port {}...", port);
            start_node(port, connect_to, chain, chain_file.clone()).await;
        }

        // =====================================================================
        // mine-and-broadcast <peer_ip:port>
        //
        // Syncs chain from peer first, then mines, then broadcasts.
        // =====================================================================
        "mine-and-broadcast" => {
            let peer = args.get(2)
                .expect("Usage: mine-and-broadcast <peer_ip:port>");

            let password     = ask_password("Password: ");
            let combined_key = wallet_store::load_wallet(&password, wallet_file.as_str())
                .expect("Failed to load wallet");
            let wallet    = crypto::Wallet::from_hex(&combined_key);
            let mut chain = chain_store::load_chain(chain_file.as_str())
                .expect("Failed to load chain");

            // ── SYNC FIRST ──────────────────────────────────────────────────
            println!("Syncing chain from {}...", peer);
            match TcpStream::connect(peer).await {
                Ok(mut stream) => {
                    if send_message(&mut stream, &Message::RequestChain).await.is_ok() {
                        match network::receive_message(&mut stream).await {
                            Ok(Message::ResponseChain(their_chain)) => {
                                if their_chain.len() > chain.chain.len() {
                                    println!("Adopting peer chain ({} blocks vs our {})",
                                        their_chain.len(), chain.chain.len());
                                    chain.chain        = their_chain;
                                    chain.utxo_set.clear();
                                    chain.tx_nonces.clear();
                                    chain.total_supply = 0;
                                    for block in &chain.chain.clone() {
                                        for tx in &block.transactions {
                                            if tx.from == "coinbase" {
                                                chain.total_supply += tx.amount;
                                            } else {
                                                let s = chain.utxo_set
                                                    .entry(tx.sender_address())
                                                    .or_insert(0);
                                                *s -= tx.amount;
                                                chain.tx_nonces
                                                    .insert(tx.sender_address(), tx.nonce);
                                            }
                                            let r = chain.utxo_set
                                                .entry(tx.to.clone())
                                                .or_insert(0);
                                            *r += tx.amount;
                                        }
                                    }
                                    chain_store::save_chain(&chain, chain_file.as_str())
                                        .expect("Failed to save synced chain");
                                } else {
                                    println!("Our chain is current ({} blocks)", chain.chain.len());
                                }
                            }
                            Ok(_)  => println!("Unexpected response during sync"),
                            Err(e) => println!("Sync error: {} — mining on local chain", e),
                        }
                    }
                }
                Err(e) => {
                    println!("Could not reach peer for sync: {} — mining on local chain", e);
                }
            }

            // ── MINE ────────────────────────────────────────────────────────
            println!("Mining on chain tip: block #{}", chain.latest_block().index);
            chain.mine_block(wallet.address());
            chain_store::save_chain(&chain, chain_file.as_str())
                .expect("Failed to save chain");
            chain_store::clear_mempool(chain_file.as_str());

            // ── BROADCAST ───────────────────────────────────────────────────
            // The peer's node will receive the block and propagate it to all
            // of its connected peers automatically via the PeerMap.
            let latest_block = chain.latest_block().clone();
            match TcpStream::connect(peer).await {
                Ok(mut stream) => {
                    match send_message(&mut stream, &Message::NewBlock(latest_block)).await {
                        Ok(_)  => println!("Block broadcast to {}", peer),
                        Err(e) => println!("Broadcast failed (block saved locally): {}", e),
                    }
                }
                Err(e) => println!("Could not reach peer {} (block saved locally): {}", peer, e),
            }

            println!("Your balance: {} coins", chain.get_balance(&wallet.address()));
        }

        // =====================================================================
        // recover-wallet
        // =====================================================================
        "recover-wallet" => {
            if std::path::Path::new(wallet_file.as_str()).exists() {
                println!("Wallet '{}' already exists!", wallet_file);
                println!("Use --wallet <n> to recover to a different name");
                return;
            }

            println!("Enter your 12 recovery words separated by spaces:");
            let phrase = ask_password("Recovery phrase: ");

            if let Err(e) = seed_phrase::validate_phrase(&phrase) {
                println!("Error: {}", e);
                return;
            }

            let phrase_file = wallet_file.replace(".dat", ".phrase");
            println!("Looking for phrase backup file: {}", phrase_file);
            println!("(This file must be present — copy it from your backup)");

            let (combined_key_hex, _stored_phrase) =
                match seed_phrase::load_phrase_backup(&phrase, &phrase_file) {
                    Ok(result) => result,
                    Err(e) => {
                        println!("Recovery failed: {}", e);
                        return;
                    }
                };

            let wallet = crypto::Wallet::from_hex(&combined_key_hex);
            println!("Recovered address: {}", wallet.address());
            println!("Is this your address? (yes/no)");
            let confirm = ask_password("");
            if confirm.trim().to_lowercase() != "yes" {
                println!("Address mismatch — check your phrase is correct and complete.");
                return;
            }

            let new_password = ask_password("Choose a new password: ");
            let confirm_pw   = ask_password("Confirm password: ");
            if new_password != confirm_pw {
                println!("Passwords don't match — recovery cancelled");
                return;
            }

            wallet_store::save_wallet(&combined_key_hex, &new_password, wallet_file.as_str())
                .expect("Failed to save recovered wallet");

            println!("Wallet recovered: {}", wallet_file);
            println!("Your address: {}", wallet.address());
        }

        // =====================================================================
        // show-phrase
        // =====================================================================
        "show-phrase" => {
            let phrase_file = wallet_file.replace(".dat", ".phrase");
            if !std::path::Path::new(&phrase_file).exists() {
                println!("No phrase backup found for '{}'.", wallet_file);
                println!("This wallet was created before phrase support was added.");
                return;
            }

            println!("Your 12 recovery words will be shown. Make sure nobody can see your screen.");
            let confirm = ask_password("Type 'show' to continue: ");
            if confirm.trim() != "show" {
                println!("Cancelled.");
                return;
            }

            println!("Enter your 12 recovery words to decrypt the backup:");
            let phrase = ask_password("Recovery phrase: ");

            match seed_phrase::load_phrase_backup(&phrase, &phrase_file) {
                Ok((_, stored_phrase)) => {
                    println!("\n╔══════════════════════════════════════════════════════════════╗");
                    println!("║                  YOUR RECOVERY PHRASE                       ║");
                    println!("╠══════════════════════════════════════════════════════════════╣");
                    println!("{}", seed_phrase::format_for_display(&stored_phrase));
                    println!("╚══════════════════════════════════════════════════════════════╝\n");
                }
                Err(e) => println!("Failed to load phrase: {}", e),
            }
        }

        // =====================================================================
        // help
        // =====================================================================
        _ => {
            println!("Commands:");
            println!("  new-wallet                        create a new encrypted wallet");
            println!("  list-wallets                      show all wallets on this machine");
            println!("  balance                           show address, balance, and nonce");
            println!("  mine                              mine a block and earn rewards");
            println!("  mine-and-broadcast <peer>         sync, mine, and broadcast");
            println!("  send <to> <amount> [peer]         send coins to an address");
            println!("  chain                             print all blocks and transactions");
            println!("  node <port> [peer]                start a persistent P2P node");
            println!("  recover-wallet                    recover wallet from 12-word phrase");
            println!("  show-phrase                       display your recovery phrase");
            println!();
            println!("Options (append to any command):");
            println!("  --wallet <n>      wallet file to use       (default: wallet.dat)");
            println!("  --network <n>     chain file to use        (default: chain.json)");
            println!("  --seed <ip:port>  seed node for discovery  (use with node command)");
            println!();
            println!("Examples:");
            println!("  cargo run -- new-wallet --wallet alice");
            println!("  cargo run -- balance --wallet alice");
            println!("  cargo run -- mine --wallet alice --network mainnet");
            println!("  cargo run -- node 8001 --wallet alice --network mainnet");
            println!("  cargo run -- node 8001 --seed 136.111.45.6:8000 --wallet alice");
            println!("  cargo run -- node 8001 127.0.0.1:8000 --wallet alice");
            println!("  cargo run -- mine-and-broadcast 127.0.0.1:8000 --wallet alice");
            println!("  cargo run -- send <address> 10 --wallet alice");
            println!("  cargo run -- send <address> 10 127.0.0.1:8000 --wallet alice");
        }
    }
}
