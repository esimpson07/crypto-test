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
//   balance                 Show your address and current coin balance
//   mine                    Mine a block locally and earn the block reward
//   mine-and-broadcast      Mine a block and immediately broadcast it to a peer
//   send <to> <amount>      Sign a transaction and submit it to the mempool
//   chain                   Print every block and its transactions
//   node <port> [peer]      Start a persistent P2P node (runs until Ctrl+C)
//
// GLOBAL OPTIONS (append to any command):
//
//   --wallet <n>    use wallet file <n>.dat          (default: wallet.dat)
//   --network <n>   use chain file <n>_chain.json    (default: chain.json)
//   --seed <ip:port> register with a seed node for peer discovery
//
// EXAMPLES:
//
//   cargo run -- new-wallet --wallet alice
//   cargo run -- balance --wallet alice
//   cargo run -- mine --wallet alice --network mainnet
//   cargo run -- send <address> 10 --wallet alice
//   cargo run -- send <address> 10 192.168.1.5:8000 --wallet alice
//   cargo run -- node 8001 --wallet alice --network mainnet
//   cargo run -- node 8001 --seed 136.111.45.6:8000 --wallet alice
//   cargo run -- node 8001 192.168.1.5:8000 --wallet alice
//   cargo run -- mine-and-broadcast 192.168.1.5:8000 --wallet alice
//
// POST-QUANTUM NOTES:
//
//   Wallet addresses are SHA-256(public_key) — a compact 64-char hex string.
//   Transaction.from stores the FULL public key (3,904 chars) because
//   Dilithium3 signature verification requires the actual key bytes, not
//   just the address hash. Recipients always share their compact address.
//
//   The combined private+public key hex is what wallet_store.rs encrypts.
//   Wallet.from_hex() splits them using the crate's reported key size —
//   NOT a hardcoded constant — to handle version differences correctly.
// =============================================================================

#![allow(unused_imports, dead_code)]

mod crypto;
mod transaction;
mod block;
mod blockchain;
mod wallet_store;
mod chain_store;
mod network;

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
/// Lets you run separate blockchains on the same machine:
///   --network mainnet  →  mainnet_chain.json
///   --network testnet  →  testnet_chain.json
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
/// This is used as Transaction.from — distinct from wallet.address():
///   wallet.address()  =  SHA-256(public_key)  64 chars, for display/receiving
///   public_key_hex()  =  hex(public_key)       3,904 chars, stored in transactions
///
/// The full key is required in transactions because Dilithium3 verification
/// needs the actual key bytes — it cannot recover them from a signature
/// the way classical ECDSA can.
fn public_key_hex(wallet: &crypto::Wallet) -> String {
    hex::encode(&wallet.public_key)
}

// =============================================================================
// Entry Point
// =============================================================================

/// Async main — the #[tokio::main] macro is required for the networking layer.
/// Dispatches to the appropriate command handler based on argv[1].
#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command     = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    let wallet_file = get_wallet_file(&args);
    let chain_file  = get_chain_file(&args);

    match command {

        // =====================================================================
        // new-wallet
        // Generate a Dilithium3 key pair, encrypt with password, save to disk.
        // =====================================================================
        "new-wallet" => {
            // Refuse to overwrite — losing a private key means losing coins forever
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

            // Show actual key sizes so the user knows what their crate version uses
            println!("Key sizes — private: {} bytes, public: {} bytes",
                wallet.private_key.len(), wallet.public_key.len());

            // Concatenate private key + public key as one hex string for encryption.
            // from_hex() splits them on load using the crate's reported key size.
            let combined_key_hex = format!(
                "{}{}",
                hex::encode(&wallet.private_key),
                hex::encode(&wallet.public_key)
            );

            wallet_store::save_wallet(&combined_key_hex, &password, wallet_file.as_str())
                .expect("Failed to save wallet");

            println!("Wallet created: {}", wallet_file);
            println!("Your address:   {}", wallet.address()); // SHA-256(public_key)
            println!("KEEP YOUR PASSWORD SAFE — it cannot be recovered if lost");
        }

        // =====================================================================
        // list-wallets
        // Show all .dat files in the current directory.
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
        // Show this wallet's address and current coin balance.
        // =====================================================================
        "balance" => {
            let password     = ask_password("Password: ");
            let combined_key = wallet_store::load_wallet(&password, wallet_file.as_str())
                .expect("Failed to load wallet");
            let wallet = crypto::Wallet::from_hex(&combined_key);
            let chain  = chain_store::load_chain(chain_file.as_str())
                .expect("Failed to load chain");

            println!("Address: {}", wallet.address());
            println!("Balance: {} coins", chain.get_balance(&wallet.address()));
            println!("Supply:  {}/{} coins in circulation", chain.total_supply, MAX_SUPPLY);
        }

        // =====================================================================
        // mine
        // Run proof-of-work locally. Block reward and confirmed mempool
        // transactions go to this wallet's address.
        // =====================================================================
        "mine" => {
            let password     = ask_password("Password: ");
            let combined_key = wallet_store::load_wallet(&password, wallet_file.as_str())
                .expect("Failed to load wallet");
            let wallet    = crypto::Wallet::from_hex(&combined_key);
            let mut chain = chain_store::load_chain(chain_file.as_str())
                .expect("Failed to load chain");

            chain.mine_block(wallet.address()); // blocks until a valid nonce is found

            chain_store::save_chain(&chain, chain_file.as_str())
                .expect("Failed to save chain");
            chain_store::clear_mempool(chain_file.as_str());

            println!("Your balance: {} coins", chain.get_balance(&wallet.address()));
        }

        // =====================================================================
        // send <recipient_address> <amount> [peer_ip:port]
        //
        // Signs a transaction and adds it to the local mempool.
        // Optionally broadcasts it to a peer node immediately.
        //
        // Transaction.from  = FULL public key hex (needed for Dilithium verification)
        // Transaction.to    = recipient's compact address (from their `balance` command)
        //
        // The transaction stays pending until someone mines a block.
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

            let from   = public_key_hex(&wallet); // full public key, not address
            let mut tx = Transaction::new(from, to_address.clone(), amount);
            tx.sign(&wallet);

            match chain.add_transaction(tx.clone()) {
                Ok(_) => {
                    chain_store::save_chain(&chain, chain_file.as_str())
                        .expect("Failed to save");
                    println!("Transaction added to mempool — mine a block to confirm it");

                    // If a peer address was provided as argv[4], broadcast to them
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
        // Print every block and its transactions. Validates the full chain.
        // =====================================================================
        "chain" => {
            let chain = chain_store::load_chain(chain_file.as_str())
                .expect("Failed to load chain");

            println!("Blocks: {} | Supply: {}/{} | Valid: {}",
                chain.chain.len(), chain.total_supply, MAX_SUPPLY, chain.is_valid());

            for block in &chain.chain {
                println!("\nBlock #{} | Hash: {}...", block.index, &block.hash[..16]);
                for tx in &block.transactions {
                    // sender_address() hashes tx.from (full public key) → compact address
                    let from = tx.sender_address();
                    let from_display = if from == "coinbase" {
                        "coinbase ".to_string()
                    } else {
                        format!("{}...", &from[..8])
                    };
                    println!("  {} → {}... : {} coins",
                        from_display, &tx.to[..8], tx.amount);
                }
            }
        }

        // =====================================================================
        // node <port> [direct_peer] [--seed <seed_ip:port>]
        //
        // Starts a persistent P2P node. Runs forever until Ctrl+C.
        //
        // Direct peer (optional):  connects immediately on startup
        //   cargo run -- node 8001 192.168.1.5:8000 --wallet alice
        //
        // Seed node (optional):    registers for peer discovery
        //   cargo run -- node 8001 --seed 136.111.45.6:8000 --wallet alice
        //
        // Both can be combined, or neither used (just listens for incoming).
        // =====================================================================
        "node" => {
            let port: u16 = args.get(2)
                .expect("Usage: node <port> [peer] [--seed <ip:port>]")
                .parse()
                .expect("Port must be a number");

            // argv[3] may be a direct peer address — skip if it's a flag
            let connect_to = args.get(3)
                .filter(|a| !a.starts_with("--"))
                .cloned();

            // --seed flag for seed node peer discovery
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

            // If --seed was given: register with seed node, connect to returned peers,
            // and start sending heartbeats every 5 minutes to stay registered
            if let Some(ref seed) = seed_addr {
                // Auto-detect our public IP so we can tell the seed how to reach us
                let our_ip   = network::get_public_ip().await;
                let our_addr = format!("{}:{}", our_ip, port);

                println!("Registering with seed node {}...", seed);
                println!("Our listen address: {}", our_addr);

                let peer_list = network::register_with_seed(seed, &our_addr).await;

                // Start heartbeat loop in background (keeps our seed entry alive)
                let seed_clone = seed.clone();
                let addr_clone = our_addr.clone();
                tokio::spawn(async move {
                    network::heartbeat_loop(seed_clone, addr_clone).await;
                });

                // Connect directly to each peer the seed returned
                for peer_addr in peer_list {
                    let chain_clone = Arc::clone(&chain);
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
                                    stream, chain_clone, peer_addr, path_clone
                                ).await;
                            }
                            Err(e) => println!("[seed] Could not reach peer {}: {}", peer_addr, e),
                        }
                    });
                }
            }

            println!("Starting node on port {}...", port);
            start_node(port, connect_to, chain, chain_file.clone()).await; // runs forever
        }

        // =====================================================================
        // mine-and-broadcast <peer_ip:port>
        //
        // Mines a block locally then broadcasts it to a peer.
        // Use this when you want to participate in the network without running
        // a persistent node in the background.
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

            chain.mine_block(wallet.address());

            // Save before broadcasting — block is preserved even if broadcast fails
            chain_store::save_chain(&chain, chain_file.as_str())
                .expect("Failed to save");
            chain_store::clear_mempool(chain_file.as_str());

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
        // help — shown for any unknown command
        // =====================================================================
        _ => {
            println!("Commands:");
            println!("  new-wallet                        create a new encrypted wallet");
            println!("  list-wallets                      show all wallets on this machine");
            println!("  balance                           show your address and coin balance");
            println!("  mine                              mine a block and earn rewards");
            println!("  mine-and-broadcast <peer>         mine a block and send to a peer");
            println!("  send <to> <amount> [peer]         send coins to an address");
            println!("  chain                             print all blocks and transactions");
            println!("  node <port> [peer]                start a persistent P2P node");
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
            println!("  cargo run -- node 8001 192.168.1.5:8000 --wallet alice");
            println!("  cargo run -- mine-and-broadcast 192.168.1.5:8000 --wallet alice");
            println!("  cargo run -- send <address> 10 --wallet alice");
            println!("  cargo run -- send <address> 10 192.168.1.5:8000 --wallet alice");
        }
    }
}
