// =============================================================================
// main.rs — Command Line Interface
// =============================================================================
//
// This is the program's entry point. It reads the command the user typed,
// resolves which wallet and chain files to use, and routes execution to the
// appropriate logic across the other modules.
//
// AVAILABLE COMMANDS:
//   new-wallet              create a new post-quantum wallet, encrypted with a password
//   list-wallets            show all .dat wallet files in the current directory
//   balance                 display your address and current coin balance
//   mine                    mine a new block locally (earn block reward)
//   mine-and-broadcast      mine a block and broadcast it to a peer node
//   send <to> <amount>      sign and submit a transaction to another address
//   chain                   print every block and its transactions
//   node <port> [peer]      start a persistent P2P node (runs until Ctrl+C)
//
// GLOBAL OPTIONS (append to any command):
//   --wallet <n>     use wallet file <n>.dat  (default: wallet.dat)
//   --network <n>    use chain file <n>_chain.json  (default: chain.json)
//
// EXAMPLES:
//   cargo run -- new-wallet --wallet alice
//   cargo run -- balance --wallet alice
//   cargo run -- mine --wallet alice --network mainnet
//   cargo run -- node 8000 --wallet alice --network mainnet
//   cargo run -- node 8001 192.168.1.5:8000 --wallet bob --network mainnet
//   cargo run -- mine-and-broadcast 192.168.1.5:8000 --wallet alice
//   cargo run -- send <address> 10 --wallet alice
//   cargo run -- send <address> 10 192.168.1.5:8000 --wallet alice
//
// POST-QUANTUM NOTES:
//   Wallet addresses are SHA-256(public_key) — a compact 64-char hex string.
//   When sending, Transaction.from is set to the FULL public key (3,904 chars)
//   because Dilithium3 signature verification requires the actual key bytes,
//   not just the address hash. Recipients always share their compact address.
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
// Input Helpers
// =============================================================================

/// Prints a prompt and reads one line of input from stdin.
///
/// Used for all password prompts and any other interactive input.
/// Input is visible as the user types (no hidden password mode).
/// Trims the trailing newline before returning.
fn ask_password(prompt: &str) -> String {
    print!("{}", prompt);
    // Flush stdout so the prompt appears immediately before the user types
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

// =============================================================================
// Argument Parsing Helpers
// =============================================================================

/// Resolves the wallet filename from the command line arguments.
///
/// Scans all args for "--wallet <n>" and returns "<n>.dat".
/// Defaults to "wallet.dat" if the flag isn't present.
/// The flag can appear anywhere in the argument list.
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

/// Resolves the chain filename from the command line arguments.
///
/// Scans all args for "--network <n>" and returns "<n>_chain.json".
/// Defaults to "chain.json" if the flag isn't present.
///
/// Using different --network values lets you run completely separate
/// blockchains on the same machine:
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

/// Returns the wallet's full Dilithium3 public key as a hex string.
///
/// This is used as Transaction.from — NOT the same as wallet.address().
///   wallet.address()   = SHA-256(public_key)  ← compact, 64 chars, for display
///   public_key_hex()   = hex(public_key)       ← full key, 3904 chars, for transactions
///
/// The full public key must be in transactions because Dilithium3 signature
/// verification requires the actual key bytes — it cannot recover them from
/// the signature the way classical ECDSA can.
fn public_key_hex(wallet: &crypto::Wallet) -> String {
    hex::encode(&wallet.public_key)
}

// =============================================================================
// Main Entry Point
// =============================================================================

/// The async main function — required by Tokio for the networking layer.
///
/// Reads argv[1] as the command name, resolves wallet/chain file paths from
/// flags, then dispatches to the appropriate command handler.
#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    // argv[0] = program name, argv[1] = command, argv[2+] = arguments/flags
    let command     = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    let wallet_file = get_wallet_file(&args);
    let chain_file  = get_chain_file(&args);

    match command {

        // =====================================================================
        // new-wallet — Generate a fresh post-quantum wallet and save it encrypted
        // =====================================================================
        "new-wallet" => {
            // Safety check: refuse to overwrite an existing wallet.
            // Overwriting would permanently destroy the coins at that address
            // since the old private key would be gone with no recovery option.
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

            // In new-wallet command, after generating the wallet:
            let wallet = crypto::Wallet::new();

            println!("Key sizes — private: {} bytes, public: {} bytes",
                wallet.private_key.len(),
                wallet.public_key.len()
            );

            let combined_key_hex = format!(
                "{}{}",
                hex::encode(&wallet.private_key),
                hex::encode(&wallet.public_key)
            );

            wallet_store::save_wallet(&combined_key_hex, &password, wallet_file.as_str())
                .expect("Failed to save wallet");

            println!("Wallet created: {}", wallet_file);
            // Show the compact address (SHA-256 of public key) — this is what
            // others need to send you coins. Don't confuse this with the full public key.
            println!("Your address:   {}", wallet.address());
            println!("KEEP YOUR PASSWORD SAFE — it cannot be recovered if lost");
        }

        // =====================================================================
        // list-wallets — Show all wallet files in the current directory
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
        // balance — Show address and current coin balance
        // =====================================================================
        "balance" => {
            let password        = ask_password("Password: ");
            let combined_key    = wallet_store::load_wallet(&password, wallet_file.as_str())
                .expect("Failed to load wallet");
            let wallet          = crypto::Wallet::from_hex(&combined_key);
            let chain           = chain_store::load_chain(chain_file.as_str())
                .expect("Failed to load chain");

            // wallet.address() = SHA-256(public_key) — compact and safe to share
            println!("Address: {}", wallet.address());
            println!("Balance: {} coins", chain.get_balance(&wallet.address()));
            println!("Supply:  {}/{} coins in circulation", chain.total_supply, MAX_SUPPLY);
        }

        // =====================================================================
        // mine — Mine a new block locally, earning the current block reward
        // =====================================================================
        "mine" => {
            let password        = ask_password("Password: ");
            let combined_key    = wallet_store::load_wallet(&password, wallet_file.as_str())
                .expect("Failed to load wallet");
            let wallet          = crypto::Wallet::from_hex(&combined_key);
            let mut chain       = chain_store::load_chain(chain_file.as_str())
                .expect("Failed to load chain");

            // Mine a block — proof-of-work happens here (may take a while)
            // The block reward and any mempool transactions go to wallet.address()
            chain.mine_block(wallet.address());

            // Persist the updated chain and clear the now-confirmed mempool file
            chain_store::save_chain(&chain, chain_file.as_str())
                .expect("Failed to save chain");
            chain_store::clear_mempool(chain_file.as_str());

            println!("Your balance: {} coins", chain.get_balance(&wallet.address()));
        }

        // =====================================================================
        // send — Sign a transaction and submit it to the mempool
        //
        // Usage: send <recipient_address> <amount> [peer_ip:port]
        //
        // KEY DETAIL — Transaction.from vs wallet.address():
        //   `from` = full public key hex (3,904 chars) — needed for Dilithium verification
        //   `to`   = recipient's compact address (64 chars) — what they share from `balance`
        //
        // The transaction sits in the mempool until someone runs `mine` or
        // `mine-and-broadcast` to confirm it in a block.
        // =====================================================================
        "send" => {
            let to_address = args.get(2).expect("Usage: send <address> <amount> [peer]");
            let amount: u64 = args.get(3)
                .expect("Usage: send <address> <amount> [peer]")
                .parse()
                .expect("Amount must be a whole number (no decimals)");

            let password     = ask_password("Password: ");
            let combined_key = wallet_store::load_wallet(&password, wallet_file.as_str())
                .expect("Failed to load wallet");
            let wallet       = crypto::Wallet::from_hex(&combined_key);
            let mut chain    = chain_store::load_chain(chain_file.as_str())
                .expect("Failed to load chain");

            // Build the transaction:
            //   from = FULL public key (for Dilithium verification, not the short address)
            //   to   = recipient's compact address (what they gave you from `balance`)
            let from   = public_key_hex(&wallet);
            let mut tx = Transaction::new(from, to_address.clone(), amount);

            // Sign with our Dilithium3 private key — proves we authorized this transfer
            tx.sign(&wallet);

            match chain.add_transaction(tx.clone()) {
                Ok(_) => {
                    // Save the updated mempool to disk (persists across restarts)
                    chain_store::save_chain(&chain, chain_file.as_str())
                        .expect("Failed to save");
                    println!("Transaction added to mempool — mine a block to confirm it");

                    // Optionally broadcast to a peer node immediately
                    // argv[4] is the peer address, but only if it's not a -- flag
                    if let Some(peer) = args.get(4).filter(|a| !a.starts_with("--")) {
                        match TcpStream::connect(peer).await {
                            Ok(mut stream) => {
                                let msg = Message::NewTransaction(tx);
                                match send_message(&mut stream, &msg).await {
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
        // chain — Print every block and its transactions
        // =====================================================================
        "chain" => {
            let chain = chain_store::load_chain(chain_file.as_str())
                .expect("Failed to load chain");

            println!("Blocks: {} | Supply: {}/{} | Valid: {}",
                chain.chain.len(), chain.total_supply, MAX_SUPPLY, chain.is_valid());

            for block in &chain.chain {
                println!("\nBlock #{} | Hash: {}...", block.index, &block.hash[..16]);
                for tx in &block.transactions {
                    // sender_address() hashes tx.from (the full public key) to get
                    // the compact address — same as wallet.address() for that key
                    let from = tx.sender_address();
                    let from_display = if from == "coinbase" {
                        "coinbase ".to_string() // padded to align with 8-char addresses
                    } else {
                        format!("{}...", &from[..8])
                    };
                    println!("  {} → {}... : {} coins",
                        from_display,
                        &tx.to[..8],
                        tx.amount
                    );
                }
            }
        }

        // =====================================================================
        // node — Start a persistent P2P network node (runs until Ctrl+C)
        //
        // Usage: node <port> [peer_ip:port]
        //
        // The node listens for incoming peer connections on <port>.
        // If a peer address is provided, it also connects outward to sync chains.
        // =====================================================================
        "node" => {
            let port: u16 = args.get(2)
                .expect("Usage: node <port> [peer_ip:port] [--seed <ip:port>]")
                .parse()
                .expect("Port must be a number");

            // Direct peer connection (optional — used for local testing)
            let connect_to = args.get(3)
                .filter(|a| !a.starts_with("--"))
                .cloned();

            // Seed node address (optional — used for internet connections)
            // Usage: --seed YOUR_SEED_IP:8000
            let seed_addr = args.iter()
                .position(|a| a == "--seed")
                .and_then(|i| args.get(i + 1))
                .cloned();

            let password     = ask_password("Password: ");
            let combined_key = wallet_store::load_wallet(&password, wallet_file.as_str())
                .expect("Failed to load wallet");
            let wallet       = crypto::Wallet::from_hex(&combined_key);

            println!("Wallet:  {} ({}...)", wallet_file, &wallet.address()[..16]);
            println!("Chain:   {}", chain_file);

            let chain = chain_store::load_chain(chain_file.as_str())
                .expect("Failed to load chain");
            let chain = Arc::new(Mutex::new(chain));

            // If --seed was provided, register with the seed node and
            // connect to any peers it returns
            if let Some(ref seed) = seed_addr {
                // This is the address OTHER nodes use to reach YOU
                // Replace YOUR_PUBLIC_IP with your actual public IP from whatismyip.com
                // If testing on same WiFi, use your local 192.168.x.x IP instead
                let our_ip   = network::get_public_ip().await;
                let our_addr = format!("{}:{}", our_ip, port);

                println!("Registering with seed node {}...", seed);
                println!("Our listen address: {}", our_addr);

                // Register with seed and get list of existing peers
                let peer_list = network::register_with_seed(seed, &our_addr).await;

                // Start sending heartbeats every 5 minutes so seed keeps us registered
                let seed_clone = seed.clone();
                let addr_clone = our_addr.clone();
                tokio::spawn(async move {
                    network::heartbeat_loop(seed_clone, addr_clone).await;
                });

                // Connect directly to each peer the seed gave us
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
                                    stream,
                                    chain_clone,
                                    peer_addr,
                                    path_clone
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
        // mine-and-broadcast — Mine a block and immediately send it to a peer
        //
        // Usage: mine-and-broadcast <peer_ip:port>
        //
        // Use this when you want your mined block to reach the network right
        // away without running a persistent node in the background.
        // =====================================================================
        "mine-and-broadcast" => {
            let peer = args.get(2)
                .expect("Usage: mine-and-broadcast <peer_ip:port>");

            let password     = ask_password("Password: ");
            let combined_key = wallet_store::load_wallet(&password, wallet_file.as_str())
                .expect("Failed to load wallet");
            let wallet       = crypto::Wallet::from_hex(&combined_key);
            let mut chain    = chain_store::load_chain(chain_file.as_str())
                .expect("Failed to load chain");

            // Mine the block — proof-of-work computation happens here
            chain.mine_block(wallet.address());

            // Save immediately so the block isn't lost if broadcast fails
            chain_store::save_chain(&chain, chain_file.as_str())
                .expect("Failed to save");
            chain_store::clear_mempool(chain_file.as_str());

            // Grab the block we just mined and broadcast it to the peer
            let latest_block = chain.latest_block().clone();
            match TcpStream::connect(peer).await {
                Ok(mut stream) => {
                    let msg = Message::NewBlock(latest_block);
                    match send_message(&mut stream, &msg).await {
                        Ok(_)  => println!("Block broadcast to {}", peer),
                        Err(e) => println!("Broadcast failed (block saved locally): {}", e),
                    }
                }
                Err(e) => println!("Could not reach peer {} (block saved locally): {}", peer, e),
            }

            println!("Your balance: {} coins", chain.get_balance(&wallet.address()));
        }

        // =====================================================================
        // help — Print usage information (shown for unknown commands too)
        // =====================================================================
        _ => {
            println!("Commands:");
            println!("  new-wallet                        create a new encrypted wallet");
            println!("  list-wallets                      show all wallets on this machine");
            println!("  balance                           show your address and coin balance");
            println!("  mine                              mine a block and earn rewards");
            println!("  mine-and-broadcast <peer>         mine a block and send to a peer");
            println!("  send <to> <amount> [peer]         send coins to another address");
            println!("  chain                             print all blocks and transactions");
            println!("  node <port> [peer]                start a persistent P2P node");
            println!();
            println!("Options (append to any command):");
            println!("  --wallet <n>    use wallet file <n>.dat       (default: wallet.dat)");
            println!("  --network <n>   use chain file <n>_chain.json (default: chain.json)");
            println!();
            println!("Examples:");
            println!("  cargo run -- new-wallet --wallet alice");
            println!("  cargo run -- balance --wallet alice");
            println!("  cargo run -- mine --wallet alice --network mainnet");
            println!("  cargo run -- node 8000 --wallet alice --network mainnet");
            println!("  cargo run -- node 8001 192.168.1.5:8000 --wallet bob --network mainnet");
            println!("  cargo run -- mine-and-broadcast 192.168.1.5:8000 --wallet alice");
            println!("  cargo run -- send <recipient_address> 10 --wallet alice");
            println!("  cargo run -- send <recipient_address> 10 192.168.1.5:8000 --wallet alice");
        }
    }
}
