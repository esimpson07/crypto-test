// =============================================================================
// network.rs — Peer-to-Peer Networking
// =============================================================================
//
// This file implements the P2P (peer-to-peer) networking layer that turns a
// standalone local program into a distributed cryptocurrency network.
//
// KEY CONCEPT — NO CENTRAL SERVER:
//   Unlike a bank app that talks to one server, every node in a blockchain
//   network is equal. Each holds a full copy of the chain and communicates
//   directly with other nodes. There is no master — any node can go offline
//   and the network continues. This is what makes it truly decentralized.
//
// HOW NODES COMMUNICATE:
//   Each node listens for incoming TCP connections on a port (e.g. 8000).
//   Nodes can also connect outward to known peers. Both directions work
//   simultaneously — a node is always both a client and a server.
//
//   When something happens (new transaction submitted, new block mined),
//   the event is serialized to JSON and broadcast to all connected peers.
//   Each peer validates what it receives and either accepts or rejects it.
//
// MESSAGE FRAMING PROTOCOL:
//   Raw TCP is a stream of bytes with no built-in message boundaries.
//   We use length-prefix framing: every message is preceded by a 4-byte
//   integer telling the receiver how many bytes to read for the payload.
//
//   ┌──────────────────┬──────────────────────────────────┐
//   │  4 bytes         │  N bytes                         │
//   │  message length  │  JSON-serialized Message enum    │
//   └──────────────────┴──────────────────────────────────┘
//
// CONSENSUS — THE LONGEST CHAIN WINS:
//   When a new node connects to a peer, it immediately requests their full
//   chain. If the peer has more blocks than us, we adopt their chain —
//   this is the "longest chain wins" rule. All nodes gradually converge
//   on the same canonical chain through this simple mechanism.
//
// CONCURRENCY:
//   Each peer connection runs in its own async Tokio task. Multiple peers
//   can be connected simultaneously without blocking each other.
//   The shared Blockchain state is protected by Arc<Mutex<>> — only one
//   task can modify it at a time, preventing data races.
// =============================================================================

use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use crate::block::Block;
use crate::transaction::Transaction;
use crate::blockchain::Blockchain;
use crate::chain_store;

// =============================================================================
// Message Types
// =============================================================================

/// All possible messages nodes can send to each other over the network.
///
/// Serialized to JSON before transmission, deserialized after receipt.
/// The enum variant name becomes part of the JSON, e.g.:
///   {"NewBlock": { ...block data... }}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message {
    /// A newly signed, unconfirmed transaction.
    /// Sent when a user runs `send` with a peer address.
    /// Recipients add it to their mempool if it passes validation.
    NewTransaction(Transaction),

    /// A freshly mined block ready to be added to the chain.
    /// Sent when a user runs `mine-and-broadcast`.
    /// Recipients validate the block and add it to their chain if valid.
    NewBlock(Block),

    /// Request for the peer's full chain (sent on first connection).
    /// The peer responds with ResponseChain containing all their blocks.
    RequestChain,

    /// Response to RequestChain — the sender's complete block list.
    /// If this chain is longer than ours, we adopt it.
    ResponseChain(Vec<Block>),

    /// Liveness check — "are you still connected?"
    Ping,

    /// Reply to Ping — "yes, still here."
    Pong,
}

// =============================================================================
// Message Transport
// =============================================================================

/// Sends one message to a peer over an open TCP stream.
///
/// Uses length-prefix framing: sends a 4-byte big-endian length header
/// followed by the JSON-serialized message bytes. This lets the receiver
/// know exactly how many bytes constitute one complete message.
///
/// `stream` — an open, writable TCP connection to the peer
/// `msg`    — the message to serialize and send
pub async fn send_message(stream: &mut TcpStream, msg: &Message) -> Result<(), String> {
    // Serialize the message to a JSON string
    let json = serde_json::to_string(msg).map_err(|e| e.to_string())?;
    let len  = json.len() as u32;

    // Send the 4-byte length header in big-endian byte order
    // The receiver reads this first to know how large the payload is
    stream.write_all(&len.to_be_bytes()).await.map_err(|e| e.to_string())?;

    // Send the actual JSON payload
    stream.write_all(json.as_bytes()).await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Receives one complete message from a peer over an open TCP stream.
///
/// Reads the 4-byte length header first, then reads exactly that many bytes
/// and deserializes the JSON into a Message enum variant.
///
/// This function blocks (awaits) until a complete message is available
/// or the connection is closed/errored.
pub async fn receive_message(stream: &mut TcpStream) -> Result<Message, String> {
    // Read the 4-byte length header to find out how big the payload is
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await.map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    // Read exactly `len` bytes — the complete JSON payload
    let mut buffer = vec![0u8; len];
    stream.read_exact(&mut buffer).await.map_err(|e| e.to_string())?;

    // Deserialize the JSON back into the appropriate Message variant
    let json = String::from_utf8(buffer).map_err(|e| e.to_string())?;
    serde_json::from_str(&json).map_err(|e| e.to_string())
}

// =============================================================================
// Peer Handler
// =============================================================================

/// Manages an ongoing connection with one peer for its entire lifetime.
///
/// Runs in an async loop, receiving and processing messages one at a time
/// until the peer disconnects or the connection errors out. Each peer
/// runs in its own Tokio task (spawned in start_node) so they don't block
/// each other — the node handles all peers concurrently.
///
/// The blockchain is wrapped in Arc<Mutex<>> — Arc lets it be shared across
/// tasks, Mutex ensures only one task modifies it at a time (no data races).
///
/// `stream`     — the open TCP connection to this specific peer
/// `chain`      — shared, thread-safe reference to the blockchain state
/// `peer_addr`  — the peer's IP:port string, used only for log messages
/// `chain_path` — the file path for saving chain updates (e.g. "chain.json")
async fn handle_peer(
    mut stream: TcpStream,
    chain: Arc<Mutex<Blockchain>>,
    peer_addr: String,
    chain_path: String,
) {
    println!("[network] Peer connected: {}", peer_addr);

    // Keep handling messages until the peer disconnects
    loop {
        match receive_message(&mut stream).await {
            Ok(msg) => match msg {

                // ── Ping ──────────────────────────────────────────────────
                // Liveness check — respond immediately and do nothing else
                Message::Ping => {
                    let _ = send_message(&mut stream, &Message::Pong).await;
                }

                // ── Pong ──────────────────────────────────────────────────
                // Response to our Ping — just confirms the peer is still alive
                Message::Pong => {}

                // ── New Transaction ───────────────────────────────────────
                // A peer is sharing a user-submitted transaction.
                // Validate it (signature + balance check) and add to mempool.
                // Rejected transactions are logged but don't close the connection.
                Message::NewTransaction(tx) => {
                    let mut chain = chain.lock().await;
                    match chain.add_transaction(tx) {
                        Ok(_)  => println!("[network] Added transaction from {}", peer_addr),
                        Err(e) => println!("[network] Rejected transaction from {}: {}", peer_addr, e),
                    }
                }

                // ── New Block ─────────────────────────────────────────────
                // A peer just mined a block and is broadcasting it.
                // Three conditions must ALL pass before we accept it:
                //   1. Index is exactly one more than our current tip
                //   2. prev_hash matches our tip's hash (proper chain linkage)
                //   3. The block's hash is valid (not tampered with)
                //
                // If valid: update balances, add block, save to disk.
                // If invalid: log the specific failure reason for debugging.
                Message::NewBlock(block) => {
                    let mut chain = chain.lock().await;
                    let latest = chain.latest_block().index;

                    let index_ok = block.index == latest + 1;
                    let prev_ok  = block.prev_hash == chain.latest_block().hash;
                    let hash_ok  = block.hash == block.calculate_hash();

                    if index_ok && prev_ok && hash_ok {
                        println!("[network] Accepted block #{} from {}", block.index, peer_addr);

                        // Apply all transactions in the block to update balances
                        let transactions = block.transactions.clone();
                        for tx in &transactions {
                            if tx.from == "coinbase" {
                                // Coinbase creates new coins
                                chain.total_supply += tx.amount;
                            } else {
                                // Deduct from sender using their hashed address
                                let sender = chain.utxo_set
                                    .entry(tx.sender_address())
                                    .or_insert(0);
                                *sender -= tx.amount;
                            }
                            // Credit the recipient in both cases
                            let recipient = chain.utxo_set
                                .entry(tx.to.clone())
                                .or_insert(0);
                            *recipient += tx.amount;
                        }

                        // Add the validated block to the chain
                        chain.chain.push(block);

                        // Persist the updated chain to disk immediately
                        chain_store::save_chain(&chain, &chain_path)
                            .unwrap_or_else(|e| println!("[network] Save error: {}", e));
                    } else {
                        // Log why the block was rejected — useful for debugging
                        println!(
                            "[network] Rejected block #{} from {} — \
                             index ok: {}, prev_hash ok: {}, hash ok: {}",
                            block.index, peer_addr, index_ok, prev_ok, hash_ok
                        );
                    }
                }

                // ── Chain Request ─────────────────────────────────────────
                // A peer wants our full chain, usually on first connection.
                // Send them every block we have so they can sync up.
                Message::RequestChain => {
                    let chain    = chain.lock().await;
                    let response = Message::ResponseChain(chain.chain.clone());
                    let _        = send_message(&mut stream, &response).await;
                    println!(
                        "[network] Sent chain ({} blocks) to {}",
                        chain.chain.len(), peer_addr
                    );
                }

                // ── Chain Response ────────────────────────────────────────
                // We received a peer's full chain (their reply to our RequestChain).
                //
                // LONGEST CHAIN WINS RULE:
                //   If their chain has more blocks than ours, we adopt it.
                //   We can't trust their reported balances — we rebuild our
                //   UTXO set from scratch by replaying their transaction history.
                //
                //   If our chain is equal or longer, we keep ours.
                Message::ResponseChain(their_chain) => {
                    let mut chain = chain.lock().await;

                    if their_chain.len() > chain.chain.len() {
                        println!(
                            "[network] Adopting longer chain from {} ({} blocks vs our {})",
                            peer_addr, their_chain.len(), chain.chain.len()
                        );

                        // Replace our chain with the peer's longer one
                        chain.chain = their_chain;

                        // Rebuild UTXO set and supply from scratch by replaying
                        // the new chain's transactions — never trust peer-reported balances
                        chain.utxo_set.clear();
                        chain.total_supply = 0;
                        let blocks = chain.chain.clone();

                        for block in &blocks {
                            for tx in &block.transactions {
                                if tx.from == "coinbase" {
                                    chain.total_supply += tx.amount;
                                } else {
                                    let s = chain.utxo_set
                                        .entry(tx.sender_address())
                                        .or_insert(0);
                                    *s -= tx.amount;
                                }
                                let r = chain.utxo_set
                                    .entry(tx.to.clone())
                                    .or_insert(0);
                                *r += tx.amount;
                            }
                        }

                        // Save the newly adopted chain to disk
                        chain_store::save_chain(&chain, &chain_path)
                            .unwrap_or_else(|e| println!("[network] Save error: {}", e));
                    } else {
                        println!("[network] Our chain is equal or longer — keeping ours");
                    }
                }
            },

            // The connection was closed or a read error occurred.
            // Exit the loop cleanly — the task will end and resources are freed.
            Err(_) => {
                println!("[network] Peer disconnected: {}", peer_addr);
                break;
            }
        }
    }
}

// =============================================================================
// Node Entry Point
// =============================================================================

/// Starts the network node — runs forever until the process is killed (Ctrl+C).
///
/// WHAT IT DOES:
///   1. Binds a TCP listener on `0.0.0.0:<port>` to accept any incoming connection
///   2. If `connect_to` is provided, connects outward to that peer and requests
///      their chain (to sync up before listening for new events)
///   3. Loops forever accepting new incoming peer connections, spawning a
///      concurrent async task for each one
///
/// CONCURRENCY MODEL:
///   Every peer connection (both outgoing and incoming) runs in its own
///   tokio::spawn task. These tasks run concurrently — many peers can be
///   active simultaneously without blocking each other. The shared blockchain
///   is protected by Arc<Mutex<>> to prevent concurrent modification.
///
/// `port`       — TCP port to listen on (e.g. 8000). Must be open in your firewall.
/// `connect_to` — Optional "ip:port" of an existing peer to connect to on startup.
///                Example: Some("192.168.1.5:8000") or Some("mynode.duckdns.org:8000")
/// `chain`      — The shared blockchain, wrapped in Arc<Mutex<>> for thread safety.
/// `chain_path` — File path for saving chain updates (e.g. "chain.json").
pub async fn start_node(
    port: u16,
    connect_to: Option<String>,
    chain: Arc<Mutex<Blockchain>>,
    chain_path: String,
) {
    // Bind to all interfaces on the given port ("0.0.0.0" = accept from anywhere)
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .expect("Failed to bind port — is it already in use by another process?");

    println!("[network] Listening on port {}", port);

    // If given a peer address, connect to it in a background task and
    // immediately request their chain to sync our local copy
    if let Some(peer_addr) = connect_to {
        let chain_clone = Arc::clone(&chain);
        let path_clone  = chain_path.clone();
        tokio::spawn(async move {
            match TcpStream::connect(&peer_addr).await {
                Ok(mut stream) => {
                    println!("[network] Connected to peer {}", peer_addr);
                    // Ask for their chain right away so we sync before doing anything else
                    let _ = send_message(&mut stream, &Message::RequestChain).await;
                    // Then stay connected and handle all future messages from this peer
                    handle_peer(stream, chain_clone, peer_addr, path_clone).await;
                }
                Err(e) => println!("[network] Could not connect to {}: {}", peer_addr, e),
            }
        });
    }

    // Accept incoming peer connections indefinitely
    println!("[network] Waiting for peers to connect...");
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                // Spawn a new task per peer — they run fully concurrently
                let chain_clone = Arc::clone(&chain);
                let path_clone  = chain_path.clone();
                tokio::spawn(async move {
                    handle_peer(stream, chain_clone, addr.to_string(), path_clone).await;
                });
            }
            Err(e) => println!("[network] Failed to accept connection: {}", e),
        }
    }
}

/// Registers with the seed node and returns the list of known peers.
pub async fn register_with_seed(
    seed_addr: &str,
    our_listen_addr: &str,
) -> Vec<String> {
    let mut stream = match TcpStream::connect(seed_addr).await {
        Ok(s)  => s,
        Err(e) => {
            println!("[seed] Could not reach seed node {}: {}", seed_addr, e);
            return vec![];
        }
    };

    // Send Announce message
    let msg  = serde_json::json!({ "Announce": { "address": our_listen_addr } });
    let json = msg.to_string();
    let len  = json.len() as u32;
    if stream.write_all(&len.to_be_bytes()).await.is_err() { return vec![]; }
    if stream.write_all(json.as_bytes()).await.is_err()    { return vec![]; }

    // Read length-prefixed response
    let mut len_bytes = [0u8; 4];
    if stream.read_exact(&mut len_bytes).await.is_err() { return vec![]; }
    let len = u32::from_be_bytes(len_bytes) as usize;
    let mut buf = vec![0u8; len];
    if stream.read_exact(&mut buf).await.is_err() { return vec![]; }

    let response = String::from_utf8(buf).unwrap_or_default();

    // Parse peer list out of PeerList response
    match serde_json::from_str::<serde_json::Value>(&response) {
        Ok(val) => {
            if let Some(peers) = val["PeerList"]["peers"].as_array() {
                let list: Vec<String> = peers
                    .iter()
                    .filter_map(|p| p.as_str().map(String::from))
                    .collect();
                println!("[seed] Received {} peer(s) from seed node", list.len());
                return list;
            }
        }
        Err(e) => println!("[seed] Could not parse seed response: {}", e),
    }
    vec![]
}

/// Sends a heartbeat to the seed node every 5 minutes.
/// Runs forever in a background task.
pub async fn heartbeat_loop(seed_addr: String, our_listen_addr: String) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
        match TcpStream::connect(&seed_addr).await {
            Ok(mut stream) => {
                let msg  = serde_json::json!({
                    "Heartbeat": { "address": our_listen_addr }
                });
                let json = msg.to_string();
                let len  = json.len() as u32;
                let _    = stream.write_all(&len.to_be_bytes()).await;
                let _    = stream.write_all(json.as_bytes()).await;
                println!("[seed] Heartbeat sent to seed node");
            }
            Err(e) => println!("[seed] Heartbeat failed: {}", e),
        }
    }
}

/// Public wrapper around handle_peer so it can be called from main.rs
pub async fn handle_peer_public(
    stream: TcpStream,
    chain: Arc<Mutex<Blockchain>>,
    peer_addr: String,
    chain_path: String,
) {
    handle_peer(stream, chain, peer_addr, chain_path).await;
}

/// Detects this machine's public IP by making a raw HTTP request
/// using only Tokio's TCP stream — no extra dependencies needed.
///
/// Connects directly to api.ipify.org and sends a minimal HTTP GET request,
/// then parses the plain text IP address from the response.
pub async fn get_public_ip() -> String {
    // We'll try a few services in case one is down
    // Each entry is (host, port, http_request)
    let services = [
        (
            "api.ipify.org",
            80u16,
            "GET / HTTP/1.0\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n",
        ),
        (
            "ifconfig.me",
            80u16,
            "GET /ip HTTP/1.0\r\nHost: ifconfig.me\r\nConnection: close\r\n\r\n",
        ),
        (
            "icanhazip.com",
            80u16,
            "GET / HTTP/1.0\r\nHost: icanhazip.com\r\nConnection: close\r\n\r\n",
        ),
    ];

    for (host, port, request) in &services {
        // Resolve hostname to IP and connect
        let addr = format!("{}:{}", host, port);

        match TcpStream::connect(&addr).await {
            Ok(mut stream) => {
                // Send the raw HTTP request
                if stream.write_all(request.as_bytes()).await.is_err() {
                    continue;
                }

                // Read the response
                let mut response = Vec::new();
                let mut buf = [0u8; 1024];

                loop {
                    match stream.read(&mut buf).await {
                        Ok(0)    => break, // connection closed
                        Ok(n)    => response.extend_from_slice(&buf[..n]),
                        Err(_)   => break,
                    }
                    // Stop reading once we have enough data
                    if response.len() > 4096 { break; }
                }

                let response_str = String::from_utf8_lossy(&response);

                // HTTP response looks like:
                // HTTP/1.0 200 OK\r\n
                // Content-Type: text/plain\r\n
                // \r\n
                // 76.32.11.4
                //
                // We want the last non-empty line which is the IP address
                if let Some(ip) = response_str
                    .lines()
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty())
                    .last()
                {
                    // Validate it looks like an IP address
                    // IPv4 addresses contain dots and are short
                    let ip = ip.to_string();
                    if ip.contains('.')
                        && ip.len() >= 7
                        && ip.len() <= 15
                        && ip.chars().all(|c| c.is_numeric() || c == '.')
                    {
                        println!("[network] Detected public IP: {}", ip);
                        return ip;
                    }
                }
            }
            Err(e) => {
                println!("[network] Could not connect to {}: {}", host, e);
                continue;
            }
        }
    }

    // All services failed — fall back to local IP detection
    println!("[network] Public IP detection failed — falling back to local IP");
    get_local_ip().await
}

/// Falls back to detecting the local network IP if public IP detection fails.
/// Useful for same-WiFi testing without internet access.
async fn get_local_ip() -> String {
    let targets = ["8.8.8.8:53", "1.1.1.1:53"];
    for target in &targets {
        if let Ok(stream) = TcpStream::connect(target).await {
            if let Ok(addr) = stream.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    "127.0.0.1".to_string()
}