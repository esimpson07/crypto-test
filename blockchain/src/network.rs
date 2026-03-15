// =============================================================================
// network.rs — Peer-to-Peer Networking
// =============================================================================
//
// This file turns the standalone local blockchain program into a distributed
// network where many computers hold identical copies of the chain and
// communicate in real time.
//
// ARCHITECTURE — NO CENTRAL SERVER:
//
//   Every node is equal. Each holds a full copy of the chain and connects
//   directly to other nodes. There is no master server — any node can go
//   offline and the network continues operating. Nodes are simultaneously
//   both clients (they connect outward to peers) and servers (they accept
//   incoming connections from peers).
//
// MESSAGE PROTOCOL:
//
//   Raw TCP has no message boundaries — it's a continuous stream of bytes.
//   We use length-prefix framing: every message is preceded by a 4-byte
//   big-endian integer that tells the receiver how many bytes to read.
//
//   ┌──────────────────┬──────────────────────────────────┐
//   │  4 bytes         │  N bytes                         │
//   │  payload length  │  JSON-serialized Message enum    │
//   └──────────────────┴──────────────────────────────────┘
//
//   This is distinct from the seed node protocol (Announce/Heartbeat/PeerList)
//   which uses the same framing but a different set of message types.
//
// CONSENSUS — LONGEST CHAIN WINS:
//
//   When a node connects to a peer it immediately requests their full chain.
//   If the peer has more blocks, we adopt their chain — this is the fundamental
//   consensus rule. All nodes gradually converge on the same canonical chain.
//
// CONCURRENCY MODEL:
//
//   Each peer connection runs in its own Tokio async task. Multiple peers
//   are handled simultaneously without blocking each other.
//
//   The shared Blockchain is protected by Arc<Mutex<>>:
//     Arc    — lets multiple tasks share ownership of the same data
//     Mutex  — ensures only one task can modify the blockchain at a time,
//              preventing data races
//
// SEED NODE INTEGRATION:
//
//   The seed node is a separate lightweight server (see seed_node/) that
//   maintains a directory of active node addresses. When a node starts with
//   --seed, it registers its address with the seed node and receives a list
//   of known peers to connect to directly. After the initial handshake, nodes
//   communicate peer-to-peer and no longer need the seed node.
//
//   The heartbeat_loop() keeps the node's entry alive in the seed node's
//   registry (entries expire after 10 minutes of silence).
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

/// All messages that blockchain nodes send to each other.
///
/// Serialized to JSON before sending, deserialized after receiving.
/// The variant name appears in the JSON:  {"NewBlock": { ...block fields... }}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message {
    /// A newly signed unconfirmed transaction — add to recipient's mempool.
    /// Sent when a user runs `send` with a peer address.
    NewTransaction(Transaction),

    /// A freshly mined block — validate and add to recipient's chain.
    /// Sent when a user runs `mine-and-broadcast`.
    NewBlock(Block),

    /// Request the peer's full chain (sent on first connection to sync up).
    RequestChain,

    /// Response to RequestChain — the sender's complete block list.
    /// If longer than our chain, we adopt it (longest chain wins).
    ResponseChain(Vec<Block>),

    /// Liveness check.
    Ping,

    /// Response to Ping.
    Pong,
}

// =============================================================================
// Message Transport
// =============================================================================

/// Sends one message to a peer using length-prefix framing.
///
/// Writes a 4-byte big-endian length header followed by the JSON payload.
/// The receiver reads the length first to know how many bytes to expect.
pub async fn send_message(stream: &mut TcpStream, msg: &Message) -> Result<(), String> {
    let json = serde_json::to_string(msg).map_err(|e| e.to_string())?;
    let len  = json.len() as u32;
    stream.write_all(&len.to_be_bytes()).await.map_err(|e| e.to_string())?;
    stream.write_all(json.as_bytes()).await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Receives one complete message from a peer.
///
/// Reads the 4-byte length header first, then reads exactly that many bytes
/// and deserializes into the appropriate Message variant.
/// Awaits until a complete message arrives or the connection closes.
pub async fn receive_message(stream: &mut TcpStream) -> Result<Message, String> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await.map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    let mut buffer = vec![0u8; len];
    stream.read_exact(&mut buffer).await.map_err(|e| e.to_string())?;

    let json = String::from_utf8(buffer).map_err(|e| e.to_string())?;
    serde_json::from_str(&json).map_err(|e| e.to_string())
}

// =============================================================================
// Peer Handler
// =============================================================================

/// Manages one peer connection for its entire lifetime.
///
/// Loops receiving and processing messages until the peer disconnects.
/// Each peer runs in its own tokio::spawn task (see start_node), so many
/// peers are handled concurrently without blocking each other.
///
/// `stream`     — open TCP connection to this peer
/// `chain`      — shared blockchain, Arc<Mutex<>> for concurrent safety
/// `peer_addr`  — peer's address string, used only for log output
/// `chain_path` — file path for persisting chain updates (e.g. "chain.json")
async fn handle_peer(
    mut stream: TcpStream,
    chain: Arc<Mutex<Blockchain>>,
    peer_addr: String,
    chain_path: String,
) {
    println!("[network] Peer connected: {}", peer_addr);

    loop {
        match receive_message(&mut stream).await {
            Ok(msg) => match msg {

                // Liveness check — reply immediately
                Message::Ping => {
                    let _ = send_message(&mut stream, &Message::Pong).await;
                }

                // Confirms peer is alive — no action needed
                Message::Pong => {}

                // Peer submitted a transaction — validate and add to our mempool
                Message::NewTransaction(tx) => {
                    let mut chain = chain.lock().await;
                    match chain.add_transaction(tx) {
                        Ok(_)  => println!("[network] Added transaction from {}", peer_addr),
                        Err(e) => println!("[network] Rejected transaction from {}: {}", peer_addr, e),
                    }
                }

                // Peer mined a block — validate and add to our chain if it checks out
                //
                // Three conditions must all pass:
                //   index_ok  — block is exactly one ahead of our current tip
                //   prev_ok   — block correctly references our tip's hash
                //   hash_ok   — block's stored hash matches recalculating it
                Message::NewBlock(block) => {
                    let mut chain   = chain.lock().await;
                    let latest      = chain.latest_block().index;
                    let index_ok    = block.index == latest + 1;
                    let prev_ok     = block.prev_hash == chain.latest_block().hash;
                    let hash_ok     = block.hash == block.calculate_hash();

                    if index_ok && prev_ok && hash_ok {
                        println!("[network] Accepted block #{} from {}", block.index, peer_addr);

                        // Update UTXO set and supply for every transaction in the block
                        let transactions = block.transactions.clone();
                        for tx in &transactions {
                            if tx.from == "coinbase" {
                                chain.total_supply += tx.amount;
                            } else {
                                let s = chain.utxo_set.entry(tx.sender_address()).or_insert(0);
                                *s -= tx.amount;
                            }
                            let r = chain.utxo_set.entry(tx.to.clone()).or_insert(0);
                            *r += tx.amount;
                        }

                        chain.chain.push(block);
                        chain_store::save_chain(&chain, &chain_path)
                            .unwrap_or_else(|e| println!("[network] Save error: {}", e));
                    } else {
                        println!(
                            "[network] Rejected block #{} from {} — \
                             index ok: {}, prev_hash ok: {}, hash ok: {}",
                            block.index, peer_addr, index_ok, prev_ok, hash_ok
                        );
                    }
                }

                // Peer wants our full chain — send everything we have
                Message::RequestChain => {
                    let chain    = chain.lock().await;
                    let response = Message::ResponseChain(chain.chain.clone());
                    let _        = send_message(&mut stream, &response).await;
                    println!("[network] Sent chain ({} blocks) to {}", chain.chain.len(), peer_addr);
                }

                // Peer sent us their chain — adopt it if longer (longest chain wins)
                //
                // We never trust the peer's reported balances. If we adopt their
                // chain, we rebuild the UTXO set ourselves by replaying all
                // transactions from scratch.
                Message::ResponseChain(their_chain) => {
                    let mut chain = chain.lock().await;

                    if their_chain.len() > chain.chain.len() {
                        println!(
                            "[network] Adopting longer chain from {} ({} blocks vs our {})",
                            peer_addr, their_chain.len(), chain.chain.len()
                        );

                        chain.chain = their_chain;
                        chain.utxo_set.clear();
                        chain.total_supply = 0;

                        let blocks = chain.chain.clone();
                        for block in &blocks {
                            for tx in &block.transactions {
                                if tx.from == "coinbase" {
                                    chain.total_supply += tx.amount;
                                } else {
                                    let s = chain.utxo_set.entry(tx.sender_address()).or_insert(0);
                                    *s -= tx.amount;
                                }
                                let r = chain.utxo_set.entry(tx.to.clone()).or_insert(0);
                                *r += tx.amount;
                            }
                        }

                        chain_store::save_chain(&chain, &chain_path)
                            .unwrap_or_else(|e| println!("[network] Save error: {}", e));
                    } else {
                        println!("[network] Our chain is equal or longer — keeping ours");
                    }
                }
            },

            // Connection closed or read error — exit cleanly
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

/// Starts the P2P node — runs forever until the process is killed.
///
/// 1. Binds a TCP listener on 0.0.0.0:<port> (accepts connections from anywhere)
/// 2. If connect_to is provided, connects outward to that peer and requests
///    their chain immediately to sync up
/// 3. Loops forever accepting incoming peer connections, spawning a concurrent
///    task for each one
///
/// `port`       — TCP port to listen on (e.g. 8001). Must be reachable from peers.
/// `connect_to` — Optional peer to connect to on startup, e.g. "192.168.1.5:8001"
/// `chain`      — Shared blockchain wrapped in Arc<Mutex<>>
/// `chain_path` — File path for saving chain updates (e.g. "chain.json")
pub async fn start_node(
    port: u16,
    connect_to: Option<String>,
    chain: Arc<Mutex<Blockchain>>,
    chain_path: String,
) {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .expect("Failed to bind port — is it already in use?");

    println!("[network] Listening on port {}", port);

    // Connect outward to a known peer and request their chain
    if let Some(peer_addr) = connect_to {
        let chain_clone = Arc::clone(&chain);
        let path_clone  = chain_path.clone();
        tokio::spawn(async move {
            match TcpStream::connect(&peer_addr).await {
                Ok(mut stream) => {
                    println!("[network] Connected to peer {}", peer_addr);
                    let _ = send_message(&mut stream, &Message::RequestChain).await;
                    handle_peer(stream, chain_clone, peer_addr, path_clone).await;
                }
                Err(e) => println!("[network] Could not connect to {}: {}", peer_addr, e),
            }
        });
    }

    println!("[network] Waiting for peers to connect...");
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
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

// =============================================================================
// Seed Node Integration
// =============================================================================

/// Registers this node with the seed node and returns known peers.
///
/// Sends an Announce message with our listen address. The seed node adds us
/// to its registry and replies with a PeerList of other currently active nodes.
/// We then connect directly to those peers — the seed node is not involved
/// in any subsequent communication.
///
/// The seed node uses a different protocol from the blockchain P2P layer:
///   Announce    →  "I am listening at this address"
///   PeerList    ←  "here are other known peers"
///   Heartbeat   →  "I am still alive" (sent every 5 minutes by heartbeat_loop)
///
/// `seed_addr`      — "ip:port" of the seed node (e.g. "136.111.45.6:8000")
/// `our_listen_addr`— our public "ip:port" that other nodes should connect to
pub async fn register_with_seed(seed_addr: &str, our_listen_addr: &str) -> Vec<String> {
    let mut stream = match TcpStream::connect(seed_addr).await {
        Ok(s)  => s,
        Err(e) => {
            println!("[seed] Could not reach seed node {}: {}", seed_addr, e);
            return vec![];
        }
    };

    // Send length-prefixed Announce message
    let msg  = serde_json::json!({ "Announce": { "address": our_listen_addr } });
    let json = msg.to_string();
    let len  = json.len() as u32;
    if stream.write_all(&len.to_be_bytes()).await.is_err() { return vec![]; }
    if stream.write_all(json.as_bytes()).await.is_err()    { return vec![]; }

    // Read length-prefixed PeerList response
    let mut len_bytes = [0u8; 4];
    if stream.read_exact(&mut len_bytes).await.is_err() { return vec![]; }
    let len = u32::from_be_bytes(len_bytes) as usize;
    let mut buf = vec![0u8; len];
    if stream.read_exact(&mut buf).await.is_err() { return vec![]; }

    let response = String::from_utf8(buf).unwrap_or_default();

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

/// Sends a Heartbeat to the seed node every 5 minutes.
///
/// The seed node removes entries that haven't sent a heartbeat in 10 minutes.
/// This loop keeps our entry alive so other nodes can find us.
///
/// Runs forever in a background tokio::spawn task — started in main.rs
/// immediately after register_with_seed() when --seed is used.
pub async fn heartbeat_loop(seed_addr: String, our_listen_addr: String) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
        match TcpStream::connect(&seed_addr).await {
            Ok(mut stream) => {
                let msg  = serde_json::json!({ "Heartbeat": { "address": our_listen_addr } });
                let json = msg.to_string();
                let len  = json.len() as u32;
                let _    = stream.write_all(&len.to_be_bytes()).await;
                let _    = stream.write_all(json.as_bytes()).await;
                println!("[seed] Heartbeat sent");
            }
            Err(e) => println!("[seed] Heartbeat failed — seed unreachable: {}", e),
        }
    }
}

/// Public wrapper around handle_peer for use from main.rs.
///
/// handle_peer is private because it's an internal detail of the network
/// layer. However, main.rs needs to call it directly when connecting outward
/// to seed-discovered peers (rather than going through start_node's listener).
/// This wrapper exposes it without making the full function public.
pub async fn handle_peer_public(
    stream: TcpStream,
    chain: Arc<Mutex<Blockchain>>,
    peer_addr: String,
    chain_path: String,
) {
    handle_peer(stream, chain, peer_addr, chain_path).await;
}

// =============================================================================
// IP Detection
// =============================================================================

/// Detects this machine's public IP address using a raw HTTP request.
///
/// Makes a minimal HTTP/1.0 GET request to public IP services using only
/// Tokio's TCP stream — no extra HTTP client dependencies needed.
/// Tries multiple services in case one is down or unreachable.
///
/// Falls back to get_local_ip() if all services fail (e.g. no internet).
/// The local IP is sufficient for same-network testing.
///
/// NOTE: On home networks behind NAT, routers own the public IP and
/// laptops can't query it locally. Querying an external service is the
/// only reliable way to discover it — this is standard practice for
/// all peer-to-peer software (BitTorrent clients, game servers, etc.).
pub async fn get_public_ip() -> String {
    let services = [
        ("api.ipify.org",  80u16, "GET / HTTP/1.0\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n"),
        ("ifconfig.me",    80u16, "GET /ip HTTP/1.0\r\nHost: ifconfig.me\r\nConnection: close\r\n\r\n"),
        ("icanhazip.com",  80u16, "GET / HTTP/1.0\r\nHost: icanhazip.com\r\nConnection: close\r\n\r\n"),
    ];

    for (host, port, request) in &services {
        let addr = format!("{}:{}", host, port);
        match TcpStream::connect(&addr).await {
            Ok(mut stream) => {
                if stream.write_all(request.as_bytes()).await.is_err() {
                    continue;
                }

                let mut response = Vec::new();
                let mut buf      = [0u8; 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0)  => break,
                        Ok(n)  => response.extend_from_slice(&buf[..n]),
                        Err(_) => break,
                    }
                    if response.len() > 4096 { break; }
                }

                // The IP address is the last non-empty line of the HTTP response body
                let response_str = String::from_utf8_lossy(&response);
                if let Some(ip) = response_str
                    .lines()
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty())
                    .last()
                {
                    let ip = ip.to_string();
                    // Validate: IPv4 addresses are 7-15 chars containing only digits and dots
                    if ip.contains('.') && ip.len() >= 7 && ip.len() <= 15
                        && ip.chars().all(|c| c.is_numeric() || c == '.')
                    {
                        println!("[network] Detected public IP: {}", ip);
                        return ip;
                    }
                }
            }
            Err(e) => println!("[network] Could not connect to {}: {}", host, e),
        }
    }

    println!("[network] Public IP detection failed — falling back to local IP");
    get_local_ip().await
}

/// Detects the local network IP by opening a connection and reading
/// which local address the OS assigned for the outbound route.
///
/// Returns 127.0.0.1 as a last resort if all targets are unreachable.
/// Useful for same-WiFi testing when public IP detection is not needed.
async fn get_local_ip() -> String {
    for target in &["8.8.8.8:53", "1.1.1.1:53"] {
        if let Ok(stream) = TcpStream::connect(target).await {
            if let Ok(addr) = stream.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    "127.0.0.1".to_string()
}
