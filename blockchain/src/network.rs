// =============================================================================
// network.rs — Peer-to-Peer Networking
// =============================================================================
//
// Turns the standalone blockchain program into a distributed network where
// many computers hold identical copies of the chain and communicate in real time.
//
// ARCHITECTURE — NO CENTRAL SERVER:
//
//   Every node is equal. Each holds a full copy of the chain and connects
//   directly to other nodes. There is no master server — any node can go
//   offline and the network continues. Nodes are simultaneously both clients
//   (they connect outward to peers) and servers (they accept incoming connections).
//
// MESSAGE PROTOCOL:
//
//   Raw TCP has no message boundaries — it's a continuous stream of bytes.
//   We use length-prefix framing: every message is preceded by a 4-byte
//   big-endian integer telling the receiver how many bytes to read.
//
//   ┌──────────────────┬──────────────────────────────────┐
//   │  4 bytes         │  N bytes                         │
//   │  payload length  │  JSON-serialized Message enum    │
//   └──────────────────┴──────────────────────────────────┘
//
// CONSENSUS — LONGEST CHAIN WINS:
//
//   When a node connects to a peer it immediately requests their full chain.
//   If the peer has more blocks, we adopt their chain. All nodes gradually
//   converge on the same canonical chain through this simple rule.
//
// BLOCK PROPAGATION — HOW ALL NODES STAY IN SYNC:
//
//   Previously each peer connection was isolated — when a block arrived from
//   one peer, it was never forwarded to other connected peers. This meant
//   mine-and-broadcast to port 8000 would never reach wallet_2 on port 8001.
//
//   The fix: a shared PeerMap (HashMap<address, channel>) is passed into every
//   peer handler. When a valid block or transaction arrives, the handler looks
//   up all OTHER connected peers in the map and sends them a copy via their
//   channels. A writer task per peer drains its channel and sends to the wire.
//
//   Result: broadcasting to ANY one peer propagates to ALL connected peers
//   automatically, just like real Bitcoin's gossip network.
//
// CONCURRENCY MODEL:
//
//   Each peer connection is split into:
//     - A reader task: receives messages and processes them
//     - A writer task: drains an mpsc channel and writes to the TCP socket
//
//   The channel between them means the reader can push messages to any peer
//   without blocking — it just sends to the channel and moves on.
//   Arc<Mutex<Blockchain>> ensures only one task modifies the chain at a time.
//
// SEED NODE INTEGRATION:
//
//   The seed node uses a separate protocol (Announce/Heartbeat/PeerList).
//   After initial peer discovery, nodes communicate directly peer-to-peer.
// =============================================================================

use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use std::sync::Arc;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::block::Block;
use crate::transaction::Transaction;
use crate::blockchain::Blockchain;
use crate::chain_store;

// =============================================================================
// Peer Map — Shared Registry of Connected Peers
// =============================================================================

/// A channel sender that lets any task push a Message to a specific peer.
/// The peer's writer task drains this channel and sends to the TCP socket.
type PeerSender = mpsc::UnboundedSender<Message>;

/// Shared registry of all currently connected peers.
/// Maps "ip:port" address string → channel for sending messages to that peer.
/// Wrapped in Arc<Mutex<>> so it can be shared across concurrent tasks.
pub type PeerMap = Arc<Mutex<HashMap<String, PeerSender>>>;

/// Creates a new empty peer map. Called once in start_node and passed to all handlers.
pub fn new_peer_map() -> PeerMap {
    Arc::new(Mutex::new(HashMap::new()))
}

// =============================================================================
// Message Types
// =============================================================================

/// All messages that blockchain nodes send to each other.
///
/// Serialized to JSON before sending, deserialized after receiving.
/// Variant name appears in the JSON:  {"NewBlock": { ...block fields... }}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message {
    /// A newly signed unconfirmed transaction — add to recipient's mempool.
    NewTransaction(Transaction),

    /// A freshly mined block — validate and add to recipient's chain.
    NewBlock(Block),

    /// Request the peer's full chain (sent on first connection to sync up).
    RequestChain,

    /// Response to RequestChain — the sender's complete block list.
    /// If longer than ours, we adopt it (longest chain wins).
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
pub async fn send_message(stream: &mut TcpStream, msg: &Message) -> Result<(), String> {
    let json = serde_json::to_string(msg).map_err(|e| e.to_string())?;
    let len  = json.len() as u32;
    stream.write_all(&len.to_be_bytes()).await.map_err(|e| e.to_string())?;
    stream.write_all(json.as_bytes()).await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Receives one complete message from a peer.
///
/// Reads the 4-byte length header, then reads exactly that many bytes
/// and deserializes into the appropriate Message variant.
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
// Internal Helpers
// =============================================================================

/// Broadcasts a message to all peers in the map EXCEPT the one who sent it.
///
/// Used after accepting a block or transaction to propagate it to the rest
/// of the network. The `origin` peer is excluded to avoid echoing a message
/// back to whoever sent it.
async fn broadcast_to_others(peers: &PeerMap, origin: &str, msg: Message) {
    let peer_map = peers.lock().await;
    let mut count = 0;
    for (addr, sender) in peer_map.iter() {
        if addr != origin {
            let _ = sender.send(msg.clone());
            count += 1;
        }
    }
    if count > 0 {
        println!("[network] Forwarded to {} other peer(s)", count);
    }
}

/// Sends a message to one specific peer via their channel.
async fn send_to_peer(peers: &PeerMap, addr: &str, msg: Message) {
    let peer_map = peers.lock().await;
    if let Some(sender) = peer_map.get(addr) {
        let _ = sender.send(msg);
    }
}

// =============================================================================
// Peer Handler
// =============================================================================

/// Manages one peer connection for its entire lifetime.
///
/// Splits the TCP stream into read and write halves:
///   - Spawns a writer task that drains the peer's channel to the TCP socket
///   - Runs the reader loop in the current task
///
/// This split means any other task can push messages to this peer without
/// needing direct access to the TCP stream — they just send to the channel.
///
/// On disconnect, removes the peer from the shared registry.
async fn handle_peer(
    stream: TcpStream,
    chain: Arc<Mutex<Blockchain>>,
    peers: PeerMap,
    peer_addr: String,
    chain_path: String,
) {
    println!("[network] Peer connected: {}", peer_addr);

    // Split the TCP stream into independent read and write halves
    let (mut read_half, mut write_half) = stream.into_split();

    // Create an unbounded channel for this peer
    // Other tasks push messages here; the writer task sends them to the socket
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    // Register this peer in the shared map so other handlers can reach them
    {
        let mut map = peers.lock().await;
        map.insert(peer_addr.clone(), tx);
    }

    // Spawn the writer task — drains the channel and sends to the TCP socket
    let writer_addr = peer_addr.clone();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match serde_json::to_string(&msg) {
                Ok(json) => {
                    let len = json.len() as u32;
                    if write_half.write_all(&len.to_be_bytes()).await.is_err() { break; }
                    if write_half.write_all(json.as_bytes()).await.is_err()    { break; }
                }
                Err(e) => println!("[network] Serialization error for {}: {}", writer_addr, e),
            }
        }
    });

    // Reader loop — receives messages and processes them
    loop {
        // Read length prefix
        let mut len_bytes = [0u8; 4];
        if read_half.read_exact(&mut len_bytes).await.is_err() { break; }
        let len = u32::from_be_bytes(len_bytes) as usize;

        // Read payload
        let mut buffer = vec![0u8; len];
        if read_half.read_exact(&mut buffer).await.is_err() { break; }

        // Deserialize
        let json = match String::from_utf8(buffer) {
            Ok(s)  => s,
            Err(_) => break,
        };
        let msg: Message = match serde_json::from_str(&json) {
            Ok(m)  => m,
            Err(e) => {
                println!("[network] Could not deserialize message from {}: {}", peer_addr, e);
                break;
            }
        };

        match msg {

            // Liveness check — reply via the channel (not directly to socket)
            Message::Ping => {
                send_to_peer(&peers, &peer_addr, Message::Pong).await;
            }

            // Confirms peer is alive
            Message::Pong => {}

            // Incoming transaction — validate and add to mempool.
            // Then forward to all other connected peers so the whole
            // network learns about it, not just this one node.
            Message::NewTransaction(tx) => {
                let mut chain_guard = chain.lock().await;
                match chain_guard.add_transaction(tx.clone()) {
                    Ok(_) => {
                        println!("[network] Added transaction from {}", peer_addr);
                        drop(chain_guard); // release lock before propagating
                        broadcast_to_others(&peers, &peer_addr, Message::NewTransaction(tx)).await;
                    }
                    Err(e) => println!("[network] Rejected transaction from {}: {}", peer_addr, e),
                }
            }

            // Incoming block — validate and add to chain.
            //
            // Three conditions must all pass:
            //   index_ok — block is exactly one ahead of our current tip
            //   prev_ok  — block correctly references our tip's hash
            //   hash_ok  — block's stored hash matches recalculating it
            //
            // If valid: update UTXO set, tx_nonces, supply, save, then
            // PROPAGATE to all other connected peers.
            //
            // Propagation is the key fix — without it, a block received from
            // wallet_1 on port 8000 never reaches wallet_2 on port 8001.
            Message::NewBlock(block) => {
                let mut chain_guard = chain.lock().await;
                let latest   = chain_guard.latest_block().index;
                let index_ok = block.index == latest + 1;
                let prev_ok  = block.prev_hash == chain_guard.latest_block().hash;
                let hash_ok  = block.hash == block.calculate_hash();

                if index_ok && prev_ok && hash_ok {
                    println!("[network] Accepted block #{} from {}", block.index, peer_addr);

                    // Update UTXO balances and confirmed nonces
                    let transactions = block.transactions.clone();
                    for tx in &transactions {
                        if tx.from == "coinbase" {
                            chain_guard.total_supply += tx.amount;
                        } else {
                            let s = chain_guard.utxo_set
                                .entry(tx.sender_address())
                                .or_insert(0);
                            *s -= tx.amount;
                            chain_guard.tx_nonces.insert(tx.sender_address(), tx.nonce);
                        }
                        let r = chain_guard.utxo_set.entry(tx.to.clone()).or_insert(0);
                        *r += tx.amount;
                    }

                    chain_guard.chain.push(block.clone());
                    chain_store::save_chain(&chain_guard, &chain_path)
                        .unwrap_or_else(|e| println!("[network] Save error: {}", e));

                    // Release the chain lock before propagating — propagation
                    // acquires the peers lock, and we must never hold two locks
                    // simultaneously (would cause a deadlock)
                    drop(chain_guard);

                    // Forward this block to every other connected peer
                    broadcast_to_others(&peers, &peer_addr, Message::NewBlock(block)).await;

                } else {
                    println!(
                        "[network] Rejected block #{} from {} — \
                         index ok: {}, prev_hash ok: {}, hash ok: {}",
                        block.index, peer_addr, index_ok, prev_ok, hash_ok
                    );
                }
            }

            // Peer wants our full chain — send it via the channel
            Message::RequestChain => {
                let chain_guard = chain.lock().await;
                let response    = Message::ResponseChain(chain_guard.chain.clone());
                let block_count = chain_guard.chain.len();
                drop(chain_guard);
                send_to_peer(&peers, &peer_addr, response).await;
                println!("[network] Sent chain ({} blocks) to {}", block_count, peer_addr);
            }

            // Peer sent their chain — adopt if longer (longest chain wins).
            //
            // Always rebuild ALL derived state from scratch when adopting:
            //   utxo_set    — address → balance
            //   tx_nonces   — address → last confirmed nonce
            //   total_supply — total coins minted
            //
            // Never trust peer-reported state — derive everything from raw blocks.
            Message::ResponseChain(their_chain) => {
                let mut chain_guard = chain.lock().await;

                if their_chain.len() > chain_guard.chain.len() {
                    println!(
                        "[network] Adopting longer chain from {} ({} blocks vs our {})",
                        peer_addr, their_chain.len(), chain_guard.chain.len()
                    );

                    chain_guard.chain = their_chain;
                    chain_guard.utxo_set.clear();
                    chain_guard.tx_nonces.clear();
                    chain_guard.total_supply = 0;

                    let blocks = chain_guard.chain.clone();
                    for block in &blocks {
                        for tx in &block.transactions {
                            if tx.from == "coinbase" {
                                chain_guard.total_supply += tx.amount;
                            } else {
                                let s = chain_guard.utxo_set
                                    .entry(tx.sender_address())
                                    .or_insert(0);
                                *s -= tx.amount;
                                chain_guard.tx_nonces.insert(tx.sender_address(), tx.nonce);
                            }
                            let r = chain_guard.utxo_set.entry(tx.to.clone()).or_insert(0);
                            *r += tx.amount;
                        }
                    }

                    chain_store::save_chain(&chain_guard, &chain_path)
                        .unwrap_or_else(|e| println!("[network] Save error: {}", e));
                } else {
                    println!("[network] Our chain is equal or longer — keeping ours");
                }
            }
        }
    }

    // Peer disconnected — remove from registry so we stop trying to send to them
    {
        let mut map = peers.lock().await;
        map.remove(&peer_addr);
    }
    println!("[network] Peer disconnected: {}", peer_addr);
}

// =============================================================================
// Node Entry Point
// =============================================================================

/// Starts the P2P node — runs forever until the process is killed.
///
/// Creates a shared PeerMap and passes it to every peer handler.
/// This enables block and transaction propagation across all connected peers.
///
/// 1. Binds a TCP listener on 0.0.0.0:<port>
/// 2. If connect_to is provided, connects to that peer and requests their chain
/// 3. Loops forever accepting incoming connections, one task per peer
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

    // Single shared peer map for this node — all handlers share it
    let peers = new_peer_map();

    // If given a peer address, connect outward and request their chain
    if let Some(peer_addr) = connect_to {
        let chain_clone = Arc::clone(&chain);
        let peers_clone = Arc::clone(&peers);
        let path_clone  = chain_path.clone();
        tokio::spawn(async move {
            match TcpStream::connect(&peer_addr).await {
                Ok(mut stream) => {
                    println!("[network] Connected to peer {}", peer_addr);
                    // Request their chain immediately before handing off to handler
                    let _ = send_message(&mut stream, &Message::RequestChain).await;
                    handle_peer(stream, chain_clone, peers_clone, peer_addr, path_clone).await;
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
                let peers_clone = Arc::clone(&peers);
                let path_clone  = chain_path.clone();
                tokio::spawn(async move {
                    handle_peer(stream, chain_clone, peers_clone, addr.to_string(), path_clone).await;
                });
            }
            Err(e) => println!("[network] Failed to accept connection: {}", e),
        }
    }
}

// =============================================================================
// Seed Node Integration
// =============================================================================

/// Registers with the seed node and returns the list of known peers.
///
/// Sends an Announce message. The seed node replies with a PeerList of
/// other currently active nodes. We connect directly to those peers —
/// the seed node is not involved in any subsequent communication.
pub async fn register_with_seed(seed_addr: &str, our_listen_addr: &str) -> Vec<String> {
    let mut stream = match TcpStream::connect(seed_addr).await {
        Ok(s)  => s,
        Err(e) => {
            println!("[seed] Could not reach seed node {}: {}", seed_addr, e);
            return vec![];
        }
    };

    let msg  = serde_json::json!({ "Announce": { "address": our_listen_addr } });
    let json = msg.to_string();
    let len  = json.len() as u32;
    if stream.write_all(&len.to_be_bytes()).await.is_err() { return vec![]; }
    if stream.write_all(json.as_bytes()).await.is_err()    { return vec![]; }

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
/// Runs forever in a background tokio::spawn task.
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
/// main.rs needs this when connecting outward to seed-discovered peers
/// so those connections share the same peer map as the main node.
pub async fn handle_peer_public(
    stream: TcpStream,
    chain: Arc<Mutex<Blockchain>>,
    peers: PeerMap,
    peer_addr: String,
    chain_path: String,
) {
    handle_peer(stream, chain, peers, peer_addr, chain_path).await;
}

// =============================================================================
// IP Detection
// =============================================================================

/// Detects this machine's public IP using raw HTTP over Tokio TCP.
/// No extra dependencies — uses only what's already in the project.
/// Falls back to local IP if all external services fail.
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
                if stream.write_all(request.as_bytes()).await.is_err() { continue; }

                let mut response = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0)  => break,
                        Ok(n)  => response.extend_from_slice(&buf[..n]),
                        Err(_) => break,
                    }
                    if response.len() > 4096 { break; }
                }

                let response_str = String::from_utf8_lossy(&response);
                if let Some(ip) = response_str
                    .lines()
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty())
                    .last()
                {
                    let ip = ip.to_string();
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

/// Detects the local network IP by reading which address the OS uses
/// for an outbound connection. Returns 127.0.0.1 as a last resort.
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
