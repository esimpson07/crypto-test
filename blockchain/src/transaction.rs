// =============================================================================
// transaction.rs — Coin Transfers
// =============================================================================
//
// A transaction is a signed instruction:
//   "I, the holder of this private key, authorize moving X coins to this address."
//
// The signature is everything. Without a valid Dilithium3 signature from the
// sender, a transaction is worthless — anyone could claim to send coins they
// don't own. The signature is the cryptographic proof of authorization.
//
// TRANSACTION LIFECYCLE:
//
//   1. Created    new() builds an unsigned transaction shell
//   2. Signed     sign() attaches the Dilithium3 proof of authorization
//   3. Validated  add_transaction() checks signature + nonce + balance + mempool
//   4. Confirmed  a miner includes it in a block — permanently on chain
//
// THE `from` FIELD — WHY IT'S A FULL PUBLIC KEY:
//
//   In classical ECDSA blockchains (like Bitcoin), `from` can store just the
//   sender's short address because ECDSA supports public key recovery — you can
//   mathematically reconstruct the public key from the signature alone.
//
//   Dilithium3 does NOT support public key recovery. The verifier needs the
//   actual public key bytes to check the signature. So `from` must store the
//   full 1,952-byte public key (3,904 hex chars).
//
//   Consequences:
//     - Transactions are larger (expected cost of quantum resistance)
//     - sender_address() hashes `from` to get the compact address
//     - Balance lookups use tx.sender_address(), never tx.from directly
//     - The `to` field still uses the compact address (64 chars)
//
// THE `nonce` FIELD — REPLAY ATTACK PREVENTION:
//
//   Without a nonce, a signed transaction is valid forever. If Alice sends
//   Bob 10 coins, anyone who saw that transaction on the blockchain could
//   copy it and rebroadcast it later — making Alice send another 10 coins
//   without her knowledge or consent. This is called a replay attack.
//
//   The nonce is a per-sender counter that must increment by exactly 1 with
//   each transaction. The blockchain tracks the last confirmed nonce for every
//   address in Blockchain.tx_nonces. A transaction whose nonce doesn't equal
//   last_confirmed_nonce + 1 is rejected immediately.
//
//   This makes every transaction unique even if the same amount is sent to
//   the same address repeatedly — the nonce will always differ.
//
//   Coinbase transactions use nonce = 0 (the field exists but is ignored
//   during validation since coinbase transactions have no sender nonce to track).
// =============================================================================

use serde::{Serialize, Deserialize};
use crate::crypto;

/// A single coin transfer from one address to another.
///
/// Serializable for storage in blocks (chain.json) and transmission over
/// the P2P network as a JSON message.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Transaction {
    /// The sender's full Dilithium3 public key as hex (3,904 chars).
    ///
    /// NOT the sender's address — the address is SHA-256(from).
    /// Call sender_address() to get the compact address for display or lookups.
    ///
    /// Special value "coinbase" marks a mining reward transaction. These create
    /// new coins and require no real sender, no nonce check, and no signature.
    pub from: String,

    /// The recipient's compact address as hex (64 chars).
    ///
    /// SHA-256(recipient's public key) — what the recipient shares from `balance`.
    pub to: String,

    /// Number of coins to transfer. Whole numbers only.
    pub amount: u64,

    /// Per-sender sequence number for replay attack prevention.
    ///
    /// Must be exactly last_confirmed_nonce + 1 for this sender address.
    /// The blockchain tracks confirmed nonces in Blockchain.tx_nonces.
    ///
    /// Why this works: once a transaction with nonce N is confirmed, any
    /// future transaction using the same nonce N is rejected as out of sequence.
    /// A replayed transaction always has the old nonce, which is now stale.
    ///
    /// Coinbase transactions set this to 0 — the field is present for
    /// serialization consistency but is not validated for coinbase.
    pub nonce: u64,

    /// Dilithium3 detached signature authorizing this transfer.
    ///
    /// None until sign() is called. Any non-coinbase transaction without
    /// a signature fails is_valid() and is rejected by the blockchain.
    /// Dilithium3 signatures are 3,293 bytes.
    pub signature: Option<Vec<u8>>,
}

impl Transaction {
    /// Creates a new unsigned transaction.
    ///
    /// You must call sign() before submitting — unsigned non-coinbase
    /// transactions are rejected by blockchain::add_transaction().
    ///
    /// `from`   — sender's full public key hex (use public_key_hex() in main.rs)
    ///            or "coinbase" for mining reward transactions
    /// `to`     — recipient's compact address (from wallet.address())
    /// `amount` — whole number of coins to transfer
    /// `nonce`  — must be exactly sender's last confirmed nonce + 1
    ///            use blockchain.next_nonce(sender_address) to get the right value
    ///            pass 0 for coinbase transactions
    pub fn new(from: String, to: String, amount: u64, nonce: u64) -> Self {
        Transaction { from, to, amount, nonce, signature: None }
    }

    /// Returns the bytes that are signed when authorizing this transaction.
    ///
    /// Concatenates from, to, amount, AND nonce as a UTF-8 byte string.
    /// All four fields are included so that:
    ///   - Changing the recipient invalidates the signature
    ///   - Changing the amount invalidates the signature
    ///   - Replaying with the same nonce is caught by the blockchain nonce check
    ///   - Even if the nonce check were bypassed, a replay has an identical
    ///     signature which nodes can detect and reject
    ///
    /// The signature field is excluded — it doesn't exist when signing,
    /// and including it would be circular.
    pub fn signing_data(&self) -> Vec<u8> {
        format!("{}{}{}{}", self.from, self.to, self.amount, self.nonce).into_bytes()
    }

    /// Signs this transaction with the sender's Dilithium3 private key.
    pub fn sign(&mut self, wallet: &crypto::Wallet) {
        self.signature = Some(wallet.sign(&self.signing_data()));
    }

    /// Returns the sender's compact address for display and UTXO lookups.
    ///
    /// Hashes `from` (the full public key) with SHA-256 to produce the 64-char
    /// address — identical to wallet.address() for the same key.
    ///
    /// Returns "coinbase" unchanged for mining reward transactions.
    pub fn sender_address(&self) -> String {
        if self.from == "coinbase" {
            return "coinbase".to_string();
        }
        let pk_bytes = hex::decode(&self.from).unwrap_or_default();
        crypto::to_hex(&crypto::sha256(&pk_bytes))
    }

    /// Validates this transaction's signature.
    ///
    /// Rules:
    ///   - "coinbase" transactions always pass — created by the protocol,
    ///     not by a user, so no signature or nonce check applies
    ///   - All other transactions must carry a valid Dilithium3 signature
    ///     produced by the private key corresponding to `from`
    ///
    /// Note: nonce validation and balance checks are done separately in
    /// blockchain::add_transaction() when the transaction enters the mempool.
    /// This method only verifies the cryptographic signature.
    pub fn is_valid(&self) -> bool {
        if self.from == "coinbase" {
            return true;
        }
        match &self.signature {
            None => false,
            Some(sig_bytes) => {
                match hex::decode(&self.from) {
                    Ok(pub_key_bytes) => {
                        crypto::verify_signature(&pub_key_bytes, &self.signing_data(), sig_bytes)
                    }
                    Err(_) => false,
                }
            }
        }
    }
}
