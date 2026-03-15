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
//   3. Validated  add_transaction() checks signature + balance + mempool
//   4. Confirmed  a miner includes it in a block — permanently on chain
//
// THE `from` FIELD — WHY IT'S A FULL PUBLIC KEY:
//
//   In classical ECDSA blockchains (like Bitcoin), `from` can store just
//   the sender's short address because ECDSA supports public key recovery —
//   you can mathematically reconstruct the public key from the signature.
//
//   Dilithium3 does NOT support public key recovery. The verifier needs
//   the actual public key bytes to check the signature. So `from` must
//   store the full 1,952-byte public key (3,904 hex chars).
//
//   Consequences:
//     - Transactions are larger (expected cost of quantum resistance)
//     - sender_address() hashes `from` to get the compact address
//     - Balance lookups use tx.sender_address(), never tx.from directly
//     - The `to` field still uses the compact address (64 chars)
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
    /// This is NOT the sender's address — the address is SHA-256(from).
    /// Call sender_address() to get the compact address for display or
    /// balance lookups.
    ///
    /// Special value "coinbase" marks a mining reward transaction. These
    /// create new coins and require no signature or real sender.
    pub from: String,

    /// The recipient's compact address as hex (64 chars).
    ///
    /// This is SHA-256(recipient's public key) — what the recipient gets
    /// from running `balance` and shares with anyone who wants to pay them.
    pub to: String,

    /// Number of coins to transfer. Whole numbers only — no fractions.
    pub amount: u64,

    /// The Dilithium3 detached signature authorizing this transfer.
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
    pub fn new(from: String, to: String, amount: u64) -> Self {
        Transaction { from, to, amount, signature: None }
    }

    /// Returns the bytes that are signed when authorizing this transaction.
    ///
    /// Concatenates `from`, `to`, and `amount` as a UTF-8 byte string.
    /// The signature field is excluded — it doesn't exist when signing,
    /// and including it would be circular.
    ///
    /// Tamper-proofing: if any of the three fields change after signing,
    /// the signing data changes and verification will fail. A transaction
    /// cannot be modified after it has been authorized.
    ///
    /// Dilithium3 accepts arbitrary-length input (it hashes internally),
    /// so we don't need to pre-hash the data the way ECDSA required.
    pub fn signing_data(&self) -> Vec<u8> {
        format!("{}{}{}", self.from, self.to, self.amount).into_bytes()
    }

    /// Signs this transaction with the sender's Dilithium3 private key.
    ///
    /// Attaches a detached signature to the `signature` field. After calling
    /// this, is_valid() will return true (assuming the correct wallet was used).
    pub fn sign(&mut self, wallet: &crypto::Wallet) {
        self.signature = Some(wallet.sign(&self.signing_data()));
    }

    /// Returns the sender's compact address for display and UTXO lookups.
    ///
    /// Hashes `from` (the full public key) with SHA-256 to produce the
    /// 64-char address — identical to wallet.address() for the same key.
    ///
    /// This is what the UTXO set uses as keys (address → balance), so all
    /// balance checks must go through this method rather than using `from`
    /// directly.
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
    ///   - "coinbase" transactions always pass — they create new coins and
    ///     are generated by the protocol, not by a user with a private key
    ///   - All other transactions must carry a valid Dilithium3 signature
    ///     produced by the private key corresponding to `from`
    ///
    /// Note: this only checks the signature. Balance sufficiency is checked
    /// separately in blockchain::add_transaction() when entering the mempool.
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
