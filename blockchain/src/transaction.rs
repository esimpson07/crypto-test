// =============================================================================
// transaction.rs — Transactions
// =============================================================================
//
// A transaction is a signed instruction saying:
//   "I, the owner of this public key, authorize moving X coins to this address."
//
// The word SIGNED is critical. Without a valid cryptographic signature from
// the sender, a transaction is worthless — anyone could claim to send coins
// they don't own. The signature is the mathematical proof of authorization.
//
// TRANSACTION LIFECYCLE:
//   1. Created    — new() builds an unsigned transaction shell
//   2. Signed     — sign() attaches the sender's Dilithium3 proof
//   3. Submitted  — add_transaction() validates and adds to the mempool
//   4. Confirmed  — included in a mined block, permanently on the chain
//
// POST-QUANTUM CHANGE — THE `from` FIELD:
//   In the original ECDSA version, `from` held just the sender's ADDRESS
//   (a short SHA-256 hash of their public key). The public key itself could
//   be recovered mathematically from the ECDSA signature.
//
//   Dilithium3 does NOT support public key recovery from signatures. So
//   we must include the full 1,952-byte public key in every transaction.
//   The `from` field now holds the full public key as hex (3,904 chars).
//
//   This means:
//     - Transactions are larger (expected — cost of quantum resistance)
//     - sender_address() must hash `from` to get the compact address
//     - blockchain.rs balance lookups use tx.sender_address(), not tx.from
// =============================================================================

use serde::{Serialize, Deserialize};
use crate::crypto;

/// Represents a single transfer of coins from one address to another.
///
/// Serializable so it can be stored in blocks (chain.json) and broadcast
/// across the P2P network as a JSON message.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Transaction {
    /// The sender's FULL PUBLIC KEY as a hex string (3,904 hex chars).
    ///
    /// This is NOT the same as the sender's address. The address is derived
    /// by SHA-256 hashing this field — call sender_address() to get it.
    ///
    /// We store the full public key (rather than just the address) because
    /// Dilithium3 signature verification requires the actual public key bytes.
    ///
    /// Special value: "coinbase" marks a mining reward transaction. These have
    /// no real sender and require no signature — they create new coins.
    pub from: String,

    /// The recipient's ADDRESS as a compact 64-char hex string.
    ///
    /// This is SHA-256(recipient's public key) — what the recipient gets
    /// from running `cargo run -- balance --wallet <name>` and shares with
    /// others so they can be paid. The full public key is never needed here.
    pub to: String,

    /// The number of coins being transferred.
    ///
    /// Stored as an unsigned 64-bit integer — no fractional coins.
    /// Similar to how Bitcoin uses satoshis as its smallest unit, you
    /// could define your own denomination (e.g. 1 coin = 100 subunits).
    pub amount: u64,

    /// The Dilithium3 detached signature proving the sender authorized this.
    ///
    /// None until sign() is called. A non-coinbase transaction without a
    /// signature will be rejected by is_valid() and never added to the chain.
    ///
    /// Dilithium3 signatures are 3,293 bytes, stored as raw bytes here
    /// and serialized as a hex array in JSON.
    pub signature: Option<Vec<u8>>,
}

impl Transaction {
    /// Creates a new unsigned transaction.
    ///
    /// After calling this you MUST call sign() before submitting — unsigned
    /// non-coinbase transactions are rejected by blockchain::add_transaction().
    ///
    /// `from`   — the sender's full public key hex (from public_key_hex() in main.rs)
    ///            Use "coinbase" for mining reward transactions (no signing needed)
    /// `to`     — the recipient's compact address (from wallet.address())
    /// `amount` — number of coins to transfer
    pub fn new(from: String, to: String, amount: u64) -> Self {
        Transaction { from, to, amount, signature: None }
    }

    /// Returns the raw bytes that get signed during sign() and verified during is_valid().
    ///
    /// We concatenate the three meaningful fields (from, to, amount) and convert
    /// to bytes. The signature field itself is excluded — it doesn't exist yet
    /// when we're signing, and including it would be circular.
    ///
    /// Dilithium3 signs arbitrary-length byte slices directly (it internally
    /// hashes the message during signing), so we don't need to pre-hash here
    /// the way we did with ECDSA's fixed 32-byte Message type.
    ///
    /// TAMPER-PROOFING: if `from`, `to`, or `amount` change after signing,
    /// the bytes that were signed no longer match, and verification will fail.
    /// This makes it impossible to modify a transaction after it's been authorized.
    pub fn signing_data(&self) -> Vec<u8> {
        format!("{}{}{}", self.from, self.to, self.amount).into_bytes()
    }

    /// Attaches a Dilithium3 signature to this transaction.
    ///
    /// The signature proves that the holder of the private key corresponding
    /// to the public key stored in `from` authorized this specific transfer.
    /// Without signing, the transaction will be rejected by the blockchain.
    pub fn sign(&mut self, wallet: &crypto::Wallet) {
        let data = self.signing_data();
        self.signature = Some(wallet.sign(&data));
    }

    /// Returns the sender's compact address for display and balance lookups.
    ///
    /// Since `from` holds the large public key hex (3,904 chars), this method
    /// hashes it to get the compact 64-char address — identical to what
    /// wallet.address() returns for the same key. This is what the UTXO set
    /// uses as keys, so balance lookups must go through this method.
    ///
    /// Returns "coinbase" unchanged for mining reward transactions.
    pub fn sender_address(&self) -> String {
        if self.from == "coinbase" {
            return "coinbase".to_string();
        }
        // Decode the public key from hex, then hash it to get the address
        // This is the same computation as wallet.address() — always consistent
        let pk_bytes = hex::decode(&self.from).unwrap_or_default();
        crypto::to_hex(&crypto::sha256(&pk_bytes))
    }

    /// Validates this transaction — returns true if it should be accepted.
    ///
    /// VALIDATION RULES:
    ///   Coinbase transactions (mining rewards) are always valid — they have
    ///   no sender and need no signature, as they're created by the protocol.
    ///
    ///   All other transactions must have a valid Dilithium3 signature that
    ///   was produced by the private key corresponding to the public key in `from`.
    ///
    /// NOTE: this only validates the SIGNATURE, not the balance. Whether the
    /// sender has enough coins to cover the transfer is checked separately in
    /// blockchain::add_transaction() when the transaction enters the mempool.
    pub fn is_valid(&self) -> bool {
        // Mining reward transactions are always considered valid —
        // they have "coinbase" as the sender and carry no signature
        if self.from == "coinbase" {
            return true;
        }

        match &self.signature {
            // No signature at all — immediately invalid
            None => false,

            Some(sig_bytes) => {
                // Decode the sender's public key from the `from` field
                let pub_key_bytes = match hex::decode(&self.from) {
                    Ok(bytes) => bytes,
                    Err(_)    => return false, // `from` contains invalid hex
                };

                // Verify the Dilithium3 signature against the signing data
                // Returns true only if the signature was produced by the private
                // key that corresponds to the public key in pub_key_bytes
                crypto::verify_signature(&pub_key_bytes, &self.signing_data(), sig_bytes)
            }
        }
    }
}
