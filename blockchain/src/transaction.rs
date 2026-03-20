// =============================================================================
// transaction.rs — Coin Transfers, Staking, Unstaking, and Slashing
// =============================================================================
//
// Four transaction kinds:
//
//   Transfer  — move coins between addresses
//   Stake     — lock coins into the validator set
//   Unstake   — begin the unbonding period
//   Slash     — protocol-generated penalty for a proven double-sign offense
//
// SLASHING:
//
//   A slash transaction is created automatically when a node detects a
//   validator has signed two different blocks at the same height. It carries:
//     - The offending validator's address
//     - Both conflicting block hashes and their signatures as evidence
//     - A fraction of the stake is burned (removed from supply), the rest
//       goes to the whistleblower who submitted the evidence
//
//   Slash transactions have from = "slash" and require no user signature —
//   the evidence (two valid signatures from the same key on different blocks
//   at the same height) is the proof. Any node can submit slash evidence
//   to the mempool via the slash_validator() method on Blockchain.
// =============================================================================

use serde::{Serialize, Deserialize};
use crate::crypto;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum TxKind {
    Transfer,
    Stake,
    Unstake,
    /// Protocol-generated slashing penalty for proven double-signing.
    Slash,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Transaction {
    pub kind:      TxKind,
    pub from:      String,
    pub to:        String,
    pub amount:    u64,
    pub nonce:     u64,
    pub signature: Option<Vec<u8>>,

    /// Slashing evidence — only populated for TxKind::Slash.
    /// Contains (block_hash_a, sig_a, block_hash_b, sig_b) proving
    /// the validator signed two different blocks at the same height.
    pub slash_evidence: Option<SlashEvidence>,
}

/// Cryptographic proof that a validator double-signed at a given height.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SlashEvidence {
    /// The height at which both blocks were signed.
    pub block_height: u64,
    /// Hash of the first block the validator signed.
    pub block_hash_a: String,
    /// Validator's Dilithium3 signature of block_hash_a.
    pub sig_a: Vec<u8>,
    /// Hash of the second (conflicting) block the validator signed.
    pub block_hash_b: String,
    /// Validator's Dilithium3 signature of block_hash_b.
    pub sig_b: Vec<u8>,
}

impl Transaction {
    pub fn new_transfer(from: String, to: String, amount: u64, nonce: u64) -> Self {
        Transaction { kind: TxKind::Transfer, from, to, amount, nonce,
            signature: None, slash_evidence: None }
    }

    /// Backwards-compatible constructor — equivalent to new_transfer.
    pub fn new(from: String, to: String, amount: u64, nonce: u64) -> Self {
        Self::new_transfer(from, to, amount, nonce)
    }

    pub fn new_stake(from_pubkey_hex: String, own_address: String, amount: u64, nonce: u64) -> Self {
        Transaction { kind: TxKind::Stake, from: from_pubkey_hex, to: own_address,
            amount, nonce, signature: None, slash_evidence: None }
    }

    pub fn new_unstake(from_pubkey_hex: String, own_address: String, amount: u64, nonce: u64) -> Self {
        Transaction { kind: TxKind::Unstake, from: from_pubkey_hex, to: own_address,
            amount, nonce, signature: None, slash_evidence: None }
    }

    pub fn new_reward(validator_address: String, amount: u64) -> Self {
        Transaction { kind: TxKind::Transfer, from: "coinbase".to_string(),
            to: validator_address, amount, nonce: 0, signature: None,
            slash_evidence: None }
    }

    pub fn new_unbonding_release(address: String, amount: u64) -> Self {
        Transaction { kind: TxKind::Transfer, from: "system".to_string(),
            to: address, amount, nonce: 0, signature: None,
            slash_evidence: None }
    }

    /// Creates a slash transaction.
    ///
    /// `offender`    — address of the validator being slashed
    /// `reporter`    — address of the whistleblower receiving the reward
    /// `slash_amount`— coins removed from offender's stake (burned or redistributed)
    /// `evidence`    — the two conflicting signed block hashes proving the offense
    pub fn new_slash(
        offender:     String,
        reporter:     String,
        slash_amount: u64,
        evidence:     SlashEvidence,
    ) -> Self {
        Transaction {
            kind:           TxKind::Slash,
            from:           format!("slash:{}", offender),
            to:             reporter,
            amount:         slash_amount,
            nonce:          0,
            signature:      None,
            slash_evidence: Some(evidence),
        }
    }

    pub fn signing_data(&self) -> Vec<u8> {
        let kind_str = match self.kind {
            TxKind::Transfer => "transfer",
            TxKind::Stake    => "stake",
            TxKind::Unstake  => "unstake",
            TxKind::Slash    => "slash",
        };
        format!("{}{}{}{}{}", kind_str, self.from, self.to, self.amount, self.nonce)
            .into_bytes()
    }

    pub fn sign(&mut self, wallet: &crypto::Wallet) {
        self.signature = Some(wallet.sign(&self.signing_data()));
    }

    pub fn sender_address(&self) -> String {
        if self.from == "coinbase" || self.from == "system"
            || self.from.starts_with("slash:")
            || self.from.starts_with("genesis:")
        {
            return self.from.clone();
        }
        let pk_bytes = hex::decode(&self.from).unwrap_or_default();
        crypto::to_hex(&crypto::sha256(&pk_bytes))
    }

    /// Validates this transaction's signature.
    ///
    /// Protocol-generated transactions (coinbase, system, slash) are always
    /// valid — they are created by the protocol, not users, and their
    /// validity is established by the slash_evidence proof instead.
    pub fn is_valid(&self) -> bool {
        if matches!(self.from.as_str(), "coinbase" | "system")
            || self.from.starts_with("slash:")
            || self.from.starts_with("genesis:")
        {
            return true;
        }
        match &self.signature {
            None => false,
            Some(sig_bytes) => {
                match hex::decode(&self.from) {
                    Ok(pub_key_bytes) => crypto::verify_signature(
                        &pub_key_bytes, &self.signing_data(), sig_bytes),
                    Err(_) => false,
                }
            }
        }
    }
}
