// Copyright (c) 2026 Kantoshi Miyamura

use axiom_primitives::{Amount, Hash256, PublicKey, Signature};
use serde::{Deserialize, Serialize};

// serde helper for Option<[u8; 80]> — uses Vec<u8> as intermediate form.
mod serde_memo {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(val: &Option<[u8; 80]>, s: S) -> Result<S::Ok, S::Error> {
        match val {
            Some(arr) => s.serialize_some(&arr.as_slice()),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 80]>, D::Error> {
        let opt: Option<Vec<u8>> = Option::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(v) => {
                if v.len() != 80 {
                    return Err(serde::de::Error::custom(format!(
                        "memo must be 80 bytes, got {}",
                        v.len()
                    )));
                }
                let mut buf = [0u8; 80];
                buf.copy_from_slice(&v);
                Ok(Some(buf))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionType {
    /// Block reward — no inputs.
    Coinbase,
    /// Standard transfer.
    Transfer,
    /// Amounts hidden behind Pedersen commitments.
    ConfidentialTransfer,
    /// Registers a community chat username on-chain.
    /// Fee: 0.001 AXM (100_000 satoshis).  One active registration per address.
    /// The username is encoded in the 80-byte memo field as raw UTF-8.
    UsernameRegistration,
}

/// Transaction input — references a previous output and proves ownership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInput {
    pub prev_tx_hash: Hash256,
    pub prev_output_index: u32,
    pub signature: Signature,
    pub pubkey: PublicKey,
}

/// Transaction output — value and recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOutput {
    pub value: Amount,
    pub pubkey_hash: Hash256,
}

/// Confidential output — amount hidden by Pedersen commitment C = v·H + r·G.
/// Bulletproof range proof guarantees v ∈ [0, 2^64).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialTxOutput {
    pub commitment: [u8; 32],
    pub range_proof_bytes: Vec<u8>,
    /// Destination is still public.
    pub pubkey_hash: [u8; 32],
}

/// A transfer of value or coinbase issuance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub version: u32,
    pub tx_type: TransactionType,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub nonce: u64,
    pub locktime: u32,
    #[serde(with = "serde_memo")]
    pub memo: Option<[u8; 80]>,
    /// Confidential outputs. Empty for Coinbase/Transfer.
    #[serde(default)]
    pub confidential_outputs: Vec<ConfidentialTxOutput>,
    /// C_balance = (-sum_of_output_blindings) * G. Lets the verifier check
    /// inputs == outputs + fee without learning individual amounts. None for
    /// standard transactions.
    #[serde(default)]
    pub balance_commitment: Option<[u8; 32]>,
}

impl Transaction {
    pub fn new_transfer(
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        nonce: u64,
        locktime: u32,
    ) -> Self {
        Transaction {
            version: 1,
            tx_type: TransactionType::Transfer,
            inputs,
            outputs,
            nonce,
            locktime,
            memo: None,
            confidential_outputs: vec![],
            balance_commitment: None,
        }
    }

    pub fn new_transfer_with_memo(
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        nonce: u64,
        locktime: u32,
        memo: Option<[u8; 80]>,
    ) -> Self {
        Transaction {
            version: 1,
            tx_type: TransactionType::Transfer,
            inputs,
            outputs,
            nonce,
            locktime,
            memo,
            confidential_outputs: vec![],
            balance_commitment: None,
        }
    }

    pub fn new_coinbase(outputs: Vec<TxOutput>, block_height: u32) -> Self {
        Transaction {
            version: 1,
            tx_type: TransactionType::Coinbase,
            inputs: vec![],
            outputs,
            nonce: block_height as u64,
            locktime: 0,
            memo: None,
            confidential_outputs: vec![],
            balance_commitment: None,
        }
    }

    /// Create a confidential transfer. Inputs from standard UTXOs; outputs hidden.
    pub fn new_confidential(
        inputs: Vec<TxInput>,
        confidential_outputs: Vec<ConfidentialTxOutput>,
        nonce: u64,
        locktime: u32,
        balance_commitment: Option<[u8; 32]>,
    ) -> Self {
        Transaction {
            version: 2,
            tx_type: TransactionType::ConfidentialTransfer,
            inputs,
            outputs: vec![],
            nonce,
            locktime,
            memo: None,
            confidential_outputs,
            balance_commitment,
        }
    }

    /// Create a username registration transaction.
    /// The `username` (≤ 32 bytes) is stored in the memo field.
    /// The caller must set exactly one output paying the 100_000 satoshi fee
    /// to the burn address and one change output.
    pub fn new_username_registration(
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        nonce: u64,
        username: &str,
    ) -> Self {
        let bytes = username.as_bytes();
        let mut buf = [0u8; 80];
        let len = bytes.len().min(32); // usernames ≤ 32 bytes
        buf[..len].copy_from_slice(&bytes[..len]);
        Transaction {
            version: 1,
            tx_type: TransactionType::UsernameRegistration,
            inputs,
            outputs,
            nonce,
            locktime: 0,
            memo: Some(buf),
            confidential_outputs: vec![],
            balance_commitment: None,
        }
    }

    pub fn with_memo(mut self, text: &str) -> Self {
        let bytes = text.as_bytes();
        let mut buf = [0u8; 80];
        let len = bytes.len().min(80);
        buf[..len].copy_from_slice(&bytes[..len]);
        self.memo = Some(buf);
        self
    }

    pub fn is_coinbase(&self) -> bool {
        matches!(self.tx_type, TransactionType::Coinbase)
    }

    pub fn is_confidential(&self) -> bool {
        matches!(self.tx_type, TransactionType::ConfidentialTransfer)
    }

    /// Returns None for coinbase (input values require UTXO lookup).
    pub fn input_value(&self) -> Option<Amount> {
        if self.is_coinbase() {
            return None;
        }
        Some(Amount::ZERO)
    }

    pub fn output_value(&self) -> crate::Result<Amount> {
        let mut total = Amount::ZERO;
        for output in &self.outputs {
            total = total.checked_add(output.value)?;
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coinbase_transaction() {
        let output = TxOutput {
            value: Amount::from_sat(5_000_000_000).unwrap(),
            pubkey_hash: Hash256::zero(),
        };

        let tx = Transaction::new_coinbase(vec![output], 0);

        assert!(tx.is_coinbase());
        assert_eq!(tx.inputs.len(), 0);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.output_value().unwrap().as_sat(), 5_000_000_000);
    }

    #[test]
    fn test_transfer_transaction() {
        let input = TxInput {
            prev_tx_hash: Hash256::zero(),
            prev_output_index: 0,
            signature: Signature::placeholder(),
            pubkey: PublicKey::from_bytes(vec![0u8; 2592]),
        };

        let output = TxOutput {
            value: Amount::from_sat(1_000_000).unwrap(),
            pubkey_hash: Hash256::zero(),
        };

        let tx = Transaction::new_transfer(vec![input], vec![output], 1, 0);

        assert!(!tx.is_coinbase());
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.nonce, 1);
    }

    #[test]
    fn test_output_value_overflow() {
        let output1 = TxOutput {
            value: Amount::MAX,
            pubkey_hash: Hash256::zero(),
        };
        let output2 = TxOutput {
            value: Amount::SATOSHI,
            pubkey_hash: Hash256::zero(),
        };

        let tx = Transaction::new_transfer(vec![], vec![output1, output2], 1, 0);

        assert!(tx.output_value().is_err());
    }
}
