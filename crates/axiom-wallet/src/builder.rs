// Copyright (c) 2026 Kantoshi Miyamura

// Transaction builder. Signs over the canonical serialization so builder and
// validator are always byte-for-byte identical — any drift silently breaks
// signature verification.

use crate::{KeyPair, Result, WalletError};
use axiom_primitives::{Amount, Hash256, Signature};
use axiom_protocol::{ConfidentialTxOutput, Transaction, TxInput, TxOutput};

/// Builder for constructing and signing transactions.
pub struct TransactionBuilder {
    inputs: Vec<(Hash256, u32)>,
    input_values: Vec<u64>, // per-input value, required for confidential txs
    outputs: Vec<TxOutput>,
    nonce: Option<u64>,
    locktime: u32,
    keypair: Option<KeyPair>,
    chain_id: String,
    memo: Option<[u8; 80]>,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        TransactionBuilder {
            inputs: Vec::new(),
            input_values: Vec::new(),
            outputs: Vec::new(),
            nonce: None,
            locktime: 0,
            keypair: None,
            chain_id: String::new(),
            memo: None,
        }
    }

    pub fn add_input(mut self, prev_tx_hash: Hash256, prev_output_index: u32) -> Self {
        self.inputs.push((prev_tx_hash, prev_output_index));
        self.input_values.push(0);
        self
    }

    /// Add an input with its UTXO value. Required for confidential transactions.
    pub fn add_input_with_value(
        mut self,
        prev_tx_hash: Hash256,
        prev_output_index: u32,
        value: u64,
    ) -> Self {
        self.inputs.push((prev_tx_hash, prev_output_index));
        self.input_values.push(value);
        self
    }

    /// Sum of all known input values (set via `add_input_with_value`).
    pub fn inputs_value(&self) -> u64 {
        self.input_values.iter().sum()
    }

    pub fn add_output(mut self, value: Amount, pubkey_hash: Hash256) -> Self {
        let output = TxOutput { value, pubkey_hash };
        self.outputs.push(output);
        self
    }

    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    pub fn locktime(mut self, locktime: u32) -> Self {
        self.locktime = locktime;
        self
    }

    pub fn keypair(mut self, keypair: KeyPair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    /// Attach a memo (truncated to 80 bytes).
    pub fn memo(mut self, text: &str) -> Self {
        let bytes = text.as_bytes();
        let mut buf = [0u8; 80];
        let len = bytes.len().min(80);
        buf[..len].copy_from_slice(&bytes[..len]);
        self.memo = Some(buf);
        self
    }

    /// Set chain ID for replay protection. Must match the validating node.
    pub fn chain_id(mut self, chain_id: impl Into<String>) -> Self {
        self.chain_id = chain_id.into();
        self
    }

    /// Build and sign the transaction.
    pub fn build(self) -> Result<Transaction> {
        let nonce = self
            .nonce
            .ok_or_else(|| WalletError::BuilderIncomplete("nonce not set".into()))?;

        let keypair = self
            .keypair
            .ok_or_else(|| WalletError::BuilderIncomplete("keypair not set".into()))?;

        if self.inputs.is_empty() {
            return Err(WalletError::BuilderIncomplete("no inputs".into()));
        }

        if self.outputs.is_empty() {
            return Err(WalletError::BuilderIncomplete("no outputs".into()));
        }

        let pubkey = keypair.public_key_struct()?;

        let unsigned_inputs: Vec<TxInput> = self
            .inputs
            .iter()
            .map(|(hash, idx)| TxInput {
                prev_tx_hash: *hash,
                prev_output_index: *idx,
                signature: Signature::placeholder(),
                pubkey: pubkey.clone(),
            })
            .collect();

        let mut unsigned_tx =
            Transaction::new_transfer(unsigned_inputs, self.outputs.clone(), nonce, self.locktime);
        unsigned_tx.memo = self.memo;

        let tx_data = axiom_protocol::serialize_transaction(&unsigned_tx);
        let sign_hash = axiom_crypto::transaction_signing_hash(&self.chain_id, &tx_data);

        let signature = keypair.sign_struct(sign_hash.as_bytes())?;

        let signed_inputs: Vec<TxInput> = self
            .inputs
            .iter()
            .map(|(hash, idx)| TxInput {
                prev_tx_hash: *hash,
                prev_output_index: *idx,
                signature: signature.clone(),
                pubkey: pubkey.clone(),
            })
            .collect();

        let mut tx = Transaction::new_transfer(signed_inputs, self.outputs, nonce, self.locktime);
        tx.memo = self.memo;
        Ok(tx)
    }

    /// Build a confidential transfer. Inputs from standard UTXOs; outputs hidden
    /// behind Pedersen commitments with Bulletproof range proofs.
    /// Returns the signed transaction and the per-output blinding factors
    /// (needed later to spend the outputs).
    pub fn build_confidential(
        self,
        outputs: &[(u64, [u8; 32])], // (value, recipient_pubkey_hash)
        fee: u64,
        keypair: &KeyPair,
    ) -> Result<(Transaction, Vec<[u8; 32]>)> {
        let nonce = self
            .nonce
            .ok_or_else(|| WalletError::BuilderIncomplete("nonce not set".into()))?;

        if self.inputs.is_empty() {
            return Err(WalletError::BuilderIncomplete("no inputs".into()));
        }

        let input_sum = self.inputs_value();
        let output_sum: u64 = outputs.iter().map(|(v, _)| v).sum();
        let total_out = output_sum
            .checked_add(fee)
            .ok_or_else(|| WalletError::Other("output_sum + fee overflow".into()))?;
        if input_sum < total_out {
            return Err(WalletError::InsufficientFunds);
        }

        let mut blindings: Vec<axiom_ct::BlindingFactor> = Vec::new();
        let mut conf_outputs: Vec<ConfidentialTxOutput> = Vec::new();

        for (value, pubkey_hash) in outputs {
            let r = axiom_ct::BlindingFactor::random();
            let r_copy = axiom_ct::BlindingFactor::from_bytes(&r.to_bytes());
            let (proof, commitments) = axiom_ct::AxiomRangeProof::prove(&[(*value, r_copy)])
                .map_err(|e| WalletError::Other(e.to_string()))?;
            let commitment_bytes = commitments[0].to_bytes();

            conf_outputs.push(ConfidentialTxOutput {
                commitment: commitment_bytes,
                range_proof_bytes: proof.to_wire_bytes(),
                pubkey_hash: *pubkey_hash,
            });
            blindings.push(r);
        }

        // balance_commitment = commit(0, -sum_r) so verifier can check
        // inputs == sum(outputs) + fee without learning individual amounts.
        let sum_r = axiom_ct::sum_blinding_factors(&blindings);
        let neg_sum_r = sum_r.negate();
        let balance_commitment = axiom_ct::Commitment::commit(0, &neg_sum_r);

        let pubkey = keypair.public_key_struct()?;
        let unsigned_inputs: Vec<TxInput> = self
            .inputs
            .iter()
            .map(|(hash, idx)| TxInput {
                prev_tx_hash: *hash,
                prev_output_index: *idx,
                signature: Signature::placeholder(),
                pubkey: pubkey.clone(),
            })
            .collect();

        let unsigned_tx = Transaction::new_confidential(
            unsigned_inputs,
            conf_outputs.clone(),
            nonce,
            self.locktime,
            Some(balance_commitment.to_bytes()),
        );

        let tx_data = axiom_protocol::serialize_transaction(&unsigned_tx);
        let sign_hash = axiom_crypto::transaction_signing_hash(&self.chain_id, &tx_data);
        let signature = keypair.sign_struct(sign_hash.as_bytes())?;

        let signed_inputs: Vec<TxInput> = self
            .inputs
            .iter()
            .map(|(hash, idx)| TxInput {
                prev_tx_hash: *hash,
                prev_output_index: *idx,
                signature: signature.clone(),
                pubkey: pubkey.clone(),
            })
            .collect();

        let tx = Transaction::new_confidential(
            signed_inputs,
            conf_outputs,
            nonce,
            self.locktime,
            Some(balance_commitment.to_bytes()),
        );

        let blinding_bytes: Vec<[u8; 32]> = blindings.iter().map(|r| r.to_bytes()).collect();
        Ok((tx, blinding_bytes))
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_basic() {
        let keypair = KeyPair::generate().unwrap();
        let amount = Amount::from_sat(1000).unwrap();

        let tx = TransactionBuilder::new()
            .add_input(Hash256::zero(), 0)
            .add_output(amount, Hash256::zero())
            .nonce(1)
            .keypair(keypair)
            .build()
            .unwrap();

        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.nonce, 1);
    }

    #[test]
    fn test_builder_missing_nonce() {
        let keypair = KeyPair::generate().unwrap();
        let amount = Amount::from_sat(1000).unwrap();

        let result = TransactionBuilder::new()
            .add_input(Hash256::zero(), 0)
            .add_output(amount, Hash256::zero())
            .keypair(keypair)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_missing_keypair() {
        let amount = Amount::from_sat(1000).unwrap();

        let result = TransactionBuilder::new()
            .add_input(Hash256::zero(), 0)
            .add_output(amount, Hash256::zero())
            .nonce(1)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_no_inputs() {
        let keypair = KeyPair::generate().unwrap();
        let amount = Amount::from_sat(1000).unwrap();

        let result = TransactionBuilder::new()
            .add_output(amount, Hash256::zero())
            .nonce(1)
            .keypair(keypair)
            .build();

        assert!(result.is_err());
    }
}
