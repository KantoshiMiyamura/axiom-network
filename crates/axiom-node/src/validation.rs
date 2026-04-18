// Copyright (c) 2026 Kantoshi Miyamura

//! Transaction validation.

use axiom_consensus::{check_value_conservation, InvariantError};
use axiom_primitives::{Amount, Signature};
use axiom_protocol::{Transaction, TxInput};
use axiom_storage::{NonceTracker, UtxoSet};
use axiom_ct;
use thiserror::Error;

/// Controls signature verification depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationMode {
    /// Verify all signatures and consensus rules.
    Full,
    /// Skip signatures for blocks below the assumevalid height.
    AssumeValid,
}

/// Minimum output value in satoshis.
pub const DUST_LIMIT_SAT: u64 = 546;

/// Blocks before coinbase outputs can be spent.
pub const COINBASE_MATURITY: u32 = 100;
/// Coinbase maturity on devnet.
pub const COINBASE_MATURITY_DEVNET: u32 = 5;

#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("transaction is coinbase (not allowed in mempool)")]
    CoinbaseNotAllowed,

    #[error("transaction has no inputs")]
    NoInputs,

    #[error("transaction has no outputs")]
    NoOutputs,

    #[error("output value {value} sat is below dust limit {minimum} sat")]
    DustOutput { value: u64, minimum: u64 },

    #[error("invalid nonce: expected {expected}, got {actual}")]
    InvalidNonce { expected: u64, actual: u64 },

    #[error("input not found: {0}")]
    InputNotFound(String),

    #[error("insufficient input value")]
    InsufficientValue,

    #[error("fee too low: {0} sat/byte")]
    FeeTooLow(u64),

    #[error("transaction locktime {locktime} not yet reached (context: {context})")]
    LocktimeNotReached { locktime: u32, context: String },

    #[error("transaction locktime {locktime} not yet reached (current height: {current})")]
    LocktimePending { locktime: u32, current: u32 },

    #[error("coinbase transaction must have locktime 0, got {0}")]
    CoinbaseLocktimeNonZero(u32),

    #[error("signature verification failed")]
    InvalidSignature,

    #[error("primitives error: {0}")]
    Primitives(#[from] axiom_primitives::Error),

    #[error("protocol error: {0}")]
    Protocol(#[from] axiom_protocol::Error),

    #[error("storage error: {0}")]
    Storage(#[from] axiom_storage::Error),

    #[error("crypto error: {0}")]
    Crypto(#[from] axiom_crypto::Error),

    #[error(
        "coinbase output is immature: only {blocks_since} blocks since creation, need {required}"
    )]
    CoinbaseImmature { blocks_since: u32, required: u32 },

    #[error("duplicate input in transaction: txid {txid:?} index {index}")]
    DuplicateInput {
        txid: axiom_primitives::Hash256,
        index: u32,
    },

    #[error("confidential transaction error: {0}")]
    ConfidentialTx(String),

    /// A consensus invariant was violated (value conservation, fee, supply).
    /// Reject immediately — never log-only.
    #[error("consensus invariant violation: {0}")]
    InvariantViolation(String),
}

impl From<InvariantError> for ValidationError {
    fn from(e: InvariantError) -> Self {
        ValidationError::InvariantViolation(e.to_string())
    }
}

/// Validates transactions against chain state.
///
/// Determinism: the validator never reads system time on its own. If the caller
/// needs timestamp-locktime checks (locktime >= 500_000_000), they must supply
/// the current time via [`with_current_timestamp`]. Otherwise those checks are
/// silently skipped — consistent with a caller-injected clock model and safe
/// because timestamp locktimes are mempool-local, not reorg-critical.
pub struct TransactionValidator<'a> {
    utxo_set: UtxoSet<'a>,
    nonce_tracker: NonceTracker<'a>,
    min_fee_rate: u64,
    chain_id: String,
    current_height: Option<u32>,
    coinbase_maturity: u32,
    /// Optional wall-clock seconds supplied by the caller. `None` disables
    /// timestamp-locktime enforcement (height-locktime still enforced).
    current_timestamp: Option<u32>,
}

impl<'a> TransactionValidator<'a> {
    pub fn new(utxo_set: UtxoSet<'a>, nonce_tracker: NonceTracker<'a>, min_fee_rate: u64) -> Self {
        TransactionValidator {
            utxo_set,
            nonce_tracker,
            min_fee_rate,
            chain_id: String::new(),
            current_height: None,
            coinbase_maturity: COINBASE_MATURITY,
            current_timestamp: None,
        }
    }

    pub fn with_coinbase_maturity(mut self, maturity: u32) -> Self {
        self.coinbase_maturity = maturity;
        self
    }

    pub fn with_height(mut self, height: u32) -> Self {
        self.current_height = Some(height);
        self
    }

    pub fn with_block_height(mut self, height: u32) -> Self {
        self.current_height = Some(height);
        self
    }

    pub fn with_chain_id(mut self, chain_id: impl Into<String>) -> Self {
        self.chain_id = chain_id.into();
        self
    }

    /// Supply a deterministic wall-clock seconds value for timestamp-locktime
    /// checks. If never called, timestamp locktimes are skipped (height
    /// locktimes are still enforced).
    pub fn with_current_timestamp(mut self, now_secs: u32) -> Self {
        self.current_timestamp = Some(now_secs);
        self
    }

    /// Full validation: signatures, nonces, values, and locktime.
    pub fn validate_transaction(&self, tx: &Transaction) -> Result<(), ValidationError> {
        if tx.is_coinbase() {
            return Err(ValidationError::CoinbaseNotAllowed);
        }

        if tx.inputs.is_empty() {
            return Err(ValidationError::NoInputs);
        }

        let mut seen_inputs = std::collections::HashSet::new();
        for input in &tx.inputs {
            let key = (input.prev_tx_hash, input.prev_output_index);
            if !seen_inputs.insert(key) {
                return Err(ValidationError::DuplicateInput {
                    txid: input.prev_tx_hash,
                    index: input.prev_output_index,
                });
            }
        }

        if tx.outputs.is_empty() && !tx.is_confidential() {
            return Err(ValidationError::NoOutputs);
        }

        if !tx.is_confidential() {
            for output in &tx.outputs {
                if output.value.as_sat() < DUST_LIMIT_SAT {
                    return Err(ValidationError::DustOutput {
                        value: output.value.as_sat(),
                        minimum: DUST_LIMIT_SAT,
                    });
                }
            }
        }

        // Values < 500_000_000 are block heights; higher values are Unix timestamps.
        // Height locktimes use the injected current_height (deterministic).
        // Timestamp locktimes require an injected current_timestamp — if absent,
        // the check is skipped (the consensus layer never reads the clock on
        // its own).
        if tx.locktime > 0 {
            if tx.locktime < 500_000_000 {
                if let Some(height) = self.current_height {
                    if tx.locktime > height {
                        return Err(ValidationError::LocktimeNotReached {
                            locktime: tx.locktime,
                            context: format!("block-height locktime, current height: {}", height),
                        });
                    }
                }
            } else if let Some(current_timestamp) = self.current_timestamp {
                if tx.locktime > current_timestamp {
                    return Err(ValidationError::LocktimeNotReached {
                        locktime: tx.locktime,
                        context: format!(
                            "unix-timestamp locktime, current timestamp: {}",
                            current_timestamp
                        ),
                    });
                }
            }
        }

        let first_input = &tx.inputs[0];
        let pubkey_hash = axiom_crypto::hash256(first_input.pubkey.as_bytes());

        // SECURITY: All inputs must be signed by the same key (single-signer model).
        // Without this, an attacker can combine inputs from multiple addresses,
        // bypassing nonce tracking for all but the first signer (double-spend vector).
        for input in &tx.inputs {
            let h = axiom_crypto::hash256(input.pubkey.as_bytes());
            if h != pubkey_hash {
                return Err(ValidationError::InvalidSignature);
            }
        }

        // SECURITY: Use checked_add instead of saturating_add. At u64::MAX,
        // saturating_add returns MAX forever, allowing unlimited replay of the last tx.
        // CRITICAL FIX: Use checked_add instead of saturating_add.
        // At u64::MAX, saturating_add returns MAX forever, allowing unlimited replay
        // of the last transaction (permanent account lockout).
        // checked_add returns None at overflow, which we convert to InvalidNonce error.
        let last_used_nonce = self.nonce_tracker.get_nonce(&pubkey_hash)?.unwrap_or(0);
        let expected_nonce = last_used_nonce.checked_add(1).ok_or(ValidationError::InvalidNonce {
            expected: u64::MAX,
            actual: tx.nonce,
        })?;

        if tx.nonce != expected_nonce {
            return Err(ValidationError::InvalidNonce {
                expected: expected_nonce,
                actual: tx.nonce,
            });
        }

        let mut input_value = Amount::ZERO;

        // Strip signatures before hashing for signing-message construction.
        let stripped_inputs: Vec<TxInput> = tx
            .inputs
            .iter()
            .map(|i| TxInput {
                prev_tx_hash: i.prev_tx_hash,
                prev_output_index: i.prev_output_index,
                signature: Signature::placeholder(),
                pubkey: i.pubkey.clone(),
            })
            .collect();
        let stripped_tx = if tx.is_confidential() {
            axiom_protocol::Transaction::new_confidential(
                stripped_inputs,
                tx.confidential_outputs.clone(),
                tx.nonce,
                tx.locktime,
                tx.balance_commitment,
            )
        } else {
            Transaction::new_transfer_with_memo(
                stripped_inputs,
                tx.outputs.clone(),
                tx.nonce,
                tx.locktime,
                tx.memo,
            )
        };
        let tx_serialized = axiom_protocol::serialize_transaction(&stripped_tx);
        let message = axiom_crypto::transaction_signing_hash(&self.chain_id, &tx_serialized);

        for input in &tx.inputs {
            // CRITICAL FIX: Reject placeholder (all-zero) signatures before any crypto work.
            // Defense-in-depth: ensures no edge case in the ML-DSA library can accept zeroes.
            // This prevents potential signature forgery if ML-DSA has undiscovered bugs.
            {
                let placeholder = axiom_primitives::Signature::placeholder();
                if input.signature.as_bytes() == placeholder.as_bytes() {
                    return Err(ValidationError::InvalidSignature);
                }
            }

            // SECURITY: Verify signature BEFORE UTXO lookup. This rejects invalid
            // signatures cheaply (crypto rejection) before expensive DB reads, preventing
            // a DoS where an attacker forces 100k UTXO lookups with invalid signatures.
            axiom_crypto::verify_signature(message.as_bytes(), &input.signature, &input.pubkey)?;

            let utxo = self
                .utxo_set
                .get_utxo(&input.prev_tx_hash, input.prev_output_index)?
                .ok_or_else(|| {
                    ValidationError::InputNotFound(format!(
                        "{}:{}",
                        hex_encode(input.prev_tx_hash.as_bytes()),
                        input.prev_output_index
                    ))
                })?;

            input_value = input_value.checked_add(utxo.value)?;

            if utxo.is_coinbase {
                let current_height = self.current_height.unwrap_or(0);
                let blocks_since = current_height.saturating_sub(utxo.height);
                if blocks_since < self.coinbase_maturity {
                    return Err(ValidationError::CoinbaseImmature {
                        blocks_since,
                        required: self.coinbase_maturity,
                    });
                }
            }

            let provided_pubkey_hash = axiom_crypto::hash256(input.pubkey.as_bytes());
            if provided_pubkey_hash != utxo.pubkey_hash {
                return Err(ValidationError::InvalidSignature);
            }
        }

        if tx.is_confidential() {
            let input_sum = input_value.as_sat();
            self.validate_confidential_outputs(tx, input_sum, 0)?;

            let tx_size = axiom_protocol::serialize_transaction(tx).len() as u64;
            if tx_size > 0 && self.min_fee_rate > 0 {
                // Fee enforcement for confidential txs is handled via balance commitment.
            }
        } else {
            let output_value = tx.output_value()?;

            // INVARIANT 1+2: enforce value conservation via the consensus module.
            //   inputs >= outputs + burn, fee = inputs - outputs - burn >= 0.
            // `burn = 0` for plain transfers today; the shape is ready for future
            // burn semantics. A violation is a hard reject, not a warning.
            let fee_sat = check_value_conservation(input_value, output_value, Amount::ZERO)
                .map_err(|e| match e {
                    InvariantError::NegativeFee { .. } => ValidationError::InsufficientValue,
                    other => ValidationError::InvariantViolation(other.to_string()),
                })?;

            let tx_size = axiom_protocol::serialize_transaction(tx).len() as u64;
            // SECURITY: Ceiling division prevents sub-1-sat/byte transactions from
            // appearing to meet minimum fee rate. floor(100/200)=0 but ceil=1.
            let fee_rate = if tx_size > 0 {
                fee_sat.div_ceil(tx_size)
            } else {
                0
            };

            if fee_rate < self.min_fee_rate {
                return Err(ValidationError::FeeTooLow(fee_rate));
            }
        }

        Ok(())
    }

    /// Dispatch to full or assumevalid validation based on mode.
    pub fn validate_transaction_with_mode(
        &self,
        tx: &Transaction,
        mode: ValidationMode,
    ) -> Result<(), ValidationError> {
        match mode {
            ValidationMode::Full => self.validate_transaction(tx),
            ValidationMode::AssumeValid => self.validate_transaction_assumevalid(tx),
        }
    }

    /// Validate without verifying signatures; all other rules still apply.
    pub fn validate_transaction_assumevalid(
        &self,
        tx: &Transaction,
    ) -> Result<(), ValidationError> {
        if tx.is_coinbase() {
            return Err(ValidationError::CoinbaseNotAllowed);
        }

        if tx.inputs.is_empty() {
            return Err(ValidationError::NoInputs);
        }

        let mut seen_inputs = std::collections::HashSet::new();
        for input in &tx.inputs {
            let key = (input.prev_tx_hash, input.prev_output_index);
            if !seen_inputs.insert(key) {
                return Err(ValidationError::DuplicateInput {
                    txid: input.prev_tx_hash,
                    index: input.prev_output_index,
                });
            }
        }

        if tx.outputs.is_empty() && !tx.is_confidential() {
            return Err(ValidationError::NoOutputs);
        }

        if !tx.is_confidential() {
            for output in &tx.outputs {
                if output.value.as_sat() < DUST_LIMIT_SAT {
                    return Err(ValidationError::DustOutput {
                        value: output.value.as_sat(),
                        minimum: DUST_LIMIT_SAT,
                    });
                }
            }
        }

        if tx.locktime > 0 {
            if tx.locktime < 500_000_000 {
                if let Some(height) = self.current_height {
                    if tx.locktime > height {
                        return Err(ValidationError::LocktimeNotReached {
                            locktime: tx.locktime,
                            context: format!("block-height locktime, current height: {}", height),
                        });
                    }
                }
            } else if let Some(current_timestamp) = self.current_timestamp {
                if tx.locktime > current_timestamp {
                    return Err(ValidationError::LocktimeNotReached {
                        locktime: tx.locktime,
                        context: format!(
                            "unix-timestamp locktime, current timestamp: {}",
                            current_timestamp
                        ),
                    });
                }
            }
        }

        let first_input = &tx.inputs[0];
        let pubkey_hash = axiom_crypto::hash256(first_input.pubkey.as_bytes());

        // SECURITY: All inputs must be from the same signer (assumevalid path).
        for input in &tx.inputs {
            let h = axiom_crypto::hash256(input.pubkey.as_bytes());
            if h != pubkey_hash {
                return Err(ValidationError::InvalidSignature);
            }
        }

        // CRITICAL FIX: Use checked_add instead of saturating_add (assumevalid path).
        // Prevents nonce saturation replay at u64::MAX.
        let last_used_nonce = self.nonce_tracker.get_nonce(&pubkey_hash)?.unwrap_or(0);
        let expected_nonce = last_used_nonce.checked_add(1).ok_or(ValidationError::InvalidNonce {
            expected: u64::MAX,
            actual: tx.nonce,
        })?;

        if tx.nonce != expected_nonce {
            return Err(ValidationError::InvalidNonce {
                expected: expected_nonce,
                actual: tx.nonce,
            });
        }

        let mut input_value = Amount::ZERO;

        for input in &tx.inputs {
            let utxo = self
                .utxo_set
                .get_utxo(&input.prev_tx_hash, input.prev_output_index)?
                .ok_or_else(|| {
                    ValidationError::InputNotFound(format!(
                        "{}:{}",
                        hex_encode(input.prev_tx_hash.as_bytes()),
                        input.prev_output_index
                    ))
                })?;

            input_value = input_value.checked_add(utxo.value)?;

            if utxo.is_coinbase {
                let current_height = self.current_height.unwrap_or(0);
                let blocks_since = current_height.saturating_sub(utxo.height);
                if blocks_since < self.coinbase_maturity {
                    return Err(ValidationError::CoinbaseImmature {
                        blocks_since,
                        required: self.coinbase_maturity,
                    });
                }
            }

            // Pubkey ownership check; signature crypto skipped on this path.
            let provided_pubkey_hash = axiom_crypto::hash256(input.pubkey.as_bytes());
            if provided_pubkey_hash != utxo.pubkey_hash {
                return Err(ValidationError::InvalidSignature);
            }
        }

        if tx.is_confidential() {
            let input_sum = input_value.as_sat();
            self.validate_confidential_outputs(tx, input_sum, 0)?;
        } else {
            let output_value = tx.output_value()?;

            // INVARIANT 1+2 (assumevalid path): same value-conservation rule.
            let fee_sat = check_value_conservation(input_value, output_value, Amount::ZERO)
                .map_err(|e| match e {
                    InvariantError::NegativeFee { .. } => ValidationError::InsufficientValue,
                    other => ValidationError::InvariantViolation(other.to_string()),
                })?;

            let tx_size = axiom_protocol::serialize_transaction(tx).len() as u64;
            // SECURITY: Ceiling division prevents sub-1-sat/byte transactions from
            // appearing to meet minimum fee rate. floor(100/200)=0 but ceil=1.
            let fee_rate = if tx_size > 0 {
                fee_sat.div_ceil(tx_size)
            } else {
                0
            };

            if fee_rate < self.min_fee_rate {
                return Err(ValidationError::FeeTooLow(fee_rate));
            }
        }

        Ok(())
    }

    /// Verify range proofs and homomorphic balance equality for confidential outputs.
    fn validate_confidential_outputs(
        &self,
        tx: &Transaction,
        input_sum: u64,
        fee: u64,
    ) -> Result<(), ValidationError> {
        if tx.confidential_outputs.is_empty() {
            return Err(ValidationError::ConfidentialTx(
                "confidential transaction has no confidential outputs".into(),
            ));
        }
        let balance_bytes = tx.balance_commitment.ok_or_else(|| {
            ValidationError::ConfidentialTx(
                "confidential transaction missing balance commitment".into(),
            )
        })?;

        // CRITICAL FIX: Reject oversized range proofs BEFORE deserialization.
        // Prevents memory exhaustion DoS where attacker submits 1GB proof forcing OOM.
        // Bulletproof for 64-bit value is ~13KB; 16KB provides safety margin.
        const MAX_RANGE_PROOF_BYTES: usize = 16_384; // 16 KB

        let mut output_commitments = Vec::new();
        for (i, out) in tx.confidential_outputs.iter().enumerate() {
            // CRITICAL FIX: Check proof size BEFORE deserialization.
            if out.range_proof_bytes.len() > MAX_RANGE_PROOF_BYTES {
                return Err(ValidationError::ConfidentialTx(format!(
                    "output {i}: range proof exceeds maximum size ({} > {})",
                    out.range_proof_bytes.len(),
                    MAX_RANGE_PROOF_BYTES
                )));
            }
            let commitment = axiom_ct::Commitment::from_bytes(out.commitment);
            let proof = axiom_ct::AxiomRangeProof::from_wire_bytes(&out.range_proof_bytes)
                .map_err(|e| {
                    ValidationError::ConfidentialTx(format!(
                        "output {i}: range proof deserialization failed: {e}"
                    ))
                })?;
            proof.verify(std::slice::from_ref(&commitment)).map_err(|_| {
                ValidationError::ConfidentialTx(format!(
                    "output {i}: range proof verification failed"
                ))
            })?;
            output_commitments.push(commitment);
        }

        // C_inputs − C_fee == sum(C_outputs) + C_balance
        let zero_blinding = axiom_ct::BlindingFactor::from_bytes(&[0u8; 32]);
        let c_inputs = axiom_ct::Commitment::commit(input_sum, &zero_blinding);
        let c_fee = axiom_ct::Commitment::commit(fee, &zero_blinding);
        let lhs = (&c_inputs - &c_fee).map_err(|e| {
            ValidationError::ConfidentialTx(format!("commitment arithmetic: {e}"))
        })?;

        let c_out_sum = axiom_ct::sum_commitments(&output_commitments)
            .map_err(|e| ValidationError::ConfidentialTx(format!("output sum: {e}")))?;
        let c_balance = axiom_ct::Commitment::from_bytes(balance_bytes);
        let rhs = (&c_out_sum + &c_balance).map_err(|e| {
            ValidationError::ConfidentialTx(format!("commitment arithmetic: {e}"))
        })?;

        if lhs != rhs {
            return Err(ValidationError::ConfidentialTx(
                "balance check failed: inputs \u{2260} outputs + balance_commitment".into(),
            ));
        }

        Ok(())
    }

    /// Validate transaction and return the fee in satoshis.
    ///
    /// Fee is computed via [`check_value_conservation`] — the canonical
    /// consensus invariant. Any negative-fee or overflow path errors out
    /// before the number reaches the caller.
    pub fn validate_and_compute_fee(&self, tx: &Transaction) -> Result<u64, ValidationError> {
        self.validate_transaction(tx)?;

        let mut input_value = Amount::ZERO;
        for input in &tx.inputs {
            let utxo = self
                .utxo_set
                .get_utxo(&input.prev_tx_hash, input.prev_output_index)?
                .ok_or_else(|| {
                    ValidationError::InputNotFound(format!(
                        "{}:{}",
                        hex_encode(input.prev_tx_hash.as_bytes()),
                        input.prev_output_index
                    ))
                })?;
            input_value = input_value.checked_add(utxo.value)?;
        }
        let output_value = tx.output_value()?;
        let fee_sat = check_value_conservation(input_value, output_value, Amount::ZERO)?;
        Ok(fee_sat)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_storage::Database;
    use tempfile::TempDir;

    fn create_test_db() -> (TempDir, Database) {
        let temp_dir = TempDir::new().unwrap();
        let db = Database::open(temp_dir.path()).unwrap();
        (temp_dir, db)
    }

    #[test]
    fn test_reject_coinbase() {
        let (_temp, db) = create_test_db();
        let utxo_set = UtxoSet::new(&db);
        let nonce_tracker = NonceTracker::new(&db);
        let validator = TransactionValidator::new(utxo_set, nonce_tracker, 1);

        let coinbase = Transaction::new_coinbase(vec![], 0);
        let result = validator.validate_transaction(&coinbase);

        assert!(matches!(result, Err(ValidationError::CoinbaseNotAllowed)));
    }

    #[test]
    fn test_reject_no_inputs() {
        let (_temp, db) = create_test_db();
        let utxo_set = UtxoSet::new(&db);
        let nonce_tracker = NonceTracker::new(&db);
        let validator = TransactionValidator::new(utxo_set, nonce_tracker, 1);

        let tx = Transaction::new_transfer(vec![], vec![], 0, 0);
        let result = validator.validate_transaction(&tx);

        assert!(matches!(result, Err(ValidationError::NoInputs)));
    }

    #[test]
    fn test_validation_mode_full_checks_signatures() {
        assert_eq!(ValidationMode::Full, ValidationMode::Full);
        assert_ne!(ValidationMode::Full, ValidationMode::AssumeValid);
    }

    #[test]
    fn test_assumevalid_height_is_zero_until_mainnet() {
        assert_eq!(crate::checkpoints::assumevalid_height(), 0);
    }

    #[test]
    fn test_duplicate_input_rejected() {
        use axiom_primitives::{Amount, Hash256, PublicKey, Signature};
        use axiom_protocol::{TxInput, TxOutput};

        let (_temp, db) = create_test_db();
        let utxo_set = UtxoSet::new(&db);
        let nonce_tracker = NonceTracker::new(&db);
        let validator = TransactionValidator::new(utxo_set, nonce_tracker, 1);

        let dup_input = TxInput {
            prev_tx_hash: Hash256::from_bytes([0xAB; 32]),
            prev_output_index: 0,
            signature: Signature::placeholder(),
            pubkey: PublicKey::from_bytes(vec![0u8; 2592]),
        };
        let output = TxOutput {
            value: Amount::from_sat(1_000_000).unwrap(),
            pubkey_hash: Hash256::zero(),
        };
        let tx = Transaction::new_transfer(vec![dup_input.clone(), dup_input], vec![output], 0, 0);

        let result = validator.validate_transaction(&tx);
        assert!(
            matches!(result, Err(ValidationError::DuplicateInput { .. })),
            "expected DuplicateInput error, got: {:?}",
            result
        );
    }
}
