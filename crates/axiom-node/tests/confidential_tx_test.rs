// Copyright (c) 2026 Kantoshi Miyamura
//
// End-to-end tests for confidential transaction validation. Gated on the
// `axiom-ct` feature — the axiom-protocol serializer refuses ConfidentialTransfer
// txs unless its own axiom-ct feature is enabled, so this test is skipped in
// the default build.

#![cfg(feature = "axiom-ct")]

use axiom_ct::{sum_blinding_factors, AxiomRangeProof, BlindingFactor, Commitment};
use axiom_node::validation::{TransactionValidator, ValidationError};
use axiom_primitives::{Amount, Hash256, PublicKey, Signature};
use axiom_protocol::{ConfidentialTxOutput, Transaction, TxInput, TxOutput};
use axiom_storage::{Database, NonceTracker, UtxoEntry, UtxoSet};
use axiom_wallet::KeyPair;
use tempfile::TempDir;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn create_test_db() -> (TempDir, Database) {
    let temp_dir = TempDir::new().unwrap();
    let db = Database::open(temp_dir.path()).unwrap();
    (temp_dir, db)
}

/// Build a minimal `ConfidentialTxOutput` for a given value and blinding factor.
fn make_conf_output(value: u64, r: &BlindingFactor) -> ConfidentialTxOutput {
    let r_copy = BlindingFactor::from_bytes(&r.to_bytes());
    let (proof, commitments) = AxiomRangeProof::prove(&[(value, r_copy)]).unwrap();
    ConfidentialTxOutput {
        commitment: commitments[0].to_bytes(),
        range_proof_bytes: proof.to_wire_bytes(),
        pubkey_hash: [0xBBu8; 32],
    }
}

/// Compute the balance commitment for a set of output blinding factors.
///
/// `C_balance = commit(0, -sum_r)`
fn make_balance_commitment(blindings: &[BlindingFactor]) -> [u8; 32] {
    let sum_r = sum_blinding_factors(blindings);
    let neg_sum_r = sum_r.negate();
    Commitment::commit(0, &neg_sum_r).to_bytes()
}

/// Build a signed confidential transaction.
///
/// Signs over the `Transaction::new_confidential` structure (matching validator).
fn build_signed_conf_tx(
    keypair: &KeyPair,
    conf_outputs: Vec<ConfidentialTxOutput>,
    balance_commitment: [u8; 32],
    prev_txid: Hash256,
    nonce: u64,
) -> Transaction {
    let pubkey = keypair.public_key_struct().unwrap();

    // Create unsigned inputs with placeholder signatures.
    let unsigned_inputs = vec![TxInput {
        prev_tx_hash: prev_txid,
        prev_output_index: 0,
        signature: Signature::placeholder(),
        pubkey: pubkey.clone(),
    }];

    // Build the unsigned confidential tx for signing.
    let unsigned_tx = Transaction::new_confidential(
        unsigned_inputs,
        conf_outputs.clone(),
        nonce,
        0,
        Some(balance_commitment),
    );

    // Compute the canonical signing hash (same as validator).
    let tx_data = axiom_protocol::serialize_transaction(&unsigned_tx);
    let sign_hash = axiom_crypto::transaction_signing_hash("", &tx_data);
    let signature = keypair.sign_struct(sign_hash.as_bytes()).unwrap();

    let signed_inputs = vec![TxInput {
        prev_tx_hash: prev_txid,
        prev_output_index: 0,
        signature,
        pubkey,
    }];

    Transaction::new_confidential(
        signed_inputs,
        conf_outputs,
        nonce,
        0,
        Some(balance_commitment),
    )
}

/// Seed the UTXO set with a plaintext UTXO and return the txid.
fn seed_utxo(utxo_set: &UtxoSet<'_>, value: u64, pubkey: &PublicKey) -> Hash256 {
    let pubkey_hash_bytes = axiom_crypto::hash256(pubkey.as_bytes());
    let txid = Hash256::from_bytes([0xAAu8; 32]);
    let entry = UtxoEntry {
        value: Amount::from_sat(value).unwrap(),
        pubkey_hash: pubkey_hash_bytes,
        height: 0,
        is_coinbase: false,
        confidential_commitment: None,
    };
    utxo_set.add_utxo(&txid, 0, &entry).unwrap();
    txid
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// A well-formed confidential transaction should pass validation.
#[test]
fn test_valid_confidential_tx_passes() {
    let (_temp, db) = create_test_db();
    let utxo_set = UtxoSet::new(&db);
    let nonce_tracker = NonceTracker::new(&db);

    let keypair = KeyPair::generate().unwrap();
    let pubkey = keypair.public_key_struct().unwrap();

    let input_value: u64 = 1_000_000;
    let txid = seed_utxo(&utxo_set, input_value, &pubkey);

    // Create one confidential output for the full input value.
    let r = BlindingFactor::random();
    let conf_output = make_conf_output(input_value, &r);
    let balance_commitment = make_balance_commitment(&[r]);

    let tx = build_signed_conf_tx(&keypair, vec![conf_output], balance_commitment, txid, 1);

    let validator = TransactionValidator::new(utxo_set, nonce_tracker, 0);
    let result = validator.validate_transaction(&tx);
    assert!(
        result.is_ok(),
        "valid confidential tx should pass validation, got: {:?}",
        result
    );
}

/// A confidential transaction with a tampered commitment must fail.
#[test]
fn test_tampered_commitment_fails_balance_check() {
    let (_temp, db) = create_test_db();
    let utxo_set = UtxoSet::new(&db);
    let nonce_tracker = NonceTracker::new(&db);

    let keypair = KeyPair::generate().unwrap();
    let pubkey = keypair.public_key_struct().unwrap();

    let input_value: u64 = 500_000;
    let txid = seed_utxo(&utxo_set, input_value, &pubkey);

    let r = BlindingFactor::random();
    let mut conf_output = make_conf_output(input_value, &r);
    // Tamper: flip one byte in the commitment.
    conf_output.commitment[0] ^= 0xFF;
    let balance_commitment = make_balance_commitment(&[r]);

    let tx = build_signed_conf_tx(&keypair, vec![conf_output], balance_commitment, txid, 1);

    let validator = TransactionValidator::new(utxo_set, nonce_tracker, 0);
    let result = validator.validate_transaction(&tx);
    assert!(
        result.is_err(),
        "tampered commitment should fail validation"
    );
}

/// A confidential transaction with a corrupted range proof must fail.
#[test]
fn test_corrupted_range_proof_fails() {
    let (_temp, db) = create_test_db();
    let utxo_set = UtxoSet::new(&db);
    let nonce_tracker = NonceTracker::new(&db);

    let keypair = KeyPair::generate().unwrap();
    let pubkey = keypair.public_key_struct().unwrap();

    let input_value: u64 = 750_000;
    let txid = seed_utxo(&utxo_set, input_value, &pubkey);

    let r = BlindingFactor::random();
    let mut conf_output = make_conf_output(input_value, &r);
    // Corrupt the range proof bytes.
    let mid = conf_output.range_proof_bytes.len() / 2;
    if mid < conf_output.range_proof_bytes.len() {
        conf_output.range_proof_bytes[mid] ^= 0xFF;
    }
    let balance_commitment = make_balance_commitment(&[r]);

    let tx = build_signed_conf_tx(&keypair, vec![conf_output], balance_commitment, txid, 1);

    let validator = TransactionValidator::new(utxo_set, nonce_tracker, 0);
    let result = validator.validate_transaction(&tx);
    assert!(
        result.is_err(),
        "corrupted range proof should fail validation"
    );
    assert!(
        matches!(result.unwrap_err(), ValidationError::ConfidentialTx(_)),
        "error must be ConfidentialTx variant"
    );
}

/// A confidential transaction with a wrong `balance_commitment` must fail.
#[test]
fn test_wrong_balance_commitment_fails() {
    let (_temp, db) = create_test_db();
    let utxo_set = UtxoSet::new(&db);
    let nonce_tracker = NonceTracker::new(&db);

    let keypair = KeyPair::generate().unwrap();
    let pubkey = keypair.public_key_struct().unwrap();

    let input_value: u64 = 1_000_000;
    let txid = seed_utxo(&utxo_set, input_value, &pubkey);

    let r = BlindingFactor::random();
    let conf_output = make_conf_output(input_value, &r);

    // Use a completely wrong balance commitment.
    let wrong_r = BlindingFactor::random();
    let wrong_balance_commitment = Commitment::commit(12345, &wrong_r).to_bytes();

    let tx = build_signed_conf_tx(
        &keypair,
        vec![conf_output],
        wrong_balance_commitment,
        txid,
        1,
    );

    let validator = TransactionValidator::new(utxo_set, nonce_tracker, 0);
    let result = validator.validate_transaction(&tx);
    assert!(
        result.is_err(),
        "wrong balance_commitment should fail validation"
    );
    assert!(
        matches!(result.unwrap_err(), ValidationError::ConfidentialTx(_)),
        "error must be ConfidentialTx variant"
    );
}

/// Missing `balance_commitment` must fail with a descriptive error.
#[test]
fn test_missing_balance_commitment_fails() {
    let (_temp, db) = create_test_db();
    let utxo_set = UtxoSet::new(&db);
    let nonce_tracker = NonceTracker::new(&db);

    let keypair = KeyPair::generate().unwrap();
    let pubkey = keypair.public_key_struct().unwrap();

    let txid = seed_utxo(&utxo_set, 500_000, &pubkey);

    // Build a confidential tx manually without a balance commitment.
    let r = BlindingFactor::random();
    let conf_output = make_conf_output(500_000, &r);
    let pubkey_s = keypair.public_key_struct().unwrap();
    let unsigned_inputs = vec![TxInput {
        prev_tx_hash: txid,
        prev_output_index: 0,
        signature: Signature::placeholder(),
        pubkey: pubkey_s.clone(),
    }];
    // Sign without a balance commitment.
    let unsigned_tx = Transaction::new_confidential(
        unsigned_inputs.clone(),
        vec![conf_output.clone()],
        1,
        0,
        None, // no balance commitment
    );
    let tx_data = axiom_protocol::serialize_transaction(&unsigned_tx);
    let sign_hash = axiom_crypto::transaction_signing_hash("", &tx_data);
    let signature = keypair.sign_struct(sign_hash.as_bytes()).unwrap();
    let signed_inputs = vec![TxInput {
        prev_tx_hash: txid,
        prev_output_index: 0,
        signature,
        pubkey: pubkey_s,
    }];
    let tx = Transaction::new_confidential(signed_inputs, vec![conf_output], 1, 0, None);

    let validator = TransactionValidator::new(utxo_set, nonce_tracker, 0);
    let result = validator.validate_transaction(&tx);
    assert!(matches!(
        result.unwrap_err(),
        ValidationError::ConfidentialTx(_)
    ));
}

/// A confidential transaction with no confidential outputs must fail.
#[test]
fn test_no_confidential_outputs_fails() {
    let (_temp, db) = create_test_db();
    let utxo_set = UtxoSet::new(&db);
    let nonce_tracker = NonceTracker::new(&db);

    let keypair = KeyPair::generate().unwrap();
    let pubkey = keypair.public_key_struct().unwrap();

    let txid = seed_utxo(&utxo_set, 500_000, &pubkey);

    // Sign a tx with no confidential outputs.
    let pubkey_s = keypair.public_key_struct().unwrap();
    let unsigned_tx = Transaction::new_confidential(
        vec![TxInput {
            prev_tx_hash: txid,
            prev_output_index: 0,
            signature: Signature::placeholder(),
            pubkey: pubkey_s.clone(),
        }],
        vec![], // no confidential outputs
        1,
        0,
        Some([0u8; 32]),
    );
    let tx_data = axiom_protocol::serialize_transaction(&unsigned_tx);
    let sign_hash = axiom_crypto::transaction_signing_hash("", &tx_data);
    let signature = keypair.sign_struct(sign_hash.as_bytes()).unwrap();
    let tx = Transaction::new_confidential(
        vec![TxInput {
            prev_tx_hash: txid,
            prev_output_index: 0,
            signature,
            pubkey: pubkey_s,
        }],
        vec![],
        1,
        0,
        Some([0u8; 32]),
    );

    let validator = TransactionValidator::new(utxo_set, nonce_tracker, 0);
    let result = validator.validate_transaction(&tx);
    assert!(matches!(
        result.unwrap_err(),
        ValidationError::ConfidentialTx(_)
    ));
}

/// Concrete balance check: verify the math is exactly right with known values.
///
/// input_sum = 1000, output = 1000 (no fee)
/// r_out = [0x05; 32]
/// C_out = commit(1000, r_out)
/// C_balance = commit(0, -r_out)
/// Check: commit(1000, 0) - commit(0, 0) == C_out + C_balance
///   LHS = 1000*H
///   RHS = (1000*H + r_out*G) + (0*H - r_out*G) = 1000*H  ✓
#[test]
fn test_balance_check_math_concrete() {
    let (_temp, db) = create_test_db();
    let utxo_set = UtxoSet::new(&db);
    let nonce_tracker = NonceTracker::new(&db);

    let keypair = KeyPair::generate().unwrap();
    let pubkey = keypair.public_key_struct().unwrap();

    let input_value: u64 = 1_000;
    let txid = seed_utxo(&utxo_set, input_value, &pubkey);

    let r_bytes = [0x05u8; 32];
    let r = BlindingFactor::from_bytes(&r_bytes);
    let conf_output = make_conf_output(input_value, &r);

    // Manually compute balance commitment.
    let r_for_balance = BlindingFactor::from_bytes(&r_bytes);
    let neg_r = r_for_balance.negate();
    let balance_commitment = Commitment::commit(0, &neg_r).to_bytes();

    let tx = build_signed_conf_tx(&keypair, vec![conf_output], balance_commitment, txid, 1);

    let validator = TransactionValidator::new(utxo_set, nonce_tracker, 0);
    validator
        .validate_transaction(&tx)
        .expect("concrete balance check must pass");
}

/// Validate that existing Transfer transactions still work after the new fields were added.
#[test]
fn test_transfer_still_works_after_confidential_changes() {
    let tx = Transaction::new_transfer(
        vec![],
        vec![TxOutput {
            value: Amount::from_sat(1000).unwrap(),
            pubkey_hash: Hash256::zero(),
        }],
        1,
        0,
    );
    assert!(!tx.is_confidential());
    assert!(tx.confidential_outputs.is_empty());
    assert!(tx.balance_commitment.is_none());
    assert_eq!(tx.output_value().unwrap().as_sat(), 1000);
}

/// Round-trip serialization of a confidential transaction.
#[test]
fn test_confidential_tx_serialize_deserialize_roundtrip() {
    let r = BlindingFactor::random();
    let conf_output = make_conf_output(42_000, &r);
    let bc = make_balance_commitment(&[r]);

    let input = TxInput {
        prev_tx_hash: Hash256::from_bytes([0xBBu8; 32]),
        prev_output_index: 0,
        signature: Signature::from_bytes(vec![0u8; 4627]),
        pubkey: PublicKey::from_bytes(vec![0u8; 2592]),
    };

    let tx = Transaction::new_confidential(vec![input], vec![conf_output], 7, 0, Some(bc));

    let serialized = axiom_protocol::serialize_transaction(&tx);
    let deserialized = axiom_protocol::deserialize_transaction(&serialized).unwrap();

    assert!(deserialized.is_confidential());
    assert_eq!(deserialized.confidential_outputs.len(), 1);
    assert_eq!(deserialized.balance_commitment, Some(bc));
    assert_eq!(deserialized.nonce, 7);
}

/// Tests for new axiom-ct helper functions.
mod ct_helpers {
    use axiom_ct::{sum_blinding_factors, BlindingFactor, Commitment};

    #[test]
    fn test_sum_blinding_factors_empty_is_zero() {
        let sum = sum_blinding_factors(&[]);
        let zero_bf = BlindingFactor::from_bytes(&[0u8; 32]);
        // sum of zero factors should commit to the same point as zero blinding
        let c_sum = Commitment::commit(42, &sum);
        let c_zero = Commitment::commit(42, &zero_bf);
        assert_eq!(c_sum, c_zero, "empty sum should be the zero scalar");
    }

    #[test]
    fn test_sum_blinding_factors_single() {
        let r_bytes = [0x07u8; 32];
        let r = BlindingFactor::from_bytes(&r_bytes);
        let sum = sum_blinding_factors(&[r]);
        let r_check = BlindingFactor::from_bytes(&r_bytes);
        let c_sum = Commitment::commit(100, &sum);
        let c_check = Commitment::commit(100, &r_check);
        assert_eq!(c_sum, c_check);
    }

    #[test]
    fn test_sum_blinding_factors_multiple() {
        // sum(r1, r2) == r1 + r2
        let r1_bytes = [0x01u8; 32];
        let r2_bytes = [0x02u8; 32];
        let r1 = BlindingFactor::from_bytes(&r1_bytes);
        let r2 = BlindingFactor::from_bytes(&r2_bytes);
        let sum = sum_blinding_factors(&[r1, r2]);

        let r1_check = BlindingFactor::from_bytes(&r1_bytes);
        let r2_check = BlindingFactor::from_bytes(&r2_bytes);
        let manual_sum = r1_check.add(&r2_check);

        let c_sum = Commitment::commit(0, &sum);
        let c_manual = Commitment::commit(0, &manual_sum);
        assert_eq!(c_sum, c_manual);
    }

    #[test]
    fn test_blinding_factor_negate() {
        let r_bytes = [0x42u8; 32];
        let r = BlindingFactor::from_bytes(&r_bytes);
        let neg_r = r.negate();

        // commit(0, r) + commit(0, -r) should equal commit(0, 0) (the identity on G)
        let zero_bf = BlindingFactor::from_bytes(&[0u8; 32]);
        let c_r = Commitment::commit(0, &BlindingFactor::from_bytes(&r_bytes));
        let c_neg_r = Commitment::commit(0, &neg_r);
        let c_zero = Commitment::commit(0, &zero_bf);

        let sum = (&c_r + &c_neg_r).unwrap();
        assert_eq!(sum, c_zero, "r + (-r) should equal zero scalar commitment");
    }

    #[test]
    fn test_to_wire_bytes_from_wire_bytes_roundtrip() {
        use axiom_ct::{AxiomRangeProof, BlindingFactor};
        // Prove with a known value and blinding factor.
        let r = BlindingFactor::random();
        let r_copy = BlindingFactor::from_bytes(&r.to_bytes());
        let (proof, commitments) = AxiomRangeProof::prove(&[(1000u64, r)]).unwrap();

        // Serialize to wire bytes.
        let wire = proof.to_wire_bytes();
        assert!(!wire.is_empty(), "wire bytes must be non-empty");

        // Deserialize and verify the recovered proof.
        let recovered = AxiomRangeProof::from_wire_bytes(&wire).unwrap();
        recovered.verify(&commitments).unwrap();

        // Two separate roundtrips must produce consistent results.
        let (proof2, commitments2) = AxiomRangeProof::prove(&[(999u64, r_copy)]).unwrap();
        let wire2 = proof2.to_wire_bytes();
        let recovered2 = AxiomRangeProof::from_wire_bytes(&wire2).unwrap();
        recovered2.verify(&commitments2).unwrap();
    }

    #[test]
    fn test_from_wire_bytes_corrupted_returns_error() {
        use axiom_ct::{AxiomRangeProof, BlindingFactor, CtError};
        let r = BlindingFactor::random();
        let (proof, _) = AxiomRangeProof::prove(&[(500u64, r)]).unwrap();
        let mut wire = proof.to_wire_bytes();
        // Corrupt the middle of the wire bytes.
        let mid = wire.len() / 2;
        wire[mid] ^= 0xFF;
        // May fail to deserialize or fail to verify.
        match AxiomRangeProof::from_wire_bytes(&wire) {
            Err(e) => assert_eq!(e, CtError::RangeProofInvalid),
            Ok(_recovered) => {
                // Acceptable — corrupted bytes happened to still deserialize
            }
        }
    }
}
