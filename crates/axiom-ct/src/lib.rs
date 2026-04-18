// Copyright (c) 2026 Kantoshi Miyamura

//! Confidential transactions for Axiom Network.
//!
//! Implements amount-hiding using **Pedersen commitments** over Ristretto255
//! and **Bulletproof range proofs** to enforce non-negativity without
//! revealing the committed value.
//!
//! ## How a confidential transaction works
//!
//! ```text
//! Sender knows:  value_in  (UTXO), blinding_in  (from original commitment)
//! Sender picks:  value_out, blinding_out (random)
//! Sender computes:
//!   C_in  = value_in  · H + blinding_in  · G
//!   C_out = value_out · H + blinding_out · G
//!   C_fee = fee       · H + blinding_fee · G      (where blinding_fee = blinding_in - blinding_out)
//!
//! Balance check (verifiable by anyone):
//!   C_in == C_out + C_fee
//!   ↔  (value_in · H + r_in · G) == (value_out · H + r_out · G) + (fee · H + r_fee · G)
//!   ↔  value_in == value_out + fee   AND   r_in == r_out + r_fee
//!
//! Range proofs ensure: value_out ≥ 0 and fee ≥ 0
//! Together this proves: value_in ≥ value_out + fee ≥ 0
//! ```
//!
//! ## Crate layout
//!
//! - [`commitment`] — Pedersen commitments, homomorphic addition/subtraction, balance check
//! - [`range_proof`] — Bulletproof range proofs (single and batched)
//! - [`output`]     — `ConfidentialOutput` and `ConfidentialOutputBatch`
//! - [`error`]      — error types

pub mod commitment;
pub mod error;
pub mod output;
pub mod range_proof;

pub use commitment::{
    sum_blinding_factors, sum_commitments, verify_balance, BlindingFactor, Commitment,
    generator_g, generator_h,
};
pub use error::{CtError, Result};
pub use output::{ConfidentialOutput, ConfidentialOutputBatch};
pub use range_proof::{AxiomRangeProof, MAX_OUTPUTS};

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::traits::Identity;

    // ── Commitment tests ──────────────────────────────────────────────────────

    #[test]
    fn test_commitment_roundtrip() {
        let r = BlindingFactor::random();
        let c = Commitment::commit(42u64, &r);
        // Should decompress without error
        let point = c.to_point().expect("decompress must succeed");
        // Re-compress and compare bytes
        let c2 = Commitment::from_bytes(point.compress().to_bytes());
        assert_eq!(c, c2);
    }

    #[test]
    fn test_commitment_to_bytes_from_bytes_roundtrip() {
        let r = BlindingFactor::random();
        let c = Commitment::commit(999u64, &r);
        let bytes = c.to_bytes();
        let c2 = Commitment::from_bytes(bytes);
        assert_eq!(c, c2);
    }

    #[test]
    fn test_commitment_is_deterministic() {
        // Same value + same blinding → same commitment
        let r_bytes = [7u8; 32];
        let r1 = BlindingFactor::from_bytes(&r_bytes);
        let r2 = BlindingFactor::from_bytes(&r_bytes);
        let c1 = Commitment::commit(100u64, &r1);
        let c2 = Commitment::commit(100u64, &r2);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_commitment_different_values_differ() {
        let r_bytes = [3u8; 32];
        let r = BlindingFactor::from_bytes(&r_bytes);
        let c1 = Commitment::commit(1u64, &r);
        let c2 = Commitment::commit(2u64, &r);
        assert_ne!(c1, c2);
    }

    // ── Homomorphic addition test ─────────────────────────────────────────────

    #[test]
    fn test_homomorphic_addition() {
        // commit(3, r1) + commit(4, r2) == commit(7, r1+r2)
        let r1_bytes = [11u8; 32];
        let r2_bytes = [22u8; 32];
        let r1 = BlindingFactor::from_bytes(&r1_bytes);
        let r2 = BlindingFactor::from_bytes(&r2_bytes);

        let c3 = Commitment::commit(3u64, &r1);
        let c4 = Commitment::commit(4u64, &r2);
        let c_sum = (&c3 + &c4).expect("homomorphic add");

        // r1 + r2 as scalars
        let r_sum_scalar = r1.inner() + r2.inner();
        let r_sum = BlindingFactor(r_sum_scalar);
        let c7 = Commitment::commit(7u64, &r_sum);

        assert_eq!(c_sum, c7, "commit(3,r1) + commit(4,r2) must equal commit(7, r1+r2)");
    }

    #[test]
    fn test_homomorphic_subtraction() {
        // commit(10, r1) - commit(3, r2) == commit(7, r1-r2)
        let r1_bytes = [55u8; 32];
        let r2_bytes = [33u8; 32];
        let r1 = BlindingFactor::from_bytes(&r1_bytes);
        let r2 = BlindingFactor::from_bytes(&r2_bytes);

        let c10 = Commitment::commit(10u64, &r1);
        let c3  = Commitment::commit(3u64,  &r2);
        let c_diff = (&c10 - &c3).expect("homomorphic sub");

        let r_diff_scalar = r1.inner() - r2.inner();
        let r_diff = BlindingFactor(r_diff_scalar);
        let c7 = Commitment::commit(7u64, &r_diff);

        assert_eq!(c_diff, c7);
    }

    // ── Balance check tests ───────────────────────────────────────────────────

    #[test]
    fn test_balance_check_passes_for_valid_tx() {
        // value_in = 100, value_out = 95, fee = 5
        // r_in = r_out + r_fee  ← we set r_fee = r_in - r_out
        let r_in_bytes  = [0xAAu8; 32];
        let r_out_bytes = [0x55u8; 32];
        let r_in  = BlindingFactor::from_bytes(&r_in_bytes);
        let r_out = BlindingFactor::from_bytes(&r_out_bytes);

        let r_fee_scalar = r_in.inner() - r_out.inner();
        let r_fee = BlindingFactor(r_fee_scalar);

        let c_in  = Commitment::commit(100u64, &r_in);
        let c_out = Commitment::commit(95u64,  &r_out);
        let c_fee = Commitment::commit(5u64,   &r_fee);

        verify_balance(&[c_in], &[c_out], &c_fee).expect("balance check must pass");
    }

    #[test]
    fn test_balance_check_fails_when_amounts_dont_balance() {
        let r_in  = BlindingFactor::random();
        let r_out = BlindingFactor::random();
        let r_fee = BlindingFactor::random(); // wrong blinding — won't balance

        let c_in  = Commitment::commit(100u64, &r_in);
        let c_out = Commitment::commit(90u64,  &r_out); // 90 + 5 ≠ 100
        let c_fee = Commitment::commit(5u64,   &r_fee);

        let result = verify_balance(&[c_in], &[c_out], &c_fee);
        assert_eq!(result.unwrap_err(), CtError::BalanceCheckFailed);
    }

    #[test]
    fn test_balance_check_multiple_inputs_outputs() {
        // Two inputs totalling 200, two outputs totalling 190, fee 10
        let r_in1 = BlindingFactor::from_bytes(&[0x01u8; 32]);
        let r_in2 = BlindingFactor::from_bytes(&[0x02u8; 32]);
        let r_out1 = BlindingFactor::from_bytes(&[0x10u8; 32]);
        let r_out2 = BlindingFactor::from_bytes(&[0x20u8; 32]);

        // r_fee = (r_in1 + r_in2) - (r_out1 + r_out2)
        let r_fee_scalar = (r_in1.inner() + r_in2.inner()) - (r_out1.inner() + r_out2.inner());
        let r_fee = BlindingFactor(r_fee_scalar);

        let c_in1  = Commitment::commit(120u64, &r_in1);
        let c_in2  = Commitment::commit(80u64,  &r_in2);
        let c_out1 = Commitment::commit(100u64, &r_out1);
        let c_out2 = Commitment::commit(90u64,  &r_out2);
        let c_fee  = Commitment::commit(10u64,  &r_fee);

        verify_balance(&[c_in1, c_in2], &[c_out1, c_out2], &c_fee)
            .expect("multi-input/output balance check must pass");
    }

    // ── Range proof tests ─────────────────────────────────────────────────────

    #[test]
    fn test_range_proof_single_output_prove_and_verify() {
        let r = BlindingFactor::random();
        let value = 1_000_000u64;
        let (proof, commitments) = AxiomRangeProof::prove(&[(value, r)])
            .expect("prove must succeed");

        assert_eq!(commitments.len(), 1);
        assert!(proof.byte_len() > 0);
        proof.verify(&commitments).expect("verify must succeed");
    }

    #[test]
    fn test_range_proof_zero_value() {
        let r = BlindingFactor::random();
        let (proof, commitments) = AxiomRangeProof::prove(&[(0u64, r)])
            .expect("zero value is valid");
        proof.verify(&commitments).expect("verify zero value");
    }

    #[test]
    fn test_range_proof_max_u64() {
        let r = BlindingFactor::random();
        let (proof, commitments) = AxiomRangeProof::prove(&[(u64::MAX, r)])
            .expect("max u64 is valid");
        proof.verify(&commitments).expect("verify max u64");
    }

    #[test]
    fn test_range_proof_batch_two_outputs() {
        let r1 = BlindingFactor::random();
        let r2 = BlindingFactor::random();
        let outputs = [(500u64, r1), (300u64, r2)];

        let (proof, commitments) = AxiomRangeProof::prove(&outputs)
            .expect("batch prove must succeed");

        assert_eq!(commitments.len(), 2);
        proof.verify(&commitments).expect("batch verify must succeed");
    }

    #[test]
    fn test_range_proof_batch_four_outputs() {
        let outputs: Vec<(u64, BlindingFactor)> = (0..4)
            .map(|i| (i as u64 * 1000, BlindingFactor::random()))
            .collect();

        let (proof, commitments) = AxiomRangeProof::prove(&outputs)
            .expect("4-output batch prove");
        proof.verify(&commitments).expect("4-output batch verify");
    }

    #[test]
    fn test_range_proof_empty_outputs_returns_error() {
        let result = AxiomRangeProof::prove(&[]);
        assert_eq!(result.unwrap_err(), CtError::EmptyOutputs);
    }

    #[test]
    fn test_range_proof_too_many_outputs_returns_error() {
        let outputs: Vec<(u64, BlindingFactor)> = (0..MAX_OUTPUTS + 1)
            .map(|_| (1u64, BlindingFactor::random()))
            .collect();
        let result = AxiomRangeProof::prove(&outputs);
        assert!(matches!(
            result.unwrap_err(),
            CtError::TooManyOutputs { .. }
        ));
    }

    #[test]
    fn test_corrupted_proof_fails_verification() {
        let r = BlindingFactor::random();
        let (proof, commitments) = AxiomRangeProof::prove(&[(42u64, r)])
            .expect("prove");

        // Corrupt the proof by flipping bytes inside the struct.
        // We access via serialization round-trip.
        let mut proof_bytes = bincode_serialize(&proof);
        // Flip a byte in the middle of the serialized proof
        let mid = proof_bytes.len() / 2;
        proof_bytes[mid] ^= 0xFF;
        // If deserialization fails that's also "corrupted proof" behavior;
        // if it succeeds, verify must fail.
        if let Ok(corrupted) = bincode_deserialize::<AxiomRangeProof>(&proof_bytes) {
            let result = corrupted.verify(&commitments);
            assert!(result.is_err(), "corrupted proof must not verify");
        }
        // Either path is acceptable (corrupt bytes may fail to deserialize).

        // More reliable: mutate the proof object directly via wrong commitments.
        let r2 = BlindingFactor::random();
        let wrong_commitment = Commitment::commit(999u64, &r2);
        let result = proof.verify(&[wrong_commitment]);
        assert_eq!(result.unwrap_err(), CtError::RangeProofInvalid);
    }

    // helper to do a simple serialize/deserialize for the corruption test
    fn bincode_serialize<T: serde::Serialize>(v: &T) -> Vec<u8> {
        // Use a simple approach: serialize to JSON bytes for mutation test
        serde_json::to_vec(v).unwrap_or_default()
    }

    fn bincode_deserialize<T: serde::de::DeserializeOwned>(b: &[u8]) -> std::result::Result<T, ()> {
        serde_json::from_slice(b).map_err(|_| ())
    }

    // ── ConfidentialOutput tests ──────────────────────────────────────────────

    #[test]
    fn test_confidential_output_create_and_verify() {
        let pubkey_hash = [0xBEu8; 32];
        let (output, _blinding) = ConfidentialOutput::create(50_000u64, pubkey_hash)
            .expect("create must succeed");

        assert_eq!(output.pubkey_hash, pubkey_hash);
        output.verify().expect("verify must succeed");
    }

    #[test]
    fn test_confidential_output_zero_value() {
        let pubkey_hash = [0x01u8; 32];
        let (output, _) = ConfidentialOutput::create(0u64, pubkey_hash)
            .expect("zero value output");
        output.verify().expect("verify zero value output");
    }

    #[test]
    fn test_confidential_output_commitment_matches_blinding() {
        // The commitment returned in the output must match manually computing
        // commit(value, blinding).
        let pubkey_hash = [0xFFu8; 32];
        let (output, blinding) = ConfidentialOutput::create(12345u64, pubkey_hash)
            .expect("create");

        let manual_commitment = Commitment::commit(12345u64, &blinding);
        assert_eq!(
            output.commitment, manual_commitment,
            "commitment in output must match manual commit(value, blinding)"
        );
    }

    // ── ConfidentialOutputBatch tests ─────────────────────────────────────────

    #[test]
    fn test_confidential_output_batch_create_and_verify() {
        let outputs = [
            (10_000u64, [0x01u8; 32]),
            (20_000u64, [0x02u8; 32]),
        ];
        let (batch, blindings) = ConfidentialOutputBatch::create(&outputs)
            .expect("batch create must succeed");

        assert_eq!(batch.commitments.len(), 2);
        assert_eq!(batch.pubkey_hashes.len(), 2);
        assert_eq!(blindings.len(), 2);
        batch.verify().expect("batch verify must succeed");
    }

    #[test]
    fn test_confidential_output_batch_single_output() {
        let outputs = [(99_999u64, [0xABu8; 32])];
        let (batch, _) = ConfidentialOutputBatch::create(&outputs)
            .expect("single-output batch");
        batch.verify().expect("verify single-output batch");
    }

    #[test]
    fn test_confidential_output_batch_empty_returns_error() {
        let result = ConfidentialOutputBatch::create(&[]);
        assert_eq!(result.unwrap_err(), CtError::EmptyOutputs);
    }

    #[test]
    fn test_confidential_output_batch_four_outputs() {
        let outputs: Vec<(u64, [u8; 32])> = (0..4u64)
            .map(|i| (i * 1000 + 1, [(i as u8).wrapping_add(1); 32]))
            .collect();
        let (batch, _) = ConfidentialOutputBatch::create(&outputs)
            .expect("4-output batch");
        batch.verify().expect("verify 4-output batch");
    }

    // ── sum_commitments edge cases ────────────────────────────────────────────

    #[test]
    fn test_sum_commitments_empty_is_identity() {
        let result = sum_commitments(&[]).expect("empty sum");
        // Identity point compresses to all zeros
        let identity_bytes = RistrettoPoint::identity().compress().to_bytes();
        assert_eq!(result.to_bytes(), identity_bytes);
    }

    #[test]
    fn test_sum_commitments_single() {
        let r = BlindingFactor::random();
        let c = Commitment::commit(77u64, &r);
        let sum = sum_commitments(&[c.clone()]).expect("single sum");
        assert_eq!(sum, c);
    }
}
