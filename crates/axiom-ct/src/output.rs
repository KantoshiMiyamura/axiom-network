// Copyright (c) 2026 Kantoshi Miyamura

//! Confidential transaction output.
//!
//! A `ConfidentialOutput` replaces the plaintext `(value, pubkey_hash)` pair
//! of a standard output with:
//!
//! - A **Pedersen commitment** to the value (hides the amount).
//! - A **range proof** proving the committed value is non-negative.
//! - The **recipient's public key hash** (the destination is still visible —
//!   for stealth addresses, combine with a one-time key protocol).
//! - An **encrypted amount** (value XOR-encrypted under the recipient's key
//!   so they can recover it; not yet implemented — field reserved for v2).

use crate::commitment::{BlindingFactor, Commitment};
use crate::error::{CtError, Result};
use crate::range_proof::AxiomRangeProof;
use serde::{Deserialize, Serialize};

/// A single confidential output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialOutput {
    /// Pedersen commitment `C = v·H + r·G`.  Hides the amount.
    pub commitment: Commitment,
    /// Bulletproof range proof: commitment is to a value in [0, 2^64).
    pub range_proof: AxiomRangeProof,
    /// Recipient — still public (use stealth addresses to hide).
    pub pubkey_hash: [u8; 32],
}

impl ConfidentialOutput {
    /// Create a confidential output committing to `value` satoshis.
    ///
    /// Returns the output and the blinding factor the sender must keep to
    /// construct the balancing commitment for the transaction.
    pub fn create(value: u64, pubkey_hash: [u8; 32]) -> Result<(Self, BlindingFactor)> {
        let r = BlindingFactor::random();
        let (proof, commitments) = AxiomRangeProof::prove(&[(value, BlindingFactor::from_bytes(&r.to_bytes()))])?;
        let commitment = commitments.into_iter().next().unwrap();

        Ok((
            ConfidentialOutput { commitment, range_proof: proof, pubkey_hash },
            r,
        ))
    }

    /// Verify the range proof for this output.
    pub fn verify(&self) -> Result<()> {
        self.range_proof.verify(std::slice::from_ref(&self.commitment))
    }
}

/// A batch of confidential outputs sharing a single aggregated range proof.
///
/// Batching is more efficient: one proof covering N outputs is smaller and
/// faster to verify than N individual proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialOutputBatch {
    /// One commitment per output.
    pub commitments: Vec<Commitment>,
    /// Single range proof covering all outputs.
    pub range_proof: AxiomRangeProof,
    /// One recipient per output.
    pub pubkey_hashes: Vec<[u8; 32]>,
}

impl ConfidentialOutputBatch {
    /// Create a batch of confidential outputs with one shared range proof.
    ///
    /// Returns the batch and the blinding factors in the same order as `outputs`.
    /// The caller must sum the blinding factors (with negation for inputs) to
    /// construct the balance commitment.
    pub fn create(outputs: &[(u64, [u8; 32])]) -> Result<(Self, Vec<BlindingFactor>)> {
        if outputs.is_empty() {
            return Err(CtError::EmptyOutputs);
        }

        let blindings: Vec<BlindingFactor> = (0..outputs.len())
            .map(|_| BlindingFactor::random())
            .collect();

        let prove_inputs: Vec<(u64, BlindingFactor)> = outputs
            .iter()
            .zip(blindings.iter())
            .map(|((v, _), r)| (*v, BlindingFactor::from_bytes(&r.to_bytes())))
            .collect();

        let (range_proof, commitments) = AxiomRangeProof::prove(&prove_inputs)?;

        let pubkey_hashes: Vec<[u8; 32]> = outputs.iter().map(|(_, ph)| *ph).collect();

        Ok((
            ConfidentialOutputBatch { commitments, range_proof, pubkey_hashes },
            blindings,
        ))
    }

    /// Verify all range proofs in this batch.
    pub fn verify(&self) -> Result<()> {
        self.range_proof.verify(&self.commitments)
    }
}
