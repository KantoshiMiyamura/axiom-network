// Copyright (c) 2026 Kantoshi Miyamura
//
// Guardian scoring model.
//
// INVARIANT: scoring is bit-identical across platforms. Every field used in
// the score is an integer; all arithmetic is i128-wide. No floats, no
// transcendentals, no platform-dependent intrinsics. Two nodes with the same
// `GuardianModel` and the same `FeatureVector` compute the same score.
//
// REPRODUCIBILITY: the model is content-addressed by `commitment`. If any
// weight or the bias changes, the commitment changes, and GuardianProofs
// produced under different models are distinguishable.
//
// NUMERIC CONVENTIONS:
//   - Features are bounded integers in `[0, FEATURE_MAX]`. The mapping from
//     raw observations to features is the responsibility of the agent — the
//     model itself is pure arithmetic.
//   - Weights are signed i64. Sum-of-abs-weights MUST fit in i64 (enforced at
//     construction) so dot products never overflow i128.
//   - Final score is clamped to `[0, SCORE_MAX]` (basis points × 100).

use axiom_primitives::Hash256;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use thiserror::Error;

pub const FEATURE_MAX: i64 = 10_000;        // inclusive upper bound per feature
pub const SCORE_MAX: i64 = 1_000_000;       // max anomaly score (basis points × 100)

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("weight magnitude exceeds safe i64 bound")]
    WeightOverflow,
}

/// Integer feature vector derived from a `GuardianObservation`.
///
/// Each component is expected to sit in `[0, FEATURE_MAX]`. The agent caps
/// values before passing them in; the model does NOT silently rescale because
/// doing so would let observational noise leak into the score in
/// non-obvious ways.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureVector {
    pub mempool_pressure: i64,
    pub block_size_anomaly: i64,
    pub fee_anomaly: i64,
    pub peer_instability: i64,
    pub timestamp_skew: i64,
}

impl FeatureVector {
    pub fn zero() -> Self {
        FeatureVector {
            mempool_pressure: 0,
            block_size_anomaly: 0,
            fee_anomaly: 0,
            peer_instability: 0,
            timestamp_skew: 0,
        }
    }

    /// Clamp every component to `[0, FEATURE_MAX]`. Called by the agent
    /// before scoring — the model itself assumes inputs are in-range.
    pub fn clamp(mut self) -> Self {
        self.mempool_pressure = self.mempool_pressure.clamp(0, FEATURE_MAX);
        self.block_size_anomaly = self.block_size_anomaly.clamp(0, FEATURE_MAX);
        self.fee_anomaly = self.fee_anomaly.clamp(0, FEATURE_MAX);
        self.peer_instability = self.peer_instability.clamp(0, FEATURE_MAX);
        self.timestamp_skew = self.timestamp_skew.clamp(0, FEATURE_MAX);
        self
    }
}

/// Signed integer weights. Positive weights push the anomaly score up;
/// negative weights pull it down. The bias is applied before scaling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnomalyWeights {
    pub w_mempool_pressure: i64,
    pub w_block_size_anomaly: i64,
    pub w_fee_anomaly: i64,
    pub w_peer_instability: i64,
    pub w_timestamp_skew: i64,
    pub bias: i64,
}

impl AnomalyWeights {
    /// Default weights tuned so that "obviously anomalous" inputs
    /// (several features near `FEATURE_MAX`) produce a score above half of
    /// `SCORE_MAX`, and "obviously normal" inputs (all zeros) produce 0.
    pub fn default_weights() -> Self {
        AnomalyWeights {
            w_mempool_pressure: 25,
            w_block_size_anomaly: 20,
            w_fee_anomaly: 20,
            w_peer_instability: 20,
            w_timestamp_skew: 15,
            bias: 0,
        }
    }

    /// Verify that the sum of absolute weights is small enough that the
    /// dot product `sum(|w_i| * FEATURE_MAX)` fits in i64 — gives a
    /// generous safety margin below i128 overflow in `score()`.
    fn validate(&self) -> Result<(), ModelError> {
        let mags = [
            self.w_mempool_pressure,
            self.w_block_size_anomaly,
            self.w_fee_anomaly,
            self.w_peer_instability,
            self.w_timestamp_skew,
            self.bias,
        ];
        let mut acc: i128 = 0;
        for m in mags {
            acc += (m as i128).abs();
        }
        // Generous: allow the total magnitude up to 1<<30 so that
        // total * FEATURE_MAX (~1e4) is still well inside i64.
        if acc > (1 << 30) { return Err(ModelError::WeightOverflow); }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianModel {
    pub weights: AnomalyWeights,
    /// Content commitment over the weights. Populated by `GuardianModel::new`.
    pub commitment: [u8; 32],
    /// Version label embedded in the commitment so two deployments with
    /// structurally identical weights but different intent are still
    /// distinguishable.
    pub version: u32,
}

impl GuardianModel {
    pub fn new(weights: AnomalyWeights, version: u32) -> Result<Self, ModelError> {
        weights.validate()?;
        let commitment = commit_weights(&weights, version);
        Ok(GuardianModel { weights, commitment, version })
    }

    pub fn default_model() -> Self {
        Self::new(AnomalyWeights::default_weights(), 1)
            .expect("default weights validate")
    }

    pub fn commitment(&self) -> Hash256 {
        Hash256::from_bytes(self.commitment)
    }

    /// Pure-integer dot product, clamped to `[0, SCORE_MAX]`.
    ///
    /// SECURITY: i128 intermediate guarantees no overflow given the weight
    /// validation in `AnomalyWeights::validate`. Deterministic on every
    /// platform Rust supports.
    pub fn score(&self, f: &FeatureVector) -> i64 {
        let w = &self.weights;
        let mut acc: i128 = w.bias as i128;
        acc += (w.w_mempool_pressure as i128) * (f.mempool_pressure as i128);
        acc += (w.w_block_size_anomaly as i128) * (f.block_size_anomaly as i128);
        acc += (w.w_fee_anomaly as i128) * (f.fee_anomaly as i128);
        acc += (w.w_peer_instability as i128) * (f.peer_instability as i128);
        acc += (w.w_timestamp_skew as i128) * (f.timestamp_skew as i128);
        acc.clamp(0, SCORE_MAX as i128) as i64
    }
}

fn commit_weights(w: &AnomalyWeights, version: u32) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"axiom/guardian/model/v1");
    h.update(version.to_le_bytes());
    h.update(w.w_mempool_pressure.to_le_bytes());
    h.update(w.w_block_size_anomaly.to_le_bytes());
    h.update(w.w_fee_anomaly.to_le_bytes());
    h.update(w.w_peer_instability.to_le_bytes());
    h.update(w.w_timestamp_skew.to_le_bytes());
    h.update(w.bias.to_le_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_deterministic() {
        let m = GuardianModel::default_model();
        let f = FeatureVector {
            mempool_pressure: 5000,
            block_size_anomaly: 0,
            fee_anomaly: 1000,
            peer_instability: 200,
            timestamp_skew: 0,
        };
        let a = m.score(&f);
        let b = m.score(&f);
        assert_eq!(a, b);
    }

    #[test]
    fn score_zero_input_returns_zero_with_zero_bias() {
        let m = GuardianModel::default_model();
        assert_eq!(m.score(&FeatureVector::zero()), 0);
    }

    #[test]
    fn score_monotone_in_feature() {
        let m = GuardianModel::default_model();
        let mut f = FeatureVector::zero();
        let low = m.score(&f);
        f.mempool_pressure = FEATURE_MAX;
        let high = m.score(&f);
        assert!(high > low);
    }

    #[test]
    fn score_clamped_to_score_max() {
        let m = GuardianModel::default_model();
        let saturated = FeatureVector {
            mempool_pressure: FEATURE_MAX,
            block_size_anomaly: FEATURE_MAX,
            fee_anomaly: FEATURE_MAX,
            peer_instability: FEATURE_MAX,
            timestamp_skew: FEATURE_MAX,
        };
        let s = m.score(&saturated);
        assert!(s >= 0 && s <= SCORE_MAX);
    }

    #[test]
    fn commitment_changes_with_weights() {
        let m1 = GuardianModel::default_model();
        let mut w = m1.weights.clone();
        w.w_fee_anomaly += 1;
        let m2 = GuardianModel::new(w, m1.version).unwrap();
        assert_ne!(m1.commitment, m2.commitment);
    }

    #[test]
    fn commitment_changes_with_version() {
        let w = AnomalyWeights::default_weights();
        let m1 = GuardianModel::new(w.clone(), 1).unwrap();
        let m2 = GuardianModel::new(w, 2).unwrap();
        assert_ne!(m1.commitment, m2.commitment);
    }

    #[test]
    fn weight_overflow_rejected() {
        let w = AnomalyWeights {
            w_mempool_pressure: i64::MAX / 2,
            w_block_size_anomaly: 0,
            w_fee_anomaly: 0,
            w_peer_instability: 0,
            w_timestamp_skew: 0,
            bias: 0,
        };
        assert!(GuardianModel::new(w, 1).is_err());
    }
}
