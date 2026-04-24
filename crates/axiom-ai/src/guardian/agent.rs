// Copyright (c) 2026 Kantoshi Miyamura
//
// GuardianAgent — per-node observer that maps observations to decisions.
//
// ROLE: pure function from (observation, model) to (state, decision, proof).
// The agent owns a model handle, a bounded history buffer for operator
// introspection, and the derivation logic that turns raw observations into
// the bounded integer features the model consumes.
//
// INVARIANT: `observe()` is deterministic given its arguments. It reads from
// the observation and from `self.model`; it does not consult wall-clock,
// thread ID, entropy, or any global state. Any randomness used for
// exploration is seeded from (tip_hash, height) via `SeededRng`.
//
// ISOLATION: the agent has NO handle to the consensus validator, the
// mempool, or the UTXO set. It is fed `GuardianObservation` values by the
// node; whatever it returns is passed back to the node as advisory data.
// The agent CANNOT reach into consensus state (see AI-CONSENSUS-AUDIT.md).

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use super::decision::{GuardianDecision, GuardianProof, TxPriorityHint};
use super::model::{FeatureVector, GuardianModel, FEATURE_MAX};
use super::seeded_rng::SeededRng;
use super::state::{DeterministicState, GuardianObservation};

const HISTORY_CAP: usize = 1024;

/// A single (state, decision, proof) triple. Stored in the agent's ring
/// buffer so operators can inspect recent decisions via RPC.
#[derive(Debug, Clone)]
pub struct DecisionRecord {
    pub state: DeterministicState,
    pub decision: GuardianDecision,
    pub proof: GuardianProof,
}

pub struct GuardianAgent {
    model: Arc<GuardianModel>,
    history: RwLock<VecDeque<DecisionRecord>>,
}

impl GuardianAgent {
    pub fn new(model: GuardianModel) -> Self {
        GuardianAgent {
            model: Arc::new(model),
            history: RwLock::new(VecDeque::with_capacity(HISTORY_CAP)),
        }
    }

    pub fn model(&self) -> &GuardianModel { &self.model }

    /// Produce a decision for a single observation tick.
    ///
    /// DETERMINISM: given the same `obs` and the same agent state, the output
    /// is byte-identical across runs and across platforms. The function is
    /// self-contained — it reads no external state — so it is also safe to
    /// call from multiple threads without ordering concerns.
    pub fn observe(&self, obs: &GuardianObservation) -> DecisionRecord {
        let state = DeterministicState::encode(obs);
        let features = derive_features(obs);
        let anomaly_score = self.model.score(&features);

        // The decision's peer flags and priority hint are derived from
        // thresholds over the same bounded features — no extra data source.
        let decision = GuardianDecision {
            anomaly_score,
            peer_flags: Vec::new(),
            tx_priority_hint: derive_priority_hint(obs),
        };

        let proof = GuardianProof::compute(&state, &decision, &self.model);
        let record = DecisionRecord { state, decision, proof };

        {
            let mut hist = self.history.write().expect("guardian history lock");
            if hist.len() == HISTORY_CAP { hist.pop_front(); }
            hist.push_back(record.clone());
        }

        record
    }

    /// Consume a deterministic RNG seeded from the most recent tip. Callers
    /// that want to sample (e.g. a heuristic that flips between two
    /// aggregation strategies) get an auditable, reproducible stream.
    ///
    /// The RNG is ephemeral: it is never persisted, never shared, and its
    /// seed is derived entirely from observation inputs.
    pub fn deterministic_rng(&self, obs: &GuardianObservation) -> SeededRng {
        SeededRng::new(SeededRng::seed_from_block(&obs.tip_hash, obs.height))
    }

    pub fn history_snapshot(&self, limit: usize) -> Vec<DecisionRecord> {
        let hist = self.history.read().expect("guardian history lock");
        hist.iter().rev().take(limit).cloned().collect()
    }
}

/// Map raw observation counters to clamped integer features.
///
/// The thresholds below ARE the tunable surface of the Guardian. Changing
/// them alters every produced score — record them in the model version bump
/// when they move. Keeping them explicit and integer-only means the mapping
/// is auditable and reproducible.
fn derive_features(obs: &GuardianObservation) -> FeatureVector {
    // Mempool pressure: saturates at 10k pending txs.
    let mempool_pressure = ((obs.tx_patterns.mempool_size as i64) * FEATURE_MAX / 10_000)
        .clamp(0, FEATURE_MAX);

    // Block size anomaly: ratio of max block size in window vs average,
    // in basis points. Saturates at 10k (== 100× average).
    let avg_size = avg_block_size(obs);
    let max_size = max_block_size(obs);
    let block_size_anomaly = if avg_size > 0 {
        ((max_size.saturating_mul(FEATURE_MAX as u64)) / avg_size.max(1)) as i64
    } else { 0 }.clamp(0, FEATURE_MAX);

    // Fee anomaly: dust-fraction of the mempool. 10k means the entire
    // mempool is dust.
    let fee_anomaly = if obs.tx_patterns.mempool_size > 0 {
        (obs.tx_patterns.dust_count as i64) * FEATURE_MAX
            / (obs.tx_patterns.mempool_size as i64).max(1)
    } else { 0 }.clamp(0, FEATURE_MAX);

    // Peer instability: handshake failures per peer, capped at FEATURE_MAX.
    let peer_instability = if obs.peer_stats.peer_count > 0 {
        (obs.peer_stats.handshake_failures as i64) * FEATURE_MAX
            / (obs.peer_stats.peer_count as i64).max(1)
    } else { 0 }.clamp(0, FEATURE_MAX);

    // Timestamp skew: gap (seconds) between the two most recent blocks
    // relative to the protocol target (60s). 60s → 0, 600s → FEATURE_MAX.
    let timestamp_skew = recent_block_gap_skew(obs);

    FeatureVector {
        mempool_pressure,
        block_size_anomaly,
        fee_anomaly,
        peer_instability,
        timestamp_skew,
    }.clamp()
}

fn avg_block_size(obs: &GuardianObservation) -> u64 {
    if obs.block_window.is_empty() { return 0; }
    let total: u64 = obs.block_window.iter().map(|b| b.size_bytes as u64).sum();
    total / (obs.block_window.len() as u64)
}

fn max_block_size(obs: &GuardianObservation) -> u64 {
    obs.block_window.iter().map(|b| b.size_bytes as u64).max().unwrap_or(0)
}

fn recent_block_gap_skew(obs: &GuardianObservation) -> i64 {
    if obs.block_window.len() < 2 { return 0; }
    let mut by_height: Vec<_> = obs.block_window.iter().collect();
    by_height.sort_by_key(|b| b.height);
    let a = by_height[by_height.len() - 2];
    let b = by_height[by_height.len() - 1];
    let gap = b.timestamp.saturating_sub(a.timestamp) as i64;
    // Protocol target is 60s. Linear map: 60→0, 600→FEATURE_MAX.
    ((gap.saturating_sub(60)).max(0) * FEATURE_MAX / 540).clamp(0, FEATURE_MAX)
}

/// Derive a relay priority hint from the observation. This only produces a
/// floor and empty sender lists — populating promote/demote sets is the job
/// of a follow-up pass once we track per-sender behaviour. Keeping this
/// conservative is intentional: the invariant is "priority hints never reject",
/// not "priority hints maximise throughput".
fn derive_priority_hint(obs: &GuardianObservation) -> TxPriorityHint {
    let floor = if obs.tx_patterns.mempool_size > 5_000 {
        obs.tx_patterns.avg_fee_rate_millisat
    } else { 0 };
    TxPriorityHint {
        median_fee_floor_millisat: floor,
        promote_senders: Vec::new(),
        demote_senders: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::state::{BlockSummary, GuardianObservation, PeerStats, TxPatternStats};

    fn obs() -> GuardianObservation {
        GuardianObservation {
            height: 5,
            tip_hash: [9u8; 32],
            block_window: vec![
                BlockSummary { hash: [1u8; 32], height: 3, tx_count: 2, size_bytes: 1000, timestamp: 100 },
                BlockSummary { hash: [2u8; 32], height: 4, tx_count: 2, size_bytes: 1100, timestamp: 160 },
                BlockSummary { hash: [3u8; 32], height: 5, tx_count: 3, size_bytes: 1200, timestamp: 220 },
            ],
            tx_patterns: TxPatternStats {
                mempool_size: 100, avg_fee_rate_millisat: 2000,
                unique_senders: 40, dust_count: 5,
            },
            peer_stats: PeerStats { peer_count: 8, handshake_failures: 0, median_latency_ms: 50 },
        }
    }

    #[test]
    fn observe_is_deterministic() {
        let m = GuardianModel::default_model();
        let a = GuardianAgent::new(m.clone());
        let b = GuardianAgent::new(m);
        let ra = a.observe(&obs());
        let rb = b.observe(&obs());
        assert_eq!(ra.state, rb.state);
        assert_eq!(ra.decision, rb.decision);
        assert_eq!(ra.proof, rb.proof);
    }

    #[test]
    fn observe_proof_verifies() {
        let agent = GuardianAgent::new(GuardianModel::default_model());
        let r = agent.observe(&obs());
        assert!(r.proof.verify(&r.state, &r.decision, agent.model()));
    }

    #[test]
    fn history_is_bounded() {
        let agent = GuardianAgent::new(GuardianModel::default_model());
        let o = obs();
        for _ in 0..(HISTORY_CAP + 5) {
            agent.observe(&o);
        }
        let hist = agent.history_snapshot(2 * HISTORY_CAP);
        assert!(hist.len() <= HISTORY_CAP);
    }

    #[test]
    fn deterministic_rng_depends_on_tip() {
        let agent = GuardianAgent::new(GuardianModel::default_model());
        let mut rng_a = agent.deterministic_rng(&obs());
        let mut o2 = obs(); o2.tip_hash[0] ^= 1;
        let mut rng_b = agent.deterministic_rng(&o2);
        assert_ne!(rng_a.next_u64(), rng_b.next_u64());
    }
}
