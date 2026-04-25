// Copyright (c) 2026 Kantoshi Miyamura
//
// Guardian decision + cryptographic proof.
//
// INVARIANT: a `GuardianDecision` is a pure function of
// (DeterministicState, GuardianModel). A `GuardianProof` binds the decision
// to the state and to the model commitment so that a verifier given the same
// observation and model can reproduce the proof byte-for-byte.
//
//     Proof = SHA3-256("axiom/guardian/proof/v1" ||
//                      state_hash                ||
//                      model_commitment          ||
//                      canonical_decision_bytes)
//
// SECURITY REASONING: the proof is NOT a zero-knowledge proof and is NOT a
// consensus artefact. It is an audit trail: given a report, a third party
// with the claimed state and model can recompute the proof and flag
// divergences. Mismatches indicate the reporting node either used a
// different model than declared, or hallucinated state.

use axiom_primitives::Hash256;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use super::model::GuardianModel;
use super::state::DeterministicState;

/// Per-peer verdict carried inside a decision. `peer_id_hash` is SHA3-256 of
/// the peer's verifying key — never the raw key. Using a hash decouples the
/// decision format from ML-DSA-87's specific byte layout and shrinks the
/// on-wire footprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerFlag {
    pub peer_id_hash: [u8; 32],
    pub kind: PeerFlagKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum PeerFlagKind {
    Trusted = 0,
    Neutral = 1,
    Suspect = 2,
    Slow = 3,
    Malicious = 4,
}

impl PeerFlagKind {
    fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Advisory hint consumed by local mempool / relay policy. The Guardian
/// NEVER produces a "reject" instruction: the worst it says is "deprioritise
/// this sender" or "prefer these senders". Consensus acceptance remains
/// controlled by `axiom-consensus::validation`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxPriorityHint {
    /// Local relay-floor (sat/vbyte × 1000). Transactions below this floor
    /// are accepted by consensus but deprioritised in relay / block template
    /// selection. Zero means no hint.
    pub median_fee_floor_millisat: u64,
    /// Sender-address hashes to promote in the relay / template.
    pub promote_senders: Vec<[u8; 32]>,
    /// Sender-address hashes to demote. MUST NOT gate acceptance.
    pub demote_senders: Vec<[u8; 32]>,
}

impl TxPriorityHint {
    pub fn empty() -> Self {
        TxPriorityHint {
            median_fee_floor_millisat: 0,
            promote_senders: Vec::new(),
            demote_senders: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianDecision {
    pub anomaly_score: i64,
    pub peer_flags: Vec<PeerFlag>,
    pub tx_priority_hint: TxPriorityHint,
}

impl GuardianDecision {
    /// Canonical byte encoding used inside the proof. Lists are sorted to
    /// remove ordering ambiguity.
    ///
    /// Layout:
    ///   i64 LE              score
    ///   u32 LE              peer_flags.len()
    ///   for each flag (sorted by peer_id_hash):
    ///     32 bytes          peer_id_hash
    ///     u8                flag kind discriminant
    ///   u64 LE              median_fee_floor_millisat
    ///   u32 LE              promote_senders.len()
    ///   for each (sorted):  32 bytes
    ///   u32 LE              demote_senders.len()
    ///   for each (sorted):  32 bytes
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + 33 * self.peer_flags.len());
        out.extend_from_slice(&self.anomaly_score.to_le_bytes());

        let mut flags = self.peer_flags.clone();
        flags.sort_by(|a, b| a.peer_id_hash.cmp(&b.peer_id_hash));
        out.extend_from_slice(&(flags.len() as u32).to_le_bytes());
        for f in &flags {
            out.extend_from_slice(&f.peer_id_hash);
            out.push(f.kind.as_byte());
        }

        out.extend_from_slice(
            &self
                .tx_priority_hint
                .median_fee_floor_millisat
                .to_le_bytes(),
        );

        let mut promote = self.tx_priority_hint.promote_senders.clone();
        promote.sort();
        out.extend_from_slice(&(promote.len() as u32).to_le_bytes());
        for s in &promote {
            out.extend_from_slice(s);
        }

        let mut demote = self.tx_priority_hint.demote_senders.clone();
        demote.sort();
        out.extend_from_slice(&(demote.len() as u32).to_le_bytes());
        for s in &demote {
            out.extend_from_slice(s);
        }

        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianProof(pub [u8; 32]);

impl GuardianProof {
    pub fn compute(
        state: &DeterministicState,
        decision: &GuardianDecision,
        model: &GuardianModel,
    ) -> Self {
        let mut h = Sha3_256::new();
        h.update(b"axiom/guardian/proof/v1");
        h.update(state.0);
        h.update(model.commitment);
        h.update(decision.canonical_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        GuardianProof(out)
    }

    pub fn verify(
        &self,
        state: &DeterministicState,
        decision: &GuardianDecision,
        model: &GuardianModel,
    ) -> bool {
        Self::compute(state, decision, model).0 == self.0
    }

    pub fn as_hash(&self) -> Hash256 {
        Hash256::from_bytes(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::super::state::{
        BlockSummary, DeterministicState, GuardianObservation, PeerStats, TxPatternStats,
    };
    use super::*;

    fn obs() -> GuardianObservation {
        GuardianObservation {
            height: 1,
            tip_hash: [0u8; 32],
            block_window: vec![BlockSummary {
                hash: [1u8; 32],
                height: 1,
                tx_count: 1,
                size_bytes: 100,
                timestamp: 1,
            }],
            tx_patterns: TxPatternStats {
                mempool_size: 0,
                avg_fee_rate_millisat: 0,
                unique_senders: 0,
                dust_count: 0,
            },
            peer_stats: PeerStats {
                peer_count: 3,
                handshake_failures: 0,
                median_latency_ms: 10,
            },
        }
    }

    fn decision() -> GuardianDecision {
        GuardianDecision {
            anomaly_score: 1234,
            peer_flags: vec![
                PeerFlag {
                    peer_id_hash: [9u8; 32],
                    kind: PeerFlagKind::Suspect,
                },
                PeerFlag {
                    peer_id_hash: [2u8; 32],
                    kind: PeerFlagKind::Trusted,
                },
            ],
            tx_priority_hint: TxPriorityHint {
                median_fee_floor_millisat: 1500,
                promote_senders: vec![[7u8; 32], [3u8; 32]],
                demote_senders: vec![[8u8; 32]],
            },
        }
    }

    #[test]
    fn canonical_bytes_stable_under_flag_permutation() {
        let mut d1 = decision();
        let d2 = decision();
        d1.peer_flags.reverse();
        assert_eq!(d1.canonical_bytes(), d2.canonical_bytes());
    }

    #[test]
    fn canonical_bytes_stable_under_sender_permutation() {
        let mut d1 = decision();
        let d2 = decision();
        d1.tx_priority_hint.promote_senders.reverse();
        assert_eq!(d1.canonical_bytes(), d2.canonical_bytes());
    }

    #[test]
    fn proof_reproducible() {
        let s = DeterministicState::encode(&obs());
        let m = GuardianModel::default_model();
        let d = decision();
        let p1 = GuardianProof::compute(&s, &d, &m);
        let p2 = GuardianProof::compute(&s, &d, &m);
        assert_eq!(p1, p2);
        assert!(p1.verify(&s, &d, &m));
    }

    #[test]
    fn proof_fails_on_decision_tamper() {
        let s = DeterministicState::encode(&obs());
        let m = GuardianModel::default_model();
        let mut d = decision();
        let p = GuardianProof::compute(&s, &d, &m);
        d.anomaly_score += 1;
        assert!(!p.verify(&s, &d, &m));
    }

    #[test]
    fn proof_fails_on_model_swap() {
        let s = DeterministicState::encode(&obs());
        let m1 = GuardianModel::default_model();
        let mut weights = m1.weights.clone();
        weights.bias += 1;
        let m2 = GuardianModel::new(weights, m1.version).unwrap();
        let d = decision();
        let p = GuardianProof::compute(&s, &d, &m1);
        assert!(!p.verify(&s, &d, &m2));
    }
}
