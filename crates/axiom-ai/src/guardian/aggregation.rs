// Copyright (c) 2026 Kantoshi Miyamura
//
// Deterministic aggregation over GuardianReports.
//
// INVARIANT: given the same *set* of verified reports, every node produces
// byte-identical aggregation output. Non-determinism sources that we must
// eliminate:
//
//   - Report ordering: inputs are sorted by (node_pubkey_hash, height) before
//     use. The final output never depends on caller-supplied order.
//   - Duplicate reports per sender: the latest (highest-height) is kept.
//     Same-height duplicates resolved by lowest signature hash.
//   - Floating-point arithmetic: disallowed. Medians are computed via
//     sort + index; means are avoided where they would need division that
//     could alias.
//
// OUTPUT SCOPE: the aggregated decision feeds ONLY:
//   - local peer-score table
//   - relay-rate limiter
//   - block-template sender prioritisation
// It NEVER feeds block or transaction validity. See AI-CONSENSUS-AUDIT.md
// for the isolation argument.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;

use super::decision::PeerFlagKind;
use super::report::GuardianReport;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatedDecision {
    /// Median anomaly score across the most recent report from each reporter.
    pub median_anomaly_score: i64,
    /// Majority-vote flag per peer (ties broken by the enum's byte order).
    pub peer_consensus_flags: Vec<(/* peer_id_hash */ [u8; 32], PeerFlagKind)>,
    /// Median of reporters' suggested fee floors. Integer-only — no rounding.
    pub priority_median_fee_millisat: u64,
    /// Number of distinct reporters that contributed after dedup.
    pub reporter_count: u32,
    /// Hash of the sorted reporter pubkey list. Allows downstream policy
    /// (e.g. require N-of-M reporters) to verify the membership without
    /// re-reading every report.
    pub reporter_set_hash: [u8; 32],
}

/// Aggregate verified reports. The caller is responsible for verifying each
/// report (signature AND proof) before calling this function — aggregation
/// itself does NOT re-verify, to keep it allocation-bounded and obviously
/// deterministic.
pub fn aggregate(reports: &[GuardianReport]) -> AggregatedDecision {
    // Dedup to one report per reporter: keep the highest height, break ties
    // by lowest signature hash. Using BTreeMap keeps traversal ordered by
    // the key, so the downstream iteration is also deterministic.
    let mut latest: BTreeMap<Vec<u8>, &GuardianReport> = BTreeMap::new();
    for r in reports {
        match latest.get(&r.node_pubkey) {
            None => {
                latest.insert(r.node_pubkey.clone(), r);
            }
            Some(prev) => {
                let take_new = r.height > prev.height
                    || (r.height == prev.height
                        && sig_hash(&r.signature) < sig_hash(&prev.signature));
                if take_new {
                    latest.insert(r.node_pubkey.clone(), r);
                }
            }
        }
    }

    // Median of anomaly scores.
    let mut scores: Vec<i64> = latest.values().map(|r| r.decision.anomaly_score).collect();
    scores.sort();
    let median_anomaly_score = median(&scores);

    // Per-peer majority vote on flag. Ties broken by enum byte order so the
    // choice is stable.
    let mut per_peer: BTreeMap<[u8; 32], BTreeMap<u8, u32>> = BTreeMap::new();
    for r in latest.values() {
        for f in &r.decision.peer_flags {
            let tally = per_peer.entry(f.peer_id_hash).or_default();
            *tally.entry(flag_discriminant(f.kind)).or_insert(0) += 1;
        }
    }
    let mut peer_consensus_flags: Vec<([u8; 32], PeerFlagKind)> = per_peer
        .into_iter()
        .map(|(peer, tally)| (peer, majority_flag(&tally)))
        .collect();
    peer_consensus_flags.sort_by(|a, b| a.0.cmp(&b.0));

    // Median fee floor.
    let mut floors: Vec<u64> = latest
        .values()
        .map(|r| r.decision.tx_priority_hint.median_fee_floor_millisat)
        .collect();
    floors.sort();
    let priority_median_fee_millisat = if floors.is_empty() {
        0
    } else {
        median_u64(&floors)
    };

    // Reporter-set hash.
    let mut reporters: Vec<&Vec<u8>> = latest.keys().collect();
    reporters.sort();
    let mut h = Sha3_256::new();
    h.update(b"axiom/guardian/reporters/v1");
    for k in &reporters {
        h.update((k.len() as u32).to_le_bytes());
        h.update(k.as_slice());
    }
    let mut reporter_set_hash = [0u8; 32];
    reporter_set_hash.copy_from_slice(&h.finalize());

    AggregatedDecision {
        median_anomaly_score,
        peer_consensus_flags,
        priority_median_fee_millisat,
        reporter_count: latest.len() as u32,
        reporter_set_hash,
    }
}

fn sig_hash(sig: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(sig);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn median(v: &[i64]) -> i64 {
    if v.is_empty() {
        return 0;
    }
    let mid = v.len() / 2;
    if v.len() % 2 == 1 {
        v[mid]
    } else {
        (v[mid - 1] + v[mid]) / 2
    }
}

fn median_u64(v: &[u64]) -> u64 {
    if v.is_empty() {
        return 0;
    }
    let mid = v.len() / 2;
    if v.len() % 2 == 1 {
        v[mid]
    } else {
        (v[mid - 1] + v[mid]) / 2
    }
}

fn flag_discriminant(f: PeerFlagKind) -> u8 {
    match f {
        PeerFlagKind::Trusted => 0,
        PeerFlagKind::Neutral => 1,
        PeerFlagKind::Suspect => 2,
        PeerFlagKind::Slow => 3,
        PeerFlagKind::Malicious => 4,
    }
}

fn discriminant_to_flag(d: u8) -> PeerFlagKind {
    match d {
        0 => PeerFlagKind::Trusted,
        1 => PeerFlagKind::Neutral,
        2 => PeerFlagKind::Suspect,
        3 => PeerFlagKind::Slow,
        _ => PeerFlagKind::Malicious,
    }
}

fn majority_flag(tally: &BTreeMap<u8, u32>) -> PeerFlagKind {
    // Highest count wins; ties broken by lowest discriminant. BTreeMap
    // iteration is ordered, so the tie-break is deterministic.
    let mut best = (0u32, 255u8);
    for (disc, count) in tally {
        if *count > best.0 || (*count == best.0 && *disc < best.1) {
            best = (*count, *disc);
        }
    }
    discriminant_to_flag(best.1)
}

#[cfg(test)]
mod tests {
    use super::super::decision::{GuardianDecision, GuardianProof, PeerFlag, TxPriorityHint};
    use super::super::model::GuardianModel;
    use super::super::state::DeterministicState;
    use super::*;
    use axiom_crypto::generate_keypair;

    fn make_report(
        sk: &[u8],
        vk: Vec<u8>,
        height: u64,
        score: i64,
        floor: u64,
        peer_flags: Vec<PeerFlag>,
        model: &GuardianModel,
    ) -> GuardianReport {
        let state = DeterministicState([height as u8; 32]);
        let decision = GuardianDecision {
            anomaly_score: score,
            peer_flags,
            tx_priority_hint: TxPriorityHint {
                median_fee_floor_millisat: floor,
                promote_senders: vec![],
                demote_senders: vec![],
            },
        };
        let proof = GuardianProof::compute(&state, &decision, model);
        GuardianReport::sign(sk, vk, height, 0, state, decision, proof, model.commitment).unwrap()
    }

    #[test]
    fn aggregation_is_order_independent() {
        let model = GuardianModel::default_model();
        let (sk1, vk1) = generate_keypair();
        let (sk2, vk2) = generate_keypair();
        let (sk3, vk3) = generate_keypair();
        let r1 = make_report(&sk1, vk1, 1, 100, 1000, vec![], &model);
        let r2 = make_report(&sk2, vk2, 1, 300, 2000, vec![], &model);
        let r3 = make_report(&sk3, vk3, 1, 500, 3000, vec![], &model);

        let a = aggregate(&[r1.clone(), r2.clone(), r3.clone()]);
        let b = aggregate(&[r3, r2, r1]);
        assert_eq!(a, b);
    }

    #[test]
    fn aggregation_dedup_keeps_latest() {
        let model = GuardianModel::default_model();
        let (sk, vk) = generate_keypair();
        let r_old = make_report(&sk, vk.clone(), 1, 100, 1000, vec![], &model);
        let r_new = make_report(&sk, vk, 2, 900, 5000, vec![], &model);
        let agg = aggregate(&[r_old, r_new]);
        assert_eq!(agg.reporter_count, 1);
        assert_eq!(agg.median_anomaly_score, 900);
        assert_eq!(agg.priority_median_fee_millisat, 5000);
    }

    #[test]
    fn aggregation_median_is_integer() {
        let model = GuardianModel::default_model();
        let (sk1, vk1) = generate_keypair();
        let (sk2, vk2) = generate_keypair();
        let r1 = make_report(&sk1, vk1, 1, 100, 0, vec![], &model);
        let r2 = make_report(&sk2, vk2, 1, 200, 0, vec![], &model);
        let agg = aggregate(&[r1, r2]);
        // median of [100, 200] = 150 via integer arithmetic
        assert_eq!(agg.median_anomaly_score, 150);
    }

    #[test]
    fn peer_majority_vote() {
        let model = GuardianModel::default_model();
        let (sk1, vk1) = generate_keypair();
        let (sk2, vk2) = generate_keypair();
        let (sk3, vk3) = generate_keypair();
        let peer = [7u8; 32];
        let r1 = make_report(
            &sk1,
            vk1,
            1,
            0,
            0,
            vec![PeerFlag {
                peer_id_hash: peer,
                kind: PeerFlagKind::Trusted,
            }],
            &model,
        );
        let r2 = make_report(
            &sk2,
            vk2,
            1,
            0,
            0,
            vec![PeerFlag {
                peer_id_hash: peer,
                kind: PeerFlagKind::Suspect,
            }],
            &model,
        );
        let r3 = make_report(
            &sk3,
            vk3,
            1,
            0,
            0,
            vec![PeerFlag {
                peer_id_hash: peer,
                kind: PeerFlagKind::Suspect,
            }],
            &model,
        );
        let agg = aggregate(&[r1, r2, r3]);
        assert_eq!(agg.peer_consensus_flags.len(), 1);
        assert_eq!(agg.peer_consensus_flags[0].1, PeerFlagKind::Suspect);
    }

    #[test]
    fn empty_aggregate_is_zero() {
        let agg = aggregate(&[]);
        assert_eq!(agg.median_anomaly_score, 0);
        assert_eq!(agg.reporter_count, 0);
        assert_eq!(agg.priority_median_fee_millisat, 0);
        assert!(agg.peer_consensus_flags.is_empty());
    }
}
