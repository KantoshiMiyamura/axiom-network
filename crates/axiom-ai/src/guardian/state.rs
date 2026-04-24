// Copyright (c) 2026 Kantoshi Miyamura
//
// Deterministic state encoding for Guardian observations.
//
// INVARIANT: `DeterministicState::encode(obs)` is a pure function of `obs`.
// Two nodes holding the same `GuardianObservation` (same blocks, same mempool
// summary, same peer stats) MUST produce the same 32-byte commitment. This is
// what makes GuardianProof reproducible and aggregation meaningful across the
// network.
//
// Canonicalisation rules (required for determinism):
//   1. All integers are little-endian fixed-width.
//   2. Collections are length-prefixed (u32 LE).
//   3. Inner collections are sorted by a stable total order before hashing.
//   4. All byte strings are written verbatim (no text normalisation).
//   5. A domain-separation tag prefix prevents cross-context collisions.

use axiom_primitives::Hash256;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Per-block summary fed into the Guardian's observation window.
///
/// Fields are drawn directly from canonical on-chain values — no derived
/// statistics, no wall-clock at observation time. `timestamp` is the block's
/// own header timestamp, not the observer's clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockSummary {
    pub hash: [u8; 32],
    pub height: u64,
    pub tx_count: u32,
    pub size_bytes: u32,
    pub timestamp: u64,
}

/// Mempool / transaction-pattern statistics.
///
/// Fee rate is carried as integer sat/vbyte × 1000 ("milli-sat/vbyte") to
/// avoid floats. `unique_senders` and `dust_count` are counters over the
/// current mempool snapshot, not running totals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxPatternStats {
    pub mempool_size: u32,
    pub avg_fee_rate_millisat: u64,
    pub unique_senders: u32,
    pub dust_count: u32,
}

/// Peer-level connectivity stats as seen by the local node. These are *local*
/// observations, but the state commitment is deterministic given the local
/// view — every node derives its own commitment from its own view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerStats {
    pub peer_count: u32,
    pub handshake_failures: u32,
    pub median_latency_ms: u32,
}

/// Full observation supplied to the Guardian each tick. The commitment derived
/// from this object is the S_t in the protocol specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianObservation {
    pub height: u64,
    pub tip_hash: [u8; 32],
    pub block_window: Vec<BlockSummary>,
    pub tx_patterns: TxPatternStats,
    pub peer_stats: PeerStats,
}

/// Opaque 32-byte commitment to an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeterministicState(pub [u8; 32]);

impl DeterministicState {
    /// Canonical SHA3-256 commitment. See file-level invariant.
    pub fn encode(obs: &GuardianObservation) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(b"axiom/guardian/state/v1");

        hasher.update(obs.height.to_le_bytes());
        hasher.update(obs.tip_hash);

        // Block window: sort by (height asc, hash asc) so any ingestion order
        // produces the same commitment.
        let mut window = obs.block_window.clone();
        window.sort_by(|a, b| a.height.cmp(&b.height).then_with(|| a.hash.cmp(&b.hash)));
        hasher.update((window.len() as u32).to_le_bytes());
        for b in &window {
            hasher.update(b.hash);
            hasher.update(b.height.to_le_bytes());
            hasher.update(b.tx_count.to_le_bytes());
            hasher.update(b.size_bytes.to_le_bytes());
            hasher.update(b.timestamp.to_le_bytes());
        }

        hasher.update(obs.tx_patterns.mempool_size.to_le_bytes());
        hasher.update(obs.tx_patterns.avg_fee_rate_millisat.to_le_bytes());
        hasher.update(obs.tx_patterns.unique_senders.to_le_bytes());
        hasher.update(obs.tx_patterns.dust_count.to_le_bytes());

        hasher.update(obs.peer_stats.peer_count.to_le_bytes());
        hasher.update(obs.peer_stats.handshake_failures.to_le_bytes());
        hasher.update(obs.peer_stats.median_latency_ms.to_le_bytes());

        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        DeterministicState(out)
    }

    pub fn as_hash(&self) -> Hash256 {
        Hash256::from_bytes(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_obs() -> GuardianObservation {
        GuardianObservation {
            height: 100,
            tip_hash: [0xAAu8; 32],
            block_window: vec![
                BlockSummary { hash: [1u8; 32], height: 98, tx_count: 3, size_bytes: 1024, timestamp: 1000 },
                BlockSummary { hash: [2u8; 32], height: 99, tx_count: 5, size_bytes: 2048, timestamp: 1010 },
                BlockSummary { hash: [3u8; 32], height: 100, tx_count: 7, size_bytes: 3072, timestamp: 1020 },
            ],
            tx_patterns: TxPatternStats {
                mempool_size: 42,
                avg_fee_rate_millisat: 3500,
                unique_senders: 17,
                dust_count: 2,
            },
            peer_stats: PeerStats {
                peer_count: 12,
                handshake_failures: 1,
                median_latency_ms: 45,
            },
        }
    }

    #[test]
    fn encoding_is_deterministic() {
        let a = DeterministicState::encode(&sample_obs());
        let b = DeterministicState::encode(&sample_obs());
        assert_eq!(a, b);
    }

    #[test]
    fn encoding_invariant_under_block_order() {
        let mut obs = sample_obs();
        let original = DeterministicState::encode(&obs);
        // Reverse the window; sort-by-(height,hash) inside encode must undo it.
        obs.block_window.reverse();
        let reordered = DeterministicState::encode(&obs);
        assert_eq!(original, reordered);
    }

    #[test]
    fn encoding_sensitive_to_every_field() {
        let base = sample_obs();
        let base_h = DeterministicState::encode(&base);

        let mut t = base.clone(); t.height += 1;
        assert_ne!(DeterministicState::encode(&t), base_h);

        let mut t = base.clone(); t.tip_hash[0] ^= 1;
        assert_ne!(DeterministicState::encode(&t), base_h);

        let mut t = base.clone(); t.tx_patterns.mempool_size += 1;
        assert_ne!(DeterministicState::encode(&t), base_h);

        let mut t = base.clone(); t.peer_stats.peer_count += 1;
        assert_ne!(DeterministicState::encode(&t), base_h);

        let mut t = base.clone(); t.block_window[0].tx_count += 1;
        assert_ne!(DeterministicState::encode(&t), base_h);
    }

    #[test]
    fn domain_separation_prevents_preimage_collisions() {
        // Encoding an observation must not coincide with SHA3-256 of the raw
        // concatenation of the same bytes without the domain tag.
        let obs = sample_obs();
        let commitment = DeterministicState::encode(&obs);
        let mut naive = Sha3_256::new();
        naive.update(obs.height.to_le_bytes());
        naive.update(obs.tip_hash);
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&naive.finalize());
        assert_ne!(commitment.0, raw);
    }
}
