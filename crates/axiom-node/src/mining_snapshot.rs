// Copyright (c) 2026 Kantoshi Miyamura

//! Mining snapshot: immutable view of chain state for safe mining.

use axiom_primitives::Hash256;
use axiom_protocol::Transaction;

/// Immutable snapshot of chain state for mining.
/// Miners work on this snapshot, not live mutable state.
#[derive(Debug, Clone)]
pub struct MiningSnapshot {
    /// Parent block hash (what we're building on).
    pub parent_hash: Hash256,
    /// Parent block height.
    pub parent_height: u32,
    /// Difficulty target for the new block.
    pub target: u32,
    /// Selected transactions (coinbase first, then mempool).
    pub transactions: Vec<Transaction>,
    /// Timestamp basis (must be >= MTP).
    pub timestamp_basis: u32,
    /// Unique snapshot version identifier.
    pub snapshot_version: u64,
}

impl MiningSnapshot {
    /// Create a new mining snapshot.
    pub fn new(
        parent_hash: Hash256,
        parent_height: u32,
        target: u32,
        transactions: Vec<Transaction>,
        timestamp_basis: u32,
        snapshot_version: u64,
    ) -> Self {
        MiningSnapshot {
            parent_hash,
            parent_height,
            target,
            transactions,
            timestamp_basis,
            snapshot_version,
        }
    }

    /// Check if this snapshot is still valid (parent is still active tip).
    /// Returns true if the snapshot's parent is still the active tip.
    pub fn is_stale(&self, current_tip: &Hash256, current_version: u64) -> bool {
        self.parent_hash != *current_tip || self.snapshot_version != current_version
    }

    /// Get the height of the block we're mining.
    pub fn mining_height(&self) -> u32 {
        self.parent_height + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mining_snapshot_creation() {
        let snapshot = MiningSnapshot::new(
            Hash256::zero(),
            0,
            0x207fffff,
            vec![],
            0,
            1,
        );

        assert_eq!(snapshot.parent_height, 0);
        assert_eq!(snapshot.mining_height(), 1);
        assert_eq!(snapshot.snapshot_version, 1);
    }

    #[test]
    fn test_mining_snapshot_staleness() {
        let snapshot = MiningSnapshot::new(
            Hash256::zero(),
            0,
            0x207fffff,
            vec![],
            0,
            1,
        );

        // Same tip and version: not stale
        assert!(!snapshot.is_stale(&Hash256::zero(), 1));

        // Different tip: stale
        assert!(snapshot.is_stale(&Hash256::from_bytes([1u8; 32]), 1));

        // Different version: stale
        assert!(snapshot.is_stale(&Hash256::zero(), 2));
    }
}
