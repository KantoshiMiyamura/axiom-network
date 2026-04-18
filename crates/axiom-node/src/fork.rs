// Copyright (c) 2026 Kantoshi Miyamura

//! Orphan block pool and chain tip tracking.

use axiom_consensus::Block;
use axiom_primitives::Hash256;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ForkError {
    #[error("orphan pool full")]
    OrphanPoolFull,

    #[error("orphan not found: {0}")]
    OrphanNotFound(String),

    #[error("too many orphans from peer: {peer_id} has {count} orphans (max: {max})")]
    TooManyOrphansFromPeer {
        peer_id: String,
        count: usize,
        max: usize,
    },
}

const MAX_ORPHAN_BLOCKS: usize = 100;
const MAX_ORPHAN_MEMORY_BYTES: usize = 50 * 1024 * 1024;
const ORPHAN_TTL: Duration = Duration::from_secs(60 * 60);

// CRITICAL FIX: Per-peer orphan limit to prevent memory exhaustion DoS.
// Without this, an attacker can connect from 100 IPs and send 100 orphans each,
// consuming 500MB+ memory and crashing the node.
// Must be LOWER than MAX_ORPHAN_BLOCKS (100) to prevent a single peer from
// filling the entire pool. Set to 10 so ≥10 peers can each contribute orphans.
const MAX_ORPHANS_PER_PEER: usize = 10;

struct OrphanEntry {
    block: Block,
    size_bytes: usize,
    admitted_at: Instant,
    peer_id: Option<String>,
}

pub struct OrphanPool {
    orphans: HashMap<Hash256, OrphanEntry>,
    by_parent: HashMap<Hash256, Vec<Hash256>>,
    by_peer: HashMap<String, Vec<Hash256>>,
    total_bytes: usize,
}

impl Default for OrphanPool {
    fn default() -> Self {
        Self::new()
    }
}

impl OrphanPool {
    pub fn new() -> Self {
        OrphanPool {
            orphans: HashMap::new(),
            by_parent: HashMap::new(),
            by_peer: HashMap::new(),
            total_bytes: 0,
        }
    }

    fn estimate_block_size(block: &Block) -> usize {
        let header_size = 80usize;
        let tx_size: usize = block
            .transactions
            .iter()
            .map(|tx| 256 + tx.inputs.len() * 64 + tx.outputs.len() * 64)
            .sum();
        header_size + tx_size
    }

    fn expire_stale(&mut self) {
        let now = Instant::now();
        let stale: Vec<Hash256> = self
            .orphans
            .iter()
            .filter(|(_, e)| now.duration_since(e.admitted_at) >= ORPHAN_TTL)
            .map(|(h, _)| *h)
            .collect();

        for hash in stale {
            self.evict_one(&hash);
        }
    }

    fn evict_one(&mut self, block_hash: &Hash256) {
        if let Some(entry) = self.orphans.remove(block_hash) {
            self.total_bytes = self.total_bytes.saturating_sub(entry.size_bytes);
            let parent_hash = entry.block.header.prev_block_hash;
            if let Some(children) = self.by_parent.get_mut(&parent_hash) {
                children.retain(|h| h != block_hash);
                if children.is_empty() {
                    self.by_parent.remove(&parent_hash);
                }
            }
            // CRITICAL FIX: Remove from per-peer tracking
            if let Some(ref peer_id) = entry.peer_id {
                if let Some(peer_orphans) = self.by_peer.get_mut(peer_id) {
                    peer_orphans.retain(|h| h != block_hash);
                    if peer_orphans.is_empty() {
                        self.by_peer.remove(peer_id);
                    }
                }
            }
        }
    }

    fn evict_oldest(&mut self) {
        let oldest_hash = self
            .orphans
            .iter()
            .min_by_key(|(_, e)| e.admitted_at)
            .map(|(h, _)| *h);

        if let Some(hash) = oldest_hash {
            tracing::debug!(
                "ORPHAN_EVICT_OLDEST: hash={}",
                hex::encode(&hash.as_bytes()[..8])
            );
            self.evict_one(&hash);
        }
    }

    pub fn add_orphan(&mut self, block: Block) -> Result<(), ForkError> {
        self.add_orphan_from_peer(block, None)
    }

    /// CRITICAL FIX: Add orphan with per-peer tracking to prevent memory exhaustion DoS.
    /// An attacker can connect from 100 IPs and send 100 orphans each (10,000 total),
    /// consuming 500MB+ memory. Per-peer limits prevent this attack.
    pub fn add_orphan_from_peer(
        &mut self,
        block: Block,
        peer_id: Option<String>,
    ) -> Result<(), ForkError> {
        self.expire_stale();

        let block_hash = block.hash();
        let parent_hash = block.header.prev_block_hash;
        let size_bytes = Self::estimate_block_size(&block);

        // CRITICAL FIX: Enforce per-peer orphan limit BEFORE global limit.
        // This prevents a single malicious peer from filling the entire orphan pool.
        if let Some(ref peer) = peer_id {
            let peer_orphan_count = self.by_peer.get(peer).map_or(0, |v| v.len());
            if peer_orphan_count >= MAX_ORPHANS_PER_PEER {
                tracing::warn!(
                    peer_id = %peer,
                    count = peer_orphan_count,
                    max = MAX_ORPHANS_PER_PEER,
                    "ORPHAN_REJECTED reason=peer_limit_exceeded"
                );
                return Err(ForkError::TooManyOrphansFromPeer {
                    peer_id: peer.clone(),
                    count: peer_orphan_count,
                    max: MAX_ORPHANS_PER_PEER,
                });
            }
        }

        if self.orphans.len() >= MAX_ORPHAN_BLOCKS {
            self.evict_oldest();
        }

        while self.total_bytes + size_bytes > MAX_ORPHAN_MEMORY_BYTES && !self.orphans.is_empty() {
            self.evict_oldest();
        }

        if self.total_bytes + size_bytes > MAX_ORPHAN_MEMORY_BYTES {
            return Err(ForkError::OrphanPoolFull);
        }

        self.total_bytes += size_bytes;
        self.orphans.insert(
            block_hash,
            OrphanEntry {
                block,
                size_bytes,
                admitted_at: Instant::now(),
                peer_id: peer_id.clone(),
            },
        );
        self.by_parent
            .entry(parent_hash)
            .or_default()
            .push(block_hash);

        // CRITICAL FIX: Track orphans by peer
        if let Some(peer) = peer_id {
            self.by_peer
                .entry(peer)
                .or_default()
                .push(block_hash);
        }

        Ok(())
    }

    pub fn get_orphan(&self, block_hash: &Hash256) -> Option<&Block> {
        self.orphans.get(block_hash).map(|e| &e.block)
    }

    pub fn remove_orphan(&mut self, block_hash: &Hash256) -> Option<Block> {
        if let Some(entry) = self.orphans.remove(block_hash) {
            self.total_bytes = self.total_bytes.saturating_sub(entry.size_bytes);
            let parent_hash = entry.block.header.prev_block_hash;

            if let Some(children) = self.by_parent.get_mut(&parent_hash) {
                children.retain(|h| h != block_hash);
                if children.is_empty() {
                    self.by_parent.remove(&parent_hash);
                }
            }

            // CRITICAL FIX: Remove from per-peer tracking
            if let Some(ref peer_id) = entry.peer_id {
                if let Some(peer_orphans) = self.by_peer.get_mut(peer_id) {
                    peer_orphans.retain(|h| h != block_hash);
                    if peer_orphans.is_empty() {
                        self.by_peer.remove(peer_id);
                    }
                }
            }

            Some(entry.block)
        } else {
            None
        }
    }

    pub fn get_children(&self, parent_hash: &Hash256) -> Vec<Hash256> {
        self.by_parent.get(parent_hash).cloned().unwrap_or_default()
    }

    pub fn has_orphan(&self, block_hash: &Hash256) -> bool {
        self.orphans.contains_key(block_hash)
    }

    pub fn len(&self) -> usize {
        self.orphans.len()
    }

    pub fn is_empty(&self) -> bool {
        self.orphans.is_empty()
    }

    pub fn memory_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn clear(&mut self) {
        self.orphans.clear();
        self.by_parent.clear();
        self.by_peer.clear();
        self.total_bytes = 0;
    }

    /// Get the number of orphans from a specific peer.
    pub fn orphan_count_for_peer(&self, peer_id: &str) -> usize {
        self.by_peer.get(peer_id).map_or(0, |v| v.len())
    }
}

#[derive(Debug, Clone)]
pub struct ChainTip {
    pub block_hash: Hash256,
    pub height: u32,
    pub cumulative_work: u128,
}

impl ChainTip {
    pub fn is_better_than(&self, other: &ChainTip) -> bool {
        if self.cumulative_work > other.cumulative_work {
            return true;
        }

        if self.cumulative_work < other.cumulative_work {
            return false;
        }

        self.block_hash.as_bytes() < other.block_hash.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_consensus::{calculate_block_reward, compute_merkle_root, BlockHeader};
    use axiom_protocol::{Transaction, TxOutput};

    fn create_test_block(height: u32, prev_hash: Hash256) -> Block {
        let reward = calculate_block_reward(height);
        let output = TxOutput {
            value: reward,
            pubkey_hash: Hash256::zero(),
        };
        let coinbase = Transaction::new_coinbase(vec![output], height);

        let merkle_root = compute_merkle_root(&[coinbase.clone()]);

        let header = BlockHeader {
            version: 1,
            prev_block_hash: prev_hash,
            merkle_root,
            timestamp: height,
            difficulty_target: 0x1d00ffff,
            nonce: 0,
        };

        Block {
            header,
            transactions: vec![coinbase],
        }
    }

    #[test]
    fn test_orphan_pool_add_remove() {
        let mut pool = OrphanPool::new();

        let block = create_test_block(1, Hash256::zero());
        let block_hash = block.hash();

        pool.add_orphan(block).unwrap();
        assert!(pool.has_orphan(&block_hash));
        assert_eq!(pool.len(), 1);

        let removed = pool.remove_orphan(&block_hash);
        assert!(removed.is_some());
        assert!(!pool.has_orphan(&block_hash));
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_orphan_pool_children() {
        let mut pool = OrphanPool::new();

        let parent_hash = Hash256::zero();
        let block1 = create_test_block(1, parent_hash);
        let block2 = create_test_block(1, parent_hash);

        let hash1 = block1.hash();
        let hash2 = block2.hash();

        pool.add_orphan(block1).unwrap();
        pool.add_orphan(block2).unwrap();

        let children = pool.get_children(&parent_hash);
        assert_eq!(children.len(), 2);
        assert!(children.contains(&hash1));
        assert!(children.contains(&hash2));
    }

    #[test]
    fn test_orphan_pool_limit_evicts_oldest() {
        let mut pool = OrphanPool::new();

        let mut hashes = Vec::new();
        for i in 0..MAX_ORPHAN_BLOCKS {
            let mut prev = [0u8; 32];
            prev[0] = (i & 0xFF) as u8;
            prev[1] = ((i >> 8) & 0xFF) as u8;
            let prev_hash = Hash256::from_bytes(prev);
            let block = create_test_block(i as u32 + 1, prev_hash);
            let h = block.hash();
            pool.add_orphan(block).unwrap();
            hashes.push(h);
        }

        assert_eq!(pool.len(), MAX_ORPHAN_BLOCKS);

        let extra_block = create_test_block(999, Hash256::zero());
        let result = pool.add_orphan(extra_block);
        assert!(
            result.is_ok(),
            "adding beyond limit should evict oldest, not error"
        );
        assert_eq!(
            pool.len(),
            MAX_ORPHAN_BLOCKS,
            "count must stay at limit after eviction"
        );
    }

    #[test]
    fn test_orphan_pool_memory_tracked() {
        let mut pool = OrphanPool::new();
        let block = create_test_block(1, Hash256::zero());
        let size_before = pool.memory_bytes();
        pool.add_orphan(block.clone()).unwrap();
        assert!(pool.memory_bytes() > size_before);

        let hash = block.hash();
        pool.remove_orphan(&hash);
        assert_eq!(pool.memory_bytes(), 0);
    }

    #[test]
    fn test_chain_tip_comparison() {
        let tip1 = ChainTip {
            block_hash: Hash256::zero(),
            height: 10,
            cumulative_work: 1000,
        };

        let tip2 = ChainTip {
            block_hash: Hash256::zero(),
            height: 10,
            cumulative_work: 2000,
        };

        assert!(tip2.is_better_than(&tip1));
        assert!(!tip1.is_better_than(&tip2));
    }

    #[test]
    fn test_chain_tip_tie_break() {
        let hash1 = Hash256::from_slice(&[0u8; 32]).unwrap();
        let hash2 = Hash256::from_slice(&[1u8; 32]).unwrap();

        let tip1 = ChainTip {
            block_hash: hash1,
            height: 10,
            cumulative_work: 1000,
        };

        let tip2 = ChainTip {
            block_hash: hash2,
            height: 10,
            cumulative_work: 1000,
        };

        assert!(tip1.is_better_than(&tip2));
        assert!(!tip2.is_better_than(&tip1));
    }
}
