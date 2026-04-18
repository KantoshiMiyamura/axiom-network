// Copyright (c) 2026 Kantoshi Miyamura

//! Block index: tracks all known blocks including side forks with full validation state.

use axiom_primitives::Hash256;
use std::collections::HashMap;

/// Validation status of a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockValidationStatus {
    /// Header is valid (PoW, target, prev_hash linkage).
    HeaderValid,
    /// Body is valid (merkle root, transactions).
    BodyValid,
    /// Fully valid and ready for activation.
    FullyValid,
    /// Invalid with reason.
    Invalid(&'static str),
}

/// Source of a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockSource {
    /// Mined locally.
    LocalMined,
    /// Received from peer.
    Peer,
    /// Received during sync.
    Sync,
}

/// Indexed block entry: stores all metadata about a known block.
#[derive(Debug, Clone)]
pub struct BlockIndexEntry {
    /// Block hash.
    pub hash: Hash256,
    /// Previous block hash.
    pub prev_hash: Hash256,
    /// Block height.
    pub height: u32,
    /// Difficulty target (compact form).
    pub target: u32,
    /// Cumulative work from genesis to this block.
    pub chainwork: u128,
    /// Validation status.
    pub status: BlockValidationStatus,
    /// Source of this block.
    pub source: BlockSource,
    /// Child block hashes (for quick reorg traversal).
    pub children: Vec<Hash256>,
}

/// Full block index: tracks all known blocks and forks.
pub struct BlockIndex {
    /// Map from block hash to index entry.
    entries: HashMap<Hash256, BlockIndexEntry>,
    /// Map from height to all block hashes at that height (for fork tracking).
    height_map: HashMap<u32, Vec<Hash256>>,
}

impl BlockIndex {
    /// Create a new empty block index.
    pub fn new() -> Self {
        BlockIndex {
            entries: HashMap::new(),
            height_map: HashMap::new(),
        }
    }

    /// Add or update a block entry.
    pub fn insert(
        &mut self,
        hash: Hash256,
        prev_hash: Hash256,
        height: u32,
        target: u32,
        chainwork: u128,
        source: BlockSource,
    ) {
        let entry = BlockIndexEntry {
            hash,
            prev_hash,
            height,
            target,
            chainwork,
            status: BlockValidationStatus::HeaderValid,
            source,
            children: Vec::new(),
        };

        // Update parent's children list.
        if let Some(parent) = self.entries.get_mut(&prev_hash) {
            if !parent.children.contains(&hash) {
                parent.children.push(hash);
            }
        }

        // Add to height map.
        self.height_map.entry(height).or_default().push(hash);

        self.entries.insert(hash, entry);
    }

    /// Get an entry by hash.
    pub fn get(&self, hash: &Hash256) -> Option<&BlockIndexEntry> {
        self.entries.get(hash)
    }

    /// Get a mutable entry by hash.
    pub fn get_mut(&mut self, hash: &Hash256) -> Option<&mut BlockIndexEntry> {
        self.entries.get_mut(hash)
    }

    /// Update validation status.
    pub fn set_status(&mut self, hash: &Hash256, status: BlockValidationStatus) {
        if let Some(entry) = self.entries.get_mut(hash) {
            entry.status = status;
        }
    }

    /// Get all blocks at a specific height.
    pub fn get_at_height(&self, height: u32) -> Vec<Hash256> {
        self.height_map.get(&height).cloned().unwrap_or_default()
    }

    /// Get all children of a block.
    pub fn get_children(&self, hash: &Hash256) -> Vec<Hash256> {
        self.entries
            .get(hash)
            .map(|e| e.children.clone())
            .unwrap_or_default()
    }

    /// Check if a block exists.
    pub fn contains(&self, hash: &Hash256) -> bool {
        self.entries.contains_key(hash)
    }

    /// Get the best (highest chainwork) block at a given height.
    pub fn best_at_height(&self, height: u32) -> Option<Hash256> {
        self.height_map
            .get(&height)
            .and_then(|hashes| {
                hashes
                    .iter()
                    .max_by_key(|h| {
                        self.entries
                            .get(h)
                            .map(|e| e.chainwork)
                            .unwrap_or(0)
                    })
                    .copied()
            })
    }

    /// Get all fully valid blocks.
    pub fn fully_valid_blocks(&self) -> Vec<Hash256> {
        self.entries
            .iter()
            .filter(|(_, e)| e.status == BlockValidationStatus::FullyValid)
            .map(|(h, _)| *h)
            .collect()
    }

    /// Count total entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for BlockIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_index_creation() {
        let index = BlockIndex::new();
        assert!(index.is_empty());
    }

    #[test]
    fn test_block_index_insert() {
        let mut index = BlockIndex::new();
        let hash = Hash256::zero();
        let prev_hash = Hash256::zero();

        index.insert(hash, prev_hash, 0, 0x207fffff, 1, BlockSource::LocalMined);

        assert!(index.contains(&hash));
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn test_block_index_height_map() {
        let mut index = BlockIndex::new();
        let hash1 = Hash256::zero();
        let hash2 = Hash256::from_bytes([1u8; 32]);

        index.insert(hash1, Hash256::zero(), 0, 0x207fffff, 1, BlockSource::LocalMined);
        index.insert(hash2, hash1, 1, 0x207fffff, 2, BlockSource::Peer);

        assert_eq!(index.get_at_height(0).len(), 1);
        assert_eq!(index.get_at_height(1).len(), 1);
    }

    #[test]
    fn test_block_index_children() {
        let mut index = BlockIndex::new();
        let parent = Hash256::zero();
        let child = Hash256::from_bytes([1u8; 32]);

        index.insert(parent, Hash256::zero(), 0, 0x207fffff, 1, BlockSource::LocalMined);
        index.insert(child, parent, 1, 0x207fffff, 2, BlockSource::Peer);

        let children = index.get_children(&parent);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0], child);
    }
}
