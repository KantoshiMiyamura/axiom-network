// Copyright (c) 2026 Kantoshi Miyamura

use axiom_primitives::Hash256;
use axiom_protocol::Transaction;
use serde::{Deserialize, Serialize};

/// Block header with PoW fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub prev_block_hash: Hash256,
    pub merkle_root: Hash256,
    /// Unix timestamp.
    pub timestamp: u32,
    /// Compact difficulty target.
    pub difficulty_target: u32,
    pub nonce: u32,
}

impl BlockHeader {
    /// SHA256d of the serialized header.
    pub fn hash(&self) -> Hash256 {
        let serialized = self.serialize();
        axiom_crypto::double_hash256(&serialized)
    }

    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(self.prev_block_hash.as_bytes());
        bytes.extend_from_slice(self.merkle_root.as_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.difficulty_target.to_le_bytes());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes
    }
}

/// Block header plus transaction list. First transaction must be coinbase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn hash(&self) -> Hash256 {
        self.header.hash()
    }

    /// Height encoded in coinbase nonce, or None if no coinbase.
    pub fn height(&self) -> Option<u32> {
        self.transactions
            .first()
            .filter(|tx| tx.is_coinbase())
            .map(|tx| tx.nonce as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_header_hash_deterministic() {
        let header = BlockHeader {
            version: 1,
            prev_block_hash: Hash256::zero(),
            merkle_root: Hash256::zero(),
            timestamp: 1234567890,
            difficulty_target: 0x1d00ffff,
            nonce: 0,
        };

        let hash1 = header.hash();
        let hash2 = header.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_block_header_different_nonce() {
        let header1 = BlockHeader {
            version: 1,
            prev_block_hash: Hash256::zero(),
            merkle_root: Hash256::zero(),
            timestamp: 1234567890,
            difficulty_target: 0x1d00ffff,
            nonce: 0,
        };

        let header2 = BlockHeader {
            nonce: 1,
            ..header1
        };

        assert_ne!(header1.hash(), header2.hash());
    }
}
