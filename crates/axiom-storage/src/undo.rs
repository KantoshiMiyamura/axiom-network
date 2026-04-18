// Copyright (c) 2026 Kantoshi Miyamura

// Block undo data for chain reorganization.

use axiom_primitives::{Amount, Hash256};
use serde::{Deserialize, Serialize};

/// A UTXO that was spent by a block — restored on rollback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoUndo {
    pub txid: Hash256,
    pub output_index: u32,
    pub value: Amount,
    pub pubkey_hash: Hash256,
    pub height: u32,
    pub is_coinbase: bool,
}

/// Nonce state before a transaction was applied — restored on rollback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceUndo {
    pub pubkey_hash: Hash256,
    pub prev_nonce: u64,
}

/// All data needed to roll back a block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockUndo {
    pub block_hash: Hash256,
    pub height: u32,
    pub spent_utxos: Vec<UtxoUndo>,
    pub nonce_updates: Vec<NonceUndo>,
}

impl BlockUndo {
    pub fn new(block_hash: Hash256, height: u32) -> Self {
        BlockUndo {
            block_hash,
            height,
            spent_utxos: Vec::new(),
            nonce_updates: Vec::new(),
        }
    }

    pub fn add_spent_utxo(&mut self, undo: UtxoUndo) {
        self.spent_utxos.push(undo);
    }

    pub fn add_nonce_update(&mut self, undo: NonceUndo) {
        self.nonce_updates.push(undo);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_undo_creation() {
        let block_hash = Hash256::zero();
        let undo = BlockUndo::new(block_hash, 1);

        assert_eq!(undo.block_hash, block_hash);
        assert_eq!(undo.height, 1);
        assert!(undo.spent_utxos.is_empty());
        assert!(undo.nonce_updates.is_empty());
    }

    #[test]
    fn test_add_spent_utxo() {
        let mut undo = BlockUndo::new(Hash256::zero(), 1);

        let utxo_undo = UtxoUndo {
            txid: Hash256::zero(),
            output_index: 0,
            value: Amount::from_sat(1000).unwrap(),
            pubkey_hash: Hash256::zero(),
            height: 0,
            is_coinbase: false,
        };

        undo.add_spent_utxo(utxo_undo);
        assert_eq!(undo.spent_utxos.len(), 1);
    }

    #[test]
    fn test_add_nonce_update() {
        let mut undo = BlockUndo::new(Hash256::zero(), 1);

        let nonce_undo = NonceUndo {
            pubkey_hash: Hash256::zero(),
            prev_nonce: 5,
        };

        undo.add_nonce_update(nonce_undo);
        assert_eq!(undo.nonce_updates.len(), 1);
    }
}
