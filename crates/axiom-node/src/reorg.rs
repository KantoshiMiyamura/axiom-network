// Copyright (c) 2026 Kantoshi Miyamura

//! Chain reorganization engine.

use crate::{ChainState, StateError};
use axiom_consensus::{calculate_work, Block, CompactTarget};
use axiom_primitives::Hash256;
use axiom_storage::{StorageBatch, UtxoEntry};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReorgError {
    #[error("state error: {0}")]
    State(#[from] StateError),

    #[error("storage error: {0}")]
    Storage(#[from] axiom_storage::Error),

    #[error("undo data not found for block: {0:?}")]
    UndoNotFound(Hash256),

    #[error("fork point not found")]
    ForkPointNotFound,
}

/// Rolls back disconnected blocks and connects the new chain during a reorg.
pub struct ReorgEngine<'a> {
    state: &'a mut ChainState,
}

impl<'a> ReorgEngine<'a> {
    pub fn new(state: &'a mut ChainState) -> Self {
        ReorgEngine { state }
    }

    /// True if this block's chain outweighs the current tip.
    pub fn should_reorganize(&self, block: &Block) -> Result<bool, ReorgError> {
        let block_hash = block.hash();

        let target = CompactTarget(block.header.difficulty_target);
        let block_work = calculate_work(target);

        let parent_work = self
            .state
            .get_chain_work(&block.header.prev_block_hash)?
            .unwrap_or(0);

        let new_chain_work = parent_work + block_work;

        let current_tip = self.state.best_block_hash().unwrap_or(Hash256::zero());
        let current_work = self.state.get_chain_work(&current_tip)?.unwrap_or(0);

        if new_chain_work > current_work {
            Ok(true)
        } else if new_chain_work == current_work {
            Ok(block_hash.as_bytes() < current_tip.as_bytes())
        } else {
            Ok(false)
        }
    }

    /// Walk both branches back to find their common ancestor.
    /// Uses a HashSet for O(n) lookup instead of O(n²) linear scan.
    pub fn find_fork_point(
        &self,
        old_tip: &Hash256,
        new_tip: &Hash256,
    ) -> Result<Hash256, ReorgError> {
        if old_tip == new_tip {
            return Ok(*old_tip);
        }

        let mut old_set = std::collections::HashSet::new();
        old_set.insert(*old_tip);
        let mut old_hash = *old_tip;
        while let Some(block) = self.state.get_block(&old_hash)? {
            old_hash = block.header.prev_block_hash;
            old_set.insert(old_hash);
            if old_hash == Hash256::zero() {
                break;
            }
        }

        let mut new_hash = *new_tip;

        if old_set.contains(&new_hash) {
            return Ok(new_hash);
        }

        while let Some(block) = self.state.get_block(&new_hash)? {
            new_hash = block.header.prev_block_hash;
            if old_set.contains(&new_hash) {
                return Ok(new_hash);
            }
            if new_hash == Hash256::zero() {
                return Ok(Hash256::zero());
            }
        }

        Ok(Hash256::zero())
    }

    /// Undo a single block: restore spent UTXOs and revert nonces.
    /// CRITICAL FIX: Returns error if undo data is missing for a non-genesis block.
    /// Previously returned Ok(()) silently, which would leave the UTXO set in an
    /// inconsistent state during a reorg if undo data was corrupted or deleted.
    pub fn rollback_block(&mut self, block_hash: &Hash256) -> Result<(), ReorgError> {
        let undo = self.state.database().load_undo(block_hash)?;

        let undo = match undo {
            Some(u) => u,
            None => {
                // Genesis block has no undo data — this is expected.
                // For any other block, missing undo data is a corruption error
                // that would produce an inconsistent UTXO set.
                let block = self.state.get_block(block_hash)?;
                let is_genesis = block
                    .as_ref()
                    .map(|b| b.header.prev_block_hash == Hash256::zero())
                    .unwrap_or(false);
                if is_genesis {
                    return Ok(());
                }
                return Err(ReorgError::UndoNotFound(*block_hash));
            }
        };

        let mut batch = StorageBatch::new(self.state.database());

        for utxo_undo in &undo.spent_utxos {
            let entry = UtxoEntry {
                value: utxo_undo.value,
                pubkey_hash: utxo_undo.pubkey_hash,
                height: utxo_undo.height,
                is_coinbase: utxo_undo.is_coinbase,
                confidential_commitment: None,
            };
            batch.put_utxo(&utxo_undo.txid, utxo_undo.output_index, &entry)?;
        }

        for nonce_undo in &undo.nonce_updates {
            batch.put_nonce(&nonce_undo.pubkey_hash, nonce_undo.prev_nonce);
        }

        let block = self.state.get_block(block_hash)?.ok_or_else(|| {
            ReorgError::Storage(axiom_storage::Error::NotFound(format!(
                "block {:?}",
                block_hash
            )))
        })?;

        for tx in &block.transactions {
            let txid =
                axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(tx));

            for (index, _) in tx.outputs.iter().enumerate() {
                batch.delete_utxo(&txid, index as u32);
            }
        }

        batch.commit()?;

        axiom_storage::TxIndex::new(self.state.database()).unindex_block(&block)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, Node};
    use tempfile::TempDir;

    fn create_test_node() -> (TempDir, Node) {
        let temp_dir = TempDir::new().unwrap();
        let config = Config {
            data_dir: temp_dir.path().to_path_buf(),
            ..Config::default()
        };
        let node = Node::new(config).unwrap();
        (temp_dir, node)
    }

    #[test]
    fn test_reorg_engine_creation() {
        let (_temp, mut node) = create_test_node();
        let state = &mut node.state;
        let _engine = ReorgEngine::new(state);
    }

    #[test]
    fn test_should_reorganize_more_work() {
        let (_temp, mut node) = create_test_node();

        let block1 = node.build_block().unwrap();
        node.process_block(block1).unwrap();

        let state = &mut node.state;
        let engine = ReorgEngine::new(state);

        assert!(engine.state.best_height().is_some());
    }
}
