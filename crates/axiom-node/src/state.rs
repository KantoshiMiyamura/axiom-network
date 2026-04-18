// Copyright (c) 2026 Kantoshi Miyamura

use axiom_consensus::Block;
use axiom_primitives::Hash256;
use axiom_storage::{Database, StorageBatch, UtxoEntry};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StateError {
    #[error("genesis not initialized")]
    GenesisNotInitialized,

    #[error("genesis already initialized")]
    GenesisAlreadyInitialized,

    #[error("block not found: {0}")]
    BlockNotFound(String),

    #[error("storage error: {0}")]
    Storage(#[from] axiom_storage::Error),

    #[error("consensus error: {0}")]
    Consensus(#[from] axiom_consensus::Error),

    #[error("protocol error: {0}")]
    Protocol(#[from] axiom_protocol::Error),
}

/// Tracks the canonical chain tip and wraps the on-disk database.
pub struct ChainState {
    db: Database,
    pub(crate) best_block_hash: Option<Hash256>,
    pub(crate) best_height: Option<u32>,
}

impl ChainState {
    pub fn new(db: Database) -> Result<Self, StateError> {
        let best_block_hash = db.get_best_block_hash()?;
        let best_height = db.get_best_height()?;

        Ok(ChainState {
            db,
            best_block_hash,
            best_height,
        })
    }

    pub fn is_genesis_initialized(&self) -> Result<bool, StateError> {
        Ok(self.db.get_genesis_hash()?.is_some())
    }

    pub fn initialize_genesis(&mut self, genesis: &Block) -> Result<(), StateError> {
        if self.is_genesis_initialized()? {
            return Err(StateError::GenesisAlreadyInitialized);
        }

        let genesis_hash = genesis.hash();

        axiom_consensus::validate_block_structure(genesis)?;

        let mut batch = StorageBatch::new(&self.db);

        batch.put_block(genesis)?;

        for tx in &genesis.transactions {
            let txid = batch.put_transaction(tx)?;

            for (index, output) in tx.outputs.iter().enumerate() {
                let entry = UtxoEntry::from_output(output, 0, true);
                batch.put_utxo(&txid, index as u32, &entry)?;
            }
        }

        self.db.set_genesis_hash(&genesis_hash)?;

        batch.put_best_block_hash(&genesis_hash);
        batch.put_best_height(0);

        // Store genesis block's chainwork
        let genesis_target = axiom_consensus::CompactTarget(genesis.header.difficulty_target);
        let genesis_work = axiom_consensus::calculate_work(genesis_target);
        // Only store if reasonable (not overflow-prone)
        if genesis_work < u128::MAX / 2 {
            batch.put_chain_work(&genesis_hash, genesis_work);
        }

        batch.index_block_txs(genesis, 0)?;

        batch.put_height_index(0, &genesis_hash);

        batch.commit()?;

        self.best_block_hash = Some(genesis_hash);
        self.best_height = Some(0);

        Ok(())
    }

    /// Apply a block: update UTXOs, nonces, and chain work in one atomic batch.
    pub fn apply_block(&mut self, block: &Block) -> Result<(), StateError> {
        let block_hash = block.hash();
        let height = self.best_height.unwrap_or(0) + 1;

        let prev_hash = self.best_block_hash.unwrap_or(Hash256::zero());
        let prev_timestamps = self.get_prev_timestamps(11)?;
        let validator = axiom_consensus::ConsensusValidator::new(prev_hash, height)
            .with_prev_timestamps(prev_timestamps);
        validator.validate_block(block)?;

        let target = axiom_consensus::CompactTarget(block.header.difficulty_target);
        let block_work = axiom_consensus::calculate_work(target);

        let prev_work = if let Some(prev_hash) = self.best_block_hash {
            self.db.load_chain_work(&prev_hash)?.unwrap_or(0)
        } else {
            0
        };

        let cumulative_work = prev_work.checked_add(block_work).ok_or_else(|| {
            StateError::Consensus(axiom_consensus::Error::InvalidBlock(
                "chainwork overflow".into(),
            ))
        })?;

        let mut undo = axiom_storage::BlockUndo::new(block_hash, height);

        let mut batch = StorageBatch::new(&self.db);

        batch.put_block(block)?;

        batch.put_chain_work(&block_hash, cumulative_work);

        let utxo_set = axiom_storage::UtxoSet::new(&self.db);
        let nonce_tracker = axiom_storage::NonceTracker::new(&self.db);

        let mut spent_in_block: std::collections::HashSet<(axiom_primitives::Hash256, u32)> =
            std::collections::HashSet::new();

        // Track actual fees from UTXO lookups for coinbase validation
        let mut total_fees_sat: u64 = 0;

        for tx in &block.transactions {
            let txid = batch.put_transaction(tx)?;

            if !tx.is_coinbase() {
                // Sum input values from UTXO set for fee calculation
                let mut tx_input_sat: u64 = 0;

                for input in &tx.inputs {
                    let key = (input.prev_tx_hash, input.prev_output_index);
                    if spent_in_block.contains(&key) {
                        return Err(StateError::Consensus(axiom_consensus::Error::InvalidBlock(
                            "intra-block double-spend detected".into(),
                        )));
                    }
                    spent_in_block.insert(key);
                    if let Some(utxo_entry) =
                        utxo_set.get_utxo(&input.prev_tx_hash, input.prev_output_index)?
                    {
                        tx_input_sat = tx_input_sat.checked_add(utxo_entry.value.as_sat()).ok_or_else(|| {
                            StateError::Consensus(axiom_consensus::Error::InvalidBlock(
                                "input value overflow".into(),
                            ))
                        })?;

                        let utxo_undo = axiom_storage::UtxoUndo {
                            txid: input.prev_tx_hash,
                            output_index: input.prev_output_index,
                            value: utxo_entry.value,
                            pubkey_hash: utxo_entry.pubkey_hash,
                            height: utxo_entry.height,
                            is_coinbase: utxo_entry.is_coinbase,
                        };
                        undo.add_spent_utxo(utxo_undo);
                    }

                    batch.delete_utxo(&input.prev_tx_hash, input.prev_output_index);
                }

                let tx_output_value = tx.output_value()
                    .map_err(|e| StateError::Consensus(axiom_consensus::Error::InvalidBlock(
                        format!("transaction output value error: {}", e),
                    )))?;
                let tx_output_sat = tx_output_value.as_sat();

                // Fee = inputs - outputs (must be non-negative)
                if tx_input_sat < tx_output_sat {
                    return Err(StateError::Consensus(axiom_consensus::Error::InvalidBlock(
                        format!("transaction outputs ({}) exceed inputs ({})", tx_output_sat, tx_input_sat),
                    )));
                }
                let tx_fee = tx_input_sat - tx_output_sat;
                total_fees_sat = total_fees_sat.checked_add(tx_fee).ok_or_else(|| {
                    StateError::Consensus(axiom_consensus::Error::InvalidBlock(
                        "total fees overflow".into(),
                    ))
                })?;

                let pubkey_hash = axiom_crypto::hash256(tx.inputs[0].pubkey.as_bytes());
                let prev_nonce = nonce_tracker.get_nonce(&pubkey_hash)?.unwrap_or(0);

                let nonce_undo = axiom_storage::NonceUndo {
                    pubkey_hash,
                    prev_nonce,
                };
                undo.add_nonce_update(nonce_undo);

                batch.put_nonce(&pubkey_hash, tx.nonce.checked_add(1).ok_or_else(|| {
                    StateError::Consensus(axiom_consensus::Error::InvalidBlock(
                        "nonce overflow".into(),
                    ))
                })?);
            }

            for (index, output) in tx.outputs.iter().enumerate() {
                let entry = UtxoEntry::from_output(output, height, tx.is_coinbase());
                batch.put_utxo(&txid, index as u32, &entry)?;
            }
        }

        // CRITICAL: Validate coinbase value against block_reward + actual UTXO-derived fees.
        // This prevents miners from inflating the money supply.
        let coinbase = &block.transactions[0];
        let coinbase_value = coinbase.output_value()
            .map_err(|e| StateError::Consensus(axiom_consensus::Error::InvalidBlock(
                format!("coinbase output value error: {}", e),
            )))?;
        let block_reward = axiom_consensus::calculate_block_reward(height);
        let total_fees = axiom_primitives::Amount::from_sat(total_fees_sat)
            .map_err(|e| StateError::Consensus(axiom_consensus::Error::InvalidBlock(
                format!("fee amount error: {}", e),
            )))?;
        let max_coinbase = block_reward.checked_add(total_fees)
            .map_err(|e| StateError::Consensus(axiom_consensus::Error::InvalidBlock(
                format!("max coinbase overflow: {}", e),
            )))?;
        if coinbase_value > max_coinbase {
            return Err(StateError::Consensus(axiom_consensus::Error::InvalidBlock(
                format!(
                    "coinbase value {} exceeds reward {} + fees {} = {} at height {} (overpay: {} sat)",
                    coinbase_value.as_sat(),
                    block_reward.as_sat(),
                    total_fees_sat,
                    max_coinbase.as_sat(),
                    height,
                    coinbase_value.as_sat() as i64 - max_coinbase.as_sat() as i64,
                ),
            )));
        }

        batch.put_best_block_hash(&block_hash);
        batch.put_best_height(height);

        batch.put_undo(&undo)?;
        batch.index_block_txs(block, height)?;
        batch.put_height_index(height, &block_hash);

        batch.commit()?;

        self.best_block_hash = Some(block_hash);
        self.best_height = Some(height);

        Ok(())
    }

    /// Last `n` block timestamps, oldest first; used to compute Median Time Past.
    pub(crate) fn get_prev_timestamps(&self, n: usize) -> Result<Vec<u64>, StateError> {
        let cursor = match self.best_block_hash {
            Some(h) => h,
            None => return Ok(Vec::new()),
        };
        self.get_prev_timestamps_from(cursor, n)
    }

    /// Last `n` block timestamps walking back from `start_hash`, oldest first.
    /// CRITICAL FIX: Fork blocks must also be validated against MTP.
    /// Without this method, `handle_fork()` had no way to get timestamps for
    /// the fork's parent chain, so fork blocks bypassed MTP validation entirely.
    pub(crate) fn get_prev_timestamps_from(
        &self,
        start_hash: Hash256,
        n: usize,
    ) -> Result<Vec<u64>, StateError> {
        let mut timestamps = Vec::with_capacity(n);
        let mut cursor = start_hash;

        for _ in 0..n {
            let header = match self.db.load_block_header(&cursor) {
                Ok(h) => h,
                Err(axiom_storage::Error::NotFound(_)) => break,
                Err(e) => return Err(StateError::Storage(e)),
            };
            timestamps.push(header.timestamp as u64);
            if header.prev_block_hash == Hash256::zero() {
                break;
            }
            cursor = header.prev_block_hash;
        }

        timestamps.reverse();
        Ok(timestamps)
    }

    pub fn best_block_hash(&self) -> Option<Hash256> {
        self.best_block_hash
    }

    pub fn best_height(&self) -> Option<u32> {
        self.best_height
    }

    pub fn database(&self) -> &Database {
        &self.db
    }

    pub fn get_block(&self, block_hash: &Hash256) -> Result<Option<Block>, StateError> {
        match self.db.load_block(block_hash) {
            Ok(block) => Ok(Some(block)),
            Err(axiom_storage::Error::NotFound(_)) => Ok(None),
            Err(e) => Err(StateError::Storage(e)),
        }
    }

    pub fn has_block(&self, block_hash: &Hash256) -> Result<bool, StateError> {
        Ok(self.db.has_block(block_hash)?)
    }

    pub fn get_chain_work(&self, block_hash: &Hash256) -> Result<Option<u128>, StateError> {
        Ok(self.db.load_chain_work(block_hash)?)
    }

    pub fn db_get_hash_by_height(&self, height: u32) -> Result<Option<Hash256>, StateError> {
        Ok(self.db.get_hash_by_height(height)?)
    }

    pub fn db_store_height_index(&self, height: u32, hash: &Hash256) -> Result<(), StateError> {
        Ok(self.db.store_height_index(height, hash)?)
    }

    pub fn db_load_block_header(&self, hash: &Hash256) -> Result<axiom_consensus::BlockHeader, StateError> {
        Ok(self.db.load_block_header(hash)?)
    }

    /// Required difficulty target for the next block.
    pub fn get_next_difficulty_target(&self, next_height: u32) -> Result<u32, StateError> {
        let prev_hash = self.best_block_hash.unwrap_or(Hash256::zero());
        self.get_next_difficulty_target_from_parent(prev_hash, next_height)
    }

    /// LWMA-3 difficulty retarget from an arbitrary parent hash.
    pub fn get_next_difficulty_target_from_parent(
        &self,
        parent_hash: Hash256,
        next_height: u32,
    ) -> Result<u32, StateError> {
        use axiom_consensus::{calculate_lwma_target, CompactTarget, LWMA_WINDOW};

        let n = LWMA_WINDOW as usize;

        if next_height == 0 || parent_hash == Hash256::zero() {
            return Ok(CompactTarget::initial().0);
        }

        let parent_block = match self.get_block(&parent_hash)? {
            Some(b) => b,
            None => return Ok(CompactTarget::initial().0),
        };

        if (next_height as usize) < n {
            return Ok(parent_block.header.difficulty_target);
        }

        let mut timestamps = Vec::with_capacity(n + 1);
        let mut targets = Vec::with_capacity(n);

        timestamps.push(parent_block.header.timestamp as u64);
        targets.push(CompactTarget(parent_block.header.difficulty_target));

        let mut current = parent_block;
        for _ in 1..n {
            let ph = current.header.prev_block_hash;
            if ph == Hash256::zero() {
                return Ok(targets.last().unwrap().0);
            }
            current = match self.get_block(&ph)? {
                Some(b) => b,
                None => {
                    return Ok(targets.last().unwrap().0);
                }
            };
            timestamps.push(current.header.timestamp as u64);
            targets.push(CompactTarget(current.header.difficulty_target));
        }

        let oldest_ph = current.header.prev_block_hash;
        if oldest_ph == Hash256::zero() {
            return Ok(targets.last().unwrap().0);
        }
        let oldest = match self.get_block(&oldest_ph)? {
            Some(b) => b,
            None => return Ok(targets.last().unwrap().0),
        };
        timestamps.push(oldest.header.timestamp as u64);

        timestamps.reverse();
        targets.reverse();

        let new_target = calculate_lwma_target(&timestamps, &targets);
        Ok(new_target.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_consensus::BlockHeader;
    use axiom_primitives::Amount;
    use axiom_protocol::{Transaction, TxOutput};
    use tempfile::TempDir;

    fn create_test_state() -> (TempDir, ChainState) {
        let temp_dir = TempDir::new().unwrap();
        let db = Database::open(temp_dir.path()).unwrap();
        let state = ChainState::new(db).unwrap();
        (temp_dir, state)
    }

    fn create_genesis() -> Block {
        let output = TxOutput {
            value: Amount::from_sat(5_000_000_000).unwrap(),
            pubkey_hash: Hash256::zero(),
        };
        let coinbase = Transaction::new_coinbase(vec![output], 0);
        let merkle_root = axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(&coinbase));

        let header = BlockHeader {
            version: 1,
            prev_block_hash: Hash256::zero(),
            merkle_root,
            timestamp: 0,
            difficulty_target: 0,
            nonce: 0,
        };

        Block {
            header,
            transactions: vec![coinbase],
        }
    }

    #[test]
    fn test_genesis_initialization() {
        let (_temp, mut state) = create_test_state();

        assert!(!state.is_genesis_initialized().unwrap());

        let genesis = create_genesis();
        state.initialize_genesis(&genesis).unwrap();

        assert!(state.is_genesis_initialized().unwrap());
        assert_eq!(state.best_height(), Some(0));
        assert_eq!(state.best_block_hash(), Some(genesis.hash()));
    }

    #[test]
    fn test_genesis_already_initialized() {
        let (_temp, mut state) = create_test_state();

        let genesis = create_genesis();
        state.initialize_genesis(&genesis).unwrap();

        let result = state.initialize_genesis(&genesis);
        assert!(matches!(result, Err(StateError::GenesisAlreadyInitialized)));
    }
}
