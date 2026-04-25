// Copyright (c) 2026 Kantoshi Miyamura

use crate::{keys, Database, Error, Result, UtxoEntry};
use axiom_consensus::Block;
use axiom_primitives::Hash256;
use axiom_protocol::Transaction;

/// Groups multiple storage writes into a single atomic commit.
pub struct StorageBatch<'a> {
    db: &'a crate::Database,
    batch: fjall::Batch,
}

impl<'a> StorageBatch<'a> {
    pub fn new(db: &'a Database) -> Self {
        StorageBatch {
            batch: db.keyspace().batch(),
            db,
        }
    }

    /// Stage a block write. Also writes the header-only key so it survives pruning.
    pub fn put_block(&mut self, block: &Block) -> Result<()> {
        let block_hash = block.hash();
        let block_value = bincode::serde::encode_to_vec(block, bincode::config::standard())
            .map_err(|e| Error::Serialization(e.to_string()))?;
        let header_value =
            bincode::serde::encode_to_vec(&block.header, bincode::config::standard())
                .map_err(|e| Error::Serialization(e.to_string()))?;

        self.batch.insert(
            self.db.partition(),
            keys::block_key(&block_hash),
            block_value,
        );
        self.batch.insert(
            self.db.partition(),
            keys::block_header_key(&block_hash),
            header_value,
        );
        Ok(())
    }

    pub fn put_transaction(&mut self, tx: &Transaction) -> Result<Hash256> {
        let txid =
            axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(tx));
        let key = keys::tx_key(&txid);
        let value = bincode::serde::encode_to_vec(tx, bincode::config::standard())
            .map_err(|e| Error::Serialization(e.to_string()))?;

        self.batch.insert(self.db.partition(), key, value);
        Ok(txid)
    }

    pub fn put_utxo(&mut self, txid: &Hash256, output_index: u32, entry: &UtxoEntry) -> Result<()> {
        let key = keys::utxo_key(txid, output_index);
        let value = bincode::serde::encode_to_vec(entry, bincode::config::standard())
            .map_err(|e| Error::Serialization(e.to_string()))?;

        self.batch.insert(self.db.partition(), key, value);
        Ok(())
    }

    pub fn delete_utxo(&mut self, txid: &Hash256, output_index: u32) {
        let key = keys::utxo_key(txid, output_index);
        self.batch.remove(self.db.partition(), key);
    }

    pub fn put_best_block_hash(&mut self, block_hash: &Hash256) {
        let key = keys::meta_key(keys::META_BEST_BLOCK_HASH);
        self.batch
            .insert(self.db.partition(), key, block_hash.as_bytes());
    }

    pub fn put_best_height(&mut self, height: u32) {
        let key = keys::meta_key(keys::META_BEST_HEIGHT);
        self.batch
            .insert(self.db.partition(), key, height.to_le_bytes());
    }

    pub fn put_nonce(&mut self, pubkey_hash: &Hash256, nonce: u64) {
        let key = keys::nonce_key(pubkey_hash);
        self.batch
            .insert(self.db.partition(), key, nonce.to_le_bytes());
    }

    pub fn put_chain_work(&mut self, block_hash: &Hash256, work: u128) {
        let key = keys::chain_work_key(block_hash);
        self.batch
            .insert(self.db.partition(), key, work.to_le_bytes());
    }

    pub fn put_undo(&mut self, undo: &crate::BlockUndo) -> Result<()> {
        let value = bincode::serde::encode_to_vec(undo, bincode::config::standard())
            .map_err(|e| Error::Serialization(e.to_string()))?;
        let key = keys::undo_key(&undo.block_hash);
        self.batch.insert(self.db.partition(), key, value);
        Ok(())
    }

    /// Stage tx-location and address-tx index entries for every transaction in `block`.
    /// Committed atomically with the rest of the block data.
    pub fn index_block_txs(&mut self, block: &Block, block_height: u32) -> Result<()> {
        let block_hash = block.hash();

        for (pos, tx) in block.transactions.iter().enumerate() {
            let txid =
                axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(tx));

            let location = crate::TxLocation {
                block_hash,
                tx_position: pos as u32,
                block_height,
            };
            let location_bytes =
                bincode::serde::encode_to_vec(&location, bincode::config::standard())
                    .map_err(|e| Error::Serialization(e.to_string()))?;
            self.batch.insert(
                self.db.partition(),
                keys::tx_location_key(&txid),
                location_bytes,
            );

            for output in &tx.outputs {
                self.batch.insert(
                    self.db.partition(),
                    keys::addr_tx_key(&output.pubkey_hash, &txid),
                    &[] as &[u8],
                );
            }

            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    let sender_hash = axiom_crypto::hash256(input.pubkey.as_bytes());
                    self.batch.insert(
                        self.db.partition(),
                        keys::addr_tx_key(&sender_hash, &txid),
                        &[] as &[u8],
                    );
                }
            }
        }

        Ok(())
    }

    pub fn put_height_index(&mut self, height: u32, block_hash: &Hash256) {
        self.batch.insert(
            self.db.partition(),
            keys::height_index_key(height),
            block_hash.as_bytes(),
        );
    }

    /// Commit all staged operations atomically.
    pub fn commit(self) -> Result<()> {
        self.batch.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_consensus::{Block, BlockHeader};
    use axiom_primitives::Amount;
    use axiom_protocol::{Transaction, TxOutput};
    use tempfile::TempDir;

    fn create_test_db() -> (TempDir, Database) {
        let temp_dir = TempDir::new().unwrap();
        let db = Database::open(temp_dir.path()).unwrap();
        (temp_dir, db)
    }

    #[test]
    fn test_batch_commit() {
        let (_temp, db) = create_test_db();

        let header = BlockHeader {
            version: 1,
            prev_block_hash: Hash256::zero(),
            merkle_root: Hash256::zero(),
            timestamp: 0,
            difficulty_target: 0,
            nonce: 0,
        };

        let output = TxOutput {
            value: Amount::from_sat(5_000_000_000).unwrap(),
            pubkey_hash: Hash256::zero(),
        };

        let coinbase = Transaction::new_coinbase(vec![output], 0);
        let block = Block {
            header,
            transactions: vec![coinbase],
        };

        let block_hash = block.hash();

        let mut batch = StorageBatch::new(&db);
        batch.put_block(&block).unwrap();
        batch.put_best_block_hash(&block_hash);
        batch.put_best_height(0);
        batch.commit().unwrap();

        assert!(db.has_block(&block_hash).unwrap());
        assert_eq!(db.get_best_height().unwrap(), Some(0));
    }

    #[test]
    fn test_batch_utxo_operations() {
        let (_temp, db) = create_test_db();

        let txid = Hash256::from_bytes([1u8; 32]);
        let entry = UtxoEntry {
            value: Amount::from_sat(1000).unwrap(),
            pubkey_hash: Hash256::zero(),
            height: 100,
            is_coinbase: false,
            confidential_commitment: None,
        };

        let mut batch = StorageBatch::new(&db);
        batch.put_utxo(&txid, 0, &entry).unwrap();
        batch.commit().unwrap();

        let utxo_set = crate::UtxoSet::new(&db);
        assert!(utxo_set.has_utxo(&txid, 0).unwrap());

        let mut batch2 = StorageBatch::new(&db);
        batch2.delete_utxo(&txid, 0);
        batch2.commit().unwrap();

        assert!(!utxo_set.has_utxo(&txid, 0).unwrap());
    }
}
