// Copyright (c) 2026 Kantoshi Miyamura

// Transaction index: txid -> block location, pubkey_hash -> txids.
// index_block / unindex_block are called on canonical commit / rollback.
// Both operations are atomic (fjall batch).
//
// Key layout:
//   0x08 || txid[32]                    -> bincode(TxLocation)
//   0x09 || pubkey_hash[32] || txid[32] -> [] (presence = indexed)

use crate::{keys, Database, Error, Result};
use axiom_consensus::Block;
use axiom_primitives::Hash256;
use serde::{Deserialize, Serialize};

/// Location of a confirmed transaction on-chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxLocation {
    pub block_hash: Hash256,
    pub tx_position: u32,
    pub block_height: u32,
}

/// Transaction index backed by fjall.
pub struct TxIndex<'a> {
    db: &'a Database,
}

impl<'a> TxIndex<'a> {
    pub fn new(db: &'a Database) -> Self {
        TxIndex { db }
    }

    /// Index every transaction in `block` (called on canonical block commit).
    pub fn index_block(&self, block: &Block, block_height: u32) -> Result<()> {
        let block_hash = block.hash();
        let mut batch = self.db.keyspace().batch();

        for (pos, tx) in block.transactions.iter().enumerate() {
            let txid =
                axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(tx));

            let location = TxLocation {
                block_hash,
                tx_position: pos as u32,
                block_height,
            };
            let location_bytes =
                bincode::serde::encode_to_vec(&location, bincode::config::standard())
                    .map_err(|e| Error::Serialization(e.to_string()))?;
            batch.insert(
                self.db.partition(),
                keys::tx_location_key(&txid),
                location_bytes,
            );

            for output in &tx.outputs {
                batch.insert(
                    self.db.partition(),
                    keys::addr_tx_key(&output.pubkey_hash, &txid),
                    &[] as &[u8],
                );
            }

            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    let sender_hash = axiom_crypto::hash256(input.pubkey.as_bytes());
                    batch.insert(
                        self.db.partition(),
                        keys::addr_tx_key(&sender_hash, &txid),
                        &[] as &[u8],
                    );
                }
            }
        }

        batch.commit()?;
        Ok(())
    }

    /// Remove index entries for every transaction in `block` (called on rollback).
    pub fn unindex_block(&self, block: &Block) -> Result<()> {
        let mut batch = self.db.keyspace().batch();

        for tx in &block.transactions {
            let txid =
                axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(tx));

            batch.remove(self.db.partition(), keys::tx_location_key(&txid));

            for output in &tx.outputs {
                batch.remove(
                    self.db.partition(),
                    keys::addr_tx_key(&output.pubkey_hash, &txid),
                );
            }

            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    let sender_hash = axiom_crypto::hash256(input.pubkey.as_bytes());
                    batch.remove(self.db.partition(), keys::addr_tx_key(&sender_hash, &txid));
                }
            }
        }

        batch.commit()?;
        Ok(())
    }

    /// Return where a confirmed transaction is stored, or `None` if not indexed.
    pub fn get_tx_location(&self, txid: &Hash256) -> Result<Option<TxLocation>> {
        let key = keys::tx_location_key(txid);
        match self.db.partition().get(key)? {
            Some(value) => {
                let loc = bincode::serde::decode_from_slice(&value, bincode::config::standard())
                    .map(|(v, _)| v)
                    .map_err(|e| Error::Deserialization(e.to_string()))?;
                Ok(Some(loc))
            }
            None => Ok(None),
        }
    }

    /// Return all txids that involve `pubkey_hash`. Prefix scan over 0x09 || pubkey_hash.
    pub fn get_address_txids(&self, pubkey_hash: &Hash256) -> Result<Vec<Hash256>> {
        let prefix = keys::addr_tx_prefix(pubkey_hash);
        let txid_offset = prefix.len();

        let mut txids = Vec::new();

        for item in self.db.partition().prefix(&prefix) {
            let (key, _) = item?;
            if key.len() == txid_offset + 32 {
                let txid = Hash256::from_slice(&key[txid_offset..])
                    .map_err(|e| Error::Deserialization(e.to_string()))?;
                txids.push(txid);
            }
        }

        Ok(txids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;
    use axiom_consensus::{Block, BlockHeader};
    use axiom_primitives::Amount;
    use axiom_protocol::{Transaction, TxOutput};
    use tempfile::TempDir;

    fn open_db() -> (TempDir, Database) {
        let tmp = TempDir::new().unwrap();
        let db = Database::open(tmp.path()).unwrap();
        (tmp, db)
    }

    fn coinbase_block(pubkey_hash: Hash256) -> Block {
        let output = TxOutput {
            value: Amount::from_sat(5_000_000_000).unwrap(),
            pubkey_hash,
        };
        let coinbase = Transaction::new_coinbase(vec![output], 0);
        let serialized = axiom_protocol::serialize_transaction(&coinbase);
        let merkle_root = axiom_crypto::double_hash256(&serialized);
        Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: Hash256::zero(),
                merkle_root,
                timestamp: 1_700_000_000,
                difficulty_target: 0,
                nonce: 0,
            },
            transactions: vec![coinbase],
        }
    }

    #[test]
    fn test_index_block_stores_tx_location() {
        let (_tmp, db) = open_db();
        let pkh = Hash256::from_bytes([1u8; 32]);
        let block = coinbase_block(pkh);
        let txid = {
            let tx = &block.transactions[0];
            axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(tx))
        };

        let idx = TxIndex::new(&db);
        idx.index_block(&block, 0).unwrap();

        let loc = idx.get_tx_location(&txid).unwrap().unwrap();
        assert_eq!(loc.block_hash, block.hash());
        assert_eq!(loc.tx_position, 0);
        assert_eq!(loc.block_height, 0);
    }

    #[test]
    fn test_index_block_stores_address_entry() {
        let (_tmp, db) = open_db();
        let pkh = Hash256::from_bytes([2u8; 32]);
        let block = coinbase_block(pkh);
        let txid = {
            let tx = &block.transactions[0];
            axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(tx))
        };

        let idx = TxIndex::new(&db);
        idx.index_block(&block, 0).unwrap();

        let txids = idx.get_address_txids(&pkh).unwrap();
        assert_eq!(txids.len(), 1);
        assert_eq!(txids[0], txid);
    }

    #[test]
    fn test_unindex_block_removes_tx_location() {
        let (_tmp, db) = open_db();
        let pkh = Hash256::from_bytes([3u8; 32]);
        let block = coinbase_block(pkh);
        let txid = {
            let tx = &block.transactions[0];
            axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(tx))
        };

        let idx = TxIndex::new(&db);
        idx.index_block(&block, 0).unwrap();
        idx.unindex_block(&block).unwrap();

        assert!(idx.get_tx_location(&txid).unwrap().is_none());
    }

    #[test]
    fn test_unindex_block_removes_address_entry() {
        let (_tmp, db) = open_db();
        let pkh = Hash256::from_bytes([4u8; 32]);
        let block = coinbase_block(pkh);

        let idx = TxIndex::new(&db);
        idx.index_block(&block, 0).unwrap();
        idx.unindex_block(&block).unwrap();

        let txids = idx.get_address_txids(&pkh).unwrap();
        assert!(txids.is_empty());
    }

    #[test]
    fn test_get_tx_location_missing_returns_none() {
        let (_tmp, db) = open_db();
        let idx = TxIndex::new(&db);
        let result = idx.get_tx_location(&Hash256::zero()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_get_address_txids_empty() {
        let (_tmp, db) = open_db();
        let idx = TxIndex::new(&db);
        let txids = idx.get_address_txids(&Hash256::zero()).unwrap();
        assert!(txids.is_empty());
    }

    #[test]
    fn test_multiple_blocks_accumulate_address_history() {
        let (_tmp, db) = open_db();
        let pkh = Hash256::from_bytes([5u8; 32]);

        let make_block = |height_nonce: u32, prev: Hash256| {
            let output = TxOutput {
                value: Amount::from_sat(5_000_000_000).unwrap(),
                pubkey_hash: pkh,
            };
            let coinbase = Transaction::new_coinbase(vec![output], height_nonce);
            let merkle_root = axiom_crypto::double_hash256(
                &axiom_protocol::serialize_transaction_unsigned(&coinbase),
            );
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_block_hash: prev,
                    merkle_root,
                    timestamp: 1_700_000_000 + height_nonce,
                    difficulty_target: 0,
                    nonce: 0,
                },
                transactions: vec![coinbase],
            }
        };

        let block1 = make_block(0, Hash256::zero());
        let block2 = make_block(1, block1.hash());

        let idx = TxIndex::new(&db);
        idx.index_block(&block1, 0).unwrap();
        idx.index_block(&block2, 1).unwrap();

        let txids = idx.get_address_txids(&pkh).unwrap();
        assert_eq!(txids.len(), 2, "both blocks should be indexed for address");
    }

    #[test]
    fn test_restart_persistence() {
        let tmp = TempDir::new().unwrap();
        let pkh = Hash256::from_bytes([6u8; 32]);
        let block = coinbase_block(pkh);
        let txid = {
            let tx = &block.transactions[0];
            axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(tx))
        };

        {
            let db = Database::open(tmp.path()).unwrap();
            let idx = TxIndex::new(&db);
            idx.index_block(&block, 0).unwrap();
        }

        let db2 = Database::open(tmp.path()).unwrap();
        let idx2 = TxIndex::new(&db2);

        let loc = idx2.get_tx_location(&txid).unwrap().unwrap();
        assert_eq!(loc.block_hash, block.hash());

        let txids = idx2.get_address_txids(&pkh).unwrap();
        assert_eq!(txids.len(), 1);
    }
}
