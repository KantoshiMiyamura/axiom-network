// Copyright (c) 2026 Kantoshi Miyamura

use crate::{keys, Error, Result};
use axiom_consensus::{Block, BlockHeader};
use axiom_primitives::Hash256;
use axiom_protocol::Transaction;
use fjall::{Config, PartitionCreateOptions};
use std::path::Path;

pub struct Database {
    keyspace: fjall::Keyspace,
    partition: fjall::PartitionHandle,
}

impl Database {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let keyspace = Config::new(path).open()?;
        let partition = keyspace.open_partition("main", PartitionCreateOptions::default())?;
        Ok(Database {
            keyspace,
            partition,
        })
    }
    pub(crate) fn partition(&self) -> &fjall::PartitionHandle {
        &self.partition
    }
    pub(crate) fn keyspace(&self) -> &fjall::Keyspace {
        &self.keyspace
    }

    // ── Block storage ────────────────────────────────────────────────────────

    /// Store a full block and its header. Dual-write so the header survives pruning.
    pub fn store_block(&self, block: &Block) -> Result<()> {
        let block_hash = block.hash();
        let block_value = bincode::serde::encode_to_vec(block, bincode::config::standard())
            .map_err(|e| Error::Serialization(e.to_string()))?;
        let header_value =
            bincode::serde::encode_to_vec(&block.header, bincode::config::standard())
                .map_err(|e| Error::Serialization(e.to_string()))?;

        let mut batch = self.keyspace.batch();
        batch.insert(&self.partition, keys::block_key(&block_hash), block_value);
        batch.insert(
            &self.partition,
            keys::block_header_key(&block_hash),
            header_value,
        );
        batch.commit()?;
        Ok(())
    }

    pub fn load_block(&self, block_hash: &Hash256) -> Result<Block> {
        let key = keys::block_key(block_hash);
        let value = self
            .partition
            .get(key)?
            .ok_or_else(|| Error::NotFound(format!("block {:?}", block_hash)))?;
        bincode::serde::decode_from_slice(&value, bincode::config::standard())
            .map(|(v, _)| v)
            .map_err(|e| Error::Deserialization(e.to_string()))
    }

    pub fn has_block(&self, block_hash: &Hash256) -> Result<bool> {
        Ok(self.partition.contains_key(keys::block_key(block_hash))?)
    }

    /// Load the block header. Tries the header-only key first (fast path for pruned blocks).
    pub fn load_block_header(&self, block_hash: &Hash256) -> Result<BlockHeader> {
        let header_key = keys::block_header_key(block_hash);
        if let Some(v) = self.partition.get(&header_key)? {
            return bincode::serde::decode_from_slice(&v, bincode::config::standard())
                .map(|(h, _)| h)
                .map_err(|e| Error::Deserialization(e.to_string()));
        }
        let block = self.load_block(block_hash)?;
        Ok(block.header)
    }

    /// True if the block body has been pruned but its header still exists.
    pub fn is_block_pruned(&self, block_hash: &Hash256) -> Result<bool> {
        if self.partition.contains_key(keys::block_key(block_hash))? {
            return Ok(false);
        }
        Ok(self
            .partition
            .contains_key(keys::block_header_key(block_hash))?)
    }

    // ── Transaction storage ──────────────────────────────────────────────────

    pub fn store_transaction(&self, tx: &Transaction) -> Result<Hash256> {
        let txid =
            axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(tx));
        let value = bincode::serde::encode_to_vec(tx, bincode::config::standard())
            .map_err(|e| Error::Serialization(e.to_string()))?;
        self.partition.insert(keys::tx_key(&txid), value)?;
        Ok(txid)
    }

    pub fn load_transaction(&self, txid: &Hash256) -> Result<Transaction> {
        let value = self
            .partition
            .get(keys::tx_key(txid))?
            .ok_or_else(|| Error::NotFound(format!("transaction {:?}", txid)))?;
        bincode::serde::decode_from_slice(&value, bincode::config::standard())
            .map(|(v, _)| v)
            .map_err(|e| Error::Deserialization(e.to_string()))
    }

    pub fn has_transaction(&self, txid: &Hash256) -> Result<bool> {
        Ok(self.partition.contains_key(keys::tx_key(txid))?)
    }

    // ── Chain metadata ───────────────────────────────────────────────────────

    pub fn get_best_block_hash(&self) -> Result<Option<Hash256>> {
        match self
            .partition
            .get(keys::meta_key(keys::META_BEST_BLOCK_HASH))?
        {
            Some(v) if v.len() == 32 => Ok(Some(Hash256::from_slice(&v)?)),
            Some(v) => Err(Error::Corruption(format!(
                "bad best_block_hash len {}",
                v.len()
            ))),
            None => Ok(None),
        }
    }
    pub fn set_best_block_hash(&self, h: &Hash256) -> Result<()> {
        self.partition
            .insert(keys::meta_key(keys::META_BEST_BLOCK_HASH), h.as_bytes())?;
        Ok(())
    }
    pub fn get_best_height(&self) -> Result<Option<u32>> {
        match self.partition.get(keys::meta_key(keys::META_BEST_HEIGHT))? {
            Some(v) if v.len() == 4 => Ok(Some(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))),
            Some(v) => Err(Error::Corruption(format!(
                "bad best_height len {}",
                v.len()
            ))),
            None => Ok(None),
        }
    }
    pub fn set_best_height(&self, height: u32) -> Result<()> {
        self.partition
            .insert(keys::meta_key(keys::META_BEST_HEIGHT), height.to_le_bytes())?;
        Ok(())
    }
    pub fn get_genesis_hash(&self) -> Result<Option<Hash256>> {
        match self
            .partition
            .get(keys::meta_key(keys::META_GENESIS_HASH))?
        {
            Some(v) if v.len() == 32 => Ok(Some(Hash256::from_slice(&v)?)),
            Some(v) => Err(Error::Corruption(format!(
                "bad genesis_hash len {}",
                v.len()
            ))),
            None => Ok(None),
        }
    }
    pub fn set_genesis_hash(&self, h: &Hash256) -> Result<()> {
        let key = keys::meta_key(keys::META_GENESIS_HASH);
        if self.partition.contains_key(&key)? {
            return Err(Error::Corruption("genesis hash already set".into()));
        }
        self.partition.insert(key, h.as_bytes())?;
        Ok(())
    }

    // ── Height index ─────────────────────────────────────────────────────────

    pub fn store_height_index(&self, height: u32, block_hash: &Hash256) -> Result<()> {
        self.partition
            .insert(keys::height_index_key(height), block_hash.as_bytes())?;
        Ok(())
    }

    pub fn get_hash_by_height(&self, height: u32) -> Result<Option<Hash256>> {
        match self.partition.get(keys::height_index_key(height))? {
            Some(v) if v.len() == 32 => Ok(Some(Hash256::from_slice(&v)?)),
            Some(v) => Err(Error::Corruption(format!(
                "bad height-index value len {} at height {}",
                v.len(),
                height
            ))),
            None => Ok(None),
        }
    }

    pub fn flush(&self) -> Result<()> {
        self.keyspace.persist(fjall::PersistMode::SyncData)?;
        Ok(())
    }

    // ── Chain work ───────────────────────────────────────────────────────────

    pub fn store_chain_work(&self, block_hash: &Hash256, work: u128) -> Result<()> {
        self.partition
            .insert(keys::chain_work_key(block_hash), work.to_le_bytes())?;
        Ok(())
    }
    pub fn load_chain_work(&self, block_hash: &Hash256) -> Result<Option<u128>> {
        match self.partition.get(keys::chain_work_key(block_hash))? {
            Some(v) if v.len() == 16 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&v);
                Ok(Some(u128::from_le_bytes(b)))
            }
            Some(v) => Err(Error::Corruption(format!("bad chain_work len {}", v.len()))),
            None => Ok(None),
        }
    }

    // ── Undo data ────────────────────────────────────────────────────────────

    pub fn store_undo(&self, undo: &crate::BlockUndo) -> Result<()> {
        let value = bincode::serde::encode_to_vec(undo, bincode::config::standard())
            .map_err(|e| Error::Serialization(e.to_string()))?;
        self.partition
            .insert(keys::undo_key(&undo.block_hash), value)?;
        Ok(())
    }
    pub fn load_undo(&self, block_hash: &Hash256) -> Result<Option<crate::BlockUndo>> {
        match self.partition.get(keys::undo_key(block_hash))? {
            Some(v) => {
                let undo = bincode::serde::decode_from_slice(&v, bincode::config::standard())
                    .map(|(x, _)| x)
                    .map_err(|e| Error::Deserialization(e.to_string()))?;
                Ok(Some(undo))
            }
            None => Ok(None),
        }
    }

    // ── Pruning ──────────────────────────────────────────────────────────────

    /// Remove the full block body, its transactions, and undo data.
    /// Header is preserved under the header-only key. UTXO set, nonces, chain
    /// work, and index entries are never touched. Idempotent.
    pub fn prune_block_data(&self, block_hash: &Hash256) -> Result<()> {
        let block = match self.load_block(block_hash) {
            Ok(b) => b,
            Err(Error::NotFound(_)) => return Ok(()),
            Err(e) => return Err(e),
        };

        let txids: Vec<Hash256> = block
            .transactions
            .iter()
            .map(|tx| {
                axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(tx))
            })
            .collect();

        let header_value =
            bincode::serde::encode_to_vec(&block.header, bincode::config::standard())
                .map_err(|e| Error::Serialization(e.to_string()))?;

        let mut batch = self.keyspace.batch();
        batch.insert(
            &self.partition,
            keys::block_header_key(block_hash),
            header_value,
        );
        batch.remove(&self.partition, keys::block_key(block_hash));
        batch.remove(&self.partition, keys::undo_key(block_hash));
        for txid in &txids {
            batch.remove(&self.partition, keys::tx_key(txid));
        }
        batch.commit()?;

        Ok(())
    }

    /// Prune all block bodies older than `prune_depth` blocks from the tip.
    /// Preserves: UTXO set, headers, chain work, tx location index, address-tx index.
    /// Returns the number of blocks pruned.
    pub fn prune_to_depth(&self, prune_depth: u32) -> Result<usize> {
        let best_height = match self.get_best_height()? {
            Some(h) => h,
            None => return Ok(0),
        };
        let best_hash = match self.get_best_block_hash()? {
            Some(h) => h,
            None => return Ok(0),
        };

        if best_height <= prune_depth {
            return Ok(0);
        }

        // Walk back prune_depth steps to find the oldest block to keep.
        let mut keep_cursor = best_hash;
        for _ in 0..prune_depth {
            let header = self.load_block_header(&keep_cursor)?;
            if header.prev_block_hash == Hash256::zero() {
                return Ok(0);
            }
            keep_cursor = header.prev_block_hash;
        }
        let boundary_header = self.load_block_header(&keep_cursor)?;
        if boundary_header.prev_block_hash == Hash256::zero() {
            return Ok(0);
        }

        let mut current = boundary_header.prev_block_hash;
        let mut count = 0usize;

        loop {
            let header = match self.load_block_header(&current) {
                Ok(h) => h,
                Err(Error::NotFound(_)) => break,
                Err(e) => return Err(e),
            };

            // Never prune genesis.
            if header.prev_block_hash == Hash256::zero() {
                break;
            }

            // Already pruned — older blocks should be too.
            if self.is_block_pruned(&current)? {
                break;
            }

            let prev = header.prev_block_hash;
            self.prune_block_data(&current)?;
            count += 1;
            current = prev;
        }

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_consensus::BlockHeader;
    use axiom_primitives::Amount;
    use axiom_protocol::{Transaction, TxOutput};
    use tempfile::TempDir;

    fn open_db() -> (TempDir, Database) {
        let tmp = TempDir::new().unwrap();
        let db = Database::open(tmp.path()).unwrap();
        (tmp, db)
    }

    fn make_coinbase_block(prev_hash: Hash256, height_nonce: u32) -> Block {
        let output = TxOutput {
            value: Amount::from_sat(5_000_000_000).unwrap(),
            pubkey_hash: Hash256::zero(),
        };
        let coinbase = Transaction::new_coinbase(vec![output], height_nonce);
        let merkle_root = axiom_crypto::double_hash256(
            &axiom_protocol::serialize_transaction_unsigned(&coinbase),
        );
        Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: prev_hash,
                merkle_root,
                timestamp: 1_700_000_000 + height_nonce,
                difficulty_target: 0,
                nonce: 0,
            },
            transactions: vec![coinbase],
        }
    }

    #[test]
    fn test_store_block_writes_header_key() {
        let (_tmp, db) = open_db();
        let block = make_coinbase_block(Hash256::zero(), 0);
        let hash = block.hash();

        db.store_block(&block).unwrap();

        assert!(db.has_block(&hash).unwrap());
        let header = db.load_block_header(&hash).unwrap();
        assert_eq!(header.prev_block_hash, Hash256::zero());
    }

    #[test]
    fn test_load_block_header_from_header_key_after_prune() {
        let (_tmp, db) = open_db();
        let block = make_coinbase_block(Hash256::zero(), 0);
        let hash = block.hash();

        db.store_block(&block).unwrap();

        let block2 = make_coinbase_block(hash, 1);
        let hash2 = block2.hash();
        db.store_block(&block2).unwrap();

        db.prune_block_data(&hash2).unwrap();

        assert!(!db.has_block(&hash2).unwrap());
        assert!(db.is_block_pruned(&hash2).unwrap());

        let h = db.load_block_header(&hash2).unwrap();
        assert_eq!(h.prev_block_hash, hash);
    }

    #[test]
    fn test_is_block_pruned_false_for_full_block() {
        let (_tmp, db) = open_db();
        let block = make_coinbase_block(Hash256::zero(), 0);
        let hash = block.hash();
        db.store_block(&block).unwrap();
        assert!(!db.is_block_pruned(&hash).unwrap());
    }

    #[test]
    fn test_is_block_pruned_false_for_unknown_block() {
        let (_tmp, db) = open_db();
        assert!(!db.is_block_pruned(&Hash256::zero()).unwrap());
    }

    #[test]
    fn test_is_block_pruned_true_after_prune_block_data() {
        let (_tmp, db) = open_db();
        let b0 = make_coinbase_block(Hash256::zero(), 0);
        let b1 = make_coinbase_block(b0.hash(), 1);
        let h1 = b1.hash();

        db.store_block(&b0).unwrap();
        db.store_block(&b1).unwrap();
        db.prune_block_data(&h1).unwrap();

        assert!(db.is_block_pruned(&h1).unwrap());
    }

    #[test]
    fn test_prune_block_data_removes_block_and_txs() {
        let (_tmp, db) = open_db();
        let b0 = make_coinbase_block(Hash256::zero(), 0);
        let b1 = make_coinbase_block(b0.hash(), 1);
        let h1 = b1.hash();

        db.store_block(&b0).unwrap();
        db.store_block(&b1).unwrap();
        let txid = db.store_transaction(&b1.transactions[0]).unwrap();

        db.prune_block_data(&h1).unwrap();

        assert!(!db.has_block(&h1).unwrap());
        assert!(!db.has_transaction(&txid).unwrap());
    }

    #[test]
    fn test_prune_block_data_idempotent() {
        let (_tmp, db) = open_db();
        let b0 = make_coinbase_block(Hash256::zero(), 0);
        let b1 = make_coinbase_block(b0.hash(), 1);

        let h1 = b1.hash();
        db.store_block(&b0).unwrap();
        db.store_block(&b1).unwrap();

        db.prune_block_data(&h1).unwrap();
        db.prune_block_data(&h1).unwrap();
    }

    fn build_chain(db: &Database, n: u32) -> Vec<Hash256> {
        let mut hashes = Vec::new();
        let mut prev = Hash256::zero();

        for i in 0..n {
            let block = make_coinbase_block(prev, i);
            let hash = block.hash();
            db.store_block(&block).unwrap();
            db.set_best_block_hash(&hash).unwrap();
            db.set_best_height(i).unwrap();
            prev = hash;
            hashes.push(hash);
        }

        hashes
    }

    #[test]
    fn test_prune_to_depth_short_chain_prunes_nothing() {
        let (_tmp, db) = open_db();
        build_chain(&db, 5);
        let pruned = db.prune_to_depth(10).unwrap();
        assert_eq!(pruned, 0);
    }

    #[test]
    fn test_prune_to_depth_prunes_old_blocks() {
        let (_tmp, db) = open_db();
        let hashes = build_chain(&db, 5);

        // depth=2: oldest kept = height 2; only height 1 pruned (genesis=0 protected).
        let pruned = db.prune_to_depth(2).unwrap();
        assert_eq!(pruned, 1, "should prune only height 1");

        assert!(db.has_block(&hashes[2]).unwrap());
        assert!(db.has_block(&hashes[3]).unwrap());
        assert!(db.has_block(&hashes[4]).unwrap());

        assert!(!db.has_block(&hashes[1]).unwrap());
        assert!(db.is_block_pruned(&hashes[1]).unwrap());

        assert!(db.has_block(&hashes[0]).unwrap());
        assert!(!db.is_block_pruned(&hashes[0]).unwrap());
    }

    #[test]
    fn test_prune_to_depth_headers_remain_loadable() {
        let (_tmp, db) = open_db();
        let hashes = build_chain(&db, 6);

        db.prune_to_depth(2).unwrap();

        for hash in &hashes {
            let header = db.load_block_header(hash).unwrap();
            assert_eq!(header.version, 1);
        }
    }

    #[test]
    fn test_prune_to_depth_idempotent() {
        let (_tmp, db) = open_db();
        build_chain(&db, 6);

        let first = db.prune_to_depth(2).unwrap();
        let second = db.prune_to_depth(2).unwrap();

        assert!(first > 0);
        assert_eq!(second, 0, "second run should prune nothing new");
    }

    #[test]
    fn test_prune_to_depth_prune_depth_zero_prunes_all_except_genesis() {
        let (_tmp, db) = open_db();
        let hashes = build_chain(&db, 4);

        let pruned = db.prune_to_depth(0).unwrap();
        assert_eq!(pruned, 2);

        assert!(db.has_block(&hashes[0]).unwrap()); // genesis kept
        assert!(!db.has_block(&hashes[1]).unwrap()); // pruned
        assert!(!db.has_block(&hashes[2]).unwrap()); // pruned
        assert!(db.has_block(&hashes[3]).unwrap()); // tip kept
    }

    #[test]
    fn test_prune_to_depth_no_best_hash_returns_zero() {
        let (_tmp, db) = open_db();
        assert_eq!(db.prune_to_depth(100).unwrap(), 0);
    }
}
