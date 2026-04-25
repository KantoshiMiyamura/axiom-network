// Copyright (c) 2026 Kantoshi Miyamura

use axiom_consensus::{Block, BlockHeader};
use axiom_primitives::{Amount, Hash256};
use axiom_protocol::{Transaction, TxOutput};
use axiom_storage::{Database, StorageBatch, UtxoEntry};
use tempfile::TempDir;

fn create_test_db() -> (TempDir, Database) {
    let temp_dir = TempDir::new().unwrap();
    let db = Database::open(temp_dir.path()).unwrap();
    (temp_dir, db)
}

#[test]
fn test_block_roundtrip() {
    let (_temp, db) = create_test_db();

    let header = BlockHeader {
        version: 1,
        prev_block_hash: Hash256::zero(),
        merkle_root: Hash256::zero(),
        timestamp: 1234567890,
        difficulty_target: 0x1d00ffff,
        nonce: 12345,
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

    db.store_block(&block).unwrap();
    assert!(db.has_block(&block_hash).unwrap());

    let loaded = db.load_block(&block_hash).unwrap();
    assert_eq!(loaded, block);
}

#[test]
fn test_transaction_roundtrip() {
    let (_temp, db) = create_test_db();

    let output = TxOutput {
        value: Amount::from_sat(1_000_000).unwrap(),
        pubkey_hash: Hash256::zero(),
    };

    let tx = Transaction::new_coinbase(vec![output], 0);

    let txid = db.store_transaction(&tx).unwrap();
    assert!(db.has_transaction(&txid).unwrap());

    let loaded = db.load_transaction(&txid).unwrap();
    assert_eq!(loaded, tx);
}

#[test]
fn test_chain_metadata() {
    let (_temp, db) = create_test_db();

    assert_eq!(db.get_best_block_hash().unwrap(), None);
    assert_eq!(db.get_best_height().unwrap(), None);

    let block_hash = Hash256::from_bytes([1u8; 32]);
    db.set_best_block_hash(&block_hash).unwrap();
    db.set_best_height(100).unwrap();

    assert_eq!(db.get_best_block_hash().unwrap(), Some(block_hash));
    assert_eq!(db.get_best_height().unwrap(), Some(100));
}

#[test]
fn test_genesis_hash_once() {
    let (_temp, db) = create_test_db();

    let genesis_hash = Hash256::from_bytes([1u8; 32]);
    db.set_genesis_hash(&genesis_hash).unwrap();

    assert_eq!(db.get_genesis_hash().unwrap(), Some(genesis_hash));

    let other_hash = Hash256::from_bytes([2u8; 32]);
    assert!(db.set_genesis_hash(&other_hash).is_err());
}

#[test]
fn test_restart_recovery() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().to_path_buf();

    let block_hash = Hash256::from_bytes([1u8; 32]);

    {
        let db = Database::open(&path).unwrap();
        db.set_best_block_hash(&block_hash).unwrap();
        db.set_best_height(42).unwrap();
    }

    {
        let db = Database::open(&path).unwrap();
        assert_eq!(db.get_best_block_hash().unwrap(), Some(block_hash));
        assert_eq!(db.get_best_height().unwrap(), Some(42));
    }
}

#[test]
fn test_atomic_batch() {
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

    let coinbase = Transaction::new_coinbase(vec![output.clone()], 0);
    let block = Block {
        header,
        transactions: vec![coinbase.clone()],
    };

    let block_hash = block.hash();

    let mut batch = StorageBatch::new(&db);
    batch.put_block(&block).unwrap();
    let txid = batch.put_transaction(&coinbase).unwrap();

    let utxo_entry = UtxoEntry::from_output(&output, 0, true);
    batch.put_utxo(&txid, 0, &utxo_entry).unwrap();

    batch.put_best_block_hash(&block_hash);
    batch.put_best_height(0);

    batch.commit().unwrap();

    assert!(db.has_block(&block_hash).unwrap());
    assert!(db.has_transaction(&txid).unwrap());
    assert_eq!(db.get_best_height().unwrap(), Some(0));
}

#[test]
fn test_missing_data() {
    let (_temp, db) = create_test_db();

    let fake_hash = Hash256::from_bytes([99u8; 32]);

    assert!(!db.has_block(&fake_hash).unwrap());
    assert!(db.load_block(&fake_hash).is_err());

    assert!(!db.has_transaction(&fake_hash).unwrap());
    assert!(db.load_transaction(&fake_hash).is_err());
}
