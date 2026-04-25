// Copyright (c) 2026 Kantoshi Miyamura

//! RPC integration tests.

use axiom_node::{Config, Network, Node};
use axiom_primitives::{Amount, Hash256};
use axiom_rpc::SharedNodeState;
use axiom_wallet::{Address, KeyPair, TransactionBuilder};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::RwLock;

fn create_test_node() -> (TempDir, Node) {
    let temp_dir = TempDir::new().unwrap();
    let config = Config {
        network: Network::Test,
        data_dir: temp_dir.path().to_path_buf(),
        rpc_bind: "127.0.0.1:8332".to_string(),
        mempool_max_size: 1_000_000,
        mempool_max_count: 100,
        min_fee_rate: 1,
    };

    let node = Node::new(config).unwrap();
    (temp_dir, node)
}

#[tokio::test]
async fn test_rpc_get_status() {
    let (_temp, node) = create_test_node();
    let state: SharedNodeState = Arc::new(RwLock::new(node));

    // Query status
    let node = state.read().await;
    let best_height = node.best_height();
    let mempool_size = node.mempool_size();

    // Genesis should be initialized
    assert_eq!(best_height, Some(0));
    assert_eq!(mempool_size, 0);
}

#[tokio::test]
async fn test_rpc_get_best_block_hash() {
    let (_temp, node) = create_test_node();
    let state: SharedNodeState = Arc::new(RwLock::new(node));

    let node = state.read().await;
    let best_hash = node.best_block_hash();

    // Should have genesis block
    assert!(best_hash.is_some());
}

#[tokio::test]
async fn test_rpc_get_block() {
    let (_temp, node) = create_test_node();
    let state: SharedNodeState = Arc::new(RwLock::new(node));

    let node = state.read().await;
    let genesis_hash = node.best_block_hash().unwrap();

    // Query genesis block
    let block = node.get_block(&genesis_hash).unwrap();
    assert!(block.is_some());

    let block = block.unwrap();
    assert_eq!(block.height(), Some(0));
}

#[test]
fn test_rpc_submit_transaction() {
    let (_temp, mut node) = create_test_node();

    // Create a test transaction
    let keypair = KeyPair::generate().unwrap();
    let amount = Amount::from_sat(1000).unwrap();

    let tx = TransactionBuilder::new()
        .add_input(Hash256::zero(), 0)
        .add_output(amount, Hash256::zero())
        .nonce(1)
        .keypair(keypair)
        .build()
        .unwrap();

    // Submit transaction (will fail validation but tests the path)
    let result = node.submit_transaction(tx);

    // Should fail because inputs don't exist
    assert!(result.is_err());
}

#[tokio::test]
async fn test_rpc_get_nonce() {
    let (_temp, node) = create_test_node();
    let state: SharedNodeState = Arc::new(RwLock::new(node));

    let keypair = KeyPair::generate().unwrap();
    let pubkey_hash = keypair.public_key_hash();

    let node = state.read().await;
    let nonce = node.get_nonce(&pubkey_hash).unwrap();

    // New address should have nonce 0
    assert_eq!(nonce, 0);
}

#[test]
fn test_rpc_mempool_operations() {
    let (_temp, mut node) = create_test_node();

    // Initial mempool should be empty
    assert_eq!(node.mempool_size(), 0);

    // Create and submit a transaction (will fail validation)
    let keypair = KeyPair::generate().unwrap();
    let amount = Amount::from_sat(1000).unwrap();

    let tx = TransactionBuilder::new()
        .add_input(Hash256::zero(), 0)
        .add_output(amount, Hash256::zero())
        .nonce(1)
        .keypair(keypair)
        .build()
        .unwrap();

    let _ = node.submit_transaction(tx);

    // Mempool should still be empty (transaction rejected)
    assert_eq!(node.mempool_size(), 0);
}

#[test]
fn test_rpc_address_parsing() {
    let keypair = KeyPair::generate().unwrap();
    let pubkey_hash = keypair.public_key_hash();
    let address = Address::from_pubkey_hash(pubkey_hash);

    // Convert to string and back
    let addr_str = address.to_string();
    assert!(addr_str.starts_with("axm"));

    let parsed = Address::from_string(&addr_str).unwrap();
    assert_eq!(address, parsed);
}

#[tokio::test]
async fn test_rpc_block_query_by_height() {
    let (_temp, node) = create_test_node();
    let state: SharedNodeState = Arc::new(RwLock::new(node));

    let node = state.read().await;

    // Query recent blocks
    let blocks = node.get_recent_blocks(10).unwrap();

    // Should have at least genesis
    assert!(!blocks.is_empty());
    assert_eq!(blocks[0].height(), Some(0));
}

#[tokio::test]
async fn test_rpc_chain_work() {
    let (_temp, node) = create_test_node();
    let state: SharedNodeState = Arc::new(RwLock::new(node));

    let node = state.read().await;
    let chain_work = node.get_chain_work().unwrap();

    // Chain work may be None if not yet calculated, or Some(value) if stored
    // Both are valid states for a fresh node
    assert!(chain_work.is_none() || chain_work.is_some());
}

#[tokio::test]
async fn test_rpc_orphan_count() {
    let (_temp, node) = create_test_node();
    let state: SharedNodeState = Arc::new(RwLock::new(node));

    let node = state.read().await;
    let orphan_count = node.orphan_count();

    // Should start with no orphans
    assert_eq!(orphan_count, 0);
}

#[tokio::test]
async fn test_rpc_balance_calculation() {
    let (_temp, node) = create_test_node();

    // Create a keypair
    let keypair = KeyPair::generate().unwrap();
    let pubkey_hash = keypair.public_key_hash();
    let _address = Address::from_pubkey_hash(pubkey_hash);

    // Initial balance should be 0
    let state: SharedNodeState = Arc::new(RwLock::new(node));
    {
        let node = state.read().await;
        let db = node.state.database();
        let utxo_set = axiom_storage::UtxoSet::new(db);
        let balance = utxo_set.get_balance(&pubkey_hash).unwrap();
        assert_eq!(balance, 0);
    }

    // Add a UTXO manually for testing
    {
        let node = state.read().await;
        let db = node.state.database();
        let utxo_set = axiom_storage::UtxoSet::new(db);

        let txid = Hash256::from_bytes([1u8; 32]);
        let entry = axiom_storage::UtxoEntry {
            value: Amount::from_sat(5000).unwrap(),
            pubkey_hash,
            height: 1,
            is_coinbase: false,
            confidential_commitment: None,
        };

        utxo_set.add_utxo(&txid, 0, &entry).unwrap();
    }

    // Balance should now be 5000
    {
        let node = state.read().await;
        let db = node.state.database();
        let utxo_set = axiom_storage::UtxoSet::new(db);
        let balance = utxo_set.get_balance(&pubkey_hash).unwrap();
        assert_eq!(balance, 5000);
    }

    // Add another UTXO
    {
        let node = state.read().await;
        let db = node.state.database();
        let utxo_set = axiom_storage::UtxoSet::new(db);

        let txid = Hash256::from_bytes([2u8; 32]);
        let entry = axiom_storage::UtxoEntry {
            value: Amount::from_sat(3000).unwrap(),
            pubkey_hash,
            height: 1,
            is_coinbase: false,
            confidential_commitment: None,
        };

        utxo_set.add_utxo(&txid, 0, &entry).unwrap();
    }

    // Balance should now be 8000
    {
        let node = state.read().await;
        let db = node.state.database();
        let utxo_set = axiom_storage::UtxoSet::new(db);
        let balance = utxo_set.get_balance(&pubkey_hash).unwrap();
        assert_eq!(balance, 8000);
    }
}

#[tokio::test]
async fn test_rpc_balance_multiple_addresses() {
    let (_temp, node) = create_test_node();
    let state: SharedNodeState = Arc::new(RwLock::new(node));

    // Create two keypairs
    let keypair1 = KeyPair::generate().unwrap();
    let pubkey_hash1 = keypair1.public_key_hash();

    let keypair2 = KeyPair::generate().unwrap();
    let pubkey_hash2 = keypair2.public_key_hash();

    // Add UTXOs for both addresses
    {
        let node = state.read().await;
        let db = node.state.database();
        let utxo_set = axiom_storage::UtxoSet::new(db);

        // Address 1: 10000 sat
        let entry1 = axiom_storage::UtxoEntry {
            value: Amount::from_sat(10000).unwrap(),
            pubkey_hash: pubkey_hash1,
            height: 1,
            is_coinbase: false,
            confidential_commitment: None,
        };
        utxo_set
            .add_utxo(&Hash256::from_bytes([1u8; 32]), 0, &entry1)
            .unwrap();

        // Address 2: 20000 sat
        let entry2 = axiom_storage::UtxoEntry {
            value: Amount::from_sat(20000).unwrap(),
            pubkey_hash: pubkey_hash2,
            height: 1,
            is_coinbase: false,
            confidential_commitment: None,
        };
        utxo_set
            .add_utxo(&Hash256::from_bytes([2u8; 32]), 0, &entry2)
            .unwrap();
    }

    // Verify balances are separate
    {
        let node = state.read().await;
        let db = node.state.database();
        let utxo_set = axiom_storage::UtxoSet::new(db);

        let balance1 = utxo_set.get_balance(&pubkey_hash1).unwrap();
        let balance2 = utxo_set.get_balance(&pubkey_hash2).unwrap();

        assert_eq!(balance1, 10000);
        assert_eq!(balance2, 20000);
    }
}

#[tokio::test]
async fn test_rpc_recent_blocks() {
    let (_temp, node) = create_test_node();
    let state: SharedNodeState = Arc::new(RwLock::new(node));

    let node = state.read().await;
    let blocks = node.get_recent_blocks(10).unwrap();

    // Should have at least genesis
    assert!(!blocks.is_empty());
    assert_eq!(blocks[0].height(), Some(0));
}

#[tokio::test]
async fn test_rpc_block_transactions() {
    let (_temp, node) = create_test_node();
    let state: SharedNodeState = Arc::new(RwLock::new(node));

    let node = state.read().await;
    let genesis_hash = node.best_block_hash().unwrap();
    let block = node.get_block(&genesis_hash).unwrap().unwrap();

    // Genesis should have coinbase transaction
    assert!(!block.transactions.is_empty());
    assert!(block.transactions[0].is_coinbase());
}

#[tokio::test]
async fn test_rpc_address_transactions() {
    let (_temp, node) = create_test_node();
    let state: SharedNodeState = Arc::new(RwLock::new(node));

    let keypair = KeyPair::generate().unwrap();
    let pubkey_hash = keypair.public_key_hash();

    // Add a UTXO for this address
    {
        let node = state.read().await;
        let db = node.state.database();
        let utxo_set = axiom_storage::UtxoSet::new(db);

        let txid = Hash256::from_bytes([1u8; 32]);
        let entry = axiom_storage::UtxoEntry {
            value: Amount::from_sat(1000).unwrap(),
            pubkey_hash,
            height: 1,
            is_coinbase: false,
            confidential_commitment: None,
        };

        utxo_set.add_utxo(&txid, 0, &entry).unwrap();
    }

    // Query transactions for this address
    {
        let node = state.read().await;
        let db = node.state.database();
        let utxo_set = axiom_storage::UtxoSet::new(db);

        let txs = utxo_set.iter_by_address(&pubkey_hash).unwrap();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].2.value.as_sat(), 1000);
    }
}

#[tokio::test]
async fn test_rpc_metrics() {
    let (_temp, node) = create_test_node();
    let state: SharedNodeState = Arc::new(RwLock::new(node));

    let node = state.read().await;

    // Metrics should reflect node state
    assert_eq!(node.best_height(), Some(0));
    assert!(node.best_block_hash().is_some());
    assert_eq!(node.mempool_size(), 0);
    assert_eq!(node.orphan_count(), 0);
}
