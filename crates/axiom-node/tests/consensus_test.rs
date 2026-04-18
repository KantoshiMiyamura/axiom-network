// Copyright (c) 2026 Kantoshi Miyamura

//! Consensus stress tests.
//!
//! Tests deterministic consensus behavior across multiple scenarios.

use axiom_consensus::{
    calculate_block_reward, compute_merkle_root, Block, BlockHeader, ConsensusValidator,
};
use axiom_node::{Config, Network, Node};
use axiom_primitives::{Amount, Hash256};
use axiom_protocol::{Transaction, TxOutput};
use tempfile::TempDir;

fn create_test_node() -> (TempDir, Node) {
    let temp_dir = TempDir::new().unwrap();
    let mut config = Config::default();
    config.data_dir = temp_dir.path().to_path_buf();
    let node = Node::new(config).unwrap();
    (temp_dir, node)
}

fn create_valid_block(height: u32, prev_hash: Hash256) -> Block {
    let reward = calculate_block_reward(height);
    let output = TxOutput {
        value: reward,
        pubkey_hash: Hash256::zero(),
    };
    let coinbase = Transaction::new_coinbase(vec![output], height);

    let merkle_root = compute_merkle_root(&[coinbase.clone()]);

    // Use current Unix time + height so the timestamp always passes MTP and drift checks.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let timestamp = now + height;

    let header = BlockHeader {
        version: 1,
        prev_block_hash: prev_hash,
        merkle_root,
        timestamp,
        difficulty_target: 0,
        nonce: 0,
    };

    Block {
        header,
        transactions: vec![coinbase],
    }
}

#[test]
fn test_two_nodes_identical_state() {
    let (_temp1, mut node1) = create_test_node();
    let (_temp2, mut node2) = create_test_node();

    // Both nodes build and process same blocks
    for _ in 0..5 {
        let block1 = node1.build_block().unwrap();
        let block2 = node2.build_block().unwrap();

        // Blocks should be identical (deterministic)
        assert_eq!(block1.hash(), block2.hash());

        node1.process_block(block1.clone()).unwrap();
        node2.process_block(block2).unwrap();
    }

    // Final state should be identical
    assert_eq!(node1.best_height(), node2.best_height());
    assert_eq!(node1.best_block_hash(), node2.best_block_hash());
}

#[test]
fn test_reject_duplicate_block_application() {
    let (_temp, mut node) = create_test_node();

    let block = node.build_block().unwrap();

    // First application succeeds
    node.process_block(block.clone()).unwrap();
    assert_eq!(node.best_height(), Some(1));

    // Second application should fail (wrong prev_hash)
    let result = node.process_block(block);
    assert!(result.is_err());

    // Height should not change
    assert_eq!(node.best_height(), Some(1));
}

#[test]
fn test_reject_wrong_prev_hash() {
    let prev_hash = Hash256::zero();
    let wrong_hash = Hash256::from_slice(&[1u8; 32]).unwrap();

    let block = create_valid_block(1, wrong_hash);

    let validator = ConsensusValidator::new(prev_hash, 1);
    let result = validator.validate_block(&block);

    assert!(result.is_err());
}

#[test]
fn test_reject_wrong_merkle_root() {
    let prev_hash = Hash256::zero();
    let mut block = create_valid_block(1, prev_hash);

    // Corrupt merkle root
    block.header.merkle_root = Hash256::zero();

    let validator = ConsensusValidator::new(prev_hash, 1);
    let result = validator.validate_block(&block);

    assert!(result.is_err());
}

#[test]
fn test_reject_excessive_coinbase() {
    let prev_hash = Hash256::zero();
    let mut block = create_valid_block(1, prev_hash);

    // Set excessive coinbase
    let excessive_output = TxOutput {
        value: Amount::from_sat(100_000_000_000).unwrap(), // 1000 AXM
        pubkey_hash: Hash256::zero(),
    };
    block.transactions[0] = Transaction::new_coinbase(vec![excessive_output], 1);
    block.header.merkle_root = compute_merkle_root(&block.transactions);

    let validator = ConsensusValidator::new(prev_hash, 1);
    let result = validator.validate_block(&block);

    assert!(result.is_err());
}

#[test]
fn test_reject_wrong_coinbase_height() {
    let prev_hash = Hash256::zero();
    let mut block = create_valid_block(1, prev_hash);

    // Set wrong height in coinbase
    let output = TxOutput {
        value: calculate_block_reward(1),
        pubkey_hash: Hash256::zero(),
    };
    block.transactions[0] = Transaction::new_coinbase(vec![output], 999);
    block.header.merkle_root = compute_merkle_root(&block.transactions);

    let validator = ConsensusValidator::new(prev_hash, 1);
    let result = validator.validate_block(&block);

    assert!(result.is_err());
}

#[test]
fn test_reject_no_coinbase() {
    let prev_hash = Hash256::zero();

    let tx = Transaction::new_transfer(vec![], vec![], 0, 0);
    let merkle_root = compute_merkle_root(&[tx.clone()]);

    let header = BlockHeader {
        version: 1,
        prev_block_hash: prev_hash,
        merkle_root,
        timestamp: 1,
        difficulty_target: 0,
        nonce: 0,
    };

    let block = Block {
        header,
        transactions: vec![tx],
    };

    let validator = ConsensusValidator::new(prev_hash, 1);
    let result = validator.validate_block(&block);

    assert!(result.is_err());
}

#[test]
fn test_reject_multiple_coinbase() {
    let prev_hash = Hash256::zero();

    let output = TxOutput {
        value: calculate_block_reward(1),
        pubkey_hash: Hash256::zero(),
    };
    let coinbase1 = Transaction::new_coinbase(vec![output.clone()], 1);
    let coinbase2 = Transaction::new_coinbase(vec![output], 1);

    let merkle_root = compute_merkle_root(&[coinbase1.clone(), coinbase2.clone()]);

    let header = BlockHeader {
        version: 1,
        prev_block_hash: prev_hash,
        merkle_root,
        timestamp: 1,
        difficulty_target: 0,
        nonce: 0,
    };

    let block = Block {
        header,
        transactions: vec![coinbase1, coinbase2],
    };

    let validator = ConsensusValidator::new(prev_hash, 1);
    let result = validator.validate_block(&block);

    assert!(result.is_err());
}

#[test]
fn test_reject_duplicate_transaction_in_block() {
    let prev_hash = Hash256::zero();

    let output = TxOutput {
        value: calculate_block_reward(1),
        pubkey_hash: Hash256::zero(),
    };
    let coinbase = Transaction::new_coinbase(vec![output.clone()], 1);
    let tx = Transaction::new_transfer(vec![], vec![output], 0, 100);

    let merkle_root = compute_merkle_root(&[coinbase.clone(), tx.clone(), tx.clone()]);

    let header = BlockHeader {
        version: 1,
        prev_block_hash: prev_hash,
        merkle_root,
        timestamp: 1,
        difficulty_target: 0,
        nonce: 0,
    };

    let block = Block {
        header,
        transactions: vec![coinbase, tx.clone(), tx],
    };

    let validator = ConsensusValidator::new(prev_hash, 1);
    let result = validator.validate_block(&block);

    assert!(result.is_err());
}

#[test]
fn test_deterministic_block_hash() {
    let block1 = create_valid_block(1, Hash256::zero());
    let block2 = create_valid_block(1, Hash256::zero());

    // Same inputs produce same hash
    assert_eq!(block1.hash(), block2.hash());
}

#[test]
fn test_deterministic_merkle_root() {
    let output = TxOutput {
        value: Amount::from_sat(1000).unwrap(),
        pubkey_hash: Hash256::zero(),
    };
    let tx1 = Transaction::new_coinbase(vec![output.clone()], 0);
    let tx2 = Transaction::new_coinbase(vec![output], 0);

    let merkle1 = compute_merkle_root(&[tx1.clone()]);
    let merkle2 = compute_merkle_root(&[tx2]);

    // Same transactions produce same merkle root
    assert_eq!(merkle1, merkle2);
}

#[test]
fn test_block_reward_deterministic() {
    // Block reward must be deterministic for all nodes (smooth decay model).
    use axiom_consensus::{INITIAL_REWARD_SAT, MIN_REWARD_SAT};
    // Height 0: full initial reward (50 AXM).
    assert_eq!(calculate_block_reward(0).as_sat(), INITIAL_REWARD_SAT);
    // Height 1: strictly less than height 0 (decay has started).
    assert!(calculate_block_reward(1).as_sat() < INITIAL_REWARD_SAT);
    // Height 2_000_000: deep past decay floor (~12.5 years) → locked at MIN_REWARD_SAT.
    assert_eq!(calculate_block_reward(2_000_000).as_sat(), MIN_REWARD_SAT);
    // Alias must match the canonical function.
    assert_eq!(
        calculate_block_reward(1000),
        axiom_consensus::calculate_smooth_reward(1000)
    );
}

#[test]
fn test_sequential_block_application() {
    let (_temp, mut node) = create_test_node();

    // Build blocks sequentially
    let block1 = node.build_block().unwrap();
    node.process_block(block1).unwrap();

    let block2 = node.build_block().unwrap();
    node.process_block(block2).unwrap();

    let block3 = node.build_block().unwrap();
    node.process_block(block3).unwrap();

    assert_eq!(node.best_height(), Some(3));
}

#[test]
fn test_reject_out_of_order_blocks() {
    let (_temp, mut node) = create_test_node();

    // Build block 1
    let block1 = node.build_block().unwrap();
    let hash1 = block1.hash();
    node.process_block(block1).unwrap();

    // Build block 2
    let block2 = node.build_block().unwrap();
    node.process_block(block2).unwrap();

    // Try to apply block 3 that references block 1 (skipping block 2)
    let block3 = create_valid_block(2, hash1);
    let result = node.process_block(block3);

    // Should fail because prev_hash doesn't match current tip
    assert!(result.is_err());
}

#[test]
fn test_state_consistency_after_restart() {
    let temp_dir = TempDir::new().unwrap();
    let data_dir = temp_dir.path().to_path_buf();

    let final_height;
    let final_hash;

    // First session: build blocks
    {
        let mut config = Config::default();
        config.data_dir = data_dir.clone();
        let mut node = Node::new(config).unwrap();

        for _ in 0..3 {
            let block = node.build_block().unwrap();
            node.process_block(block).unwrap();
        }

        final_height = node.best_height();
        final_hash = node.best_block_hash();
    }

    // Second session: reopen and verify state
    {
        let mut config = Config::default();
        config.data_dir = data_dir;
        let node = Node::new(config).unwrap();

        assert_eq!(node.best_height(), final_height);
        assert_eq!(node.best_block_hash(), final_hash);
    }
}
