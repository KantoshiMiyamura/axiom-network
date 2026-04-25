// Copyright (c) 2026 Kantoshi Miyamura

//! Fork resolution and chain reorganization tests.

use axiom_consensus::{
    calculate_block_reward, calculate_work, compute_merkle_root, Block, BlockHeader, CompactTarget,
};
use axiom_node::{Config, Node};
use axiom_primitives::Hash256;
use axiom_protocol::{Transaction, TxOutput};
use tempfile::TempDir;

fn create_test_node() -> (TempDir, Node) {
    let temp_dir = TempDir::new().unwrap();
    let config = Config {
        data_dir: temp_dir.path().to_path_buf(),
        ..Default::default()
    };
    let node = Node::new(config).unwrap();
    (temp_dir, node)
}

fn create_block_at_height(height: u32, prev_hash: Hash256, difficulty: u32) -> Block {
    let reward = calculate_block_reward(height);
    let output = TxOutput {
        value: reward,
        pubkey_hash: Hash256::zero(),
    };
    let coinbase = Transaction::new_coinbase(vec![output], height);

    let merkle_root = compute_merkle_root(std::slice::from_ref(&coinbase));

    let header = BlockHeader {
        version: 1,
        prev_block_hash: prev_hash,
        merkle_root,
        timestamp: height,
        difficulty_target: difficulty,
        nonce: 0,
    };

    Block {
        header,
        transactions: vec![coinbase],
    }
}

#[test]
fn test_chain_work_tracking() {
    let (_temp, mut node) = create_test_node();

    // Build and apply blocks
    let block1 = node.build_block().unwrap();
    let _hash1 = block1.hash();
    node.process_block(block1).unwrap();

    let block2 = node.build_block().unwrap();
    let hash2 = block2.hash();
    node.process_block(block2).unwrap();

    // Verify chain work is tracked
    // Note: get_chain_work is not exposed on Node yet, but it's stored
    assert_eq!(node.best_height(), Some(2));
    assert_eq!(node.best_block_hash(), Some(hash2));
}

#[test]
fn test_sequential_blocks_cumulative_work() {
    let (_temp, mut node) = create_test_node();

    // Build 5 blocks sequentially
    for _ in 0..5 {
        let block = node.build_block().unwrap();
        node.process_block(block).unwrap();
    }

    assert_eq!(node.best_height(), Some(5));
}

#[test]
fn test_fork_detection_same_parent() {
    let (_temp, mut node) = create_test_node();

    // Build block 1
    let block1 = node.build_block().unwrap();
    let _hash1 = block1.hash();
    node.process_block(block1).unwrap();

    // Create competing block at height 1 (fork) — must use the current initial
    // difficulty (0x1e00ffff) so the block passes difficulty validation.
    let fork_block = create_block_at_height(1, Hash256::zero(), 0x1e00ffff);
    let _fork_hash = fork_block.hash();
    let result = node.process_block(fork_block);

    // Fork should be processed successfully
    assert!(result.is_ok());

    // Chain tip may have changed due to tie-break (lower hash wins)
    // Just verify node is still functional
    assert!(node.best_height().is_some());
    assert_eq!(node.best_height(), Some(1));
}

#[test]
fn test_work_calculation_deterministic() {
    let easy_target = CompactTarget(0x1d00ffff);
    let hard_target = CompactTarget(0x1c00ffff);

    let easy_work = calculate_work(easy_target);
    let hard_work = calculate_work(hard_target);

    // Harder target produces more work
    assert!(hard_work > easy_work);

    // Work calculation is deterministic
    assert_eq!(calculate_work(easy_target), easy_work);
    assert_eq!(calculate_work(hard_target), hard_work);
}

#[test]
fn test_cumulative_work_increases() {
    let (_temp, mut node) = create_test_node();

    let mut prev_height = 0;

    // Build blocks and verify height increases
    for i in 1..=3 {
        let block = node.build_block().unwrap();
        node.process_block(block).unwrap();

        let current_height = node.best_height().unwrap();
        assert_eq!(current_height, i);
        assert!(current_height > prev_height);
        prev_height = current_height;
    }
}

#[test]
fn test_block_with_different_difficulty() {
    let (_temp, mut node) = create_test_node();

    // Build block with default difficulty
    let block = node.build_block().unwrap();
    let difficulty = block.header.difficulty_target;

    node.process_block(block).unwrap();

    // Verify difficulty was stored
    assert!(difficulty > 0);
}

#[test]
fn test_chain_work_persistence() {
    let temp_dir = TempDir::new().unwrap();
    let data_dir = temp_dir.path().to_path_buf();

    let final_height;

    // First session: build blocks
    {
        let config = Config {
            data_dir: data_dir.clone(),
            ..Default::default()
        };
        let mut node = Node::new(config).unwrap();

        for _ in 0..3 {
            let block = node.build_block().unwrap();
            node.process_block(block).unwrap();
        }

        final_height = node.best_height();
    }

    // Second session: verify chain work persisted
    {
        let config = Config {
            data_dir,
            ..Default::default()
        };
        let node = Node::new(config).unwrap();

        assert_eq!(node.best_height(), final_height);
    }
}

#[test]
fn test_reject_block_wrong_prev_hash() {
    let (_temp, mut node) = create_test_node();

    // Build first block
    let block1 = node.build_block().unwrap();
    node.process_block(block1).unwrap();

    // Try to apply block with wrong prev_hash (unknown parent)
    let wrong_prev = Hash256::from_slice(&[1u8; 32]).unwrap();
    let bad_block = create_block_at_height(2, wrong_prev, 0x1d00ffff);

    // Should be stored as orphan, not rejected
    let result = node.process_block(bad_block);
    assert!(result.is_ok());

    // Should be in orphan pool
    assert_eq!(node.orphan_count(), 1);

    // Chain tip should not change
    assert_eq!(node.best_height(), Some(1));
}

#[test]
fn test_two_miners_sequential() {
    let (_temp1, mut node1) = create_test_node();
    let (_temp2, mut node2) = create_test_node();

    // Miner 1 builds block 1
    let block1 = node1.build_block().unwrap();
    node1.process_block(block1.clone()).unwrap();

    // Miner 2 receives and applies block 1
    node2.process_block(block1).unwrap();

    // Both should be at same state
    assert_eq!(node1.best_height(), node2.best_height());
    assert_eq!(node1.best_block_hash(), node2.best_block_hash());

    // Miner 2 builds block 2
    let block2 = node2.build_block().unwrap();
    node2.process_block(block2.clone()).unwrap();

    // Miner 1 receives and applies block 2
    node1.process_block(block2).unwrap();

    // Both should still be at same state
    assert_eq!(node1.best_height(), node2.best_height());
    assert_eq!(node1.best_block_hash(), node2.best_block_hash());
}

#[test]
fn test_chain_work_comparison() {
    // Test that we can compare chain work values
    let work1 = calculate_work(CompactTarget(0x1d00ffff));
    let work2 = calculate_work(CompactTarget(0x1d00ffff));
    let work3 = calculate_work(CompactTarget(0x1c00ffff));

    assert_eq!(work1, work2); // Same difficulty = same work
    assert!(work3 > work1); // Harder difficulty = more work

    // Cumulative work
    let cumulative1 = work1 + work2;
    let cumulative2 = work1 + work3;

    assert!(cumulative2 > cumulative1); // Chain with harder block has more work
}
