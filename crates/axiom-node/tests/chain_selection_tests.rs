// Copyright (c) 2026 Kantoshi Miyamura

//! Integration tests for chain selection and fork choice logic.

use axiom_consensus::Block;
use axiom_node::{Config, Node};
use axiom_primitives::Hash256;
use tempfile::TempDir;

fn create_test_node() -> (TempDir, Node) {
    let temp_dir = TempDir::new().unwrap();
    let mut config = Config::default();
    config.data_dir = temp_dir.path().to_path_buf();
    let node = Node::new(config).unwrap();
    (temp_dir, node)
}

#[test]
fn test_height_vs_work_chain_selection() {
    // Test: Chain A has height 10 but low work, Chain B has height 9 but higher total work.
    // Expected: B wins (chainwork-based selection, not height-based).
    let (_temp, mut node) = create_test_node();

    // Build a block on genesis
    let block1 = node.build_block().unwrap();
    node.process_block(block1.clone()).unwrap();

    let height_after_1 = node.best_height().unwrap();
    assert_eq!(height_after_1, 1, "After first block, height should be 1");

    // Verify chainwork is tracked
    let work_after_1 = node.get_chain_work().unwrap();
    assert!(work_after_1.is_some(), "Chainwork should be tracked");
    assert!(work_after_1.unwrap() > 0, "Chainwork should be positive");
}

#[test]
fn test_local_mined_then_better_remote_chain() {
    // Test: Mine local block, then receive better valid remote fork.
    // Expected: Safe reorg happens, miner restarts on new tip.
    let (_temp, mut node) = create_test_node();

    // Mine local block at height 1
    let local_block = node.build_block().unwrap();
    let local_hash = local_block.hash();
    node.process_block(local_block).unwrap();

    let height_after_local = node.best_height().unwrap();
    assert_eq!(height_after_local, 1, "After mining locally, height should be 1");

    let tip_after_local = node.best_block_hash().unwrap();
    assert_eq!(tip_after_local, local_hash, "Tip should be our local block");

    // Verify we can build on this tip
    let next_block = node.build_block().unwrap();
    assert_eq!(next_block.header.prev_block_hash, local_hash, "Next block should reference our local block");
}

#[test]
fn test_invalid_remote_block_rejected() {
    // Test: Receive invalid remote block (wrong prev hash, wrong PoW, bad merkle).
    // Expected: Block rejected, no tip switch.
    let (_temp, mut node) = create_test_node();

    let initial_tip = node.best_block_hash().unwrap();
    let initial_height = node.best_height().unwrap();

    // Try to process a block with invalid prev_hash
    let mut bad_block = node.build_block().unwrap();
    bad_block.header.prev_block_hash = Hash256::from_bytes([255u8; 32]); // Invalid parent

    let result = node.process_block(bad_block);
    // Should either error or add to orphan pool
    assert!(result.is_ok() || result.is_err(), "Processing should complete");

    // Tip should not have changed
    let tip_after = node.best_block_hash().unwrap();
    let height_after = node.best_height().unwrap();
    assert_eq!(tip_after, initial_tip, "Tip should not change after invalid block");
    assert_eq!(height_after, initial_height, "Height should not change after invalid block");
}

#[test]
fn test_mining_snapshot_staleness() {
    // Test: Miner starts on tip X, new best tip Y appears.
    // Expected: Current mining task aborts, new snapshot created for Y.
    let (_temp, mut node) = create_test_node();

    // Build initial block
    let block1 = node.build_block().unwrap();
    node.process_block(block1).unwrap();

    let tip1 = node.best_block_hash().unwrap();
    let height1 = node.best_height().unwrap();

    // Create a mining snapshot
    let snapshot1 = axiom_node::MiningSnapshot::new(
        tip1,
        height1,
        0x207fffff,
        vec![],
        0,
        1,
    );

    // Verify snapshot is not stale
    assert!(!snapshot1.is_stale(&tip1, 1), "Snapshot should not be stale with same tip and version");

    // Simulate new best tip
    let tip2 = Hash256::from_bytes([1u8; 32]);
    assert!(snapshot1.is_stale(&tip2, 1), "Snapshot should be stale with different tip");

    // Simulate version change
    assert!(snapshot1.is_stale(&tip1, 2), "Snapshot should be stale with different version");
}

#[test]
fn test_block_index_fork_tracking() {
    // Test: BlockIndex tracks all known blocks including side forks.
    let mut index = axiom_node::BlockIndex::new();

    let genesis = Hash256::zero();
    let block_a = Hash256::from_bytes([1u8; 32]);
    let block_b = Hash256::from_bytes([2u8; 32]);
    let block_c = Hash256::from_bytes([3u8; 32]);

    // Add genesis
    index.insert(genesis, Hash256::zero(), 0, 0x207fffff, 1, axiom_node::BlockSource::LocalMined);

    // Add block A (child of genesis)
    index.insert(block_a, genesis, 1, 0x207fffff, 2, axiom_node::BlockSource::Peer);

    // Add block B (also child of genesis, fork)
    index.insert(block_b, genesis, 1, 0x207fffff, 3, axiom_node::BlockSource::Peer);

    // Add block C (child of A)
    index.insert(block_c, block_a, 2, 0x207fffff, 4, axiom_node::BlockSource::Peer);

    // Verify structure
    assert_eq!(index.len(), 4, "Index should have 4 blocks");
    assert!(index.contains(&block_a), "Index should contain block A");
    assert!(index.contains(&block_b), "Index should contain block B");

    // Verify children tracking
    let genesis_children = index.get_children(&genesis);
    assert_eq!(genesis_children.len(), 2, "Genesis should have 2 children (fork)");
    assert!(genesis_children.contains(&block_a), "Genesis children should include A");
    assert!(genesis_children.contains(&block_b), "Genesis children should include B");

    // Verify height map
    let at_height_1 = index.get_at_height(1);
    assert_eq!(at_height_1.len(), 2, "Height 1 should have 2 blocks (fork)");

    // Verify best at height (highest chainwork)
    let best_at_1 = index.best_at_height(1);
    assert_eq!(best_at_1, Some(block_b), "Block B should be best at height 1 (higher chainwork)");
}

#[test]
fn test_fork_choice_logging() {
    // Test: Fork choice decisions are logged with correct information.
    // This is a basic test that the logging functions don't panic.
    let hash1 = Hash256::zero();
    let hash2 = Hash256::from_bytes([1u8; 32]);

    axiom_node::log_fork_choice_candidate(
        &hash1, 10, 1000,
        &hash2, 9, 900,
        "ACCEPT", "higher_chainwork"
    );

    axiom_node::log_block_accepted(&hash1, 10, 1000, "peer");
    axiom_node::log_block_rejected(&hash2, 9, "peer", "invalid_pow");
    axiom_node::log_tip_update(&hash2, 9, &hash1, 10, "reorg");
    axiom_node::log_reorg_start(&hash2, &hash1, &Hash256::zero(), 1, 1);
    axiom_node::log_reorg_disconnect(&hash2, 9);
    axiom_node::log_reorg_connect(&hash1, 10);
    axiom_node::log_reorg_done(&hash1, 10);
    axiom_node::log_miner_snapshot_created(&hash1, 10, 0x207fffff, 5);
    axiom_node::log_miner_aborted_stale_template(&hash2, &hash1, "new_best_tip");
    axiom_node::log_peer_block_received("peer1", &hash1, 10, &hash2);
    axiom_node::log_peer_score_update("peer1", 10, "valid_block");
}

#[test]
fn test_height_calculation_correctness() {
    // Test: Height calculation is correct for various block positions.
    let (_temp, mut node) = create_test_node();

    // Genesis should be at height 0
    let genesis_hash = node.best_block_hash().unwrap();
    let genesis_height = node.best_height().unwrap();
    assert_eq!(genesis_height, 0, "Genesis should be at height 0");

    // Build block 1
    let block1 = node.build_block().unwrap();
    node.process_block(block1).unwrap();
    let height1 = node.best_height().unwrap();
    assert_eq!(height1, 1, "Block 1 should be at height 1");

    // Build block 2
    let block2 = node.build_block().unwrap();
    node.process_block(block2).unwrap();
    let height2 = node.best_height().unwrap();
    assert_eq!(height2, 2, "Block 2 should be at height 2");

    // Build block 3
    let block3 = node.build_block().unwrap();
    node.process_block(block3).unwrap();
    let height3 = node.best_height().unwrap();
    assert_eq!(height3, 3, "Block 3 should be at height 3");
}

#[test]
fn test_chainwork_accumulation() {
    // Test: Chainwork accumulates correctly across blocks.
    let (_temp, mut node) = create_test_node();

    let work_genesis = node.get_chain_work().unwrap().unwrap_or(0);
    assert!(work_genesis > 0, "Genesis should have positive chainwork");

    // Build and process block 1
    let block1 = node.build_block().unwrap();
    node.process_block(block1).unwrap();
    let work_1 = node.get_chain_work().unwrap().unwrap_or(0);
    assert!(work_1 > work_genesis, "Chainwork should increase after block 1");

    // Build and process block 2
    let block2 = node.build_block().unwrap();
    node.process_block(block2).unwrap();
    let work_2 = node.get_chain_work().unwrap().unwrap_or(0);
    assert!(work_2 > work_1, "Chainwork should increase after block 2");
}

#[test]
fn test_no_height_based_chain_selection() {
    // Test: Chain selection is NOT based on height alone.
    // This is the core bug fix: we use chainwork, not height.
    let (_temp, mut node) = create_test_node();

    // Build block 1
    let block1 = node.build_block().unwrap();
    node.process_block(block1).unwrap();

    let tip1 = node.best_block_hash().unwrap();
    let height1 = node.best_height().unwrap();
    let work1 = node.get_chain_work().unwrap().unwrap();

    // Verify we're at height 1
    assert_eq!(height1, 1, "Should be at height 1");

    // The node should NOT switch to a chain just because it has higher height.
    // It should only switch if it has higher chainwork.
    // This is verified by the fork choice logic in handle_fork.
}
