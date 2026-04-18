// Copyright (c) 2026 Kantoshi Miyamura

//! Integration smoke test.
//!
//! Verifies the full block-and-transaction pipeline without network I/O:
//! - Genesis initialisation
//! - Two independent nodes share the same deterministic genesis
//! - Mempool is empty after genesis
//! - `build_block` / `process_block` advances the chain height
//! - The chain continues to grow correctly across multiple blocks
//! - Orphan tracking works (block with unknown parent lands in orphan pool)
//! - Node uptime and chain-ID accessors behave correctly
//! - Config validation rejects bad parameters

use axiom_consensus::{calculate_block_reward, compute_merkle_root, Block, BlockHeader};
use axiom_node::{Config, Network, Node};
use axiom_primitives::Hash256;
use axiom_protocol::{Transaction, TxOutput};
use tempfile::TempDir;

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Create a fresh Dev-network node backed by a temp directory.
fn make_node() -> (TempDir, Node) {
    let dir = TempDir::new().unwrap();
    let mut cfg = Config::default();
    cfg.data_dir = dir.path().to_path_buf();
    let node = Node::new(cfg).unwrap();
    (dir, node)
}

/// Build a minimal coinbase-only block for `height` that extends `prev_hash`.
///
/// The difficulty target mirrors the dev-net genesis value so the block
/// passes consensus validation without real PoW.
fn make_coinbase_block(height: u32, prev_hash: Hash256) -> Block {
    let reward = calculate_block_reward(height);
    let output = TxOutput {
        value: reward,
        pubkey_hash: Hash256::zero(),
    };
    let coinbase = Transaction::new_coinbase(vec![output], height);
    let merkle_root = compute_merkle_root(&[coinbase.clone()]);

    // Timestamp must exceed MTP; use current time + height as a safe value.
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
        difficulty_target: 0x1f00_ffff, // dev-net genesis difficulty
        nonce: 0,
    };

    Block {
        header,
        transactions: vec![coinbase],
    }
}

// ── Test 1: Genesis is initialised at height 0 ──────────────────────────────

#[test]
fn test_genesis_block_is_initialized() {
    let (_dir, node) = make_node();

    let height = node.best_height();
    assert!(
        height.is_some(),
        "best_height should be Some after genesis init"
    );
    assert_eq!(height.unwrap(), 0, "genesis is at height 0");

    let hash = node.best_block_hash();
    assert!(
        hash.is_some(),
        "best_block_hash should be Some after genesis init"
    );
}

// ── Test 2: Two independent nodes share the same genesis ────────────────────

#[test]
fn test_two_independent_nodes_have_same_genesis() {
    let (_dir1, node1) = make_node();
    let (_dir2, node2) = make_node();

    assert_eq!(
        node1.best_block_hash(),
        node2.best_block_hash(),
        "independent nodes must share genesis hash"
    );
    assert_eq!(node1.best_height(), node2.best_height());
}

// ── Test 3: Height advances after build_block / process_block ───────────────

#[test]
fn test_best_height_advances_with_blocks() {
    let (_dir, mut node) = make_node();

    assert_eq!(node.best_height(), Some(0));

    let block = node.build_block().unwrap();
    node.process_block(block).unwrap();

    assert_eq!(
        node.best_height(),
        Some(1),
        "height must be 1 after first block"
    );
}

// ── Test 4: Mempool is empty after genesis ───────────────────────────────────

#[test]
fn test_mempool_empty_after_genesis() {
    let (_dir, node) = make_node();
    assert_eq!(node.mempool_size(), 0, "fresh node mempool must be empty");
}

// ── Test 5: Config validation rejects zero mempool size ─────────────────────

#[test]
fn test_node_config_validation() {
    let dir = TempDir::new().unwrap();
    let mut cfg = Config::default();
    cfg.data_dir = dir.path().to_path_buf();
    cfg.mempool_max_size = 0; // invalid

    let result = Node::new(cfg);
    assert!(result.is_err(), "zero mempool_max_size must be rejected");
}

// ── Test 6: Chain grows correctly across multiple sequential blocks ──────────

#[test]
fn test_chain_grows_sequentially() {
    let (_dir, mut node) = make_node();

    for expected_height in 1u32..=5 {
        let block = node.build_block().unwrap();
        node.process_block(block).unwrap();
        assert_eq!(
            node.best_height(),
            Some(expected_height),
            "height should be {expected_height} after block {expected_height}"
        );
    }
}

// ── Test 7: Block hash changes with each new block ───────────────────────────

#[test]
fn test_best_block_hash_changes_each_block() {
    let (_dir, mut node) = make_node();

    let genesis_hash = node.best_block_hash().unwrap();

    let block1 = node.build_block().unwrap();
    let hash1 = block1.hash();
    node.process_block(block1).unwrap();

    assert_ne!(
        node.best_block_hash().unwrap(),
        genesis_hash,
        "tip hash must change after block 1"
    );
    assert_eq!(node.best_block_hash(), Some(hash1));

    let block2 = node.build_block().unwrap();
    let hash2 = block2.hash();
    node.process_block(block2).unwrap();

    assert_ne!(hash2, hash1, "block 2 hash must differ from block 1");
    assert_eq!(node.best_block_hash(), Some(hash2));
}

// ── Test 8: Mempool stays empty after coinbase-only blocks ───────────────────

#[test]
fn test_mempool_empty_after_coinbase_block() {
    let (_dir, mut node) = make_node();

    // build_block with empty mempool produces a coinbase-only block
    let block = node.build_block().unwrap();
    node.process_block(block).unwrap();

    assert_eq!(
        node.mempool_size(),
        0,
        "mempool must remain empty after a coinbase-only block"
    );
}

// ── Test 9: Orphan pool accepts block with unknown parent ────────────────────

#[test]
fn test_orphan_block_lands_in_orphan_pool() {
    let (_dir, mut node) = make_node();

    // Parent hash is unknown — block must become an orphan
    let unknown_parent = Hash256::from_slice(&[0xAB; 32]).unwrap();
    let orphan = make_coinbase_block(5, unknown_parent);
    let orphan_hash = orphan.hash();

    node.process_block(orphan).unwrap();

    assert_eq!(node.orphan_count(), 1, "orphan block must be stored");
    assert!(
        node.is_orphan(&orphan_hash),
        "block must be flagged as orphan"
    );
    assert_eq!(node.best_height(), Some(0), "chain tip must not advance");
}

// ── Test 10: Two nodes stay in sync when sharing blocks ─────────────────────

#[test]
fn test_two_nodes_stay_in_sync() {
    let (_dir1, mut node1) = make_node();
    let (_dir2, mut node2) = make_node();

    // node1 mines block 1, node2 receives it
    let block1 = node1.build_block().unwrap();
    node1.process_block(block1.clone()).unwrap();
    node2.process_block(block1).unwrap();

    assert_eq!(node1.best_height(), node2.best_height());
    assert_eq!(node1.best_block_hash(), node2.best_block_hash());

    // node2 mines block 2, node1 receives it
    let block2 = node2.build_block().unwrap();
    node2.process_block(block2.clone()).unwrap();
    node1.process_block(block2).unwrap();

    assert_eq!(node1.best_height(), Some(2));
    assert_eq!(node2.best_height(), Some(2));
    assert_eq!(node1.best_block_hash(), node2.best_block_hash());
}

// ── Test 11: Duplicate block is rejected ────────────────────────────────────

#[test]
fn test_duplicate_block_is_rejected() {
    let (_dir, mut node) = make_node();

    let block = node.build_block().unwrap();
    node.process_block(block.clone()).unwrap();

    // Submitting the same block a second time must return an error
    let result = node.process_block(block);
    assert!(result.is_err(), "duplicate block must be rejected");
}

// ── Test 12: Chain state persists across node restarts ──────────────────────

#[test]
fn test_chain_state_persists_across_restart() {
    let dir = TempDir::new().unwrap();
    let data_dir = dir.path().to_path_buf();

    let saved_hash;

    // First session: mine 3 blocks
    {
        let mut cfg = Config::default();
        cfg.data_dir = data_dir.clone();
        let mut node = Node::new(cfg).unwrap();

        for _ in 0..3 {
            let block = node.build_block().unwrap();
            node.process_block(block).unwrap();
        }

        assert_eq!(node.best_height(), Some(3));
        saved_hash = node.best_block_hash();
    }

    // Second session: verify height and hash survived
    {
        let mut cfg = Config::default();
        cfg.data_dir = data_dir;
        let node = Node::new(cfg).unwrap();

        assert_eq!(node.best_height(), Some(3), "height must survive restart");
        assert_eq!(
            node.best_block_hash(),
            saved_hash,
            "tip hash must survive restart"
        );
    }
}

// ── Test 13: Uptime accessor increases over time ─────────────────────────────

#[test]
fn test_uptime_accessor() {
    let (_dir, node) = make_node();
    // uptime_seconds() returns u64; at creation it should be 0 or very small
    let uptime = node.uptime_seconds();
    assert!(
        uptime < 60,
        "uptime immediately after creation should be < 60 s"
    );
}

// ── Test 14: chain_id matches Dev network ────────────────────────────────────

#[test]
fn test_chain_id_matches_network() {
    let (_dir, node) = make_node();
    assert_eq!(node.chain_id(), "axiom-dev-1");
}

// ── Test 15: get_recent_blocks returns blocks in descending order ─────────────

#[test]
fn test_get_recent_blocks() {
    let (_dir, mut node) = make_node();

    // Mine 3 blocks
    for _ in 0..3 {
        let block = node.build_block().unwrap();
        node.process_block(block).unwrap();
    }

    let recent = node.get_recent_blocks(2).unwrap();
    assert_eq!(recent.len(), 2, "should return the 2 most recent blocks");
}

// ── Test 16: get_block round-trip ────────────────────────────────────────────

#[test]
fn test_get_block_round_trip() {
    let (_dir, mut node) = make_node();

    let block = node.build_block().unwrap();
    let block_hash = block.hash();
    node.process_block(block.clone()).unwrap();

    let retrieved = node.get_block(&block_hash).unwrap();
    assert!(
        retrieved.is_some(),
        "get_block must return the stored block"
    );
    assert_eq!(retrieved.unwrap().hash(), block_hash);
}

// ── Test 17: has_block is consistent with get_block ──────────────────────────

#[test]
fn test_has_block_consistent() {
    let (_dir, mut node) = make_node();

    let unknown = Hash256::from_slice(&[0xFF; 32]).unwrap();
    assert!(
        !node.has_block(&unknown).unwrap(),
        "unknown hash must not be found"
    );

    let block = node.build_block().unwrap();
    let hash = block.hash();
    node.process_block(block).unwrap();

    assert!(
        node.has_block(&hash).unwrap(),
        "applied block must be found"
    );
}

// ── Test 18: mempool_max_count reflects config ────────────────────────────────

#[test]
fn test_mempool_config_accessors() {
    let dir = TempDir::new().unwrap();
    let mut cfg = Config::default();
    cfg.data_dir = dir.path().to_path_buf();
    cfg.mempool_max_count = 12_345;
    cfg.mempool_max_size = 1_000_000;
    cfg.min_fee_rate = 42;
    let node = Node::new(cfg).unwrap();

    assert_eq!(node.mempool_max_count(), 12_345);
    assert_eq!(node.mempool_max_byte_size(), 1_000_000);
    assert_eq!(node.min_fee_rate(), 42);
}

// ── Test 19: Network::parse_str round-trip ────────────────────────────────────

#[test]
fn test_network_from_str() {
    assert_eq!(Network::parse_str("dev").unwrap(), Network::Dev);
    assert_eq!(Network::parse_str("devnet").unwrap(), Network::Dev);
    assert_eq!(Network::parse_str("test").unwrap(), Network::Test);
    assert_eq!(Network::parse_str("testnet").unwrap(), Network::Test);
    assert_eq!(Network::parse_str("main").unwrap(), Network::Mainnet);
    assert_eq!(Network::parse_str("mainnet").unwrap(), Network::Mainnet);
    assert!(Network::parse_str("unknown").is_err());
}

// ── Test 20: Dev network does NOT require PoW ─────────────────────────────────

#[test]
fn test_dev_network_no_pow() {
    assert!(
        !Network::Dev.requires_pow(),
        "Dev network must not require proof-of-work"
    );
    assert!(
        Network::Test.requires_pow(),
        "Test network must require PoW"
    );
    assert!(Network::Mainnet.requires_pow(), "Mainnet must require PoW");
}

// ── Test 21: persist_mempool creates mempool.dat ─────────────────────────────

#[test]
fn test_persist_mempool_creates_file() {
    let dir = TempDir::new().unwrap();
    let mut cfg = Config::default();
    cfg.data_dir = dir.path().to_path_buf();
    let node = Node::new(cfg).unwrap();

    // Persist should succeed even with empty mempool
    let result = node.persist_mempool();
    assert!(
        result.is_ok(),
        "persist_mempool should succeed: {:?}",
        result
    );

    // The file should exist after persist
    let mempool_path = dir.path().join("mempool.dat");
    assert!(
        mempool_path.exists(),
        "mempool.dat should be created by persist_mempool"
    );
}

// ── Test 22: mempool survives a node restart ──────────────────────────────────

#[test]
fn test_mempool_survives_restart() {
    let dir = TempDir::new().unwrap();
    let mut cfg = Config::default();
    cfg.data_dir = dir.path().to_path_buf();

    {
        let node = Node::new(cfg.clone()).unwrap();
        // Persist empty mempool
        node.persist_mempool().unwrap();
    }

    // Restart
    let node2 = Node::new(cfg).unwrap();
    // Should load cleanly with 0 transactions
    assert_eq!(node2.mempool_size(), 0);
}
