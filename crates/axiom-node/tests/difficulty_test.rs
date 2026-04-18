// Copyright (c) 2026 Kantoshi Miyamura

//! Difficulty adjustment integration tests.
//!
//! Tests LWMA-3 retargeting end-to-end through the node and chain state,
//! covering:
//! - Early blocks (height < LWMA_WINDOW) carry forward parent difficulty
//! - LWMA retargets every block once the window is full
//! - Determinism: same chain always produces same difficulty
//! - Persistence: difficulty survives node restart
//! - Validator rejects blocks with wrong difficulty_target
//! - Validator accepts blocks with correct difficulty_target

use axiom_consensus::{
    calculate_block_reward, compute_merkle_root, Block, BlockHeader, CompactTarget,
    ConsensusValidator, DIFFICULTY_ADJUSTMENT_INTERVAL, TARGET_BLOCK_TIME,
};
use axiom_node::{ChainState, Config, Node};
use axiom_primitives::Hash256;
use axiom_protocol::{Transaction, TxOutput};
use axiom_storage::Database;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn create_test_node() -> (TempDir, Node) {
    let temp_dir = TempDir::new().unwrap();
    let mut config = Config::default();
    config.data_dir = temp_dir.path().to_path_buf();
    let node = Node::new(config).unwrap();
    (temp_dir, node)
}

fn create_test_state(temp_dir: &TempDir) -> ChainState {
    let db = Database::open(temp_dir.path()).unwrap();
    ChainState::new(db).unwrap()
}

/// Create a minimal valid block manually (without going through Node::build_block).
///
/// `timestamp` is exposed so callers can control elapsed time for retarget tests.
fn make_block(height: u32, prev_hash: Hash256, difficulty_target: u32, timestamp: u32) -> Block {
    let reward = calculate_block_reward(height);
    let output = TxOutput {
        value: reward,
        pubkey_hash: Hash256::zero(),
    };
    let coinbase = Transaction::new_coinbase(vec![output], height);
    let merkle_root = compute_merkle_root(&[coinbase.clone()]);
    let header = BlockHeader {
        version: 1,
        prev_block_hash: prev_hash,
        merkle_root,
        timestamp,
        difficulty_target,
        nonce: 0,
    };
    Block {
        header,
        transactions: vec![coinbase],
    }
}

// ---------------------------------------------------------------------------
// 1. Non-retarget blocks carry forward parent difficulty
// ---------------------------------------------------------------------------

#[test]
fn test_non_retarget_blocks_carry_forward_difficulty() {
    let (_temp, mut node) = create_test_node();

    let genesis_difficulty = node
        .state
        .get_next_difficulty_target(1)
        .expect("should compute difficulty for height 1");

    // Build several blocks – none of them at a retarget height
    for _ in 0..5 {
        let block = node.build_block().unwrap();
        let diff = block.header.difficulty_target;
        node.process_block(block).unwrap();
        assert_eq!(
            diff, genesis_difficulty,
            "non-retarget block must carry forward genesis difficulty"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. get_next_difficulty_target is deterministic for the same chain
// ---------------------------------------------------------------------------

#[test]
fn test_difficulty_target_deterministic() {
    let (_temp1, mut node1) = create_test_node();
    let (_temp2, mut node2) = create_test_node();

    // Both nodes apply the same sequence of blocks
    let block1 = node1.build_block().unwrap();
    node2.process_block(block1.clone()).unwrap();
    node1.process_block(block1).unwrap();

    let block2 = node1.build_block().unwrap();
    node2.process_block(block2.clone()).unwrap();
    node1.process_block(block2).unwrap();

    // Both compute the same next difficulty
    let d1 = node1.state.get_next_difficulty_target(3).unwrap();
    let d2 = node2.state.get_next_difficulty_target(3).unwrap();
    assert_eq!(
        d1, d2,
        "difficulty must be deterministic given the same chain"
    );
}

// ---------------------------------------------------------------------------
// 3. Difficulty persists across node restart
// ---------------------------------------------------------------------------

#[test]
fn test_difficulty_persists_after_restart() {
    let temp_dir = TempDir::new().unwrap();
    let data_dir = temp_dir.path().to_path_buf();

    let difficulty_before = {
        let mut config = Config::default();
        config.data_dir = data_dir.clone();
        let mut node = Node::new(config).unwrap();

        // Build a few blocks to advance the chain
        let b1 = node.build_block().unwrap();
        node.process_block(b1).unwrap();
        let b2 = node.build_block().unwrap();
        node.process_block(b2).unwrap();

        node.state.get_next_difficulty_target(3).unwrap()
    };

    // Restart node and re-check
    let mut config = Config::default();
    config.data_dir = data_dir;
    let node_after = Node::new(config).unwrap();
    assert_eq!(node_after.best_height(), Some(2));

    let difficulty_after = node_after.state.get_next_difficulty_target(3).unwrap();
    assert_eq!(
        difficulty_before, difficulty_after,
        "difficulty target must survive a restart"
    );
}

// ---------------------------------------------------------------------------
// 4. Validator rejects block with wrong difficulty_target
// ---------------------------------------------------------------------------

#[test]
fn test_validator_rejects_wrong_difficulty() {
    let (_temp, mut node) = create_test_node();

    let b1 = node.build_block().unwrap();
    let prev_hash = b1.hash();
    node.process_block(b1).unwrap();

    // Expected difficulty for height 2
    let expected_diff = node.state.get_next_difficulty_target(2).unwrap();
    let wrong_diff = expected_diff ^ 0x0000_0001; // flip one bit

    let bad_block = make_block(2, prev_hash, wrong_diff, 1);

    let result = node.process_block(bad_block);
    assert!(
        result.is_err(),
        "block with wrong difficulty_target must be rejected"
    );
}

// ---------------------------------------------------------------------------
// 5. Validator accepts block with correct difficulty_target
// ---------------------------------------------------------------------------

#[test]
fn test_validator_accepts_correct_difficulty() {
    let (_temp, mut node) = create_test_node();

    let b1 = node.build_block().unwrap();
    node.process_block(b1).unwrap();

    // build_block already uses the correct difficulty
    let b2 = node.build_block().unwrap();
    let result = node.process_block(b2);
    assert!(
        result.is_ok(),
        "block with correct difficulty_target must be accepted"
    );
}

// ---------------------------------------------------------------------------
// 6. ConsensusValidator::with_expected_difficulty enforces the field
// ---------------------------------------------------------------------------

#[test]
fn test_consensus_validator_with_expected_difficulty() {
    let prev_hash = Hash256::zero();

    let correct_block = make_block(1, prev_hash, 0x1d00ffff, 0);
    let wrong_block = make_block(1, prev_hash, 0x1c00ffff, 0);

    let validator = ConsensusValidator::new(prev_hash, 1).with_expected_difficulty(0x1d00ffff);

    assert!(
        validator.validate_block(&correct_block).is_ok(),
        "block with matching difficulty must pass"
    );
    assert!(
        validator.validate_block(&wrong_block).is_err(),
        "block with mismatched difficulty must fail"
    );
}

// ---------------------------------------------------------------------------
// 7. LWMA retarget: faster mining → target decreases (harder)
// ---------------------------------------------------------------------------
//
// Build LWMA_WINDOW blocks with timestamps at TARGET_BLOCK_TIME/2 each,
// then verify the computed difficulty for the next block is harder.
//
// NOTE: Marked #[ignore] to keep CI fast; run with --ignored when needed.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "builds LWMA_WINDOW-block window; run explicitly with --ignored"]
fn test_retarget_faster_mining_decreases_target() {
    use axiom_consensus::LWMA_WINDOW;

    let temp_dir = TempDir::new().unwrap();
    let mut config = Config::default();
    config.data_dir = temp_dir.path().to_path_buf();
    let mut node = Node::new(config).unwrap();

    let half_block_time = (TARGET_BLOCK_TIME / 2) as u32;

    let genesis_hash = node.best_block_hash().unwrap();
    let genesis_difficulty = node.state.get_next_difficulty_target(1).unwrap();

    let mut prev = genesis_hash;
    for i in 1..=LWMA_WINDOW {
        let timestamp = i * half_block_time;
        let block = make_block(i, prev, genesis_difficulty, timestamp);
        prev = block.hash();
        node.process_block(block).unwrap();
    }

    let next_height = LWMA_WINDOW + 1;
    let new_diff = node.state.get_next_difficulty_target(next_height).unwrap();

    let old_target = CompactTarget(genesis_difficulty).to_target();
    let new_target = CompactTarget(new_diff).to_target();
    assert!(
        new_target < old_target,
        "faster mining should decrease target (increase difficulty)"
    );
}

// ---------------------------------------------------------------------------
// 8. LWMA retarget: slower mining → target increases (easier)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "builds LWMA_WINDOW-block window; run explicitly with --ignored"]
fn test_retarget_slower_mining_increases_target() {
    use axiom_consensus::{calculate_lwma_target, LWMA_WINDOW};

    let n = LWMA_WINDOW as usize;
    let base = CompactTarget(0x1c00ffff); // harder base so there is room to ease

    // Build N+1 uniform timestamps at 2× the target block time.
    let slow_solvetime = TARGET_BLOCK_TIME * 2;
    let timestamps: Vec<u64> = (0..=(n as u64)).map(|i| i * slow_solvetime).collect();
    let targets: Vec<CompactTarget> = vec![base; n];

    let new_target = calculate_lwma_target(&timestamps, &targets);

    assert!(
        new_target.to_target() > base.to_target(),
        "slower mining should increase target (decrease difficulty)"
    );
    assert!(
        new_target.to_target() <= CompactTarget::initial().to_target(),
        "new target must not exceed maximum"
    );
}

// ---------------------------------------------------------------------------
// 9. Retarget clamp: slowdown beyond 4× is clamped
// ---------------------------------------------------------------------------

#[test]
fn test_retarget_clamp_upper_bound() {
    use axiom_consensus::calculate_new_target;

    let old_target = CompactTarget(0x1c00ffff);
    let expected_time = DIFFICULTY_ADJUSTMENT_INTERVAL as u64 * TARGET_BLOCK_TIME;

    let result_4x = calculate_new_target(old_target, expected_time * 4, expected_time);
    let result_10x = calculate_new_target(old_target, expected_time * 10, expected_time);

    assert_eq!(
        result_4x, result_10x,
        "slowdown beyond 4× must be clamped to the 4× result"
    );
}

// ---------------------------------------------------------------------------
// 10. Retarget clamp: speedup beyond 4× is clamped
// ---------------------------------------------------------------------------

#[test]
fn test_retarget_clamp_lower_bound() {
    use axiom_consensus::calculate_new_target;

    let old_target = CompactTarget(0x1d00ffff);
    let expected_time = DIFFICULTY_ADJUSTMENT_INTERVAL as u64 * TARGET_BLOCK_TIME;

    let result_div4 = calculate_new_target(old_target, expected_time / 4, expected_time);
    let result_div10 = calculate_new_target(old_target, expected_time / 10, expected_time);

    assert_eq!(
        result_div4, result_div10,
        "speedup beyond 4× must be clamped to the 1/4× result"
    );
}

// ---------------------------------------------------------------------------
// 11. On-time mining → target unchanged
// ---------------------------------------------------------------------------

#[test]
fn test_retarget_on_time_unchanged() {
    use axiom_consensus::calculate_new_target;

    let old_target = CompactTarget(0x1d00ffff);
    let expected_time = DIFFICULTY_ADJUSTMENT_INTERVAL as u64 * TARGET_BLOCK_TIME;

    let new_target = calculate_new_target(old_target, expected_time, expected_time);

    assert_eq!(
        new_target, old_target,
        "on-time mining must not change the target"
    );
}

// ---------------------------------------------------------------------------
// 12. Target never exceeds maximum allowed
// ---------------------------------------------------------------------------

#[test]
fn test_target_never_exceeds_maximum() {
    use axiom_consensus::calculate_new_target;

    let old_target = CompactTarget(0x1d00ffff);
    let expected_time = DIFFICULTY_ADJUSTMENT_INTERVAL as u64 * TARGET_BLOCK_TIME;

    // Use absurdly slow mining
    let new_target = calculate_new_target(old_target, u64::MAX, expected_time);

    assert!(
        new_target.to_target() <= CompactTarget::initial().to_target(),
        "target must never exceed CompactTarget::initial()"
    );
}
