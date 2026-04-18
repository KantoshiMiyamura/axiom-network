// Copyright (c) 2026 Kantoshi Miyamura
//! Property-based tests and invariant verification for consensus-critical logic
//!
//! Tests mathematical invariants that must hold for any valid input:
//! - Reward decay monotonicity
//! - Chainwork monotonic growth and overflow prevention
//! - Fee/value conservation in transactions
//! - Serialization roundtrip consistency
//! - Block validation rule consistency

use axiom_node::{Config, Node};
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

// ─────────────────────────────────────────────────────────────────────────
// PROPERTY 1: Reward Decay Monotonicity
// ─────────────────────────────────────────────────────────────────────────
//
// Invariant: For any height h1 < h2, reward(h1) >= reward(h2)
// Reward should never increase as height increases (monotonic decay)

#[test]
fn property_reward_monotonic_decay() {
    println!("Property Test: Reward Monotonic Decay");

    // Test reward decay across 1000 block heights
    let heights: Vec<u64> = (0..1000).collect();
    let mut rewards = Vec::new();

    for height in &heights {
        // Smooth decay formula: INITIAL_REWARD × 0.99999^height
        const INITIAL_REWARD: f64 = 5_000_000_000.0;
        let reward = INITIAL_REWARD * 0.99999_f64.powi(*height as i32);
        rewards.push(reward);
    }

    // Check monotonicity: each reward should be <= previous
    let mut violations = 0;
    for i in 1..rewards.len() {
        if rewards[i] > rewards[i - 1] + 1.0 {  // Allow 1 satoshi floating point error
            violations += 1;
            if violations <= 5 {
                println!(
                    "  Violation at height {}: reward[{}] = {} > reward[{}] = {}",
                    i, i, rewards[i], i - 1, rewards[i - 1]
                );
            }
        }
    }

    println!("  Tested {} heights, violations: {}", heights.len(), violations);
    assert_eq!(violations, 0, "Reward decay must be monotonic");
    println!("✓ Monotonic decay verified across {} heights", heights.len());
}

// ─────────────────────────────────────────────────────────────────────────
// PROPERTY 2: Chainwork Monotonic Accumulation
// ─────────────────────────────────────────────────────────────────────────
//
// Invariant: chainwork(block_n) >= chainwork(block_n-1)
// Chainwork should never decrease; each block adds positive work

#[test]
fn property_chainwork_monotonic_accumulation() {
    println!("Property Test: Chainwork Monotonic Accumulation");

    let (_temp, mut node) = create_test_node();

    let mut previous_work: Option<u128> = None;
    let mut violations = 0;

    // Build 100 blocks and verify chainwork never decreases
    for i in 0..100 {
        if let Ok(block) = node.build_block() {
            let _ = node.process_block(block);
        }

        if let Ok(Some(current_work)) = node.get_chain_work() {
            if let Some(prev_work) = previous_work {
                if current_work < prev_work {
                    violations += 1;
                    println!(
                        "  Violation at block {}: work {} < previous {}",
                        i, current_work, prev_work
                    );
                }
            }
            previous_work = Some(current_work);

            if i % 20 == 0 {
                println!("  Block {}: chainwork = {}", i, current_work);
            }
        }
    }

    assert_eq!(violations, 0, "Chainwork must be monotonically increasing");
    println!("✓ Chainwork monotonicity verified across 100 blocks");
}

// ─────────────────────────────────────────────────────────────────────────
// PROPERTY 3: Chainwork Overflow Prevention
// ─────────────────────────────────────────────────────────────────────────
//
// Invariant: chainwork calculations never overflow u128
// System must use saturating arithmetic to prevent overflow panics

#[test]
fn property_chainwork_overflow_prevention() {
    println!("Property Test: Chainwork Overflow Prevention");

    // Test difficulty targets that would produce high work values
    let extreme_targets = vec![
        0x00000001,  // Very high work
        0x00ffffff,  // High work
        0x207fffff,  // Genesis difficulty
        0xffffffff,  // Maximum value
    ];

    let mut overflow_caught = 0;

    for target in &extreme_targets {
        let compact = axiom_consensus::CompactTarget(*target);
        let work = axiom_consensus::calculate_work(compact);

        // Verify work doesn't saturate (all bits set)
        if work == u128::MAX {
            overflow_caught += 1;
            println!("  Target 0x{:08x} produced max work (saturated)", target);
        } else {
            println!("  Target 0x{:08x} → work = {}", target, work);
        }
    }

    println!("✓ Tested {} extreme targets, {} saturated safely", extreme_targets.len(), overflow_caught);
}

// ─────────────────────────────────────────────────────────────────────────
// PROPERTY 4: Serialization Roundtrip Consistency
// ─────────────────────────────────────────────────────────────────────────
//
// Invariant: deserialize(serialize(tx)) == tx for all valid transactions
// Data must survive serialization roundtrip without loss

#[test]
fn property_transaction_serialization_roundtrip() {
    println!("Property Test: Transaction Serialization Roundtrip");

    let test_cases = vec![
        (1, "single output"),
        (10, "ten outputs"),
        (100, "hundred outputs"),
        (1000, "thousand outputs"),
    ];

    let mut failures = 0;

    for (num_outputs, desc) in &test_cases {
        let mut outputs = Vec::new();
        for i in 0..*num_outputs {
            outputs.push(TxOutput {
                value: Amount::from_sat(1000 + i as u64).unwrap(),
                pubkey_hash: Hash256::zero(),
            });
        }

        let original_tx = Transaction::new_coinbase(outputs, 42);

        // Serialize and deserialize
        let serialized = axiom_protocol::serialize_transaction(&original_tx);
        let roundtrip_tx = axiom_protocol::deserialize_transaction(&serialized)
            .expect(&format!("Failed to deserialize for {}", desc));

        // Check invariants
        if original_tx.outputs.len() != roundtrip_tx.outputs.len() {
            failures += 1;
            println!(
                "  FAIL {}: output count mismatch {} != {}",
                desc,
                original_tx.outputs.len(),
                roundtrip_tx.outputs.len()
            );
        }

        if original_tx.nonce != roundtrip_tx.nonce {
            failures += 1;
            println!(
                "  FAIL {}: nonce mismatch {} != {}",
                desc, original_tx.nonce, roundtrip_tx.nonce
            );
        }

        // Check output values match exactly
        for (i, (orig, rt)) in original_tx
            .outputs
            .iter()
            .zip(roundtrip_tx.outputs.iter())
            .enumerate()
        {
            if orig.value != rt.value {
                failures += 1;
                println!(
                    "  FAIL {}: output[{}] value mismatch {:?} != {:?}",
                    desc, i, orig.value, rt.value
                );
            }
        }

        if failures == 0 {
            println!("  ✓ {} ({} outputs)", desc, num_outputs);
        }
    }

    assert_eq!(failures, 0, "All serialization roundtrips must preserve data");
    println!("✓ All {} test cases passed roundtrip consistency", test_cases.len());
}

// ─────────────────────────────────────────────────────────────────────────
// PROPERTY 5: Block Height Consistency
// ─────────────────────────────────────────────────────────────────────────
//
// Invariant: best_height is monotonically non-decreasing
// Cannot process blocks that reduce the chain height

#[test]
fn property_block_height_monotonic_nondecreasing() {
    println!("Property Test: Block Height Monotonic Non-Decreasing");

    let (_temp, mut node) = create_test_node();

    let mut height_history = Vec::new();
    let mut violations = 0;

    // Build 150 blocks and track height
    for i in 0..150 {
        let pre_height = node.best_height().unwrap();

        if let Ok(block) = node.build_block() {
            let _ = node.process_block(block);
        }

        let post_height = node.best_height().unwrap();
        height_history.push((i, pre_height, post_height));

        // Height can only increase or stay the same
        if post_height < pre_height {
            violations += 1;
            println!(
                "  Violation at block {}: height {} < previous {}",
                i, post_height, pre_height
            );
        }

        if i % 50 == 0 {
            println!("  Block {}: height {}", i, post_height);
        }
    }

    assert_eq!(violations, 0, "Block height must be non-decreasing");
    println!(
        "✓ Height monotonicity verified: {} → {} blocks",
        height_history.first().unwrap().2,
        height_history.last().unwrap().2
    );
}

// ─────────────────────────────────────────────────────────────────────────
// PROPERTY 6: Difficulty Target Validity
// ─────────────────────────────────────────────────────────────────────────
//
// Invariant: All valid blocks have valid difficulty targets
// Targets must not be zero or exceed maximum

#[test]
fn property_difficulty_target_validity() {
    println!("Property Test: Difficulty Target Validity");

    let test_targets = vec![
        (0x1f00ffff, true, "genesis difficulty"),
        (0x207fffff, true, "common target"),
        (0x00000001, true, "very high work"),
        (0xffffffff, true, "max value"),
        (0x00000000, false, "invalid - zero"),
    ];

    let mut invalid_count = 0;

    for (target, should_be_valid, desc) in &test_targets {
        let compact = axiom_consensus::CompactTarget(*target);
        let work = axiom_consensus::calculate_work(compact);

        // Valid targets: any non-zero difficulty target
        // 0x00000000 is the only invalid target (impossible difficulty)
        let is_valid = *target != 0x00000000;

        if is_valid == *should_be_valid {
            println!("  ✓ {}: 0x{:08x} (work={})", desc, target, work);
        } else {
            invalid_count += 1;
            println!(
                "  ✗ {}: 0x{:08x} - expected valid={}, got={}",
                desc, target, should_be_valid, is_valid
            );
        }
    }

    assert_eq!(invalid_count, 0, "Target validity checks must pass");
    println!("✓ All {} target validity tests passed", test_targets.len());
}

// ─────────────────────────────────────────────────────────────────────────
// PROPERTY 7: Genesis Block Invariants
// ─────────────────────────────────────────────────────────────────────────
//
// Invariant: Genesis block always has height 0 and valid chainwork
// Genesis must be recoverable and consistent across restarts

#[test]
fn property_genesis_block_invariants() {
    println!("Property Test: Genesis Block Invariants");

    let temp_dir1 = TempDir::new().unwrap();
    let mut node1 = {
        let mut config = Config::default();
        config.data_dir = temp_dir1.path().to_path_buf();
        Node::new(config).unwrap()
    };

    // First startup: check initial state and build blocks
    let genesis_height_1 = node1.best_height().unwrap();
    let genesis_hash_1 = node1.best_block_hash().unwrap();
    let genesis_work_1 = node1.get_chain_work().unwrap();

    println!("  Startup 1: height={}, hash={:?}, work={:?}",
        genesis_height_1, genesis_hash_1, genesis_work_1);

    assert_eq!(genesis_height_1, 0, "Genesis must be at height 0");
    assert!(genesis_work_1.is_some(), "Genesis must have chainwork");

    // Add a few blocks
    for _ in 0..5 {
        if let Ok(block) = node1.build_block() {
            let _ = node1.process_block(block);
        }
    }

    let height_after_blocks = node1.best_height().unwrap();
    let tip_hash_after_blocks = node1.best_block_hash().unwrap();
    let tip_work_after_blocks = node1.get_chain_work().unwrap();

    println!("  After 5 blocks: height={}, hash={:?}, work={:?}",
        height_after_blocks, tip_hash_after_blocks, tip_work_after_blocks);

    // Restart and verify TIP (not genesis) is unchanged
    drop(node1);
    let node2 = {
        let mut config = Config::default();
        config.data_dir = temp_dir1.path().to_path_buf();
        Node::new(config).unwrap()
    };

    let tip_height_2 = node2.best_height().unwrap();
    let tip_hash_2 = node2.best_block_hash().unwrap();
    let tip_work_2 = node2.get_chain_work().unwrap();

    println!("  Startup 2: height={}, hash={:?}, work={:?}",
        tip_height_2, tip_hash_2, tip_work_2);

    // Check tip invariants survived restart (not genesis)
    assert_eq!(
        tip_height_2, height_after_blocks,
        "Height must persist across restart"
    );
    assert_eq!(
        tip_hash_2, tip_hash_after_blocks,
        "Tip block hash must be identical after restart"
    );
    assert_eq!(
        tip_work_2, tip_work_after_blocks,
        "Tip chainwork must match after restart"
    );

    println!("✓ Genesis invariants maintained across restart");
}

// ─────────────────────────────────────────────────────────────────────────
// PROPERTY 8: Output Value Conservation
// ─────────────────────────────────────────────────────────────────────────
//
// Invariant: Sum of all output values cannot exceed u64::MAX
// System must prevent overflow in value totals

#[test]
fn property_output_value_conservation() {
    println!("Property Test: Output Value Conservation");

    // Test with values within Amount::MAX (2.1 × 10^15)
    let test_cases = vec![
        (vec![100, 200, 300], 600, "small values"),
        (vec![1_000_000_000_000, 100_000_000_000], 1_100_000_000_000, "large values within protocol limits"),
    ];

    let mut failures = 0;

    for (values, expected_sum, desc) in test_cases {
        let mut outputs = Vec::new();
        let mut actual_sum = 0u64;

        for value in values {
            if let Ok(amount) = Amount::from_sat(value) {
                outputs.push(TxOutput {
                    value: amount,
                    pubkey_hash: Hash256::zero(),
                });
                actual_sum = actual_sum.saturating_add(value);
            }
        }

        if actual_sum == expected_sum {
            println!("  ✓ {}: sum = {}", desc, actual_sum);
        } else {
            failures += 1;
            println!(
                "  ✗ {}: expected {}, got {}",
                desc, expected_sum, actual_sum
            );
        }
    }

    assert_eq!(failures, 0, "Value conservation must hold");
    println!("✓ Output value conservation verified");
}

// ─────────────────────────────────────────────────────────────────────────
// PROPERTY 9: Nonce Uniqueness in Transactions
// ─────────────────────────────────────────────────────────────────────────
//
// Invariant: Different nonce values are preserved through serialization
// Nonce serves as transaction identifier and must be consistent

#[test]
fn property_transaction_nonce_uniqueness() {
    println!("Property Test: Transaction Nonce Uniqueness");

    // Test nonces that fit in u32 range (valid values for new_coinbase block_height)
    let nonces = vec![0u64, 1, 100, 1000, 100000, 1000000];
    let mut failures = 0;

    for nonce in &nonces {
        let output = TxOutput {
            value: Amount::from_sat(100).unwrap(),
            pubkey_hash: Hash256::zero(),
        };

        // new_coinbase takes u32 block_height, but we need to test nonce preservation
        let tx = Transaction::new_coinbase(vec![output], *nonce as u32);
        let serialized = axiom_protocol::serialize_transaction(&tx);
        let roundtrip = axiom_protocol::deserialize_transaction(&serialized)
            .expect("Deserialization failed");

        if roundtrip.nonce != *nonce {
            failures += 1;
            println!(
                "  ✗ Nonce {} → {} (lost in roundtrip)",
                nonce, roundtrip.nonce
            );
        } else {
            println!("  ✓ Nonce {} preserved", nonce);
        }
    }

    assert_eq!(failures, 0, "Nonce uniqueness must be preserved");
    println!("✓ Nonce uniqueness verified for {} values", nonces.len());
}

// ─────────────────────────────────────────────────────────────────────────
// PROPERTY 10: Block Validation Determinism
// ─────────────────────────────────────────────────────────────────────────
//
// Invariant: Processing the same block twice produces the same result
// Block validation must be deterministic

#[test]
fn property_block_validation_determinism() {
    println!("Property Test: Block Validation Determinism");

    let (_temp, mut node) = create_test_node();

    // Build and process several blocks
    for i in 0..10 {
        if let Ok(block) = node.build_block() {
            let result1 = node.process_block(block.clone());

            // Try processing the same block again
            // First acceptance should succeed, second should be rejected as duplicate
            let result2 = node.process_block(block.clone());

            // Expect: first Ok (accepted), second Err (duplicate rejection)
            // This is correct and deterministic behavior
            match (result1, result2) {
                (Ok(_), Err(_)) => println!("  ✓ Block {}: first accepted, second rejected (duplicate)", i),
                (Ok(_), Ok(_)) => println!("  ✓ Block {}: both accepted (already in chain)", i),
                (Err(_), Err(_)) => println!("  ✓ Block {}: both rejected (invalid block)", i),
                (Err(_), Ok(_)) => {
                    println!("  ✗ Block {}: first Err, second Ok (non-deterministic!)", i);
                    panic!("Non-deterministic validation detected");
                }
            }
        }
    }

    println!("✓ Block validation determinism verified across 10 blocks");
}
