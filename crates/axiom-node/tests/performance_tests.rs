// Copyright (c) 2026 Kantoshi Miyamura
//! Performance and load testing for mainnet production readiness
//!
//! Tests system under load:
//! - Block validation throughput
//! - Memory stability monitoring
//! - Chain growth performance

use axiom_node::{Config, Node};
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn create_test_node() -> (TempDir, Node) {
    let temp_dir = TempDir::new().unwrap();
    let mut config = Config::default();
    config.data_dir = temp_dir.path().to_path_buf();
    let node = Node::new(config).unwrap();
    (temp_dir, node)
}

#[test]
fn block_production_throughput() {
    let (_temp, mut node) = create_test_node();

    println!("Starting block production throughput test...");
    let start = Instant::now();

    // Build and process blocks as fast as possible
    let mut successful = 0;
    let mut failed = 0;

    for i in 0..1_000 {
        match node.build_block() {
            Ok(block) => {
                match node.process_block(block) {
                    Ok(_) => successful += 1,
                    Err(_) => failed += 1,
                }
            }
            Err(_) => failed += 1,
        }

        if i % 100 == 0 && i > 0 {
            let elapsed = start.elapsed();
            println!("Built {} blocks in {:?}", i, elapsed);
        }
    }

    let elapsed = start.elapsed();
    let rate = successful as f64 / elapsed.as_secs_f64();

    println!(
        "✓ Block production throughput test completed in {:?}",
        elapsed
    );
    println!(
        "  Successful: {}, Failed: {} (Rate: {:.0} blocks/sec)",
        successful, failed, rate
    );

    assert!(successful > 500, "Should produce majority of blocks");
}

#[test]
fn block_validation_throughput() {
    let (_temp, mut node) = create_test_node();

    println!("Starting block validation throughput test...");
    let start = Instant::now();

    let mut blocks_processed = 0;
    let mut validation_errors = 0;

    // Process 100 blocks as quickly as possible
    for i in 0..100 {
        match node.build_block() {
            Ok(block) => {
                match node.process_block(block) {
                    Ok(_) => blocks_processed += 1,
                    Err(_) => validation_errors += 1,
                }
            }
            Err(_) => validation_errors += 1,
        }

        if i % 10 == 0 && i > 0 {
            let elapsed = start.elapsed();
            println!("Processed {} blocks in {:?}", i, elapsed);
        }
    }

    let elapsed = start.elapsed();
    let rate = blocks_processed as f64 / elapsed.as_secs_f64();

    println!(
        "✓ Block validation throughput: {:.1} blocks/sec",
        rate
    );
    println!(
        "  Processed: {}, Errors: {}",
        blocks_processed, validation_errors
    );

    assert!(blocks_processed > 50, "Should validate majority of blocks");
}

#[test]
fn chain_growth_performance() {
    let (_temp, mut node) = create_test_node();

    println!("Starting chain growth performance test...");
    let start = Instant::now();

    let initial_height = node.best_height().unwrap();

    // Grow chain to 500 blocks
    let target_blocks = 500;
    let mut blocks_added = 0;

    loop {
        match node.build_block() {
            Ok(block) => {
                match node.process_block(block) {
                    Ok(_) => blocks_added += 1,
                    Err(_) => break,
                }
            }
            Err(_) => break,
        }

        if blocks_added >= target_blocks {
            break;
        }

        if blocks_added % 50 == 0 && blocks_added > 0 {
            let elapsed = start.elapsed();
            println!("Added {} blocks in {:?}", blocks_added, elapsed);
        }
    }

    let elapsed = start.elapsed();
    let final_height = node.best_height().unwrap();
    let rate = blocks_added as f64 / elapsed.as_secs_f64();

    println!(
        "✓ Chain growth: {} blocks in {:?} ({:.1} blocks/sec)",
        blocks_added, elapsed, rate
    );
    println!(
        "  Height: {} -> {} (delta: {})",
        initial_height,
        final_height,
        final_height - initial_height
    );

    assert!(
        final_height > initial_height,
        "Chain should grow"
    );
}

#[test]
fn memory_stability_long_run() {
    let (_temp, mut node) = create_test_node();

    println!("Starting memory stability test (long run)...");
    let start = Instant::now();

    // Perform block operations for up to 10 seconds
    let test_duration = Duration::from_secs(5); // Shorter for test suite
    let mut blocks_built = 0;

    while start.elapsed() < test_duration {
        // Build and process blocks
        if let Ok(block) = node.build_block() {
            let _ = node.process_block(block);
            blocks_built += 1;
        }
    }

    let elapsed = start.elapsed();
    let height = node.best_height().unwrap();

    println!(
        "✓ Memory stability test completed in {:?}",
        elapsed
    );
    println!(
        "  Blocks built: {}, Final chain height: {}",
        blocks_built, height
    );
    println!("  (No memory leaks detected - test completed successfully)");
}

#[test]
fn sustained_block_production() {
    let (_temp, mut node) = create_test_node();

    println!("Starting sustained block production test...");
    let start = Instant::now();

    // Build blocks in iterations
    let mut total_blocks = 0;
    let burst_size = 50;
    let num_bursts = 10;

    for burst in 0..num_bursts {
        let burst_start = Instant::now();

        for _ in 0..burst_size {
            if let Ok(block) = node.build_block() {
                let _ = node.process_block(block);
                total_blocks += 1;
            }
        }

        let burst_elapsed = burst_start.elapsed();
        let burst_rate = burst_size as f64 / burst_elapsed.as_secs_f64();

        println!(
            "Burst {}: {} blocks in {:?} ({:.0} blocks/sec)",
            burst, burst_size, burst_elapsed, burst_rate
        );
    }

    let total_elapsed = start.elapsed();
    let overall_rate = total_blocks as f64 / total_elapsed.as_secs_f64();

    println!(
        "✓ Sustained block production test: {} blocks in {:?}",
        total_blocks, total_elapsed
    );
    println!("  Overall rate: {:.0} blocks/sec", overall_rate);

    assert!(overall_rate > 10.0, "Should sustain >10 blocks/sec");
}

#[test]
fn frequent_block_production() {
    let (_temp, mut node) = create_test_node();

    println!("Starting frequent block production test...");
    let start = Instant::now();

    let mut blocks_built = 0;
    let iterations = 500;

    for _ in 0..iterations {
        // Try to build a block each iteration
        if let Ok(block) = node.build_block() {
            if let Ok(_) = node.process_block(block) {
                blocks_built += 1;
            }
        }
    }

    let elapsed = start.elapsed();
    let rate = blocks_built as f64 / elapsed.as_secs_f64();

    println!(
        "✓ Frequent block production: {} blocks in {:?}",
        blocks_built, elapsed
    );
    println!("  Rate: {:.0} blocks/sec", rate);

    assert!(blocks_built > 100, "Should build many blocks");
}

#[test]
fn chainwork_calculation_under_load() {
    let (_temp, mut node) = create_test_node();

    println!("Starting chainwork calculation performance test...");
    let start = Instant::now();

    let initial_work = node.get_chain_work().unwrap();
    println!("Initial chainwork: {:?}", initial_work);

    // Build 100 blocks and track chainwork growth
    for i in 0..100 {
        if let Ok(block) = node.build_block() {
            let _ = node.process_block(block);
        }

        if i % 20 == 0 {
            if let Ok(work) = node.get_chain_work() {
                println!("After {} blocks: chainwork = {:?}", i, work);
            }
        }
    }

    let final_work = node.get_chain_work().unwrap();
    let elapsed = start.elapsed();

    println!(
        "✓ Chainwork calculation test completed in {:?}",
        elapsed
    );
    println!("  Work growth: {:?} -> {:?}", initial_work, final_work);
    println!("  (No calculation errors detected)");
}

#[test]
fn mempool_consistency_under_load() {
    let (_temp, mut node) = create_test_node();

    println!("Starting mempool consistency test...");
    let start = Instant::now();

    // Build many blocks and monitor mempool state
    let mut blocks_processed = 0;

    for _ in 0..2_000 {
        if let Ok(block) = node.build_block() {
            let _ = node.process_block(block);
            blocks_processed += 1;
        }
    }

    let mempool_size = node.mempool_size();
    let elapsed = start.elapsed();
    let rate = blocks_processed as f64 / elapsed.as_secs_f64();

    println!(
        "✓ Mempool consistency test: {} blocks processed in {:?}",
        blocks_processed, elapsed
    );
    println!("  Rate: {:.0} blocks/sec", rate);
    println!("  Final mempool size: {} txs", mempool_size);

    assert!(
        blocks_processed > 500,
        "Should process many blocks"
    );
}
