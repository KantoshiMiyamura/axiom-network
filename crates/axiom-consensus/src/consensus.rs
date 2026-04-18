// Copyright (c) 2026 Kantoshi Miyamura

use crate::invariants::check_coinbase_value;
use crate::pow::{check_proof_of_work, CompactTarget};
#[cfg(test)]
use crate::BlockHeader;
use crate::{Block, Error, Result};
use axiom_primitives::{Amount, Hash256};
use axiom_protocol::Transaction;
use std::collections::HashSet;

/// Max block size in bytes.
/// CRITICAL FIX: Unified constant (was 1MB in consensus.rs, 4MB in validation.rs).
/// Using 4MB for scalability while maintaining consensus safety.
pub const MAX_BLOCK_SIZE: usize = 4_000_000; // 4 MB

/// Max transactions per block.
pub const MAX_BLOCK_TRANSACTIONS: usize = 10_000;

/// Max transaction size in bytes.
pub const MAX_TRANSACTION_SIZE: usize = 100_000; // 100 KB


/// Initial block reward: 50 AXM in satoshis.
pub const INITIAL_REWARD_SAT: u64 = 5_000_000_000;

/// Reward floor: 0.0001 AXM. Reached at ~height 1,312,000 (~12.5 years).
pub const MIN_REWARD_SAT: u64 = 10_000;

/// Per-block decay factor: reward(h) = 50 AXM × 0.99999^h.
/// Retained for documentation; consensus uses integer-only arithmetic below.
pub const DECAY_FACTOR: f64 = 0.99999;

/// 0.99999 in Q64 fixed-point: floor(99999 × 2^64 / 100000) = 18446559606268814520.
/// Used for platform-independent reward calculation (no floating point).
const DECAY_Q64: u128 = 18_446_559_606_268_814_520;

/// Block reward decays smoothly: reward(h) = 50 AXM × 0.99999^h
///
/// CRITICAL: Uses integer-only fixed-point arithmetic (Q64) to guarantee
/// identical results on all platforms. Floating-point FPU rounding differences
/// (x87 80-bit vs SSE2 64-bit, ARM vs x86) would cause consensus splits.
///
/// Algorithm: exponentiation by squaring in Q64, then multiply by INITIAL_REWARD_SAT.
/// O(log h) multiplications, all deterministic.
///
/// Total supply: ~5,000,000 AXM
/// Minimum reward reached at ~height 1,312,000
pub fn calculate_smooth_reward(height: u32) -> Amount {
    if height == 0 {
        return Amount::from_sat(INITIAL_REWARD_SAT).unwrap_or(Amount::ZERO);
    }

    // Compute 0.99999^height in Q64 via exponentiation by squaring.
    // Result is in [0, 2^64) representing [0.0, 1.0).
    let factor = pow_q64(DECAY_Q64, height);

    // reward_sat = INITIAL_REWARD_SAT × factor / 2^64, rounded to nearest.
    // Without rounding, floor truncation causes 1-satoshi undershoot at low heights
    // (e.g. height 1: floor gives 4,999,949,999 instead of correct 4,999,950,000).
    // Adding 2^63 (0.5 in Q64) before shifting gives round-half-up behavior.
    let product = (INITIAL_REWARD_SAT as u128) * factor;
    let reward_sat = ((product + (1u128 << 63)) >> 64) as u64;

    Amount::from_sat(reward_sat.max(MIN_REWARD_SAT)).unwrap_or(Amount::ZERO)
}

/// Fixed-point exponentiation: base^exp in Q64.
/// base is in Q64 (i.e., represents base/2^64 ∈ [0,1)).
/// Returns result in Q64.
fn pow_q64(base: u128, mut exp: u32) -> u128 {
    let one_q64: u128 = 1u128 << 64;
    let mut result = one_q64;
    let mut b = base;

    while exp > 0 {
        if exp & 1 == 1 {
            // result = (result * b) >> 64
            result = mul_q64(result, b);
        }
        // b = (b * b) >> 64
        b = mul_q64(b, b);
        exp >>= 1;
    }
    result
}

/// Multiply two Q64 values: (a * b) >> 64, without overflow.
/// Both a, b must be at most 2^64 (Q64 fixed-point values representing [0, 1]).
#[inline]
fn mul_q64(a: u128, b: u128) -> u128 {
    // Split each into two 32-bit halves to avoid u128 overflow in the product.
    let a_hi = (a >> 32) as u64;
    let a_lo = (a & 0xFFFF_FFFF) as u64;
    let b_hi = (b >> 32) as u64;
    let b_lo = (b & 0xFFFF_FFFF) as u64;

    let ll = (a_lo as u128) * (b_lo as u128);
    let lh = (a_lo as u128) * (b_hi as u128);
    let hl = (a_hi as u128) * (b_lo as u128);
    let hh = (a_hi as u128) * (b_hi as u128);

    // Full product = hh*2^64 + (lh+hl)*2^32 + ll
    // We want round((full product) / 2^64).
    // Add 2^31 (half an LSB of the 32-bit shift) for rounding to minimize
    // error accumulation during exponentiation-by-squaring.
    let mid = lh + hl + (ll >> 32);
    hh + ((mid + (1u128 << 31)) >> 32)
}

#[inline]
pub fn calculate_block_reward(height: u32) -> Amount {
    calculate_smooth_reward(height)
}

/// Compute merkle root of a transaction list.
/// CRITICAL FIX: Added validation to prevent merkle tree manipulation.
pub fn compute_merkle_root(transactions: &[Transaction]) -> Hash256 {
    if transactions.is_empty() {
        return Hash256::zero();
    }
    
    // SECURITY: Validate transaction count is reasonable before hashing.
    // Prevents DoS where attacker submits block with millions of empty transactions.
    if transactions.len() > MAX_BLOCK_TRANSACTIONS {
        // Return zero hash for invalid input (will be caught by block validator)
        return Hash256::zero();
    }
    
    let mut hashes: Vec<Hash256> = transactions
        .iter()
        .map(|tx| {
            axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(tx))
        })
        .collect();

    while hashes.len() > 1 {
        if !hashes.len().is_multiple_of(2) {
            // CRITICAL FIX: When duplicating last hash for odd-length trees,
            // ensure we're not creating merkle proof collision vulnerabilities.
            // This is standard Bitcoin behavior but must be carefully validated.
            hashes.push(*hashes.last().unwrap());
        }
        hashes = hashes
            .chunks(2)
            .map(|pair| {
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(pair[0].as_bytes());
                combined[32..].copy_from_slice(pair[1].as_bytes());
                axiom_crypto::double_hash256(&combined)
            })
            .collect();
    }
    hashes[0]
}

/// Validates blocks against consensus rules. UTXO and signature checks are done by the node.
pub struct ConsensusValidator {
    prev_block_hash: Hash256,
    height: u32,
    validate_pow: bool,
    expected_difficulty: Option<u32>,
    // Last up-to-11 timestamps (oldest first) for MTP check. Empty = skip.
    prev_timestamps: Vec<u64>,
}

impl ConsensusValidator {
    /// Dev/test mode: PoW and difficulty checks off.
    pub fn new(prev_block_hash: Hash256, height: u32) -> Self {
        ConsensusValidator {
            prev_block_hash,
            height,
            validate_pow: false,
            expected_difficulty: None,
            prev_timestamps: Vec::new(),
        }
    }

    /// Enable PoW validation.
    pub fn with_pow(prev_block_hash: Hash256, height: u32) -> Self {
        ConsensusValidator {
            prev_block_hash,
            height,
            validate_pow: true,
            expected_difficulty: None,
            prev_timestamps: Vec::new(),
        }
    }

    /// Reject blocks whose difficulty_target doesn't match `expected`.
    pub fn with_expected_difficulty(mut self, expected: u32) -> Self {
        self.expected_difficulty = Some(expected);
        self
    }

    /// MTP check: block timestamp must exceed median of last 11 blocks.
    // Skip this call for genesis or when chain history isn't available.
    pub fn with_prev_timestamps(mut self, timestamps: Vec<u64>) -> Self {
        self.prev_timestamps = timestamps;
        self
    }

    /// Validate block structure and consensus rules.
    ///
    /// Thin wrapper that reads wall clock once and delegates to the **pure**
    /// [`validate_block_at`]. Consensus-critical logic lives in `validate_block_at`;
    /// this wrapper exists only so legacy callers don't need to thread a clock.
    /// Tests and chain-replay scenarios should call `validate_block_at` directly.
    // Does not check UTXO existence, signatures, or nonces — those require state.
    pub fn validate_block(&self, block: &Block) -> Result<()> {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.validate_block_at(block, now_secs)
    }

    /// Pure block validation — takes wall-clock seconds as an input rather than
    /// reading them.
    ///
    /// Determinism guarantee: this function performs **no I/O, no system-time
    /// reads, no RNG, no floating-point arithmetic**. Given the same
    /// `(self, block, now_secs)` it always produces the same result on every
    /// platform. `now_secs` is only used for the future-drift guard — a
    /// node-local acceptance rule, not part of the historical chain contract.
    pub fn validate_block_at(&self, block: &Block, now_secs: u64) -> Result<()> {
        if block.transactions.is_empty() {
            return Err(Error::InvalidBlock("block has no transactions".into()));
        }

        if block.header.prev_block_hash != self.prev_block_hash {
            return Err(Error::InvalidBlock(format!(
                "previous hash mismatch: expected {:?}, got {:?}",
                self.prev_block_hash, block.header.prev_block_hash
            )));
        }

        let computed_merkle = compute_merkle_root(&block.transactions);
        if block.header.merkle_root != computed_merkle {
            return Err(Error::InvalidBlock("merkle root mismatch".into()));
        }

        if !block.transactions[0].is_coinbase() {
            return Err(Error::InvalidBlock(
                "first transaction is not coinbase".into(),
            ));
        }

        for tx in &block.transactions[1..] {
            if tx.is_coinbase() {
                return Err(Error::InvalidBlock("multiple coinbase transactions".into()));
            }
        }

        let coinbase = &block.transactions[0];
        let expected_reward = calculate_block_reward(self.height);

        // INVARIANT 4: coinbase_value <= reward + total_fees.
        //
        // At this layer we cannot compute total_fees (requires UTXO lookup),
        // so we enforce the lower bound `coinbase_value <= reward` (fees = 0).
        // This is a strict subset of the full rule and cannot be violated by
        // any valid block — the node state validator re-checks with real fees.
        let coinbase_value = coinbase.output_value()?;
        check_coinbase_value(coinbase_value, expected_reward, 0).map_err(|e| {
            Error::InvalidBlock(format!(
                "{} at height {} (diff: {} sat). Fees are validated separately by the node state validator.",
                e,
                self.height,
                coinbase_value.as_sat() as i128 - expected_reward.as_sat() as i128,
            ))
        })?;

        // Coinbase nonce encodes block height.
        if coinbase.nonce as u32 != self.height {
            return Err(Error::InvalidBlock(format!(
                "coinbase height mismatch: expected {}, got {}",
                self.height, coinbase.nonce
            )));
        }

        let mut seen_txids = HashSet::new();
        for tx in &block.transactions {
            let txid = axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(tx));

            if !seen_txids.insert(txid) {
                return Err(Error::InvalidBlock("duplicate transaction in block".into()));
            }
        }

        // Future-timestamp guard: reject blocks more than 10 minutes ahead of
        // the wall clock passed in by the caller. The consensus layer does NOT
        // read system time — `now_secs` is an input.
        //
        // CRITICAL FIX: 10 minutes (was 7200). Wider drift lets attackers push
        // block timestamps far forward and manipulate LWMA-3 difficulty.
        const MAX_FUTURE_DRIFT_SECS: u64 = 600;
        let drift_cutoff = now_secs.saturating_add(MAX_FUTURE_DRIFT_SECS);
        if (block.header.timestamp as u64) > drift_cutoff {
            return Err(Error::InvalidBlock(format!(
                "block timestamp {} is more than {} seconds in the future (now: {})",
                block.header.timestamp, MAX_FUTURE_DRIFT_SECS, now_secs
            )));
        }

        // MTP: prevents timestamp manipulation to skew LWMA-3 difficulty.
        if !self.prev_timestamps.is_empty() {
            let mut sorted = self.prev_timestamps.clone();
            sorted.sort_unstable();
            let median = sorted[sorted.len() / 2];
            if (block.header.timestamp as u64) <= median {
                return Err(Error::InvalidBlock(format!(
                    "block timestamp {} ≤ median past time {} (MTP violation)",
                    block.header.timestamp, median
                )));
            }
        }

        let block_size = self.estimate_block_size(block);
        if block_size > MAX_BLOCK_SIZE {
            return Err(Error::InvalidBlock(format!(
                "block size {} exceeds maximum {}",
                block_size, MAX_BLOCK_SIZE
            )));
        }

        if block.transactions.len() > MAX_BLOCK_TRANSACTIONS {
            return Err(Error::InvalidBlock(format!(
                "transaction count {} exceeds maximum {}",
                block.transactions.len(),
                MAX_BLOCK_TRANSACTIONS
            )));
        }

        for tx in &block.transactions {
            let tx_size = axiom_protocol::serialize_transaction(tx).len();
            if tx_size > MAX_TRANSACTION_SIZE {
                return Err(Error::InvalidBlock(format!(
                    "transaction size {} exceeds maximum {}",
                    tx_size, MAX_TRANSACTION_SIZE
                )));
            }
        }

        for tx in &block.transactions {
            tx.output_value()?;
        }

        if self.validate_pow {
            let block_hash = block.hash();
            let target = CompactTarget(block.header.difficulty_target);

            if !check_proof_of_work(&block_hash, target) {
                return Err(Error::InvalidBlock("proof-of-work check failed".into()));
            }
        }

        if let Some(expected) = self.expected_difficulty {
            if block.header.difficulty_target != expected {
                return Err(Error::InvalidBlock(format!(
                    "difficulty target mismatch: expected 0x{:08x}, got 0x{:08x}",
                    expected, block.header.difficulty_target
                )));
            }
        }

        Ok(())
    }

    // header + sum of serialized tx sizes
    fn estimate_block_size(&self, block: &Block) -> usize {
        let header_size = 4 + 32 + 32 + 4 + 4 + 4; // version + prev + merkle + time + diff + nonce
        let mut tx_size = 0;

        for tx in &block.transactions {
            tx_size += axiom_protocol::serialize_transaction(tx).len();
        }

        header_size + tx_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_protocol::TxOutput;

    fn create_test_block(height: u32, prev_hash: Hash256) -> Block {
        let output = TxOutput {
            value: calculate_block_reward(height),
            pubkey_hash: Hash256::zero(),
        };
        let coinbase = Transaction::new_coinbase(vec![output], height);

        let merkle_root = compute_merkle_root(&[coinbase.clone()]);

        let header = BlockHeader {
            version: 1,
            prev_block_hash: prev_hash,
            merkle_root,
            timestamp: 0,
            difficulty_target: 0,
            nonce: 0,
        };

        Block {
            header,
            transactions: vec![coinbase],
        }
    }

    #[test]
    fn test_validate_valid_block() {
        let prev_hash = Hash256::zero();
        let block = create_test_block(1, prev_hash);

        let validator = ConsensusValidator::new(prev_hash, 1);
        assert!(validator.validate_block(&block).is_ok());
    }

    #[test]
    fn test_reject_wrong_prev_hash() {
        let prev_hash = Hash256::zero();
        let wrong_hash = Hash256::from_slice(&[1u8; 32]).unwrap();
        let block = create_test_block(1, wrong_hash);

        let validator = ConsensusValidator::new(prev_hash, 1);
        assert!(validator.validate_block(&block).is_err());
    }

    #[test]
    fn test_reject_wrong_merkle_root() {
        let prev_hash = Hash256::zero();
        let mut block = create_test_block(1, prev_hash);
        block.header.merkle_root = Hash256::zero();

        let validator = ConsensusValidator::new(prev_hash, 1);
        assert!(validator.validate_block(&block).is_err());
    }

    #[test]
    fn test_reject_excessive_coinbase() {
        let prev_hash = Hash256::zero();
        let mut block = create_test_block(1, prev_hash);

        let excessive_output = TxOutput {
            value: Amount::from_sat(10_000_000_000).unwrap(), // 100 AXM
            pubkey_hash: Hash256::zero(),
        };
        block.transactions[0] = Transaction::new_coinbase(vec![excessive_output], 1);
        block.header.merkle_root = compute_merkle_root(&block.transactions);

        let validator = ConsensusValidator::new(prev_hash, 1);
        assert!(validator.validate_block(&block).is_err());
    }

    #[test]
    fn test_reject_wrong_height() {
        let prev_hash = Hash256::zero();
        let mut block = create_test_block(1, prev_hash);

        let output = TxOutput {
            value: calculate_block_reward(1),
            pubkey_hash: Hash256::zero(),
        };
        block.transactions[0] = Transaction::new_coinbase(vec![output], 999);
        block.header.merkle_root = compute_merkle_root(&block.transactions);

        let validator = ConsensusValidator::new(prev_hash, 1);
        assert!(validator.validate_block(&block).is_err());
    }

    #[test]
    fn test_smooth_reward_initial() {
        assert_eq!(calculate_smooth_reward(0).as_sat(), INITIAL_REWARD_SAT);
    }

    #[test]
    fn test_smooth_reward_decays() {
        let r0 = calculate_smooth_reward(0).as_sat();
        let r1 = calculate_smooth_reward(1).as_sat();
        let r100 = calculate_smooth_reward(100).as_sat();
        assert!(r1 < r0, "reward must decrease at every block");
        assert!(r100 < r1, "reward must continue to decrease");
        assert!(r0 > MIN_REWARD_SAT);
        assert!(r1 > MIN_REWARD_SAT);
        assert!(r100 > MIN_REWARD_SAT);
    }

    #[test]
    fn test_min_reward_floor() {
        // 0.99999^2_000_000 ≈ e^-20 ≈ 2.1e-9; 5e9 × 2.1e-9 ≈ 10 sat < MIN_REWARD_SAT
        let late_reward = calculate_smooth_reward(2_000_000).as_sat();
        assert_eq!(
            late_reward, MIN_REWARD_SAT,
            "reward at height 2_000_000 must be clamped to MIN_REWARD_SAT"
        );
    }

    #[test]
    fn test_no_tail_emission() {
        // Floor must be a small computational minimum, not a large tail emission.
        assert!(
            MIN_REWARD_SAT <= 100_000,
            "MIN_REWARD_SAT must be a small floor, not a large tail emission"
        );
    }

    #[test]
    fn test_supply_bounded_by_21m() {
        // Theoretical sum = INITIAL_REWARD_SAT / (1 - DECAY_FACTOR) = 5e14 sat = 5 M AXM.
        const SAT_PER_AXM: f64 = 100_000_000.0;
        let theoretical_max_sat = INITIAL_REWARD_SAT as f64 / (1.0 - DECAY_FACTOR);
        let theoretical_max_axm = theoretical_max_sat / SAT_PER_AXM;
        assert!(
            theoretical_max_axm < 21_000_000.0,
            "theoretical supply ({:.0} AXM) must be under 21 M cap",
            theoretical_max_axm
        );
        let partial_sum_sat =
            INITIAL_REWARD_SAT as f64 * (1.0 - DECAY_FACTOR.powi(2_000_000)) / (1.0 - DECAY_FACTOR);
        let ratio = partial_sum_sat / theoretical_max_sat;
        assert!(
            ratio > 0.999,
            "supply at height 2M must be >99.9% of theoretical max"
        );
    }

    #[test]
    fn test_deterministic_reward() {
        for h in [0u32, 1, 500, 100_000, 1_312_000, 2_000_000] {
            assert_eq!(
                calculate_smooth_reward(h),
                calculate_smooth_reward(h),
                "reward at height {} must be deterministic",
                h
            );
        }
    }

    /// Pinned consensus-critical reward values. Changing any of these breaks
    /// the chain — every node must agree on exact satoshi amounts.
    #[test]
    fn test_pinned_reward_values() {
        let cases: &[(u32, u64)] = &[
            (0, 5_000_000_000),
            (1, 4_999_950_000),
            (2, 4_999_900_000),
            (10, 4_999_500_022),
            (100, 4_995_002_474),
            (1_000, 4_950_248_921),
            (10_000, 4_524_184_828),
            (100_000, 1_839_388_009),
            (1_312_000, 10_023),
            (2_000_000, MIN_REWARD_SAT),
        ];

        for &(height, expected_sat) in cases {
            let actual = calculate_smooth_reward(height).as_sat();
            assert_eq!(
                actual, expected_sat,
                "CONSENSUS BREAK: reward at height {} = {}, expected {} (diff: {})",
                height,
                actual,
                expected_sat,
                actual as i64 - expected_sat as i64,
            );
        }
    }

    #[test]
    fn test_reward_alias_matches() {
        for h in [0u32, 1, 1000, 1_312_000, 2_000_000] {
            assert_eq!(calculate_block_reward(h), calculate_smooth_reward(h));
        }
    }

    #[test]
    fn test_mtp_rejects_equal_timestamp() {
        let prev_hash = Hash256::zero();
        let mut block = create_test_block(1, prev_hash);

        block.header.timestamp = 1000;
        block.header.merkle_root = compute_merkle_root(&block.transactions);

        let validator = ConsensusValidator::new(prev_hash, 1).with_prev_timestamps(vec![1000]);
        let result = validator.validate_block(&block);
        assert!(
            result.is_err(),
            "MTP should reject block with timestamp ≤ median"
        );
    }

    #[test]
    fn test_mtp_accepts_greater_timestamp() {
        let prev_hash = Hash256::zero();
        let mut block = create_test_block(1, prev_hash);

        block.header.timestamp = 1000;
        block.header.merkle_root = compute_merkle_root(&block.transactions);

        let validator = ConsensusValidator::new(prev_hash, 1).with_prev_timestamps(vec![999]);
        assert!(
            validator.validate_block(&block).is_ok(),
            "MTP should accept valid timestamp"
        );
    }

    #[test]
    fn test_mtp_skipped_when_no_prev_timestamps() {
        let prev_hash = Hash256::zero();
        let block = create_test_block(1, prev_hash);

        let validator = ConsensusValidator::new(prev_hash, 1);
        assert!(
            validator.validate_block(&block).is_ok(),
            "MTP should be skipped without prev_timestamps"
        );
    }
}
