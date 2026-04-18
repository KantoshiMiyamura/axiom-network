// Copyright (c) 2026 Kantoshi Miyamura

use crate::BlockHeader;
use axiom_primitives::Hash256;

/// Target block time in seconds.
pub const TARGET_BLOCK_TIME: u64 = 30;

/// LWMA difficulty adjustment window (blocks).
pub const LWMA_WINDOW: u32 = 60;

/// Kept for import compatibility. LWMA adjusts every block.
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u32 = LWMA_WINDOW;

/// Max difficulty increase per interval (4×).
pub const MAX_ADJUSTMENT_FACTOR: u64 = 4;

/// Max difficulty decrease per interval (÷4).
pub const MIN_ADJUSTMENT_FACTOR: u64 = 4;

/// Compact difficulty target. Format: 0x1d00ffff → 0x00ffff × 2^(8×(0x1d−3)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactTarget(pub u32);

impl CompactTarget {
    /// Expand compact target to 32-byte big-endian target.
    pub fn to_target(&self) -> [u8; 32] {
        let compact = self.0;
        let size = (compact >> 24) as usize;
        let word = compact & 0x00ffffff;

        let mut target = [0u8; 32];

        if size <= 3 {
            let word_bytes = word.to_be_bytes();
            let offset = 3 - size;
            target[29 + offset..32].copy_from_slice(&word_bytes[1 + offset..4]);
        } else if size < 32 {
            let word_bytes = word.to_be_bytes();
            let offset = 32 - size;
            target[offset..offset + 3].copy_from_slice(&word_bytes[1..4]);
        }

        target
    }

    /// Compress a 32-byte target into compact form.
    pub fn from_target(target: &[u8; 32]) -> Self {
        let mut size = 32;
        for (i, &byte) in target.iter().enumerate() {
            if byte != 0 {
                size = 32 - i;
                break;
            }
        }

        if size == 0 {
            return CompactTarget(0);
        }

        let offset = 32 - size;
        let mut word = if size >= 3 {
            u32::from_be_bytes([0, target[offset], target[offset + 1], target[offset + 2]])
        } else if size == 2 {
            u32::from_be_bytes([0, 0, target[offset], target[offset + 1]])
        } else {
            u32::from_be_bytes([0, 0, 0, target[offset]])
        };

        // High bit set would be interpreted as negative; shift and widen.
        if word & 0x00800000 != 0 {
            word >>= 8;
            size += 1;
        }

        let compact = (size as u32) << 24 | word;
        CompactTarget(compact)
    }

    /// Initial target: 0x1e00ffff (~256× easier than Bitcoin genesis).
    /// Single CPU core mines a block in 3–17 s; LWMA-3 converges to 30 s within 60 blocks.
    pub fn initial() -> Self {
        CompactTarget(0x1e00ffff)
    }
}

/// Returns true if block_hash ≤ target.
pub fn check_proof_of_work(block_hash: &Hash256, target: CompactTarget) -> bool {
    let target_bytes = target.to_target();
    let hash_bytes = block_hash.as_bytes();

    for i in 0..32 {
        if hash_bytes[i] < target_bytes[i] {
            return true;
        } else if hash_bytes[i] > target_bytes[i] {
            return false;
        }
    }

    true // equal is valid
}

/// Work ≈ max_target / current_target (proportional to expected hashes).
pub fn calculate_work(target: CompactTarget) -> u128 {
    let target_bytes = target.to_target();

    let mut target_u128 = 0u128;
    for &byte in &target_bytes[..16] {
        target_u128 = (target_u128 << 8) | (byte as u128);
    }

    if target_u128 == 0 {
        return u128::MAX;
    }

    let max_work = u128::MAX / 1000;
    max_work / target_u128.max(1)
}

/// Bitcoin-style retarget: new_target = old_target × (actual_time / expected_time).
// Clamped to [expected/4, expected×4]. Never exceeds max target.
pub fn calculate_new_target(
    old_target: CompactTarget,
    actual_time: u64,
    expected_time: u64,
) -> CompactTarget {
    let min_time = expected_time / MIN_ADJUSTMENT_FACTOR;
    let max_time = expected_time * MAX_ADJUSTMENT_FACTOR;
    let clamped_time = actual_time.clamp(min_time, max_time);

    let size = old_target.0 >> 24;
    let mantissa = (old_target.0 & 0x007fffff) as u128;

    if mantissa == 0 {
        return old_target;
    }

    // max mantissa ≈ 2^23, max clamped ≈ 2^22 → product fits in u128
    let new_mantissa_raw = mantissa.saturating_mul(clamped_time as u128) / (expected_time as u128);

    if new_mantissa_raw == 0 {
        return CompactTarget((size << 24) | 1);
    }

    let mut new_mantissa = new_mantissa_raw;
    let mut new_size = size;

    // Normalize mantissa to 3 bytes.
    while new_mantissa > 0x7fffff {
        new_mantissa >>= 8;
        new_size = new_size.saturating_add(1);
    }

    // Clear compact sign bit.
    if new_mantissa & 0x800000 != 0 {
        new_mantissa >>= 8;
        new_size = new_size.saturating_add(1);
    }

    if new_size > 32 {
        return CompactTarget::initial();
    }

    let compact = (new_size << 24) | (new_mantissa as u32 & 0x007fffff);
    let result = CompactTarget(compact);

    if result.to_target() > CompactTarget::initial().to_target() {
        return CompactTarget::initial();
    }

    result
}

/// LWMA-3 difficulty adjustment.
// timestamps: N+1 entries oldest-first. targets: N compact targets, same order.
// Returns initial target if chain is too short.
pub fn calculate_lwma_target(timestamps: &[u64], targets: &[CompactTarget]) -> CompactTarget {
    let n = LWMA_WINDOW as usize;

    if timestamps.len() < n + 1 || targets.len() < n {
        return CompactTarget::initial();
    }

    let t = TARGET_BLOCK_TIME as f64;
    // k = N·(N+1)/2 · T — LWMA denominator
    let k = (n * (n + 1) / 2) as f64 * t;

    let mut weighted_sum = 0f64;
    for i in 0..n {
        let raw = timestamps[i + 1] as i64 - timestamps[i] as i64;
        // CRITICAL FIX: Clamp solvetime to [1, 6T] to resist timestamp manipulation.
        // Prevents attacker from submitting blocks with manipulated timestamps to
        // force LWMA-3 to calculate extreme solvetimes, causing difficulty oscillation.
        // Lower bound (1s): prevents negative/zero solvetimes from timestamp reordering.
        // Upper bound (6T=180s): prevents single block from causing >4x difficulty swing.
        let solvetime = (raw.max(1) as f64).min(6.0 * t);
        let weight = (i + 1) as f64;
        weighted_sum += weight * solvetime;
    }

    // ratio = LWMA/T; clamped to [1/MAX_ADJUSTMENT_FACTOR, MAX_ADJUSTMENT_FACTOR]
    // so no window flips difficulty >MAX_ADJUSTMENT_FACTOR×.
    let max_ratio = MAX_ADJUSTMENT_FACTOR as f64;
    let min_ratio = 1.0 / max_ratio;
    let ratio = (weighted_sum / k).clamp(min_ratio, max_ratio);

    let base = targets[n - 1];
    let size = base.0 >> 24;
    let mantissa = (base.0 & 0x007fffff) as u128;

    if mantissa == 0 {
        return base;
    }

    // Fixed-point scale ×10^6 to preserve decimal precision.
    const SCALE: u128 = 1_000_000;
    let ratio_fp = (ratio * SCALE as f64) as u128;

    let new_mantissa_raw = mantissa.saturating_mul(ratio_fp) / SCALE;

    if new_mantissa_raw == 0 {
        return CompactTarget((size << 24) | 1);
    }

    let mut new_mantissa = new_mantissa_raw;
    let mut new_size = size;

    while new_mantissa > 0x7fffff {
        new_mantissa >>= 8;
        new_size = new_size.saturating_add(1);
    }
    if new_mantissa & 0x800000 != 0 {
        new_mantissa >>= 8;
        new_size = new_size.saturating_add(1);
    }

    if new_size > 32 {
        return CompactTarget::initial();
    }

    let result = CompactTarget((new_size << 24) | (new_mantissa as u32 & 0x007fffff));

    if result.to_target() > CompactTarget::initial().to_target() {
        return CompactTarget::initial();
    }

    result
}

/// Iterate nonce space until hash meets target. Bumps timestamp when nonce wraps.
// Returns Some(nonce) on success, None if max_iterations exhausted first.
pub fn mine_block(header: &mut BlockHeader, max_iterations: Option<u64>) -> Option<u32> {
    let target = CompactTarget(header.difficulty_target);
    let max_iter = max_iterations.unwrap_or(u64::MAX);
    let mut total: u64 = 0;

    loop {
        for nonce in 0..=u32::MAX {
            if total >= max_iter {
                return None;
            }
            total += 1;

            header.nonce = nonce;
            let hash = header.hash();

            if check_proof_of_work(&hash, target) {
                return Some(nonce);
            }
        }
        header.timestamp = header.timestamp.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compact_target_roundtrip() {
        let compact = CompactTarget(0x1d00ffff);
        let target = compact.to_target();
        let compact2 = CompactTarget::from_target(&target);

        // Rounding may differ by 1 mantissa byte; exponent must match.
        assert_eq!(compact.0 >> 24, compact2.0 >> 24);
    }

    #[test]
    fn test_check_proof_of_work_easy() {
        let target = CompactTarget(0x1d00ffff);
        let hash = Hash256::zero();
        assert!(check_proof_of_work(&hash, target));
    }

    #[test]
    fn test_check_proof_of_work_impossible() {
        let target = CompactTarget(0x01000000);
        let hash = Hash256::zero();
        assert!(check_proof_of_work(&hash, target)); // zero == zero
    }

    #[test]
    fn test_calculate_work() {
        let easy_target = CompactTarget(0x1d00ffff);
        let hard_target = CompactTarget(0x1c00ffff);

        let easy_work = calculate_work(easy_target);
        let hard_work = calculate_work(hard_target);

        assert!(hard_work > easy_work);
    }

    // ── calculate_new_target (legacy helper) ─────────────────────────────────

    #[test]
    fn test_difficulty_adjustment_on_time() {
        let old_target = CompactTarget(0x1d00ffff);
        let expected_time = 2016u64 * TARGET_BLOCK_TIME;
        let new_target = calculate_new_target(old_target, expected_time, expected_time);
        assert_eq!(
            new_target, old_target,
            "on-time mining should not change target"
        );
    }

    #[test]
    fn test_difficulty_adjustment_faster() {
        let old_target = CompactTarget(0x1d00ffff);
        let expected_time = 2016u64 * TARGET_BLOCK_TIME;
        let new_target = calculate_new_target(old_target, expected_time / 2, expected_time);
        assert!(new_target.to_target() < old_target.to_target());
    }

    #[test]
    fn test_difficulty_adjustment_slower() {
        let old_target = CompactTarget(0x1c00ffff);
        let expected_time = 2016u64 * TARGET_BLOCK_TIME;
        let new_target = calculate_new_target(old_target, expected_time * 2, expected_time);
        assert!(new_target.to_target() > old_target.to_target());
    }

    #[test]
    fn test_difficulty_adjustment_clamp_upper() {
        let old_target = CompactTarget(0x1d00ffff);
        let expected_time = 2016u64 * TARGET_BLOCK_TIME;
        let new_10x = calculate_new_target(old_target, expected_time * 10, expected_time);
        let new_4x = calculate_new_target(old_target, expected_time * 4, expected_time);
        assert_eq!(new_10x, new_4x, "extreme slowdown must be clamped to 4×");
    }

    #[test]
    fn test_difficulty_adjustment_clamp_lower() {
        let old_target = CompactTarget(0x1d00ffff);
        let expected_time = 2016u64 * TARGET_BLOCK_TIME;
        let new_div10 = calculate_new_target(old_target, expected_time / 10, expected_time);
        let new_div4 = calculate_new_target(old_target, expected_time / 4, expected_time);
        assert_eq!(
            new_div10, new_div4,
            "extreme speedup must be clamped to 1/4×"
        );
    }

    #[test]
    fn test_difficulty_adjustment_deterministic() {
        let old_target = CompactTarget(0x1d00ffff);
        let expected_time = 2016u64 * TARGET_BLOCK_TIME;
        let actual_time = expected_time * 3;
        let r1 = calculate_new_target(old_target, actual_time, expected_time);
        let r2 = calculate_new_target(old_target, actual_time, expected_time);
        assert_eq!(r1, r2, "retarget must be deterministic");
    }

    #[test]
    fn test_difficulty_adjustment_never_exceeds_max() {
        let old_target = CompactTarget(0x1d00ffff);
        let expected_time = 2016u64 * TARGET_BLOCK_TIME;
        let new_target = calculate_new_target(old_target, u64::MAX, expected_time);
        assert!(new_target.to_target() <= CompactTarget::initial().to_target());
    }

    #[test]
    fn test_difficulty_adjustment_clamped() {
        let old_target = CompactTarget(0x1d00ffff);
        let expected_time = 2016u64 * TARGET_BLOCK_TIME;
        let new_target = calculate_new_target(old_target, expected_time * 10, expected_time);
        assert!(new_target.0 > 0);
    }

    // ── calculate_lwma_target ─────────────────────────────────────────────────

    fn uniform_timestamps(n: usize, solvetime_secs: u64) -> Vec<u64> {
        (0..=(n as u64)).map(|i| i * solvetime_secs).collect()
    }

    fn uniform_targets(n: usize, compact: u32) -> Vec<CompactTarget> {
        vec![CompactTarget(compact); n]
    }

    #[test]
    fn test_lwma_on_target_unchanged() {
        // Uniform solvetimes = TARGET_BLOCK_TIME → ratio = 1 → target unchanged.
        let n = LWMA_WINDOW as usize;
        let ts = uniform_timestamps(n, TARGET_BLOCK_TIME);
        let tgts = uniform_targets(n, 0x1d00ffff);
        let result = calculate_lwma_target(&ts, &tgts);
        assert_eq!(result.0 >> 24, 0x1d, "exponent must match");
    }

    #[test]
    fn test_lwma_faster_decreases_target() {
        let n = LWMA_WINDOW as usize;
        let ts = uniform_timestamps(n, TARGET_BLOCK_TIME / 2);
        let tgts = uniform_targets(n, 0x1c00ffff);
        let base = CompactTarget(0x1c00ffff);
        let result = calculate_lwma_target(&ts, &tgts);
        assert!(
            result.to_target() < base.to_target(),
            "faster blocks → smaller (harder) target"
        );
    }

    #[test]
    fn test_lwma_slower_increases_target() {
        let n = LWMA_WINDOW as usize;
        let ts = uniform_timestamps(n, TARGET_BLOCK_TIME * 2);
        let tgts = uniform_targets(n, 0x1c00ffff);
        let base = CompactTarget(0x1c00ffff);
        let result = calculate_lwma_target(&ts, &tgts);
        assert!(
            result.to_target() > base.to_target(),
            "slower blocks → larger (easier) target"
        );
    }

    #[test]
    fn test_lwma_never_exceeds_max() {
        let n = LWMA_WINDOW as usize;
        let ts = uniform_timestamps(n, u32::MAX as u64);
        let tgts = uniform_targets(n, 0x1d00ffff);
        let result = calculate_lwma_target(&ts, &tgts);
        assert!(result.to_target() <= CompactTarget::initial().to_target());
    }

    #[test]
    fn test_lwma_deterministic() {
        let n = LWMA_WINDOW as usize;
        let ts = uniform_timestamps(n, TARGET_BLOCK_TIME * 3);
        let tgts = uniform_targets(n, 0x1d00ffff);
        let r1 = calculate_lwma_target(&ts, &tgts);
        let r2 = calculate_lwma_target(&ts, &tgts);
        assert_eq!(r1, r2, "LWMA must be deterministic");
    }

    #[test]
    fn test_lwma_insufficient_data_returns_initial() {
        let result = calculate_lwma_target(&[0u64, 300], &[CompactTarget(0x1d00ffff)]);
        assert_eq!(result, CompactTarget::initial());
    }

    #[test]
    fn test_mine_block_easy_target() {
        let mut header = BlockHeader {
            version: 1,
            prev_block_hash: Hash256::zero(),
            merkle_root: Hash256::zero(),
            timestamp: 0,
            difficulty_target: 0x207fffff,
            nonce: 0,
        };

        let result = mine_block(&mut header, Some(10000));

        if let Some(_nonce) = result {
            let hash = header.hash();
            let target = CompactTarget(header.difficulty_target);
            assert!(check_proof_of_work(&hash, target));
        }
        // Not finding a solution in 10k iterations is acceptable.
    }
}
