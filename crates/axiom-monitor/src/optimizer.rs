// Copyright (c) 2026 Kantoshi Miyamura

//! Adaptive fee-rate and protocol parameter optimizer.

use std::collections::VecDeque;

/// Adaptive fee rate optimizer that learns from mempool patterns.
pub struct FeeOptimizer {
    /// Rolling window of mempool depths (for trend analysis)
    depth_history: VecDeque<usize>,
    /// Rolling window of fee rates
    fee_history: VecDeque<u64>,
}

impl FeeOptimizer {
    pub fn new() -> Self {
        FeeOptimizer {
            depth_history: VecDeque::with_capacity(20),
            fee_history: VecDeque::with_capacity(20),
        }
    }

    pub fn update(&mut self, depth: usize, median_fee: u64) {
        if self.depth_history.len() >= 20 {
            self.depth_history.pop_front();
        }
        if self.fee_history.len() >= 20 {
            self.fee_history.pop_front();
        }
        self.depth_history.push_back(depth);
        self.fee_history.push_back(median_fee);
    }

    /// Compute optimal fee rate recommendation for different priority levels.
    pub fn optimal_fee_rates(&self) -> OptimalFeeRates {
        let mut sorted: Vec<u64> = self.fee_history.iter().copied().collect();
        sorted.sort_unstable();

        let p50 = percentile(&sorted, 50);
        let p75 = percentile(&sorted, 75);
        let p90 = percentile(&sorted, 90);

        OptimalFeeRates {
            low_priority: p50.max(1),
            medium_priority: p75.max(2),
            high_priority: p90.max(5),
            urgent: p90.saturating_mul(2).max(10),
        }
    }

    /// Is the fee market trending up, down, or stable?
    pub fn fee_trend(&self) -> FeeTrend {
        if self.fee_history.len() < 5 {
            return FeeTrend::Stable;
        }

        let recent: Vec<u64> = self.fee_history.iter().rev().take(5).copied().collect();
        let older: Vec<u64> = self
            .fee_history
            .iter()
            .rev()
            .skip(5)
            .take(5)
            .copied()
            .collect();

        if older.is_empty() {
            return FeeTrend::Stable;
        }

        let recent_avg = recent.iter().sum::<u64>() as f64 / recent.len() as f64;
        let older_avg = older.iter().sum::<u64>() as f64 / older.len() as f64;

        if recent_avg > older_avg * 1.15 {
            FeeTrend::Rising
        } else if recent_avg < older_avg * 0.85 {
            FeeTrend::Falling
        } else {
            FeeTrend::Stable
        }
    }
}

impl Default for FeeOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

fn percentile(sorted: &[u64], p: usize) -> u64 {
    if sorted.is_empty() {
        return 1;
    }
    let idx = (sorted.len() * p / 100).min(sorted.len() - 1);
    sorted[idx]
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OptimalFeeRates {
    pub low_priority: u64,
    pub medium_priority: u64,
    pub high_priority: u64,
    pub urgent: u64,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum FeeTrend {
    Rising,
    Falling,
    Stable,
}
