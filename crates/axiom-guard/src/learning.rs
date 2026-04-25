// Copyright (c) 2026 Kantoshi Miyamura
// Online learning via Exponential Weighted Moving Average.
// AxiomMind learns "normal" network behaviour and detects deviations in real time.

/// Exponential Weighted Moving Average baseline.
/// Continuously learns the mean and variance of a metric from a live stream.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EwmaBaseline {
    mean: f64,
    variance: f64,
    alpha: f64,
    initialized: bool,
    sample_count: u64,
}

impl EwmaBaseline {
    pub fn new(alpha: f64) -> Self {
        Self {
            mean: 0.0,
            variance: 1.0,
            alpha: alpha.clamp(0.001, 0.999),
            initialized: false,
            sample_count: 0,
        }
    }

    pub fn update(&mut self, value: f64) {
        self.sample_count += 1;
        if !self.initialized {
            self.mean = value;
            self.variance = 1.0;
            self.initialized = true;
            return;
        }
        let delta = value - self.mean;
        self.mean += self.alpha * delta;
        self.variance = (1.0 - self.alpha) * (self.variance + self.alpha * delta * delta);
    }

    /// Z-score style anomaly score. 0 = normal, >3 = notable, >6 = anomalous.
    pub fn anomaly_score(&self, value: f64) -> f64 {
        if !self.initialized || self.variance < 1e-10 {
            return 0.0;
        }
        (value - self.mean).abs() / self.variance.sqrt()
    }

    pub fn mean(&self) -> f64 {
        self.mean
    }
    pub fn std_dev(&self) -> f64 {
        self.variance.sqrt()
    }
    pub fn sample_count(&self) -> u64 {
        self.sample_count
    }
    pub fn is_trained(&self) -> bool {
        self.sample_count >= 30
    }
}

/// All baselines AxiomMind tracks about network health.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkBaselines {
    /// Seconds between consecutive blocks.
    pub block_interval_secs: EwmaBaseline,
    /// Transactions per block.
    pub tx_count_per_block: EwmaBaseline,
    /// Percentage change in difficulty per adjustment.
    pub difficulty_change_pct: EwmaBaseline,
    /// Mempool pending transaction count.
    pub mempool_size: EwmaBaseline,
    /// Fee rate in sat/byte.
    pub fee_rate: EwmaBaseline,
}

impl NetworkBaselines {
    pub fn new() -> Self {
        Self {
            block_interval_secs: EwmaBaseline::new(0.08),
            tx_count_per_block: EwmaBaseline::new(0.05),
            difficulty_change_pct: EwmaBaseline::new(0.10),
            mempool_size: EwmaBaseline::new(0.15),
            fee_rate: EwmaBaseline::new(0.05),
        }
    }
}

impl Default for NetworkBaselines {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ewma_converges_to_constant() {
        let mut b = EwmaBaseline::new(0.2);
        for _ in 0..200 {
            b.update(30.0);
        }
        assert!((b.mean() - 30.0).abs() < 0.01, "mean should converge to 30");
        assert!(
            b.std_dev() < 0.5,
            "std_dev should be near 0 for constant input"
        );
    }

    #[test]
    fn ewma_anomaly_score_spike() {
        let mut b = EwmaBaseline::new(0.1);
        for _ in 0..100 {
            b.update(30.0);
        }
        // A value 10× the mean should produce a very high anomaly score
        let score = b.anomaly_score(300.0);
        assert!(
            score > 5.0,
            "spike should yield anomaly score > 5, got {}",
            score
        );
    }

    #[test]
    fn ewma_no_score_before_init() {
        let b = EwmaBaseline::new(0.1);
        assert_eq!(b.anomaly_score(999.0), 0.0);
    }

    #[test]
    fn is_trained_after_30_samples() {
        let mut b = EwmaBaseline::new(0.1);
        for i in 0..29 {
            b.update(i as f64);
            assert!(!b.is_trained());
        }
        b.update(29.0);
        assert!(b.is_trained());
    }
}
