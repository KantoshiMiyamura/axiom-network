// Copyright (c) 2026 Kantoshi Miyamura

//! Core network analysis engine — reads node state and produces structured reports.

use crate::types::*;
use axiom_node::Node;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

// ── Fee predictor ─────────────────────────────────────────────────────────────

/// Online linear regression for fee prediction: mempool_depth → fee_rate
pub struct FeePredictor {
    n: u64,
    sum_x: f64,
    sum_y: f64,
    sum_xx: f64,
    sum_xy: f64,
    history_x: std::collections::VecDeque<f64>,
    history_y: std::collections::VecDeque<f64>,
}

impl FeePredictor {
    pub fn new() -> Self {
        Self {
            n: 0,
            sum_x: 0.0,
            sum_y: 0.0,
            sum_xx: 0.0,
            sum_xy: 0.0,
            history_x: std::collections::VecDeque::with_capacity(500),
            history_y: std::collections::VecDeque::with_capacity(500),
        }
    }

    pub fn update(&mut self, depth: usize, fee_rate: f64) {
        let x = depth as f64;
        let y = fee_rate;
        self.n += 1;
        self.sum_x += x;
        self.sum_y += y;
        self.sum_xx += x * x;
        self.sum_xy += x * y;
        if self.history_x.len() >= 500 {
            // Remove oldest point from sums
            let ox = self.history_x.pop_front().unwrap_or(0.0);
            let oy = self.history_y.pop_front().unwrap_or(0.0);
            self.n -= 1;
            self.sum_x -= ox;
            self.sum_y -= oy;
            self.sum_xx -= ox * ox;
            self.sum_xy -= ox * oy;
        }
        self.history_x.push_back(x);
        self.history_y.push_back(y);
    }

    pub fn predict(&self, depth: usize) -> f64 {
        if self.n < 5 {
            return 10.0;
        }
        let denom = self.n as f64 * self.sum_xx - self.sum_x * self.sum_x;
        if denom.abs() < 1e-10 {
            return self.sum_y / self.n as f64;
        }
        let slope = (self.n as f64 * self.sum_xy - self.sum_x * self.sum_y) / denom;
        let intercept = (self.sum_y - slope * self.sum_x) / self.n as f64;
        (intercept + slope * depth as f64).max(1.0)
    }

    pub fn trend(&self) -> &'static str {
        if self.history_y.len() < 10 {
            return "stable";
        }
        let recent: f64 = self.history_y.iter().rev().take(5).sum::<f64>() / 5.0;
        let older: f64 = self.history_y.iter().rev().skip(5).take(5).sum::<f64>() / 5.0;
        if older < 0.001 {
            return "stable";
        }
        if recent > older * 1.15 {
            "rising"
        } else if recent < older * 0.85 {
            "falling"
        } else {
            "stable"
        }
    }
}

impl Default for FeePredictor {
    fn default() -> Self {
        Self::new()
    }
}

pub struct NetworkAnalyzer {
    node: Arc<RwLock<Node>>,
    history: AnalysisHistory,
    fee_predictor: FeePredictor,
}

struct AnalysisHistory {
    block_times: VecDeque<f64>,
    fee_rates: VecDeque<u64>,
    health_scores: VecDeque<f64>,
    max_history: usize,
}

impl AnalysisHistory {
    fn new() -> Self {
        AnalysisHistory {
            block_times: VecDeque::with_capacity(20),
            fee_rates: VecDeque::with_capacity(20),
            health_scores: VecDeque::with_capacity(10),
            max_history: 20,
        }
    }

    fn push_block_time(&mut self, t: f64) {
        if self.block_times.len() >= self.max_history {
            self.block_times.pop_front();
        }
        self.block_times.push_back(t);
    }

    fn push_fee_rate(&mut self, r: u64) {
        if self.fee_rates.len() >= self.max_history {
            self.fee_rates.pop_front();
        }
        self.fee_rates.push_back(r);
    }

    fn push_health(&mut self, h: f64) {
        if self.health_scores.len() >= 10 {
            self.health_scores.pop_front();
        }
        self.health_scores.push_back(h);
    }
}

impl NetworkAnalyzer {
    pub fn new(node: Arc<RwLock<Node>>) -> Self {
        NetworkAnalyzer {
            node,
            history: AnalysisHistory::new(),
            fee_predictor: FeePredictor::new(),
        }
    }

    pub async fn analyze(&mut self) -> MonitorReport {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let (fee_analysis, block_time_analysis, network_analysis) = {
            let node = self.node.read().await;
            let fee = analyze_fee_market(&node);
            let block_time = analyze_block_times(&node);
            let network = analyze_network(&node);
            (fee, block_time, network)
        };

        // Update fee predictor with latest mempool depth and p50 fee rate, then
        // fill the new predicted_rate / trend fields on the analysis value.
        self.fee_predictor.update(
            fee_analysis.mempool_depth,
            fee_analysis.median_fee_rate as f64,
        );
        let fee_analysis = FeeAnalysis {
            predicted_rate: self.fee_predictor.predict(fee_analysis.mempool_depth) as u64,
            trend: self.fee_predictor.trend().to_string(),
            ..fee_analysis
        };

        self.history.push_fee_rate(fee_analysis.median_fee_rate);
        self.history
            .push_block_time(block_time_analysis.avg_block_time_secs);

        let health = compute_health_score(
            &fee_analysis,
            &block_time_analysis,
            &network_analysis,
            now_ms,
        );
        self.history.push_health(health.overall);

        let alerts = generate_alerts(
            &fee_analysis,
            &block_time_analysis,
            &network_analysis,
            &health,
        );
        let recommendations =
            generate_recommendations(&fee_analysis, &block_time_analysis, &network_analysis);

        MonitorReport {
            cycle_id: now_ms / 60_000, // minute bucket
            timestamp_ms: now_ms,
            health,
            alerts,
            recommendations,
            fee_analysis,
            block_time_analysis,
            network_analysis,
        }
    }
}

// ── Fee market analysis ───────────────────────────────────────────────────────

fn analyze_fee_market(node: &Node) -> FeeAnalysis {
    let count = node.mempool_size();
    let size_bytes = node.mempool_byte_size();
    let max_mempool = node.mempool_max_byte_size();

    let (median, p75, p90) = match node.mempool_fee_percentiles() {
        Some(p) => (p.p50, p.p75, p.p90),
        None => (1, 1, 1),
    };

    let fill_ratio = if max_mempool > 0 {
        size_bytes as f64 / max_mempool as f64
    } else {
        0.0
    };

    let pressure = if fill_ratio < 0.25 {
        FeePressure::Low
    } else if fill_ratio < 0.75 {
        FeePressure::Medium
    } else if fill_ratio < 0.90 {
        FeePressure::High
    } else {
        FeePressure::Critical
    };

    // Estimate blocks to clear: assume 1 MB blocks, variable tx size
    let avg_tx_size = if count > 0 { size_bytes / count } else { 1_000 };
    let txs_per_block = 1_000_000 / avg_tx_size.max(1);
    let clear_blocks = if txs_per_block > 0 {
        (count / txs_per_block + 1) as u32
    } else {
        0
    };

    FeeAnalysis {
        median_fee_rate: median,
        p75_fee_rate: p75,
        p90_fee_rate: p90,
        mempool_depth: count,
        fee_pressure: pressure,
        estimated_clear_time_blocks: clear_blocks,
        // predicted_rate and trend are filled by NetworkAnalyzer::analyze()
        // after the fee predictor is updated with the latest sample.
        predicted_rate: 0,
        trend: String::new(),
    }
}

// ── Block time analysis ───────────────────────────────────────────────────────

fn analyze_block_times(node: &Node) -> BlockTimeAnalysis {
    // Grab up to 21 recent blocks to compute 20 inter-block intervals.
    let blocks = node.get_recent_blocks(21).unwrap_or_default();

    let mut timestamps: Vec<u32> = blocks.iter().map(|b| b.header.timestamp).collect();
    // get_recent_blocks returns newest first; reverse to oldest-first for diff.
    timestamps.reverse();

    let current_difficulty = blocks
        .first()
        .map(|b| b.header.difficulty_target)
        .unwrap_or(0);

    let mut intervals: Vec<f64> = Vec::new();
    for i in 1..timestamps.len() {
        let diff = (timestamps[i] as i64 - timestamps[i - 1] as i64).max(0) as f64;
        intervals.push(diff);
    }

    let avg = if intervals.is_empty() {
        30.0
    } else {
        intervals.iter().sum::<f64>() / intervals.len() as f64
    };

    let variance = if intervals.len() < 2 {
        0.0
    } else {
        intervals.iter().map(|&x| (x - avg).powi(2)).sum::<f64>() / (intervals.len() - 1) as f64
    };
    let std_dev = variance.sqrt();

    // Rough hashrate estimate: difficulty * 2^32 / avg_block_time
    let estimated_hashrate = if avg > 0.0 {
        current_difficulty as f64 * 4_294_967_296.0 / avg
    } else {
        0.0
    };

    let variance_coeff = if avg > 0.0 { std_dev / avg } else { 0.0 };

    BlockTimeAnalysis {
        avg_block_time_secs: avg,
        std_dev_secs: std_dev,
        target_secs: 30.0,
        current_difficulty,
        estimated_hashrate,
        next_expected_block_eta_secs: avg,
        variance_coefficient: variance_coeff,
    }
}

// ── Network connectivity analysis ─────────────────────────────────────────────

fn analyze_network(node: &Node) -> NetworkAnalysis {
    // Chain tip age: now - tip block timestamp
    let chain_tip_age_secs: u64 = {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Some(hash) = node.best_block_hash() {
            if let Ok(Some(block)) = node.get_block(&hash) {
                let tip_ts = block.header.timestamp as u64;
                now.saturating_sub(tip_ts)
            } else {
                u64::MAX
            }
        } else {
            u64::MAX
        }
    };

    // Peer count is managed by NetworkService, not Node directly.
    // We use 0 as the fallback here; the agent can optionally receive peer
    // count via a separate channel if wired in the future.  For now the
    // analyzer reports what it can from the Node alone.
    let peer_count: u32 = 0;

    NetworkAnalysis {
        peer_count,
        inbound_count: 0,
        outbound_count: 0,
        is_well_connected: false,
        threat_level: "normal".to_string(),
        chain_tip_age_secs,
        is_synced: chain_tip_age_secs < 120,
    }
}

// ── Health score computation ──────────────────────────────────────────────────

pub fn compute_health_score(
    fee: &FeeAnalysis,
    block_time: &BlockTimeAnalysis,
    network: &NetworkAnalysis,
    now_ms: u64,
) -> NetworkHealthScore {
    let peer_score = (network.peer_count as f64 / 8.0).min(1.0) * 100.0;

    let time_deviation = (block_time.avg_block_time_secs - 30.0).abs() / 30.0;
    let block_time_score = (1.0 - time_deviation.min(1.0)) * 100.0;

    let mempool_score = match fee.fee_pressure {
        FeePressure::Low => 100.0,
        FeePressure::Medium => 75.0,
        FeePressure::High => 40.0,
        FeePressure::Critical => 10.0,
    };

    let progress_score = if network.chain_tip_age_secs < 60 {
        100.0
    } else if network.chain_tip_age_secs < 120 {
        80.0
    } else if network.chain_tip_age_secs < 300 {
        50.0
    } else {
        10.0
    };

    let overall =
        peer_score * 0.25 + block_time_score * 0.35 + mempool_score * 0.20 + progress_score * 0.20;

    NetworkHealthScore {
        overall: (overall * 10.0).round() / 10.0,
        components: HealthComponents {
            peer_connectivity: (peer_score * 10.0).round() / 10.0,
            block_time_stability: (block_time_score * 10.0).round() / 10.0,
            mempool_health: (mempool_score * 10.0).round() / 10.0,
            chain_progress: (progress_score * 10.0).round() / 10.0,
        },
        computed_at_ms: now_ms,
        // Populated by callers that have access to a ReputationRegistry; None here.
        adaptive_baselines: None,
    }
}

// ── Alert generation ──────────────────────────────────────────────────────────

pub fn generate_alerts(
    fee: &FeeAnalysis,
    block_time: &BlockTimeAnalysis,
    network: &NetworkAnalysis,
    health: &NetworkHealthScore,
) -> Vec<AgentAlert> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let mut alerts = Vec::new();

    // Peer count alerts
    if network.peer_count < 3 {
        alerts.push(AgentAlert {
            id: format!("{:016x}", now_ms ^ 0x01),
            severity: AlertSeverity::Critical,
            category: "network_health".to_string(),
            message: format!(
                "Very low peer count: {} (minimum recommended: 4)",
                network.peer_count
            ),
            recommendation:
                "Check network connectivity and seed node availability. Consider adding --peer flags."
                    .to_string(),
            timestamp_ms: now_ms,
            data: serde_json::json!({"peer_count": network.peer_count}),
        });
    } else if network.peer_count < 6 {
        alerts.push(AgentAlert {
            id: format!("{:016x}", now_ms ^ 0x02),
            severity: AlertSeverity::Warning,
            category: "network_health".to_string(),
            message: format!("Low peer count: {} peers connected", network.peer_count),
            recommendation: "Consider adding more peer connections for better network coverage."
                .to_string(),
            timestamp_ms: now_ms,
            data: serde_json::json!({"peer_count": network.peer_count}),
        });
    }

    // Fee pressure alerts
    if fee.fee_pressure == FeePressure::Critical {
        alerts.push(AgentAlert {
            id: format!("{:016x}", now_ms ^ 0x03),
            severity: AlertSeverity::Critical,
            category: "fee_market".to_string(),
            message: format!(
                "Mempool critically full: {} transactions backlogged",
                fee.mempool_depth
            ),
            recommendation: format!(
                "Raise min_fee_rate to {}+ sat/byte to shed low-fee transactions.",
                fee.p75_fee_rate + 1
            ),
            timestamp_ms: now_ms,
            data: serde_json::json!({"depth": fee.mempool_depth, "p75_fee": fee.p75_fee_rate}),
        });
    } else if fee.fee_pressure == FeePressure::High {
        alerts.push(AgentAlert {
            id: format!("{:016x}", now_ms ^ 0x04),
            severity: AlertSeverity::Warning,
            category: "fee_market".to_string(),
            message: format!("High mempool pressure: {} transactions queued", fee.mempool_depth),
            recommendation:
                "Monitor fee rates. Users should use medium or higher fee priority.".to_string(),
            timestamp_ms: now_ms,
            data: serde_json::json!({"depth": fee.mempool_depth, "median_fee": fee.median_fee_rate}),
        });
    }

    // Block time anomaly
    let time_deviation = (block_time.avg_block_time_secs - 30.0).abs();
    if time_deviation > 15.0 {
        let severity = if time_deviation > 30.0 {
            AlertSeverity::Warning
        } else {
            AlertSeverity::Info
        };
        alerts.push(AgentAlert {
            id: format!("{:016x}", now_ms ^ 0x05),
            severity,
            category: "block_time".to_string(),
            message: format!(
                "Block time deviation: avg {:.1}s (target: 30s)",
                block_time.avg_block_time_secs
            ),
            recommendation: if block_time.avg_block_time_secs > 45.0 {
                "Network may have lost hashrate. Difficulty will adjust down in next window."
                    .to_string()
            } else {
                "Hashrate increase detected. Difficulty will adjust up in next window.".to_string()
            },
            timestamp_ms: now_ms,
            data: serde_json::json!({
                "avg_block_time": block_time.avg_block_time_secs,
                "std_dev": block_time.std_dev_secs,
                "target": 30.0
            }),
        });
    }

    // Stale chain tip
    if network.chain_tip_age_secs > 180 {
        alerts.push(AgentAlert {
            id: format!("{:016x}", now_ms ^ 0x06),
            severity: AlertSeverity::Warning,
            category: "block_time".to_string(),
            message: format!(
                "No new block in {}s (last block: {}m ago)",
                network.chain_tip_age_secs,
                network.chain_tip_age_secs / 60
            ),
            recommendation:
                "Check peer connectivity and mining status. Chain may be experiencing a long \
                 natural gap or connectivity issue."
                    .to_string(),
            timestamp_ms: now_ms,
            data: serde_json::json!({"chain_tip_age_secs": network.chain_tip_age_secs}),
        });
    }

    // Low overall health
    if health.overall < 50.0 {
        alerts.push(AgentAlert {
            id: format!("{:016x}", now_ms ^ 0x07),
            severity: AlertSeverity::Critical,
            category: "network_health".to_string(),
            message: format!("Network health score critical: {:.1}/100", health.overall),
            recommendation:
                "Immediate investigation required. Check peers, chain progress, and mempool status."
                    .to_string(),
            timestamp_ms: now_ms,
            data: serde_json::json!(health.components),
        });
    }

    alerts
}

// ── Recommendation generation ─────────────────────────────────────────────────

pub fn generate_recommendations(
    fee: &FeeAnalysis,
    block_time: &BlockTimeAnalysis,
    _network: &NetworkAnalysis,
) -> Vec<ParameterRecommendation> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let mut recs = Vec::new();

    if fee.fee_pressure == FeePressure::High || fee.fee_pressure == FeePressure::Critical {
        let recommended_min = fee.p75_fee_rate.max(2);
        recs.push(ParameterRecommendation {
            parameter: "min_fee_rate".to_string(),
            current_value: 1.0,
            recommended_value: recommended_min as f64,
            confidence: 0.85,
            rationale: format!(
                "Mempool is under high pressure ({} txs queued). Raising minimum fee rate to \
                 {} sat/byte would shed low-priority transactions.",
                fee.mempool_depth, recommended_min
            ),
            timestamp_ms: now_ms,
        });
    }

    if block_time.variance_coefficient > 0.8 {
        recs.push(ParameterRecommendation {
            parameter: "mining_interval".to_string(),
            current_value: 1.0,
            recommended_value: 2.0,
            confidence: 0.6,
            rationale: format!(
                "Block time variance coefficient is {:.2} (very high). Reducing mining polling \
                 interval may improve block production consistency.",
                block_time.variance_coefficient
            ),
            timestamp_ms: now_ms,
        });
    }

    recs
}
