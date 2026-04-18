// Copyright (c) 2026 Kantoshi Miyamura
// Attack pattern detection engine.
// Analyses every block and mempool state for known attack signatures.

use crate::alerts::AlertKind;
use crate::learning::NetworkBaselines;
use crate::threat::ThreatLevel;
use axiom_primitives::Hash256;
use std::collections::{HashMap, VecDeque};

/// A peer identifier — opaque string (address, peer-id, etc.).
pub type PeerId = String;

pub struct BlockAnalysis {
    pub height: u64,
    pub timestamp: u32,
    pub prev_timestamp: Option<u32>,
    pub difficulty_target: u32,
    pub prev_difficulty: Option<u32>,
    pub tx_count: usize,
    pub interval_secs: Option<f64>,
}

pub struct DetectionResult {
    pub kind: AlertKind,
    pub score: f64,
    pub details: String,
}

/// How many block announcements from a single peer within `SELFISH_MINING_WINDOW_SECS`
/// before we flag it as suspicious.
const SELFISH_MINING_RAPID_THRESHOLD: usize = 3;

/// Sliding window in seconds for selfish-mining rapid-announcement detection.
const SELFISH_MINING_WINDOW_SECS: u64 = 60;

/// If two blocks at the same height arrive from different peers within this
/// many seconds, raise a fork-race alert.
const FORK_RACE_WINDOW_SECS: u64 = 2;

pub struct AnomalyDetector {
    consecutive_fast_blocks: u32,
    recent_difficulties: VecDeque<u32>,
    /// Timestamps (unix seconds) of block announcements per peer.
    block_announcement_times: HashMap<PeerId, VecDeque<u64>>,
    /// Most-recent (height, timestamp, peer_id) of the last seen block per height,
    /// used to detect competing fork-race announcements.
    last_seen_by_height: HashMap<u64, (u64, PeerId)>,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            consecutive_fast_blocks: 0,
            recent_difficulties: VecDeque::with_capacity(64),
            block_announcement_times: HashMap::new(),
            last_seen_by_height: HashMap::new(),
        }
    }

    pub fn analyze(
        &mut self,
        block: &BlockAnalysis,
        baselines: &NetworkBaselines,
    ) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        // ── 1. Rapid block production (potential 51% attack) ──────────────────
        if let Some(interval) = block.interval_secs {
            let mean = baselines.block_interval_secs.mean();
            if baselines.block_interval_secs.is_trained() && mean > 0.0 {
                if interval < mean * 0.12 {
                    self.consecutive_fast_blocks += 1;
                    let score = (mean / interval.max(0.1)).ln() * 3.0
                        + self.consecutive_fast_blocks as f64 * 0.5;
                    results.push(DetectionResult {
                        kind: AlertKind::RapidBlockProduction,
                        score,
                        details: format!(
                            "Block interval {:.1}s vs baseline {:.1}s ({}x faster, {} consecutive)",
                            interval, mean, (mean / interval.max(0.1)) as u32,
                            self.consecutive_fast_blocks
                        ),
                    });
                } else {
                    self.consecutive_fast_blocks = 0;
                }

                // ── 2. Network stall ──────────────────────────────────────────
                if interval > mean * 10.0 {
                    let score = interval / mean.max(1.0);
                    results.push(DetectionResult {
                        kind: AlertKind::NetworkStall,
                        score,
                        details: format!(
                            "No block for {:.0}s (baseline {:.0}s, {:.0}x stall)",
                            interval, mean, interval / mean.max(1.0)
                        ),
                    });
                }
            }
        }

        // ── 3. Timestamp manipulation ─────────────────────────────────────────
        if let Some(prev_ts) = block.prev_timestamp {
            let diff = block.timestamp as i64 - prev_ts as i64;
            if diff < 0 {
                results.push(DetectionResult {
                    kind: AlertKind::TimestampManipulation,
                    score: 10.0,
                    details: format!(
                        "Timestamp went BACKWARDS by {}s (height {})",
                        diff.abs(), block.height
                    ),
                });
            } else if diff > 7_200 {
                results.push(DetectionResult {
                    kind: AlertKind::TimestampManipulation,
                    score: 5.0 + (diff as f64 / 3_600.0),
                    details: format!(
                        "Timestamp jumped forward {:.1}h at height {}",
                        diff as f64 / 3_600.0, block.height
                    ),
                });
            }
        }

        // ── 4. Difficulty drop anomaly ────────────────────────────────────────
        if let Some(prev_diff) = block.prev_difficulty {
            if prev_diff > 0 {
                let change_pct = (block.difficulty_target as f64 - prev_diff as f64).abs()
                    / prev_diff as f64 * 100.0;
                let score = baselines.difficulty_change_pct.anomaly_score(change_pct);
                if score > 4.0 && change_pct > 35.0 {
                    results.push(DetectionResult {
                        kind: AlertKind::DifficultyDropAnomaly,
                        score,
                        details: format!(
                            "Difficulty changed {:.1}% at height {} (anomaly score {:.1})",
                            change_pct, block.height, score
                        ),
                    });
                }
            }
        }

        // ── 5. Transaction volume spike ───────────────────────────────────────
        if baselines.tx_count_per_block.is_trained() {
            let score = baselines.tx_count_per_block.anomaly_score(block.tx_count as f64);
            if score > 6.0 {
                results.push(DetectionResult {
                    kind: AlertKind::TransactionAnomalySpike,
                    score,
                    details: format!(
                        "{} txs in block (baseline {:.1}±{:.1}, score {:.1})",
                        block.tx_count,
                        baselines.tx_count_per_block.mean(),
                        baselines.tx_count_per_block.std_dev(),
                        score
                    ),
                });
            }
        }

        // Track difficulty history
        if self.recent_difficulties.len() >= 64 {
            self.recent_difficulties.pop_front();
        }
        self.recent_difficulties.push_back(block.difficulty_target);

        results
    }

    /// Detect mempool flooding.
    pub fn analyze_mempool(
        &self,
        mempool_size: usize,
        baselines: &NetworkBaselines,
    ) -> Option<DetectionResult> {
        if !baselines.mempool_size.is_trained() {
            return None;
        }
        let score = baselines.mempool_size.anomaly_score(mempool_size as f64);
        if score > 6.0 {
            Some(DetectionResult {
                kind: AlertKind::MempoolFlooding,
                score,
                details: format!(
                    "{} pending txs (baseline {:.0}±{:.0}, score {:.1})",
                    mempool_size,
                    baselines.mempool_size.mean(),
                    baselines.mempool_size.std_dev(),
                    score
                ),
            })
        } else {
            None
        }
    }

    /// Detect eclipse attack from low peer count.
    pub fn analyze_peer_count(&self, peer_count: usize) -> Option<DetectionResult> {
        if peer_count == 0 {
            Some(DetectionResult {
                kind: AlertKind::PeerDiversityLow,
                score: 10.0,
                details: "No peers connected — node is isolated".to_string(),
            })
        } else if peer_count < 3 {
            Some(DetectionResult {
                kind: AlertKind::PeerDiversityLow,
                score: (4 - peer_count) as f64 * 2.5,
                details: format!("Only {} peer(s) connected — eclipse attack risk", peer_count),
            })
        } else {
            None
        }
    }

    // ── Selfish mining detection ─────────────────────────────────────────────

    /// Detect selfish-mining patterns from peer block announcements.
    ///
    /// Selfish mining signatures detected:
    /// 1. A peer announces `SELFISH_MINING_RAPID_THRESHOLD`+ blocks within
    ///    `SELFISH_MINING_WINDOW_SECS` — "rapid burst" pattern.
    /// 2. Two blocks at the **same height** arrive from **different peers**
    ///    within `FORK_RACE_WINDOW_SECS` — "fork race" pattern.
    ///
    /// Returns the highest `ThreatLevel` detected, or `None` if clean.
    ///
    /// `blocks_announced` — hashes of blocks this peer just announced.
    /// `timestamps`        — unix-second timestamps for each announced block
    ///                       (parallel to `blocks_announced`; must be same length).
    /// `block_heights`     — block heights (parallel to the above two slices).
    #[allow(dead_code)]
    pub fn detect_selfish_mining(
        &mut self,
        peer_id: PeerId,
        blocks_announced: &[Hash256],
        timestamps: &[u64],
        block_heights: &[u64],
    ) -> Option<ThreatLevel> {
        if blocks_announced.is_empty() {
            return None;
        }

        let n = blocks_announced.len().min(timestamps.len()).min(block_heights.len());
        let mut max_threat: Option<ThreatLevel> = None;

        // --- Check 1: rapid burst from this peer ----------------------------
        let queue = self
            .block_announcement_times
            .entry(peer_id.clone())
            .or_default();

        for &ts in &timestamps[..n] {
            queue.push_back(ts);
        }

        // Prune entries older than the window.
        let latest_ts = *timestamps[..n].iter().max().unwrap_or(&0);
        while let Some(&front) = queue.front() {
            if front + SELFISH_MINING_WINDOW_SECS < latest_ts {
                queue.pop_front();
            } else {
                break;
            }
        }

        if queue.len() >= SELFISH_MINING_RAPID_THRESHOLD {
            let threat = ThreatLevel::High;
            max_threat = Some(max_threat.map(|t: ThreatLevel| t.max(threat)).unwrap_or(threat));
        }

        // --- Check 2: fork race — same height from different peers ----------
        for i in 0..n {
            let height = block_heights[i];
            let ts = timestamps[i];

            if let Some((prev_ts, ref prev_peer)) = self.last_seen_by_height.get(&height).cloned() {
                if prev_peer != &peer_id {
                    let gap = (ts as i64 - prev_ts as i64).unsigned_abs();
                    if gap <= FORK_RACE_WINDOW_SECS {
                        let threat = ThreatLevel::Medium;
                        max_threat = Some(
                            max_threat.map(|t: ThreatLevel| t.max(threat)).unwrap_or(threat),
                        );
                    }
                }
            }

            // Record latest announcement for this height.
            self.last_seen_by_height.insert(height, (ts, peer_id.clone()));
        }

        // Prune height map to avoid unbounded growth (keep last 500 heights).
        if self.last_seen_by_height.len() > 500 {
            let min_height = self
                .last_seen_by_height
                .keys()
                .copied()
                .min()
                .unwrap_or(0);
            self.last_seen_by_height.remove(&min_height);
        }

        max_threat
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self { Self::new() }
}
