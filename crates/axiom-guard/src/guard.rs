// Copyright (c) 2026 Kantoshi Miyamura
// NetworkGuard — the core of AxiomMind.
// Analyses every block in real time, maintains learning baselines,
// detects attacks, and issues ML-DSA-87-signed alerts.

use crate::alerts::{AlertKind, GuardAlert};
use crate::detector::{AnomalyDetector, BlockAnalysis};
use crate::fingerprint::CognitiveFingerprint;
use crate::learning::NetworkBaselines;
use crate::reputation::PeerReputationTable;
use crate::threat::ThreatLevel;
use axiom_consensus::Block;
use std::collections::VecDeque;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

const MAX_ALERT_HISTORY: usize = 1_000;
const MAX_BLOCK_HISTORY: usize = 128;
const MIN_SCORE_FOR_ALERT: f64 = 3.0;

#[derive(Debug, Clone)]
struct BlockSummary {
    timestamp: u32,
    difficulty_target: u32,
}

/// Snapshot of AxiomMind's current state — safe to clone and send over RPC.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GuardStatus {
    pub active: bool,
    pub threat_level: ThreatLevel,
    pub threat_color: String,
    pub threat_emoji: String,
    pub blocks_analyzed: u64,
    pub threats_detected: u64,
    pub cognitive_fingerprint_address: String,
    pub cognitive_fingerprint_pubkey_hex: String,
    pub recent_alerts: Vec<GuardAlert>,
    pub baseline_block_interval_mean: f64,
    pub baseline_block_interval_std: f64,
    pub baseline_trained: bool,
    pub peer_trusted_count: usize,
    pub peer_banned_count: usize,
}

/// The AI guardian. One instance lives inside every node.
pub struct NetworkGuard {
    fingerprint: CognitiveFingerprint,
    baselines: NetworkBaselines,
    detector: AnomalyDetector,
    alert_history: VecDeque<GuardAlert>,
    threat_level: ThreatLevel,
    recent_blocks: VecDeque<BlockSummary>,
    peer_reputation: PeerReputationTable,
    blocks_analyzed: u64,
    threats_detected: u64,
    clean_blocks_since_last_alert: u64,
}

impl NetworkGuard {
    pub fn new(data_dir: &Path) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let fingerprint = CognitiveFingerprint::load_or_create(data_dir)?;

        info!("╔══════════════════════════════════════════════════════════════╗");
        info!("║              AxiomMind  —  Neural Network Guardian          ║");
        info!("╚══════════════════════════════════════════════════════════════╝");
        info!("  Cognitive fingerprint: {}", fingerprint.address());
        info!("  Signature scheme:      ML-DSA-87 (NIST Level 5, 256-bit PQ)");
        info!("  Status:                ACTIVE — learning network behaviour");
        info!("");

        Ok(Self {
            fingerprint,
            baselines: NetworkBaselines::new(),
            detector: AnomalyDetector::new(),
            alert_history: VecDeque::with_capacity(MAX_ALERT_HISTORY),
            threat_level: ThreatLevel::Safe,
            recent_blocks: VecDeque::with_capacity(MAX_BLOCK_HISTORY),
            peer_reputation: PeerReputationTable::new(),
            blocks_analyzed: 0,
            threats_detected: 0,
            clean_blocks_since_last_alert: 0,
        })
    }

    /// Called by the node on every accepted block.
    pub fn on_block(&mut self, block: &Block, height: u64) -> Vec<GuardAlert> {
        self.blocks_analyzed += 1;
        self.clean_blocks_since_last_alert += 1;

        let prev = self.recent_blocks.back().cloned();

        let interval_secs = prev
            .as_ref()
            .map(|p| (block.header.timestamp as i64 - p.timestamp as i64).max(0) as f64);

        // Update learning baselines first
        if let Some(s) = interval_secs {
            self.baselines.block_interval_secs.update(s);
        }
        self.baselines
            .tx_count_per_block
            .update(block.transactions.len() as f64);
        if let Some(p) = prev.as_ref() {
            if p.difficulty_target > 0 {
                let pct = (block.header.difficulty_target as f64 - p.difficulty_target as f64)
                    .abs()
                    / p.difficulty_target as f64
                    * 100.0;
                self.baselines.difficulty_change_pct.update(pct);
            }
        }

        let analysis = BlockAnalysis {
            height,
            timestamp: block.header.timestamp,
            prev_timestamp: prev.as_ref().map(|p| p.timestamp),
            difficulty_target: block.header.difficulty_target,
            prev_difficulty: prev.as_ref().map(|p| p.difficulty_target),
            tx_count: block.transactions.len(),
            interval_secs,
        };

        let detections = self.detector.analyze(&analysis, &self.baselines);

        // Record block
        self.recent_blocks.push_back(BlockSummary {
            timestamp: block.header.timestamp,
            difficulty_target: block.header.difficulty_target,
        });
        if self.recent_blocks.len() > MAX_BLOCK_HISTORY {
            self.recent_blocks.pop_front();
        }

        // Emit alerts for high-score detections
        let mut alerts = Vec::new();
        for d in detections {
            if d.score >= MIN_SCORE_FOR_ALERT {
                if let Some(alert) = self.emit_alert(d.kind, height, d.score, d.details) {
                    alerts.push(alert);
                }
            }
        }

        // Decay threat level after sustained clean period
        if alerts.is_empty()
            && self.clean_blocks_since_last_alert > 50
            && self.threat_level > ThreatLevel::Safe
        {
            let prev_level = self.threat_level;
            self.threat_level = match self.threat_level {
                ThreatLevel::Critical => ThreatLevel::High,
                ThreatLevel::High => ThreatLevel::Medium,
                ThreatLevel::Medium => ThreatLevel::Low,
                _ => ThreatLevel::Safe,
            };
            info!(
                "{} AxiomMind threat decayed: {} → {}",
                self.threat_level.emoji(),
                prev_level,
                self.threat_level
            );
            self.clean_blocks_since_last_alert = 0;
        }

        alerts
    }

    /// Called periodically with current mempool size.
    pub fn on_mempool_update(&mut self, size: usize) {
        self.baselines.mempool_size.update(size as f64);
        if let Some(d) = self.detector.analyze_mempool(size, &self.baselines) {
            if d.score >= MIN_SCORE_FOR_ALERT {
                self.emit_alert(d.kind, 0, d.score, d.details);
            }
        }
    }

    /// Called when peer count changes.
    pub fn on_peer_count_change(&mut self, count: usize) {
        if let Some(d) = self.detector.analyze_peer_count(count) {
            if d.score >= MIN_SCORE_FOR_ALERT {
                self.emit_alert(d.kind, 0, d.score, d.details);
            }
        }
    }

    /// Inspect peer block announcements for selfish-mining patterns.
    ///
    /// Call this whenever a peer announces one or more blocks.
    /// Returns any generated `GuardAlert`s.
    #[allow(dead_code)]
    pub fn on_peer_block_announcements(
        &mut self,
        peer_id: &str,
        block_hashes: &[axiom_primitives::Hash256],
        timestamps: &[u64],
        block_heights: &[u64],
    ) -> Vec<GuardAlert> {
        use crate::detector::PeerId;

        let pid: PeerId = peer_id.to_string();
        match self.detector.detect_selfish_mining(
            pid.clone(),
            block_hashes,
            timestamps,
            block_heights,
        ) {
            None => vec![],
            Some(threat_level) => {
                let count = block_hashes.len();
                let details = format!(
                    "Potential selfish mining: rapid block announcements from peer {} ({} blocks)",
                    peer_id, count
                );
                // Use the highest block height from the batch as the alert height.
                let height = block_heights.iter().copied().max().unwrap_or(0);
                let score = match threat_level {
                    crate::threat::ThreatLevel::High => 7.0,
                    crate::threat::ThreatLevel::Medium => 4.0,
                    _ => 3.5,
                };
                match self.emit_alert(
                    crate::alerts::AlertKind::SelfishMining,
                    height,
                    score,
                    details,
                ) {
                    Some(alert) => vec![alert],
                    None => vec![],
                }
            }
        }
    }

    /// Record that a peer relayed a valid block.
    pub fn peer_valid_block(&mut self, peer_id: &str, height: u64) {
        self.peer_reputation.record_valid_block(peer_id, height);
    }

    /// Record that a peer relayed an invalid block.
    pub fn peer_invalid_block(&mut self, peer_id: &str) {
        self.peer_reputation.record_invalid_block(peer_id);
    }

    pub fn threat_level(&self) -> ThreatLevel {
        self.threat_level
    }
    pub fn blocks_analyzed(&self) -> u64 {
        self.blocks_analyzed
    }
    pub fn threats_detected(&self) -> u64 {
        self.threats_detected
    }
    pub fn fingerprint_address(&self) -> &str {
        self.fingerprint.address()
    }

    pub fn recent_alerts(&self, n: usize) -> Vec<GuardAlert> {
        self.alert_history.iter().rev().take(n).cloned().collect()
    }

    pub fn status(&self) -> GuardStatus {
        GuardStatus {
            active: true,
            threat_level: self.threat_level,
            threat_color: self.threat_level.color().to_string(),
            threat_emoji: self.threat_level.emoji().to_string(),
            blocks_analyzed: self.blocks_analyzed,
            threats_detected: self.threats_detected,
            cognitive_fingerprint_address: self.fingerprint.address().to_string(),
            cognitive_fingerprint_pubkey_hex: hex::encode(&self.fingerprint.public_key),
            recent_alerts: self.recent_alerts(10),
            baseline_block_interval_mean: self.baselines.block_interval_secs.mean(),
            baseline_block_interval_std: self.baselines.block_interval_secs.std_dev(),
            baseline_trained: self.baselines.block_interval_secs.is_trained(),
            peer_trusted_count: self.peer_reputation.trusted_count(),
            peer_banned_count: self.peer_reputation.banned_count(),
        }
    }

    fn emit_alert(
        &mut self,
        kind: AlertKind,
        height: u64,
        score: f64,
        details: String,
    ) -> Option<GuardAlert> {
        self.threats_detected += 1;
        self.clean_blocks_since_last_alert = 0;

        let score_x1000 = (score * 1000.0) as u64;
        let msg = GuardAlert::signing_message(kind, height, score_x1000);

        let signature = match self.fingerprint.sign(&msg) {
            Ok(sig) => sig,
            Err(e) => {
                warn!("AxiomMind failed to sign alert: {}", e);
                return None;
            }
        };

        // Unique ID = first 8 bytes of hash of signing message
        let id_hash = axiom_crypto::hash256(&msg);
        let id = hex::encode(&id_hash.as_bytes()[..8]);

        let threat_level = kind.threat_level();

        // Elevate network threat level
        if threat_level > self.threat_level {
            warn!(
                "{} AxiomMind threat elevated: {} → {}",
                threat_level.emoji(),
                self.threat_level,
                threat_level
            );
            self.threat_level = threat_level;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let alert = GuardAlert {
            id: id.clone(),
            code: kind.code().to_string(),
            kind,
            severity: kind.severity(),
            threat_level,
            timestamp_unix: now,
            block_height: height,
            anomaly_score: score,
            description: kind.description().to_string(),
            details: details.clone(),
            signature,
            signer_pubkey: self.fingerprint.public_key.clone(),
            signer_address: self.fingerprint.address().to_string(),
        };

        warn!(
            "{} AxiomMind [{}] score={:.1} h={}: {}",
            threat_level.emoji(),
            kind.code(),
            score,
            height,
            details
        );

        if self.alert_history.len() >= MAX_ALERT_HISTORY {
            self.alert_history.pop_front();
        }
        self.alert_history.push_back(alert.clone());

        Some(alert)
    }
}
