// Copyright (c) 2026 Kantoshi Miyamura
// AxiomMind v2 - Anomaly Detection Engine

use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Anomaly types detected by AxiomMind v2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnomalyType {
    /// Timestamp manipulation detected
    TimestampManipulation,
    /// Unusually fast blocks
    RapidBlocks,
    /// Orphan block surge
    OrphanBlocks,
    /// Nonce saturation attempts
    NonceAnomaly,
    /// Merkle tree manipulation
    MerkleAnomaly,
    /// Unusual fee patterns
    FeeAnomaly,
    /// Mempool flooding
    MempoolAnomaly,
    /// Invalid signatures
    SignatureAnomaly,
    /// Consensus drift
    ConsensusAnomaly,
    /// Network partition
    NetworkAnomaly,
}

/// Severity levels for anomalies
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Anomaly alert with detection details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyAlert {
    pub anomaly_type: AnomalyType,
    pub severity: Severity,
    pub score: f64,
    pub timestamp: u64,
    pub description: String,
    pub affected_entity: String,
    pub recommended_action: String,
}

/// Historical anomaly event for learning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyEvent {
    pub alert: AnomalyAlert,
    pub resolved: bool,
    pub resolution_time: Option<u64>,
}

/// Detector trait for anomaly detection
pub trait Detector: Send + Sync {
    fn detect(&self, data: &DetectionData) -> Option<AnomalyAlert>;
    fn name(&self) -> &str;
}

/// Data structure for detection
#[derive(Debug, Clone)]
pub struct DetectionData {
    pub block_height: u64,
    pub block_timestamp: u64,
    pub block_time_delta: u64,
    pub nonce: u64,
    pub merkle_root: String,
    pub fee_rate: f64,
    pub mempool_size: usize,
    pub signature_count: usize,
    pub invalid_signatures: usize,
    pub consensus_height: u64,
    pub peer_count: usize,
    pub orphan_count: usize,
}

/// Timestamp Manipulation Detector
pub struct TimestampDetector {
    max_drift_secs: u64,
    #[allow(dead_code)]
    history: Arc<RwLock<VecDeque<u64>>>,
}

impl TimestampDetector {
    pub fn new(max_drift_secs: u64) -> Self {
        TimestampDetector {
            max_drift_secs,
            history: Arc::new(RwLock::new(VecDeque::with_capacity(100))),
        }
    }
}

impl Detector for TimestampDetector {
    fn detect(&self, data: &DetectionData) -> Option<AnomalyAlert> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if data.block_timestamp > now + self.max_drift_secs {
            return Some(AnomalyAlert {
                anomaly_type: AnomalyType::TimestampManipulation,
                severity: Severity::High,
                score: 0.95,
                timestamp: now,
                description: format!(
                    "Block timestamp {} is {} seconds in the future",
                    data.block_timestamp,
                    data.block_timestamp - now
                ),
                affected_entity: format!("Block {}", data.block_height),
                recommended_action: "Reject block and investigate peer".to_string(),
            });
        }

        None
    }

    fn name(&self) -> &str {
        "TimestampDetector"
    }
}

/// Rapid Blocks Detector
pub struct RapidBlocksDetector {
    min_block_time: u64,
    #[allow(dead_code)]
    history: Arc<RwLock<VecDeque<u64>>>,
}

impl RapidBlocksDetector {
    pub fn new(min_block_time: u64) -> Self {
        RapidBlocksDetector {
            min_block_time,
            history: Arc::new(RwLock::new(VecDeque::with_capacity(100))),
        }
    }
}

impl Detector for RapidBlocksDetector {
    fn detect(&self, data: &DetectionData) -> Option<AnomalyAlert> {
        if data.block_time_delta < self.min_block_time && data.block_time_delta > 0 {
            return Some(AnomalyAlert {
                anomaly_type: AnomalyType::RapidBlocks,
                severity: Severity::Medium,
                score: 0.75,
                timestamp: data.block_timestamp,
                description: format!(
                    "Block arrived {} seconds after previous (minimum: {})",
                    data.block_time_delta, self.min_block_time
                ),
                affected_entity: format!("Block {}", data.block_height),
                recommended_action: "Monitor for consensus issues".to_string(),
            });
        }

        None
    }

    fn name(&self) -> &str {
        "RapidBlocksDetector"
    }
}

/// Orphan Blocks Detector
pub struct OrphanBlocksDetector {
    max_orphan_rate: f64,
}

impl OrphanBlocksDetector {
    pub fn new(max_orphan_rate: f64) -> Self {
        OrphanBlocksDetector { max_orphan_rate }
    }
}

impl Detector for OrphanBlocksDetector {
    fn detect(&self, data: &DetectionData) -> Option<AnomalyAlert> {
        let orphan_rate = if data.block_height > 0 {
            data.orphan_count as f64 / data.block_height as f64
        } else {
            0.0
        };

        if orphan_rate > self.max_orphan_rate {
            return Some(AnomalyAlert {
                anomaly_type: AnomalyType::OrphanBlocks,
                severity: Severity::High,
                score: 0.85,
                timestamp: data.block_timestamp,
                description: format!(
                    "Orphan block rate {:.2}% exceeds threshold {:.2}%",
                    orphan_rate * 100.0,
                    self.max_orphan_rate * 100.0
                ),
                affected_entity: format!("Network (orphans: {})", data.orphan_count),
                recommended_action: "Investigate network partition or consensus issues".to_string(),
            });
        }

        None
    }

    fn name(&self) -> &str {
        "OrphanBlocksDetector"
    }
}

/// Nonce Anomaly Detector
pub struct NonceAnomalyDetector {
    max_nonce: u64,
}

impl NonceAnomalyDetector {
    pub fn new(max_nonce: u64) -> Self {
        NonceAnomalyDetector { max_nonce }
    }
}

impl Detector for NonceAnomalyDetector {
    fn detect(&self, data: &DetectionData) -> Option<AnomalyAlert> {
        let threshold = self.max_nonce.saturating_mul(90) / 100;
        if data.nonce > threshold {
            return Some(AnomalyAlert {
                anomaly_type: AnomalyType::NonceAnomaly,
                severity: Severity::Critical,
                score: 0.98,
                timestamp: data.block_timestamp,
                description: format!(
                    "Nonce {} is approaching saturation limit {}",
                    data.nonce, self.max_nonce
                ),
                affected_entity: format!("Block {}", data.block_height),
                recommended_action: "Investigate potential nonce saturation attack".to_string(),
            });
        }

        None
    }

    fn name(&self) -> &str {
        "NonceAnomalyDetector"
    }
}

/// Merkle Anomaly Detector
pub struct MerkleAnomalyDetector {
    #[allow(dead_code)]
    history: Arc<RwLock<VecDeque<String>>>,
}

impl Default for MerkleAnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleAnomalyDetector {
    pub fn new() -> Self {
        MerkleAnomalyDetector {
            history: Arc::new(RwLock::new(VecDeque::with_capacity(1000))),
        }
    }
}

impl Detector for MerkleAnomalyDetector {
    fn detect(&self, data: &DetectionData) -> Option<AnomalyAlert> {
        // Check for duplicate merkle roots (potential manipulation)
        // In production, this would check against actual merkle tree validation
        if data.merkle_root.is_empty() {
            return Some(AnomalyAlert {
                anomaly_type: AnomalyType::MerkleAnomaly,
                severity: Severity::High,
                score: 0.90,
                timestamp: data.block_timestamp,
                description: "Empty merkle root detected".to_string(),
                affected_entity: format!("Block {}", data.block_height),
                recommended_action: "Reject block - invalid merkle root".to_string(),
            });
        }

        None
    }

    fn name(&self) -> &str {
        "MerkleAnomalyDetector"
    }
}

/// Fee Anomaly Detector
pub struct FeeAnomalyDetector {
    normal_fee_range: (f64, f64),
}

impl FeeAnomalyDetector {
    pub fn new(min_fee: f64, max_fee: f64) -> Self {
        FeeAnomalyDetector {
            normal_fee_range: (min_fee, max_fee),
        }
    }
}

impl Detector for FeeAnomalyDetector {
    fn detect(&self, data: &DetectionData) -> Option<AnomalyAlert> {
        if data.fee_rate < self.normal_fee_range.0 || data.fee_rate > self.normal_fee_range.1 {
            return Some(AnomalyAlert {
                anomaly_type: AnomalyType::FeeAnomaly,
                severity: Severity::Medium,
                score: 0.70,
                timestamp: data.block_timestamp,
                description: format!(
                    "Fee rate {:.6} outside normal range {:.6}-{:.6}",
                    data.fee_rate, self.normal_fee_range.0, self.normal_fee_range.1
                ),
                affected_entity: format!("Block {}", data.block_height),
                recommended_action: "Monitor for fee market manipulation".to_string(),
            });
        }

        None
    }

    fn name(&self) -> &str {
        "FeeAnomalyDetector"
    }
}

/// Mempool Anomaly Detector
pub struct MempoolAnomalyDetector {
    max_mempool_size: usize,
}

impl MempoolAnomalyDetector {
    pub fn new(max_mempool_size: usize) -> Self {
        MempoolAnomalyDetector { max_mempool_size }
    }
}

impl Detector for MempoolAnomalyDetector {
    fn detect(&self, data: &DetectionData) -> Option<AnomalyAlert> {
        if data.mempool_size > self.max_mempool_size {
            return Some(AnomalyAlert {
                anomaly_type: AnomalyType::MempoolAnomaly,
                severity: Severity::High,
                score: 0.88,
                timestamp: data.block_timestamp,
                description: format!(
                    "Mempool size {} exceeds threshold {}",
                    data.mempool_size, self.max_mempool_size
                ),
                affected_entity: "Mempool".to_string(),
                recommended_action: "Investigate potential mempool flooding attack".to_string(),
            });
        }

        None
    }

    fn name(&self) -> &str {
        "MempoolAnomalyDetector"
    }
}

/// Signature Anomaly Detector
pub struct SignatureAnomalyDetector {
    max_invalid_rate: f64,
}

impl SignatureAnomalyDetector {
    pub fn new(max_invalid_rate: f64) -> Self {
        SignatureAnomalyDetector { max_invalid_rate }
    }
}

impl Detector for SignatureAnomalyDetector {
    fn detect(&self, data: &DetectionData) -> Option<AnomalyAlert> {
        if data.signature_count > 0 {
            let invalid_rate = data.invalid_signatures as f64 / data.signature_count as f64;
            if invalid_rate > self.max_invalid_rate {
                return Some(AnomalyAlert {
                    anomaly_type: AnomalyType::SignatureAnomaly,
                    severity: Severity::Critical,
                    score: 0.96,
                    timestamp: data.block_timestamp,
                    description: format!(
                        "Invalid signature rate {:.2}% exceeds threshold {:.2}%",
                        invalid_rate * 100.0,
                        self.max_invalid_rate * 100.0
                    ),
                    affected_entity: format!("Block {}", data.block_height),
                    recommended_action: "Reject block - invalid signatures detected".to_string(),
                });
            }
        }

        None
    }

    fn name(&self) -> &str {
        "SignatureAnomalyDetector"
    }
}

/// Consensus Anomaly Detector
pub struct ConsensusAnomalyDetector {
    max_height_drift: u64,
}

impl ConsensusAnomalyDetector {
    pub fn new(max_height_drift: u64) -> Self {
        ConsensusAnomalyDetector { max_height_drift }
    }
}

impl Detector for ConsensusAnomalyDetector {
    fn detect(&self, data: &DetectionData) -> Option<AnomalyAlert> {
        let height_drift = data.block_height.abs_diff(data.consensus_height);

        if height_drift > self.max_height_drift {
            return Some(AnomalyAlert {
                anomaly_type: AnomalyType::ConsensusAnomaly,
                severity: Severity::High,
                score: 0.87,
                timestamp: data.block_timestamp,
                description: format!(
                    "Consensus drift: block height {} vs consensus height {} (drift: {})",
                    data.block_height, data.consensus_height, height_drift
                ),
                affected_entity: "Consensus".to_string(),
                recommended_action: "Investigate consensus divergence".to_string(),
            });
        }

        None
    }

    fn name(&self) -> &str {
        "ConsensusAnomalyDetector"
    }
}

/// Network Anomaly Detector
pub struct NetworkAnomalyDetector {
    min_peer_count: usize,
}

impl NetworkAnomalyDetector {
    pub fn new(min_peer_count: usize) -> Self {
        NetworkAnomalyDetector { min_peer_count }
    }
}

impl Detector for NetworkAnomalyDetector {
    fn detect(&self, data: &DetectionData) -> Option<AnomalyAlert> {
        if data.peer_count < self.min_peer_count {
            return Some(AnomalyAlert {
                anomaly_type: AnomalyType::NetworkAnomaly,
                severity: Severity::High,
                score: 0.82,
                timestamp: data.block_timestamp,
                description: format!(
                    "Peer count {} below minimum threshold {}",
                    data.peer_count, self.min_peer_count
                ),
                affected_entity: "Network".to_string(),
                recommended_action: "Investigate network partition or connectivity issues".to_string(),
            });
        }

        None
    }

    fn name(&self) -> &str {
        "NetworkAnomalyDetector"
    }
}

/// Main Anomaly Detection Engine
pub struct AnomalyDetectionEngine {
    detectors: Vec<Box<dyn Detector>>,
    alert_threshold: f64,
    history: Arc<RwLock<VecDeque<AnomalyEvent>>>,
}

impl AnomalyDetectionEngine {
    pub fn new(alert_threshold: f64) -> Self {
        let detectors: Vec<Box<dyn Detector>> = vec![
            Box::new(TimestampDetector::new(600)),       // 10 minutes max drift
            Box::new(RapidBlocksDetector::new(30)),      // 30 seconds minimum
            Box::new(OrphanBlocksDetector::new(0.05)),   // 5% max orphan rate
            Box::new(NonceAnomalyDetector::new(u64::MAX)), // 90% saturation threshold
            Box::new(MerkleAnomalyDetector::new()),
            Box::new(FeeAnomalyDetector::new(0.00001, 1000.0)), // Reasonable fee range
            Box::new(MempoolAnomalyDetector::new(100000)), // 100k transaction limit
            Box::new(SignatureAnomalyDetector::new(0.01)), // 1% max invalid rate
            Box::new(ConsensusAnomalyDetector::new(10)),   // 10 block max drift
            Box::new(NetworkAnomalyDetector::new(3)),      // Minimum 3 peers
        ];

        AnomalyDetectionEngine {
            detectors,
            alert_threshold,
            history: Arc::new(RwLock::new(VecDeque::with_capacity(10000))),
        }
    }

    /// Scan data for all anomalies
    pub async fn scan(&self, data: &DetectionData) -> Vec<AnomalyAlert> {
        let mut alerts = Vec::new();

        for detector in &self.detectors {
            if let Some(alert) = detector.detect(data) {
                if alert.score >= self.alert_threshold {
                    alerts.push(alert);
                }
            }
        }

        // Log alerts to history
        for alert in &alerts {
            let event = AnomalyEvent {
                alert: alert.clone(),
                resolved: false,
                resolution_time: None,
            };
            let mut history = self.history.write().await;
            history.push_back(event);
            if history.len() > 10000 {
                history.pop_front();
            }
        }

        alerts
    }

    /// Get anomaly history
    pub async fn get_history(&self, limit: usize) -> Vec<AnomalyEvent> {
        let history = self.history.read().await;
        history
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Mark anomaly as resolved
    pub async fn resolve_anomaly(&self, index: usize) {
        let mut history = self.history.write().await;
        if let Some(event) = history.get_mut(index) {
            event.resolved = true;
            event.resolution_time = Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            );
        }
    }

    /// Get statistics
    pub async fn get_stats(&self) -> AnomalyStats {
        let history = self.history.read().await;
        let total = history.len();
        let resolved = history.iter().filter(|e| e.resolved).count();
        let unresolved = total - resolved;

        let mut by_type: std::collections::HashMap<AnomalyType, usize> =
            std::collections::HashMap::new();
        for event in history.iter() {
            *by_type.entry(event.alert.anomaly_type).or_insert(0) += 1;
        }

        let mut by_severity: std::collections::HashMap<Severity, usize> =
            std::collections::HashMap::new();
        for event in history.iter() {
            *by_severity.entry(event.alert.severity).or_insert(0) += 1;
        }

        AnomalyStats {
            total_anomalies: total,
            resolved_anomalies: resolved,
            unresolved_anomalies: unresolved,
            by_type,
            by_severity,
        }
    }
}

/// Statistics about detected anomalies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyStats {
    pub total_anomalies: usize,
    pub resolved_anomalies: usize,
    pub unresolved_anomalies: usize,
    pub by_type: std::collections::HashMap<AnomalyType, usize>,
    pub by_severity: std::collections::HashMap<Severity, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_detector() {
        let detector = TimestampDetector::new(600);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let data = DetectionData {
            block_height: 1000,
            block_timestamp: now + 700, // 700 seconds in future
            block_time_delta: 60,
            nonce: 1000,
            merkle_root: "abc123".to_string(),
            fee_rate: 0.001,
            mempool_size: 1000,
            signature_count: 10,
            invalid_signatures: 0,
            consensus_height: 1000,
            peer_count: 10,
            orphan_count: 0,
        };

        let alert = detector.detect(&data);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().anomaly_type, AnomalyType::TimestampManipulation);
    }

    #[test]
    fn test_rapid_blocks_detector() {
        let detector = RapidBlocksDetector::new(30);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let data = DetectionData {
            block_height: 1000,
            block_timestamp: now,
            block_time_delta: 10, // 10 seconds (too fast)
            nonce: 1000,
            merkle_root: "abc123".to_string(),
            fee_rate: 0.001,
            mempool_size: 1000,
            signature_count: 10,
            invalid_signatures: 0,
            consensus_height: 1000,
            peer_count: 10,
            orphan_count: 0,
        };

        let alert = detector.detect(&data);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().anomaly_type, AnomalyType::RapidBlocks);
    }

    #[tokio::test]
    async fn test_anomaly_detection_engine() {
        let engine = AnomalyDetectionEngine::new(0.5);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let data = DetectionData {
            block_height: 1000,
            block_timestamp: now,
            block_time_delta: 60,
            nonce: 1000,
            merkle_root: "abc123".to_string(),
            fee_rate: 0.001,
            mempool_size: 1000,
            signature_count: 10,
            invalid_signatures: 0,
            consensus_height: 1000,
            peer_count: 10,
            orphan_count: 0,
        };

        let alerts = engine.scan(&data).await;
        assert!(alerts.is_empty()); // No anomalies in normal data

        let stats = engine.get_stats().await;
        assert_eq!(stats.total_anomalies, 0);
    }
}
