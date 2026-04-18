// Copyright (c) 2026 Kantoshi Miyamura

use crate::threat::ThreatLevel;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertKind {
    RapidBlockProduction,
    TimestampManipulation,
    DeepReorgDetected,
    MempoolFlooding,
    FeeMarketAnomaly,
    DifficultyDropAnomaly,
    HashrateDominance,
    PeerDiversityLow,
    TransactionAnomalySpike,
    NetworkStall,
    SelfishMining,
}

impl AlertKind {
    pub fn severity(&self) -> AlertSeverity {
        match self {
            Self::RapidBlockProduction  => AlertSeverity::Critical,
            Self::TimestampManipulation => AlertSeverity::Critical,
            Self::DeepReorgDetected     => AlertSeverity::Critical,
            Self::MempoolFlooding       => AlertSeverity::Warning,
            Self::FeeMarketAnomaly      => AlertSeverity::Warning,
            Self::DifficultyDropAnomaly => AlertSeverity::Warning,
            Self::HashrateDominance     => AlertSeverity::Critical,
            Self::PeerDiversityLow      => AlertSeverity::Warning,
            Self::TransactionAnomalySpike => AlertSeverity::Info,
            Self::NetworkStall          => AlertSeverity::Critical,
            Self::SelfishMining         => AlertSeverity::Critical,
        }
    }

    pub fn threat_level(&self) -> ThreatLevel {
        match self {
            Self::RapidBlockProduction  => ThreatLevel::Critical,
            Self::TimestampManipulation => ThreatLevel::High,
            Self::DeepReorgDetected     => ThreatLevel::Critical,
            Self::MempoolFlooding       => ThreatLevel::Medium,
            Self::FeeMarketAnomaly      => ThreatLevel::Medium,
            Self::DifficultyDropAnomaly => ThreatLevel::High,
            Self::HashrateDominance     => ThreatLevel::High,
            Self::PeerDiversityLow      => ThreatLevel::Medium,
            Self::TransactionAnomalySpike => ThreatLevel::Low,
            Self::NetworkStall          => ThreatLevel::High,
            Self::SelfishMining         => ThreatLevel::High,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::RapidBlockProduction =>
                "Blocks are being produced significantly faster than normal. Possible 51% hashrate attack.",
            Self::TimestampManipulation =>
                "Block timestamps deviate anomalously. Possible timestamp manipulation attack.",
            Self::DeepReorgDetected =>
                "A deep chain reorganization has been detected. Chain integrity at risk.",
            Self::MempoolFlooding =>
                "Mempool transaction count spiked abnormally. Possible DDoS or spam attack.",
            Self::FeeMarketAnomaly =>
                "Fee rates have dropped to near-zero. Possible coordinated fee manipulation.",
            Self::DifficultyDropAnomaly =>
                "Network difficulty dropped unusually fast. Possible hashrate departure.",
            Self::HashrateDominance =>
                "A single entity may control an anomalous proportion of hashrate.",
            Self::PeerDiversityLow =>
                "Node connected to suspiciously few peers. Possible eclipse attack.",
            Self::TransactionAnomalySpike =>
                "Unusual spike in transaction volume detected.",
            Self::NetworkStall =>
                "Block production has stalled far beyond the expected interval.",
            Self::SelfishMining =>
                "Potential selfish mining: a peer is withholding and releasing blocks in bursts.",
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::RapidBlockProduction  => "RAPID_BLOCKS",
            Self::TimestampManipulation => "TS_MANIP",
            Self::DeepReorgDetected     => "DEEP_REORG",
            Self::MempoolFlooding       => "MEMPOOL_FLOOD",
            Self::FeeMarketAnomaly      => "FEE_ANOMALY",
            Self::DifficultyDropAnomaly => "DIFF_DROP",
            Self::HashrateDominance     => "HASH_DOMINANCE",
            Self::PeerDiversityLow      => "PEER_LOW",
            Self::TransactionAnomalySpike => "TX_SPIKE",
            Self::NetworkStall          => "NET_STALL",
            Self::SelfishMining         => "SELFISH_MINING",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardAlert {
    /// Unique 8-byte hex identifier.
    pub id: String,
    pub code: String,
    pub kind: AlertKind,
    pub severity: AlertSeverity,
    pub threat_level: ThreatLevel,
    pub timestamp_unix: u64,
    pub block_height: u64,
    pub anomaly_score: f64,
    pub description: String,
    pub details: String,
    /// ML-DSA-87 signature by AxiomMind's cognitive fingerprint.
    pub signature: Vec<u8>,
    /// AxiomMind's ML-DSA-87 public key (2592 bytes).
    pub signer_pubkey: Vec<u8>,
    /// AxiomMind's axm... address.
    pub signer_address: String,
}

impl GuardAlert {
    /// The canonical bytes that AxiomMind signs for this alert.
    pub fn signing_message(kind: AlertKind, height: u64, score_x1000: u64) -> Vec<u8> {
        let mut msg = b"axiom-guard-alert:v1:".to_vec();
        msg.extend_from_slice(
            format!("{}:h{:020}:s{:020}", kind.code(), height, score_x1000).as_bytes(),
        );
        msg
    }
}
