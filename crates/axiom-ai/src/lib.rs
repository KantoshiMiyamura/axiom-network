// Copyright (c) 2026 Kantoshi Miyamura

//! `axiom-ai` — AI registry, inference accounting, PoUC, and AxiomMind v2.
//!
//! INVARIANT: this crate has no dependency on `axiom-consensus` and no path
//! by which its outputs can mutate consensus state. Registries persist in
//! their own fjall partitions (`<data_dir>/ai_registry/`, `<data_dir>/ai_jobs/`);
//! `amount_sat` fields are accounting numbers internal to the AI registry and
//! do NOT lock or move on-chain UTXOs. AxiomMind v2 components (anomaly
//! detector, self-healer, RL engine, monitoring) are advisory observers only.
//! See AI-CONSENSUS-AUDIT.md for the full isolation argument.
//!
//! Modules:
//! - `registry`, `inference`, `reputation` — model/inference/provider records
//! - `worker`, `verifier`, `settlement`, `protocol`, `compute_types` — PoUC
//! - `neural_network`, `anomaly_detection`, `self_healing`,
//!   `reinforcement_learning`, `monitoring`, `axiommind_v2` — AxiomMind v2

pub mod inference;
pub mod registry;
pub mod reputation;
pub mod types;

// Proof of Useful Compute (PoUC).
pub mod compute_types;
pub mod protocol;
pub mod settlement;
pub mod verifier;
pub mod worker;

// AxiomMind v2 — observers only; see crate-level INVARIANT.
pub mod anomaly_detection;
pub mod axiommind_v2;
pub mod monitoring;
#[allow(clippy::needless_range_loop)]
pub mod neural_network;
pub mod reinforcement_learning;
pub mod self_healing;

// Guardian — deterministic, signed, gossip-able advisory layer.
pub mod guardian;

pub use inference::{InferenceError, InferenceRegistry};
pub use registry::{ModelRegistry, RegistryError};
pub use reputation::{ProviderStake, ReputationError, ReputationRegistry};
pub use types::{
    AddStakeRequest, CancelInferenceRequest, CompleteInferenceRequest, InferenceJob, JobStatus,
    ModelRecord, RateModelRequest, RegisterModelRequest, ReputationScore, RequestInferenceRequest,
};

// PoUC Protocol exports
pub use compute_types::{
    ComputeError, ComputeJob, ComputeJobStatus, ComputeJobType, DisputeRecord, DisputeResolution,
    FileChallengeRequest, RegisterVerifierRequest, RegisterWorkerRequest, ResolvDisputeRequest,
    Result as ComputeResult, SettlementOutcome, SettlementRecord, SubmitComputeJobRequest,
    SubmitResultRequest, VerifierRegistration, WorkerRegistration,
};
pub use protocol::ComputeProtocol;
pub use settlement::SettlementEngine;
pub use verifier::VerifierRegistry;
pub use worker::WorkerRegistry;

// AxiomMind v2 exports
pub use anomaly_detection::{
    AnomalyAlert, AnomalyDetectionEngine, AnomalyType, DetectionData, Detector, Severity,
};
pub use axiommind_v2::{
    AxiomMindV2, HealthLevel, HealthStatus, ScanResult, SystemReport, SystemStatus,
};
pub use monitoring::{
    AIDashboard, Alert, AlertManager, AlertSeverity, AlertType, AuditEvent, AuditEventType,
    AuditLogger, AuditSeverity, MonitoringSystem, NetworkDashboard, PerformanceDashboard,
    ReportGenerator, SecurityDashboard, StatusReport,
};
pub use neural_network::{DistributedNeuralNetwork, NeuralModel};
pub use reinforcement_learning::{
    Action, Episode, LearningStats, Policy, QLearningModule, ReinforcementLearningEngine, Reward,
    State,
};
pub use self_healing::{
    ConsensusEngine, Patch, PatchGenerator, PatchResult, SelfHealingSystem, Vulnerability,
    VulnerabilityDatabase, VulnerabilitySeverity, VulnerabilityType,
};
