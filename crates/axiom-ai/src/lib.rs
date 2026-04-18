// Copyright (c) 2026 Kantoshi Miyamura

//! `axiom-ai` — AI model registry and inference payment layer for the
//! Axiom Network.
//!
//! # Phase AI-1: Model Registry
//!
//! Persistent, append-only registration of AI model artifacts by SHA-256 hash.
//! Backed by a fjall partition at `<data_dir>/ai_registry/`.
//!
//! - `POST /ai/model/register` — register a model hash with metadata
//! - `GET  /ai/model/:hash`    — fetch a model record by hash
//! - `GET  /ai/models/recent`  — list recently registered models
//!
//! # Phase AI-2: Inference Payments
//!
//! Lifecycle management for AI inference jobs.  AXM is the settlement token:
//! requester locks `amount_sat` on job creation; provider earns it on completion.
//! Backed by a fjall partition at `<data_dir>/ai_jobs/`.
//!
//! - `POST /ai/inference/request`  — open a new Pending job
//! - `POST /ai/inference/complete` — provider marks job done + submits result hash
//! - `POST /ai/inference/cancel`   — requester cancels a Pending job
//! - `GET  /ai/inference/:job_id`  — fetch a job by ID
//! - `GET  /ai/inference/jobs/:address` — list jobs for an address

pub mod inference;
pub mod registry;
pub mod reputation;
pub mod types;

// Proof of Useful Compute (PoUC) Protocol — Phase AI-3
pub mod compute_types;
pub mod worker;
pub mod verifier;
pub mod settlement;
pub mod protocol;

// AxiomMind v2 - Neural Guardian modules
#[allow(clippy::needless_range_loop)]
pub mod neural_network;
pub mod anomaly_detection;
pub mod self_healing;
pub mod reinforcement_learning;
pub mod monitoring;
pub mod axiommind_v2;

pub use inference::{InferenceError, InferenceRegistry};
pub use registry::{ModelRegistry, RegistryError};
pub use reputation::{ProviderStake, ReputationError, ReputationRegistry};
pub use types::{
    AddStakeRequest, CancelInferenceRequest, CompleteInferenceRequest, InferenceJob, JobStatus,
    ModelRecord, RateModelRequest, RegisterModelRequest, ReputationScore, RequestInferenceRequest,
};

// PoUC Protocol exports
pub use compute_types::{
    ComputeError, ComputeJob, ComputeJobStatus, ComputeJobType, DisputeRecord,
    DisputeResolution, FileChallengeRequest, RegisterVerifierRequest, RegisterWorkerRequest,
    ResolvDisputeRequest, SettlementOutcome, SettlementRecord, SubmitComputeJobRequest,
    SubmitResultRequest, VerifierRegistration, WorkerRegistration, Result as ComputeResult,
};
pub use worker::WorkerRegistry;
pub use verifier::VerifierRegistry;
pub use settlement::SettlementEngine;
pub use protocol::ComputeProtocol;

// AxiomMind v2 exports
pub use neural_network::{DistributedNeuralNetwork, NeuralModel};
pub use anomaly_detection::{
    AnomalyAlert, AnomalyDetectionEngine, AnomalyType, Detector, DetectionData, Severity,
};
pub use self_healing::{
    ConsensusEngine, Patch, PatchGenerator, PatchResult, SelfHealingSystem, Vulnerability,
    VulnerabilityDatabase, VulnerabilitySeverity, VulnerabilityType,
};
pub use reinforcement_learning::{
    Action, Episode, LearningStats, Policy, QLearningModule, ReinforcementLearningEngine, Reward,
    State,
};
pub use monitoring::{
    AIDashboard, Alert, AlertManager, AlertSeverity, AlertType, AuditEvent, AuditEventType,
    AuditLogger, AuditSeverity, MonitoringSystem, NetworkDashboard, PerformanceDashboard,
    ReportGenerator, SecurityDashboard, StatusReport,
};
pub use axiommind_v2::{AxiomMindV2, HealthLevel, HealthStatus, ScanResult, SystemReport, SystemStatus};
