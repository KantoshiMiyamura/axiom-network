// Copyright (c) 2026 Kantoshi Miyamura
//
//! Proof of Useful Compute Protocol (PoUC) — Type Definitions
//!
//! This module defines all data types for the AI compute market protocol,
//! including jobs, workers, verifiers, disputes, and settlements.
//! The protocol ensures:
//! - Workers are incentivized to produce correct results (via stake + reputation)
//! - Verifiers are incentivized to catch fraud (via rewards)
//! - Bad actors are slashed and evicted (via reputation decay)
//! - The blockchain remains deterministic (all compute is off-chain)

use serde::{Deserialize, Serialize};

// ─ Protocol Constants ─────────────────────────────────────────────────────

/// Minimum stake required to register as a worker (satoshis)
pub const MIN_WORKER_STAKE_SAT: u64 = 1_000;

/// Minimum stake required to register as a verifier (satoshis)
pub const MIN_VERIFIER_STAKE_SAT: u64 = 5_000;

/// Minimum job fee (satoshis)
pub const MIN_JOB_FEE_SAT: u64 = 546;

/// Maximum result payload size (bytes)
pub const MAX_RESULT_BYTES: u64 = 1_048_576; // 1 MB

/// Maximum concurrent active jobs per address
pub const MAX_CONCURRENT_JOBS_PER_ADDRESS: usize = 10;

/// Default job deadline (seconds from creation)
pub const DEFAULT_JOB_DEADLINE_SECS: u64 = 3600; // 1 hour

/// Challenge window duration (seconds after result submission)
pub const DEFAULT_CHALLENGE_WINDOW_SECS: u64 = 300; // 5 minutes

/// Fee distribution (basis points, 10000 = 100%)
pub const WORKER_REWARD_BPS: u64 = 8000; // 80% to worker
pub const VERIFIER_SAMPLE_BPS: u64 = 500; // 5% for normal verification
pub const VERIFIER_FRAUD_CATCH_BPS: u64 = 1500; // 15% for catching fraud
pub const PROTOCOL_FEE_BPS: u64 = 500; // 5% protocol fee
pub const CHALLENGE_DEPOSIT_BPS: u64 = 1000; // 10% challenge deposit

/// Slash amounts (basis points)
pub const FRAUD_WORKER_SLASH_BPS: u64 = 2000; // 20% of stake on fraud
pub const FALSE_ACCUSE_SLASH_BPS: u64 = 5000; // 50% of deposit on false accuse

/// Reputation changes
pub const REPUTATION_SUCCESS_BONUS: f64 = 0.002; // +0.2% per successful job
pub const REPUTATION_FRAUD_PENALTY: f64 = 0.85; // 0.85x on fraud (15% cut)
pub const REPUTATION_EVICTION_THRESHOLD: f64 = 0.15; // Evict below this

/// Verifier sampling rate (30% of jobs spot-checked)
pub const VERIFIER_SAMPLE_RATE_BPS: u64 = 3000;

// ─ Error Types ───────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ComputeError {
    #[error("storage error: {0}")]
    Storage(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("job not found: {0}")]
    JobNotFound(String),

    #[error("worker not found: {0}")]
    WorkerNotFound(String),

    #[error("verifier not found: {0}")]
    VerifierNotFound(String),

    #[error("dispute not found: {0}")]
    DisputeNotFound(String),

    #[error("invalid state transition: expected {expected}, got {got}")]
    InvalidTransition { expected: String, got: String },

    #[error("invalid job fee: {0}")]
    InvalidFee(String),

    #[error("invalid input hash: {0}")]
    InvalidHash(String),

    #[error("model not registered: {0}")]
    ModelNotRegistered(String),

    #[error("worker not active: {0}")]
    WorkerNotActive(String),

    #[error("verifier not active: {0}")]
    VerifierNotActive(String),

    #[error("insufficient stake: required {required}, have {have}")]
    InsufficientStake { required: u64, have: u64 },

    #[error("too many active jobs for address: {0}")]
    TooManyActiveJobs(String),

    #[error("result payload too large: {size} bytes (max {max})")]
    ResultTooLarge { size: u64, max: u64 },

    #[error("challenge window expired")]
    ChallengeWindowExpired,

    #[error("deadline already passed")]
    DeadlineExpired,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("commitment mismatch")]
    CommitmentMismatch,
}

pub type Result<T> = std::result::Result<T, ComputeError>;

// ─ Job Types ─────────────────────────────────────────────────────────────

/// Type of compute job
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ComputeJobType {
    Inference,
    Validation,
    Benchmark,
}

impl std::fmt::Display for ComputeJobType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ComputeJobType::Inference => write!(f, "inference"),
            ComputeJobType::Validation => write!(f, "validation"),
            ComputeJobType::Benchmark => write!(f, "benchmark"),
        }
    }
}

/// Lifecycle status of a compute job
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ComputeJobStatus {
    /// Job created, waiting for worker assignment
    Submitted,
    /// Assigned to a worker but not yet acknowledged
    Assigned { worker: String },
    /// Worker acknowledged, computation in progress
    Computing { worker: String },
    /// Worker submitted result, verification in progress
    Completed {
        worker: String,
        result_hash: String,
        commitment_hash: String,
        submitted_at: u64,
    },
    /// Result challenged by verifier, dispute in progress
    Challenged {
        worker: String,
        verifier: String,
        challenge_result_hash: String,
        challenged_at: u64,
    },
    /// Job finalized (no challenge or dispute resolved), rewards distributed
    Finalized {
        result_hash: String,
        finalized_at: u64,
    },
    /// Job cancelled before assignment
    Cancelled,
    /// Job expired due to deadline
    Expired,
}

/// A compute job with full lifecycle state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeJob {
    /// Unique job identifier
    pub job_id: String,
    /// Type of computation
    pub job_type: ComputeJobType,
    /// SHA-256 of registered model (must exist in ModelRegistry)
    pub model_hash: String,
    /// SHA-256 of input data (full data stored off-chain)
    pub input_hash: String,
    /// Requester's Axiom address
    pub requester: String,
    /// Fee in satoshis (held in escrow)
    pub fee_sat: u64,
    /// Deadline (Unix seconds)
    pub deadline_ts: u64,
    /// Challenge window duration (seconds after result submission)
    pub challenge_window_secs: u64,
    /// Current lifecycle state
    pub status: ComputeJobStatus,
    /// Job creation time (Unix seconds)
    pub created_at: u64,
    /// Maximum result payload size (bytes)
    pub result_size_limit_bytes: u64,
}

// ─ Worker Registration ────────────────────────────────────────────────────

/// Registered compute provider with stake and reputation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRegistration {
    /// Worker's Axiom address
    pub worker_id: String,
    /// Staked collateral (satoshis)
    pub stake_sat: u64,
    /// Registration time (Unix seconds)
    pub registered_at: u64,
    /// Whether worker is active (not evicted)
    pub active: bool,
    /// Reputation score (0.0 to 1.0)
    pub reputation_score: f64,
    /// Total jobs completed
    pub total_jobs: u64,
    /// Successful completions
    pub successful_jobs: u64,
    /// Fraud convictions
    pub fraud_convictions: u64,
}

// ─ Verifier Registration ──────────────────────────────────────────────────

/// Registered verifier with stake and reputation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierRegistration {
    /// Verifier's Axiom address
    pub verifier_id: String,
    /// Staked collateral (satoshis)
    pub stake_sat: u64,
    /// Registration time (Unix seconds)
    pub registered_at: u64,
    /// Whether verifier is active (not evicted)
    pub active: bool,
    /// Reputation score (0.0 to 1.0)
    pub reputation_score: f64,
    /// Total challenges filed
    pub total_challenges: u64,
    /// Successful challenges (fraud caught)
    pub successful_challenges: u64,
    /// False accusations
    pub false_challenges: u64,
}

// ─ Result Submission ──────────────────────────────────────────────────────

/// Worker's result submission with cryptographic commitment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultSubmission {
    /// Job ID being completed
    pub job_id: String,
    /// Worker's Axiom address
    pub worker_address: String,
    /// SHA-256 of full result (data stored off-chain)
    pub result_hash: String,
    /// Size of result payload (bytes)
    pub result_size_bytes: u64,
    /// Computation time (milliseconds)
    pub compute_time_ms: u64,
    /// SHA-256(job_id || "|" || worker_address || "|" || result_hash)
    pub commitment_hash: String,
    /// ML-DSA-87 signature over commitment_hash
    pub worker_signature: Vec<u8>,
    /// Submission time (Unix seconds)
    pub submitted_at: u64,
}

// ─ Dispute Protocol ───────────────────────────────────────────────────────

/// A challenge to a result submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeRecord {
    /// Unique dispute identifier
    pub dispute_id: String,
    /// Job ID being disputed
    pub job_id: String,
    /// Verifier's Axiom address
    pub challenger: String,
    /// SHA-256 hash of verifier's recomputed result
    pub challenger_result_hash: String,
    /// SHA-256(job_id || "|" || challenger || "|" || challenger_result_hash)
    pub commitment_hash: String,
    /// ML-DSA-87 signature over commitment_hash
    pub challenger_signature: Vec<u8>,
    /// Challenge deposit held in escrow (satoshis)
    pub challenge_deposit_sat: u64,
    /// Time dispute filed (Unix seconds)
    pub filed_at: u64,
    /// Deadline for evidence submission (Unix seconds)
    pub evidence_deadline_ts: u64,
    /// Resolution outcome (if any)
    pub resolution: Option<DisputeResolution>,
}

/// Outcome of a resolved dispute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DisputeResolution {
    /// Worker was caught cheating
    FraudConfirmed {
        worker_slash_sat: u64,
        verifier_reward_sat: u64,
        resolved_at: u64,
    },
    /// Verifier's accusation was false
    FalseAccusation {
        verifier_slash_sat: u64,
        worker_bonus_sat: u64,
        resolved_at: u64,
    },
    /// No conclusive evidence
    Inconclusive { resolved_at: u64 },
}

// ─ Settlement ─────────────────────────────────────────────────────────────

/// Outcome of job settlement
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SettlementOutcome {
    Success,
    FraudConvicted,
    FalseAccusation,
    Cancelled,
    Expired,
}

/// Settlement record for a job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementRecord {
    /// Job ID
    pub job_id: String,
    /// Reward to worker (satoshis)
    pub worker_reward_sat: u64,
    /// Reward to verifier (satoshis)
    pub verifier_reward_sat: u64,
    /// Protocol fee collected (satoshis)
    pub protocol_fee_sat: u64,
    /// Amount slashed (satoshis)
    pub slash_sat: u64,
    /// Settlement time (Unix seconds)
    pub settled_at: u64,
    /// Outcome of settlement
    pub outcome: SettlementOutcome,
}

// ─ RPC Request Types ──────────────────────────────────────────────────────

/// Request to submit a new compute job
#[derive(Debug, Clone, Deserialize)]
pub struct SubmitComputeJobRequest {
    pub job_type: String,
    pub model_hash: String,
    pub input_hash: String,
    pub requester: String,
    pub fee_sat: u64,
    pub deadline_secs: u64,
    pub result_size_limit_bytes: u64,
}

/// Request to register as a worker
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterWorkerRequest {
    pub worker_id: String,
    pub initial_stake_sat: u64,
}

/// Request to register as a verifier
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterVerifierRequest {
    pub verifier_id: String,
    pub initial_stake_sat: u64,
}

/// Request to submit a result
#[derive(Debug, Clone, Deserialize)]
pub struct SubmitResultRequest {
    pub job_id: String,
    pub worker_address: String,
    pub result_hash: String,
    pub result_size_bytes: u64,
    pub compute_time_ms: u64,
    pub commitment_hash: String,
    pub worker_signature: String, // hex-encoded
}

/// Request to challenge a result
#[derive(Debug, Clone, Deserialize)]
pub struct FileChallengeRequest {
    pub job_id: String,
    pub verifier_address: String,
    pub challenger_result_hash: String,
    pub commitment_hash: String,
    pub verifier_signature: String, // hex-encoded
}

/// Request to resolve a dispute
#[derive(Debug, Clone, Deserialize)]
pub struct ResolvDisputeRequest {
    pub dispute_id: String,
    pub resolution: String, // "fraud_confirmed", "false_accusation", "inconclusive"
}

// ─ RPC Response Types ─────────────────────────────────────────────────────

/// Response for job submission
#[derive(Debug, Clone, Serialize)]
pub struct ComputeJobResponse {
    pub job_id: String,
    pub status: String,
    pub model_hash: String,
    pub requester: String,
    pub fee_sat: u64,
    pub deadline_ts: u64,
    pub created_at: u64,
}

/// Response for worker registration
#[derive(Debug, Clone, Serialize)]
pub struct WorkerRegistrationResponse {
    pub worker_id: String,
    pub stake_sat: u64,
    pub reputation_score: f64,
    pub active: bool,
    pub registered_at: u64,
}

/// Response for verifier registration
#[derive(Debug, Clone, Serialize)]
pub struct VerifierRegistrationResponse {
    pub verifier_id: String,
    pub stake_sat: u64,
    pub reputation_score: f64,
    pub active: bool,
    pub registered_at: u64,
}

/// Response for listing active workers
#[derive(Debug, Clone, Serialize)]
pub struct ListWorkersResponse {
    pub workers: Vec<WorkerRegistrationResponse>,
    pub count: usize,
}

/// Response for listing active verifiers
#[derive(Debug, Clone, Serialize)]
pub struct ListVerifiersResponse {
    pub verifiers: Vec<VerifierRegistrationResponse>,
    pub count: usize,
}

/// Response for dispute resolution
#[derive(Debug, Clone, Serialize)]
pub struct DisputeResolutionResponse {
    pub dispute_id: String,
    pub job_id: String,
    pub resolution: String,
    pub resolved_at: u64,
    pub worker_slash_sat: u64,
    pub verifier_reward_sat: u64,
}

/// Response for settlement
#[derive(Debug, Clone, Serialize)]
pub struct SettlementResponse {
    pub job_id: String,
    pub worker_reward_sat: u64,
    pub verifier_reward_sat: u64,
    pub protocol_fee_sat: u64,
    pub outcome: String,
    pub settled_at: u64,
}
