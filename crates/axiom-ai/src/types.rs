// Copyright (c) 2026 Kantoshi Miyamura

use serde::{Deserialize, Serialize};

/// A model record stored in the on-chain AI model registry.
///
/// The `model_hash` is a SHA-256 hex digest (64 chars) of the model weights
/// or artifact that was registered.  Registration is permanent and
/// append-only — a hash can only be registered once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRecord {
    /// SHA-256 hex digest of the model artifact (64 lowercase hex chars).
    pub model_hash: String,
    /// Human-readable model name.
    pub name: String,
    /// Semantic version string (e.g. "1.0.0").
    pub version: String,
    /// Short description of the model's purpose.
    pub description: String,
    /// Axiom address of the registrant.
    pub registered_by: String,
    /// Unix timestamp (seconds) at registration time.
    pub registered_at: u64,
}

// ── Inference payment types ───────────────────────────────────────────────────

/// Lifecycle state of an inference job.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum JobStatus {
    /// Job created; waiting for provider to execute.
    Pending,
    /// Provider completed the job and submitted a result hash.
    Completed,
    /// Requester cancelled before completion.
    Cancelled,
}

/// A single inference job stored in the payment registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceJob {
    /// Unique job identifier (SHA-256 hex of model+requester+timestamp).
    pub job_id: String,
    /// SHA-256 hex hash of the model to run (must be registered).
    pub model_hash: String,
    /// Axiom address of the party requesting inference.
    pub requester: String,
    /// Axiom address of the party providing compute.
    pub provider: String,
    /// AXM satoshis to pay the provider on completion.
    pub amount_sat: u64,
    /// Current lifecycle state.
    pub status: JobStatus,
    /// SHA-256 hex hash of the inference output (set on completion).
    pub result_hash: Option<String>,
    /// Unix timestamp (milliseconds) when the job was created.
    pub created_at: u64,
    /// Unix timestamp (milliseconds) when the job reached a terminal state.
    pub completed_at: Option<u64>,
}

/// Request body for `POST /ai/inference/request`.
#[derive(Debug, Deserialize)]
pub struct RequestInferenceRequest {
    /// Registered model hash to run.
    pub model_hash: String,
    /// Axiom address of the requester.
    pub requester: String,
    /// Axiom address of the intended provider.
    pub provider: String,
    /// AXM satoshis to pay on completion.
    pub amount_sat: u64,
}

/// Request body for `POST /ai/inference/complete`.
#[derive(Debug, Deserialize)]
pub struct CompleteInferenceRequest {
    /// Job to mark as completed.
    pub job_id: String,
    /// SHA-256 hex hash of the inference output produced by the provider.
    pub result_hash: String,
}

/// Request body for `POST /ai/inference/cancel`.
#[derive(Debug, Deserialize)]
pub struct CancelInferenceRequest {
    /// Job to cancel.
    pub job_id: String,
}

// ── Reputation types ──────────────────────────────────────────────────────────

/// Aggregated reputation score for a model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationScore {
    /// Model this score belongs to.
    pub model_hash: String,
    /// Number of ratings submitted.
    pub total_ratings: u64,
    /// Mean rating (1.0–5.0); 0.0 if no ratings yet.
    pub avg_rating: f64,
    /// Total completed inference jobs recorded for this model.
    pub completions: u64,
    /// Composite score: `avg_rating × completions / (completions + 1)`.
    pub score: f64,
}

/// Request body for `POST /ai/reputation/:model_hash/rate`.
#[derive(Debug, Deserialize)]
pub struct RateModelRequest {
    /// Rating from 1 (worst) to 5 (best).
    pub rating: u8,
    /// Axiom address of the rater. Used to prevent duplicate ratings.
    /// If omitted, deduplication is skipped (backwards-compatible).
    #[serde(default)]
    pub rater_address: String,
}

/// Request body for `POST /ai/stake`.
#[derive(Debug, Deserialize)]
pub struct AddStakeRequest {
    /// Axiom address of the provider staking funds.
    pub provider: String,
    /// AXM satoshis to add to the stake.
    pub amount_sat: u64,
}

// ── Model registry types ──────────────────────────────────────────────────────

/// Request body for `POST /ai/model/register`.
#[derive(Debug, Deserialize)]
pub struct RegisterModelRequest {
    /// SHA-256 hex digest of the model artifact.
    pub model_hash: String,
    /// Human-readable model name.
    pub name: String,
    /// Semantic version string.
    pub version: String,
    /// Short description.
    pub description: String,
    /// Axiom address of the registrant.
    pub registered_by: String,
}
