//! Job posting and work submission handlers

use axum::extract::{State, Path, Query, ConnectInfo, Extension};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

use axiom_community_shared::crypto;
use crate::state::AppState;
use crate::error::{Result, ServerError};
use crate::middleware::auth::UserContext;

/// List jobs in a channel
pub async fn list_jobs(
    State(state): State<Arc<AppState>>,
    Extension(_user_ctx): Extension<UserContext>,
    Query(params): Query<ListJobsParams>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    // Validate channel name
    let channel = params.channel.unwrap_or_else(|| "general".to_string());
    if channel.is_empty() || channel.len() > 100 {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidChannel,
        ));
    }

    let limit = params.limit.unwrap_or(50).min(100) as i64;
    let offset = params.offset.unwrap_or(0) as i64;

    // Query database
    let jobs = state.db.list_jobs(&channel, limit, offset).await?;

    let job_list: Vec<serde_json::Value> = jobs
        .iter()
        .map(|job| {
            json!({
                "id": job.id,
                "channel": job.channel,
                "requester": job.requester,
                "title": job.title,
                "description": job.description,
                "reward_sat": job.reward_sat,
                "deadline": job.deadline,
                "max_workers": job.max_workers,
                "state": job.state,
                "work_type": job.work_type,
                "assigned_workers": job.assigned_workers,
                "timestamp": job.timestamp,
            })
        })
        .collect();

    info!(
        "Listed {} jobs in channel '{}'",
        job_list.len(),
        channel
    );

    let response = json!({
        "status": "ok",
        "data": {
            "jobs": job_list,
            "total": job_list.len(),
        }
    });

    Ok((StatusCode::OK, Json(response)))
}

/// Create new job
pub async fn create_job(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user_ctx): Extension<UserContext>,
    Json(req): Json<CreateJobRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    // Validate channel
    if req.channel.is_empty() || req.channel.len() > 100 {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidChannel,
        ));
    }

    // Validate title and description
    if req.title.is_empty() || req.title.len() > 500 {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidMessage,
        ));
    }

    if req.description.is_empty() || req.description.len() > 50_000 {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::MessageTooLong,
        ));
    }

    // Validate reward
    if req.reward_sat == 0 {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidMessage,
        ));
    }

    // Validate deadline is in the future
    let now = chrono::Utc::now().timestamp();
    if req.deadline <= now {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidMessage,
        ));
    }

    // Check rate limit (20 jobs per minute per user)
    if !state.rate_limiter.check_job(&user_ctx.address).await {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::RateLimitExceeded,
        ));
    }

    // Replay protection: reject if this signature was already used
    if !state.signature_nonce_tracker.check_and_record(&req.signature, &user_ctx.address, "job_action").await {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidSignature,
        ));
    }

    // Create job
    let job_id = format!("job:{}", uuid::Uuid::new_v4());

    state
        .db
        .create_job(
            &job_id,
            &req.channel,
            &user_ctx.address,
            &req.title,
            &req.description,
            req.reward_sat as i64,
            req.deadline,
            req.max_workers as i32,
            &req.work_type,
            req.requirements,
            now,
            &req.signature,
        )
        .await?;

    // Log audit
    let _ = state
        .db
        .log_audit(
            Some(&user_ctx.address),
            "job_posted",
            "success",
            Some(&addr.ip().to_string()),
            None,
        )
        .await;

    info!("Job posted with ID {}", job_id);

    let response = json!({
        "status": "ok",
        "data": {
            "id": job_id,
            "timestamp": now,
        }
    });

    Ok((StatusCode::CREATED, Json(response)))
}

/// Get job details
pub async fn get_job(
    State(state): State<Arc<AppState>>,
    Extension(_user_ctx): Extension<UserContext>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    let job = state
        .db
        .get_job(&id)
        .await?
        .ok_or(ServerError::Shared(
            axiom_community_shared::Error::JobNotFound,
        ))?;

    let response = json!({
        "status": "ok",
        "data": {
            "id": job.id,
            "channel": job.channel,
            "requester": job.requester,
            "title": job.title,
            "description": job.description,
            "reward_sat": job.reward_sat,
            "deadline": job.deadline,
            "max_workers": job.max_workers,
            "state": job.state,
            "work_type": job.work_type,
            "requirements": job.requirements,
            "assigned_workers": job.assigned_workers,
            "timestamp": job.timestamp,
        }
    });

    Ok((StatusCode::OK, Json(response)))
}

/// Submit work result
pub async fn submit_result(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user_ctx): Extension<UserContext>,
    Json(req): Json<SubmitResultRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    // Verify job exists
    let job = state
        .db
        .get_job(&job_id)
        .await?
        .ok_or(ServerError::Shared(
            axiom_community_shared::Error::JobNotFound,
        ))?;

    // Check job is still open
    if job.state != "open" && job.state != "assigned" && job.state != "in_progress" {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidJobState,
        ));
    }

    // Validate submission data size (max 1MB)
    if req.submission_data.len() > 1_048_576 {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::MessageTooLong,
        ));
    }

    // Verify data hash matches
    let computed_hash = crypto::sha256_hex(req.submission_data.as_bytes());
    if computed_hash != req.data_hash {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidMessage,
        ));
    }

    // Check rate limit (100 submissions per minute per user)
    if !state.rate_limiter.check_message(&user_ctx.address).await {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::RateLimitExceeded,
        ));
    }

    // Replay protection: reject if this signature was already used
    if !state.signature_nonce_tracker.check_and_record(&req.signature, &user_ctx.address, "job_action").await {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidSignature,
        ));
    }

    // Create submission
    let submission_id = format!("work:{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().timestamp();

    state
        .db
        .create_work_submission(
            &submission_id,
            &job_id,
            &user_ctx.address,
            &req.submission_data,
            &req.data_hash,
            now,
            &req.signature,
        )
        .await?;

    // Log audit
    let _ = state
        .db
        .log_audit(
            Some(&user_ctx.address),
            "work_submitted",
            "success",
            Some(&addr.ip().to_string()),
            None,
        )
        .await;

    info!("Work submission {} for job {}", submission_id, job_id);

    let response = json!({
        "status": "ok",
        "data": {
            "submission_id": submission_id,
            "timestamp": now,
            "data_hash": req.data_hash,
        }
    });

    Ok((StatusCode::CREATED, Json(response)))
}

#[derive(Debug, Deserialize)]
pub struct ListJobsParams {
    pub channel: Option<String>,
    pub state: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct CreateJobRequest {
    pub channel: String,
    pub title: String,
    pub description: String,
    pub reward_sat: u64,
    pub deadline: i64,
    pub max_workers: u32,
    pub work_type: String,
    pub requirements: Vec<String>,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct SubmitResultRequest {
    pub submission_data: String,
    pub data_hash: String,
    pub signature: String,
}
