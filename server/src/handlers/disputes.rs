//! Dispute filing and resolution handlers

use axum::extract::{ConnectInfo, Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

use crate::error::{Result, ServerError};
use crate::middleware::auth::UserContext;
use crate::state::AppState;
use axiom_community_shared::crypto;

/// List disputes
pub async fn list_disputes(
    State(state): State<Arc<AppState>>,
    Extension(_user_ctx): Extension<UserContext>,
    Query(params): Query<ListDisputesParams>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    let limit = params.limit.unwrap_or(50).min(100) as i64;
    let offset = params.offset.unwrap_or(0) as i64;

    // Query database
    let disputes = state.db.list_disputes(limit, offset).await?;

    let dispute_list: Vec<serde_json::Value> = disputes
        .iter()
        .map(|dispute| {
            json!({
                "id": dispute.id,
                "job_id": dispute.job_id,
                "work_id": dispute.work_id,
                "initiator": dispute.initiator,
                "reason": dispute.reason,
                "status": dispute.status,
                "resolver": dispute.resolver,
                "timestamp": dispute.timestamp,
            })
        })
        .collect();

    info!("Listed {} disputes", dispute_list.len());

    let response = json!({
        "status": "ok",
        "data": {
            "disputes": dispute_list,
            "total": dispute_list.len(),
        }
    });

    Ok((StatusCode::OK, Json(response)))
}

/// File new dispute/challenge
pub async fn file_dispute(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user_ctx): Extension<UserContext>,
    Json(req): Json<FileDisputeRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    // Validate job exists
    let _job = state
        .db
        .get_job(&req.job_id)
        .await?
        .ok_or(ServerError::Shared(
            axiom_community_shared::Error::JobNotFound,
        ))?;

    // Validate work submission exists
    let _submission =
        state
            .db
            .get_work_submission(&req.work_id)
            .await?
            .ok_or(ServerError::Shared(
                axiom_community_shared::Error::WorkSubmissionNotFound,
            ))?;

    // Validate reason and evidence
    if req.reason.is_empty() || req.reason.len() > 5000 {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidMessage,
        ));
    }

    if req.evidence.is_empty() || req.evidence.len() > 50_000 {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::MessageTooLong,
        ));
    }

    // Rate limit disputes (10 per minute per user)
    if !state.rate_limiter.check_message(&user_ctx.address).await {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::RateLimitExceeded,
        ));
    }

    // Replay protection: reject if this signature was already used
    if !state
        .signature_nonce_tracker
        .check_and_record(&req.signature, &user_ctx.address, "dispute_filed")
        .await
    {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidSignature,
        ));
    }

    // Create dispute
    let dispute_id = format!("dispute:{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().timestamp();
    let evidence_hash = crypto::sha256_hex(req.evidence.as_bytes());

    state
        .db
        .create_dispute(
            &dispute_id,
            &req.job_id,
            &req.work_id,
            &user_ctx.address,
            &req.reason,
            &req.evidence,
            &evidence_hash,
            now,
            &req.signature,
        )
        .await?;

    // Log audit
    let _ = state
        .db
        .log_audit(
            Some(&user_ctx.address),
            "dispute_filed",
            "success",
            Some(&addr.ip().to_string()),
            None,
        )
        .await;

    info!("Dispute filed with ID {}", dispute_id);

    let response = json!({
        "status": "ok",
        "data": {
            "dispute_id": dispute_id,
            "timestamp": now,
        }
    });

    Ok((StatusCode::CREATED, Json(response)))
}

/// Get dispute details
pub async fn get_dispute(
    State(state): State<Arc<AppState>>,
    Extension(_user_ctx): Extension<UserContext>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    let dispute = state.db.get_dispute(&id).await?.ok_or(ServerError::Shared(
        axiom_community_shared::Error::DisputeNotFound,
    ))?;

    let response = json!({
        "status": "ok",
        "data": {
            "id": dispute.id,
            "job_id": dispute.job_id,
            "work_id": dispute.work_id,
            "initiator": dispute.initiator,
            "reason": dispute.reason,
            "evidence_hash": dispute.evidence_hash,
            "status": dispute.status,
            "resolver": dispute.resolver,
            "resolved_at": dispute.resolved_at,
            "timestamp": dispute.timestamp,
        }
    });

    Ok((StatusCode::OK, Json(response)))
}

#[derive(Debug, Deserialize)]
pub struct ListDisputesParams {
    pub status: Option<String>,
    pub job_id: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct FileDisputeRequest {
    pub job_id: String,
    pub work_id: String,
    pub reason: String,
    pub evidence: String,
    pub signature: String,
}
