//! Moderation action handlers (Moderator+ role required)

use axum::extract::{State, Query, ConnectInfo, Extension};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

use crate::permissions;
use crate::state::AppState;
use crate::error::{Result, ServerError};
use crate::middleware::auth::UserContext;

/// Create moderation action
pub async fn create_action(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user_ctx): Extension<UserContext>,
    Json(req): Json<CreateModerationRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    // Enforce Moderator role (defense-in-depth — middleware also checks)
    permissions::check_can_moderate(&user_ctx.roles)?;

    // Validate action type
    let valid_actions = ["delete_message", "mute_user", "ban_user", "warn_user"];
    if !valid_actions.contains(&req.action.as_str()) {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidMessage,
        ));
    }

    // Validate reason
    if req.reason.is_empty() || req.reason.len() > 1000 {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidMessage,
        ));
    }

    // Validate target format (message ID or address)
    let target_type = if req.target.starts_with("msg:") {
        "message"
    } else if req.target.starts_with("axiom1") && req.target.len() == 42 {
        "user"
    } else {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidAddress,
        ));
    };

    // Validate duration if provided
    let duration_secs = req.duration_secs.map(|d| d as i64);
    if let Some(d) = duration_secs {
        if d <= 0 {
            return Err(ServerError::Shared(
                axiom_community_shared::Error::InvalidMessage,
            ));
        }
    }

    // Replay protection: reject if this signature was already used
    if !state.signature_nonce_tracker.check_and_record(&req.signature, &user_ctx.address, "moderation_action").await {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidSignature,
        ));
    }

    // Create moderation action
    let action_id = format!("mod:{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().timestamp();

    state
        .db
        .create_moderation_action(
            &action_id,
            &req.action,
            &req.target,
            target_type,
            &req.reason,
            duration_secs,
            &user_ctx.address,
            now,
            &req.signature,
        )
        .await?;

    // Log audit
    let _ = state
        .db
        .log_audit(
            Some(&user_ctx.address),
            &format!("action_{}", req.action),
            "success",
            Some(&addr.ip().to_string()),
            None,
        )
        .await;

    info!("Moderation action {} created: {} on {}", action_id, req.action, req.target);

    let response = json!({
        "status": "ok",
        "data": {
            "action_id": action_id,
            "timestamp": now,
        }
    });

    Ok((StatusCode::CREATED, Json(response)))
}

/// List moderation actions
pub async fn list_actions(
    State(state): State<Arc<AppState>>,
    Extension(_user_ctx): Extension<UserContext>,
    Query(params): Query<ListActionsParams>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    let limit = params.limit.unwrap_or(50).min(100) as i64;
    let offset = params.offset.unwrap_or(0) as i64;

    // Query database
    let actions = state.db.list_moderation_actions(limit, offset).await?;

    let action_list: Vec<serde_json::Value> = actions
        .iter()
        .map(|action| {
            json!({
                "id": action.id,
                "action": action.action,
                "target": action.target,
                "target_type": action.target_type,
                "reason": action.reason,
                "moderator": action.moderator,
                "expires_at": action.expires_at,
                "timestamp": action.timestamp,
            })
        })
        .collect();

    info!("Listed {} moderation actions", action_list.len());

    let response = json!({
        "status": "ok",
        "data": {
            "actions": action_list,
            "total": action_list.len(),
        }
    });

    Ok((StatusCode::OK, Json(response)))
}

#[derive(Debug, Deserialize)]
pub struct CreateModerationRequest {
    pub action: String, // delete_message, mute_user, ban_user, warn_user
    pub target: String, // message ID or user address
    pub reason: String,
    pub duration_secs: Option<u64>, // None = permanent
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct ListActionsParams {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}
