//! User profile and reputation handlers

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::json;
use std::sync::Arc;
use tracing::info;

use crate::error::{Result, ServerError};
use crate::middleware::auth::UserContext;
use crate::state::AppState;

/// Get user profile
pub async fn get_user(
    State(state): State<Arc<AppState>>,
    Extension(_user_ctx): Extension<UserContext>,
    Path(address): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    // Validate address format (axiom1 + 36 chars = 42 total)
    if address.len() != 42 || !address.starts_with("axiom1") {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidAddress,
        ));
    }

    // Get user from database
    let user = state
        .db
        .get_user(&address)
        .await?
        .ok_or(ServerError::Shared(
            axiom_community_shared::Error::InvalidAddress,
        ))?;

    info!("Retrieved user profile for {}", address);

    let response = json!({
        "status": "ok",
        "data": {
            "address": user.address,
            "reputation_score": user.reputation_score,
            "roles": user.roles,
            "is_banned": user.is_banned,
            "created_at": user.created_at,
            "updated_at": user.updated_at,
        }
    });

    Ok((StatusCode::OK, Json(response)))
}

/// Get user reputation history
pub async fn get_reputation(
    State(state): State<Arc<AppState>>,
    Extension(_user_ctx): Extension<UserContext>,
    Path(address): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    // Validate address format
    if address.len() != 42 || !address.starts_with("axiom1") {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidAddress,
        ));
    }

    // Get user from database
    let user = state
        .db
        .get_user(&address)
        .await?
        .ok_or(ServerError::Shared(
            axiom_community_shared::Error::InvalidAddress,
        ))?;

    info!("Retrieved reputation for {}", address);

    // For Phase 5, return basic reputation info
    let response = json!({
        "status": "ok",
        "data": {
            "address": user.address,
            "reputation_score": user.reputation_score,
            "role_count": user.roles.len(),
            "current_roles": user.roles,
        }
    });

    Ok((StatusCode::OK, Json(response)))
}
