//! Role management handlers (CoreDev role required)

use axum::extract::{State, Path, ConnectInfo, Extension};
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

/// Grant role to user
pub async fn grant_role(
    State(state): State<Arc<AppState>>,
    Path((address, role)): Path<(String, String)>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user_ctx): Extension<UserContext>,
    Json(_req): Json<RoleActionRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    // Enforce CoreDev role (defense-in-depth — middleware also checks)
    permissions::check_can_manage_roles(&user_ctx.roles)?;

    // Validate address format
    if address.len() != 42 || !address.starts_with("axiom1") {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidAddress,
        ));
    }

    // Validate role
    if permissions::Role::from_string(&role).is_none() {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidRole,
        ));
    }

    // Get user
    let mut user = state
        .db
        .get_user(&address)
        .await?
        .ok_or(ServerError::Shared(
            axiom_community_shared::Error::InvalidAddress,
        ))?;

    // Add role if not already present
    if !user.roles.contains(&role) {
        user.roles.push(role.clone());
        state.db.update_user_roles(&address, user.roles).await?;
    }

    // Log audit
    let _ = state
        .db
        .log_audit(
            Some(&user_ctx.address),
            &format!("grant_role_{}", role),
            "success",
            Some(&addr.ip().to_string()),
            None,
        )
        .await;

    info!("Granted role {} to {}", role, address);

    let response = json!({
        "status": "ok",
        "data": {
            "address": address,
            "role": role,
        }
    });

    Ok((StatusCode::OK, Json(response)))
}

/// Revoke role from user
pub async fn revoke_role(
    State(state): State<Arc<AppState>>,
    Path((address, role)): Path<(String, String)>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user_ctx): Extension<UserContext>,
    Json(_req): Json<RoleActionRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    // Enforce CoreDev role (defense-in-depth — middleware also checks)
    permissions::check_can_manage_roles(&user_ctx.roles)?;

    // Validate address format
    if address.len() != 42 || !address.starts_with("axiom1") {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidAddress,
        ));
    }

    // Validate role
    if permissions::Role::from_string(&role).is_none() {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidRole,
        ));
    }

    // Get user
    let mut user = state
        .db
        .get_user(&address)
        .await?
        .ok_or(ServerError::Shared(
            axiom_community_shared::Error::InvalidAddress,
        ))?;

    // Remove role if present
    user.roles.retain(|r| r != &role);
    // Ensure member role remains
    if user.roles.is_empty() {
        user.roles.push("member".to_string());
    }
    state.db.update_user_roles(&address, user.roles).await?;

    // Log audit
    let _ = state
        .db
        .log_audit(
            Some(&user_ctx.address),
            &format!("revoke_role_{}", role),
            "success",
            Some(&addr.ip().to_string()),
            None,
        )
        .await;

    info!("Revoked role {} from {}", role, address);

    let response = json!({
        "status": "ok",
        "data": {
            "address": address,
            "role": role,
        }
    });

    Ok((StatusCode::OK, Json(response)))
}

/// Ban user
pub async fn ban_user(
    State(state): State<Arc<AppState>>,
    Path(address): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user_ctx): Extension<UserContext>,
    Json(req): Json<BanUserRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    // Enforce CoreDev role (defense-in-depth — middleware also checks)
    permissions::check_can_ban_user(&user_ctx.roles)?;

    // Validate address format
    if address.len() != 42 || !address.starts_with("axiom1") {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidAddress,
        ));
    }

    // Validate reason
    if req.reason.is_empty() || req.reason.len() > 500 {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidMessage,
        ));
    }

    // Get user to verify exists
    let _user = state
        .db
        .get_user(&address)
        .await?
        .ok_or(ServerError::Shared(
            axiom_community_shared::Error::InvalidAddress,
        ))?;

    // Ban user
    state.db.ban_user(&address, &req.reason).await?;

    // Revoke ALL active sessions for this user across all instances.
    // The auth middleware checks session revocation in DB on every request.
    state.revoke_all_tokens_for_address(&address).await;

    // Log audit
    let _ = state
        .db
        .log_audit(
            Some(&user_ctx.address),
            "user_banned",
            "success",
            Some(&addr.ip().to_string()),
            None,
        )
        .await;

    info!("Banned user {}: {}", address, req.reason);

    let response = json!({
        "status": "ok",
        "data": {
            "address": address,
            "banned": true,
        }
    });

    Ok((StatusCode::OK, Json(response)))
}

/// Unban user
pub async fn unban_user(
    State(state): State<Arc<AppState>>,
    Path(address): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user_ctx): Extension<UserContext>,
    Json(_req): Json<UnbanUserRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    // Enforce CoreDev role (defense-in-depth — middleware also checks)
    permissions::check_can_ban_user(&user_ctx.roles)?;

    // Validate address format
    if address.len() != 42 || !address.starts_with("axiom1") {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidAddress,
        ));
    }

    // Get user to verify exists
    let _user = state
        .db
        .get_user(&address)
        .await?
        .ok_or(ServerError::Shared(
            axiom_community_shared::Error::InvalidAddress,
        ))?;

    // Unban user
    state.db.unban_user(&address).await?;

    // Log audit
    let _ = state
        .db
        .log_audit(
            Some(&user_ctx.address),
            "user_unbanned",
            "success",
            Some(&addr.ip().to_string()),
            None,
        )
        .await;

    info!("Unbanned user {}", address);

    let response = json!({
        "status": "ok",
        "data": {
            "address": address,
            "banned": false,
        }
    });

    Ok((StatusCode::OK, Json(response)))
}

#[derive(Debug, Deserialize)]
pub struct RoleActionRequest {
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BanUserRequest {
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct UnbanUserRequest {
    pub reason: Option<String>,
}
