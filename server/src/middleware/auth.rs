//! Authentication middleware for extracting and validating user context

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::state::AppState;

/// User context extracted from authentication
#[derive(Debug, Clone)]
pub struct UserContext {
    pub address: String,
    pub roles: Vec<String>,
    pub is_banned: bool,
}

/// Extract Bearer token from Authorization header
fn extract_token(headers: &HeaderMap) -> Option<String> {
    let auth_header = headers.get("Authorization")?.to_str().ok()?;
    auth_header.strip_prefix("Bearer ").map(|s| s.to_string())
}

/// Middleware to validate authentication and ban status
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let headers = request.headers();

    // Extract token from Authorization header
    let token = match extract_token(headers) {
        Some(token) => token,
        None => {
            debug!("Missing Authorization header");
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "Unauthorized",
                    "details": "Missing or invalid Authorization header"
                })),
            )
                .into_response();
        }
    };

    // Validate and decode JWT token
    let token_payload = match state.token_manager.validate_token(&token) {
        Ok(payload) => payload,
        Err(e) => {
            warn!("Invalid token: {}", e);
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "Unauthorized",
                    "details": "Invalid or expired token"
                })),
            )
                .into_response();
        }
    };

    // Check JWT revocation (blacklist)
    if state
        .is_token_revoked(&token_payload.claims.session_id)
        .await
    {
        warn!(
            "Revoked token used: session {}",
            token_payload.claims.session_id
        );
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Unauthorized",
                "details": "Token has been revoked"
            })),
        )
            .into_response();
    }

    let address = token_payload.claims.address.to_string();
    let roles: Vec<String> = token_payload
        .claims
        .roles
        .iter()
        .map(|r| match r {
            axiom_community_shared::Role::Member => "member".to_string(),
            axiom_community_shared::Role::Worker => "worker".to_string(),
            axiom_community_shared::Role::Verifier => "verifier".to_string(),
            axiom_community_shared::Role::Moderator => "moderator".to_string(),
            axiom_community_shared::Role::CoreDev => "core_dev".to_string(),
        })
        .collect();

    // Check user ban status from database
    let is_banned = match state.db.get_user(&address).await {
        Ok(Some(user)) => user.is_banned,
        Ok(None) => {
            warn!("User not found in database: {}", address);
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "Unauthorized",
                    "details": "User not found"
                })),
            )
                .into_response();
        }
        Err(e) => {
            warn!("Database error checking user: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Internal Server Error",
                    "details": "Failed to check user status"
                })),
            )
                .into_response();
        }
    };

    // If user is banned, deny access
    if is_banned {
        warn!("Banned user attempted access: {}", address);
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "Forbidden",
                "details": "User account is banned"
            })),
        )
            .into_response();
    }

    // Create user context and insert into request extensions
    let user_context = UserContext {
        address: address.clone(),
        roles,
        is_banned,
    };

    request.extensions_mut().insert(user_context);

    debug!("User authenticated: {}", address);

    // Pass to next middleware
    next.run(request).await
}
