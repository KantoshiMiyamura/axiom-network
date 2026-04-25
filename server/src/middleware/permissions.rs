//! Permission enforcement middleware and helpers

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use tracing::{info, warn};

use crate::middleware::auth::UserContext;
use crate::permissions;

/// Check if endpoint requires specific permission (with path parameter matching)
pub fn requires_permission(path: &str, method: &str) -> Option<permissions::Role> {
    // Normalize path by replacing path parameters with placeholders
    let normalized = normalize_path(path);

    match (method, normalized.as_str()) {
        // Public endpoints (no auth required)
        ("POST", "/auth/challenge")
        | ("POST", "/auth/verify")
        | ("GET", "/health") => None,

        // Member-level endpoints (auth)
        ("POST", "/auth/refresh")
        | ("POST", "/auth/logout")
        // Member-level endpoints (content)
        | ("GET", "/channels/*/messages")
        | ("POST", "/channels/*/messages")
        | ("GET", "/messages/*")
        | ("GET", "/users/*")
        | ("GET", "/users/*/reputation") => Some(permissions::Role::Member),

        // Worker-level endpoints
        ("GET", "/jobs")
        | ("POST", "/jobs")
        | ("GET", "/jobs/*")
        | ("POST", "/jobs/*/results") => Some(permissions::Role::Worker),

        // Verifier-level endpoints
        ("GET", "/disputes")
        | ("POST", "/disputes")
        | ("GET", "/disputes/*") => Some(permissions::Role::Verifier),

        // Moderator-level endpoints
        ("POST", "/moderation/actions")
        | ("GET", "/moderation/actions") => Some(permissions::Role::Moderator),

        // CoreDev-level endpoints
        ("GET", "/audit/logs")
        | ("POST", "/roles/*/grant/*")
        | ("POST", "/roles/*/revoke/*")
        | ("POST", "/roles/*/ban")
        | ("POST", "/roles/*/unban") => Some(permissions::Role::CoreDev),

        // Default-deny: unmapped routes require Member at minimum
        _ => Some(permissions::Role::Member),
    }
}

/// Normalize path by replacing path parameters (e.g., :id, :address) with wildcard
fn normalize_path(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    parts
        .into_iter()
        .map(|part| {
            if part.starts_with(':') || part.is_empty() && path != "/" {
                "*"
            } else if part.is_empty() {
                ""
            } else {
                part
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Permission enforcement middleware
pub async fn permission_middleware(request: Request, next: Next) -> Response {
    let path = request.uri().path();
    let method = request.method().as_str();

    // Check if this endpoint requires permission
    let required_role = requires_permission(path, method);

    // If endpoint is public, pass through
    if required_role.is_none() {
        info!("Public endpoint accessed: {} {}", method, path);
        return next.run(request).await;
    }

    let required_role = required_role.unwrap();

    // Extract user context from request extensions
    let user_context = match request.extensions().get::<UserContext>() {
        Some(ctx) => ctx.clone(),
        None => {
            warn!(
                "Missing user context for protected endpoint: {} {}",
                method, path
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "Unauthorized",
                    "details": "User context not found"
                })),
            )
                .into_response();
        }
    };

    // Validate permission level
    if !permissions::has_role(&user_context.roles, required_role.clone()) {
        warn!(
            "Permission denied for {} on {} {}: required {}, has roles: {:?}",
            user_context.address,
            method,
            path,
            required_role.as_str(),
            user_context.roles
        );

        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "Forbidden",
                "details": format!("Insufficient permissions. Required role: {}", required_role.as_str())
            })),
        )
            .into_response();
    }

    info!(
        "Permission granted for {} on {} {} (role: {})",
        user_context.address,
        method,
        path,
        required_role.as_str()
    );

    // Pass to next middleware
    next.run(request).await
}
