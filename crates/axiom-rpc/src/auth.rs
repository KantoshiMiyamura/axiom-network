// Copyright (c) 2026 Kantoshi Miyamura

//! Bearer-token authentication middleware.
//!
//! When no token is configured (`AuthConfig::open()`), all requests pass through —
//! preserves backward compatibility for devnet and local testing.

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::sync::Arc;
use subtle::ConstantTimeEq;

// ── AuthConfig ─────────────────────────────────────────────────────────────

/// `token = None` → open access; `token = Some(t)` → every request must carry `Authorization: Bearer t`.
#[derive(Clone, Debug)]
pub struct AuthConfig {
    pub(crate) token: Option<String>,
}

impl AuthConfig {
    /// Open access — no token required.
    pub fn open() -> Self {
        AuthConfig { token: None }
    }

    /// Require `Authorization: Bearer <token>` on every request.
    pub fn with_token(token: String) -> Self {
        AuthConfig { token: Some(token) }
    }

    /// Returns `true` if authentication is required.
    pub fn is_protected(&self) -> bool {
        self.token.is_some()
    }

    /// Returns `true` if no authentication is configured (open access).
    pub fn is_open(&self) -> bool {
        self.token.is_none()
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Constant-time byte-content equality — prevents timing-based token extraction.
///
/// Backed by `subtle::ConstantTimeEq` rather than a hand-rolled XOR fold so the
/// compiler is prevented (via `black_box`-style optimization barriers inside
/// the `subtle` crate) from reintroducing a short-circuit. The length check
/// below is NOT constant-time, but that is acceptable: the token's length is
/// not the secret; its bytes are. Every byte-level comparison that matters is
/// constant-time.
#[inline]
fn constant_time_eq(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

// ── Middleware ──────────────────────────────────────────────────────────────

/// Extract the bearer token from the `Authorization` header.
fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get("Authorization")?.to_str().ok()?;
    value.strip_prefix("Bearer ")
}

/// Axum middleware that enforces bearer-token authentication.
pub async fn auth_middleware(
    State(config): State<Arc<AuthConfig>>,
    request: Request,
    next: Next,
) -> Response {
    if let Some(expected) = &config.token {
        match extract_bearer(request.headers()) {
            Some(provided) if constant_time_eq(provided, expected.as_str()) => {
                // token matches — continue
            }
            Some(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "unauthorized: invalid token"})),
                )
                    .into_response();
            }
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "unauthorized: Authorization: Bearer <token> header required"})),
                )
                    .into_response();
            }
        }
    }

    next.run(request).await
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_config_not_protected() {
        assert!(!AuthConfig::open().is_protected());
    }

    #[test]
    fn token_config_is_protected() {
        assert!(AuthConfig::with_token("abc".into()).is_protected());
    }

    #[test]
    fn extract_bearer_present() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer my-secret".parse().unwrap());
        assert_eq!(extract_bearer(&headers), Some("my-secret"));
    }

    #[test]
    fn extract_bearer_absent() {
        let headers = HeaderMap::new();
        assert_eq!(extract_bearer(&headers), None);
    }

    #[test]
    fn extract_bearer_wrong_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Basic dXNlcjpwYXNz".parse().unwrap());
        assert_eq!(extract_bearer(&headers), None);
    }

    #[test]
    fn constant_time_eq_accepts_match() {
        assert!(constant_time_eq("secret-token", "secret-token"));
    }

    #[test]
    fn constant_time_eq_rejects_mismatch() {
        assert!(!constant_time_eq("secret-token", "secret-tokem"));
    }

    #[test]
    fn constant_time_eq_rejects_different_lengths() {
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(!constant_time_eq("abcd", "abc"));
    }

    #[test]
    fn constant_time_eq_empty_strings() {
        assert!(constant_time_eq("", ""));
        assert!(!constant_time_eq("", "a"));
    }
}
