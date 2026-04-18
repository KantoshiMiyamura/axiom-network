//! Server error types

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::fmt;

/// Server error type
#[derive(Debug)]
pub enum ServerError {
    /// Shared library error
    Shared(axiom_community_shared::Error),
    /// Database error
    Database(sqlx::Error),
    /// Configuration error
    Config(String),
    /// HTTP/request error
    Http(String),
    /// Internal server error
    Internal(String),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerError::Shared(e) => write!(f, "Shared error: {}", e),
            ServerError::Database(e) => write!(f, "Database error: {}", e),
            ServerError::Config(e) => write!(f, "Config error: {}", e),
            ServerError::Http(e) => write!(f, "HTTP error: {}", e),
            ServerError::Internal(e) => write!(f, "Internal error: {}", e),
        }
    }
}

impl std::error::Error for ServerError {}

impl From<axiom_community_shared::Error> for ServerError {
    fn from(err: axiom_community_shared::Error) -> Self {
        ServerError::Shared(err)
    }
}

impl From<sqlx::Error> for ServerError {
    fn from(err: sqlx::Error) -> Self {
        ServerError::Database(err)
    }
}

impl From<anyhow::Error> for ServerError {
    fn from(err: anyhow::Error) -> Self {
        ServerError::Internal(err.to_string())
    }
}

impl From<serde_json::Error> for ServerError {
    fn from(err: serde_json::Error) -> Self {
        ServerError::Http(format!("JSON error: {}", err))
    }
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match &self {
            ServerError::Shared(e) => {
                if e.is_auth_error() {
                    (
                        StatusCode::UNAUTHORIZED,
                        "AUTH_ERROR",
                        e.to_string(),
                    )
                } else if e.is_authz_error() {
                    (
                        StatusCode::FORBIDDEN,
                        "AUTHZ_ERROR",
                        e.to_string(),
                    )
                } else if e.is_rate_limited() {
                    (
                        StatusCode::TOO_MANY_REQUESTS,
                        "RATE_LIMITED",
                        e.to_string(),
                    )
                } else {
                    (
                        StatusCode::BAD_REQUEST,
                        "INVALID_REQUEST",
                        e.to_string(),
                    )
                }
            }
            ServerError::Database(_) => {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DATABASE_ERROR",
                    "An internal database error occurred".to_string(),
                )
            }
            ServerError::Config(_) => {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "CONFIG_ERROR",
                    "Server configuration error".to_string(),
                )
            }
            ServerError::Http(msg) => {
                (
                    StatusCode::BAD_REQUEST,
                    "HTTP_ERROR",
                    msg.clone(),
                )
            }
            ServerError::Internal(_) => {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "An internal server error occurred".to_string(),
                )
            }
        };

        let body = Json(json!({
            "status": "error",
            "code": error_code,
            "message": message,
        }));

        (status, body).into_response()
    }
}

pub type Result<T> = std::result::Result<T, ServerError>;
