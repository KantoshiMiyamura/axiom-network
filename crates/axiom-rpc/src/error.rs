// Copyright (c) 2026 Kantoshi Miyamura

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

pub type Result<T> = std::result::Result<T, RpcError>;

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Block not found: {0}")]
    BlockNotFound(String),

    #[error("Transaction rejected: {0}")]
    TransactionRejected(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Forbidden")]
    Forbidden,
}

impl IntoResponse for RpcError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            RpcError::InvalidRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            RpcError::BlockNotFound(msg) => (StatusCode::NOT_FOUND, msg),
            RpcError::TransactionRejected(msg) => (StatusCode::BAD_REQUEST, msg),
            RpcError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            RpcError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            RpcError::Forbidden => (StatusCode::FORBIDDEN, "Forbidden: localhost only".to_string()),
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}
