//! Health check endpoint

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::json;
use std::sync::Arc;

use crate::state::AppState;

/// Health check endpoint
pub async fn health_check(
    State(state): State<Arc<AppState>>,
) -> Result<(StatusCode, Json<serde_json::Value>), StatusCode> {
    // Check database connectivity
    match state.db.health_check().await {
        Ok(_) => {
            let response = json!({
                "status": "ok",
                "timestamp": chrono::Utc::now().timestamp(),
                "version": env!("CARGO_PKG_VERSION"),
            });
            Ok((StatusCode::OK, Json(response)))
        }
        Err(_) => {
            let _body = json!({
                "status": "error",
                "message": "Database health check failed",
            });
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}
