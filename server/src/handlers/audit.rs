//! Audit log handlers (CoreDev role required)

use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tracing::info;

use crate::error::Result;
use crate::middleware::auth::UserContext;
use crate::permissions;
use crate::state::AppState;

/// List audit logs
pub async fn list_audit_logs(
    State(state): State<Arc<AppState>>,
    Extension(user_ctx): Extension<UserContext>,
    Query(params): Query<ListAuditParams>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    // Enforce CoreDev role (defense-in-depth — middleware also checks)
    permissions::check_can_view_audit(&user_ctx.roles)?;

    let limit = params.limit.unwrap_or(100).min(500) as i64;
    let offset = params.offset.unwrap_or(0) as i64;

    // Query database (address, action, timestamp filters handled by DB if implemented)
    let logs = state.db.list_audit_logs(limit, offset).await?;

    let log_list: Vec<serde_json::Value> = logs
        .iter()
        .map(|log| {
            json!({
                "timestamp": log.timestamp,
                "address": log.address,
                "action": log.action,
                "status": log.status,
                "ip_address": log.ip_address,
            })
        })
        .collect();

    info!("Listed {} audit logs", log_list.len());

    let response = json!({
        "status": "ok",
        "data": {
            "logs": log_list,
            "total": log_list.len(),
        }
    });

    Ok((StatusCode::OK, Json(response)))
}

#[derive(Debug, Deserialize)]
pub struct ListAuditParams {
    pub address: Option<String>,
    pub action: Option<String>,
    pub from_timestamp: Option<i64>,
    pub to_timestamp: Option<i64>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}
