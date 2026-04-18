//! Message posting and retrieval handlers

use axum::extract::{State, Path, Query, ConnectInfo, Extension};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

use axiom_community_shared::crypto;
use crate::state::AppState;
use crate::error::{Result, ServerError};
use crate::middleware::auth::UserContext;

/// List messages in a channel
pub async fn list_messages(
    State(state): State<Arc<AppState>>,
    Extension(_user_ctx): Extension<UserContext>,
    Path(channel): Path<String>,
    Query(params): Query<ListParams>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    // Validate channel name
    if channel.is_empty() || channel.len() > 100 {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidChannel,
        ));
    }

    let limit = params.limit.unwrap_or(50).min(100) as i64; // Max 100
    let offset = params.offset.unwrap_or(0) as i64;

    // Query database
    let messages = state.db.list_messages(&channel, limit, offset).await?;

    let message_list: Vec<serde_json::Value> = messages
        .iter()
        .map(|msg| {
            json!({
                "id": msg.id,
                "channel": msg.channel,
                "author": msg.author,
                "content": msg.content,
                "content_hash": msg.content_hash,
                "timestamp": msg.timestamp,
                "is_edited": msg.is_edited,
            })
        })
        .collect();

    info!(
        "Listed {} messages in channel '{}'",
        message_list.len(),
        channel
    );

    let response = json!({
        "status": "ok",
        "data": {
            "messages": message_list,
            "total": message_list.len(),
        }
    });

    Ok((StatusCode::OK, Json(response)))
}

/// Post new message to channel
pub async fn post_message(
    State(state): State<Arc<AppState>>,
    Path(channel): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(user_ctx): Extension<UserContext>,
    Json(req): Json<PostMessageRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    // Validate channel
    if channel.is_empty() || channel.len() > 100 {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidChannel,
        ));
    }

    // Validate message content length
    if req.content.is_empty() || req.content.len() > 10_000 {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::MessageTooLong,
        ));
    }

    // Check rate limit per user
    if !state.rate_limiter.check_message(&user_ctx.address).await {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::RateLimitExceeded,
        ));
    }

    // Replay protection: reject if this signature was already used
    if !state.signature_nonce_tracker.check_and_record(&req.signature, &user_ctx.address, "message_posted").await {
        return Err(ServerError::Shared(
            axiom_community_shared::Error::InvalidSignature,
        ));
    }

    // Create message
    let msg_id = format!("msg:{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().timestamp();
    let content_hash = crypto::sha3_256_hex(req.content.as_bytes());

    state
        .db
        .create_message(
            &msg_id,
            &channel,
            &user_ctx.address,
            &req.content,
            &content_hash,
            req.parent_id.as_deref(),
            now,
            &req.signature,
        )
        .await?;

    // Log audit
    let _ = state
        .db
        .log_audit(
            Some(&user_ctx.address),
            "message_posted",
            "success",
            Some(&addr.ip().to_string()),
            None,
        )
        .await;

    info!("Message posted to channel '{}' with ID {}", channel, msg_id);

    let response = json!({
        "status": "ok",
        "data": {
            "id": msg_id,
            "timestamp": now,
            "content_hash": content_hash,
        }
    });

    Ok((StatusCode::CREATED, Json(response)))
}

/// Get specific message
pub async fn get_message(
    State(state): State<Arc<AppState>>,
    Extension(_user_ctx): Extension<UserContext>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    let message = state
        .db
        .get_message(&id)
        .await?
        .ok_or(ServerError::Shared(
            axiom_community_shared::Error::InternalError(format!("Message not found: {}", id)),
        ))?;

    let response = json!({
        "status": "ok",
        "data": {
            "id": message.id,
            "channel": message.channel,
            "author": message.author,
            "content": message.content,
            "content_hash": message.content_hash,
            "timestamp": message.timestamp,
            "is_edited": message.is_edited,
        }
    });

    Ok((StatusCode::OK, Json(response)))
}

#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct PostMessageRequest {
    pub content: String,
    pub signature: String,
    pub parent_id: Option<String>,
}
