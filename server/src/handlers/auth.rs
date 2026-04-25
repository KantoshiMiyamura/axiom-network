//! Authentication handlers
//! - Challenge request
//! - Signature verification
//! - Token refresh
//! - Logout

use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

use crate::error::Result;
use crate::state::AppState;
use axiom_community_shared::models::{ChallengeRequest, ChallengeResponse, VerifyRequest};

/// Request a new authentication challenge
pub async fn request_challenge(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<ChallengeRequest>,
) -> Result<(StatusCode, Json<ChallengeResponse>)> {
    // Validate address format
    if !req.address.is_valid() {
        return Err(crate::error::ServerError::Shared(
            axiom_community_shared::Error::InvalidAddress,
        ));
    }

    // Create challenge
    let (nonce, challenge, expires_at) = state
        .challenge_manager
        .create_challenge(req.address.as_str(), &req.user_agent)
        .await;

    // Log audit
    let _ = state
        .db
        .log_audit(
            Some(req.address.as_str()),
            "auth_challenge_requested",
            "success",
            Some(&addr.ip().to_string()),
            Some(&req.user_agent),
        )
        .await;

    info!("Challenge requested for {} from {}", req.address, addr.ip());

    let response = ChallengeResponse {
        nonce,
        challenge,
        expires_at,
        domain: "axiom.community.v1".to_string(),
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Verify signature and create session
pub async fn verify_signature(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<VerifyRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    // Validate address
    if !req.address.is_valid() {
        return Err(crate::error::ServerError::Shared(
            axiom_community_shared::Error::InvalidAddress,
        ));
    }

    // Verify challenge exists and is valid
    let challenge = state
        .challenge_manager
        .verify_challenge(&req.nonce)
        .await
        .map_err(|e| match e {
            crate::auth::challenge::ChallengeError::NotFound => {
                crate::error::ServerError::Shared(axiom_community_shared::Error::ChallengeNotFound)
            }
            crate::auth::challenge::ChallengeError::Expired => {
                crate::error::ServerError::Shared(axiom_community_shared::Error::ChallengeExpired)
            }
            crate::auth::challenge::ChallengeError::AlreadyUsed => {
                crate::error::ServerError::Shared(
                    axiom_community_shared::Error::ChallengeAlreadyUsed,
                )
            }
        })?;

    // Verify challenge matches
    if challenge.challenge != req.challenge {
        let _ = state
            .db
            .log_audit(
                Some(req.address.as_str()),
                "auth_verify_failed",
                "failure",
                Some(&addr.ip().to_string()),
                Some(&req.user_agent),
            )
            .await;

        return Err(crate::error::ServerError::Shared(
            axiom_community_shared::Error::InvalidChallenge,
        ));
    }

    // Verify ML-DSA-87 signature (FIPS 204, Category 5 — post-quantum)
    let public_key_bytes = hex::decode(&req.public_key).map_err(|_| {
        crate::error::ServerError::Shared(axiom_community_shared::Error::InvalidSignature)
    })?;
    let signature_bytes = hex::decode(&req.signature).map_err(|_| {
        crate::error::ServerError::Shared(axiom_community_shared::Error::InvalidSignature)
    })?;

    // Reconstruct the challenge message that should have been signed.
    // Domain separation: prefix with "axiom-community-auth:" to prevent cross-protocol replay.
    // A signature valid for community auth cannot be replayed against the RPC or on-chain layer.
    let challenge_message = format!(
        "axiom-community-auth:{}|{}|{}|{}",
        req.nonce, req.challenge, "axiom.community.v1", req.expires_at
    );

    let sig_valid = axiom_community_shared::crypto::verify_ml_dsa_87(
        &public_key_bytes,
        challenge_message.as_bytes(),
        &signature_bytes,
    )
    .map_err(|_| {
        crate::error::ServerError::Shared(axiom_community_shared::Error::InvalidSignature)
    })?;

    if !sig_valid {
        // Record auth failure for IP auto-ban
        state.ip_ban_manager.record_auth_failure(addr.ip()).await;

        let _ = state
            .db
            .log_audit(
                Some(req.address.as_str()),
                "auth_verify_invalid_signature",
                "failure",
                Some(&addr.ip().to_string()),
                Some(&req.user_agent),
            )
            .await;

        return Err(crate::error::ServerError::Shared(
            axiom_community_shared::Error::InvalidSignature,
        ));
    }

    // Successful signature — reset auth failure counter
    state.ip_ban_manager.reset_auth_failures(&addr.ip()).await;

    // Public key binding: on first auth, store the key. On subsequent, verify it matches.
    let stored_pk = state
        .db
        .get_public_key(req.address.as_str())
        .await
        .map_err(|e| {
            crate::error::ServerError::Shared(axiom_community_shared::Error::DatabaseError(
                e.to_string(),
            ))
        })?;

    match stored_pk {
        Some(ref existing_pk) => {
            // Subsequent auth: verify submitted key matches stored key
            if existing_pk != &req.public_key {
                let _ = state
                    .db
                    .log_audit(
                        Some(req.address.as_str()),
                        "auth_verify_key_mismatch",
                        "failure",
                        Some(&addr.ip().to_string()),
                        Some(&req.user_agent),
                    )
                    .await;

                return Err(crate::error::ServerError::Shared(
                    axiom_community_shared::Error::InvalidSignature,
                ));
            }
        }
        None => {
            // First auth: bind the public key to this address
            let _ = state
                .db
                .store_public_key(req.address.as_str(), &req.public_key)
                .await;
        }
    }

    // Ensure user exists (auto-register on first authentication)
    let _ = state.db.create_or_get_user(req.address.as_str()).await;

    let user =
        state
            .db
            .get_user(req.address.as_str())
            .await?
            .ok_or(crate::error::ServerError::Shared(
                axiom_community_shared::Error::InvalidAddress,
            ))?;

    // Check if user is banned
    if user.is_banned {
        let _ = state
            .db
            .log_audit(
                Some(req.address.as_str()),
                "auth_verify_banned_user",
                "failure",
                Some(&addr.ip().to_string()),
                Some(&req.user_agent),
            )
            .await;

        return Err(crate::error::ServerError::Shared(
            axiom_community_shared::Error::UserBanned,
        ));
    }

    // Create session
    let session_claims = state
        .session_manager
        .create_session(
            req.address.as_str(),
            user.roles,
            &addr.ip().to_string(),
            &req.user_agent,
        )
        .await?;

    // Generate JWT token
    let session_token = state.token_manager.generate_token(session_claims.clone())?;
    let refresh_token = format!("refresh_{}", session_claims.session_id);

    // Log audit
    let _ = state
        .db
        .log_audit(
            Some(req.address.as_str()),
            "auth_verify_success",
            "success",
            Some(&addr.ip().to_string()),
            Some(&req.user_agent),
        )
        .await;

    info!("User {} authenticated successfully", req.address);

    let response = json!({
        "status": "ok",
        "session_id": session_claims.session_id,
        "session_token": session_token,
        "refresh_token": refresh_token,
        "expires_at": session_claims.expires_at,
        "user": {
            "address": session_claims.address.to_string(),
            "roles": session_claims.roles.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
            "reputation_score": user.reputation_score,
        }
    });

    Ok((StatusCode::CREATED, Json(response)))
}

/// Refresh authentication token
///
/// Implements refresh token rotation: each refresh token can only be used once.
/// If a previously-used refresh token is submitted, the entire session is revoked
/// (indicates potential token theft).
pub async fn refresh_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    // Hash the submitted refresh token
    let refresh_hash = axiom_community_shared::crypto::sha256_hex(req.refresh_token.as_bytes());

    // Look up the session
    let session = state
        .db
        .get_session(&req.session_id)
        .await
        .map_err(|e| {
            crate::error::ServerError::Shared(axiom_community_shared::Error::DatabaseError(
                e.to_string(),
            ))
        })?
        .ok_or(crate::error::ServerError::Shared(
            axiom_community_shared::Error::Unauthorized {
                required: "Session not found".to_string(),
            },
        ))?;

    // Check if session is revoked
    if session.revoked {
        return Err(crate::error::ServerError::Shared(
            axiom_community_shared::Error::Unauthorized {
                required: "Session revoked".to_string(),
            },
        ));
    }

    // Check if refresh token matches (token rotation check)
    if session.refresh_token_hash != refresh_hash {
        // Token mismatch — possible token theft. Revoke the entire session.
        let _ = state.db.revoke_session(&req.session_id).await;
        let _ = state
            .db
            .log_audit(
                Some(&session.address),
                "auth_refresh_token_reuse_detected",
                "failure",
                None,
                None,
            )
            .await;

        return Err(crate::error::ServerError::Shared(
            axiom_community_shared::Error::Unauthorized {
                required: "Refresh token invalid — session revoked for security".to_string(),
            },
        ));
    }

    // Check refresh window (7 days from session creation)
    let now = chrono::Utc::now().timestamp();
    let refresh_window =
        session.created_at + axiom_community_shared::protocol::REFRESH_TOKEN_EXPIRY_SECS;
    if now > refresh_window {
        return Err(crate::error::ServerError::Shared(
            axiom_community_shared::Error::Unauthorized {
                required: "Refresh token expired".to_string(),
            },
        ));
    }

    // Generate new tokens
    let new_session_claims = state
        .session_manager
        .create_session(
            &session.address,
            state
                .db
                .get_user(&session.address)
                .await
                .map_err(|e| {
                    crate::error::ServerError::Shared(axiom_community_shared::Error::DatabaseError(
                        e.to_string(),
                    ))
                })?
                .ok_or(crate::error::ServerError::Shared(
                    axiom_community_shared::Error::InvalidAddress,
                ))?
                .roles,
            &session.ip_address,
            &session.user_agent,
        )
        .await?;

    let new_session_token = state
        .token_manager
        .generate_token(new_session_claims.clone())?;
    let new_refresh_token = axiom_community_shared::crypto::random_hex(32);
    let new_refresh_hash = axiom_community_shared::crypto::sha256_hex(new_refresh_token.as_bytes());
    let new_token_hash = axiom_community_shared::crypto::sha256_hex(new_session_token.as_bytes());

    // Rotate: update the session in DB with new hashes
    let _ = state
        .db
        .rotate_refresh_token(
            &req.session_id,
            &new_refresh_hash,
            &new_token_hash,
            new_session_claims.expires_at,
        )
        .await;

    let _ = state
        .db
        .log_audit(
            Some(&session.address),
            "auth_refresh_success",
            "success",
            None,
            None,
        )
        .await;

    let response = json!({
        "status": "ok",
        "session_id": req.session_id,
        "session_token": new_session_token,
        "refresh_token": new_refresh_token,
        "expires_at": new_session_claims.expires_at,
    });

    Ok((StatusCode::OK, Json(response)))
}

/// Logout and revoke session
pub async fn logout(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LogoutRequest>,
) -> Result<StatusCode> {
    // Revoke the session in database
    state
        .session_manager
        .revoke_session(&req.session_id, "user_logout")
        .await?;

    // Immediately blacklist the JWT so it cannot be used until natural expiry
    state.revoke_token(&req.session_id).await;

    info!("Session revoked: {}", req.session_id);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
    pub session_id: String,
}

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub session_id: String,
}
