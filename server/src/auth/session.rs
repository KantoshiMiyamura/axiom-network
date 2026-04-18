//! Session management

use crate::db::Database;
use crate::error::{Result, ServerError};
use axiom_community_shared::crypto;
use axiom_community_shared::models::SessionClaims;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

/// Session manager for CRUD operations
pub struct SessionManager {
    db: Database,
}

impl SessionManager {
    /// Create new session manager
    pub fn new(db: Database) -> Self {
        SessionManager { db }
    }

    /// Create new session
    pub async fn create_session(
        &self,
        address: &str,
        roles: Vec<String>,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<SessionClaims> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let now = current_timestamp();
        let expires_at = now + 900; // 15 minutes

        // Hash IP and user-agent for binding
        let ip_hash = crypto::hash_ip(ip_address).to_string();
        let user_agent_hash = crypto::hash_user_agent(user_agent).to_string();

        // Convert string roles to Role enum
        let role_enums: Vec<_> = roles
            .iter()
            .filter_map(|r| axiom_community_shared::models::Role::parse(r))
            .collect();

        // Hash tokens for storage (never store plaintext)
        let session_token_hash = crypto::sha256_hex(session_id.as_bytes());
        let refresh_token_hash = crypto::sha256_hex(format!("refresh_{}", session_id).as_bytes());

        // Store in database
        self.db
            .create_session(
                &session_id,
                address,
                &session_token_hash,
                &refresh_token_hash,
                expires_at,
                ip_address,
                user_agent,
            )
            .await?;

        debug!("Created session {} for user {}", session_id, address);

        // Return session claims
        Ok(SessionClaims {
            session_id,
            address: axiom_community_shared::models::Address::new(address),
            roles: role_enums,
            issued_at: now,
            expires_at,
            ip_hash,
            user_agent_hash,
        })
    }

    /// Validate session exists and is not expired/revoked
    pub async fn validate_session(
        &self,
        session_id: &str,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<()> {
        let session = self
            .db
            .get_session(session_id)
            .await?
            .ok_or(ServerError::Shared(
                axiom_community_shared::Error::SessionNotFound,
            ))?;

        // Check not revoked
        if session.revoked {
            warn!("Session {} is revoked", session_id);
            return Err(ServerError::Shared(
                axiom_community_shared::Error::SessionRevoked,
            ));
        }

        // Check not expired
        let now = current_timestamp();
        if session.expires_at < now {
            return Err(ServerError::Shared(
                axiom_community_shared::Error::SessionExpired,
            ));
        }

        // Verify IP and user-agent match (binding check)
        let _ip_hash = crypto::hash_ip(ip_address);
        let _ua_hash = crypto::hash_user_agent(user_agent);

        // Get stored hashes from database or compare directly
        // For now, just check IP matches exactly (Phase 2 simplification)
        if session.ip_address != ip_address {
            warn!(
                "IP mismatch for session {}: expected {}, got {}",
                session_id, session.ip_address, ip_address
            );
            return Err(ServerError::Shared(
                axiom_community_shared::Error::IPMismatch,
            ));
        }

        debug!("Validated session {}", session_id);
        Ok(())
    }

    /// Revoke session (logout)
    pub async fn revoke_session(&self, session_id: &str, reason: &str) -> Result<()> {
        self.db.revoke_session(session_id).await?;
        debug!("Revoked session {}: {}", session_id, reason);
        Ok(())
    }
}

/// Get current Unix timestamp
fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_creation() {
        // Note: This test requires a database connection
        // For Phase 2, we'd use a test database
        // Skipping for now since we need DB setup
    }
}
