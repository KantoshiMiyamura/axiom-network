//! Challenge management for authentication
//!
//! Supports both in-memory-only mode (for tests) and persistent mode
//! (write-through to PostgreSQL via `Database`).

use axiom_community_shared::crypto;
use axiom_community_shared::protocol::{AUTH_DOMAIN, CHALLENGE_EXPIRY_SECS};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

use crate::db::Database;

/// Challenge record
#[derive(Debug, Clone)]
pub struct Challenge {
    pub nonce: String,
    pub challenge: String,
    pub address: String,
    pub user_agent: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub used: bool,
}

/// Challenge manager — stores challenges in memory with optional DB persistence.
pub struct ChallengeManager {
    challenges: Arc<RwLock<HashMap<String, Challenge>>>,
    db: Option<Database>,
}

impl ChallengeManager {
    /// Create new challenge manager (in-memory only, for tests).
    pub fn new() -> Self {
        ChallengeManager {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            db: None,
        }
    }

    /// Create new challenge manager backed by a database.
    pub fn with_db(db: Database) -> Self {
        ChallengeManager {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            db: Some(db),
        }
    }

    /// Create new challenge
    pub async fn create_challenge(&self, address: &str, user_agent: &str) -> (String, String, i64) {
        let nonce = crypto::random_hex(32); // 32 bytes = 64 hex chars
        let now = current_timestamp();
        let expires_at = now + CHALLENGE_EXPIRY_SECS;

        let challenge =
            crypto::create_challenge_hex(nonce.as_bytes(), address, AUTH_DOMAIN, user_agent);

        let record = Challenge {
            nonce: nonce.clone(),
            challenge: challenge.clone(),
            address: address.to_string(),
            user_agent: user_agent.to_string(),
            created_at: now,
            expires_at,
            used: false,
        };

        // Store in memory
        self.challenges.write().await.insert(nonce.clone(), record);

        // Persist to DB if available
        if let Some(db) = &self.db {
            if let Err(e) = db
                .store_challenge(&nonce, &challenge, address, user_agent, now, expires_at)
                .await
            {
                tracing::warn!("Failed to persist challenge to DB: {}", e);
            }
        }

        debug!(
            "Created challenge for {} (expires in {}s)",
            address, CHALLENGE_EXPIRY_SECS
        );

        (nonce, challenge, expires_at)
    }

    /// Verify challenge exists, is not expired, and not already used.
    /// If a DB is available, consumes it atomically in the DB first.
    pub async fn verify_challenge(&self, nonce: &str) -> Result<Challenge, ChallengeError> {
        // Try DB-backed verification first (atomic consume)
        if let Some(db) = &self.db {
            match db.consume_challenge(nonce).await {
                Ok(Some(row)) => {
                    // Also mark used in memory cache
                    if let Some(record) = self.challenges.write().await.get_mut(nonce) {
                        record.used = true;
                    }

                    return Ok(Challenge {
                        nonce: row.nonce,
                        challenge: row.challenge_hash,
                        address: row.address,
                        user_agent: row.user_agent,
                        created_at: row.created_at,
                        expires_at: row.expires_at,
                        used: true,
                    });
                }
                Ok(None) => {
                    // Challenge not found, expired, or already used in DB
                    return Err(ChallengeError::NotFound);
                }
                Err(e) => {
                    tracing::warn!("DB challenge lookup failed, falling back to memory: {}", e);
                    // Fall through to in-memory path
                }
            }
        }

        // In-memory fallback
        let mut challenges = self.challenges.write().await;

        let challenge = challenges
            .get(nonce)
            .ok_or(ChallengeError::NotFound)?
            .clone();

        // Check not expired
        let now = current_timestamp();
        if challenge.expires_at < now {
            return Err(ChallengeError::Expired);
        }

        // Check not already used (replay attack prevention)
        if challenge.used {
            return Err(ChallengeError::AlreadyUsed);
        }

        // Mark as used
        if let Some(record) = challenges.get_mut(nonce) {
            record.used = true;
        }

        debug!("Verified challenge for {}", challenge.address);
        Ok(challenge)
    }

    /// Clean up expired challenges periodically
    pub async fn cleanup_expired(&self) {
        let now = current_timestamp();
        let mut challenges = self.challenges.write().await;

        let before = challenges.len();
        challenges.retain(|_, c| c.expires_at > now);
        let after = challenges.len();

        if before != after {
            debug!(
                "Cleaned up {} expired challenges from memory",
                before - after
            );
        }

        // Also clean DB
        if let Some(db) = &self.db {
            match db.cleanup_expired_challenges().await {
                Ok(n) if n > 0 => debug!("Cleaned up {} expired challenges from DB", n),
                Ok(_) => {}
                Err(e) => tracing::warn!("Failed to cleanup challenges from DB: {}", e),
            }
        }
    }
}

impl Default for ChallengeManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Challenge error types
#[derive(Debug, Clone)]
pub enum ChallengeError {
    NotFound,
    Expired,
    AlreadyUsed,
}

impl std::fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChallengeError::NotFound => write!(f, "Challenge not found"),
            ChallengeError::Expired => write!(f, "Challenge expired"),
            ChallengeError::AlreadyUsed => write!(f, "Challenge already used (replay attack)"),
        }
    }
}

/// Get current Unix timestamp
fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_challenge_creation_and_verification() {
        let manager = ChallengeManager::new();

        let (nonce, challenge, expires_at) =
            manager.create_challenge("axmtest123", "test-ua").await;

        assert!(!nonce.is_empty());
        assert!(!challenge.is_empty());
        assert!(expires_at > current_timestamp());

        // Verify challenge
        let verified = manager.verify_challenge(&nonce).await;
        assert!(verified.is_ok());

        // Try to use again (replay attack)
        let replayed = manager.verify_challenge(&nonce).await;
        assert!(matches!(replayed, Err(ChallengeError::AlreadyUsed)));
    }

    #[tokio::test]
    async fn test_invalid_challenge() {
        let manager = ChallengeManager::new();

        let result = manager.verify_challenge("invalid_nonce").await;
        assert!(matches!(result, Err(ChallengeError::NotFound)));
    }
}
