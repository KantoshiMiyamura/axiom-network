//! Application state shared across handlers

use crate::auth::{ChallengeManager, SessionManager, TokenManager};
use crate::config::Config;
use crate::db::Database;
use crate::middleware::security::{
    GlobalRateLimiter, IpBanManager, PerIpRateLimiter, SignatureNonceTracker,
};
use crate::rate_limit::RateLimitManager;

/// Application state shared with all handlers.
///
/// All security stores (IP bans, signature replay, rate limiting, JWT revocation)
/// are backed by PostgreSQL for multi-instance consistency.
pub struct AppState {
    /// Database connection pool
    pub db: Database,
    /// Server configuration
    pub config: Config,
    /// JWT token manager
    pub token_manager: TokenManager,
    /// Session manager
    pub session_manager: SessionManager,
    /// Challenge manager
    pub challenge_manager: ChallengeManager,
    /// Per-user/per-session rate limiter (local fast-path)
    pub rate_limiter: RateLimitManager,
    /// IP ban manager (DB-backed, local cache with short TTL)
    pub ip_ban_manager: IpBanManager,
    /// Global rate limiter (DB-backed, shared across instances)
    pub global_rate_limiter: GlobalRateLimiter,
    /// Per-IP rate limiter (DB-backed, shared across instances)
    pub per_ip_rate_limiter: PerIpRateLimiter,
    /// Signature replay protection (DB-backed, shared across instances)
    pub signature_nonce_tracker: SignatureNonceTracker,
}

impl AppState {
    /// Create new application state. All security stores use the shared database.
    pub fn new(db: Database, config: Config) -> anyhow::Result<Self> {
        let token_manager = TokenManager::new(&config)?;
        let session_manager = SessionManager::new(db.clone());
        let challenge_manager = ChallengeManager::new();
        let rate_limiter = RateLimitManager::new();

        // DB-backed security stores — shared across all instances
        let ip_ban_manager = IpBanManager::new(db.clone());
        let global_rate_limiter = GlobalRateLimiter::new(db.clone(), 1000);
        let per_ip_rate_limiter = PerIpRateLimiter::new(db.clone(), 120);
        let signature_nonce_tracker = SignatureNonceTracker::new(db.clone(), 3600);

        Ok(AppState {
            db,
            config,
            token_manager,
            session_manager,
            challenge_manager,
            rate_limiter,
            ip_ban_manager,
            global_rate_limiter,
            per_ip_rate_limiter,
            signature_nonce_tracker,
        })
    }

    /// Revoke a JWT by its session ID.
    /// Writes to the sessions table — visible to all instances immediately.
    pub async fn revoke_token(&self, session_id: &str) {
        let _ = self.db.revoke_session(session_id).await;
    }

    /// Check if a JWT session ID has been revoked.
    /// Reads from the sessions table — consistent across all instances.
    pub async fn is_token_revoked(&self, session_id: &str) -> bool {
        self.db.is_session_revoked(session_id).await.unwrap_or(true) // fail closed
    }

    /// Revoke all active sessions for a user (e.g., on ban).
    /// Affects all instances immediately via shared DB.
    pub async fn revoke_all_tokens_for_address(&self, address: &str) {
        let _ = self.db.revoke_all_sessions_for_address(address).await;
    }
}
