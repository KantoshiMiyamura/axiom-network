//! Protocol definitions and constants for Axiom Community Platform

// ============================================================================
// Protocol Constants
// ============================================================================

/// Current protocol version
pub const PROTOCOL_VERSION: &str = "1.0.0";

/// Authentication domain (prevents cross-site token usage)
pub const AUTH_DOMAIN: &str = "axiom.community.v1";

/// Challenge expiry time (seconds)
pub const CHALLENGE_EXPIRY_SECS: i64 = 300; // 5 minutes

/// Session token expiry time (seconds)
pub const SESSION_TOKEN_EXPIRY_SECS: i64 = 900; // 15 minutes

/// Refresh token expiry time (seconds)
pub const REFRESH_TOKEN_EXPIRY_SECS: i64 = 604800; // 7 days

/// Rate limiting windows
pub mod rate_limits {
    /// Challenge requests per minute (per IP)
    pub const CHALLENGE_PER_MINUTE: u32 = 10;

    /// Verification attempts per minute (per IP)
    pub const VERIFY_PER_MINUTE: u32 = 5;

    /// Messages posted per minute (per session)
    pub const MESSAGES_PER_MINUTE: u32 = 100;

    /// Message list requests per minute (per session)
    pub const LIST_MESSAGES_PER_MINUTE: u32 = 200;

    /// Job submissions per minute (per session)
    pub const JOBS_PER_MINUTE: u32 = 20;

    /// Work submissions per minute (per session)
    pub const WORK_SUBMISSIONS_PER_MINUTE: u32 = 10;

    /// Messages per minute (per channel, all users)
    pub const CHANNEL_MESSAGES_PER_MINUTE: u32 = 500;

    /// Jobs per minute (per channel, all users)
    pub const CHANNEL_JOBS_PER_MINUTE: u32 = 100;
}

/// Message size limits
pub mod limits {
    /// Maximum message content length (characters)
    pub const MAX_MESSAGE_LENGTH: usize = 10_000;

    /// Maximum channel name length
    pub const MAX_CHANNEL_NAME: usize = 100;

    /// Maximum job title length
    pub const MAX_JOB_TITLE: usize = 200;

    /// Maximum job description length
    pub const MAX_JOB_DESCRIPTION: usize = 50_000;

    /// Maximum signature length (for ML-DSA-87: 4627 bytes = 9254 hex chars)
    pub const MAX_SIGNATURE_LENGTH: usize = 10_000;

    /// Maximum work submission data length (encrypted)
    pub const MAX_WORK_DATA_LENGTH: usize = 1_000_000;

    /// Maximum concurrent active jobs per user
    pub const MAX_ACTIVE_JOBS_PER_USER: u32 = 10;

    /// Maximum concurrent workers per job
    pub const MAX_WORKERS_PER_JOB: u32 = 100;
}

/// Cryptographic sizes
pub mod crypto_sizes {
    /// SHA-3-256 hash size (bytes)
    pub const SHA3_256_SIZE: usize = 32;

    /// Nonce size (bytes)
    pub const NONCE_SIZE: usize = 32;

    /// ML-DSA-87 verifying (public) key size (bytes) — FIPS 204, Category 5
    pub const ML_DSA_87_PUBLIC_KEY_SIZE: usize = 2592;

    /// ML-DSA-87 signing key seed size (bytes) — the 32-byte xi seed
    pub const ML_DSA_87_PRIVATE_KEY_SIZE: usize = 32;

    /// ML-DSA-87 signature size (bytes) — FIPS 204
    pub const ML_DSA_87_SIGNATURE_SIZE: usize = 4627;

    /// IP/UA hash size (bytes, before hex encoding)
    pub const HASH_SIZE_SHORT: usize = 16;
}

// ============================================================================
// Job-Related Constants
// ============================================================================

/// Default job deadline (seconds from now)
pub const DEFAULT_JOB_DEADLINE_SECS: i64 = 86400; // 24 hours

/// Dispute resolution timeout (seconds)
pub const DISPUTE_TIMEOUT_SECS: i64 = 604800; // 7 days

/// Reputation decay per day of inactivity (fraction)
pub const REPUTATION_DECAY_DAILY: f64 = 0.001;

/// Reputation bonus per completed job
pub const REPUTATION_JOB_BONUS: u32 = 10;

/// Reputation penalty per fraud conviction
pub const REPUTATION_FRAUD_PENALTY: u32 = 100;

// ============================================================================
// Role-Based Configuration
// ============================================================================

pub mod roles {
    use crate::models::Role;

    /// Roles required to post jobs
    pub fn can_post_jobs(roles: &[Role]) -> bool {
        roles.contains(&Role::Worker) || roles.contains(&Role::Verifier) || roles.contains(&Role::CoreDev)
    }

    /// Roles required to take jobs
    pub fn can_take_jobs(roles: &[Role]) -> bool {
        roles.contains(&Role::Worker) || roles.contains(&Role::Verifier) || roles.contains(&Role::CoreDev)
    }

    /// Roles required to verify work
    pub fn can_verify(roles: &[Role]) -> bool {
        roles.contains(&Role::Verifier) || roles.contains(&Role::CoreDev)
    }

    /// Roles required to moderate
    pub fn can_moderate(roles: &[Role]) -> bool {
        roles.contains(&Role::Moderator) || roles.contains(&Role::CoreDev)
    }

    /// Roles required to administer
    pub fn can_administer(roles: &[Role]) -> bool {
        roles.contains(&Role::CoreDev)
    }
}

// ============================================================================
// HTTP Status Codes
// ============================================================================

pub mod http {
    /// Success
    pub const OK: u16 = 200;
    pub const CREATED: u16 = 201;
    pub const ACCEPTED: u16 = 202;
    pub const NO_CONTENT: u16 = 204;

    /// Client errors
    pub const BAD_REQUEST: u16 = 400;
    pub const UNAUTHORIZED: u16 = 401;
    pub const FORBIDDEN: u16 = 403;
    pub const NOT_FOUND: u16 = 404;
    pub const CONFLICT: u16 = 409;
    pub const TOO_MANY_REQUESTS: u16 = 429;

    /// Server errors
    pub const INTERNAL_ERROR: u16 = 500;
    pub const SERVICE_UNAVAILABLE: u16 = 503;
}

// ============================================================================
// Protocol Versioning
// ============================================================================

/// Minimum supported client version
pub const MIN_CLIENT_VERSION: &str = "1.0.0";

/// Minimum supported server version
pub const MIN_SERVER_VERSION: &str = "1.0.0";

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants_are_sane() {
        // Challenge expiry should be shorter than session
        assert!(CHALLENGE_EXPIRY_SECS < SESSION_TOKEN_EXPIRY_SECS);

        // Session should be shorter than refresh
        assert!(SESSION_TOKEN_EXPIRY_SECS < REFRESH_TOKEN_EXPIRY_SECS);

        // Rate limits should be reasonable
        assert!(rate_limits::CHALLENGE_PER_MINUTE > 0);
        assert!(rate_limits::VERIFY_PER_MINUTE > 0);
        assert!(rate_limits::MESSAGES_PER_MINUTE > 0);

        // Limits should be set
        assert!(limits::MAX_MESSAGE_LENGTH > 0);
        assert!(limits::MAX_SIGNATURE_LENGTH > 0);
    }

    #[test]
    fn test_crypto_sizes() {
        assert_eq!(crypto_sizes::SHA3_256_SIZE, 32);
        assert_eq!(crypto_sizes::NONCE_SIZE, 32);
        assert_eq!(crypto_sizes::ML_DSA_87_SIGNATURE_SIZE, 4627);
    }

    #[test]
    fn test_role_permissions() {
        use crate::models::Role;

        let worker_roles = vec![Role::Worker];
        let admin_roles = vec![Role::CoreDev];

        assert!(roles::can_post_jobs(&worker_roles));
        assert!(roles::can_administer(&admin_roles));
        assert!(!roles::can_administer(&worker_roles));
    }
}
