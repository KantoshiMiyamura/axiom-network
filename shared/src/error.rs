//! Error types for the community platform

use std::fmt;
use thiserror::Error;

/// Result type for community platform operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error types for authentication, network, and business logic
#[derive(Error, Debug)]
pub enum Error {
    // Authentication errors
    #[error("Challenge not found")]
    ChallengeNotFound,

    #[error("Challenge expired")]
    ChallengeExpired,

    #[error("Challenge already used (replay attack)")]
    ChallengeAlreadyUsed,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid challenge")]
    InvalidChallenge,

    #[error("Timestamp mismatch")]
    TimestampMismatch,

    #[error("IP address mismatch")]
    IPMismatch,

    #[error("IP hash mismatch (possible session hijacking)")]
    IPHashMismatch,

    #[error("User-agent hash mismatch (possible session hijacking)")]
    UserAgentMismatch,

    // Session errors
    #[error("Session not found")]
    SessionNotFound,

    #[error("Session expired")]
    SessionExpired,

    #[error("Session revoked")]
    SessionRevoked,

    #[error("Session mismatch")]
    SessionMismatch,

    // Authorization errors
    #[error("Unauthorized (missing required role: {required})")]
    Unauthorized { required: String },

    #[error("User banned")]
    UserBanned,

    // Rate limiting
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    // Validation errors
    #[error("Invalid address format")]
    InvalidAddress,

    #[error("Invalid role")]
    InvalidRole,

    #[error("Invalid channel name")]
    InvalidChannel,

    #[error("Message too long (max 10000 characters)")]
    MessageTooLong,

    #[error("Invalid message content")]
    InvalidMessage,

    #[error("Job not found")]
    JobNotFound,

    #[error("Job state invalid for operation")]
    InvalidJobState,

    #[error("Work submission not found")]
    WorkSubmissionNotFound,

    #[error("Dispute not found")]
    DisputeNotFound,

    // Crypto errors
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("Key derivation failed")]
    KeyDerivationFailed,

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    // Network errors
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Connection timeout")]
    ConnectionTimeout,

    #[error("Server unreachable")]
    ServerUnreachable,

    // Database errors
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Transaction failed")]
    TransactionFailed,

    // Cache errors
    #[error("Cache error: {0}")]
    CacheError(String),

    // Configuration errors
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Missing configuration: {0}")]
    MissingConfig(String),

    // Generic errors
    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Not implemented")]
    NotImplemented,

    #[error("Invalid JSON: {0}")]
    InvalidJson(String),

    #[error("Invalid UTF-8")]
    InvalidUtf8,

    #[error("Unknown error")]
    Unknown,
}

impl Error {
    /// Create an unauthorized error with the required role
    pub fn unauthorized(required: impl Into<String>) -> Self {
        Error::Unauthorized {
            required: required.into(),
        }
    }

    /// Create a crypto error
    pub fn crypto(msg: impl Into<String>) -> Self {
        Error::CryptoError(msg.into())
    }

    /// Create a network error
    pub fn network(msg: impl Into<String>) -> Self {
        Error::NetworkError(msg.into())
    }

    /// Create a database error
    pub fn database(msg: impl Into<String>) -> Self {
        Error::DatabaseError(msg.into())
    }

    /// Create a cache error
    pub fn cache(msg: impl Into<String>) -> Self {
        Error::CacheError(msg.into())
    }

    /// Check if error is a rate limit
    pub fn is_rate_limited(&self) -> bool {
        matches!(self, Error::RateLimitExceeded)
    }

    /// Check if error is authentication-related
    pub fn is_auth_error(&self) -> bool {
        matches!(
            self,
            Error::ChallengeNotFound
                | Error::ChallengeExpired
                | Error::InvalidSignature
                | Error::SessionNotFound
                | Error::SessionExpired
                | Error::SessionRevoked
        )
    }

    /// Check if error is authorization-related
    pub fn is_authz_error(&self) -> bool {
        matches!(self, Error::Unauthorized { .. } | Error::UserBanned)
    }
}

// Convert from JSON errors
impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::InvalidJson(err.to_string())
    }
}

// Convert from UTF-8 errors
impl From<std::string::FromUtf8Error> for Error {
    fn from(_err: std::string::FromUtf8Error) -> Self {
        Error::InvalidUtf8
    }
}

// Convert from std::fmt::Error
impl From<fmt::Error> for Error {
    fn from(err: fmt::Error) -> Self {
        Error::InternalError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::ChallengeNotFound;
        assert_eq!(err.to_string(), "Challenge not found");
    }

    #[test]
    fn test_error_is_auth_error() {
        assert!(Error::SessionExpired.is_auth_error());
        assert!(!Error::InvalidChannel.is_auth_error());
    }

    #[test]
    fn test_error_is_authz_error() {
        assert!(Error::unauthorized("member").is_authz_error());
        assert!(Error::UserBanned.is_authz_error());
    }
}
