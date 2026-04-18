//! Core data models for the Axiom Community Platform

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Basic Types
// ============================================================================

/// Axiom blockchain address (32 bytes, hex-encoded)
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Address(pub String);

impl Address {
    /// Create a new address
    pub fn new(addr: impl Into<String>) -> Self {
        Address(addr.into())
    }

    /// Validate address format (basic check)
    pub fn is_valid(&self) -> bool {
        // Axiom addresses start with "axm" prefix
        // v1 (legacy): 67 chars (axm + 64 hex)
        // v2 (current): 75 chars (axm + 64 hex pubkey_hash + 8 hex checksum)
        self.0.starts_with("axm")
            && (self.0.len() == 67 || self.0.len() == 75)
            && self.0[3..].chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Get address as string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for Address {
    fn from(s: String) -> Self {
        Address(s)
    }
}

impl From<&str> for Address {
    fn from(s: &str) -> Self {
        Address(s.to_string())
    }
}

// ============================================================================
// Roles & Permissions
// ============================================================================

/// User role in the community platform
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Role {
    /// Basic community member (read-only)
    Member = 1,
    /// Can post jobs and earn rewards
    Worker = 2,
    /// Can verify work submissions
    Verifier = 3,
    /// Can moderate channels and enforce rules
    Moderator = 4,
    /// Core development team (full access)
    CoreDev = 5,
}

impl Role {
    /// Get role as a number (for ordering)
    pub fn level(&self) -> u32 {
        *self as u32
    }

    /// Check if this role has permission for another role
    pub fn can_act_on(&self, other: Role) -> bool {
        self.level() >= other.level()
    }

    /// All roles in order
    pub fn all() -> &'static [Role] {
        &[Role::Member, Role::Worker, Role::Verifier, Role::Moderator, Role::CoreDev]
    }

    /// Get role from string
    pub fn parse(s: &str) -> Option<Role> {
        match s.to_lowercase().as_str() {
            "member" => Some(Role::Member),
            "worker" => Some(Role::Worker),
            "verifier" => Some(Role::Verifier),
            "moderator" => Some(Role::Moderator),
            "core_dev" | "coredev" => Some(Role::CoreDev),
            _ => None,
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Member => write!(f, "member"),
            Role::Worker => write!(f, "worker"),
            Role::Verifier => write!(f, "verifier"),
            Role::Moderator => write!(f, "moderator"),
            Role::CoreDev => write!(f, "core_dev"),
        }
    }
}

// ============================================================================
// Authentication Types
// ============================================================================

/// Request to start authentication challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub address: Address,
    pub user_agent: String,
}

/// Server's authentication challenge response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// One-time nonce (hex-encoded, 32 bytes)
    pub nonce: String,
    /// Challenge hash (hex-encoded, 32 bytes)
    pub challenge: String,
    /// When this challenge expires (Unix timestamp)
    pub expires_at: i64,
    /// Domain for this challenge
    pub domain: String,
}

/// Signature verification request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub nonce: String,
    pub challenge: String,
    /// ML-DSA-87 signature (hex-encoded, 4627 bytes raw)
    pub signature: String,
    /// ML-DSA-87 verifying key (hex-encoded, 2592 bytes raw)
    pub public_key: String,
    pub address: Address,
    pub expires_at: i64,
    pub user_agent: String,
}

/// Session token response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResponse {
    pub session_id: String,
    /// JWT token (15 minute expiry)
    pub session_token: String,
    /// Refresh token (7 day expiry)
    pub refresh_token: String,
    pub expires_at: i64,
    pub user: UserInfo,
}

/// User information in session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub address: Address,
    pub roles: Vec<Role>,
    pub reputation_score: u64,
}

/// Session claims (inside JWT)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClaims {
    pub session_id: String,
    pub address: Address,
    pub roles: Vec<Role>,
    pub issued_at: i64,
    pub expires_at: i64,
    /// Hash of client IP (16 bytes, hex-encoded)
    pub ip_hash: String,
    /// Hash of user-agent (16 bytes, hex-encoded)
    pub user_agent_hash: String,
}

/// Refresh token request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
    pub session_id: String,
}

// ============================================================================
// Messaging Types
// ============================================================================

/// Channel message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMessage {
    /// Unique message ID
    pub id: String,
    /// Channel name
    pub channel: String,
    /// Message author address
    pub author: Address,
    /// Unix timestamp
    pub timestamp: i64,
    /// Message content
    pub content: String,
    /// SHA-3 256 hash of content (hex)
    pub content_hash: String,
    /// Parent message ID (for threads)
    pub parent_id: Option<String>,
    /// Message thread count
    pub thread_count: u32,
    /// Reactions: emoji -> count
    pub reactions: HashMap<String, u32>,
    /// Ed25519 signature of content (hex)
    pub signature: String,
    /// Was message edited?
    pub is_edited: bool,
}

impl ChannelMessage {
    /// Validate message structure
    pub fn validate(&self) -> crate::Result<()> {
        if self.content.is_empty() || self.content.len() > 10000 {
            return Err(crate::Error::MessageTooLong);
        }
        if self.channel.is_empty() || self.channel.len() > 100 {
            return Err(crate::Error::InvalidChannel);
        }
        Ok(())
    }
}

// ============================================================================
// Job Types
// ============================================================================

/// Job state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobState {
    Open,
    Assigned,
    InProgress,
    Completed,
    Disputed,
    Settled,
}

impl std::fmt::Display for JobState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JobState::Open => write!(f, "open"),
            JobState::Assigned => write!(f, "assigned"),
            JobState::InProgress => write!(f, "in_progress"),
            JobState::Completed => write!(f, "completed"),
            JobState::Disputed => write!(f, "disputed"),
            JobState::Settled => write!(f, "settled"),
        }
    }
}

/// Job posting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobPosting {
    pub id: String,
    pub channel: String,
    pub requester: Address,
    pub title: String,
    pub description: String,
    /// Reward in satoshis
    pub reward_sat: u64,
    /// Deadline (Unix timestamp)
    pub deadline: i64,
    /// Maximum workers who can take this job
    pub max_workers: u32,
    pub state: JobState,
    /// Type of work: "verify", "compute", "review", etc.
    pub work_type: String,
    /// Required roles to take job
    pub requirements: Vec<String>,
    pub timestamp: i64,
    /// Signature of job posting
    pub signature: String,
}

impl JobPosting {
    /// Check if job is still open
    pub fn is_open(&self) -> bool {
        self.state == JobState::Open && self.deadline > current_timestamp()
    }
}

/// Work submission for a job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkSubmission {
    pub id: String,
    pub job_id: String,
    pub worker: Address,
    /// Encrypted work data
    pub submission_data: String,
    /// SHA-3 256 hash of submission
    pub data_hash: String,
    pub timestamp: i64,
    /// Worker's signature
    pub signature: String,
    /// Review status
    pub status: String,
}

// ============================================================================
// Dispute Types
// ============================================================================

/// Dispute on a job outcome
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dispute {
    pub id: String,
    pub job_id: String,
    pub work_id: String,
    pub initiator: Address,
    pub reason: String,
    /// Evidence (encrypted)
    pub evidence: String,
    pub timestamp: i64,
    /// Initiator's signature
    pub signature: String,
    /// Current status
    pub status: String,
}

// ============================================================================
// Moderation Types
// ============================================================================

/// Moderation action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModerationAction {
    pub id: String,
    /// Action type: delete_message, mute_user, ban_user
    pub action: String,
    /// Target ID (message or user address)
    pub target: String,
    pub reason: String,
    /// Duration in seconds (0 = permanent)
    pub duration_secs: u64,
    pub moderator: Address,
    pub timestamp: i64,
    pub signature: String,
}

// ============================================================================
// Audit Log Types
// ============================================================================

/// Audit log entry (no secrets)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: i64,
    pub address: Option<Address>,
    pub action: String,
    /// Action details (JSON, no secrets)
    pub details: serde_json::Value,
    /// "success" or "failure"
    pub status: String,
    /// Client IP address (optional)
    pub ip_address: Option<String>,
    /// Client user-agent (optional)
    pub user_agent: Option<String>,
}

// ============================================================================
// API Response Wrapper
// ============================================================================

/// Generic API response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub status: String,
    pub data: T,
}

impl<T> ApiResponse<T> {
    /// Create a successful response
    pub fn ok(data: T) -> Self {
        ApiResponse {
            status: "ok".to_string(),
            data,
        }
    }
}

/// Error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: String,
    pub error: String,
    pub code: String,
}

impl ErrorResponse {
    /// Create an error response
    pub fn new(error: impl Into<String>, code: impl Into<String>) -> Self {
        ErrorResponse {
            status: "error".to_string(),
            error: error.into(),
            code: code.into(),
        }
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Get current Unix timestamp
pub fn current_timestamp() -> i64 {
    chrono::Utc::now().timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_validation() {
        // v2 address: axm + 64 hex + 8 hex checksum = 75 chars
        let valid_v2 = Address::new(format!("axm{}", "a1b2c3d4".repeat(9)));
        assert!(valid_v2.is_valid());

        // v1 legacy address: axm + 64 hex = 67 chars
        let valid_v1 = Address::new(format!("axm{}", "ab".repeat(32)));
        assert!(valid_v1.is_valid());

        let invalid = Address::new("invalid");
        assert!(!invalid.is_valid());

        // Wrong prefix
        let wrong_prefix = Address::new(format!("btc{}", "ab".repeat(32)));
        assert!(!wrong_prefix.is_valid());
    }

    #[test]
    fn test_role_ordering() {
        assert!(Role::CoreDev.can_act_on(Role::Member));
        assert!(!Role::Member.can_act_on(Role::CoreDev));
        assert!(Role::Moderator.can_act_on(Role::Moderator));
    }

    #[test]
    fn test_role_from_str() {
        assert_eq!(Role::parse("member"), Some(Role::Member));
        assert_eq!(Role::parse("core_dev"), Some(Role::CoreDev));
        assert_eq!(Role::parse("invalid"), None);
    }

    #[test]
    fn test_job_state_display() {
        assert_eq!(JobState::Open.to_string(), "open");
        assert_eq!(JobState::Disputed.to_string(), "disputed");
    }

    #[test]
    fn test_message_validation() {
        let valid = ChannelMessage {
            id: "msg:1".to_string(),
            channel: "general".to_string(),
            author: Address::new("axiom1test"),
            timestamp: current_timestamp(),
            content: "Hello!".to_string(),
            content_hash: "abc123".to_string(),
            parent_id: None,
            thread_count: 0,
            reactions: HashMap::new(),
            signature: "sig".to_string(),
            is_edited: false,
        };
        assert!(valid.validate().is_ok());

        let invalid = ChannelMessage {
            content: "x".repeat(10001),
            ..valid
        };
        assert!(invalid.validate().is_err());
    }
}
