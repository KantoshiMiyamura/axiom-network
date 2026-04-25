//! Authentication module
//!
//! Provides:
//! - JWT token generation and validation
//! - Session management
//! - Challenge-response protocol

pub mod challenge;
pub mod jwt;
pub mod session;

pub use challenge::ChallengeManager;
pub use jwt::TokenManager;
pub use session::SessionManager;
