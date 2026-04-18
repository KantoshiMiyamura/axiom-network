//! Authentication module
//!
//! Provides:
//! - JWT token generation and validation
//! - Session management
//! - Challenge-response protocol

pub mod jwt;
pub mod session;
pub mod challenge;

pub use jwt::TokenManager;
pub use session::SessionManager;
pub use challenge::ChallengeManager;
