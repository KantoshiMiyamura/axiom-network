//! Axiom Community Platform — Shared Library
//!
//! Common types, protocols, and cryptography utilities used by
//! both client and server.

pub mod error;
pub mod models;
pub mod crypto;
pub mod protocol;

// Re-exports for convenience
pub use error::{Error, Result};
pub use models::*;
pub use protocol::*;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
