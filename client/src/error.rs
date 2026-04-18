//! Client error types

use std::fmt;

/// Client error type
#[derive(Debug)]
pub enum ClientError {
    /// Shared library error
    Shared(axiom_community_shared::Error),
    /// Network/HTTP error
    Network(String),
    /// Configuration error
    Config(String),
    /// Wallet/key error
    Wallet(String),
    /// IO error
    Io(std::io::Error),
    /// Internal error
    Internal(String),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Shared(e) => write!(f, "Shared error: {}", e),
            ClientError::Network(e) => write!(f, "Network error: {}", e),
            ClientError::Config(e) => write!(f, "Config error: {}", e),
            ClientError::Wallet(e) => write!(f, "Wallet error: {}", e),
            ClientError::Io(e) => write!(f, "IO error: {}", e),
            ClientError::Internal(e) => write!(f, "Internal error: {}", e),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<axiom_community_shared::Error> for ClientError {
    fn from(err: axiom_community_shared::Error) -> Self {
        ClientError::Shared(err)
    }
}

impl From<reqwest::Error> for ClientError {
    fn from(err: reqwest::Error) -> Self {
        ClientError::Network(err.to_string())
    }
}

impl From<std::io::Error> for ClientError {
    fn from(err: std::io::Error) -> Self {
        ClientError::Io(err)
    }
}

impl From<serde_json::Error> for ClientError {
    fn from(err: serde_json::Error) -> Self {
        ClientError::Internal(format!("JSON error: {}", err))
    }
}

pub type Result<T> = std::result::Result<T, ClientError>;
