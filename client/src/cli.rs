//! CLI command handlers
//!
//! Each command corresponds to a subcommand of the client binary.
//! Commands that require authentication load the session token from
//! the local config directory and pass it as a Bearer token.

use crate::api::ApiClient;
use crate::config::ClientConfig;
use crate::error::Result;

/// Login command
///
/// Flow:
/// 1. Load or generate user keys from the local keystore
/// 2. Request challenge from server (`POST /auth/challenge`)
/// 3. Sign challenge with local ML-DSA-87 key
/// 4. Verify signature with server (`POST /auth/verify`)
/// 5. Store session + refresh tokens locally
pub async fn login(_config: &ClientConfig) -> Result<()> {
    println!("Login command — requires local keystore and running server");
    Ok(())
}

/// Post message command
///
/// Requires an active session (run `login` first).
pub async fn post(config: &ClientConfig, channel: &str, message: &str) -> Result<()> {
    let _client = ApiClient::new(config);
    println!("Posting to {}: {}", channel, message);
    println!("Session token needed for actual post");
    Ok(())
}

/// List messages command
pub async fn list_messages(config: &ClientConfig, channel: &str) -> Result<()> {
    let _client = ApiClient::new(config);
    println!("Messages in channel: {}", channel);
    Ok(())
}

/// List jobs command
pub async fn list_jobs(config: &ClientConfig) -> Result<()> {
    let _client = ApiClient::new(config);
    println!("Available jobs");
    Ok(())
}

/// Create job command
///
/// Requires Worker role or higher.
pub async fn create_job(config: &ClientConfig, _json_file: &str) -> Result<()> {
    let _client = ApiClient::new(config);
    println!("Creating job...");
    Ok(())
}
