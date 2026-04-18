//! Client configuration

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Server base URL (e.g., http://localhost:3000)
    pub server_url: String,
    /// Local data directory for keys and cache
    pub data_dir: PathBuf,
    /// Enable verbose logging
    pub verbose_logging: bool,
}

impl ClientConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        dotenv::dotenv().ok();

        let server_url =
            env::var("SERVER_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
        let data_dir = env::var("DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
                home.join(".axiom-community")
            });

        // Create data directory if it doesn't exist
        std::fs::create_dir_all(&data_dir)?;

        Ok(ClientConfig {
            server_url,
            data_dir,
            verbose_logging: env::var("VERBOSE_LOGGING")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(false),
        })
    }
}
