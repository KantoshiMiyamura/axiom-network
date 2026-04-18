//! Server configuration management

use serde::{Deserialize, Serialize};
use std::env;

/// Server environment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Environment {
    Development,
    Testing,
    Production,
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Environment::Development => write!(f, "development"),
            Environment::Testing => write!(f, "testing"),
            Environment::Production => write!(f, "production"),
        }
    }
}

impl Environment {
    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "dev" | "development" => Some(Environment::Development),
            "test" | "testing" => Some(Environment::Testing),
            "prod" | "production" => Some(Environment::Production),
            _ => None,
        }
    }
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server host
    pub host: String,
    /// Server port
    pub port: u16,
    /// Database URL (PostgreSQL connection string)
    pub database_url: String,
    /// Environment (dev, test, prod)
    pub environment: Environment,
    /// JWT secret key (min 32 bytes recommended)
    pub jwt_secret: String,
    /// Session token expiry (seconds)
    pub session_token_expiry_secs: i64,
    /// Refresh token expiry (seconds)
    pub refresh_token_expiry_secs: i64,
    /// Challenge expiry (seconds)
    pub challenge_expiry_secs: i64,
    /// Rate limit: challenge requests per minute per IP
    pub rate_limit_challenge_per_minute: u32,
    /// Rate limit: verify attempts per minute per IP
    pub rate_limit_verify_per_minute: u32,
    /// Rate limit: messages per minute per session
    pub rate_limit_messages_per_minute: u32,
    /// Max message size (bytes)
    pub max_message_bytes: usize,
    /// Max job description size (bytes)
    pub max_job_description_bytes: usize,
    /// Enable detailed logging
    pub verbose_logging: bool,
    /// Allowed CORS origins (comma-separated). Empty = localhost-only.
    pub cors_allowed_origins: Vec<String>,
    /// Require HTTPS (reject plain HTTP in production)
    pub require_https: bool,
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> anyhow::Result<Self> {
        dotenv::dotenv().ok();

        let host = env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port: u16 = env::var("SERVER_PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse()?;
        let database_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost:5432/axiom_community".to_string());
        let environment_str = env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
        let environment = Environment::from_str(&environment_str)
            .ok_or_else(|| anyhow::anyhow!("Invalid environment: {}", environment_str))?;

        let jwt_secret = if environment == Environment::Production {
            // Production: JWT_SECRET MUST be set explicitly — never fall back to a default.
            let secret = env::var("JWT_SECRET").map_err(|_| {
                anyhow::anyhow!(
                    "FATAL: JWT_SECRET environment variable is required in production. \
                     Generate one with: openssl rand -hex 32"
                )
            })?;
            if secret.len() < 32 {
                anyhow::bail!(
                    "FATAL: JWT_SECRET must be at least 32 bytes in production (got {})",
                    secret.len()
                );
            }
            // Reject known default/placeholder values
            if secret.contains("please-change") || secret.contains("dev-secret") {
                anyhow::bail!(
                    "FATAL: JWT_SECRET contains a placeholder value — set a real secret for production"
                );
            }
            secret
        } else {
            // Dev/test: allow default but warn
            env::var("JWT_SECRET").unwrap_or_else(|_| {
                eprintln!("WARNING: Using default JWT_SECRET — not safe for production");
                "dev-secret-key-please-change-in-production-min-32-bytes-long".to_string()
            })
        };

        // Validate DATABASE_URL is not the default in production
        if environment == Environment::Production {
            if database_url.contains("localhost") || database_url.contains("127.0.0.1") {
                anyhow::bail!(
                    "FATAL: DATABASE_URL points to localhost in production — use a production database"
                );
            }
        }

        // Parse allowed CORS origins
        let cors_origins_str = env::var("CORS_ALLOWED_ORIGINS").unwrap_or_default();
        let cors_allowed_origins: Vec<String> = if cors_origins_str.is_empty() {
            vec![] // empty = localhost-only default
        } else {
            cors_origins_str.split(',').map(|s| s.trim().to_string()).collect()
        };

        // HTTPS enforcement: always on in production
        let require_https = environment == Environment::Production
            || env::var("REQUIRE_HTTPS").unwrap_or_default() == "true";

        Ok(Config {
            host,
            port,
            database_url,
            environment,
            jwt_secret,
            session_token_expiry_secs: 900,   // 15 minutes
            refresh_token_expiry_secs: 604800, // 7 days
            challenge_expiry_secs: 300,        // 5 minutes
            rate_limit_challenge_per_minute: 10,
            rate_limit_verify_per_minute: 5,
            rate_limit_messages_per_minute: 100,
            max_message_bytes: 10_000,
            max_job_description_bytes: 50_000,
            verbose_logging: environment == Environment::Development,
            cors_allowed_origins,
            require_https,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment_parsing() {
        assert_eq!(Environment::from_str("dev"), Some(Environment::Development));
        assert_eq!(
            Environment::from_str("production"),
            Some(Environment::Production)
        );
        assert_eq!(Environment::from_str("invalid"), None);
    }
}
