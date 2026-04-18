//! JWT token management

use crate::config::Config;
use crate::error::{Result, ServerError};
use axiom_community_shared::models::SessionClaims;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// JWT token payload (extends SessionClaims)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPayload {
    #[serde(flatten)]
    pub claims: SessionClaims,
    pub exp: i64, // Expiration timestamp
    pub iat: i64, // Issued at timestamp
}

/// Token manager for JWT operations
pub struct TokenManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    expiry_secs: i64,
}

impl TokenManager {
    /// Create new token manager
    pub fn new(config: &Config) -> Result<Self> {
        let secret = config.jwt_secret.as_bytes();

        // Validate secret length (min 32 bytes recommended)
        if secret.len() < 32 && config.environment.to_string() == "production" {
            return Err(ServerError::Config(
                "JWT_SECRET must be at least 32 bytes in production".to_string(),
            ));
        }

        let encoding_key = EncodingKey::from_secret(secret);
        let decoding_key = DecodingKey::from_secret(secret);

        Ok(TokenManager {
            encoding_key,
            decoding_key,
            expiry_secs: config.session_token_expiry_secs,
        })
    }

    /// Generate new JWT token
    pub fn generate_token(&self, claims: SessionClaims) -> Result<String> {
        let now = current_timestamp();
        let exp = now + self.expiry_secs;

        let payload = TokenPayload {
            claims,
            exp,
            iat: now,
        };

        let token = encode(&Header::default(), &payload, &self.encoding_key)
            .map_err(|e| ServerError::Internal(format!("Failed to encode token: {}", e)))?;

        debug!("Generated JWT token for session");
        Ok(token)
    }

    /// Validate and decode JWT token
    pub fn validate_token(&self, token: &str) -> Result<TokenPayload> {
        let validation = Validation::default();

        let data = decode::<TokenPayload>(token, &self.decoding_key, &validation)
            .map_err(|_e| ServerError::Shared(axiom_community_shared::Error::InvalidSignature))?;

        // Check expiration
        let now = current_timestamp();
        if data.claims.exp < now {
            return Err(ServerError::Shared(
                axiom_community_shared::Error::SessionExpired,
            ));
        }

        debug!("Validated JWT token for session: {}", data.claims.claims.session_id);
        Ok(data.claims)
    }

    /// Refresh token (generate new one with extended expiry)
    pub fn refresh_token(&self, old_claims: SessionClaims) -> Result<String> {
        // Create new claims with same data but fresh timestamps
        let new_claims = SessionClaims {
            issued_at: current_timestamp(),
            expires_at: current_timestamp() + self.expiry_secs,
            ..old_claims
        };

        self.generate_token(new_claims)
    }
}

/// Get current Unix timestamp
fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_community_shared::models::{Address, Role};

    fn create_test_config() -> Config {
        Config {
            host: "localhost".to_string(),
            port: 3000,
            database_url: "postgres://localhost/test".to_string(),
            environment: crate::config::Environment::Testing,
            jwt_secret: "test-secret-key-at-least-32-bytes-long-1234567890".to_string(),
            session_token_expiry_secs: 900,
            refresh_token_expiry_secs: 604800,
            challenge_expiry_secs: 300,
            rate_limit_challenge_per_minute: 10,
            rate_limit_verify_per_minute: 5,
            rate_limit_messages_per_minute: 100,
            max_message_bytes: 10_000,
            max_job_description_bytes: 50_000,
            verbose_logging: false,
            cors_allowed_origins: vec![],
            require_https: false,
        }
    }

    #[test]
    fn test_token_generation_and_validation() {
        let config = create_test_config();
        let manager = TokenManager::new(&config).unwrap();

        let claims = SessionClaims {
            session_id: "test-session".to_string(),
            address: Address::new("axiom1test123456789012345678901234567890ab"),
            roles: vec![Role::Member],
            issued_at: current_timestamp(),
            expires_at: current_timestamp() + 900,
            ip_hash: "abc123".to_string(),
            user_agent_hash: "def456".to_string(),
        };

        // Generate token
        let token = manager.generate_token(claims.clone()).unwrap();
        assert!(!token.is_empty());

        // Validate token
        let payload = manager.validate_token(&token).unwrap();
        assert_eq!(payload.claims.session_id, "test-session");
        assert_eq!(payload.claims.address, claims.address);
    }

    #[test]
    fn test_invalid_token() {
        let config = create_test_config();
        let manager = TokenManager::new(&config).unwrap();

        let result = manager.validate_token("invalid.token.here");
        assert!(result.is_err());
    }
}
