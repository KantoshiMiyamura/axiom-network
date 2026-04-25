//! HTTP API client for server communication

use crate::config::ClientConfig;
use crate::error::Result;
use axiom_community_shared::models::{ChallengeResponse, SessionResponse};
use reqwest::Client;

/// HTTP API client
pub struct ApiClient {
    client: Client,
    base_url: String,
}

impl ApiClient {
    /// Create new API client
    pub fn new(config: &ClientConfig) -> Self {
        ApiClient {
            client: Client::new(),
            base_url: config.server_url.clone(),
        }
    }

    /// Health check — calls `GET /health` and returns true if the node is up.
    pub async fn health_check(&self) -> Result<bool> {
        let resp = self
            .client
            .get(format!("{}/health", self.base_url))
            .send()
            .await
            .map_err(|e| crate::error::ClientError::Internal(e.to_string()))?;

        Ok(resp.status().is_success())
    }

    /// Request authentication challenge from the server.
    pub async fn request_challenge(
        &self,
        address: &str,
        user_agent: &str,
    ) -> Result<ChallengeResponse> {
        let body = serde_json::json!({
            "address": address,
            "user_agent": user_agent,
        });

        let resp = self
            .client
            .post(format!("{}/auth/challenge", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| crate::error::ClientError::Internal(e.to_string()))?;

        let challenge: ChallengeResponse = resp
            .json()
            .await
            .map_err(|e| crate::error::ClientError::Internal(e.to_string()))?;

        Ok(challenge)
    }

    /// Verify signature and establish a session.
    pub async fn verify_signature(
        &self,
        nonce: &str,
        challenge: &str,
        signature: &str,
        address: &str,
    ) -> Result<SessionResponse> {
        let body = serde_json::json!({
            "nonce": nonce,
            "challenge": challenge,
            "signature": signature,
            "address": address,
        });

        let resp = self
            .client
            .post(format!("{}/auth/verify", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| crate::error::ClientError::Internal(e.to_string()))?;

        let session: SessionResponse = resp
            .json()
            .await
            .map_err(|e| crate::error::ClientError::Internal(e.to_string()))?;

        Ok(session)
    }

    /// List messages in a channel.
    pub async fn list_messages(&self, channel: &str, limit: u32) -> Result<Vec<serde_json::Value>> {
        let resp = self
            .client
            .get(format!(
                "{}/channels/{}/messages?limit={}",
                self.base_url, channel, limit
            ))
            .send()
            .await
            .map_err(|e| crate::error::ClientError::Internal(e.to_string()))?;

        let messages: Vec<serde_json::Value> = resp
            .json()
            .await
            .map_err(|e| crate::error::ClientError::Internal(e.to_string()))?;

        Ok(messages)
    }

    /// Post a message to a channel. Requires a valid session token.
    pub async fn post_message(
        &self,
        session_token: &str,
        channel: &str,
        content: &str,
        signature: &str,
    ) -> Result<String> {
        let body = serde_json::json!({
            "content": content,
            "signature": signature,
        });

        let resp = self
            .client
            .post(format!("{}/channels/{}/messages", self.base_url, channel))
            .bearer_auth(session_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| crate::error::ClientError::Internal(e.to_string()))?;

        let result: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| crate::error::ClientError::Internal(e.to_string()))?;

        Ok(result
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string())
    }

    /// List available jobs.
    pub async fn list_jobs(&self, limit: u32) -> Result<Vec<serde_json::Value>> {
        let resp = self
            .client
            .get(format!("{}/jobs?limit={}", self.base_url, limit))
            .send()
            .await
            .map_err(|e| crate::error::ClientError::Internal(e.to_string()))?;

        let jobs: Vec<serde_json::Value> = resp
            .json()
            .await
            .map_err(|e| crate::error::ClientError::Internal(e.to_string()))?;

        Ok(jobs)
    }

    /// Create a new job. Requires Worker role or higher.
    pub async fn create_job(
        &self,
        session_token: &str,
        job_data: serde_json::Value,
    ) -> Result<String> {
        let resp = self
            .client
            .post(format!("{}/jobs", self.base_url))
            .bearer_auth(session_token)
            .json(&job_data)
            .send()
            .await
            .map_err(|e| crate::error::ClientError::Internal(e.to_string()))?;

        let result: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| crate::error::ClientError::Internal(e.to_string()))?;

        Ok(result
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string())
    }
}
