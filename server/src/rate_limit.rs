//! Rate limiting enforcement with sliding window counters.
//!
//! Each limiter resets its counter after a 60-second window expires.

use axiom_community_shared::protocol::rate_limits;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::warn;

/// Sliding window rate limiter (resets every 60 seconds).
#[derive(Clone)]
struct SlidingLimiter {
    count: u32,
    max_per_minute: u32,
    window_start: std::time::Instant,
}

impl SlidingLimiter {
    fn new(max_per_minute: u32) -> Self {
        SlidingLimiter {
            count: 0,
            max_per_minute,
            window_start: std::time::Instant::now(),
        }
    }

    fn check(&mut self) -> bool {
        let now = std::time::Instant::now();
        if now.duration_since(self.window_start) >= std::time::Duration::from_secs(60) {
            // Window expired — reset counter
            self.count = 0;
            self.window_start = now;
        }

        if self.count < self.max_per_minute {
            self.count += 1;
            true
        } else {
            false
        }
    }

    fn is_idle(&self) -> bool {
        let elapsed = std::time::Instant::now().duration_since(self.window_start);
        elapsed >= std::time::Duration::from_secs(300) // 5 minutes idle
    }
}

/// Rate limiter for different endpoints.
pub struct RateLimitManager {
    // Per-IP rate limiters
    challenge_limiters: Arc<RwLock<HashMap<IpAddr, SlidingLimiter>>>,
    verify_limiters: Arc<RwLock<HashMap<IpAddr, SlidingLimiter>>>,

    // Per-session/user rate limiters
    message_limiters: Arc<RwLock<HashMap<String, SlidingLimiter>>>,
    job_limiters: Arc<RwLock<HashMap<String, SlidingLimiter>>>,
}

impl RateLimitManager {
    /// Create new rate limit manager.
    pub fn new() -> Self {
        RateLimitManager {
            challenge_limiters: Arc::new(RwLock::new(HashMap::new())),
            verify_limiters: Arc::new(RwLock::new(HashMap::new())),
            message_limiters: Arc::new(RwLock::new(HashMap::new())),
            job_limiters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if challenge request is allowed.
    pub async fn check_challenge(&self, ip: IpAddr) -> bool {
        self.check_rate_limit_ip(
            &self.challenge_limiters,
            ip,
            rate_limits::CHALLENGE_PER_MINUTE,
        )
        .await
    }

    /// Check if verify attempt is allowed.
    pub async fn check_verify(&self, ip: IpAddr) -> bool {
        self.check_rate_limit_ip(
            &self.verify_limiters,
            ip,
            rate_limits::VERIFY_PER_MINUTE,
        )
        .await
    }

    /// Check if message posting is allowed.
    pub async fn check_message(&self, key: &str) -> bool {
        self.check_rate_limit_key(
            &self.message_limiters,
            key,
            rate_limits::MESSAGES_PER_MINUTE,
        )
        .await
    }

    /// Check if job creation is allowed.
    pub async fn check_job(&self, key: &str) -> bool {
        self.check_rate_limit_key(
            &self.job_limiters,
            key,
            rate_limits::JOBS_PER_MINUTE,
        )
        .await
    }

    async fn check_rate_limit_ip(
        &self,
        limiters: &Arc<RwLock<HashMap<IpAddr, SlidingLimiter>>>,
        ip: IpAddr,
        per_minute: u32,
    ) -> bool {
        let mut map = limiters.write().await;
        let limiter = map
            .entry(ip)
            .or_insert_with(|| SlidingLimiter::new(per_minute));

        if limiter.check() {
            true
        } else {
            warn!("Rate limit exceeded for IP {}: {} per minute", ip, per_minute);
            false
        }
    }

    async fn check_rate_limit_key(
        &self,
        limiters: &Arc<RwLock<HashMap<String, SlidingLimiter>>>,
        key: &str,
        per_minute: u32,
    ) -> bool {
        let mut map = limiters.write().await;
        let limiter = map
            .entry(key.to_string())
            .or_insert_with(|| SlidingLimiter::new(per_minute));

        if limiter.check() {
            true
        } else {
            warn!(
                "Rate limit exceeded for key {}: {} per minute",
                key, per_minute
            );
            false
        }
    }

    /// Remove idle limiters (entries with no activity for >5 minutes).
    /// Call periodically from a background task.
    pub async fn cleanup(&self) {
        let mut challenge = self.challenge_limiters.write().await;
        challenge.retain(|_, v| !v.is_idle());

        let mut verify = self.verify_limiters.write().await;
        verify.retain(|_, v| !v.is_idle());

        let mut message = self.message_limiters.write().await;
        message.retain(|_, v| !v.is_idle());

        let mut job = self.job_limiters.write().await;
        job.retain(|_, v| !v.is_idle());
    }
}

impl Default for RateLimitManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[tokio::test]
    async fn test_challenge_rate_limit() {
        let manager = RateLimitManager::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // First requests should succeed
        for _ in 0..rate_limits::CHALLENGE_PER_MINUTE {
            assert!(manager.check_challenge(ip).await);
        }

        // Next request should fail
        assert!(!manager.check_challenge(ip).await);
    }

    #[tokio::test]
    async fn test_session_rate_limit() {
        let manager = RateLimitManager::new();
        let session_id = "session_123";

        // First requests should succeed
        for _ in 0..rate_limits::MESSAGES_PER_MINUTE {
            assert!(manager.check_message(session_id).await);
        }

        // Next request should fail
        assert!(!manager.check_message(session_id).await);
    }

    #[tokio::test]
    async fn test_different_ips_independent() {
        let manager = RateLimitManager::new();
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // Exhaust ip1
        for _ in 0..=rate_limits::CHALLENGE_PER_MINUTE {
            manager.check_challenge(ip1).await;
        }

        // ip2 should still have capacity
        assert!(manager.check_challenge(ip2).await);
    }
}
