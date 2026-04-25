// Copyright (c) 2026 Kantoshi Miyamura

//! RPC rate limiting and request tracking.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Rate limit: requests per minute per IP.
pub const RPC_RATE_LIMIT_PER_MINUTE: u32 = 100;

/// Rate limit: requests per second per IP.
pub const RPC_RATE_LIMIT_PER_SECOND: u32 = 10;

/// Temporary IP ban duration in seconds (1 hour).
pub const RPC_BAN_DURATION_SECS: u64 = 3600;

/// Request tracking for rate limiting.
#[derive(Debug, Clone)]
pub struct RpcRequestTracker {
    pub ip: IpAddr,
    pub requests_this_second: u32,
    pub requests_this_minute: u32,
    pub last_second_reset: u64,
    pub last_minute_reset: u64,
    pub banned_until: Option<u64>,
}

impl RpcRequestTracker {
    pub fn new(ip: IpAddr) -> Self {
        let now = current_timestamp();
        RpcRequestTracker {
            ip,
            requests_this_second: 0,
            requests_this_minute: 0,
            last_second_reset: now,
            last_minute_reset: now,
            banned_until: None,
        }
    }

    pub fn is_banned(&self) -> bool {
        if let Some(ban_until) = self.banned_until {
            current_timestamp() < ban_until
        } else {
            false
        }
    }

    pub fn ban_temporarily(&mut self) {
        self.banned_until = Some(current_timestamp() + RPC_BAN_DURATION_SECS);
    }

    pub fn unban(&mut self) {
        self.banned_until = None;
    }
}

/// RPC rate limiter.
pub struct RpcRateLimiter {
    trackers: HashMap<IpAddr, RpcRequestTracker>,
}

impl Default for RpcRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RpcRateLimiter {
    pub fn new() -> Self {
        RpcRateLimiter {
            trackers: HashMap::new(),
        }
    }

    /// Returns `Err` if the IP is banned or has exceeded per-second/per-minute limits.
    pub fn check_rate_limit(&mut self, ip: IpAddr) -> Result<(), String> {
        // Loopback is never rate-limited; genuine localhost calls only (proxy resolves real IP first).
        if ip.is_loopback() {
            return Ok(());
        }

        let now = current_timestamp();
        let tracker = self
            .trackers
            .entry(ip)
            .or_insert_with(|| RpcRequestTracker::new(ip));

        if tracker.is_banned() {
            return Err("IP is temporarily banned due to rate limit violation".to_string());
        }

        if now - tracker.last_second_reset >= 1 {
            tracker.requests_this_second = 0;
            tracker.last_second_reset = now;
        }

        if now - tracker.last_minute_reset >= 60 {
            tracker.requests_this_minute = 0;
            tracker.last_minute_reset = now;
        }

        if tracker.requests_this_second >= RPC_RATE_LIMIT_PER_SECOND {
            tracker.ban_temporarily();
            return Err("Rate limit exceeded (per second)".to_string());
        }

        if tracker.requests_this_minute >= RPC_RATE_LIMIT_PER_MINUTE {
            tracker.ban_temporarily();
            return Err("Rate limit exceeded (per minute)".to_string());
        }

        tracker.requests_this_second += 1;
        tracker.requests_this_minute += 1;

        Ok(())
    }

    pub fn cleanup_expired_bans(&mut self) {
        for tracker in self.trackers.values_mut() {
            if let Some(ban_until) = tracker.banned_until {
                if current_timestamp() >= ban_until {
                    tracker.unban();
                }
            }
        }
    }

    pub fn get_banned_ips(&self) -> Vec<IpAddr> {
        self.trackers
            .values()
            .filter(|t| t.is_banned())
            .map(|t| t.ip)
            .collect()
    }

    pub fn remove(&mut self, ip: IpAddr) {
        self.trackers.remove(&ip);
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Axum middleware ─────────────────────────────────────────────────────────

// When peer is loopback (local reverse proxy), read the real client IP from
// X-Real-IP or X-Forwarded-For. External peers never get header trust.
fn extract_real_ip(peer_ip: std::net::IpAddr, headers: &axum::http::HeaderMap) -> std::net::IpAddr {
    use std::net::IpAddr;
    use std::str::FromStr;

    if !peer_ip.is_loopback() {
        return peer_ip;
    }

    if let Some(val) = headers.get("x-real-ip") {
        if let Ok(s) = val.to_str() {
            if let Ok(ip) = IpAddr::from_str(s.trim()) {
                return ip;
            }
        }
    }

    // X-Forwarded-For: take leftmost (client) address
    if let Some(val) = headers.get("x-forwarded-for") {
        if let Ok(s) = val.to_str() {
            if let Some(first) = s.split(',').next() {
                if let Ok(ip) = IpAddr::from_str(first.trim()) {
                    return ip;
                }
            }
        }
    }

    peer_ip
}

/// Per-IP rate limiting middleware. Violators get 429 and are banned for `RPC_BAN_DURATION_SECS`.
pub async fn rate_limit_middleware(
    axum::extract::State(limiter): axum::extract::State<
        std::sync::Arc<std::sync::Mutex<RpcRateLimiter>>,
    >,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::{http::StatusCode, response::IntoResponse, Json};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    // Falls back to 127.0.0.1 when connect-info is absent (unit tests).
    let peer_ip: IpAddr = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

    let ip = extract_real_ip(peer_ip, request.headers());

    // Lock is released before .await — safe with std::sync::Mutex.
    let result = {
        let mut rl = limiter.lock().unwrap_or_else(|p| p.into_inner());
        rl.check_rate_limit(ip)
    };

    match result {
        Ok(()) => next.run(request).await,
        Err(msg) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": msg})),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use std::str::FromStr;

    #[test]
    fn test_extract_real_ip_non_loopback_ignores_headers() {
        let peer = IpAddr::from_str("203.0.113.5").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "10.0.0.1".parse().unwrap());
        assert_eq!(extract_real_ip(peer, &headers), peer);
    }

    #[test]
    fn test_extract_real_ip_loopback_uses_x_real_ip() {
        let peer = IpAddr::from_str("127.0.0.1").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "203.0.113.42".parse().unwrap());
        let ip = extract_real_ip(peer, &headers);
        assert_eq!(ip, IpAddr::from_str("203.0.113.42").unwrap());
    }

    #[test]
    fn test_extract_real_ip_loopback_uses_x_forwarded_for() {
        let peer = IpAddr::from_str("127.0.0.1").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.7, 10.0.0.1".parse().unwrap());
        let ip = extract_real_ip(peer, &headers);
        assert_eq!(ip, IpAddr::from_str("203.0.113.7").unwrap());
    }

    #[test]
    fn test_extract_real_ip_loopback_no_headers_returns_loopback() {
        let peer = IpAddr::from_str("127.0.0.1").unwrap();
        let headers = HeaderMap::new();
        assert_eq!(extract_real_ip(peer, &headers), peer);
    }

    #[test]
    fn test_request_tracker_creation() {
        let ip = IpAddr::from_str("127.0.0.1").unwrap();
        let tracker = RpcRequestTracker::new(ip);
        assert_eq!(tracker.requests_this_second, 0);
        assert!(!tracker.is_banned());
    }

    #[test]
    fn test_rate_limiter_allows_requests() {
        let mut limiter = RpcRateLimiter::new();
        let ip = IpAddr::from_str("127.0.0.1").unwrap();

        for _ in 0..5 {
            assert!(limiter.check_rate_limit(ip).is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_bans_on_excess() {
        let mut limiter = RpcRateLimiter::new();
        // Non-loopback — loopback is exempt
        let ip = IpAddr::from_str("10.0.0.1").unwrap();

        for _ in 0..RPC_RATE_LIMIT_PER_SECOND {
            let _ = limiter.check_rate_limit(ip);
        }

        assert!(limiter.check_rate_limit(ip).is_err());
        assert!(limiter.trackers.get(&ip).unwrap().is_banned());
    }

    #[test]
    fn test_loopback_never_rate_limited() {
        let mut limiter = RpcRateLimiter::new();
        let ip = IpAddr::from_str("127.0.0.1").unwrap();
        for _ in 0..10_000 {
            assert!(limiter.check_rate_limit(ip).is_ok());
        }
    }
}
