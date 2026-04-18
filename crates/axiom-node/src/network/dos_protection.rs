// Copyright (c) 2026 Kantoshi Miyamura

//! DoS protection mechanisms.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const RATE_LIMIT_PER_MINUTE: u32 = 1000;
pub const RATE_LIMIT_PER_SECOND: u32 = 100;
pub const IP_BAN_DURATION_SECS: u64 = 3600;

#[derive(Debug, Clone)]
pub struct RequestTracker {
    pub ip: IpAddr,
    pub requests_this_second: u32,
    pub requests_this_minute: u32,
    pub last_second_reset: u64,
    pub last_minute_reset: u64,
    pub banned_until: Option<u64>,
}

impl RequestTracker {
    pub fn new(ip: IpAddr) -> Self {
        let now = current_timestamp();
        RequestTracker {
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
        self.banned_until = Some(current_timestamp() + IP_BAN_DURATION_SECS);
    }

    pub fn unban(&mut self) {
        self.banned_until = None;
    }
}

pub struct RateLimiter {
    trackers: HashMap<IpAddr, RequestTracker>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            trackers: HashMap::new(),
        }
    }

    /// CRITICAL FIX: Only trust X-Forwarded-For from loopback connections.
    /// Without this, an attacker can set X-Forwarded-For: 127.0.0.1 to bypass rate limiting.
    /// 
    /// Parameters:
    /// - `socket_ip`: The actual socket IP address (from TCP connection)
    /// - `forwarded_for`: Optional X-Forwarded-For header value
    /// 
    /// Returns the effective IP to use for rate limiting.
    pub fn check_rate_limit_with_forwarding(
        &mut self,
        socket_ip: IpAddr,
        forwarded_for: Option<IpAddr>,
    ) -> Result<(), String> {
        // CRITICAL: Only trust forwarded headers from loopback/trusted proxies.
        // Never trust forwarded headers from remote peers.
        let effective_ip = if socket_ip.is_loopback() {
            // Connection is from localhost (trusted reverse proxy)
            forwarded_for.unwrap_or(socket_ip)
        } else {
            // Connection is from remote peer - NEVER trust forwarded headers
            if forwarded_for.is_some() {
                tracing::debug!(
                    socket_ip = %socket_ip,
                    forwarded_for = ?forwarded_for,
                    "PEER_HEADER_IGNORED reason=untrusted_forward_header"
                );
            }
            socket_ip
        };

        self.check_rate_limit(effective_ip)
    }

    /// DEPRECATED: Use check_rate_limit_with_forwarding() instead.
    /// This method is kept for backward compatibility but logs a warning.
    pub fn check_rate_limit(&mut self, ip: IpAddr) -> Result<(), String> {
        tracing::debug!(
            ip = %ip,
            method = "check_rate_limit",
            "DEPRECATED: Using old check_rate_limit() method. Migrate to check_rate_limit_with_forwarding()"
        );
        
        if ip.is_loopback() {
            return Ok(());
        }

        let now = current_timestamp();
        let tracker = self
            .trackers
            .entry(ip)
            .or_insert_with(|| RequestTracker::new(ip));

        if tracker.is_banned() {
            return Err("IP is temporarily banned".to_string());
        }

        if now - tracker.last_second_reset >= 1 {
            tracker.requests_this_second = 0;
            tracker.last_second_reset = now;
        }

        if now - tracker.last_minute_reset >= 60 {
            tracker.requests_this_minute = 0;
            tracker.last_minute_reset = now;
        }

        if tracker.requests_this_second >= RATE_LIMIT_PER_SECOND {
            tracker.ban_temporarily();
            return Err("Rate limit exceeded (per second)".to_string());
        }

        if tracker.requests_this_minute >= RATE_LIMIT_PER_MINUTE {
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

pub struct DosProtection {
    rate_limiter: RateLimiter,
}

impl Default for DosProtection {
    fn default() -> Self {
        Self::new()
    }
}

impl DosProtection {
    pub fn new() -> Self {
        DosProtection {
            rate_limiter: RateLimiter::new(),
        }
    }

    /// DEPRECATED: Use check_request_with_forwarding() instead.
    /// This method is kept for backward compatibility but logs a warning.
    pub fn check_request(&mut self, ip: IpAddr) -> Result<(), String> {
        tracing::warn!(
            ip = %ip,
            method = "check_request",
            "DEPRECATED: Using old check_request() method. Migrate to check_request_with_forwarding()"
        );
        self.rate_limiter.check_rate_limit(ip)
    }

    /// CRITICAL FIX: Check request with X-Forwarded-For support (only trusted from loopback).
    /// This prevents attackers from spoofing their IP to bypass rate limiting.
    pub fn check_request_with_forwarding(
        &mut self,
        socket_ip: IpAddr,
        forwarded_for: Option<IpAddr>,
    ) -> Result<(), String> {
        self.rate_limiter
            .check_rate_limit_with_forwarding(socket_ip, forwarded_for)
    }

    pub fn cleanup(&mut self) {
        self.rate_limiter.cleanup_expired_bans();
    }

    pub fn get_banned_ips(&self) -> Vec<IpAddr> {
        self.rate_limiter.get_banned_ips()
    }
}

/// Per-IP rate limiter for mempool submissions.
pub struct MempoolRateLimiter {
    pub entries: HashMap<IpAddr, PeerTxStats>,
    max_tx_per_minute: u32,
    max_bytes_per_minute: usize,
}

pub struct PeerTxStats {
    pub tx_count: u32,
    pub bytes: usize,
    pub window_start: Instant,
}

impl Default for MempoolRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl MempoolRateLimiter {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            max_tx_per_minute: 100,
            max_bytes_per_minute: 1_000_000,
        }
    }

    pub fn check_and_record(
        &mut self,
        peer_ip: IpAddr,
        tx_size_bytes: usize,
    ) -> Result<(), &'static str> {
        if peer_ip.is_loopback() {
            return Ok(());
        }

        let now = Instant::now();
        let entry = self.entries.entry(peer_ip).or_insert(PeerTxStats {
            tx_count: 0,
            bytes: 0,
            window_start: now,
        });

        if now.duration_since(entry.window_start) >= Duration::from_secs(60) {
            entry.tx_count = 0;
            entry.bytes = 0;
            entry.window_start = now;
        }

        if entry.tx_count >= self.max_tx_per_minute {
            return Err("rate limit: too many transactions per minute");
        }
        if entry.bytes + tx_size_bytes > self.max_bytes_per_minute {
            return Err("rate limit: too many bytes per minute");
        }

        entry.tx_count += 1;
        entry.bytes += tx_size_bytes;
        Ok(())
    }

    pub fn evict_stale(&mut self) {
        let now = Instant::now();
        self.entries
            .retain(|_, v| now.duration_since(v.window_start) < Duration::from_secs(600));
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_request_tracker_creation() {
        let ip = IpAddr::from_str("127.0.0.1").unwrap();
        let tracker = RequestTracker::new(ip);
        assert_eq!(tracker.requests_this_second, 0);
        assert!(!tracker.is_banned());
    }

    #[test]
    fn test_rate_limiter_allows_requests() {
        let mut limiter = RateLimiter::new();
        let ip = IpAddr::from_str("127.0.0.1").unwrap();

        for _ in 0..10 {
            assert!(limiter.check_rate_limit(ip).is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_bans_on_excess() {
        let mut limiter = RateLimiter::new();
        let ip = IpAddr::from_str("10.0.0.1").unwrap();

        for _ in 0..RATE_LIMIT_PER_SECOND {
            let _ = limiter.check_rate_limit(ip);
        }

        assert!(limiter.check_rate_limit(ip).is_err());
        assert!(limiter.trackers.get(&ip).unwrap().is_banned());
    }

    #[test]
    fn test_loopback_never_rate_limited() {
        let mut limiter = RateLimiter::new();
        let ip = IpAddr::from_str("127.0.0.1").unwrap();
        for _ in 0..10_000 {
            assert!(limiter.check_rate_limit(ip).is_ok());
        }
    }

    #[test]
    fn test_dos_protection() {
        let mut dos = DosProtection::new();
        let ip = IpAddr::from_str("127.0.0.1").unwrap();

        assert!(dos.check_request(ip).is_ok());
    }

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let mut limiter = MempoolRateLimiter::new();
        let peer = ip("127.0.0.1");
        for _ in 0..50 {
            assert!(limiter.check_and_record(peer, 100).is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_tx_limit() {
        let mut limiter = MempoolRateLimiter::new();
        let peer = ip("10.0.0.1");
        for _ in 0..100 {
            limiter.check_and_record(peer, 100).ok();
        }
        assert!(limiter.check_and_record(peer, 100).is_err());
    }

    #[test]
    fn test_rate_limiter_blocks_over_bytes_limit() {
        let mut limiter = MempoolRateLimiter::new();
        let peer = ip("10.0.0.2");
        for _ in 0..10 {
            limiter.check_and_record(peer, 100_000).ok();
        }
        assert!(limiter.check_and_record(peer, 100_000).is_err());
    }

    #[test]
    fn test_rate_limiter_different_peers_independent() {
        let mut limiter = MempoolRateLimiter::new();
        let peer_a = ip("10.0.0.1");
        let peer_b = ip("10.0.0.2");
        for _ in 0..100 {
            limiter.check_and_record(peer_a, 100).ok();
        }
        assert!(limiter.check_and_record(peer_a, 100).is_err());
        assert!(limiter.check_and_record(peer_b, 100).is_ok());
    }

    #[test]
    fn test_evict_stale_removes_old_entries() {
        let mut limiter = MempoolRateLimiter::new();
        let peer = ip("10.0.0.3");
        limiter.check_and_record(peer, 100).ok();
        assert_eq!(limiter.entries.len(), 1);
        limiter.evict_stale();
        assert_eq!(limiter.entries.len(), 1);
    }
}
