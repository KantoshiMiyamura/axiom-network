//! Security hardening middleware: HTTPS enforcement, IP banning, global rate limiting.
//!
//! All stores are backed by PostgreSQL for multi-instance consistency.
//! Local caches with short TTLs reduce DB load on the hot path.

use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::warn;

use crate::db::Database;
use crate::state::AppState;

// ── HTTPS enforcement ──────────────────────────────────────────────────────

/// Reject plain HTTP requests in production.
pub async fn https_enforcement_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    if !state.config.require_https {
        return next.run(request).await;
    }

    let proto = request
        .headers()
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let scheme = request.uri().scheme_str().unwrap_or("");

    if proto == "https" || scheme == "https" {
        return next.run(request).await;
    }

    let is_loopback = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().is_loopback())
        .unwrap_or(true);

    if is_loopback {
        return next.run(request).await;
    }

    warn!("Rejected non-HTTPS request from {}", scheme);
    (
        StatusCode::MISDIRECTED_REQUEST,
        Json(json!({
            "error": "HTTPS required",
            "details": "This endpoint requires a secure connection"
        })),
    )
        .into_response()
}

// ── IP ban manager (DB-backed with local cache) ────────────────────────────

/// Threshold: ban IP after this many auth failures in 5 minutes.
const AUTH_FAILURE_BAN_THRESHOLD: i32 = 20;
/// Auth failure window (seconds).
const AUTH_FAILURE_WINDOW_SECS: i64 = 300;
/// Auto-ban duration (seconds): 1 hour.
const AUTO_BAN_DURATION_SECS: i64 = 3600;
/// Local ban cache TTL (seconds) — how long to trust the local cache before re-checking DB.
const BAN_CACHE_TTL_SECS: i64 = 10;

/// DB-backed IP ban manager with local write-through cache.
pub struct IpBanManager {
    db: Database,
    /// Local cache: IP → (is_banned, cache_expiry_timestamp)
    cache: RwLock<HashMap<IpAddr, (bool, i64)>>,
}

impl IpBanManager {
    pub fn new(db: Database) -> Self {
        IpBanManager {
            db,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Check if an IP is currently banned. Uses local cache with short TTL,
    /// falls back to DB on cache miss or expiry.
    pub async fn is_banned(&self, ip: &IpAddr) -> bool {
        let now = current_timestamp();

        // Check local cache first
        {
            let cache = self.cache.read().await;
            if let Some(&(banned, expires)) = cache.get(ip) {
                if now < expires {
                    return banned;
                }
            }
        }

        // Cache miss or expired — check DB
        let ip_str = ip.to_string();
        let banned = self.db.is_ip_banned(&ip_str).await.unwrap_or(false);

        // Update cache
        self.cache
            .write()
            .await
            .insert(*ip, (banned, now + BAN_CACHE_TTL_SECS));

        banned
    }

    /// Ban an IP until `expires_at` (0 = permanent). Writes to DB + cache.
    pub async fn ban(&self, ip: IpAddr, expires_at: i64) {
        let ip_str = ip.to_string();
        let _ = self.db.ban_ip(&ip_str, "auto", expires_at, None).await;
        self.cache
            .write()
            .await
            .insert(ip, (true, current_timestamp() + BAN_CACHE_TTL_SECS));
    }

    /// Unban an IP. Writes to DB + cache.
    pub async fn unban(&self, ip: &IpAddr) {
        let ip_str = ip.to_string();
        let _ = self.db.unban_ip(&ip_str).await;
        self.cache
            .write()
            .await
            .insert(*ip, (false, current_timestamp() + BAN_CACHE_TTL_SECS));
    }

    /// Record an auth failure. Atomically increments the counter in DB.
    /// Auto-bans if threshold exceeded.
    pub async fn record_auth_failure(&self, ip: IpAddr) {
        let ip_str = ip.to_string();
        let count = self
            .db
            .record_auth_failure(&ip_str, AUTH_FAILURE_WINDOW_SECS)
            .await
            .unwrap_or(0);

        if count >= AUTH_FAILURE_BAN_THRESHOLD {
            let now = current_timestamp();
            warn!("Auto-banning IP {} after {} auth failures", ip, count);
            self.ban(ip, now + AUTO_BAN_DURATION_SECS).await;
        }
    }

    /// Reset auth failure counter (on successful auth).
    pub async fn reset_auth_failures(&self, ip: &IpAddr) {
        let ip_str = ip.to_string();
        let _ = self.db.reset_auth_failures(&ip_str).await;
    }

    /// Evict stale entries from the local cache.
    pub async fn cleanup_cache(&self) {
        let now = current_timestamp();
        self.cache
            .write()
            .await
            .retain(|_, (_, expires)| *expires > now);
    }
}

// ── Global rate limiter (DB-backed) ────────────────────────────────────────

/// Global request counter across all instances — prevents DDoS saturation.
pub struct GlobalRateLimiter {
    db: Database,
    max_rps: i32,
}

impl GlobalRateLimiter {
    pub fn new(db: Database, max_rps: i32) -> Self {
        GlobalRateLimiter { db, max_rps }
    }

    /// Returns true if the request is allowed. Atomically increments the
    /// shared counter in the database.
    pub async fn check(&self) -> bool {
        self.db
            .check_rate_limit("global", self.max_rps, 1)
            .await
            .unwrap_or(false)
    }
}

// ── Per-IP rate limiter (DB-backed) ────────────────────────────────────────

/// Per-IP request rate limiter shared across instances.
pub struct PerIpRateLimiter {
    db: Database,
    max_per_minute: i32,
}

impl PerIpRateLimiter {
    pub fn new(db: Database, max_per_minute: i32) -> Self {
        PerIpRateLimiter { db, max_per_minute }
    }

    pub async fn check(&self, ip: IpAddr) -> bool {
        if ip.is_loopback() {
            return true;
        }
        let key = format!("ip:{}", ip);
        self.db
            .check_rate_limit(&key, self.max_per_minute, 60)
            .await
            .unwrap_or(false)
    }
}

// ── Signature nonce tracker (DB-backed) ────────────────────────────────────

/// DB-backed signature replay protection. Tracks used signatures in PostgreSQL
/// so replay attempts are blocked across all server instances.
pub struct SignatureNonceTracker {
    db: Database,
    retention_secs: i64,
}

impl SignatureNonceTracker {
    pub fn new(db: Database, retention_secs: i64) -> Self {
        SignatureNonceTracker { db, retention_secs }
    }

    /// Returns `true` if this signature has NOT been seen before (first use).
    /// Returns `false` if replay detected. Atomic across instances via
    /// INSERT ... ON CONFLICT DO NOTHING.
    pub async fn check_and_record(&self, signature_hex: &str, address: &str, action: &str) -> bool {
        let prefix = if signature_hex.len() > 64 {
            &signature_hex[..64]
        } else {
            signature_hex
        };

        self.db
            .check_and_record_signature(prefix, address, action)
            .await
            .unwrap_or(false)
    }

    /// Remove entries older than retention window.
    pub async fn cleanup(&self) {
        let _ = self.db.cleanup_used_signatures(self.retention_secs).await;
    }
}

// ── Combined security middleware ───────────────────────────────────────────

/// Combined security middleware: IP ban check + global rate limit + per-IP rate limit.
/// Applied to all routes (public and protected) as an outer layer.
pub async fn security_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let peer_ip: IpAddr = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

    let ip = extract_real_ip(peer_ip, request.headers());

    // 1. Check IP ban (DB-backed with local cache)
    if state.ip_ban_manager.is_banned(&ip).await {
        warn!("Rejected request from banned IP {}", ip);
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "Forbidden",
                "details": "IP address is banned"
            })),
        )
            .into_response();
    }

    // 2. Check global rate limit (DB-backed, shared across instances)
    if !state.global_rate_limiter.check().await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "Service overloaded",
                "details": "Global rate limit exceeded — try again shortly"
            })),
        )
            .into_response();
    }

    // 3. Check per-IP rate limit (DB-backed, shared across instances)
    if !state.per_ip_rate_limiter.check(ip).await {
        warn!("Per-IP rate limit exceeded for {}", ip);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "Rate limit exceeded",
                "details": "Too many requests from this IP"
            })),
        )
            .into_response();
    }

    next.run(request).await
}

/// Extract real client IP (trust X-Real-IP/X-Forwarded-For only from loopback).
fn extract_real_ip(peer_ip: IpAddr, headers: &axum::http::HeaderMap) -> IpAddr {
    if !peer_ip.is_loopback() {
        return peer_ip;
    }

    if let Some(val) = headers.get("x-real-ip") {
        if let Ok(s) = val.to_str() {
            if let Ok(ip) = s.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }

    if let Some(val) = headers.get("x-forwarded-for") {
        if let Ok(s) = val.to_str() {
            if let Some(first) = s.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }

    peer_ip
}

fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_real_ip_non_loopback() {
        let peer = "203.0.113.5".parse().unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", "10.0.0.1".parse().unwrap());
        assert_eq!(extract_real_ip(peer, &headers), peer);
    }

    #[test]
    fn test_extract_real_ip_loopback_trusts_header() {
        let peer = "127.0.0.1".parse().unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-real-ip", "203.0.113.42".parse().unwrap());
        assert_eq!(
            extract_real_ip(peer, &headers),
            "203.0.113.42".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_extract_real_ip_loopback_xff() {
        let peer = "127.0.0.1".parse().unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.7, 10.0.0.1".parse().unwrap());
        assert_eq!(
            extract_real_ip(peer, &headers),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_extract_real_ip_loopback_no_headers() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let headers = axum::http::HeaderMap::new();
        assert_eq!(extract_real_ip(peer, &headers), peer);
    }
}
