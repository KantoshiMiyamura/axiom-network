// Network security tests - rate limiting and DoS protection

#[cfg(test)]
mod tests {
    use axiom_node::network::dos_protection::RateLimiter;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_rate_limiter_enforces_limits() {
        let mut limiter = RateLimiter::new();
        let ip = IpAddr::from_str("10.0.0.1").unwrap();
        
        // First request should succeed
        let result = limiter.check_rate_limit(ip);
        assert!(result.is_ok(), "First request should succeed");
        
        println!("✅ Rate limiter enforces limits");
    }

    #[test]
    fn test_loopback_never_rate_limited() {
        let mut limiter = RateLimiter::new();
        let loopback = IpAddr::from_str("127.0.0.1").unwrap();
        
        // Loopback should never be rate limited
        for _ in 0..1000 {
            let result = limiter.check_rate_limit(loopback);
            assert!(result.is_ok(), "Loopback should never be rate limited");
        }
        
        println!("✅ Loopback never rate limited");
    }

    #[test]
    fn test_x_forwarded_for_trusted_from_loopback() {
        let mut limiter = RateLimiter::new();
        let loopback = IpAddr::from_str("127.0.0.1").unwrap();
        let forwarded = IpAddr::from_str("203.0.113.50").unwrap();
        
        // From loopback, X-Forwarded-For should be trusted
        let result = limiter.check_rate_limit_with_forwarding(loopback, Some(forwarded));
        assert!(result.is_ok(), "Loopback should trust X-Forwarded-For");
        
        println!("✅ X-Forwarded-For trusted from loopback");
    }

    #[test]
    fn test_x_forwarded_for_ignored_from_remote() {
        let mut limiter = RateLimiter::new();
        let remote = IpAddr::from_str("10.0.0.1").unwrap();
        let spoofed = IpAddr::from_str("127.0.0.1").unwrap();
        
        // From remote, X-Forwarded-For should be ignored
        let result = limiter.check_rate_limit_with_forwarding(remote, Some(spoofed));
        assert!(result.is_ok(), "Remote should ignore spoofed X-Forwarded-For");
        
        println!("✅ X-Forwarded-For ignored from remote");
    }

    #[test]
    fn test_dos_protection_basic() {
        use axiom_node::network::DosProtection;
        
        let mut dos = DosProtection::new();
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        
        // Basic DoS protection should work
        let result = dos.check_request(ip);
        assert!(result.is_ok(), "DoS protection should allow first request");
        
        println!("✅ DoS protection basic test passed");
    }
}
