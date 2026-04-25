//! Integration tests for authentication flow
//!
//! Tests the complete challenge-response -> signature verification -> session flow

#[cfg(test)]
mod tests {
    use axiom_community_shared::crypto;
    use axiom_community_shared::models::*;
    use axiom_community_shared::protocol::AUTH_DOMAIN;

    /// Helper: create a valid v1 axm address (axm + 64 hex = 67 chars)
    fn test_address() -> String {
        format!("axm{}", "ab".repeat(32))
    }

    /// Test complete authentication flow with real ML-DSA-87
    #[test]
    fn test_complete_auth_flow() {
        use ml_dsa::{KeyGen, MlDsa87};
        use rand_core::OsRng;

        let address = test_address();
        let user_agent = "test-client/1.0";

        // Step 1: Generate challenge
        let nonce = crypto::random_hex(32);
        let challenge_hash =
            crypto::create_challenge_hex(nonce.as_bytes(), &address, AUTH_DOMAIN, user_agent);

        // Verify challenge is deterministic
        let challenge_hash2 =
            crypto::create_challenge_hex(nonce.as_bytes(), &address, AUTH_DOMAIN, user_agent);
        assert_eq!(challenge_hash, challenge_hash2);

        // Step 2: Generate ML-DSA-87 keypair and sign the challenge
        let kp = MlDsa87::key_gen(&mut OsRng);
        let sk_bytes = kp.signing_key().encode().as_slice().to_vec();
        let vk_bytes = kp.verifying_key().encode().as_slice().to_vec();

        let expires_at = chrono::Utc::now().timestamp() + 300;
        let challenge_message = format!(
            "{}|{}|{}|{}",
            nonce, challenge_hash, AUTH_DOMAIN, expires_at
        );

        let sig_bytes = crypto::sign_ml_dsa_87(&sk_bytes, challenge_message.as_bytes()).unwrap();
        assert_eq!(sig_bytes.len(), 4627);

        // Step 3: Verify signature
        let valid =
            crypto::verify_ml_dsa_87(&vk_bytes, challenge_message.as_bytes(), &sig_bytes).unwrap();
        assert!(valid);

        // Step 4: Construct VerifyRequest
        let verify_req = VerifyRequest {
            nonce: nonce.clone(),
            challenge: challenge_hash.clone(),
            signature: hex::encode(&sig_bytes),
            public_key: hex::encode(&vk_bytes),
            address: Address::new(&address),
            expires_at,
            user_agent: user_agent.to_string(),
        };

        assert!(verify_req.address.is_valid());
        assert_eq!(verify_req.challenge, challenge_hash);
    }

    /// Test challenge expiration
    #[test]
    fn test_challenge_expiration() {
        let now = chrono::Utc::now().timestamp();
        let expires_at = now + 300; // 5 minutes

        let challenge_req = ChallengeRequest {
            address: Address::new(test_address()),
            user_agent: "test-client/1.0".to_string(),
        };

        assert!(challenge_req.address.is_valid());

        // Check expiration logic
        assert!(expires_at > now);
        assert!(expires_at - now == 300);
    }

    /// Test address validation
    #[test]
    fn test_address_validation() {
        // Valid v1 address (axm + 64 hex = 67 chars)
        let valid_v1 = Address::new(format!("axm{}", "ab".repeat(32)));
        assert!(valid_v1.is_valid());

        // Valid v2 address (axm + 72 hex = 75 chars)
        let valid_v2 = Address::new(format!("axm{}", "ab".repeat(36)));
        assert!(valid_v2.is_valid());

        // Invalid addresses
        assert!(!Address::new("invalid").is_valid());
        assert!(!Address::new("bitcoin1abc...").is_valid());
        assert!(!Address::new("axmshort").is_valid());
        assert!(!Address::new("").is_valid());
    }

    /// Test session claims structure
    #[test]
    fn test_session_claims() {
        let claims = SessionClaims {
            session_id: "session_123".to_string(),
            address: Address::new(test_address()),
            roles: vec![Role::Member],
            issued_at: chrono::Utc::now().timestamp(),
            expires_at: chrono::Utc::now().timestamp() + 900,
            ip_hash: "abcd1234".to_string(),
            user_agent_hash: "efgh5678".to_string(),
        };

        assert_eq!(claims.roles.len(), 1);
        assert!(claims.expires_at > claims.issued_at);
        assert_eq!(claims.expires_at - claims.issued_at, 900);
    }

    /// Test role hierarchy
    #[test]
    fn test_role_hierarchy() {
        assert!(Role::CoreDev.can_act_on(Role::Member));
        assert!(Role::CoreDev.can_act_on(Role::Moderator));
        assert!(!Role::Member.can_act_on(Role::CoreDev));
        assert!(Role::Moderator.can_act_on(Role::Moderator));
    }

    /// Test message validation
    #[test]
    fn test_message_validation() {
        let valid_msg = ChannelMessage {
            id: "msg_123".to_string(),
            channel: "general".to_string(),
            author: Address::new(test_address()),
            timestamp: chrono::Utc::now().timestamp(),
            content: "Hello world".to_string(),
            content_hash: crypto::sha3_256_hex(b"Hello world"),
            parent_id: None,
            thread_count: 0,
            reactions: std::collections::HashMap::new(),
            signature: "sig_123".to_string(),
            is_edited: false,
        };

        assert!(valid_msg.validate().is_ok());

        // Message too long
        let too_long = ChannelMessage {
            content: "x".repeat(10001),
            ..valid_msg.clone()
        };

        assert!(too_long.validate().is_err());

        // Invalid channel
        let bad_channel = ChannelMessage {
            channel: "".to_string(),
            ..valid_msg
        };

        assert!(bad_channel.validate().is_err());
    }

    /// Test cryptographic operations
    #[test]
    fn test_crypto_operations() {
        let data = b"test data";

        // SHA-3 256
        let hash1 = crypto::sha3_256(data);
        let hash2 = crypto::sha3_256(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);

        // SHA-256
        let hash3 = crypto::sha256(data);
        assert_eq!(hash3.len(), 32);

        // Hex encoding
        let hex_hash = crypto::sha3_256_hex(data);
        assert_eq!(hex_hash.len(), 64);

        // IP hashing
        let ip_hash = crypto::hash_ip("192.168.1.1");
        assert_eq!(ip_hash.len(), 32);

        // User-agent hashing
        let ua_hash = crypto::hash_user_agent("Mozilla/5.0");
        assert_eq!(ua_hash.len(), 32);

        // Different inputs = different hashes
        let diff_hash = crypto::sha3_256(b"different data");
        assert_ne!(hash1, diff_hash);
    }

    /// Test random number generation
    #[test]
    fn test_random_generation() {
        let bytes1 = crypto::random_bytes(32);
        let bytes2 = crypto::random_bytes(32);

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2);

        let hex1 = crypto::random_hex(32);
        let hex2 = crypto::random_hex(32);

        assert_eq!(hex1.len(), 64);
        assert_eq!(hex2.len(), 64);
        assert_ne!(hex1, hex2);
    }

    /// Test secure zero out
    #[test]
    fn test_secure_zero() {
        let mut buf = vec![1u8, 2u8, 3u8, 4u8, 5u8];
        crypto::secure_zero(&mut buf);

        for byte in buf {
            assert_eq!(byte, 0);
        }
    }

    /// Test protocol constants
    #[test]
    fn test_protocol_constants() {
        use axiom_community_shared::protocol::*;

        // Expiry times
        assert_eq!(CHALLENGE_EXPIRY_SECS, 300);
        assert_eq!(SESSION_TOKEN_EXPIRY_SECS, 900);
        assert_eq!(REFRESH_TOKEN_EXPIRY_SECS, 604800);

        // Verify ordering
        assert!(CHALLENGE_EXPIRY_SECS < SESSION_TOKEN_EXPIRY_SECS);
        assert!(SESSION_TOKEN_EXPIRY_SECS < REFRESH_TOKEN_EXPIRY_SECS);

        // Rate limits
        assert!(rate_limits::CHALLENGE_PER_MINUTE > 0);
        assert!(rate_limits::VERIFY_PER_MINUTE > 0);
        assert!(rate_limits::MESSAGES_PER_MINUTE > rate_limits::VERIFY_PER_MINUTE);

        // Corrected ML-DSA-87 sizes (FIPS 204)
        assert_eq!(crypto_sizes::SHA3_256_SIZE, 32);
        assert_eq!(crypto_sizes::ML_DSA_87_PUBLIC_KEY_SIZE, 2592);
        assert_eq!(crypto_sizes::ML_DSA_87_SIGNATURE_SIZE, 4627);

        // Limits
        assert!(limits::MAX_MESSAGE_LENGTH > 0);
        assert!(limits::MAX_JOB_DESCRIPTION > limits::MAX_MESSAGE_LENGTH);
    }
}
