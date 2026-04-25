//! Cryptographic utilities for Axiom Community Platform
//!
//! Provides:
//! - SHA-3-256 hashing for challenges
//! - SHA-256 for fingerprints
//! - Random number generation
//! - Challenge generation and verification
//! - ML-DSA-87 (FIPS 204) signing and verification

use crate::error::Result;
use crate::{models::*, Error};
use hex::{decode as hex_decode, encode as hex_encode};
use ml_dsa::{EncodedSignature, EncodedSigningKey, EncodedVerifyingKey, MlDsa87};
use rand::Rng;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use signature::{Signer, Verifier};

/// Generate random bytes
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..n).map(|_| rng.gen::<u8>()).collect()
}

/// Generate random hex string
pub fn random_hex(n: usize) -> String {
    hex_encode(random_bytes(n))
}

/// SHA-3-256 hash (32 bytes)
pub fn sha3_256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// SHA-3-256 hash as hex string
pub fn sha3_256_hex(data: &[u8]) -> String {
    hex_encode(sha3_256(data))
}

/// SHA-256 hash (32 bytes)
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// SHA-256 hash as hex string
pub fn sha256_hex(data: &[u8]) -> String {
    hex_encode(sha256(data))
}

/// Create authentication challenge
///
/// Challenge = SHA-3(nonce || address || domain || user_agent)
pub fn create_challenge(nonce: &[u8], address: &str, domain: &str, user_agent: &str) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(nonce);
    data.extend_from_slice(address.as_bytes());
    data.extend_from_slice(domain.as_bytes());
    data.extend_from_slice(user_agent.as_bytes());
    sha3_256(&data)
}

/// Create authentication challenge as hex string
pub fn create_challenge_hex(nonce: &[u8], address: &str, domain: &str, user_agent: &str) -> String {
    hex_encode(create_challenge(nonce, address, domain, user_agent))
}

/// Hash an IP address (first 16 bytes for binding)
pub fn hash_ip(ip: &str) -> String {
    let hash = sha256(ip.as_bytes());
    hex_encode(&hash[..16])
}

/// Hash a user-agent (first 16 bytes for binding)
pub fn hash_user_agent(ua: &str) -> String {
    let hash = sha256(ua.as_bytes());
    hex_encode(&hash[..16])
}

/// ML-DSA-87 key/signature sizes (FIPS 204, Category 5)
pub const ML_DSA_87_VK_BYTES: usize = 2592;
pub const ML_DSA_87_SK_BYTES: usize = 4896;
pub const ML_DSA_87_SIG_BYTES: usize = 4627;

/// Verify ML-DSA-87 signature (FIPS 204, Category 5 — 256-bit post-quantum security).
///
/// Parameters:
/// - public_key: Raw verifying key bytes (2592 bytes for ML-DSA-87)
/// - message: The message that was signed (raw bytes, not pre-hashed)
/// - signature: Signature bytes (4627 bytes for ML-DSA-87)
///
/// Returns: Ok(true) if signature is valid, Ok(false) if invalid
pub fn verify_ml_dsa_87(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    if public_key.len() != ML_DSA_87_VK_BYTES {
        return Err(Error::crypto(format!(
            "ML-DSA-87 public key must be {} bytes, got {}",
            ML_DSA_87_VK_BYTES,
            public_key.len()
        )));
    }
    if signature.len() != ML_DSA_87_SIG_BYTES {
        return Err(Error::crypto(format!(
            "ML-DSA-87 signature must be {} bytes, got {}",
            ML_DSA_87_SIG_BYTES,
            signature.len()
        )));
    }

    let vk_arr: [u8; 2592] = public_key
        .try_into()
        .map_err(|_| Error::crypto("Invalid public key length"))?;
    let vk_encoded: EncodedVerifyingKey<MlDsa87> = vk_arr.into();
    let vk = ml_dsa::VerifyingKey::<MlDsa87>::decode(&vk_encoded);

    let sig_arr: [u8; 4627] = signature
        .try_into()
        .map_err(|_| Error::crypto("Invalid signature length"))?;
    let sig_encoded: EncodedSignature<MlDsa87> = sig_arr.into();
    let sig = ml_dsa::Signature::<MlDsa87>::decode(&sig_encoded)
        .ok_or_else(|| Error::crypto("Failed to decode ML-DSA-87 signature"))?;

    match vk.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Sign a message with an ML-DSA-87 signing key (FIPS 204, Category 5).
///
/// Parameters:
/// - private_key: ML-DSA-87 signing key (4896 bytes, the full expanded key)
/// - message: Message to sign (raw bytes)
///
/// Returns: Signature bytes (4627 bytes)
pub fn sign_ml_dsa_87(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    if private_key.len() != ML_DSA_87_SK_BYTES {
        return Err(Error::crypto(format!(
            "ML-DSA-87 signing key must be {} bytes, got {}",
            ML_DSA_87_SK_BYTES,
            private_key.len()
        )));
    }

    let sk_arr: [u8; 4896] = private_key
        .try_into()
        .map_err(|_| Error::crypto("Invalid signing key length"))?;
    let sk_encoded: EncodedSigningKey<MlDsa87> = sk_arr.into();
    let sk = ml_dsa::SigningKey::<MlDsa87>::decode(&sk_encoded);
    let sig = sk.sign(message);
    Ok(sig.encode().as_slice().to_vec())
}

/// Verify challenge signature
///
/// Reconstructs the message that was signed and verifies the signature.
/// ML-DSA-87 signs the raw message (not a pre-hash), so we pass the
/// canonical challenge string directly to the verifier.
///
/// Domain separation: prefixed with "axiom-community-auth:" to prevent
/// cross-protocol replay attacks. A community auth signature cannot be
/// replayed against the RPC layer or on-chain transactions.
pub fn verify_challenge_signature(
    public_key: &[u8],
    nonce: &str,
    challenge: &str,
    domain: &str,
    expires_at: i64,
    signature_hex: &str,
) -> Result<bool> {
    // Reconstruct the message that should have been signed (with domain separation prefix)
    let message = format!(
        "axiom-community-auth:{}|{}|{}|{}",
        nonce, challenge, domain, expires_at,
    );

    let signature = hex_decode(signature_hex)
        .map_err(|e| Error::crypto(format!("Invalid signature hex: {}", e)))?;

    verify_ml_dsa_87(public_key, message.as_bytes(), &signature)
}

/// Secure zero out a buffer (for sensitive data)
pub fn secure_zero(buf: &mut [u8]) {
    for byte in buf {
        *byte = 0u8;
    }
}

// ============================================================================
// Serialization Helpers
// ============================================================================

/// Hash a JSON value
pub fn hash_json(value: &serde_json::Value) -> Result<String> {
    let json_str = serde_json::to_string(value)?;
    Ok(sha3_256_hex(json_str.as_bytes()))
}

/// Create a JWT claim
pub fn create_jwt_payload(claims: &SessionClaims) -> Result<String> {
    Ok(serde_json::to_string(claims)?)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes() {
        let bytes1 = random_bytes(32);
        let bytes2 = random_bytes(32);

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        // Should be different (with extremely high probability)
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_random_hex() {
        let hex1 = random_hex(16);
        let hex2 = random_hex(16);

        assert_eq!(hex1.len(), 32); // 16 bytes = 32 hex chars
        assert_eq!(hex2.len(), 32);
        assert_ne!(hex1, hex2);

        // Valid hex
        assert!(hex_decode(&hex1).is_ok());
    }

    #[test]
    fn test_sha3_256() {
        let data = b"test data";
        let hash1 = sha3_256(data);
        let hash2 = sha3_256(data);

        assert_eq!(hash1.len(), 32);
        assert_eq!(hash1, hash2); // Deterministic

        // Different input -> different hash
        let hash3 = sha3_256(b"different data");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_sha256() {
        let data = b"test data";
        let hash1 = sha256(data);
        let hash2 = sha256(data);

        assert_eq!(hash1.len(), 32);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_create_challenge() {
        let nonce = b"test_nonce";
        let address = "axiom1test123";
        let domain = "axiom.community.v1";
        let ua = "test-client/1.0";

        let challenge = create_challenge(nonce, address, domain, ua);
        assert_eq!(challenge.len(), 32);

        // Deterministic
        let challenge2 = create_challenge(nonce, address, domain, ua);
        assert_eq!(challenge, challenge2);

        // Different inputs -> different challenge
        let challenge3 = create_challenge(b"different_nonce", address, domain, ua);
        assert_ne!(challenge, challenge3);
    }

    #[test]
    fn test_hash_ip() {
        let ip = "192.168.1.1";
        let hash = hash_ip(ip);

        assert_eq!(hash.len(), 32); // 16 bytes in hex

        // Deterministic
        let hash2 = hash_ip(ip);
        assert_eq!(hash, hash2);

        // Different IP
        let hash3 = hash_ip("10.0.0.1");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_hash_user_agent() {
        let ua = "axiom-cli/1.0";
        let hash = hash_user_agent(ua);

        assert_eq!(hash.len(), 32);

        // Deterministic
        let hash2 = hash_user_agent(ua);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_ml_dsa_87_roundtrip() {
        use ml_dsa::{KeyGen, MlDsa87};
        use rand_core::OsRng;

        let kp = MlDsa87::key_gen(&mut OsRng);
        let sk_bytes = kp.signing_key().encode().as_slice().to_vec();
        let vk_bytes = kp.verifying_key().encode().as_slice().to_vec();

        assert_eq!(sk_bytes.len(), ML_DSA_87_SK_BYTES);
        assert_eq!(vk_bytes.len(), ML_DSA_87_VK_BYTES);

        let message = b"axiom community test message";
        let sig = sign_ml_dsa_87(&sk_bytes, message).unwrap();
        assert_eq!(sig.len(), ML_DSA_87_SIG_BYTES);

        let valid = verify_ml_dsa_87(&vk_bytes, message, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_ml_dsa_87_wrong_message_rejected() {
        use ml_dsa::{KeyGen, MlDsa87};
        use rand_core::OsRng;

        let kp = MlDsa87::key_gen(&mut OsRng);
        let sk_bytes = kp.signing_key().encode().as_slice().to_vec();
        let vk_bytes = kp.verifying_key().encode().as_slice().to_vec();

        let sig = sign_ml_dsa_87(&sk_bytes, b"correct message").unwrap();
        let valid = verify_ml_dsa_87(&vk_bytes, b"wrong message", &sig).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_ml_dsa_87_wrong_key_rejected() {
        use ml_dsa::{KeyGen, MlDsa87};
        use rand_core::OsRng;

        let kp1 = MlDsa87::key_gen(&mut OsRng);
        let kp2 = MlDsa87::key_gen(&mut OsRng);
        let sk_bytes = kp1.signing_key().encode().as_slice().to_vec();
        let vk2_bytes = kp2.verifying_key().encode().as_slice().to_vec();

        let sig = sign_ml_dsa_87(&sk_bytes, b"test").unwrap();
        let valid = verify_ml_dsa_87(&vk2_bytes, b"test", &sig).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_ml_dsa_87_size_validation() {
        // Wrong public key size
        assert!(verify_ml_dsa_87(&[0u8; 100], b"message", &[0u8; 4627]).is_err());

        // Wrong signature size
        assert!(verify_ml_dsa_87(&[0u8; 2592], b"message", &[0u8; 100]).is_err());

        // Wrong signing key size
        assert!(sign_ml_dsa_87(&[0u8; 100], b"message").is_err());
    }

    #[test]
    fn test_secure_zero() {
        let mut buf = vec![1u8, 2u8, 3u8, 4u8];
        secure_zero(&mut buf);
        assert_eq!(buf, vec![0u8, 0u8, 0u8, 0u8]);
    }

    #[test]
    fn test_hash_json() {
        let json = serde_json::json!({
            "address": "axiom1test",
            "roles": ["member"],
        });

        let hash1 = hash_json(&json).unwrap();
        let hash2 = hash_json(&json).unwrap();

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // 32 bytes in hex
    }
}
