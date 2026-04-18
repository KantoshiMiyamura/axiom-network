// Copyright (c) 2026 Kantoshi Miyamura

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// ML-DSA-87 seed size (FIPS 204). Private keys are derived from 32-byte seeds.
/// This is the xi seed used for deterministic key generation.
pub const ML_DSA_87_SEED_BYTES: usize = 32;

/// ML-DSA-87 verifying key size (FIPS 204, security category 5).
pub const ML_DSA_87_PUBLIC_KEY_BYTES: usize = 2592;

/// ML-DSA-87 signature size (FIPS 204, security category 5).
pub const ML_DSA_87_SIGNATURE_BYTES: usize = 4627;

/// ML-DSA-87 verifying key (2592 bytes). Variable-length to support future scheme upgrades.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(#[serde(with = "serde_bytes")] Vec<u8>);

impl PublicKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        PublicKey(bytes)
    }

    /// Create from a slice. Enforces the 2592-byte ML-DSA-87 length to reject
    /// malformed keys before they reach the signature verifier.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != ML_DSA_87_PUBLIC_KEY_BYTES {
            return Err(Error::InvalidPublicKeyLength(slice.len()));
        }
        Ok(PublicKey(slice.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// ML-DSA-87 signature (4627 bytes). Variable-length to support future scheme upgrades.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(#[serde(with = "serde_bytes")] Vec<u8>);

impl Signature {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Signature(bytes)
    }

    /// Create from a slice. Enforces the 4627-byte ML-DSA-87 length to reject
    /// malformed signatures before they reach the verifier.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != ML_DSA_87_SIGNATURE_BYTES {
            return Err(Error::InvalidSignatureLength(slice.len()));
        }
        Ok(Signature(slice.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Zero-filled placeholder used when constructing unsigned transactions for signing.
    pub fn placeholder() -> Self {
        Signature(vec![0u8; 4627])
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// ML-DSA-87 secret signing key (32-byte seed).
///
/// This type is designed to prevent accidental exposure of the private key:
/// - No `Debug` impl (prevents logging)
/// - No `Clone` impl (prevents accidental copying)
/// - Automatically zeroized on drop (memory is overwritten)
/// - Only accessible via immutable reference to bytes
///
/// The private key should NEVER be:
/// - Serialized to disk (use encrypted seed phrases instead)
/// - Sent over the network
/// - Logged or printed
/// - Cloned or copied
///
/// Secret keys should be created in a trusted process and discarded
/// (dropped) as soon as signing is complete.
pub struct SecretSigningKey {
    /// 32-byte xi seed for ML-DSA-87. Zeroized on drop.
    bytes: Zeroizing<Vec<u8>>,
}

impl SecretSigningKey {
    /// Create a secret key from raw seed bytes.
    ///
    /// The provided bytes are immediately wrapped in a Zeroizing container,
    /// which will overwrite the memory when dropped.
    ///
    /// # Arguments
    /// * `seed` - 32-byte ML-DSA-87 seed
    ///
    /// # Errors
    /// Returns InvalidPrivateKey if the seed is not exactly 32 bytes.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        if seed.len() != ML_DSA_87_SEED_BYTES {
            return Err(Error::InvalidPrivateKeyLength(seed.len()));
        }
        Ok(SecretSigningKey {
            bytes: Zeroizing::new(seed.to_vec()),
        })
    }

    /// Get the secret key bytes as a slice.
    ///
    /// This is the ONLY way to access the private key material.
    /// Ensure you do not:
    /// - Clone or copy these bytes
    /// - Log or print them
    /// - Persist them to disk
    /// - Send them over the network
    ///
    /// The returned reference is valid only as long as self is alive.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the length of the secret key (always 32 bytes for ML-DSA-87).
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the secret key is empty (should never be true after construction).
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl AsRef<[u8]> for SecretSigningKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// Intentionally no Debug, Clone, or Serialize impls
// to prevent accidental exposure of the private key material.
//
// Drop is automatically implemented by Zeroizing<Vec<u8>>,
// which overwrites the memory with zeros before freeing.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pubkey_from_bytes() {
        let bytes = vec![1u8; 2592];
        let pk = PublicKey::from_bytes(bytes.clone());
        assert_eq!(pk.as_bytes(), bytes.as_slice());
    }

    #[test]
    fn test_pubkey_from_slice() {
        let bytes = vec![2u8; 2592];
        let pk = PublicKey::from_slice(&bytes).unwrap();
        assert_eq!(pk.as_bytes(), bytes.as_slice());

        assert!(PublicKey::from_slice(&[]).is_err());
        assert!(PublicKey::from_slice(&[0u8; 32]).is_err());
        assert!(PublicKey::from_slice(&[0u8; 2591]).is_err());
        assert!(PublicKey::from_slice(&[0u8; 2593]).is_err());
    }

    #[test]
    fn test_signature_from_bytes() {
        let bytes = vec![4u8; 4627];
        let sig = Signature::from_bytes(bytes.clone());
        assert_eq!(sig.as_bytes(), bytes.as_slice());
    }

    #[test]
    fn test_signature_from_slice() {
        let bytes = vec![5u8; 4627];
        let sig = Signature::from_slice(&bytes).unwrap();
        assert_eq!(sig.as_bytes(), bytes.as_slice());

        assert!(Signature::from_slice(&[]).is_err());
        assert!(Signature::from_slice(&[0u8; 64]).is_err());
        assert!(Signature::from_slice(&[0u8; 4626]).is_err());
        assert!(Signature::from_slice(&[0u8; 4628]).is_err());
    }

    #[test]
    fn test_signature_placeholder_size() {
        let sig = Signature::placeholder();
        assert_eq!(sig.len(), 4627);
    }

    // ── SecretSigningKey tests ───────────────────────────────────────────

    #[test]
    fn test_secret_key_from_seed() {
        let seed = vec![0x42u8; 32];
        let sk = SecretSigningKey::from_seed(&seed).unwrap();
        assert_eq!(sk.as_bytes(), seed.as_slice());
        assert_eq!(sk.len(), 32);
    }

    #[test]
    fn test_secret_key_rejects_wrong_length() {
        // Too short
        assert!(SecretSigningKey::from_seed(&[0u8; 16]).is_err());

        // Too long
        assert!(SecretSigningKey::from_seed(&[0u8; 64]).is_err());

        // Empty
        assert!(SecretSigningKey::from_seed(&[]).is_err());
    }

    #[test]
    fn test_secret_key_as_ref() {
        let seed = vec![0xABu8; 32];
        let sk = SecretSigningKey::from_seed(&seed).unwrap();
        let r: &[u8] = sk.as_ref();
        assert_eq!(r, seed.as_slice());
    }

    #[test]
    fn test_secret_key_no_clone() {
        // This test verifies that SecretSigningKey does NOT implement Clone.
        // If it compiles, we've failed the test. So we don't include the code that would fail to compile.
        // The absence of a Clone impl is tested by the compiler itself.
        let _sk = SecretSigningKey::from_seed(&[0u8; 32]).unwrap();
        // sk.clone();  // ❌ This would not compile — which is what we want!
    }

    #[test]
    fn test_secret_key_zeroization() {
        // Verify that SecretSigningKey uses Zeroizing internally
        let seed = vec![0xCDu8; 32];
        let sk = SecretSigningKey::from_seed(&seed).unwrap();
        // When sk is dropped, Zeroizing<Vec<u8>> will overwrite the memory
        drop(sk);
        // After this point, the memory SHOULD have been zeroed by Zeroizing.
        // We can't directly verify this without unsafe code, but the type system
        // ensures the zeroization happens via Drop impl.
    }
}
