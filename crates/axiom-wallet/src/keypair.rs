// Copyright (c) 2026 Kantoshi Miyamura

// ML-DSA-87 key pair. Private key never leaves this module; the RPC layer
// only ever sees signed transactions.

use crate::signing::{MlDsa87Backend, SignatureBackend};
use crate::{Result, WalletError};
use axiom_crypto::hash256;
use axiom_primitives::{Hash256, PublicKey, Signature};
use zeroize::Zeroizing;

// 32-byte xi seed (FIPS 204 ML-DSA.KeyGen_internal input — same for all parameter sets).
const ML_DSA_87_SK_BYTES: usize = 32;
const ML_DSA_87_VK_BYTES: usize = 2592;
const ML_DSA_87_SIG_BYTES: usize = 4627;

/// ML-DSA-87 key pair. Private key is zeroized on drop.
#[derive(Clone)]
pub struct KeyPair {
    private_key: Zeroizing<Vec<u8>>,
    public_key: Vec<u8>,
}

impl KeyPair {
    /// Generate a new random ML-DSA-87 key pair from OS entropy.
    pub fn generate() -> Result<Self> {
        let b = MlDsa87Backend;
        let (priv_key, pub_key) = b.generate_random_keypair()?;
        Ok(KeyPair {
            private_key: priv_key,
            public_key: pub_key,
        })
    }

    /// Construct from a private key seed, deriving the public key deterministically.
    pub fn from_private_key(private_key: Vec<u8>) -> Result<Self> {
        let b = MlDsa87Backend;
        let pub_key = b.public_key_from_private(&private_key)?;
        Ok(KeyPair {
            private_key: Zeroizing::new(private_key),
            public_key: pub_key,
        })
    }

    /// Reconstruct from both key halves (e.g. restored from keystore). Validates lengths.
    pub fn from_key_bytes(private_key: Vec<u8>, public_key: Vec<u8>) -> Result<Self> {
        if private_key.len() != ML_DSA_87_SK_BYTES {
            return Err(WalletError::InvalidPrivateKey);
        }
        if public_key.len() != ML_DSA_87_VK_BYTES {
            return Err(WalletError::InvalidPublicKey);
        }
        Ok(KeyPair {
            private_key: Zeroizing::new(private_key),
            public_key,
        })
    }

    /// Like [`from_key_bytes`] but accepts a pre-wrapped `Zeroizing<Vec<u8>>`,
    /// avoiding an intermediate non-zeroized copy of the private key.
    pub(crate) fn from_key_bytes_zeroized(
        private_key: Zeroizing<Vec<u8>>,
        public_key: Vec<u8>,
    ) -> Result<Self> {
        if private_key.len() != ML_DSA_87_SK_BYTES {
            return Err(WalletError::InvalidPrivateKey);
        }
        if public_key.len() != ML_DSA_87_VK_BYTES {
            return Err(WalletError::InvalidPublicKey);
        }
        Ok(KeyPair {
            private_key,
            public_key,
        })
    }

    /// Export raw private key bytes. Do not log, transmit, or store in plaintext.
    pub fn export_private_key(&self) -> &[u8] {
        &self.private_key
    }

    /// Public key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Public key as a typed [`PublicKey`].
    pub fn public_key_struct(&self) -> Result<PublicKey> {
        if self.public_key.len() == ML_DSA_87_VK_BYTES {
            Ok(PublicKey::from_slice(&self.public_key)?)
        } else {
            Err(WalletError::InvalidPublicKey)
        }
    }

    /// Hash of the public key — used as the address payload.
    pub fn public_key_hash(&self) -> Hash256 {
        hash256(&self.public_key)
    }

    /// Sign `message` bytes. Returns raw signature bytes.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        MlDsa87Backend.sign(&self.private_key, message)
    }

    /// Sign `message` and return as a typed [`Signature`].
    pub fn sign_struct(&self, message: &[u8]) -> Result<Signature> {
        let sig_bytes = self.sign(message)?;
        if sig_bytes.len() == ML_DSA_87_SIG_BYTES {
            Ok(Signature::from_slice(&sig_bytes)?)
        } else {
            Err(WalletError::SignatureVerificationFailed)
        }
    }

    /// Verify a signature against this key pair's public key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        match MlDsa87Backend.verify(&self.public_key, message, signature) {
            Ok(()) => Ok(true),
            Err(WalletError::SignatureVerificationFailed) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &hex::encode(&self.public_key))
            .field("private_key", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_lengths() {
        let kp = KeyPair::generate().unwrap();
        assert_eq!(kp.private_key.len(), ML_DSA_87_SK_BYTES);
        assert_eq!(kp.public_key.len(), ML_DSA_87_VK_BYTES);
    }

    #[test]
    fn sign_and_verify() {
        let kp = KeyPair::generate().unwrap();
        let msg = b"test message";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn wrong_message_rejected() {
        let kp = KeyPair::generate().unwrap();
        let sig = kp.sign(b"real").unwrap();
        assert!(!kp.verify(b"fake", &sig).unwrap());
    }

    #[test]
    fn public_key_deterministic() {
        let kp = KeyPair::generate().unwrap();
        assert_eq!(kp.public_key_hash(), kp.public_key_hash());
    }

    #[test]
    fn from_private_key_derives_correct_public_key() {
        let kp1 = KeyPair::generate().unwrap();
        let priv_bytes = kp1.export_private_key().to_vec();
        let kp2 = KeyPair::from_private_key(priv_bytes).unwrap();
        assert_eq!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn from_key_bytes_roundtrip() {
        let kp = KeyPair::generate().unwrap();
        let kp2 =
            KeyPair::from_key_bytes(kp.export_private_key().to_vec(), kp.public_key().to_vec())
                .unwrap();
        let msg = b"hello";
        let sig = kp2.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn debug_redacts_private_key() {
        let kp = KeyPair::generate().unwrap();
        let s = format!("{:?}", kp);
        assert!(s.contains("<redacted>"));
        assert!(!s.contains(hex::encode(kp.export_private_key()).as_str()));
    }
}
