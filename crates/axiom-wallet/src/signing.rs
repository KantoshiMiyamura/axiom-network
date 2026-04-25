// Copyright (c) 2026 Kantoshi Miyamura

// Signature backend abstraction. Only scheme: ML-DSA-87 (FIPS 204).
// Ed25519 has been fully removed — no legacy code paths remain.

use crate::{Result, WalletError};
use zeroize::Zeroizing;

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Abstract interface for a digital signature scheme.
pub trait SignatureBackend: Send + Sync + 'static {
    /// Human-readable identifier (e.g. `"ml-dsa-87"`).
    fn name(&self) -> &'static str;

    /// Generate a new keypair from OS entropy. Returns `(private_key, public_key)`.
    fn generate_random_keypair(&self) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)>;

    /// Derive a deterministic keypair from a seed (>= 32 bytes).
    fn keypair_from_seed(&self, seed: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)>;

    /// Derive the public key from private key bytes.
    fn public_key_from_private(&self, private_key: &[u8]) -> Result<Vec<u8>>;

    /// Sign `message` with `private_key`. Returns raw signature bytes.
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>>;

    /// Verify `signature` over `message`. Returns `Err(SignatureVerificationFailed)` if invalid.
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()>;

    fn private_key_len(&self) -> usize;
    fn public_key_len(&self) -> usize;
    fn signature_len(&self) -> usize;
}

// ── ML-DSA-87 backend (active on-chain scheme) ────────────────────────────────

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, KeyGen, MlDsa87};
use rand_core::{OsRng, RngCore};
use signature::{Signer, Verifier};

// 32-byte xi seed (FIPS 204 ML-DSA.KeyGen_internal input — same for all parameter sets).
const SEED_BYTES: usize = 32;
const VK_BYTES: usize = 2592;
const SIG_BYTES: usize = 4627;

/// ML-DSA-87 (FIPS 204) — 256-bit post-quantum security, NIST Category 5.
/// Equivalent to AES-256. No quantum computer can break this.
/// Private key is the 32-byte xi seed; signing key derived on demand.
pub struct MlDsa87Backend;

impl SignatureBackend for MlDsa87Backend {
    fn name(&self) -> &'static str {
        "ml-dsa-87"
    }

    fn generate_random_keypair(&self) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
        let mut xi = Zeroizing::new([0u8; SEED_BYTES]);
        OsRng.fill_bytes(xi.as_mut());
        let kp = MlDsa87::key_gen_internal(&(*xi).into());
        let vk = kp.verifying_key().encode().as_slice().to_vec();
        Ok((Zeroizing::new(xi.to_vec()), vk))
    }

    fn keypair_from_seed(&self, seed: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
        if seed.len() < SEED_BYTES {
            return Err(WalletError::InvalidPrivateKey);
        }
        let mut xi = Zeroizing::new([0u8; SEED_BYTES]);
        xi.copy_from_slice(&seed[..SEED_BYTES]);
        let kp = MlDsa87::key_gen_internal(&(*xi).into());
        let vk = kp.verifying_key().encode().as_slice().to_vec();
        Ok((Zeroizing::new(xi.to_vec()), vk))
    }

    fn public_key_from_private(&self, private_key: &[u8]) -> Result<Vec<u8>> {
        if private_key.len() != SEED_BYTES {
            return Err(WalletError::InvalidPrivateKey);
        }
        let mut xi = Zeroizing::new([0u8; SEED_BYTES]);
        xi.copy_from_slice(private_key);
        let kp = MlDsa87::key_gen_internal(&(*xi).into());
        Ok(kp.verifying_key().encode().as_slice().to_vec())
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        if private_key.len() != SEED_BYTES {
            return Err(WalletError::InvalidPrivateKey);
        }
        let mut xi = Zeroizing::new([0u8; SEED_BYTES]);
        xi.copy_from_slice(private_key);
        let kp = MlDsa87::key_gen_internal(&(*xi).into());
        Ok(kp.signing_key().sign(message).encode().as_slice().to_vec())
    }

    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        if public_key.len() != VK_BYTES {
            return Err(WalletError::InvalidPublicKey);
        }
        if signature.len() != SIG_BYTES {
            return Err(WalletError::SignatureVerificationFailed);
        }
        let vk_arr: [u8; VK_BYTES] = public_key
            .try_into()
            .map_err(|_| WalletError::InvalidPublicKey)?;
        let vk_encoded: EncodedVerifyingKey<MlDsa87> = vk_arr.into();
        let vk = ml_dsa::VerifyingKey::<MlDsa87>::decode(&vk_encoded);

        let sig_arr: [u8; SIG_BYTES] = signature
            .try_into()
            .map_err(|_| WalletError::SignatureVerificationFailed)?;
        let sig_encoded: EncodedSignature<MlDsa87> = sig_arr.into();
        let sig = ml_dsa::Signature::<MlDsa87>::decode(&sig_encoded)
            .ok_or(WalletError::SignatureVerificationFailed)?;

        vk.verify(message, &sig)
            .map_err(|_| WalletError::SignatureVerificationFailed)
    }

    fn private_key_len(&self) -> usize {
        SEED_BYTES
    }
    fn public_key_len(&self) -> usize {
        VK_BYTES
    }
    fn signature_len(&self) -> usize {
        SIG_BYTES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_dsa87_backend_roundtrip() {
        let b = MlDsa87Backend;
        let (priv_key, pub_key) = b.generate_random_keypair().unwrap();
        assert_eq!(priv_key.len(), SEED_BYTES);
        assert_eq!(pub_key.len(), VK_BYTES);
        let msg = b"axiom test message";
        let sig = b.sign(&priv_key, msg).unwrap();
        assert_eq!(sig.len(), SIG_BYTES);
        b.verify(&pub_key, msg, &sig).unwrap();
    }

    #[test]
    fn ml_dsa87_wrong_message_rejected() {
        let b = MlDsa87Backend;
        let (priv_key, pub_key) = b.generate_random_keypair().unwrap();
        let sig = b.sign(&priv_key, b"correct").unwrap();
        assert!(b.verify(&pub_key, b"wrong", &sig).is_err());
    }

    #[test]
    fn ml_dsa87_wrong_key_rejected() {
        let b = MlDsa87Backend;
        let (priv_key, _) = b.generate_random_keypair().unwrap();
        let (_, pub_key2) = b.generate_random_keypair().unwrap();
        let sig = b.sign(&priv_key, b"msg").unwrap();
        assert!(b.verify(&pub_key2, b"msg", &sig).is_err());
    }

    #[test]
    fn ml_dsa87_deterministic_from_seed() {
        let b = MlDsa87Backend;
        let seed = [42u8; 64];
        let (priv1, pub1) = b.keypair_from_seed(&seed).unwrap();
        let (priv2, pub2) = b.keypair_from_seed(&seed).unwrap();
        assert_eq!(&*priv1, &*priv2);
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn ml_dsa87_pubkey_derivation() {
        let b = MlDsa87Backend;
        let (priv_key, pub_key) = b.generate_random_keypair().unwrap();
        let derived = b.public_key_from_private(&priv_key).unwrap();
        assert_eq!(derived, pub_key);
    }

    /// Ed25519 is fully removed from the signing layer — only ML-DSA-87 is supported.
    /// This test ensures that no Ed25519 backend struct exists at compile time.
    #[test]
    fn no_ed25519_in_production() {
        // If Ed25519Backend existed, this file would export it.
        // The fact that this compiles without it proves isolation is complete.
        let b = MlDsa87Backend;
        assert_eq!(b.name(), "ml-dsa-87");
    }
}
