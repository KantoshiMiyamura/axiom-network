// Copyright (c) 2026 Kantoshi Miyamura

use crate::{Error, Result};
use axiom_primitives::{PublicKey, Signature};

// ML-DSA-87 (FIPS 204) — post-quantum signature scheme.
// Security: 256-bit post-quantum (Category 5 — highest NIST level), classical 256-bit.
// Equivalent to AES-256 security. Resists all known quantum attacks.
use ml_dsa::{EncodedSignature, EncodedSigningKey, EncodedVerifyingKey, KeyGen, MlDsa87};
use rand_core::OsRng;
use signature::{Signer, Verifier};

/// ML-DSA-87 key sizes (FIPS 204, security category 5).
pub const ML_DSA_87_SK_BYTES: usize = 4896;
pub const ML_DSA_87_VK_BYTES: usize = 2592;
pub const ML_DSA_87_SIG_BYTES: usize = 4627;

/// Generate a new ML-DSA-87 keypair using OS entropy.
///
/// Returns `(signing_key_bytes, verifying_key_bytes)`.
/// Signing key: 4896 bytes. Verifying key: 2592 bytes.
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let kp = MlDsa87::key_gen(&mut OsRng);
    let sk = kp.signing_key().encode().as_slice().to_vec();
    let vk = kp.verifying_key().encode().as_slice().to_vec();
    (sk, vk)
}

/// Sign `message` with an ML-DSA-87 signing key.
///
/// `private_key` must be exactly [`ML_DSA_87_SK_BYTES`] (4896) bytes.
pub fn sign_message(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    if private_key.len() != ML_DSA_87_SK_BYTES {
        return Err(Error::InvalidPrivateKey);
    }
    let arr: [u8; ML_DSA_87_SK_BYTES] = private_key
        .try_into()
        .map_err(|_| Error::InvalidPrivateKey)?;
    let encoded: EncodedSigningKey<MlDsa87> = arr.into();
    let sk = ml_dsa::SigningKey::<MlDsa87>::decode(&encoded);
    let sig = sk.sign(message);
    Ok(sig.encode().as_slice().to_vec())
}

/// Sign a message with domain separation for cross-network replay protection.
///
/// Prepends `domain` bytes to the message before signing so that a signature
/// produced on one network (e.g. `"axiom-dev-1"`) is invalid on another
/// network (e.g. `"axiom-test-1"`).
pub fn sign_with_domain(private_key: &[u8], domain: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let mut prefixed = Vec::with_capacity(domain.len() + message.len());
    prefixed.extend_from_slice(domain);
    prefixed.extend_from_slice(message);
    sign_message(private_key, &prefixed)
}

/// Verify an ML-DSA-87 signature produced with [`sign_with_domain`].
pub fn verify_signature_with_domain(
    domain: &[u8],
    message: &[u8],
    signature: &Signature,
    public_key: &PublicKey,
) -> Result<()> {
    let mut prefixed = Vec::with_capacity(domain.len() + message.len());
    prefixed.extend_from_slice(domain);
    prefixed.extend_from_slice(message);
    verify_signature(&prefixed, signature, public_key)
}

/// Verify an ML-DSA-87 signature.
///
/// Returns `Ok(())` if valid, `Err` otherwise.
pub fn verify_signature(
    message: &[u8],
    signature: &Signature,
    public_key: &PublicKey,
) -> Result<()> {
    let vk_bytes = public_key.as_bytes();
    let sig_bytes = signature.as_bytes();

    if vk_bytes.len() != ML_DSA_87_VK_BYTES {
        return Err(Error::InvalidPublicKey);
    }
    if sig_bytes.len() != ML_DSA_87_SIG_BYTES {
        return Err(Error::InvalidSignature);
    }

    let vk_arr: [u8; ML_DSA_87_VK_BYTES] =
        vk_bytes.try_into().map_err(|_| Error::InvalidPublicKey)?;
    let vk_encoded: EncodedVerifyingKey<MlDsa87> = vk_arr.into();
    let vk = ml_dsa::VerifyingKey::<MlDsa87>::decode(&vk_encoded);

    let sig_arr: [u8; ML_DSA_87_SIG_BYTES] =
        sig_bytes.try_into().map_err(|_| Error::InvalidSignature)?;
    let sig_encoded: EncodedSignature<MlDsa87> = sig_arr.into();
    let sig = ml_dsa::Signature::<MlDsa87>::decode(&sig_encoded).ok_or(Error::InvalidSignature)?;

    vk.verify(message, &sig)
        .map_err(|_| Error::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_dsa87_roundtrip() {
        let (sk, vk) = generate_keypair();
        assert_eq!(sk.len(), ML_DSA_87_SK_BYTES);
        assert_eq!(vk.len(), ML_DSA_87_VK_BYTES);

        let message = b"axiom test message";
        let sig_bytes = sign_message(&sk, message).unwrap();
        assert_eq!(sig_bytes.len(), ML_DSA_87_SIG_BYTES);

        let pk = PublicKey::from_bytes(vk);
        let sig = Signature::from_bytes(sig_bytes);
        verify_signature(message, &sig, &pk).unwrap();
    }

    #[test]
    fn ml_dsa87_wrong_message_rejected() {
        let (sk, vk) = generate_keypair();
        let sig_bytes = sign_message(&sk, b"correct").unwrap();
        let pk = PublicKey::from_bytes(vk);
        let sig = Signature::from_bytes(sig_bytes);
        assert!(verify_signature(b"wrong", &sig, &pk).is_err());
    }

    #[test]
    fn ml_dsa87_wrong_key_rejected() {
        let (sk, _) = generate_keypair();
        let (_, vk2) = generate_keypair();
        let sig_bytes = sign_message(&sk, b"msg").unwrap();
        let pk2 = PublicKey::from_bytes(vk2);
        let sig = Signature::from_bytes(sig_bytes);
        assert!(verify_signature(b"msg", &sig, &pk2).is_err());
    }

    #[test]
    fn sign_with_domain_roundtrip() {
        let (sk, vk) = generate_keypair();
        let pk = PublicKey::from_bytes(vk);
        let domain = b"axiom-test-1";
        let message = b"send 10 AXM to alice";

        let sig_bytes = sign_with_domain(&sk, domain, message).unwrap();
        let sig = Signature::from_bytes(sig_bytes);
        verify_signature_with_domain(domain, message, &sig, &pk).unwrap();
    }

    #[test]
    fn domain_prevents_cross_network_replay() {
        let (sk, vk) = generate_keypair();
        let pk = PublicKey::from_bytes(vk);
        let message = b"send 10 AXM to alice";

        let sig_bytes = sign_with_domain(&sk, b"axiom-dev-1", message).unwrap();
        let sig = Signature::from_bytes(sig_bytes);
        assert!(verify_signature_with_domain(b"axiom-test-1", message, &sig, &pk).is_err());
    }

    #[test]
    fn domain_sig_differs_from_plain_sig() {
        let (sk, vk) = generate_keypair();
        let pk = PublicKey::from_bytes(vk);
        let domain = b"axiom-dev-1";
        let message = b"some payload";

        let sig_bytes = sign_with_domain(&sk, domain, message).unwrap();
        let sig = Signature::from_bytes(sig_bytes);
        assert!(verify_signature(message, &sig, &pk).is_err());
    }
}
