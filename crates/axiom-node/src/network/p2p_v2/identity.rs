// Copyright (c) 2026 Kantoshi Miyamura

//! v2 hybrid node-identity proof. Spec: `V2_PROTOCOL.md §4.3`.
//!
//! A v2 peer proves its identity with **both** an ML-DSA-87 signature and
//! an Ed25519 signature over the handshake transcript. Both must verify;
//! either failing aborts the handshake. This is additive defence — a
//! future flaw in either library does not let an adversary forge node
//! identity on its own.

use ed25519_dalek::{
    Signature as Ed25519Signature, SigningKey as Ed25519SigningKey, Verifier as Ed25519Verifier,
    VerifyingKey as Ed25519VerifyingKey,
};

use super::handshake::HandshakeError;

/// The two-signature identity proof exchanged in `HelloV2` / `HelloAckV2`.
#[derive(Clone)]
pub struct NodeIdentityProof {
    /// ML-DSA-87 long-term identity public key (FIPS 204).
    pub ml_dsa_pubkey: Vec<u8>,
    /// Ed25519 long-term identity public key.
    pub ed25519_pubkey: [u8; 32],
    /// ML-DSA-87 signature over the transcript hash.
    pub ml_dsa_signature: Vec<u8>,
    /// Ed25519 signature over the transcript hash.
    pub ed25519_signature: [u8; 64],
}

impl std::fmt::Debug for NodeIdentityProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdentityProof")
            .field("ml_dsa_pubkey_len", &self.ml_dsa_pubkey.len())
            .field("ed25519_pubkey_len", &self.ed25519_pubkey.len())
            .field("ml_dsa_signature_len", &self.ml_dsa_signature.len())
            .field("ed25519_signature_len", &self.ed25519_signature.len())
            .finish()
    }
}

/// Build a hybrid identity proof. The caller signs the same transcript
/// hash with both keys; verification will reject any pair that disagrees
/// on the digest.
pub fn sign_identity(
    ml_dsa_private_key: &[u8],
    ml_dsa_public_key: Vec<u8>,
    ed25519_signing_key: &Ed25519SigningKey,
    transcript_hash: &[u8; 32],
) -> Result<NodeIdentityProof, HandshakeError> {
    // ML-DSA-87 over the transcript digest. Domain separation is provided
    // by the V2_TRANSCRIPT_TAG already mixed into the digest.
    let ml_dsa_signature = axiom_crypto::sign_message(ml_dsa_private_key, transcript_hash)
        .map_err(|_| HandshakeError::MlDsaSignatureFailed)?;

    // Ed25519 over the same digest.
    use ed25519_dalek::Signer;
    let ed25519_sig: Ed25519Signature = ed25519_signing_key.sign(transcript_hash);

    Ok(NodeIdentityProof {
        ml_dsa_pubkey: ml_dsa_public_key,
        ed25519_pubkey: ed25519_signing_key.verifying_key().to_bytes(),
        ml_dsa_signature,
        ed25519_signature: ed25519_sig.to_bytes(),
    })
}

/// Verify the proof. Returns `Ok(())` only when **both** signatures
/// verify against `transcript_hash`.
pub fn verify_identity(
    proof: &NodeIdentityProof,
    transcript_hash: &[u8; 32],
) -> Result<(), HandshakeError> {
    // ML-DSA-87 — must verify.
    let pk = axiom_primitives::PublicKey::from_bytes(proof.ml_dsa_pubkey.clone());
    let sig = axiom_primitives::Signature::from_bytes(proof.ml_dsa_signature.clone());
    axiom_crypto::verify_signature(transcript_hash, &sig, &pk)
        .map_err(|_| HandshakeError::MlDsaSignatureFailed)?;

    // Ed25519 — must also verify. We never short-circuit on the ML-DSA
    // result because the security guarantee is "both pass" not "either".
    let vk = Ed25519VerifyingKey::from_bytes(&proof.ed25519_pubkey)
        .map_err(|_| HandshakeError::Ed25519PublicKeyInvalid)?;
    let sig = Ed25519Signature::from_bytes(&proof.ed25519_signature);
    vk.verify(transcript_hash, &sig)
        .map_err(|_| HandshakeError::Ed25519SignatureFailed)?;

    Ok(())
}
