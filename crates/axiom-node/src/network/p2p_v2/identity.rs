// Copyright (c) 2026 Kantoshi Miyamura

//! v2 node-identity proof — skeleton. Spec: V2_PROTOCOL.md §4.3.
//!
//! A v2 peer proves its identity with both an ML-DSA-87 signature and an
//! Ed25519 signature over the handshake transcript. Both must verify;
//! either failing aborts the handshake.

/// The two-signature identity proof exchanged in `HelloV2` / `HelloAckV2`.
#[derive(Debug, Clone)]
pub struct NodeIdentityProof {
    /// ML-DSA-87 long-term identity public key (FIPS 204).
    pub ml_dsa_pubkey: Vec<u8>,
    /// Ed25519 long-term identity public key.
    pub ed25519_pubkey: [u8; 32],
    /// ML-DSA-87 signature over the handshake transcript hash.
    pub ml_dsa_signature: Vec<u8>,
    /// Ed25519 signature over the handshake transcript hash.
    pub ed25519_signature: [u8; 64],
}

/// Verify the proof. Returns `Ok(())` only when **both** signatures verify.
/// Stub: stage 5 in V2_PROTOCOL.md §8.
pub fn verify_identity(
    _proof: &NodeIdentityProof,
    _transcript_hash: &[u8; 32],
) -> Result<(), super::handshake::HandshakeError> {
    Err(super::handshake::HandshakeError::Unimplemented)
}
