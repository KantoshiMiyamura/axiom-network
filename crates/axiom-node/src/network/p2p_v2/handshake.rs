// Copyright (c) 2026 Kantoshi Miyamura

//! v2 handshake messages — skeleton. Spec: V2_PROTOCOL.md §4.

use thiserror::Error;

/// Initiator → responder hello. See V2_PROTOCOL.md §4.1.
///
/// Field shapes are placeholders — `Vec<u8>` will become typed wrappers
/// (`MlKemCiphertext`, `MlDsaSignature`, etc.) once the matching stages of
/// the crypto roadmap (V2_PROTOCOL.md §8 stages 2-5) are implemented.
#[derive(Debug, Clone)]
pub struct HelloV2 {
    pub classical_pk: [u8; 32],
    pub pq_ciphertext: Vec<u8>,
    pub initiator_identity: super::identity::NodeIdentityProof,
    pub nonce_initiator: [u8; 32],
}

/// Responder → initiator acknowledgement. See V2_PROTOCOL.md §4.1.
#[derive(Debug, Clone)]
pub struct HelloAckV2 {
    pub classical_pk: [u8; 32],
    pub pq_ciphertext: Vec<u8>,
    pub responder_identity: super::identity::NodeIdentityProof,
    pub nonce_responder: [u8; 32],
}

#[derive(Error, Debug)]
pub enum HandshakeError {
    #[error("v2 handshake not yet implemented (V2_PROTOCOL.md §8 stage 3)")]
    Unimplemented,
}

/// Compute the transcript hash for an in-flight handshake. Will be
/// `SHA256(V2_TRANSCRIPT_TAG || hello.bytes() || ack.bytes_minus_identity())`
/// once stage 3 lands. Stub for now.
pub fn transcript_hash(_hello: &HelloV2, _ack_partial: &[u8]) -> [u8; 32] {
    unimplemented!("stage 3 — V2_PROTOCOL.md §4.1")
}
