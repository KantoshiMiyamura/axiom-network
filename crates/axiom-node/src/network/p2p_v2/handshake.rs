// Copyright (c) 2026 Kantoshi Miyamura

//! v2 handshake messages + transcript hash. Spec: `V2_PROTOCOL.md §4`.
//!
//! Wire layout for `HelloV2` (initiator → responder):
//!
//! ```text
//!   u8   message_tag = 0x01
//!   [32] classical_pk_init        (X25519 ephemeral PK)
//!   [N1] ml_kem_ek_init           (FIPS 203 ML-KEM-768 EK, 1184 bytes)
//!   [32] nonce_init               (CSPRNG, fresh per handshake attempt)
//!   u32  ml_dsa_pk_len
//!   [..] ml_dsa_pk_init           (long-term ML-DSA-87 identity PK)
//!   [32] ed25519_pk_init          (long-term Ed25519 identity PK)
//!   u32  ml_dsa_sig_len
//!   [..] ml_dsa_sig_init          (signs transcript_hash(pre-identity))
//!   [64] ed25519_sig_init         (signs transcript_hash(pre-identity))
//! ```
//!
//! `HelloAckV2` (responder → initiator) is the same shape but starts with
//! `message_tag = 0x02` and substitutes `ml_kem_ek_init` for an
//! `ml_kem_ct_resp` of FIPS 203 ML-KEM-768 ciphertext size (1088 bytes).
//!
//! The "pre-identity bytes" of each message are everything up to but not
//! including the four identity fields (`ml_dsa_pk`, `ed25519_pk`,
//! `ml_dsa_sig`, `ed25519_sig`). A signing peer hashes the running
//! transcript at its moment of signing and signs the digest; a verifying
//! peer recomputes the same digest from the bytes it observed.

use thiserror::Error;

use super::identity::NodeIdentityProof;
use super::{V2_PROTOCOL_VERSION_TAG, V2_TRANSCRIPT_TAG};

pub const HELLO_V2_TAG: u8 = 0x01;
pub const HELLO_ACK_V2_TAG: u8 = 0x02;
pub const ML_KEM_EK_BYTES: usize = axiom_crypto::kem_v2::ML_KEM_768_EK_BYTES; // 1184
pub const ML_KEM_CT_BYTES: usize = axiom_crypto::kem_v2::ML_KEM_768_CT_BYTES; // 1088
pub const NONCE_BYTES: usize = 32;
pub const X25519_PK_BYTES: usize = 32;
pub const ED25519_PK_BYTES: usize = 32;
pub const ED25519_SIG_BYTES: usize = 64;

/// Initiator → responder hello.
#[derive(Debug, Clone)]
pub struct HelloV2 {
    pub classical_pk: [u8; X25519_PK_BYTES],
    pub ml_kem_ek: Vec<u8>, // exactly ML_KEM_EK_BYTES
    pub nonce_initiator: [u8; NONCE_BYTES],
    pub initiator_identity: NodeIdentityProof,
}

/// Responder → initiator acknowledgement.
#[derive(Debug, Clone)]
pub struct HelloAckV2 {
    pub classical_pk: [u8; X25519_PK_BYTES],
    pub ml_kem_ciphertext: Vec<u8>, // exactly ML_KEM_CT_BYTES
    pub nonce_responder: [u8; NONCE_BYTES],
    pub responder_identity: NodeIdentityProof,
}

#[derive(Error, Debug)]
pub enum HandshakeError {
    #[error("message too short for v2 hello")]
    Truncated,
    #[error("unexpected message tag: got 0x{0:02x}")]
    BadTag(u8),
    #[error("invalid ML-KEM EK length: expected {expected}, got {actual}")]
    BadKemEkLen { expected: usize, actual: usize },
    #[error("invalid ML-KEM ciphertext length: expected {expected}, got {actual}")]
    BadKemCtLen { expected: usize, actual: usize },
    #[error("invalid ML-DSA pubkey length: {0}")]
    BadMlDsaPkLen(u32),
    #[error("invalid ML-DSA signature length: {0}")]
    BadMlDsaSigLen(u32),
    #[error("trailing bytes after parse: {0}")]
    TrailingBytes(usize),
    #[error("ML-DSA identity signature failed to verify")]
    MlDsaSignatureFailed,
    #[error("Ed25519 identity signature failed to verify")]
    Ed25519SignatureFailed,
    #[error("invalid Ed25519 public key")]
    Ed25519PublicKeyInvalid,
    #[error("ML-KEM operation failed: {0}")]
    Kem(#[from] axiom_crypto::kem_v2::KemError),
}

impl HelloV2 {
    /// Canonical wire bytes — everything in the message in order.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.pre_identity_bytes();
        write_identity_proof_into(&self.initiator_identity, &mut out);
        out
    }

    /// Wire bytes up to but not including the identity proof. This is the
    /// region the initiator hashes when producing its identity signature
    /// and the region a verifier hashes when checking it.
    pub fn pre_identity_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + X25519_PK_BYTES + ML_KEM_EK_BYTES + NONCE_BYTES);
        out.push(HELLO_V2_TAG);
        out.extend_from_slice(&self.classical_pk);
        out.extend_from_slice(&self.ml_kem_ek);
        out.extend_from_slice(&self.nonce_initiator);
        out
    }

    pub fn from_bytes(input: &[u8]) -> Result<Self, HandshakeError> {
        let mut cur = Cursor::new(input);
        let tag = cur.take_u8()?;
        if tag != HELLO_V2_TAG {
            return Err(HandshakeError::BadTag(tag));
        }
        let classical_pk = cur.take_array::<X25519_PK_BYTES>()?;
        let ek_bytes = cur.take_n(ML_KEM_EK_BYTES)?.to_vec();
        let nonce_initiator = cur.take_array::<NONCE_BYTES>()?;
        let identity = read_identity_proof(&mut cur)?;
        cur.expect_consumed()?;
        Ok(HelloV2 {
            classical_pk,
            ml_kem_ek: ek_bytes,
            nonce_initiator,
            initiator_identity: identity,
        })
    }
}

impl HelloAckV2 {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.pre_identity_bytes();
        write_identity_proof_into(&self.responder_identity, &mut out);
        out
    }

    pub fn pre_identity_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + X25519_PK_BYTES + ML_KEM_CT_BYTES + NONCE_BYTES);
        out.push(HELLO_ACK_V2_TAG);
        out.extend_from_slice(&self.classical_pk);
        out.extend_from_slice(&self.ml_kem_ciphertext);
        out.extend_from_slice(&self.nonce_responder);
        out
    }

    pub fn from_bytes(input: &[u8]) -> Result<Self, HandshakeError> {
        let mut cur = Cursor::new(input);
        let tag = cur.take_u8()?;
        if tag != HELLO_ACK_V2_TAG {
            return Err(HandshakeError::BadTag(tag));
        }
        let classical_pk = cur.take_array::<X25519_PK_BYTES>()?;
        let ct_bytes = cur.take_n(ML_KEM_CT_BYTES)?.to_vec();
        let nonce_responder = cur.take_array::<NONCE_BYTES>()?;
        let identity = read_identity_proof(&mut cur)?;
        cur.expect_consumed()?;
        Ok(HelloAckV2 {
            classical_pk,
            ml_kem_ciphertext: ct_bytes,
            nonce_responder,
            responder_identity: identity,
        })
    }
}

/// Compute the transcript hash for the handshake state at the moment of
/// signing. The structure is length-prefixed at every region so the
/// boundary between version, hello, and ack-pre-identity bytes is
/// unambiguous (matches `transaction_signing_hash`'s rationale in
/// `axiom-crypto`):
///
/// ```text
///   SHA-256(
///       V2_TRANSCRIPT_TAG ||
///       u32 LE  version_len    || version_bytes ||
///       u32 LE  hello_len      || hello_bytes_full ||
///       u32 LE  ack_partial_len|| ack_pre_identity_bytes
///   )
/// ```
///
/// Pass `ack_pre_identity` as `None` when computing the digest the
/// **initiator** signs (only its own message exists at that point); pass
/// `Some(...)` when computing the digest the **responder** signs (the
/// initiator's full message plus the responder's pre-identity bytes are
/// available).
pub fn transcript_hash(hello_full_bytes: &[u8], ack_pre_identity: Option<&[u8]>) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(V2_TRANSCRIPT_TAG);
    h.update((V2_PROTOCOL_VERSION_TAG.len() as u32).to_le_bytes());
    h.update(V2_PROTOCOL_VERSION_TAG);
    h.update((hello_full_bytes.len() as u32).to_le_bytes());
    h.update(hello_full_bytes);
    let ack = ack_pre_identity.unwrap_or(&[]);
    h.update((ack.len() as u32).to_le_bytes());
    h.update(ack);
    h.finalize().into()
}

// ── Internal helpers ────────────────────────────────────────────────────────

fn write_identity_proof_into(proof: &NodeIdentityProof, out: &mut Vec<u8>) {
    out.extend_from_slice(&(proof.ml_dsa_pubkey.len() as u32).to_le_bytes());
    out.extend_from_slice(&proof.ml_dsa_pubkey);
    out.extend_from_slice(&proof.ed25519_pubkey);
    out.extend_from_slice(&(proof.ml_dsa_signature.len() as u32).to_le_bytes());
    out.extend_from_slice(&proof.ml_dsa_signature);
    out.extend_from_slice(&proof.ed25519_signature);
}

fn read_identity_proof(cur: &mut Cursor) -> Result<NodeIdentityProof, HandshakeError> {
    let ml_dsa_pk_len = cur.take_u32_le()?;
    if !(1..=16_384).contains(&ml_dsa_pk_len) {
        return Err(HandshakeError::BadMlDsaPkLen(ml_dsa_pk_len));
    }
    let ml_dsa_pubkey = cur.take_n(ml_dsa_pk_len as usize)?.to_vec();
    let ed25519_pubkey = cur.take_array::<ED25519_PK_BYTES>()?;
    let ml_dsa_sig_len = cur.take_u32_le()?;
    if !(1..=16_384).contains(&ml_dsa_sig_len) {
        return Err(HandshakeError::BadMlDsaSigLen(ml_dsa_sig_len));
    }
    let ml_dsa_signature = cur.take_n(ml_dsa_sig_len as usize)?.to_vec();
    let ed25519_signature = cur.take_array::<ED25519_SIG_BYTES>()?;
    Ok(NodeIdentityProof {
        ml_dsa_pubkey,
        ed25519_pubkey,
        ml_dsa_signature,
        ed25519_signature,
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Cursor { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn take_u8(&mut self) -> Result<u8, HandshakeError> {
        if self.remaining() < 1 {
            return Err(HandshakeError::Truncated);
        }
        let b = self.bytes[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn take_u32_le(&mut self) -> Result<u32, HandshakeError> {
        if self.remaining() < 4 {
            return Err(HandshakeError::Truncated);
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.bytes[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_le_bytes(buf))
    }

    fn take_n(&mut self, n: usize) -> Result<&'a [u8], HandshakeError> {
        if self.remaining() < n {
            return Err(HandshakeError::Truncated);
        }
        let s = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], HandshakeError> {
        let s = self.take_n(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }

    fn expect_consumed(&self) -> Result<(), HandshakeError> {
        let r = self.remaining();
        if r > 0 {
            Err(HandshakeError::TrailingBytes(r))
        } else {
            Ok(())
        }
    }
}
