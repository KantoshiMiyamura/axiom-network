// Copyright (c) 2026 Kantoshi Miyamura

//! ML-KEM-768 (FIPS 203) wrapper — **skeleton only**.
//!
//! Bridges an upstream KEM implementation (chosen at stage 2 in
//! V2_PROTOCOL.md §8) into the rest of `axiom-crypto`. The intended
//! consumer is the v2 P2P handshake in
//! `axiom-node::network::p2p_v2::handshake`; nothing in v1 paths references
//! this module.
//!
//! Sizes match FIPS 203 ML-KEM-768:
//!   - encapsulation key:   1184 bytes
//!   - decapsulation key:   2400 bytes
//!   - ciphertext:          1088 bytes
//!   - shared secret:         32 bytes

use thiserror::Error;

pub const ML_KEM_768_EK_BYTES: usize = 1184;
pub const ML_KEM_768_DK_BYTES: usize = 2400;
pub const ML_KEM_768_CT_BYTES: usize = 1088;
pub const ML_KEM_768_SS_BYTES: usize = 32;

/// Encapsulation key (public, sent during v2 handshake).
#[derive(Clone)]
pub struct MlKemEncapsulationKey(pub Vec<u8>);

/// Decapsulation key (private, never leaves the node).
#[derive(Clone)]
pub struct MlKemDecapsulationKey(pub Vec<u8>);

/// KEM ciphertext sent from the encapsulator to the decapsulator.
#[derive(Clone)]
pub struct MlKemCiphertext(pub Vec<u8>);

/// 32-byte shared secret. Treated as IKM for HKDF in the v2 handshake.
pub struct MlKemSharedSecret(pub [u8; ML_KEM_768_SS_BYTES]);

#[derive(Error, Debug)]
pub enum KemError {
    #[error("ML-KEM-768 not yet implemented (V2_PROTOCOL.md §8 stage 2)")]
    Unimplemented,
}

/// Generate an ML-KEM-768 keypair. Stub.
pub fn generate_keypair() -> Result<(MlKemEncapsulationKey, MlKemDecapsulationKey), KemError> {
    Err(KemError::Unimplemented)
}

/// Encapsulate to `peer_ek`, returning `(ciphertext, shared_secret)`. Stub.
pub fn encapsulate(
    _peer_ek: &MlKemEncapsulationKey,
) -> Result<(MlKemCiphertext, MlKemSharedSecret), KemError> {
    Err(KemError::Unimplemented)
}

/// Decapsulate `ciphertext` using `dk`, returning the 32-byte shared secret. Stub.
pub fn decapsulate(
    _dk: &MlKemDecapsulationKey,
    _ciphertext: &MlKemCiphertext,
) -> Result<MlKemSharedSecret, KemError> {
    Err(KemError::Unimplemented)
}

impl std::fmt::Debug for MlKemDecapsulationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlKemDecapsulationKey")
            .field("len", &self.0.len())
            .field("bytes", &"[redacted]")
            .finish()
    }
}

impl std::fmt::Debug for MlKemSharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlKemSharedSecret")
            .field("bytes", &"[redacted; 32]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-only sanity: stubs surface a clear error rather than panicking.
    #[test]
    fn stubs_return_unimplemented_error() {
        match generate_keypair() {
            Err(KemError::Unimplemented) => {}
            other => panic!("expected Unimplemented, got {:?}", other.map(|_| "Ok")),
        }
    }

    #[test]
    fn debug_does_not_leak_secret_key() {
        let dk = MlKemDecapsulationKey(vec![0xAA; 64]);
        let s = format!("{:?}", dk);
        assert!(s.contains("redacted"));
        assert!(!s.contains("AA"));
    }
}
