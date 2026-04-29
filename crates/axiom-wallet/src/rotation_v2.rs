// Copyright (c) 2026 Kantoshi Miyamura

//! Wallet key rotation — **skeleton only**.
//!
//! Tracks the linkage between an old address and its successor without
//! ever putting a private key on-chain. Spec: V2_PROTOCOL.md §7.
//!
//! Nothing in `wallet.rs`, `keystore.rs`, `signing.rs`, or `builder.rs`
//! consults this module yet — integration is V2_PROTOCOL.md §8 stage 7.

use axiom_primitives::{PublicKey, Signature};
use thiserror::Error;

use crate::address::Address;

/// One link in a rotation chain. Each rotation publishes a record signed
/// by the *old* key authorising the *new* key as the wallet's current
/// public identity.
#[derive(Debug, Clone)]
pub struct RotationRecord {
    pub from_address: Address,
    pub to_address: Address,
    pub successor_pubkey: PublicKey,
    pub effective_height: u32,
    /// ML-DSA-87 signature by the old key over the canonical record body.
    /// Verification is stage 7 in V2_PROTOCOL.md §8.
    pub signature: Signature,
}

/// In-memory chain of rotations the wallet has executed, oldest first.
/// Persisted via the keystore alongside the historical keypairs so any
/// past UTXO is still spendable.
#[derive(Debug, Default, Clone)]
pub struct Linkage {
    pub records: Vec<RotationRecord>,
}

impl Linkage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Current canonical address — the `to_address` of the latest record,
    /// or the seed address when no rotation has happened yet.
    pub fn current_address(&self, seed: &Address) -> Address {
        self.records
            .last()
            .map(|r| r.to_address.clone())
            .unwrap_or_else(|| seed.clone())
    }
}

#[derive(Error, Debug)]
pub enum RotationError {
    #[error("wallet rotation not yet implemented (V2_PROTOCOL.md §8 stage 7)")]
    Unimplemented,
}

/// Build a `RotationRecord` signed by the old key. Stub — stage 7 in
/// V2_PROTOCOL.md §8.
pub fn build_rotation_record(
    _old_keypair: &crate::keypair::KeyPair,
    _new_pubkey: &PublicKey,
    _from_address: Address,
    _to_address: Address,
    _effective_height: u32,
) -> Result<RotationRecord, RotationError> {
    Err(RotationError::Unimplemented)
}

/// Verify a `RotationRecord` against the chain of records the wallet has
/// already accepted. Stub — stage 7 in V2_PROTOCOL.md §8.
pub fn verify_rotation_record(
    _record: &RotationRecord,
    _linkage: &Linkage,
) -> Result<(), RotationError> {
    Err(RotationError::Unimplemented)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-only sanity: empty linkage falls back to the seed address.
    #[test]
    fn empty_linkage_returns_seed_address() {
        let zero_hash = axiom_primitives::Hash256::zero();
        let seed = Address::from_pubkey_hash(zero_hash);
        let linkage = Linkage::new();
        assert_eq!(linkage.len(), 0);
        assert!(linkage.is_empty());
        assert_eq!(linkage.current_address(&seed), seed);
    }
}
