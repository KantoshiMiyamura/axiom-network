// Copyright (c) 2026 Kantoshi Miyamura

//! Axiom v2 transaction extensions — **skeleton only**.
//!
//! v1 wire format and validation paths are unchanged. This module holds the
//! types that v2 transactions will *also* carry. Existing code does not
//! consult these types yet — the integration step is V2_PROTOCOL.md §8
//! stage 6, gated on `Transaction.v2_extension.is_some()` once that field
//! is added to [`super::transaction::Transaction`].
//!
//! Every type is `pub` because the eventual integration will place them on
//! the `Transaction` envelope; nothing here is exposed through the existing
//! v1 public API today.

use axiom_primitives::Signature;

/// Optional v2 extension carried alongside a v1 `Transaction`.
///
/// When `Some`, validation MUST apply the v2 nonce rule (V2_PROTOCOL.md §6)
/// and MUST resolve `rotation_pointer` against the wallet rotation registry
/// (V2_PROTOCOL.md §7) before treating the input as authorised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionV2Extension {
    /// Address whose key signed the transaction. For multi-input txs this
    /// is the holder of the first input's UTXO. Used as the replay-rule
    /// scope (V2_PROTOCOL.md §6).
    pub payer_address_bytes: Vec<u8>,

    /// If `Some`, the transaction is publishing a key-rotation record for
    /// `payer_address`. Validation MUST verify the inner signature against
    /// the *old* address before accepting the rotation.
    pub rotation_pointer: Option<RotationPointer>,
}

/// On-chain key-rotation record. Mirrors `axiom-wallet::rotation_v2::RotationRecord`
/// shape but uses byte-vector fields so this crate stays free of a
/// `axiom-wallet` dependency cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationPointer {
    pub from_address_bytes: Vec<u8>,
    pub to_address_bytes: Vec<u8>,
    pub successor_pubkey_bytes: Vec<u8>,
    pub effective_height: u32,
    pub signature: Signature,
}

/// Domain-separation tag for v2 transaction signing. The bump from
/// `b"axiom/tx/v1"` is what makes v1 and v2 signatures live in disjoint
/// hash spaces (V2_PROTOCOL.md §5.2).
pub const TX_SIGNING_TAG_V2: &[u8] = b"axiom/tx/v2";

// The on-chain rotation envelope is *built* in `axiom-wallet::rotation_v2`
// and `axiom-wallet::builder`. This crate only describes the wire-format
// shapes — it deliberately does not construct outputs so it stays free of
// any wallet-side dependency.

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-only sanity: the extension type is constructible.
    #[test]
    fn extension_type_is_constructible() {
        let ext = TransactionV2Extension {
            payer_address_bytes: vec![0u8; 20],
            rotation_pointer: None,
        };
        assert!(ext.rotation_pointer.is_none());
        assert_eq!(ext.payer_address_bytes.len(), 20);
    }

    #[test]
    fn signing_tag_is_v2() {
        assert_eq!(TX_SIGNING_TAG_V2, b"axiom/tx/v2");
    }
}
