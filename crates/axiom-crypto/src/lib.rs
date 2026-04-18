// Copyright (c) 2026 Kantoshi Miyamura

// Cryptographic primitives for Axiom Network: hashing and ML-DSA signatures.

mod error;
mod hash;
mod sign;

pub use error::{Error, Result};
pub use hash::{double_hash256, hash256, tagged_hash};
pub use sign::{
    generate_keypair, sign_message, sign_with_domain, verify_signature,
    verify_signature_with_domain,
};

pub use axiom_primitives::Hash256;

/// Domain-separation tag for transaction signing. Bumping the version suffix
/// produces an entirely disjoint hash space — old signatures cannot be replayed
/// against a new scheme and vice-versa.
pub const TX_SIGNING_TAG: &[u8] = b"axiom/tx/v1";

/// Canonical transaction signing hash — identical for wallet and validator.
///
/// Layout (bytes fed into `tagged_hash`):
///   [u32 LE: chain_id length][chain_id bytes][tx bytes]
///
/// The length prefix eliminates boundary ambiguity: `(chain_id="ab", tx="cd")`
/// and `(chain_id="abc", tx="d")` now produce distinct preimages, which was
/// not guaranteed under the prior `chain_id || tx_bytes` concatenation.
pub fn transaction_signing_hash(chain_id: &str, tx_bytes: &[u8]) -> Hash256 {
    let chain_id_bytes = chain_id.as_bytes();
    let mut preimage = Vec::with_capacity(4 + chain_id_bytes.len() + tx_bytes.len());
    preimage.extend_from_slice(&(chain_id_bytes.len() as u32).to_le_bytes());
    preimage.extend_from_slice(chain_id_bytes);
    preimage.extend_from_slice(tx_bytes);
    tagged_hash(TX_SIGNING_TAG, &preimage)
}

#[cfg(test)]
mod signing_hash_tests {
    use super::*;

    #[test]
    fn signing_hash_deterministic() {
        let h1 = transaction_signing_hash("axiom-mainnet-1", b"tx");
        let h2 = transaction_signing_hash("axiom-mainnet-1", b"tx");
        assert_eq!(h1, h2);
    }

    #[test]
    fn signing_hash_different_chains_disjoint() {
        assert_ne!(
            transaction_signing_hash("axiom-mainnet-1", b"tx"),
            transaction_signing_hash("axiom-testnet-1", b"tx"),
        );
    }

    #[test]
    fn signing_hash_boundary_disambiguation() {
        // The central invariant: varying the chain_id / tx_bytes boundary must
        // produce distinct hashes. Under a naive `chain_id || tx` concatenation
        // these would collide; the length-prefixed tagged hash rules it out.
        let a = transaction_signing_hash("ab", b"cde");
        let b = transaction_signing_hash("abc", b"de");
        let c = transaction_signing_hash("abcd", b"e");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn signing_hash_empty_chain_id_unambiguous() {
        // Empty chain_id is not equivalent to *no* chain_id prefix — under the
        // new scheme it encodes as `len=0 || <no bytes>`, which is distinct
        // from any non-empty chain_id including a chain_id whose bytes happen
        // to match the tx prefix.
        let empty = transaction_signing_hash("", b"tx");
        let nonempty = transaction_signing_hash("t", b"x");
        assert_ne!(empty, nonempty);
    }
}
