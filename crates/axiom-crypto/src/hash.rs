// Copyright (c) 2026 Kantoshi Miyamura

use axiom_primitives::Hash256;
use sha2::{Digest, Sha256};

/// Compute SHA-256 hash of data.
pub fn hash256(data: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    Hash256::from_bytes(result.into())
}

/// Compute double SHA-256 hash of data.
///
/// Used for transaction IDs and block hashes to provide additional security.
pub fn double_hash256(data: &[u8]) -> Hash256 {
    let first = hash256(data);
    hash256(first.as_bytes())
}

/// BIP-340-style tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
///
/// Prepending two copies of `SHA256(tag)` (64 bytes = one SHA-256 block) guarantees
/// that no caller can construct a tagged-hash preimage by choosing `msg` alone,
/// because the pad is an unambiguous domain-separation prefix. Two different tags
/// cannot collide unless SHA-256 itself breaks.
pub fn tagged_hash(tag: &[u8], msg: &[u8]) -> Hash256 {
    let tag_hash = hash256(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash.as_bytes());
    hasher.update(tag_hash.as_bytes());
    hasher.update(msg);
    Hash256::from_bytes(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash256_deterministic() {
        let data = b"test data";
        let hash1 = hash256(data);
        let hash2 = hash256(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash256_different_inputs() {
        let hash1 = hash256(b"data1");
        let hash2 = hash256(b"data2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_double_hash256_deterministic() {
        let data = b"test data";
        let hash1 = double_hash256(data);
        let hash2 = double_hash256(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_double_hash256_different_from_single() {
        let data = b"test data";
        let single = hash256(data);
        let double = double_hash256(data);
        assert_ne!(single, double);
    }

    #[test]
    fn test_empty_input() {
        let hash = hash256(b"");
        assert_ne!(hash, Hash256::zero());
    }

    #[test]
    fn tagged_hash_deterministic() {
        assert_eq!(tagged_hash(b"tag", b"msg"), tagged_hash(b"tag", b"msg"));
    }

    #[test]
    fn tagged_hash_different_tags_disjoint() {
        assert_ne!(tagged_hash(b"tagA", b"msg"), tagged_hash(b"tagB", b"msg"));
    }

    #[test]
    fn tagged_hash_different_from_raw_sha256() {
        // The tagged hash must not collide with a raw hash of the same message —
        // this is the whole point of the 64-byte tag pad.
        assert_ne!(tagged_hash(b"axiom/tx/v1", b"msg"), hash256(b"msg"));
    }

    #[test]
    fn tagged_hash_empty_msg_ok() {
        // Empty-message case still produces a well-defined, tag-dependent hash.
        assert_ne!(tagged_hash(b"axiom/tx/v1", b""), Hash256::zero());
        assert_ne!(
            tagged_hash(b"axiom/tx/v1", b""),
            tagged_hash(b"axiom/tx/v2", b"")
        );
    }
}
