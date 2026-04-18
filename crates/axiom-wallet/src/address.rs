// Copyright (c) 2026 Kantoshi Miyamura

// Address format: "axm" prefix + hex payload.
// v1 (legacy, 67 chars): no checksum — accepted for backward compatibility, never emitted.
// v2 (current, 75 chars): 4-byte SHA256d checksum appended.
//   checksum = SHA256(SHA256("axiom-addr-v2:" || pubkey_hash))[0..4]

use crate::{Result, WalletError};
use axiom_primitives::Hash256;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const PREFIX: &str = "axm";
const CHECKSUM_DOMAIN: &[u8] = b"axiom-addr-v2:";
const CHECKSUM_LEN: usize = 4;
const PUBKEY_HASH_HEX_LEN: usize = 64;
const V2_HEX_LEN: usize = 72;

/// An Axiom Network address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pubkey_hash: Hash256,
}

/// SHA256d checksum: SHA256(SHA256("axiom-addr-v2:" || pubkey_hash))[0..4].
pub fn compute_checksum(pubkey_hash: &[u8]) -> [u8; CHECKSUM_LEN] {
    let mut h = Sha256::new();
    h.update(CHECKSUM_DOMAIN);
    h.update(pubkey_hash);
    let first: [u8; 32] = h.finalize().into();
    let second: [u8; 32] = Sha256::digest(first).into();
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&second[..CHECKSUM_LEN]);
    out
}

impl Address {
    pub fn from_pubkey_hash(pubkey_hash: Hash256) -> Self {
        Address { pubkey_hash }
    }

    pub fn pubkey_hash(&self) -> &Hash256 {
        &self.pubkey_hash
    }

    /// Decode address. Accepts v1 (legacy, 67 chars) and v2 (checksummed, 75 chars).
    pub fn from_string(s: &str) -> Result<Self> {
        if !s.starts_with(PREFIX) {
            return Err(WalletError::InvalidAddress);
        }
        let hex_part = &s[PREFIX.len()..];
        match hex_part.len() {
            PUBKEY_HASH_HEX_LEN => {
                let bytes = hex::decode(hex_part).map_err(|_| WalletError::InvalidAddress)?;
                let pubkey_hash = Hash256::from_slice(&bytes)?;
                Ok(Address { pubkey_hash })
            }
            V2_HEX_LEN => {
                let bytes = hex::decode(hex_part).map_err(|_| WalletError::InvalidAddress)?;
                let (hash_bytes, stored_cs) = bytes.split_at(32);
                let expected_cs = compute_checksum(hash_bytes);
                // Constant-time checksum compare. Four bytes is small, but using
                // the same primitive as every other security-sensitive compare
                // keeps the codebase audit-uniform — no sneaky `!=` on secrets.
                if !bool::from(stored_cs.ct_eq(&expected_cs)) {
                    return Err(WalletError::InvalidChecksum);
                }
                let pubkey_hash = Hash256::from_slice(hash_bytes)?;
                Ok(Address { pubkey_hash })
            }
            _ => Err(WalletError::InvalidAddress),
        }
    }

    pub fn is_valid(s: &str) -> bool {
        Self::from_string(s).is_ok()
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hash_bytes = self.pubkey_hash.as_bytes();
        let checksum = compute_checksum(hash_bytes);
        let mut payload = Vec::with_capacity(32 + CHECKSUM_LEN);
        payload.extend_from_slice(hash_bytes);
        payload.extend_from_slice(&checksum);
        write!(f, "{}{}", PREFIX, hex::encode(payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_addr() -> Address {
        Address::from_pubkey_hash(Hash256::zero())
    }

    #[test]
    fn v2_roundtrip() {
        let addr = zero_addr();
        let s = addr.to_string();
        assert_eq!(s.len(), 75);
        assert_eq!(Address::from_string(&s).unwrap(), addr);
    }

    #[test]
    fn v2_starts_with_axm() {
        assert!(zero_addr().to_string().starts_with("axm"));
    }

    #[test]
    fn invalid_checksum_rejected() {
        let mut s = zero_addr().to_string();
        let last = s.pop().unwrap();
        s.push(if last == 'a' { 'b' } else { 'a' });
        assert!(matches!(
            Address::from_string(&s).unwrap_err(),
            WalletError::InvalidChecksum
        ));
    }

    #[test]
    fn prefix_mismatch_rejected() {
        let s = zero_addr().to_string().replacen("axm", "btc", 1);
        assert!(matches!(
            Address::from_string(&s).unwrap_err(),
            WalletError::InvalidAddress
        ));
    }

    #[test]
    fn truncated_address_rejected() {
        assert!(Address::from_string("axm1234").is_err());
        assert!(Address::from_string("axm").is_err());
        assert!(Address::from_string("").is_err());
    }

    #[test]
    fn v1_legacy_accepted() {
        let hash = Hash256::zero();
        let v1 = format!("axm{}", hex::encode(hash.as_bytes()));
        assert_eq!(v1.len(), 67);
        let addr = Address::from_string(&v1).unwrap();
        assert_eq!(addr.pubkey_hash(), &hash);
    }

    #[test]
    fn checksum_deterministic() {
        let h = Hash256::zero();
        assert_eq!(
            compute_checksum(h.as_bytes()),
            compute_checksum(h.as_bytes())
        );
    }

    #[test]
    fn different_hashes_different_checksums() {
        let h1 = Hash256::zero();
        let h2 = Hash256::from_slice(&[1u8; 32]).unwrap();
        assert_ne!(
            compute_checksum(h1.as_bytes()),
            compute_checksum(h2.as_bytes())
        );
    }
}
