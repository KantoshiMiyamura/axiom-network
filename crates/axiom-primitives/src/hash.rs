// Copyright (c) 2026 Kantoshi Miyamura

use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// 256-bit hash. Used for txids, block hashes, and merkle roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hash256(#[serde(with = "serde_bytes_array")] [u8; 32]);

mod serde_bytes_array {
    use serde::{de::Error, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let bytes: Vec<u8> = serde_bytes::deserialize(d)?;
        bytes
            .try_into()
            .map_err(|_| D::Error::custom("expected 32 bytes"))
    }
}

impl Hash256 {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Hash256(bytes)
    }

    /// Create from a byte slice. Returns an error if the length is not 32.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != 32 {
            return Err(Error::InvalidHashLength(slice.len()));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Hash256(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn zero() -> Self {
        Hash256([0u8; 32])
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_from_bytes() {
        let bytes = [1u8; 32];
        let hash = Hash256::from_bytes(bytes);
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn test_hash_from_slice() {
        let bytes = [2u8; 32];
        let hash = Hash256::from_slice(&bytes).unwrap();
        assert_eq!(hash.as_bytes(), &bytes);

        let short = [3u8; 16];
        assert!(Hash256::from_slice(&short).is_err());
    }

    #[test]
    fn test_hash_zero() {
        let zero = Hash256::zero();
        assert_eq!(zero.as_bytes(), &[0u8; 32]);
    }
}
