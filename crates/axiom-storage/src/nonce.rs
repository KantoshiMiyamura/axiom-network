// Copyright (c) 2026 Kantoshi Miyamura

use crate::{keys, Database, Error, Result};
use axiom_primitives::Hash256;

/// Per-address nonce tracker for replay protection.
pub struct NonceTracker<'a> {
    db: &'a Database,
}

impl<'a> NonceTracker<'a> {
    pub fn new(db: &'a Database) -> Self {
        NonceTracker { db }
    }

    pub fn get_nonce(&self, pubkey_hash: &Hash256) -> Result<Option<u64>> {
        let key = keys::nonce_key(pubkey_hash);
        match self.db.partition().get(key)? {
            Some(value) => {
                if value.len() != 8 {
                    return Err(Error::Corruption(format!(
                        "invalid nonce length: {}",
                        value.len()
                    )));
                }
                let nonce = u64::from_le_bytes([
                    value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
                ]);
                Ok(Some(nonce))
            }
            None => Ok(None),
        }
    }

    pub fn set_nonce(&self, pubkey_hash: &Hash256, nonce: u64) -> Result<()> {
        let key = keys::nonce_key(pubkey_hash);
        self.db.partition().insert(key, nonce.to_le_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_db() -> (TempDir, Database) {
        let temp_dir = TempDir::new().unwrap();
        let db = Database::open(temp_dir.path()).unwrap();
        (temp_dir, db)
    }

    #[test]
    fn test_nonce_get_set() {
        let (_temp, db) = create_test_db();
        let tracker = NonceTracker::new(&db);

        let pubkey_hash = Hash256::from_bytes([1u8; 32]);

        assert_eq!(tracker.get_nonce(&pubkey_hash).unwrap(), None);

        tracker.set_nonce(&pubkey_hash, 42).unwrap();
        assert_eq!(tracker.get_nonce(&pubkey_hash).unwrap(), Some(42));

        tracker.set_nonce(&pubkey_hash, 100).unwrap();
        assert_eq!(tracker.get_nonce(&pubkey_hash).unwrap(), Some(100));
    }
}
