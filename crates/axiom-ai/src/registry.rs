// Copyright (c) 2026 Kantoshi Miyamura

//! Persistent AI model registry backed by a fjall LSM-tree partition.
//!
//! Each record is keyed by the 64-char SHA-256 hex hash of the model artifact
//! and encoded with bincode.  Registrations are append-only — a hash can only
//! be registered once.

use crate::types::ModelRecord;
use fjall::{Config, PartitionCreateOptions};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("storage error: {0}")]
    Storage(#[from] fjall::Error),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("invalid model hash (expected 64 lowercase hex chars): {0}")]
    InvalidHash(String),

    #[error("model already registered: {0}")]
    AlreadyExists(String),
}

pub type Result<T> = std::result::Result<T, RegistryError>;

/// Thread-safe model registry stored at `<data_dir>/ai_registry/`.
pub struct ModelRegistry {
    // Kept alive so the PartitionHandle remains valid.
    _keyspace: fjall::Keyspace,
    partition: fjall::PartitionHandle,
}

impl ModelRegistry {
    /// Open (or create) the registry at `data_dir/ai_registry`.
    pub fn open<P: AsRef<Path>>(data_dir: P) -> Result<Self> {
        let ai_path = data_dir.as_ref().join("ai_registry");
        let keyspace = Config::new(ai_path).open()?;
        let partition = keyspace.open_partition("models", PartitionCreateOptions::default())?;
        Ok(ModelRegistry {
            _keyspace: keyspace,
            partition,
        })
    }

    /// Register a model.  Returns [`RegistryError::AlreadyExists`] if the
    /// hash was previously registered.
    pub fn register(&self, record: ModelRecord) -> Result<()> {
        // Validate: 64 lowercase hex chars.
        if record.model_hash.len() != 64
            || !record.model_hash.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(RegistryError::InvalidHash(record.model_hash.clone()));
        }

        if self.partition.contains_key(&record.model_hash)? {
            return Err(RegistryError::AlreadyExists(record.model_hash.clone()));
        }

        let value = bincode::serde::encode_to_vec(&record, bincode::config::standard())
            .map_err(|e| RegistryError::Serialization(e.to_string()))?;

        self.partition.insert(&record.model_hash, value)?;
        Ok(())
    }

    /// Look up a model by its SHA-256 hash.
    pub fn get(&self, hash: &str) -> Result<Option<ModelRecord>> {
        match self.partition.get(hash)? {
            Some(v) => {
                let (record, _) = bincode::serde::decode_from_slice::<ModelRecord, _>(
                    &v,
                    bincode::config::standard(),
                )
                .map_err(|e| RegistryError::Serialization(e.to_string()))?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    /// Return up to `limit` records sorted newest-first by `registered_at`.
    pub fn list_recent(&self, limit: usize) -> Result<Vec<ModelRecord>> {
        let mut records = Vec::new();

        for kv in self.partition.iter() {
            let (_, v) = kv?;
            if let Ok((record, _)) =
                bincode::serde::decode_from_slice::<ModelRecord, _>(&v, bincode::config::standard())
            {
                records.push(record);
            }
        }

        records.sort_by(|a, b| b.registered_at.cmp(&a.registered_at));
        records.truncate(limit);
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const HASH_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn open_registry() -> (TempDir, ModelRegistry) {
        let tmp = TempDir::new().unwrap();
        let reg = ModelRegistry::open(tmp.path()).unwrap();
        (tmp, reg)
    }

    fn make_record(hash: &str, ts: u64) -> ModelRecord {
        ModelRecord {
            model_hash: hash.to_string(),
            name: format!("Model {hash:.4}"),
            version: "1.0.0".to_string(),
            description: "test".to_string(),
            registered_by: "axm_test_address".to_string(),
            registered_at: ts,
        }
    }

    #[test]
    fn test_register_and_get() {
        let (_tmp, reg) = open_registry();
        let record = make_record(HASH_A, 1_000);

        reg.register(record.clone()).unwrap();

        let fetched = reg.get(HASH_A).unwrap().expect("should exist");
        assert_eq!(fetched.model_hash, HASH_A);
        assert_eq!(fetched.name, record.name);
        assert_eq!(fetched.registered_at, 1_000);
    }

    #[test]
    fn test_get_missing_returns_none() {
        let (_tmp, reg) = open_registry();
        assert!(reg.get(HASH_A).unwrap().is_none());
    }

    #[test]
    fn test_duplicate_registration_rejected() {
        let (_tmp, reg) = open_registry();
        reg.register(make_record(HASH_A, 1_000)).unwrap();

        let err = reg.register(make_record(HASH_A, 2_000)).unwrap_err();
        assert!(matches!(err, RegistryError::AlreadyExists(_)));
    }

    #[test]
    fn test_invalid_hash_too_short() {
        let (_tmp, reg) = open_registry();
        let mut bad = make_record(HASH_A, 1_000);
        bad.model_hash = "abc123".to_string(); // too short
        let err = reg.register(bad).unwrap_err();
        assert!(matches!(err, RegistryError::InvalidHash(_)));
    }

    #[test]
    fn test_invalid_hash_non_hex() {
        let (_tmp, reg) = open_registry();
        let mut bad = make_record(HASH_A, 1_000);
        bad.model_hash = "z".repeat(64); // not hex
        let err = reg.register(bad).unwrap_err();
        assert!(matches!(err, RegistryError::InvalidHash(_)));
    }

    #[test]
    fn test_list_recent_sorted_newest_first() {
        let (_tmp, reg) = open_registry();
        reg.register(make_record(HASH_A, 1_000)).unwrap();
        reg.register(make_record(HASH_B, 3_000)).unwrap();
        reg.register(make_record(HASH_C, 2_000)).unwrap();

        let list = reg.list_recent(10).unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].registered_at, 3_000);
        assert_eq!(list[1].registered_at, 2_000);
        assert_eq!(list[2].registered_at, 1_000);
    }

    #[test]
    fn test_list_recent_respects_limit() {
        let (_tmp, reg) = open_registry();
        reg.register(make_record(HASH_A, 1_000)).unwrap();
        reg.register(make_record(HASH_B, 2_000)).unwrap();
        reg.register(make_record(HASH_C, 3_000)).unwrap();

        let list = reg.list_recent(2).unwrap();
        assert_eq!(list.len(), 2);
        // Should be the two newest
        assert_eq!(list[0].registered_at, 3_000);
        assert_eq!(list[1].registered_at, 2_000);
    }

    #[test]
    fn test_list_recent_empty() {
        let (_tmp, reg) = open_registry();
        let list = reg.list_recent(10).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn test_registry_persistence_across_reopen() {
        let tmp = TempDir::new().unwrap();
        {
            let reg = ModelRegistry::open(tmp.path()).unwrap();
            reg.register(make_record(HASH_A, 1_000)).unwrap();
        }
        // Re-open — data must survive
        let reg2 = ModelRegistry::open(tmp.path()).unwrap();
        let fetched = reg2.get(HASH_A).unwrap().expect("should persist");
        assert_eq!(fetched.model_hash, HASH_A);
    }
}
