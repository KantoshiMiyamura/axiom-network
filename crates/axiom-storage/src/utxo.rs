// Copyright (c) 2026 Kantoshi Miyamura

use crate::{keys, Database, Error, Result};
use axiom_primitives::{Amount, Hash256};
use axiom_protocol::TxOutput;
use serde::{Deserialize, Serialize};

/// An unspent transaction output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoEntry {
    pub value: Amount,
    pub pubkey_hash: Hash256,
    pub height: u32,
    pub is_coinbase: bool,
    /// Pedersen commitment for confidential UTXOs; `None` for standard outputs.
    #[serde(default)]
    pub confidential_commitment: Option<[u8; 32]>,
}

/// Versioned UTXO entry for backward compatibility during serialization changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedUtxoEntry {
    pub version: u32,
    pub entry: UtxoEntry,
}

impl VersionedUtxoEntry {
    const CURRENT_VERSION: u32 = 1;

    pub fn new(entry: UtxoEntry) -> Self {
        VersionedUtxoEntry {
            version: Self::CURRENT_VERSION,
            entry,
        }
    }

    /// Try to deserialize, handling both versioned and legacy (unversioned) formats.
    pub fn deserialize(data: &[u8]) -> std::result::Result<UtxoEntry, String> {
        // Try versioned format first
        if let Ok((versioned, _)) = bincode::serde::decode_from_slice::<VersionedUtxoEntry, _>(
            data,
            bincode::config::standard(),
        ) {
            if versioned.version == Self::CURRENT_VERSION {
                return Ok(versioned.entry);
            } else {
                return Err(format!(
                    "unsupported UTXO version: {} (expected {})",
                    versioned.version,
                    Self::CURRENT_VERSION
                ));
            }
        }

        // Fall back to legacy unversioned format
        bincode::serde::decode_from_slice::<UtxoEntry, _>(data, bincode::config::standard())
            .map(|(entry, _)| entry)
            .map_err(|e| format!("failed to deserialize UTXO: {}", e))
    }
}

impl UtxoEntry {
    pub fn from_output(output: &TxOutput, height: u32, is_coinbase: bool) -> Self {
        UtxoEntry {
            value: output.value,
            pubkey_hash: output.pubkey_hash,
            height,
            is_coinbase,
            confidential_commitment: None,
        }
    }

    pub fn is_confidential(&self) -> bool {
        self.confidential_commitment.is_some()
    }
}

/// UTXO set backed by fjall.
pub struct UtxoSet<'a> {
    db: &'a Database,
}

impl<'a> UtxoSet<'a> {
    pub fn new(db: &'a Database) -> Self {
        UtxoSet { db }
    }

    pub fn add_utxo(&self, txid: &Hash256, output_index: u32, entry: &UtxoEntry) -> Result<()> {
        let key = keys::utxo_key(txid, output_index);
        let versioned = VersionedUtxoEntry::new(entry.clone());
        let value = bincode::serde::encode_to_vec(&versioned, bincode::config::standard())
            .map_err(|e| Error::Serialization(e.to_string()))?;

        self.db.partition().insert(key, value)?;
        Ok(())
    }

    pub fn get_utxo(&self, txid: &Hash256, output_index: u32) -> Result<Option<UtxoEntry>> {
        let key = keys::utxo_key(txid, output_index);
        match self.db.partition().get(key)? {
            Some(value) => {
                let entry =
                    VersionedUtxoEntry::deserialize(&value).map_err(Error::Deserialization)?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    pub fn remove_utxo(&self, txid: &Hash256, output_index: u32) -> Result<()> {
        let key = keys::utxo_key(txid, output_index);
        self.db.partition().remove(key)?;
        Ok(())
    }

    pub fn has_utxo(&self, txid: &Hash256, output_index: u32) -> Result<bool> {
        let key = keys::utxo_key(txid, output_index);
        Ok(self.db.partition().contains_key(key)?)
    }

    /// Scan all UTXOs belonging to `pubkey_hash`. Returns (txid, output_index, entry) tuples.
    pub fn iter_by_address(&self, pubkey_hash: &Hash256) -> Result<Vec<(Hash256, u32, UtxoEntry)>> {
        let mut results = Vec::new();
        let prefix = vec![0x03]; // UTXO prefix

        for item in self.db.partition().prefix(prefix) {
            let (key, value) = item?;

            // key: [prefix:1][txid:32][output_index:4]
            if key.len() != 37 {
                continue;
            }

            let mut txid_bytes = [0u8; 32];
            txid_bytes.copy_from_slice(&key[1..33]);
            let txid = Hash256::from_bytes(txid_bytes);

            let mut index_bytes = [0u8; 4];
            index_bytes.copy_from_slice(&key[33..37]);
            let output_index = u32::from_le_bytes(index_bytes);

            let entry = VersionedUtxoEntry::deserialize(&value).map_err(Error::Deserialization)?;

            if entry.pubkey_hash == *pubkey_hash {
                results.push((txid, output_index, entry));
            }
        }

        Ok(results)
    }

    /// Sum all UTXO values belonging to `pubkey_hash`.
    pub fn get_balance(&self, pubkey_hash: &Hash256) -> Result<u64> {
        let utxos = self.iter_by_address(pubkey_hash)?;
        let mut balance = 0u64;

        for (_, _, entry) in utxos {
            balance = balance.saturating_add(entry.value.as_sat());
        }

        Ok(balance)
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
    fn test_utxo_add_get() {
        let (_temp, db) = create_test_db();
        let utxo_set = UtxoSet::new(&db);

        let txid = Hash256::from_bytes([1u8; 32]);
        let entry = UtxoEntry {
            value: Amount::from_sat(1000).unwrap(),
            pubkey_hash: Hash256::zero(),
            height: 100,
            is_coinbase: false,
            confidential_commitment: None,
        };

        utxo_set.add_utxo(&txid, 0, &entry).unwrap();
        let retrieved = utxo_set.get_utxo(&txid, 0).unwrap().unwrap();

        assert_eq!(retrieved, entry);
    }

    #[test]
    fn test_utxo_remove() {
        let (_temp, db) = create_test_db();
        let utxo_set = UtxoSet::new(&db);

        let txid = Hash256::from_bytes([1u8; 32]);
        let entry = UtxoEntry {
            value: Amount::from_sat(1000).unwrap(),
            pubkey_hash: Hash256::zero(),
            height: 100,
            is_coinbase: false,
            confidential_commitment: None,
        };

        utxo_set.add_utxo(&txid, 0, &entry).unwrap();
        assert!(utxo_set.has_utxo(&txid, 0).unwrap());

        utxo_set.remove_utxo(&txid, 0).unwrap();
        assert!(!utxo_set.has_utxo(&txid, 0).unwrap());
    }

    #[test]
    fn test_utxo_not_found() {
        let (_temp, db) = create_test_db();
        let utxo_set = UtxoSet::new(&db);

        let txid = Hash256::from_bytes([1u8; 32]);
        let result = utxo_set.get_utxo(&txid, 0).unwrap();

        assert!(result.is_none());
    }
}
