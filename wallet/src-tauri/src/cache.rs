use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::rpc::{TxSummary, UtxoEntry};

const PURPOSE_CACHE: &[u8] = b"axiom-cache-v1";

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct WalletCache {
    pub balances: HashMap<String, u64>,
    pub utxos: HashMap<String, Vec<UtxoEntry>>,
    pub transactions: Vec<CachedTx>,
    pub last_block_height: Option<u32>,
    pub last_updated: Option<u64>,
    #[serde(skip)]
    path: PathBuf,
    #[serde(skip)]
    device_secret: Option<Zeroizing<Vec<u8>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedTx {
    pub txid: String,
    pub block_height: Option<u32>,
    pub timestamp: Option<u32>,
    pub value_change: i64,
    pub address: String,
}

impl WalletCache {
    pub fn load(dir: &Path, device_secret: Option<&[u8]>) -> Self {
        let enc_path = dir.join("cache.enc");
        let plain_path = dir.join("cache.json");

        // Try encrypted cache first
        if let Some(secret) = device_secret {
            if let Some(mut cache) = Self::load_encrypted(&enc_path, secret) {
                cache.path = enc_path;
                cache.device_secret = Some(Zeroizing::new(secret.to_vec()));
                let _ = std::fs::remove_file(&plain_path);
                return cache;
            }
        }

        // Try plaintext cache (legacy / no device key)
        if let Some(mut cache) = Self::load_plaintext(&plain_path) {
            if let Some(secret) = device_secret {
                cache.path = enc_path;
                cache.device_secret = Some(Zeroizing::new(secret.to_vec()));
                cache.save();
                let _ = std::fs::remove_file(&plain_path);
            } else {
                cache.path = plain_path;
            }
            return cache;
        }

        // Start fresh
        let mut c = WalletCache::default();
        if let Some(secret) = device_secret {
            c.path = enc_path;
            c.device_secret = Some(Zeroizing::new(secret.to_vec()));
        } else {
            c.path = plain_path;
        }
        c
    }

    fn load_encrypted(path: &Path, secret: &[u8]) -> Option<Self> {
        let blob = std::fs::read(path).ok()?;
        let pt = crate::keyring::unseal(&blob, secret, PURPOSE_CACHE)?;
        serde_json::from_slice(&pt).ok()
    }

    fn load_plaintext(path: &Path) -> Option<Self> {
        let text = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// Enable encryption for the cache (called after device key is created).
    pub fn enable_encryption(&mut self, dir: &Path, secret: &[u8]) {
        self.device_secret = Some(Zeroizing::new(secret.to_vec()));
        self.path = dir.join("cache.enc");
        self.save();
    }

    pub fn save(&self) {
        let json = match serde_json::to_vec(self) {
            Ok(j) => Zeroizing::new(j),
            Err(_) => return,
        };

        if let Some(secret) = &self.device_secret {
            if let Some(sealed) = crate::keyring::seal(&json, secret.as_slice(), PURPOSE_CACHE) {
                let _ = std::fs::write(&self.path, sealed);
                return;
            }
        }
        let _ = std::fs::write(&self.path, json.as_slice());
    }

    pub fn set_balance(&mut self, addr: &str, bal: u64) {
        self.balances.insert(addr.into(), bal);
        self.touch();
    }

    pub fn set_utxos(&mut self, addr: &str, u: Vec<UtxoEntry>) {
        self.utxos.insert(addr.into(), u);
        self.touch();
    }

    pub fn set_transactions(&mut self, addr: &str, txs: Vec<TxSummary>) {
        self.transactions.retain(|t| t.address != addr);
        for tx in txs {
            self.transactions.push(CachedTx {
                txid: tx.txid,
                block_height: tx.block_height,
                timestamp: tx.timestamp,
                value_change: tx.value_change,
                address: addr.into(),
            });
        }
        self.transactions
            .sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        self.touch();
    }

    pub fn get_balance(&self, addr: &str) -> Option<u64> {
        self.balances.get(addr).copied()
    }

    pub fn get_txs(&self, addr: &str) -> Vec<&CachedTx> {
        self.transactions
            .iter()
            .filter(|t| t.address == addr)
            .collect()
    }

    /// Remove all cached data for a specific account address.
    pub fn clear_account(&mut self, addr: &str) {
        self.balances.remove(addr);
        self.utxos.remove(addr);
        self.transactions.retain(|t| t.address != addr);
        self.touch();
    }

    fn touch(&mut self) {
        self.last_updated = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        self.save();
    }
}
