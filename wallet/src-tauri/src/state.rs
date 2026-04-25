use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use axiom_wallet::{derive_account, Address, KeyPair};

use crate::cache::WalletCache;
use crate::error::{AppError, AppResult};
use crate::security::UnlockRateLimiter;

const PURPOSE_KEYSTORE: &[u8] = b"axiom-keystore-v1";

/// Serialized into the keystore's encrypted payload.
///
/// `seed_hex` and `seed_phrase` carry secret material. The Drop impl
/// zeroizes them so the plaintext does not linger after the value goes
/// out of scope (e.g. once it has been re-encrypted into the keystore).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletData {
    pub seed_hex: String,
    pub account_count: u32,
    pub seed_phrase: Option<String>,
}

impl Drop for WalletData {
    fn drop(&mut self) {
        self.seed_hex.zeroize();
        if let Some(p) = self.seed_phrase.as_mut() {
            p.zeroize();
        }
    }
}

/// Unlocked in-memory session. Key material zeroized on drop.
pub struct Session {
    seed: Zeroizing<Vec<u8>>,
    pub account_count: u32,
    seed_phrase: Option<Zeroizing<String>>,
    password: Zeroizing<String>,
}

impl Session {
    pub fn new(mut data: WalletData, password: String) -> AppResult<Self> {
        // `WalletData` has a Drop impl that zeroizes its fields, so we cannot
        // move them out by value — `mem::take` swaps in empty defaults that
        // Drop can safely run over, while we keep ownership of the secrets.
        let seed_phrase = std::mem::take(&mut data.seed_phrase).map(Zeroizing::new);
        let seed_hex = Zeroizing::new(std::mem::take(&mut data.seed_hex));
        let seed = Zeroizing::new(
            hex::decode(seed_hex.as_str())
                .map_err(|_| AppError::Internal("corrupt seed hex".into()))?,
        );
        if seed.len() != 64 {
            return Err(AppError::Internal(format!("seed len {} != 64", seed.len())));
        }
        Ok(Self {
            seed,
            account_count: data.account_count,
            seed_phrase,
            password: Zeroizing::new(password),
        })
    }

    pub fn keypair(&self, idx: u32) -> AppResult<KeyPair> {
        derive_account(&self.seed, idx).map_err(|e| AppError::Wallet(e.to_string()))
    }

    pub fn address(&self, idx: u32) -> AppResult<Address> {
        Ok(Address::from_pubkey_hash(
            self.keypair(idx)?.public_key_hash(),
        ))
    }

    pub fn new_address(&mut self) -> AppResult<(Address, u32)> {
        let i = self.account_count;
        let a = self.address(i)?;
        self.account_count += 1;
        Ok((a, i))
    }

    pub fn password(&self) -> &str {
        &self.password
    }
    pub fn seed_phrase(&self) -> Option<&str> {
        self.seed_phrase.as_ref().map(|s| s.as_str())
    }

    pub fn to_data(&self) -> WalletData {
        WalletData {
            seed_hex: hex::encode(self.seed.as_slice()),
            account_count: self.account_count,
            seed_phrase: self.seed_phrase.as_deref().map(String::from),
        }
    }
}

/// UTXO selected for spending.
pub struct SelectedUtxo {
    pub txid: String,
    pub output_index: u32,
    pub value: u64,
}

/// A transaction built but not yet broadcast, awaiting user confirmation.
pub struct PendingTx {
    pub to_address: String,
    pub amount_sat: u64,
    pub fee_sat: u64,
    pub from_address: String,
    pub account_index: u32,
    pub utxos: Vec<SelectedUtxo>,
    pub chain_id: String,
    pub nonce: u64,
}

// ── Persisted settings ──────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct Settings {
    node_url: String,
    lock_timeout_secs: u64,
}

fn load_settings(path: &PathBuf) -> (String, Duration) {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<Settings>(&s).ok())
        .map(|s| (s.node_url, Duration::from_secs(s.lock_timeout_secs)))
        .unwrap_or_else(|| ("http://127.0.0.1:9000".into(), Duration::from_secs(300)))
}

// ── Global application state ────────────────────────────────────────────────

pub struct AppState {
    pub session: Mutex<Option<Session>>,
    pub pending_tx: Mutex<Option<PendingTx>>,
    pub keystore_path: PathBuf,
    pub sealed_path: PathBuf,
    pub data_dir: PathBuf,
    pub last_activity: Mutex<Instant>,
    pub lock_timeout: Mutex<Duration>,
    pub rate_limiter: Mutex<UnlockRateLimiter>,
    pub cache: Mutex<WalletCache>,
    pub node_url: Mutex<String>,
    pub device_secret: Mutex<Option<Zeroizing<Vec<u8>>>>,
    /// Chain identifier last reported by the configured node. Cached so signing
    /// does not require an extra RPC round-trip when the node URL has not
    /// changed; cleared by `set_node_url`.
    pub chain_id: Mutex<Option<String>>,
}

impl AppState {
    pub fn new(data_dir: PathBuf) -> Self {
        let ks = data_dir.join("wallet.keystore.json");
        let sealed = data_dir.join("wallet.keystore.sealed");
        let device_secret = crate::keyring::get_device_secret();
        let cache = WalletCache::load(&data_dir, device_secret.as_deref().map(|z| z.as_slice()));
        let (url, timeout) = load_settings(&data_dir.join("settings.json"));
        Self {
            session: Mutex::new(None),
            pending_tx: Mutex::new(None),
            keystore_path: ks,
            sealed_path: sealed,
            data_dir,
            last_activity: Mutex::new(Instant::now()),
            lock_timeout: Mutex::new(timeout),
            rate_limiter: Mutex::new(UnlockRateLimiter::new()),
            cache: Mutex::new(cache),
            node_url: Mutex::new(url),
            device_secret: Mutex::new(device_secret),
            chain_id: Mutex::new(None),
        }
    }

    pub fn wallet_exists(&self) -> bool {
        self.sealed_path.exists() || self.keystore_path.exists()
    }

    /// Read the keystore JSON, unsealing the device envelope if present.
    pub fn read_keystore(&self) -> AppResult<String> {
        if self.sealed_path.exists() {
            let blob = std::fs::read(&self.sealed_path)?;
            let ds = self
                .device_secret
                .lock()
                .map_err(|_| AppError::Internal("lock".into()))?;
            if let Some(secret) = ds.as_ref() {
                if let Some(data) =
                    crate::keyring::unseal(&blob, secret.as_slice(), PURPOSE_KEYSTORE)
                {
                    return String::from_utf8(data)
                        .map_err(|_| AppError::Internal("corrupt sealed keystore".into()));
                }
            }
            return Err(AppError::Internal(
                "Device key unavailable — cannot unseal keystore. Import from seed phrase.".into(),
            ));
        }
        if self.keystore_path.exists() {
            return Ok(std::fs::read_to_string(&self.keystore_path)?);
        }
        Err(AppError::NoWallet)
    }

    /// Write the keystore JSON, sealing with device key if available.
    pub fn write_keystore(&self, json: &str) -> AppResult<()> {
        let ds = self
            .device_secret
            .lock()
            .map_err(|_| AppError::Internal("lock".into()))?;
        if let Some(secret) = ds.as_ref() {
            let sealed = crate::keyring::seal(json.as_bytes(), secret.as_slice(), PURPOSE_KEYSTORE)
                .ok_or_else(|| AppError::Internal("seal failed".into()))?;
            let tmp = self.sealed_path.with_extension("tmp");
            std::fs::write(&tmp, &sealed)?;
            std::fs::rename(&tmp, &self.sealed_path)?;
            let _ = std::fs::remove_file(&self.keystore_path);
        } else {
            let tmp = self.keystore_path.with_extension("tmp");
            std::fs::write(&tmp, json)?;
            std::fs::rename(&tmp, &self.keystore_path)?;
            crate::security::set_keystore_permissions(&self.keystore_path)?;
        }
        Ok(())
    }

    /// Verify session is alive and update activity timestamp.
    pub fn touch(&self) -> AppResult<()> {
        let session = self
            .session
            .lock()
            .map_err(|_| AppError::Internal("lock".into()))?;
        if session.is_none() {
            return Err(AppError::Locked);
        }

        let elapsed = self
            .last_activity
            .lock()
            .map_err(|_| AppError::Internal("lock".into()))?
            .elapsed();
        let timeout = *self
            .lock_timeout
            .lock()
            .map_err(|_| AppError::Internal("lock".into()))?;

        if elapsed > timeout {
            drop(session);
            *self
                .session
                .lock()
                .map_err(|_| AppError::Internal("lock".into()))? = None;
            return Err(AppError::SessionExpired);
        }
        drop(session);
        *self
            .last_activity
            .lock()
            .map_err(|_| AppError::Internal("lock".into()))? = Instant::now();
        Ok(())
    }

    /// Re-encrypt and persist the session state to the keystore file.
    pub fn persist(&self) -> AppResult<()> {
        let json = {
            let session = self
                .session
                .lock()
                .map_err(|_| AppError::Internal("lock".into()))?;
            let session = session.as_ref().ok_or(AppError::Locked)?;
            let data = session.to_data();
            let pt = Zeroizing::new(
                serde_json::to_vec(&data).map_err(|e| AppError::Internal(e.to_string()))?,
            );
            let ks = axiom_wallet::create_keystore(&pt, session.password())
                .map_err(|e| AppError::Wallet(e.to_string()))?;
            axiom_wallet::export_keystore(&ks).map_err(|e| AppError::Wallet(e.to_string()))?
        };
        self.write_keystore(&json)
    }

    pub fn save_settings(&self) -> AppResult<()> {
        let url = self
            .node_url
            .lock()
            .map_err(|_| AppError::Internal("lock".into()))?
            .clone();
        let secs = self
            .lock_timeout
            .lock()
            .map_err(|_| AppError::Internal("lock".into()))?
            .as_secs();
        let s = Settings {
            node_url: url,
            lock_timeout_secs: secs,
        };
        let j = serde_json::to_string_pretty(&s).map_err(|e| AppError::Internal(e.to_string()))?;
        std::fs::write(self.data_dir.join("settings.json"), j)?;
        Ok(())
    }
}
