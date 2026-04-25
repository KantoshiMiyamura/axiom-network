use serde::Serialize;
use std::time::Instant;
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};
use crate::state::{AppState, Session, WalletData};

#[derive(Serialize)]
pub struct CreateResult {
    pub seed_phrase: String,
    pub address: String,
}

#[derive(Serialize)]
pub struct ImportResult {
    pub address: String,
}

#[derive(Serialize)]
pub struct UnlockResult {
    pub address: String,
    pub account_count: u32,
}

#[derive(Serialize)]
pub struct SessionStatus {
    pub locked: bool,
    pub remaining_secs: u64,
}

#[tauri::command]
pub fn wallet_exists(state: tauri::State<'_, AppState>) -> bool {
    state.wallet_exists()
}

#[tauri::command]
pub fn create_wallet(
    password: String,
    state: tauri::State<'_, AppState>,
) -> AppResult<CreateResult> {
    if state.wallet_exists() {
        return Err(AppError::Internal("wallet already exists".into()));
    }
    axiom_wallet::validate_password_strength(&password)
        .map_err(|e| AppError::Wallet(e.to_string()))?;

    // Initialize OS-level device key for keystore sealing + cache encryption
    let device_secret = crate::keyring::get_or_create_device_secret();
    *state
        .device_secret
        .lock()
        .map_err(|_| AppError::Internal("lock".into()))? = device_secret.clone();

    // Enable cache encryption if device key available
    if let Some(ref secret) = device_secret {
        state
            .cache
            .lock()
            .map_err(|_| AppError::Internal("lock".into()))?
            .enable_encryption(&state.data_dir, secret.as_slice());
    }

    let (phrase, seed) = axiom_wallet::generate_seed_phrase();
    let kp = axiom_wallet::derive_account(&seed, 0).map_err(|e| AppError::Wallet(e.to_string()))?;
    let addr = axiom_wallet::Address::from_pubkey_hash(kp.public_key_hash());

    let data = WalletData {
        seed_hex: hex::encode(seed.as_slice()),
        account_count: 1,
        seed_phrase: Some(phrase.clone()),
    };
    let pt =
        Zeroizing::new(serde_json::to_vec(&data).map_err(|e| AppError::Internal(e.to_string()))?);
    let ks = axiom_wallet::create_keystore(&pt, &password)
        .map_err(|e| AppError::Wallet(e.to_string()))?;
    let json = axiom_wallet::export_keystore(&ks).map_err(|e| AppError::Wallet(e.to_string()))?;

    state.write_keystore(&json)?;

    let session = Session::new(data, password)?;
    *state
        .session
        .lock()
        .map_err(|_| AppError::Internal("lock".into()))? = Some(session);
    *state
        .last_activity
        .lock()
        .map_err(|_| AppError::Internal("lock".into()))? = Instant::now();

    Ok(CreateResult {
        seed_phrase: phrase,
        address: addr.to_string(),
    })
}

#[tauri::command]
pub fn import_wallet_seed(
    phrase: String,
    password: String,
    state: tauri::State<'_, AppState>,
) -> AppResult<ImportResult> {
    axiom_wallet::validate_password_strength(&password)
        .map_err(|e| AppError::Wallet(e.to_string()))?;

    // Initialize OS-level device key
    let device_secret = crate::keyring::get_or_create_device_secret();
    *state
        .device_secret
        .lock()
        .map_err(|_| AppError::Internal("lock".into()))? = device_secret.clone();

    if let Some(ref secret) = device_secret {
        state
            .cache
            .lock()
            .map_err(|_| AppError::Internal("lock".into()))?
            .enable_encryption(&state.data_dir, secret.as_slice());
    }

    let seed = axiom_wallet::recover_wallet_from_seed(&phrase)
        .map_err(|e| AppError::Wallet(e.to_string()))?;
    let kp = axiom_wallet::derive_account(&seed, 0).map_err(|e| AppError::Wallet(e.to_string()))?;
    let addr = axiom_wallet::Address::from_pubkey_hash(kp.public_key_hash());

    let data = WalletData {
        seed_hex: hex::encode(seed.as_slice()),
        account_count: 1,
        seed_phrase: Some(phrase),
    };
    let pt =
        Zeroizing::new(serde_json::to_vec(&data).map_err(|e| AppError::Internal(e.to_string()))?);
    let ks = axiom_wallet::create_keystore(&pt, &password)
        .map_err(|e| AppError::Wallet(e.to_string()))?;
    let json = axiom_wallet::export_keystore(&ks).map_err(|e| AppError::Wallet(e.to_string()))?;

    state.write_keystore(&json)?;

    let session = Session::new(data, password)?;
    *state
        .session
        .lock()
        .map_err(|_| AppError::Internal("lock".into()))? = Some(session);
    *state
        .last_activity
        .lock()
        .map_err(|_| AppError::Internal("lock".into()))? = Instant::now();

    Ok(ImportResult {
        address: addr.to_string(),
    })
}

#[tauri::command]
pub fn unlock_wallet(
    password: String,
    state: tauri::State<'_, AppState>,
) -> AppResult<UnlockResult> {
    if !state.wallet_exists() {
        return Err(AppError::NoWallet);
    }

    {
        let rl = state
            .rate_limiter
            .lock()
            .map_err(|_| AppError::Internal("lock".into()))?;
        if let Err(s) = rl.check() {
            return Err(AppError::RateLimited(s));
        }
    }

    let json = state.read_keystore()?;
    let ks = axiom_wallet::import_keystore(&json).map_err(|e| AppError::Wallet(e.to_string()))?;

    let pt = match axiom_wallet::unlock_keystore(&ks, &password) {
        Ok(p) => {
            state
                .rate_limiter
                .lock()
                .map_err(|_| AppError::Internal("lock".into()))?
                .record_success();
            p
        }
        Err(_) => {
            let lockout = state
                .rate_limiter
                .lock()
                .map_err(|_| AppError::Internal("lock".into()))?
                .record_failure();
            return Err(lockout
                .map(AppError::RateLimited)
                .unwrap_or(AppError::WrongPassword));
        }
    };

    let data: WalletData =
        serde_json::from_slice(&pt).map_err(|e| AppError::Internal(format!("corrupt: {e}")))?;
    let session = Session::new(data, password)?;
    let addr = session.address(0)?.to_string();
    let count = session.account_count;

    *state
        .session
        .lock()
        .map_err(|_| AppError::Internal("lock".into()))? = Some(session);
    *state
        .last_activity
        .lock()
        .map_err(|_| AppError::Internal("lock".into()))? = Instant::now();

    // Migrate: create device key and seal keystore if not yet protected
    if state
        .device_secret
        .lock()
        .map(|ds| ds.is_none())
        .unwrap_or(true)
    {
        if let Some(secret) = crate::keyring::get_or_create_device_secret() {
            if let Ok(mut cache) = state.cache.lock() {
                cache.enable_encryption(&state.data_dir, secret.as_slice());
            }
            if let Ok(mut ds) = state.device_secret.lock() {
                *ds = Some(secret);
            }
            let _ = state.persist();
        }
    }

    Ok(UnlockResult {
        address: addr,
        account_count: count,
    })
}

#[tauri::command]
pub fn lock_wallet(state: tauri::State<'_, AppState>) -> AppResult<()> {
    *state
        .session
        .lock()
        .map_err(|_| AppError::Internal("lock".into()))? = None;
    *state
        .pending_tx
        .lock()
        .map_err(|_| AppError::Internal("lock".into()))? = None;
    Ok(())
}

#[tauri::command]
pub fn check_session(state: tauri::State<'_, AppState>) -> SessionStatus {
    let locked = state.session.lock().map(|s| s.is_none()).unwrap_or(true);
    if locked {
        return SessionStatus {
            locked: true,
            remaining_secs: 0,
        };
    }

    let elapsed = state
        .last_activity
        .lock()
        .map(|t| t.elapsed())
        .unwrap_or_default();
    let timeout = state
        .lock_timeout
        .lock()
        .map(|d| *d)
        .unwrap_or(std::time::Duration::from_secs(300));

    if elapsed >= timeout {
        let _ = state.session.lock().map(|mut s| *s = None);
        let _ = state.pending_tx.lock().map(|mut p| *p = None);
        return SessionStatus {
            locked: true,
            remaining_secs: 0,
        };
    }
    SessionStatus {
        locked: false,
        remaining_secs: (timeout - elapsed).as_secs(),
    }
}

#[tauri::command]
pub fn get_seed_phrase(password: String, state: tauri::State<'_, AppState>) -> AppResult<String> {
    state.touch()?;

    // Reveal-seed is a high-value password check — gate it with the same
    // rate limiter that protects unlock so an attacker who can call this
    // RPC cannot brute-force the password unbounded.
    {
        let rl = state
            .rate_limiter
            .lock()
            .map_err(|_| AppError::Internal("lock".into()))?;
        if let Err(s) = rl.check() {
            return Err(AppError::RateLimited(s));
        }
    }

    let json = state.read_keystore()?;
    let ks = axiom_wallet::import_keystore(&json).map_err(|e| AppError::Wallet(e.to_string()))?;
    if axiom_wallet::unlock_keystore(&ks, &password).is_err() {
        let lockout = state
            .rate_limiter
            .lock()
            .map_err(|_| AppError::Internal("lock".into()))?
            .record_failure();
        return Err(lockout
            .map(AppError::RateLimited)
            .unwrap_or(AppError::WrongPassword));
    }
    state
        .rate_limiter
        .lock()
        .map_err(|_| AppError::Internal("lock".into()))?
        .record_success();

    let session = state
        .session
        .lock()
        .map_err(|_| AppError::Internal("lock".into()))?;
    let session = session.as_ref().ok_or(AppError::Locked)?;
    session
        .seed_phrase()
        .map(String::from)
        .ok_or_else(|| AppError::Internal("no seed phrase".into()))
}
