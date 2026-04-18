use serde::Serialize;

use crate::error::{AppError, AppResult};
use crate::state::AppState;

#[derive(Serialize)]
pub struct AddressValidationResult {
    pub valid: bool,
    pub checksummed: bool,
    pub legacy_format: bool,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct IntegrityInfo {
    pub binary_hash: Option<String>,
    pub keystore_hash: Option<String>,
    pub device_protection: bool,
    pub cache_encrypted: bool,
}

/// Copy text to clipboard with automatic clearing after timeout.
#[tauri::command]
pub fn secure_copy(text: String, clear_after_ms: Option<u64>) -> AppResult<()> {
    crate::security::clipboard_copy_and_clear(&text, clear_after_ms)
        .map_err(AppError::Internal)
}

/// Validate an address and return detailed information.
#[tauri::command]
pub fn validate_address_info(address: String) -> AddressValidationResult {
    if !address.starts_with("axm") {
        return AddressValidationResult {
            valid: false,
            checksummed: false,
            legacy_format: false,
            error: Some("Address must start with 'axm'".into()),
        };
    }
    match axiom_wallet::Address::from_string(&address) {
        Ok(_) => {
            let hex_len = address.len() - 3;
            AddressValidationResult {
                valid: true,
                checksummed: hex_len == 72,
                legacy_format: hex_len == 64,
                error: None,
            }
        }
        Err(e) => AddressValidationResult {
            valid: false,
            checksummed: false,
            legacy_format: false,
            error: Some(e.to_string()),
        },
    }
}

/// Return integrity and security status of the wallet application.
#[tauri::command]
pub fn get_integrity_info(state: tauri::State<'_, AppState>) -> IntegrityInfo {
    let binary_hash = crate::security::binary_checksum();
    let keystore_hash = if state.sealed_path.exists() {
        crate::security::file_checksum(&state.sealed_path)
    } else {
        crate::security::file_checksum(&state.keystore_path)
    };
    let device_protection = state
        .device_secret
        .lock()
        .map(|ds| ds.is_some())
        .unwrap_or(false);
    IntegrityInfo {
        binary_hash,
        keystore_hash,
        device_protection,
        cache_encrypted: device_protection,
    }
}

/// Clear all cached data for a specific account address (multi-account isolation).
#[tauri::command]
pub fn clear_account_cache(address: String, state: tauri::State<'_, AppState>) -> AppResult<()> {
    state.touch()?;
    state
        .cache
        .lock()
        .map_err(|_| AppError::Internal("lock".into()))?
        .clear_account(&address);
    Ok(())
}
