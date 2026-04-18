#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod cache;
mod commands;
mod error;
mod keyring;
mod rpc;
mod security;
mod state;

use state::AppState;

fn main() {
    let data_dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("axiom-wallet");
    std::fs::create_dir_all(&data_dir).expect("failed to create data directory");

    let app_state = AppState::new(data_dir);

    tauri::Builder::default()
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            // Wallet lifecycle
            commands::wallet::wallet_exists,
            commands::wallet::create_wallet,
            commands::wallet::import_wallet_seed,
            commands::wallet::unlock_wallet,
            commands::wallet::lock_wallet,
            commands::wallet::check_session,
            commands::wallet::get_seed_phrase,
            // Account
            commands::account::get_addresses,
            commands::account::new_address,
            commands::account::refresh_balance,
            commands::account::get_cached_balance,
            // Transactions
            commands::transaction::prepare_send,
            commands::transaction::confirm_send,
            commands::transaction::cancel_send,
            commands::transaction::get_history,
            commands::transaction::sign_offline,
            // Settings
            commands::settings::get_settings,
            commands::settings::set_node_url,
            commands::settings::set_lock_timeout,
            commands::settings::get_network_status,
            commands::settings::generate_qr,
            // Security
            commands::security::secure_copy,
            commands::security::validate_address_info,
            commands::security::get_integrity_info,
            commands::security::clear_account_cache,
        ])
        .run(tauri::generate_context!())
        .expect("failed to launch Axiom Wallet");
}
