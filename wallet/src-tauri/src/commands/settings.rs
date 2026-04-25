use serde::Serialize;
use std::time::Duration;

use crate::error::{AppError, AppResult};
use crate::rpc::RpcClient;
use crate::state::AppState;

#[derive(Serialize)]
pub struct WalletSettings {
    pub node_url: String,
    pub lock_timeout_secs: u64,
}

#[derive(Serialize)]
pub struct NetworkStatus {
    pub online: bool,
    pub block_height: Option<u32>,
    pub peer_count: Option<usize>,
    pub node_url: String,
}

#[tauri::command]
pub fn get_settings(state: tauri::State<'_, AppState>) -> AppResult<WalletSettings> {
    Ok(WalletSettings {
        node_url: state
            .node_url
            .lock()
            .map_err(|_| AppError::Internal("lock".into()))?
            .clone(),
        lock_timeout_secs: state
            .lock_timeout
            .lock()
            .map_err(|_| AppError::Internal("lock".into()))?
            .as_secs(),
    })
}

#[tauri::command]
pub fn set_node_url(url: String, state: tauri::State<'_, AppState>) -> AppResult<()> {
    if url.is_empty() {
        return Err(AppError::Internal("url cannot be empty".into()));
    }
    *state
        .node_url
        .lock()
        .map_err(|_| AppError::Internal("lock".into()))? = url;
    // Pointing at a different node may mean a different chain — invalidate
    // the cached chain id so the next signing path re-queries `/status`.
    *state
        .chain_id
        .lock()
        .map_err(|_| AppError::Internal("lock".into()))? = None;
    state.save_settings()
}

#[tauri::command]
pub fn set_lock_timeout(secs: u64, state: tauri::State<'_, AppState>) -> AppResult<()> {
    if secs < 30 {
        return Err(AppError::Internal("minimum 30 seconds".into()));
    }
    *state
        .lock_timeout
        .lock()
        .map_err(|_| AppError::Internal("lock".into()))? = Duration::from_secs(secs);
    state.save_settings()
}

#[tauri::command]
pub async fn get_network_status(state: tauri::State<'_, AppState>) -> AppResult<NetworkStatus> {
    let url = state
        .node_url
        .lock()
        .map_err(|_| AppError::Internal("lock".into()))?
        .clone();
    let rpc = RpcClient::new(&url);
    match rpc.status().await {
        Ok(s) => Ok(NetworkStatus {
            online: true,
            block_height: s.block_height,
            peer_count: Some(s.peer_count),
            node_url: url,
        }),
        Err(_) => Ok(NetworkStatus {
            online: false,
            block_height: None,
            peer_count: None,
            node_url: url,
        }),
    }
}

#[tauri::command]
pub fn generate_qr(data: String) -> AppResult<String> {
    use qrcode::render::svg;
    use qrcode::QrCode;
    let code = QrCode::new(data.as_bytes()).map_err(|e| AppError::Internal(format!("qr: {e}")))?;
    Ok(code
        .render()
        .min_dimensions(200, 200)
        .dark_color(svg::Color("#e4e4e7"))
        .light_color(svg::Color("#09090b"))
        .build())
}
