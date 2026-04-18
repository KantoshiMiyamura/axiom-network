use serde::Serialize;

use crate::error::{AppError, AppResult};
use crate::rpc::RpcClient;
use crate::state::AppState;

#[derive(Serialize)]
pub struct AddressEntry { pub index: u32, pub address: String }

#[derive(Serialize)]
pub struct BalanceInfo {
    pub total_sat: u64,
    pub total_axm: String,
    pub address: String,
    pub from_cache: bool,
}

#[tauri::command]
pub fn get_addresses(state: tauri::State<'_, AppState>) -> AppResult<Vec<AddressEntry>> {
    state.touch()?;
    let s = state.session.lock().map_err(|_| AppError::Internal("lock".into()))?;
    let s = s.as_ref().ok_or(AppError::Locked)?;
    (0..s.account_count).map(|i| Ok(AddressEntry { index: i, address: s.address(i)?.to_string() })).collect()
}

#[tauri::command]
pub fn new_address(state: tauri::State<'_, AppState>) -> AppResult<AddressEntry> {
    state.touch()?;
    let entry = {
        let mut s = state.session.lock().map_err(|_| AppError::Internal("lock".into()))?;
        let s = s.as_mut().ok_or(AppError::Locked)?;
        let (a, i) = s.new_address()?;
        AddressEntry { index: i, address: a.to_string() }
    };
    state.persist()?;
    Ok(entry)
}

#[tauri::command]
pub async fn refresh_balance(state: tauri::State<'_, AppState>) -> AppResult<BalanceInfo> {
    state.touch()?;
    let (addr, url) = {
        let s = state.session.lock().map_err(|_| AppError::Internal("lock".into()))?;
        let s = s.as_ref().ok_or(AppError::Locked)?;
        (s.address(0)?.to_string(), state.node_url.lock().map_err(|_| AppError::Internal("lock".into()))?.clone())
    };

    let client = RpcClient::new(&url);
    match client.balance(&addr).await {
        Ok(bal) => {
            state.cache.lock().map_err(|_| AppError::Internal("lock".into()))?.set_balance(&addr, bal);
            Ok(BalanceInfo { total_sat: bal, total_axm: fmt_axm(bal), address: addr, from_cache: false })
        }
        Err(_) => {
            let bal = state.cache.lock().map_err(|_| AppError::Internal("lock".into()))?.get_balance(&addr).unwrap_or(0);
            Ok(BalanceInfo { total_sat: bal, total_axm: fmt_axm(bal), address: addr, from_cache: true })
        }
    }
}

#[tauri::command]
pub fn get_cached_balance(state: tauri::State<'_, AppState>) -> AppResult<BalanceInfo> {
    state.touch()?;
    let addr = {
        let s = state.session.lock().map_err(|_| AppError::Internal("lock".into()))?;
        s.as_ref().ok_or(AppError::Locked)?.address(0)?.to_string()
    };
    let bal = state.cache.lock().map_err(|_| AppError::Internal("lock".into()))?.get_balance(&addr).unwrap_or(0);
    Ok(BalanceInfo { total_sat: bal, total_axm: fmt_axm(bal), address: addr, from_cache: true })
}

pub fn fmt_axm(sat: u64) -> String {
    let w = sat / 100_000_000;
    let f = sat % 100_000_000;
    if f == 0 { format!("{w}.0") } else { format!("{w}.{f:08}").trim_end_matches('0').into() }
}
