use serde::Serialize;

use axiom_primitives::{Amount, Hash256};
use axiom_wallet::{Address, TransactionBuilder};

use crate::commands::account::fmt_axm;
use crate::error::{AppError, AppResult};
use crate::rpc::RpcClient;
use crate::state::{AppState, PendingTx, SelectedUtxo};

const DUST: u64 = 546;
const DEFAULT_FEE: u64 = 10_000;
const CHAIN_ID: &str = "axiom-mainnet";

#[derive(Serialize)]
pub struct TxPreview {
    pub from: String,
    pub to: String,
    pub amount_sat: u64,
    pub amount_axm: String,
    pub fee_sat: u64,
    pub total_sat: u64,
    pub change_sat: u64,
}

#[derive(Serialize)]
pub struct SendResult { pub txid: String }

#[derive(Serialize)]
pub struct TxHistoryEntry {
    pub txid: String,
    pub block_height: Option<u32>,
    pub timestamp: Option<u32>,
    pub value_change: i64,
    pub direction: String,
    pub amount_axm: String,
}

#[tauri::command]
pub async fn prepare_send(to: String, amount_sat: u64, state: tauri::State<'_, AppState>) -> AppResult<TxPreview> {
    state.touch()?;
    Address::from_string(&to).map_err(|_| AppError::InvalidAddress(to.clone()))?;
    if amount_sat < DUST { return Err(AppError::DustAmount); }

    let (from, url) = {
        let s = state.session.lock().map_err(|_| AppError::Internal("lock".into()))?;
        let s = s.as_ref().ok_or(AppError::Locked)?;
        (s.address(0)?.to_string(), state.node_url.lock().map_err(|_| AppError::Internal("lock".into()))?.clone())
    };

    let rpc = RpcClient::new(&url);
    let utxos = rpc.utxos(&from).await?;
    let fee = rpc.fee_estimate().await.map(|f| f.medium).unwrap_or(DEFAULT_FEE);
    let nonce = rpc.nonce(&from).await?;

    let needed = amount_sat.checked_add(fee).ok_or(AppError::Internal("overflow".into()))?;
    let mut sorted = utxos;
    sorted.sort_by(|a, b| b.value.cmp(&a.value));

    let mut selected = Vec::new();
    let mut total: u64 = 0;
    for u in &sorted {
        if total >= needed { break; }
        selected.push(SelectedUtxo { txid: u.txid.clone(), output_index: u.output_index, value: u.value });
        total = total.saturating_add(u.value);
    }
    if total < needed { return Err(AppError::InsufficientFunds { have: total, need: needed }); }

    let change = total - amount_sat - fee;
    *state.pending_tx.lock().map_err(|_| AppError::Internal("lock".into()))? = Some(PendingTx {
        to_address: to.clone(), amount_sat, fee_sat: fee, from_address: from.clone(),
        account_index: 0, utxos: selected, chain_id: CHAIN_ID.into(), nonce,
    });

    Ok(TxPreview { from, to, amount_sat, amount_axm: fmt_axm(amount_sat), fee_sat: fee, total_sat: needed, change_sat: change })
}

#[tauri::command]
pub async fn confirm_send(state: tauri::State<'_, AppState>) -> AppResult<SendResult> {
    state.touch()?;
    let ptx = state.pending_tx.lock().map_err(|_| AppError::Internal("lock".into()))?.take().ok_or(AppError::NoPendingTx)?;

    let signed_hex = {
        let s = state.session.lock().map_err(|_| AppError::Internal("lock".into()))?;
        let s = s.as_ref().ok_or(AppError::Locked)?;
        let kp = s.keypair(ptx.account_index)?;

        let mut b = TransactionBuilder::new().chain_id(&ptx.chain_id).nonce(ptx.nonce);
        for u in &ptx.utxos {
            let txid = Hash256::from_slice(&hex::decode(&u.txid).map_err(|_| AppError::Internal("hex".into()))?)
                .map_err(|e| AppError::Internal(e.to_string()))?;
            b = b.add_input(txid, u.output_index);
        }

        let to = Address::from_string(&ptx.to_address).map_err(|_| AppError::InvalidAddress(ptx.to_address.clone()))?;
        b = b.add_output(Amount::from_sat(ptx.amount_sat).map_err(|e| AppError::Wallet(e.to_string()))?, *to.pubkey_hash());

        let total_in: u64 = ptx.utxos.iter().map(|u| u.value).sum();
        let change = total_in - ptx.amount_sat - ptx.fee_sat;
        if change >= DUST {
            let from = Address::from_string(&ptx.from_address).map_err(|_| AppError::InvalidAddress(ptx.from_address.clone()))?;
            b = b.add_output(Amount::from_sat(change).map_err(|e| AppError::Wallet(e.to_string()))?, *from.pubkey_hash());
        }

        let tx = b.keypair(kp).build().map_err(|e| AppError::Wallet(e.to_string()))?;
        hex::encode(axiom_protocol::serialize_transaction(&tx))
    };

    let url = state.node_url.lock().map_err(|_| AppError::Internal("lock".into()))?.clone();
    let txid = RpcClient::new(&url).submit_tx(&signed_hex).await?;
    Ok(SendResult { txid })
}

#[tauri::command]
pub fn cancel_send(state: tauri::State<'_, AppState>) -> AppResult<()> {
    *state.pending_tx.lock().map_err(|_| AppError::Internal("lock".into()))? = None;
    Ok(())
}

#[tauri::command]
pub async fn get_history(state: tauri::State<'_, AppState>) -> AppResult<Vec<TxHistoryEntry>> {
    state.touch()?;
    let (addr, url) = {
        let s = state.session.lock().map_err(|_| AppError::Internal("lock".into()))?;
        let s = s.as_ref().ok_or(AppError::Locked)?;
        (s.address(0)?.to_string(), state.node_url.lock().map_err(|_| AppError::Internal("lock".into()))?.clone())
    };

    let rpc = RpcClient::new(&url);
    match rpc.tx_history(&addr).await {
        Ok(txs) => {
            state.cache.lock().map_err(|_| AppError::Internal("lock".into()))?.set_transactions(&addr, txs.clone());
            Ok(txs.iter().map(|t| to_entry(t)).collect())
        }
        Err(_) => {
            let c = state.cache.lock().map_err(|_| AppError::Internal("lock".into()))?;
            Ok(c.get_txs(&addr).iter().map(|t| TxHistoryEntry {
                txid: t.txid.clone(), block_height: t.block_height, timestamp: t.timestamp,
                value_change: t.value_change,
                direction: if t.value_change >= 0 { "received" } else { "sent" }.into(),
                amount_axm: fmt_axm(t.value_change.unsigned_abs()),
            }).collect())
        }
    }
}

#[tauri::command]
pub fn sign_offline(unsigned_hex: String, state: tauri::State<'_, AppState>) -> AppResult<String> {
    state.touch()?;
    let s = state.session.lock().map_err(|_| AppError::Internal("lock".into()))?;
    let s = s.as_ref().ok_or(AppError::Locked)?;
    let bytes = hex::decode(&unsigned_hex).map_err(|_| AppError::Internal("bad hex".into()))?;
    let kp = s.keypair(0)?;
    let hash = axiom_crypto::transaction_signing_hash(CHAIN_ID, &bytes);
    let sig = kp.sign(hash.as_bytes()).map_err(|e| AppError::Wallet(e.to_string()))?;
    Ok(hex::encode(sig))
}

fn to_entry(t: &crate::rpc::TxSummary) -> TxHistoryEntry {
    TxHistoryEntry {
        txid: t.txid.clone(), block_height: t.block_height, timestamp: t.timestamp,
        value_change: t.value_change,
        direction: if t.value_change >= 0 { "received" } else { "sent" }.into(),
        amount_axm: fmt_axm(t.value_change.unsigned_abs()),
    }
}
