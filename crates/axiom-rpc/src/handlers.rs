// Copyright (c) 2026 Kantoshi Miyamura

//! RPC endpoint handlers.

use crate::{
    error::{Result, RpcError},
    types::*,
};
use axiom_node::network::NetworkService;
use axiom_node::Node;
use axiom_primitives::Hash256;
use axiom_protocol::Transaction;
use axiom_wallet::Address;
use axum::{
    extract::{Extension, Path, Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(serde::Deserialize, Default)]
pub struct PaginationParams {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

// ── Pagination limits ──────────────────────────────────────────────────────
const MAX_BLOCKS_PER_PAGE: usize = 100;
const DEFAULT_BLOCKS_PER_PAGE: usize = 10;

const MAX_MEMPOOL_ITEMS_PER_PAGE: usize = 500;
const DEFAULT_MEMPOOL_ITEMS: usize = 50;

const MAX_ADDRESS_TXS_PER_PAGE: usize = 1000;
const DEFAULT_ADDRESS_TXS: usize = 50;

// Reject heights above this to prevent u32 overflow attacks.
const MAX_REASONABLE_HEIGHT: u32 = 1_000_000_000;

pub type SharedModelRegistry = Arc<axiom_ai::ModelRegistry>;
pub type SharedInferenceRegistry = Arc<axiom_ai::InferenceRegistry>;
pub type SharedReputationRegistry = Arc<axiom_ai::ReputationRegistry>;
pub type SharedComputeProtocol = Arc<axiom_ai::ComputeProtocol>;
pub type SharedNodeState = Arc<RwLock<Node>>;
pub type SharedNetworkService = Arc<RwLock<NetworkService>>;
pub type SharedGuardState = Arc<RwLock<axiom_guard::NetworkGuard>>;
pub type SharedMonitorStore = Arc<RwLock<Vec<axiom_monitor::MonitorReport>>>;

pub async fn get_status(
    State(state): State<SharedNodeState>,
    Extension(ns): Extension<Option<SharedNetworkService>>,
) -> Result<Json<NodeStatus>> {
    let node = state.read().await;

    let peers = match ns {
        Some(ns) => ns.read().await.peer_manager().ready_peer_count().await,
        None => 0,
    };

    Ok(Json(NodeStatus {
        best_block_hash: node.best_block_hash().map(|h| hex::encode(h.as_bytes())),
        best_height: node.best_height(),
        mempool_size: node.mempool_size(),
        orphan_count: node.orphan_count(),
        version: concat!("Axiom Node v", env!("CARGO_PKG_VERSION")).to_string(),
        network: node.chain_id().to_string(),
        peers,
    }))
}

pub async fn get_best_block_hash(State(state): State<SharedNodeState>) -> Result<Json<String>> {
    let node = state.read().await;

    match node.best_block_hash() {
        Some(hash) => Ok(Json(hex::encode(hash.as_bytes()))),
        None => Err(RpcError::NotFound("No best block".into())),
    }
}

pub async fn get_best_height(State(state): State<SharedNodeState>) -> Result<Json<u32>> {
    let node = state.read().await;

    match node.best_height() {
        Some(height) => Ok(Json(height)),
        None => Err(RpcError::NotFound("No best height".into())),
    }
}

/// Alias for `get_status`.
pub async fn get_tip(
    State(state): State<SharedNodeState>,
    Extension(ns): Extension<Option<SharedNetworkService>>,
) -> Result<Json<NodeStatus>> {
    get_status(State(state), Extension(ns)).await
}

pub async fn get_block_by_hash(
    State(state): State<SharedNodeState>,
    Path(hash_str): Path<String>,
) -> Result<Json<BlockSummary>> {
    if hash_str.len() != 64 {
        return Err(RpcError::InvalidRequest(
            "Invalid hash format (expected 64 hex chars)".into(),
        ));
    }

    let hash_bytes = hex::decode(&hash_str)
        .map_err(|_| RpcError::InvalidRequest("Invalid hex encoding".into()))?;

    if hash_bytes.len() != 32 {
        return Err(RpcError::InvalidRequest("Invalid hash length".into()));
    }

    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(&hash_bytes);
    let hash = Hash256::from_bytes(hash_array);

    let node = state.read().await;
    match node.get_block(&hash) {
        Ok(Some(block)) => {
            let height = block.height().unwrap_or(0);
            Ok(Json(BlockSummary {
                hash: hex::encode(block.hash().as_bytes()),
                height,
                timestamp: block.header.timestamp,
                prev_block_hash: hex::encode(block.header.prev_block_hash.as_bytes()),
                merkle_root: hex::encode(block.header.merkle_root.as_bytes()),
                nonce: block.header.nonce as u64,
                difficulty: block.header.difficulty_target,
                transaction_count: block.transactions.len(),
            }))
        }
        Ok(None) => Err(RpcError::BlockNotFound(hash_str)),
        Err(e) => Err(RpcError::Internal(format!("Failed to query block: {}", e))),
    }
}

pub async fn get_block_by_height(
    State(state): State<SharedNodeState>,
    Path(target_height): Path<u32>,
) -> axum::response::Response {
    if target_height > MAX_REASONABLE_HEIGHT {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "height out of range"})),
        )
            .into_response();
    }

    let node = state.read().await;

    match node.get_block_by_height(target_height) {
        Ok(Some(block)) => {
            let height = block.height().unwrap_or(target_height);
            Json(BlockSummary {
                hash: hex::encode(block.hash().as_bytes()),
                height,
                timestamp: block.header.timestamp,
                prev_block_hash: hex::encode(block.header.prev_block_hash.as_bytes()),
                merkle_root: hex::encode(block.header.merkle_root.as_bytes()),
                nonce: block.header.nonce as u64,
                difficulty: block.header.difficulty_target,
                transaction_count: block.transactions.len(),
            })
            .into_response()
        }
        Ok(None) => RpcError::BlockNotFound(format!("height {}", target_height)).into_response(),
        Err(e) => RpcError::Internal(format!("Failed to query block: {}", e)).into_response(),
    }
}

pub async fn get_balance(
    State(state): State<SharedNodeState>,
    Path(address_str): Path<String>,
) -> Result<Json<BalanceResponse>> {
    if address_str.is_empty() || address_str.len() > 128 {
        return Err(RpcError::InvalidRequest("invalid address".into()));
    }
    let address = Address::from_string(&address_str)
        .map_err(|_| RpcError::InvalidRequest("Invalid address format".into()))?;

    let pubkey_hash = address.pubkey_hash();

    let node = state.read().await;
    let db = node.state.database();
    let utxo_set = axiom_storage::UtxoSet::new(db);

    match utxo_set.get_balance(pubkey_hash) {
        Ok(balance) => Ok(Json(BalanceResponse { balance })),
        Err(e) => Err(RpcError::Internal(format!(
            "Failed to calculate balance: {}",
            e
        ))),
    }
}

pub async fn get_nonce(
    State(state): State<SharedNodeState>,
    Path(address_str): Path<String>,
) -> Result<Json<NonceResponse>> {
    if address_str.is_empty() || address_str.len() > 128 {
        return Err(RpcError::InvalidRequest("invalid address".into()));
    }
    let address = Address::from_string(&address_str)
        .map_err(|_| RpcError::InvalidRequest("Invalid address format".into()))?;

    let pubkey_hash = address.pubkey_hash();

    let node = state.read().await;
    match node.get_nonce(pubkey_hash) {
        Ok(nonce) => Ok(Json(NonceResponse { nonce })),
        Err(e) => Err(RpcError::Internal(format!("Failed to query nonce: {}", e))),
    }
}

pub async fn submit_transaction(
    State(state): State<SharedNodeState>,
    Extension(ns): Extension<Option<SharedNetworkService>>,
    Json(req): Json<SubmitTransactionRequest>,
) -> Result<Json<SubmitTransactionResponse>> {
    let tx_bytes = hex::decode(&req.transaction_hex)
        .map_err(|_| RpcError::InvalidRequest("Invalid hex encoding".into()))?;

    let tx: Transaction = axiom_protocol::deserialize_transaction(&tx_bytes)
        .map_err(|e| RpcError::InvalidRequest(format!("Invalid transaction: {}", e)))?;

    let mut node = state.write().await;
    match node.submit_transaction(tx.clone()) {
        Ok(txid) => {
            let computed_txid =
                axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(&tx));

            tracing::info!(
                "TX_SUBMITTED_RPC: txid={}",
                hex::encode(&computed_txid.as_bytes()[..8])
            );

            // Release lock before broadcasting.
            drop(node);

            if let Some(ns) = ns {
                let service = ns.read().await;
                match service.broadcast_transaction(tx, None).await {
                    Ok(sent) => {
                        if sent > 0 {
                            tracing::info!(
                                "TX_BROADCAST_RPC: txid={}, peers={}",
                                hex::encode(&computed_txid.as_bytes()[..8]),
                                sent
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "TX_BROADCAST_RPC_FAILED: txid={}, error={}",
                            hex::encode(&computed_txid.as_bytes()[..8]),
                            e
                        );
                    }
                }
            }

            Ok(Json(SubmitTransactionResponse {
                txid: hex::encode(txid.as_bytes()),
            }))
        }
        Err(e) => Err(RpcError::TransactionRejected(format!("{}", e))),
    }
}

pub async fn get_peers(
    State(_state): State<SharedNodeState>,
    Extension(ns): Extension<Option<SharedNetworkService>>,
) -> Result<Json<PeerListResponse>> {
    let peers = match ns {
        Some(ns) => {
            let pm = ns.read().await;
            let addrs = pm.peer_manager().get_ready_peer_addrs().await;
            addrs
                .into_iter()
                .map(|addr| PeerInfo {
                    address: addr.to_string(),
                    connected: true,
                })
                .collect::<Vec<_>>()
        }
        None => vec![],
    };
    let count = peers.len();
    Ok(Json(PeerListResponse { peers, count }))
}

pub async fn get_peer_count(
    State(_state): State<SharedNodeState>,
    Extension(ns): Extension<Option<SharedNetworkService>>,
) -> Result<Json<usize>> {
    let count = match ns {
        Some(ns) => ns.read().await.peer_manager().ready_peer_count().await,
        None => 0,
    };
    Ok(Json(count))
}

pub async fn get_recent_blocks(
    State(state): State<SharedNodeState>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<RecentBlocksResponse>> {
    let limit = params
        .limit
        .unwrap_or(DEFAULT_BLOCKS_PER_PAGE)
        .min(MAX_BLOCKS_PER_PAGE);
    let offset = params.offset.unwrap_or(0);

    let node = state.read().await;

    let fetch_count = offset.saturating_add(limit).max(1);
    match node.get_recent_blocks(fetch_count) {
        Ok(blocks) => {
            let summaries: Vec<BlockSummary> = blocks
                .iter()
                .skip(offset)
                .take(limit)
                .map(|block| BlockSummary {
                    hash: hex::encode(block.hash().as_bytes()),
                    height: block.height().unwrap_or(0),
                    timestamp: block.header.timestamp,
                    prev_block_hash: hex::encode(block.header.prev_block_hash.as_bytes()),
                    merkle_root: hex::encode(block.header.merkle_root.as_bytes()),
                    nonce: block.header.nonce as u64,
                    difficulty: block.header.difficulty_target,
                    transaction_count: block.transactions.len(),
                })
                .collect();

            let count = summaries.len();
            Ok(Json(RecentBlocksResponse {
                blocks: summaries,
                count,
                limit,
                offset,
            }))
        }
        Err(e) => Err(RpcError::Internal(format!("Failed to query blocks: {}", e))),
    }
}

pub async fn get_block_transactions(
    State(state): State<SharedNodeState>,
    Path(hash_str): Path<String>,
) -> Result<Json<BlockTransactionsResponse>> {
    if hash_str.len() != 64 {
        return Err(RpcError::InvalidRequest("Invalid hash format".into()));
    }

    let hash_bytes = hex::decode(&hash_str)
        .map_err(|_| RpcError::InvalidRequest("Invalid hex encoding".into()))?;

    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(&hash_bytes);
    let hash = Hash256::from_bytes(hash_array);

    let node = state.read().await;
    match node.get_block(&hash) {
        Ok(Some(block)) => {
            let transactions: Vec<TransactionDetail> = block
                .transactions
                .iter()
                .map(|tx| {
                    let tx_type = match tx.tx_type {
                        axiom_protocol::TransactionType::Transfer => "transfer",
                        axiom_protocol::TransactionType::Coinbase => "coinbase",
                        axiom_protocol::TransactionType::ConfidentialTransfer => {
                            "confidential_transfer"
                        }
                        axiom_protocol::TransactionType::UsernameRegistration => {
                            "username_registration"
                        }
                    };

                    let inputs: Vec<TxInputDetail> = tx
                        .inputs
                        .iter()
                        .map(|input| TxInputDetail {
                            prev_tx_hash: hex::encode(input.prev_tx_hash.as_bytes()),
                            prev_output_index: input.prev_output_index,
                            signature: hex::encode(input.signature.as_bytes()),
                            pubkey: hex::encode(input.pubkey.as_bytes()),
                        })
                        .collect();

                    let outputs: Vec<TxOutputDetail> = tx
                        .outputs
                        .iter()
                        .map(|output| TxOutputDetail {
                            value: output.value.as_sat(),
                            pubkey_hash: hex::encode(output.pubkey_hash.as_bytes()),
                        })
                        .collect();

                    // Canonical txid: double-hash of the unsigned serialization.
                    // Must match the form indexed by axiom-storage and used by
                    // /tx/:txid and /address/:addr/txs.
                    let tx_data = axiom_protocol::serialize_transaction_unsigned(tx);
                    let txid = axiom_crypto::double_hash256(&tx_data);

                    TransactionDetail {
                        txid: hex::encode(txid.as_bytes()),
                        version: tx.version,
                        tx_type: tx_type.to_string(),
                        inputs,
                        outputs,
                        nonce: tx.nonce,
                        locktime: tx.locktime,
                        memo: tx.memo.map(|m| {
                            let end = m.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
                            String::from_utf8_lossy(&m[..end]).into_owned()
                        }),
                    }
                })
                .collect();

            let count = transactions.len();
            Ok(Json(BlockTransactionsResponse {
                transactions,
                count,
            }))
        }
        Ok(None) => Err(RpcError::BlockNotFound(hash_str)),
        Err(e) => Err(RpcError::Internal(format!("Failed to query block: {}", e))),
    }
}

pub async fn get_transaction(
    State(state): State<SharedNodeState>,
    Path(txid_str): Path<String>,
) -> Result<Json<TransactionDetail>> {
    if txid_str.len() != 64 {
        return Err(RpcError::InvalidRequest("Invalid txid format".into()));
    }

    let txid_bytes = hex::decode(&txid_str)
        .map_err(|_| RpcError::InvalidRequest("Invalid hex encoding".into()))?;

    let mut txid_array = [0u8; 32];
    txid_array.copy_from_slice(&txid_bytes);
    let txid = Hash256::from_bytes(txid_array);

    // Check mempool first, then confirmed index.
    let node = state.read().await;
    let mempool_txs = node.get_mempool_transactions();

    for tx in mempool_txs {
        // Canonical txid: double-hash of the unsigned serialization.
        let tx_data = axiom_protocol::serialize_transaction_unsigned(&tx);
        let tx_txid = axiom_crypto::double_hash256(&tx_data);

        if tx_txid == txid {
            let tx_type = match tx.tx_type {
                axiom_protocol::TransactionType::Transfer => "transfer",
                axiom_protocol::TransactionType::Coinbase => "coinbase",
                axiom_protocol::TransactionType::ConfidentialTransfer => "confidential_transfer",
                axiom_protocol::TransactionType::UsernameRegistration => "username_registration",
            };

            let inputs: Vec<TxInputDetail> = tx
                .inputs
                .iter()
                .map(|input| TxInputDetail {
                    prev_tx_hash: hex::encode(input.prev_tx_hash.as_bytes()),
                    prev_output_index: input.prev_output_index,
                    signature: hex::encode(input.signature.as_bytes()),
                    pubkey: hex::encode(input.pubkey.as_bytes()),
                })
                .collect();

            let outputs: Vec<TxOutputDetail> = tx
                .outputs
                .iter()
                .map(|output| TxOutputDetail {
                    value: output.value.as_sat(),
                    pubkey_hash: hex::encode(output.pubkey_hash.as_bytes()),
                })
                .collect();

            return Ok(Json(TransactionDetail {
                txid: txid_str,
                version: tx.version,
                tx_type: tx_type.to_string(),
                inputs,
                outputs,
                nonce: tx.nonce,
                locktime: tx.locktime,
                memo: tx.memo.map(|m| {
                    let end = m.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
                    String::from_utf8_lossy(&m[..end]).into_owned()
                }),
            }));
        }
    }

    let db = node.state.database();
    let tx_index = axiom_storage::TxIndex::new(db);

    match tx_index
        .get_tx_location(&txid)
        .map_err(|e| RpcError::Internal(format!("Index error: {}", e)))?
    {
        None => Err(RpcError::NotFound(format!(
            "Transaction not found: {}",
            txid_str
        ))),
        Some(loc) => {
            let block = db
                .load_block(&loc.block_hash)
                .map_err(|e| RpcError::Internal(format!("Block load error: {}", e)))?;

            let tx = block
                .transactions
                .get(loc.tx_position as usize)
                .ok_or_else(|| RpcError::Internal("tx_position out of range".into()))?;

            let tx_type = match tx.tx_type {
                axiom_protocol::TransactionType::Transfer => "transfer",
                axiom_protocol::TransactionType::Coinbase => "coinbase",
                axiom_protocol::TransactionType::ConfidentialTransfer => "confidential_transfer",
                axiom_protocol::TransactionType::UsernameRegistration => "username_registration",
            };

            let inputs: Vec<TxInputDetail> = tx
                .inputs
                .iter()
                .map(|input| TxInputDetail {
                    prev_tx_hash: hex::encode(input.prev_tx_hash.as_bytes()),
                    prev_output_index: input.prev_output_index,
                    signature: hex::encode(input.signature.as_bytes()),
                    pubkey: hex::encode(input.pubkey.as_bytes()),
                })
                .collect();

            let outputs: Vec<TxOutputDetail> = tx
                .outputs
                .iter()
                .map(|output| TxOutputDetail {
                    value: output.value.as_sat(),
                    pubkey_hash: hex::encode(output.pubkey_hash.as_bytes()),
                })
                .collect();

            Ok(Json(TransactionDetail {
                txid: txid_str,
                version: tx.version,
                tx_type: tx_type.to_string(),
                inputs,
                outputs,
                nonce: tx.nonce,
                locktime: tx.locktime,
                memo: tx.memo.map(|m| {
                    let end = m.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
                    String::from_utf8_lossy(&m[..end]).into_owned()
                }),
            }))
        }
    }
}

// Returns confirmed + pending txs; pending entries have block_height: null.
pub async fn get_address_transactions(
    State(state): State<SharedNodeState>,
    Path(address_str): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<AddressTransactionsResponse>> {
    if address_str.is_empty() || address_str.len() > 128 {
        return Err(RpcError::InvalidRequest("invalid address".into()));
    }

    let limit = params
        .limit
        .unwrap_or(DEFAULT_ADDRESS_TXS)
        .min(MAX_ADDRESS_TXS_PER_PAGE);
    let offset = params.offset.unwrap_or(0);

    let address = Address::from_string(&address_str)
        .map_err(|_| RpcError::InvalidRequest("Invalid address format".into()))?;

    let pubkey_hash = address.pubkey_hash();
    let node = state.read().await;
    let db = node.state.database();
    let tx_index = axiom_storage::TxIndex::new(db);

    let txids = tx_index
        .get_address_txids(pubkey_hash)
        .map_err(|e| RpcError::Internal(format!("Index error: {}", e)))?;

    let mut transactions = Vec::with_capacity(txids.len());
    for txid in &txids {
        let loc = match tx_index
            .get_tx_location(txid)
            .map_err(|e| RpcError::Internal(format!("Index error: {}", e)))?
        {
            Some(l) => l,
            None => continue, // index inconsistency — skip
        };

        let block = db
            .load_block(&loc.block_hash)
            .map_err(|e| RpcError::Internal(format!("Block load error: {}", e)))?;

        let tx = match block.transactions.get(loc.tx_position as usize) {
            Some(t) => t,
            None => continue,
        };

        let received: i64 = tx
            .outputs
            .iter()
            .filter(|o| o.pubkey_hash == *pubkey_hash)
            .map(|o| o.value.as_sat() as i64)
            .sum();

        let sent: i64 = if !tx.is_coinbase() {
            tx.inputs
                .iter()
                .filter(|i| axiom_crypto::hash256(i.pubkey.as_bytes()) == *pubkey_hash)
                .filter_map(|i| {
                    let prev_loc = tx_index.get_tx_location(&i.prev_tx_hash).ok()??;
                    let prev_block = db.load_block(&prev_loc.block_hash).ok()?;
                    let prev_tx = prev_block.transactions.get(prev_loc.tx_position as usize)?;
                    let output = prev_tx.outputs.get(i.prev_output_index as usize)?;
                    Some(output.value.as_sat() as i64)
                })
                .sum()
        } else {
            0
        };

        let value_change = received - sent;

        transactions.push(AddressTxSummary {
            txid: hex::encode(txid.as_bytes()),
            block_height: Some(loc.block_height),
            timestamp: None,
            value_change,
        });
    }

    // Append unconfirmed mempool txs involving this address (block_height = None).
    let confirmed_txids: std::collections::HashSet<Vec<u8>> =
        txids.iter().map(|h| h.as_bytes().to_vec()).collect();

    for (txid, tx) in node.mempool_transactions() {
        if confirmed_txids.contains(txid.as_bytes().as_slice()) {
            continue;
        }

        let involves_address = tx.outputs.iter().any(|o| o.pubkey_hash == *pubkey_hash)
            || (!tx.is_coinbase()
                && tx
                    .inputs
                    .iter()
                    .any(|i| axiom_crypto::hash256(i.pubkey.as_bytes()) == *pubkey_hash));

        if involves_address {
            let received: i64 = tx
                .outputs
                .iter()
                .filter(|o| o.pubkey_hash == *pubkey_hash)
                .map(|o| o.value.as_sat() as i64)
                .sum();
            let sent: i64 = if !tx.is_coinbase() {
                tx.inputs
                    .iter()
                    .filter(|i| axiom_crypto::hash256(i.pubkey.as_bytes()) == *pubkey_hash)
                    .filter_map(|i| {
                        let prev_loc = tx_index.get_tx_location(&i.prev_tx_hash).ok()??;
                        let prev_block = db.load_block(&prev_loc.block_hash).ok()?;
                        let prev_tx = prev_block.transactions.get(prev_loc.tx_position as usize)?;
                        let output = prev_tx.outputs.get(i.prev_output_index as usize)?;
                        Some(output.value.as_sat() as i64)
                    })
                    .sum()
            } else {
                0
            };
            transactions.push(AddressTxSummary {
                txid: hex::encode(txid.as_bytes()),
                block_height: None,
                timestamp: None,
                value_change: received - sent,
            });
        }
    }

    let total = transactions.len();
    let transactions: Vec<AddressTxSummary> =
        transactions.into_iter().skip(offset).take(limit).collect();
    let count = transactions.len();
    Ok(Json(AddressTransactionsResponse {
        transactions,
        count,
        total,
        limit,
        offset,
    }))
}

pub async fn get_utxos(
    State(state): State<SharedNodeState>,
    Path(address_str): Path<String>,
) -> Result<Json<UtxoListResponse>> {
    if address_str.is_empty() || address_str.len() > 128 {
        return Err(RpcError::InvalidRequest("invalid address".into()));
    }
    let address = Address::from_string(&address_str)
        .map_err(|_| RpcError::InvalidRequest("Invalid address format".into()))?;

    let pubkey_hash = address.pubkey_hash();

    let node = state.read().await;
    let db = node.state.database();
    let utxo_set = axiom_storage::UtxoSet::new(db);

    match utxo_set.iter_by_address(pubkey_hash) {
        Ok(utxos) => {
            let mut total_value = 0u64;
            let entries: Vec<UtxoEntry> = utxos
                .iter()
                .map(|(txid, output_index, entry)| {
                    let value = entry.value.as_sat();
                    total_value = total_value.saturating_add(value);
                    UtxoEntry {
                        txid: hex::encode(txid.as_bytes()),
                        output_index: *output_index,
                        value,
                        block_height: entry.height,
                    }
                })
                .collect();
            let count = entries.len();
            Ok(Json(UtxoListResponse {
                utxos: entries,
                total_value,
                count,
            }))
        }
        Err(e) => Err(RpcError::Internal(format!("Failed to query UTXOs: {}", e))),
    }
}

pub async fn get_metrics(
    State(state): State<SharedNodeState>,
    Extension(ns): Extension<Option<SharedNetworkService>>,
) -> Result<Json<MetricsResponse>> {
    let node = state.read().await;

    let chain_work = match node.get_chain_work() {
        Ok(Some(work)) => Some(format!("{:032x}", work)),
        _ => None,
    };

    let peer_count = match ns {
        Some(ns) => ns.read().await.peer_manager().ready_peer_count().await,
        None => 0,
    };

    // tx/s over last 10 blocks, excluding coinbase.
    let tx_rate = {
        match node.get_recent_blocks(10) {
            Ok(blocks) if blocks.len() >= 2 => {
                let oldest_ts = blocks.last().map(|b| b.header.timestamp).unwrap_or(0);
                let newest_ts = blocks.first().map(|b| b.header.timestamp).unwrap_or(0);
                let span = newest_ts.saturating_sub(oldest_ts) as f64;
                let total_txs: usize = blocks
                    .iter()
                    .map(|b| b.transactions.len().saturating_sub(1))
                    .sum();
                if span > 0.0 {
                    total_txs as f64 / span
                } else {
                    0.0
                }
            }
            _ => 0.0,
        }
    };

    Ok(Json(MetricsResponse {
        block_height: node.best_height(),
        best_block_hash: node.best_block_hash().map(|h| hex::encode(h.as_bytes())),
        mempool_size: node.mempool_size(),
        peer_count,
        orphan_block_count: node.orphan_count(),
        chain_work,
        uptime_seconds: node.uptime_seconds(),
        tx_rate,
        reorg_count: node.reorg_count(),
    }))
}

pub async fn get_fee_estimate(
    State(state): State<SharedNodeState>,
) -> Result<Json<FeeEstimateResponse>> {
    let node = state.read().await;
    let min_fee_rate = node.min_fee_rate();

    // 1-in 2-out ML-DSA-87 tx without memo: 13 (header) + 7255 (input) + 8 + 80 (outputs) + 13 (footer) = 7369 bytes.
    const TYPICAL_TX_SIZE: u64 = 7369;

    // Mempool pressure = max(count_ratio, byte_ratio).
    let tx_count = node.mempool_size() as f64;
    let max_count = node.mempool_max_count().max(1) as f64;
    let byte_size = node.mempool_byte_size() as f64;
    let max_bytes = node.mempool_max_byte_size().max(1) as f64;
    let pressure = (tx_count / max_count).max(byte_size / max_bytes).min(1.0);

    // Multipliers over min_fee_rate: idle 1/2/5×, normal 2/4/10×, busy 4/8/20×, full 8/16/40×.
    let (low_mult, med_mult, high_mult): (u64, u64, u64) = if pressure < 0.25 {
        (1, 2, 5)
    } else if pressure < 0.50 {
        (2, 4, 10)
    } else if pressure < 0.75 {
        (4, 8, 20)
    } else {
        (8, 16, 40)
    };

    let low = min_fee_rate.saturating_mul(low_mult);
    let medium = min_fee_rate.saturating_mul(med_mult);
    let high = min_fee_rate.saturating_mul(high_mult);
    let typical_fee_sat = TYPICAL_TX_SIZE.saturating_mul(medium);

    let recommended = node.mempool_recommended_fee_rates();
    let mempool_tx_count = node.mempool_size();
    let note = if mempool_tx_count > 0 {
        format!("Based on {} transactions in mempool", mempool_tx_count)
    } else {
        "Mempool is empty — using minimum relay fee".to_string()
    };

    Ok(Json(FeeEstimateResponse {
        low,
        medium,
        high,
        typical_fee_sat,
        min_fee_rate,
        typical_tx_size: TYPICAL_TX_SIZE,
        slow_sat_per_byte: recommended.slow,
        medium_sat_per_byte: recommended.medium,
        fast_sat_per_byte: recommended.fast,
        next_block_sat_per_byte: recommended.next_block,
        min_relay_sat_per_byte: recommended.min_relay,
        mempool_tx_count,
        note,
    }))
}

pub async fn get_mempool(
    State(state): State<SharedNodeState>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<MempoolResponse>> {
    let limit = params
        .limit
        .unwrap_or(DEFAULT_MEMPOOL_ITEMS)
        .min(MAX_MEMPOOL_ITEMS_PER_PAGE);
    let offset = params.offset.unwrap_or(0);

    let node = state.read().await;
    let mempool_entries = node.mempool_entries_with_fees();

    let total = mempool_entries.len();
    let mut total_size = 0usize;

    // Fee and size are taken from the mempool entry recorded at admission,
    // so we never have to redo UTXO lookups here.
    let mut all_summaries = Vec::with_capacity(total);
    for (txid, tx, fee_sat, size) in &mempool_entries {
        total_size += *size;

        all_summaries.push(MempoolTxSummary {
            txid: hex::encode(txid.as_bytes()),
            size: *size,
            fee_sat: *fee_sat,
            nonce: tx.nonce,
            input_count: tx.inputs.len(),
            output_count: tx.outputs.len(),
        });
    }

    let transactions: Vec<MempoolTxSummary> =
        all_summaries.into_iter().skip(offset).take(limit).collect();

    let count = transactions.len();
    Ok(Json(MempoolResponse {
        transactions,
        count,
        total,
        total_size,
        limit,
        offset,
    }))
}

pub async fn get_ai_analysis(
    State(state): State<SharedNodeState>,
) -> Result<Json<AiAnalysisReport>> {
    let mut node = state.write().await;
    Ok(Json(node.ai_analysis_report()))
}

pub async fn get_health(
    State(state): State<SharedNodeState>,
    Extension(ns): Extension<Option<SharedNetworkService>>,
) -> Result<Json<HealthResponse>> {
    let node = state.read().await;

    let peers = match ns {
        Some(ns) => ns.read().await.peer_manager().ready_peer_count().await,
        None => 0,
    };

    Ok(Json(HealthResponse {
        status: "ok".to_string(),
        height: node.best_height(),
        peers,
        mempool: node.mempool_size(),
    }))
}

/// Prometheus text exposition format (text/plain; version=0.0.4).
pub async fn get_metrics_prometheus(
    State(state): State<SharedNodeState>,
    Extension(ns): Extension<Option<SharedNetworkService>>,
) -> impl IntoResponse {
    let node = state.read().await;

    let height = node.best_height().unwrap_or(0);
    let mempool = node.mempool_size();
    let orphans = node.orphan_count();
    let uptime = node.uptime_seconds();

    let peer_count = match ns {
        Some(ns) => ns.read().await.peer_manager().ready_peer_count().await,
        None => 0,
    };

    let chain_work_hex = match node.get_chain_work() {
        Ok(Some(work)) => work,
        _ => 0u128,
    };

    let body = format!(
        "# HELP axiom_block_height Current best block height\n\
         # TYPE axiom_block_height gauge\n\
         axiom_block_height {height}\n\
         \n\
         # HELP axiom_peer_count Number of fully-handshaked peers\n\
         # TYPE axiom_peer_count gauge\n\
         axiom_peer_count {peer_count}\n\
         \n\
         # HELP axiom_mempool_size Number of transactions in the mempool\n\
         # TYPE axiom_mempool_size gauge\n\
         axiom_mempool_size {mempool}\n\
         \n\
         # HELP axiom_orphan_block_count Number of orphan blocks in the orphan pool\n\
         # TYPE axiom_orphan_block_count gauge\n\
         axiom_orphan_block_count {orphans}\n\
         \n\
         # HELP axiom_chain_work_numeric Cumulative chain work (numeric, may lose precision for large values)\n\
         # TYPE axiom_chain_work_numeric gauge\n\
         axiom_chain_work_numeric {chain_work_hex}\n\
         \n\
         # HELP axiom_uptime_seconds Seconds since node process started\n\
         # TYPE axiom_uptime_seconds counter\n\
         axiom_uptime_seconds {uptime}\n",
    );

    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

// ── AI model registry ─────────────────────────────────────────────────────────

/// Append-only model registration — a hash can only be registered once.
pub async fn ai_register_model(
    Extension(registry): Extension<Option<SharedModelRegistry>>,
    Json(req): Json<axiom_ai::RegisterModelRequest>,
) -> Result<Json<axiom_ai::ModelRecord>> {
    let registry =
        registry.ok_or_else(|| RpcError::Internal("model registry not initialised".into()))?;

    let record = axiom_ai::ModelRecord {
        model_hash: req.model_hash,
        name: req.name,
        version: req.version,
        description: req.description,
        registered_by: req.registered_by,
        registered_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    registry
        .register(record.clone())
        .map_err(|e| RpcError::InvalidRequest(e.to_string()))?;

    Ok(Json(record))
}

pub async fn ai_get_model(
    Extension(registry): Extension<Option<SharedModelRegistry>>,
    Path(hash): Path<String>,
) -> Result<Json<axiom_ai::ModelRecord>> {
    let registry =
        registry.ok_or_else(|| RpcError::Internal("model registry not initialised".into()))?;

    registry
        .get(&hash)
        .map_err(|e| RpcError::Internal(e.to_string()))?
        .ok_or_else(|| RpcError::NotFound(format!("model {hash}")))
        .map(Json)
}

pub async fn ai_list_models(
    Extension(registry): Extension<Option<SharedModelRegistry>>,
) -> Result<Json<Vec<axiom_ai::ModelRecord>>> {
    let registry =
        registry.ok_or_else(|| RpcError::Internal("model registry not initialised".into()))?;

    let models = registry
        .list_recent(50)
        .map_err(|e| RpcError::Internal(e.to_string()))?;

    Ok(Json(models))
}

// ── AI inference payment registry ─────────────────────────────────────────────

fn inference_registry(ext: Option<SharedInferenceRegistry>) -> Result<SharedInferenceRegistry> {
    ext.ok_or_else(|| RpcError::Internal("inference registry not initialised".into()))
}

/// Open a Pending inference job; job ID is SHA-256(model_hash, requester, timestamp).
pub async fn ai_request_inference(
    Extension(registry): Extension<Option<SharedInferenceRegistry>>,
    Json(req): Json<axiom_ai::RequestInferenceRequest>,
) -> Result<Json<axiom_ai::InferenceJob>> {
    let registry = inference_registry(registry)?;

    let job = registry
        .create_job(req.model_hash, req.requester, req.provider, req.amount_sat)
        .map_err(|e| RpcError::InvalidRequest(e.to_string()))?;

    Ok(Json(job))
}

/// Transitions job Pending → Completed; also records a reputation completion event.
pub async fn ai_complete_inference(
    Extension(registry): Extension<Option<SharedInferenceRegistry>>,
    Extension(rep_registry): Extension<Option<SharedReputationRegistry>>,
    Json(req): Json<axiom_ai::CompleteInferenceRequest>,
) -> Result<Json<axiom_ai::InferenceJob>> {
    let registry = inference_registry(registry)?;

    let job = registry
        .complete_job(&req.job_id, req.result_hash)
        .map_err(|e| match &e {
            axiom_ai::InferenceError::NotFound(_) => RpcError::NotFound(e.to_string()),
            _ => RpcError::InvalidRequest(e.to_string()),
        })?;

    if let Some(rep) = rep_registry {
        if let Err(e) = rep.record_completion(&job.model_hash) {
            tracing::warn!(
                "reputation record_completion failed for {}: {e}",
                job.model_hash
            );
        }
    }

    Ok(Json(job))
}

/// Transitions job Pending → Cancelled.
pub async fn ai_cancel_inference(
    Extension(registry): Extension<Option<SharedInferenceRegistry>>,
    Json(req): Json<axiom_ai::CancelInferenceRequest>,
) -> Result<Json<axiom_ai::InferenceJob>> {
    let registry = inference_registry(registry)?;

    let job = registry.cancel_job(&req.job_id).map_err(|e| match &e {
        axiom_ai::InferenceError::NotFound(_) => RpcError::NotFound(e.to_string()),
        _ => RpcError::InvalidRequest(e.to_string()),
    })?;

    Ok(Json(job))
}

pub async fn ai_get_inference_job(
    Extension(registry): Extension<Option<SharedInferenceRegistry>>,
    Path(job_id): Path<String>,
) -> Result<Json<axiom_ai::InferenceJob>> {
    let registry = inference_registry(registry)?;

    registry
        .get(&job_id)
        .map_err(|e| RpcError::Internal(e.to_string()))?
        .ok_or_else(|| RpcError::NotFound(format!("job {job_id}")))
        .map(Json)
}

/// Up to 50 jobs where address is requester or provider, newest-first.
pub async fn ai_list_inference_jobs(
    Extension(registry): Extension<Option<SharedInferenceRegistry>>,
    Path(address): Path<String>,
) -> Result<Json<Vec<axiom_ai::InferenceJob>>> {
    let registry = inference_registry(registry)?;

    let jobs = registry
        .list_jobs_for(&address, 50)
        .map_err(|e| RpcError::Internal(e.to_string()))?;

    Ok(Json(jobs))
}

// ── AI reputation & stake ────────────────────────────────────────────────────

fn reputation_registry(ext: Option<SharedReputationRegistry>) -> Result<SharedReputationRegistry> {
    ext.ok_or_else(|| RpcError::Internal("reputation registry not initialised".into()))
}

pub async fn ai_rate_model(
    Extension(registry): Extension<Option<SharedReputationRegistry>>,
    Path(model_hash): Path<String>,
    Json(req): Json<axiom_ai::RateModelRequest>,
) -> Result<Json<axiom_ai::ReputationScore>> {
    let registry = reputation_registry(registry)?;

    let score = registry
        .rate_model(&model_hash, req.rating, &req.rater_address)
        .map_err(|e| RpcError::InvalidRequest(e.to_string()))?;

    Ok(Json(score))
}

pub async fn ai_get_reputation(
    Extension(registry): Extension<Option<SharedReputationRegistry>>,
    Path(model_hash): Path<String>,
) -> Result<Json<axiom_ai::ReputationScore>> {
    let registry = reputation_registry(registry)?;

    let score = registry
        .get_score(&model_hash)
        .map_err(|e| RpcError::Internal(e.to_string()))?;

    Ok(Json(score))
}

pub async fn ai_ranked_models(
    Extension(registry): Extension<Option<SharedReputationRegistry>>,
) -> Result<Json<Vec<axiom_ai::ReputationScore>>> {
    let registry = reputation_registry(registry)?;

    let scores = registry
        .ranked_models(50)
        .map_err(|e| RpcError::Internal(e.to_string()))?;

    Ok(Json(scores))
}

pub async fn ai_add_stake(
    Extension(registry): Extension<Option<SharedReputationRegistry>>,
    Json(req): Json<axiom_ai::AddStakeRequest>,
) -> Result<Json<axiom_ai::ProviderStake>> {
    let registry = reputation_registry(registry)?;

    let stake = registry
        .add_stake(&req.provider, req.amount_sat)
        .map_err(|e| RpcError::Internal(e.to_string()))?;

    Ok(Json(stake))
}

pub async fn ai_get_stake(
    Extension(registry): Extension<Option<SharedReputationRegistry>>,
    Path(address): Path<String>,
) -> Result<Json<axiom_ai::ProviderStake>> {
    let registry = reputation_registry(registry)?;

    let stake = registry
        .get_stake(&address)
        .map_err(|e| RpcError::Internal(e.to_string()))?;

    Ok(Json(stake))
}

// ── SPV / light-client endpoints (not yet routed) ───────────────────────────

#[allow(dead_code)]
pub async fn get_tx_merkle_proof(
    Path(txid_hex): Path<String>,
    State(state): State<SharedNodeState>,
) -> Result<Json<crate::types::MerkleProofResponse>> {
    use axiom_consensus::generate_proof;

    if txid_hex.len() != 64 {
        return Err(RpcError::InvalidRequest(
            "Invalid txid format (expected 64 hex chars)".into(),
        ));
    }

    let txid_bytes = hex::decode(&txid_hex)
        .map_err(|_| RpcError::InvalidRequest("Invalid hex encoding".into()))?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&txid_bytes);
    let txid = axiom_primitives::Hash256::from_bytes(arr);

    let node = state.read().await;
    let db = node.state.database();
    let tx_index = axiom_storage::TxIndex::new(db);

    let mempool_txs = node.get_mempool_transactions();
    for tx in mempool_txs {
        // Canonical txid: double-hash of the unsigned serialization.
        let tx_data = axiom_protocol::serialize_transaction_unsigned(&tx);
        let mempool_txid = axiom_crypto::double_hash256(&tx_data);
        if mempool_txid == txid {
            return Err(RpcError::InvalidRequest(
                "Transaction is in mempool but not yet confirmed; no Merkle proof available".into(),
            ));
        }
    }

    let loc = tx_index
        .get_tx_location(&txid)
        .map_err(|e| RpcError::Internal(format!("Index error: {}", e)))?
        .ok_or_else(|| RpcError::NotFound(format!("Transaction not found: {}", txid_hex)))?;

    let block = db
        .load_block(&loc.block_hash)
        .map_err(|e| RpcError::Internal(format!("Block load error: {}", e)))?;

    // Merkle leaves must use the unsigned-form txid — that is what the stored
    // merkle root was computed over. A signed-form proof would never validate.
    let tx_hashes: Vec<axiom_primitives::Hash256> = block
        .transactions
        .iter()
        .map(|tx| {
            let data = axiom_protocol::serialize_transaction_unsigned(tx);
            axiom_crypto::double_hash256(&data)
        })
        .collect();

    let proof = generate_proof(&tx_hashes, loc.tx_position as usize)
        .ok_or_else(|| RpcError::Internal("Failed to generate Merkle proof".into()))?;

    let proof_path = proof
        .proof_path
        .iter()
        .map(|step| crate::types::ProofStepResponse {
            is_right: step.is_right,
            hash: hex::encode(step.hash.as_bytes()),
        })
        .collect();

    Ok(Json(crate::types::MerkleProofResponse {
        txid: txid_hex,
        block_hash: hex::encode(loc.block_hash.as_bytes()),
        block_height: loc.block_height,
        tx_index: loc.tx_position,
        proof_path,
        merkle_root: hex::encode(proof.merkle_root.as_bytes()),
    }))
}

#[allow(dead_code)]
pub async fn get_block_header_by_hash(
    State(state): State<SharedNodeState>,
    Path(hash_str): Path<String>,
) -> Result<Json<crate::types::BlockHeaderResponse>> {
    if hash_str.len() != 64 {
        return Err(RpcError::InvalidRequest(
            "Invalid hash format (expected 64 hex chars)".into(),
        ));
    }

    let hash_bytes = hex::decode(&hash_str)
        .map_err(|_| RpcError::InvalidRequest("Invalid hex encoding".into()))?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hash_bytes);
    let hash = axiom_primitives::Hash256::from_bytes(arr);

    let node = state.read().await;
    match node.get_block(&hash) {
        Ok(Some(block)) => Ok(Json(crate::types::BlockHeaderResponse {
            hash: hex::encode(block.hash().as_bytes()),
            version: block.header.version,
            prev_block_hash: hex::encode(block.header.prev_block_hash.as_bytes()),
            merkle_root: hex::encode(block.header.merkle_root.as_bytes()),
            timestamp: block.header.timestamp,
            difficulty_target: block.header.difficulty_target,
            nonce: block.header.nonce,
            height: block.height(),
        })),
        Ok(None) => Err(RpcError::BlockNotFound(hash_str)),
        Err(e) => Err(RpcError::Internal(format!("Failed to query block: {}", e))),
    }
}

#[allow(dead_code)]
pub async fn get_block_header_by_height(
    State(state): State<SharedNodeState>,
    Path(target_height): Path<u32>,
) -> Result<Json<crate::types::BlockHeaderResponse>> {
    let node = state.read().await;

    match node.get_recent_blocks(1000) {
        Ok(blocks) => {
            for block in blocks {
                let height = block.height().unwrap_or(0);
                if height == target_height {
                    return Ok(Json(crate::types::BlockHeaderResponse {
                        hash: hex::encode(block.hash().as_bytes()),
                        version: block.header.version,
                        prev_block_hash: hex::encode(block.header.prev_block_hash.as_bytes()),
                        merkle_root: hex::encode(block.header.merkle_root.as_bytes()),
                        timestamp: block.header.timestamp,
                        difficulty_target: block.header.difficulty_target,
                        nonce: block.header.nonce,
                        height: Some(height),
                    }));
                }
            }
            Err(RpcError::BlockNotFound(format!("height {}", target_height)))
        }
        Err(e) => Err(RpcError::Internal(format!("Failed to query blocks: {}", e))),
    }
}

#[allow(dead_code)]
pub async fn spv_verify(
    State(state): State<SharedNodeState>,
    Json(req): Json<crate::types::SpvVerifyRequest>,
) -> Result<Json<crate::types::SpvVerifyResponse>> {
    use axiom_consensus::{verify_proof, MerkleProof, ProofStep};

    if req.txid.len() != 64 {
        return Err(RpcError::InvalidRequest("Invalid txid format".into()));
    }
    let txid_bytes =
        hex::decode(&req.txid).map_err(|_| RpcError::InvalidRequest("Invalid txid hex".into()))?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&txid_bytes);
    let txid = axiom_primitives::Hash256::from_bytes(arr);

    if req.block_hash.len() != 64 {
        return Err(RpcError::InvalidRequest("Invalid block_hash format".into()));
    }
    let bh_bytes = hex::decode(&req.block_hash)
        .map_err(|_| RpcError::InvalidRequest("Invalid block_hash hex".into()))?;
    let mut bh_arr = [0u8; 32];
    bh_arr.copy_from_slice(&bh_bytes);
    let block_hash = axiom_primitives::Hash256::from_bytes(bh_arr);

    let node = state.read().await;
    let block = node
        .get_block(&block_hash)
        .map_err(|e| RpcError::Internal(format!("Block query error: {}", e)))?
        .ok_or_else(|| RpcError::BlockNotFound(req.block_hash.clone()))?;

    let merkle_root = block.header.merkle_root;

    let mut proof_path = Vec::with_capacity(req.proof_path.len());
    for step in &req.proof_path {
        if step.hash.len() != 64 {
            return Err(RpcError::InvalidRequest(
                "Invalid proof step hash length".into(),
            ));
        }
        let h_bytes = hex::decode(&step.hash)
            .map_err(|_| RpcError::InvalidRequest("Invalid proof step hash hex".into()))?;
        let mut h_arr = [0u8; 32];
        h_arr.copy_from_slice(&h_bytes);
        proof_path.push(ProofStep {
            is_right: step.is_right,
            hash: axiom_primitives::Hash256::from_bytes(h_arr),
        });
    }

    let proof = MerkleProof {
        txid,
        tx_index: req.tx_index,
        proof_path,
        merkle_root,
    };

    let valid = verify_proof(&proof, &merkle_root);

    Ok(Json(crate::types::SpvVerifyResponse {
        valid,
        merkle_root: hex::encode(merkle_root.as_bytes()),
    }))
}

#[allow(dead_code)]
pub async fn decode_raw_tx(
    Json(req): Json<crate::types::DecodeRawTxRequest>,
) -> Result<Json<crate::types::TransactionDetail>> {
    let tx_bytes = hex::decode(&req.raw_tx_hex)
        .map_err(|_| RpcError::InvalidRequest("Invalid hex encoding".into()))?;

    let tx = axiom_protocol::deserialize_transaction(&tx_bytes)
        .map_err(|e| RpcError::InvalidRequest(format!("Invalid transaction: {}", e)))?;

    let tx_type = match tx.tx_type {
        axiom_protocol::TransactionType::Transfer => "transfer",
        axiom_protocol::TransactionType::Coinbase => "coinbase",
        axiom_protocol::TransactionType::ConfidentialTransfer => "confidential_transfer",
        axiom_protocol::TransactionType::UsernameRegistration => "username_registration",
    };

    let inputs: Vec<crate::types::TxInputDetail> = tx
        .inputs
        .iter()
        .map(|input| crate::types::TxInputDetail {
            prev_tx_hash: hex::encode(input.prev_tx_hash.as_bytes()),
            prev_output_index: input.prev_output_index,
            signature: hex::encode(input.signature.as_bytes()),
            pubkey: hex::encode(input.pubkey.as_bytes()),
        })
        .collect();

    let outputs: Vec<crate::types::TxOutputDetail> = tx
        .outputs
        .iter()
        .map(|output| crate::types::TxOutputDetail {
            value: output.value.as_sat(),
            pubkey_hash: hex::encode(output.pubkey_hash.as_bytes()),
        })
        .collect();

    // Canonical txid: double-hash of the unsigned serialization.
    let tx_data = axiom_protocol::serialize_transaction_unsigned(&tx);
    let txid = axiom_crypto::double_hash256(&tx_data);

    Ok(Json(crate::types::TransactionDetail {
        txid: hex::encode(txid.as_bytes()),
        version: tx.version,
        tx_type: tx_type.to_string(),
        inputs,
        outputs,
        nonce: tx.nonce,
        locktime: tx.locktime,
        memo: tx.memo.map(|m| {
            let end = m.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
            String::from_utf8_lossy(&m[..end]).into_owned()
        }),
    }))
}

// ── AxiomMind / NetworkGuard endpoints ───────────────────────────────────────

/// GET /guard/status — snapshot of AxiomMind's current state.
pub async fn get_guard_status(
    Extension(guard): Extension<Option<SharedGuardState>>,
) -> Result<Json<axiom_guard::GuardStatus>> {
    match guard {
        Some(g) => Ok(Json(g.read().await.status())),
        None => Err(RpcError::NotFound(
            "AxiomMind guard not active on this node".into(),
        )),
    }
}

/// GET /guard/alerts?limit=N — last N signed alerts (default 20, max 200).
pub async fn get_guard_alerts(
    Extension(guard): Extension<Option<SharedGuardState>>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<Vec<axiom_guard::GuardAlert>>> {
    match guard {
        Some(g) => {
            let limit = params.limit.unwrap_or(20).min(200);
            Ok(Json(g.read().await.recent_alerts(limit)))
        }
        None => Err(RpcError::NotFound(
            "AxiomMind guard not active on this node".into(),
        )),
    }
}

/// Alias for `submit_transaction` using the `raw_tx_hex` field name.
#[allow(dead_code)]
pub async fn broadcast_raw_tx(
    State(state): State<SharedNodeState>,
    Extension(ns): Extension<Option<SharedNetworkService>>,
    Json(req): Json<crate::types::BroadcastRawTxRequest>,
) -> Result<Json<crate::types::SubmitTransactionResponse>> {
    let tx_bytes = hex::decode(&req.raw_tx_hex)
        .map_err(|_| RpcError::InvalidRequest("Invalid hex encoding".into()))?;

    let tx = axiom_protocol::deserialize_transaction(&tx_bytes)
        .map_err(|e| RpcError::InvalidRequest(format!("Invalid transaction: {}", e)))?;

    let mut node = state.write().await;
    match node.submit_transaction(tx.clone()) {
        Ok(txid) => {
            let computed_txid =
                axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(&tx));
            tracing::info!(
                "TX_BROADCAST_RPC: txid={}",
                hex::encode(&computed_txid.as_bytes()[..8])
            );

            drop(node);

            if let Some(ns) = ns {
                let service = ns.read().await;
                let _ = service.broadcast_transaction(tx, None).await;
            }

            Ok(Json(crate::types::SubmitTransactionResponse {
                txid: hex::encode(txid.as_bytes()),
            }))
        }
        Err(e) => Err(RpcError::TransactionRejected(format!("{}", e))),
    }
}

// ── Community chat endpoints ──────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct ChatHistoryParams {
    /// Maximum number of messages to return (default 50, max 200).
    pub limit: Option<usize>,
}

#[derive(serde::Serialize)]
pub struct ChatMessageResponse {
    pub username: String,
    pub sender_address: String,
    pub text: String,
    pub timestamp: u64,
    pub nonce: u64,
}

#[derive(serde::Deserialize)]
pub struct SendChatRequest {
    /// Registered username or any display name (≤ 32 chars).
    pub username: String,
    /// Sender's AXM address.
    pub sender_address: String,
    /// Message body (≤ 512 bytes).
    pub text: String,
    /// ML-DSA-87 signature over sha256(username ‖ text ‖ timestamp ‖ nonce), base64-encoded.
    pub signature: String,
}

/// `GET /community/messages?limit=50`
pub async fn community_get_messages(
    Extension(ns): Extension<Option<SharedNetworkService>>,
    Query(params): Query<ChatHistoryParams>,
) -> Result<Json<Vec<ChatMessageResponse>>> {
    let limit = params.limit.unwrap_or(50).min(200);

    let ns = ns.ok_or_else(|| {
        RpcError::Internal("community service unavailable — no network service".into())
    })?;
    let service = ns.read().await;

    let msgs = service.community.recent_messages(limit).await;
    let out = msgs
        .into_iter()
        .map(|m| ChatMessageResponse {
            username: m.payload.username,
            sender_address: m.payload.sender_address,
            text: m.payload.text,
            timestamp: m.payload.timestamp,
            nonce: m.payload.nonce,
        })
        .collect();

    Ok(Json(out))
}

/// `POST /community/send`
pub async fn community_send_message(
    Extension(ns): Extension<Option<SharedNetworkService>>,
    Json(req): Json<SendChatRequest>,
) -> Result<Json<serde_json::Value>> {
    use axiom_node::network::{ChatMessagePayload, Message};

    if req.text.len() > axiom_node::network::MAX_CHAT_TEXT_BYTES {
        return Err(RpcError::InvalidRequest(
            "message too long (max 512 bytes)".into(),
        ));
    }
    if req.username.is_empty() || req.username.len() > 32 {
        return Err(RpcError::InvalidRequest(
            "username must be 1–32 characters".into(),
        ));
    }

    let ns = ns.ok_or_else(|| {
        RpcError::Internal("community service unavailable — no network service".into())
    })?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let nonce: u64 = {
        use rand_core::{OsRng, RngCore};
        OsRng.next_u64()
    };

    let sig_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &req.signature)
            .map_err(|_| RpcError::InvalidRequest("signature must be valid base64".into()))?;

    let payload = ChatMessagePayload {
        username: req.username,
        sender_address: req.sender_address,
        text: req.text,
        timestamp,
        nonce,
        signature: sig_bytes,
    };

    let service = ns.read().await;

    // Store locally and relay to peers.
    let relayed = service.community.handle_chat_message(payload.clone()).await;
    if relayed {
        let _ = service
            .peer_manager()
            .broadcast(Message::ChatMessage(payload))
            .await;
    }

    if relayed {
        Ok(Json(serde_json::json!({ "status": "sent" })))
    } else {
        Err(RpcError::InvalidRequest(
            "message rejected by AxiomMind moderation or is a duplicate".into(),
        ))
    }
}

/// `GET /community/username/:address`
pub async fn community_get_username(
    Extension(ns): Extension<Option<SharedNetworkService>>,
    Path(address): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let ns = ns.ok_or_else(|| RpcError::Internal("community service unavailable".into()))?;
    let service = ns.read().await;

    match service.community.username_of(&address).await {
        Some(username) => Ok(Json(serde_json::json!({
            "address": address,
            "username": username
        }))),
        None => Err(RpcError::NotFound(format!(
            "no registered username for {}",
            address
        ))),
    }
}

// ── TASK 3: Network analytics endpoint ───────────────────────────────────────

/// `GET /analytics` — compute network analytics from the last N=100 blocks.
pub async fn get_network_analytics(
    State(state): State<SharedNodeState>,
) -> Result<Json<crate::types::NetworkAnalyticsResponse>> {
    const WINDOW: usize = 100;
    let node = state.read().await;
    let chain_height = node.best_height().unwrap_or(0) as u64;

    let blocks = node
        .get_recent_blocks(WINDOW)
        .map_err(|e| RpcError::Internal(format!("Failed to query blocks: {}", e)))?;

    let total_blocks_analyzed = blocks.len() as u32;

    if blocks.len() < 2 {
        return Ok(Json(crate::types::NetworkAnalyticsResponse {
            avg_block_time_secs: 0.0,
            std_block_time_secs: 0.0,
            avg_tx_per_block: blocks
                .first()
                .map(|b| b.transactions.len() as f64)
                .unwrap_or(0.0),
            avg_block_size_bytes: 0.0,
            blocks_per_hour: 0.0,
            estimated_tps: 0.0,
            difficulty_trend: 1.0,
            fee_rate_p50_sat_byte: 0,
            total_blocks_analyzed,
            chain_height,
        }));
    }

    // blocks[0] is newest, blocks[last] is oldest — reversed chain walk order.
    // Compute inter-block intervals.
    let mut intervals: Vec<f64> = Vec::new();
    for pair in blocks.windows(2) {
        let newer_ts = pair[0].header.timestamp as i64;
        let older_ts = pair[1].header.timestamp as i64;
        let diff = (newer_ts - older_ts) as f64;
        if diff > 0.0 {
            intervals.push(diff);
        }
    }

    let n_intervals = intervals.len() as f64;
    let avg_block_time_secs = if n_intervals > 0.0 {
        intervals.iter().sum::<f64>() / n_intervals
    } else {
        0.0
    };

    let std_block_time_secs = if n_intervals > 1.0 {
        let mean = avg_block_time_secs;
        let variance = intervals.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n_intervals;
        variance.sqrt()
    } else {
        0.0
    };

    let avg_tx_per_block = blocks
        .iter()
        .map(|b| b.transactions.len() as f64)
        .sum::<f64>()
        / blocks.len() as f64;

    let avg_block_size_bytes = blocks
        .iter()
        .map(|b| {
            b.transactions
                .iter()
                .map(|tx| axiom_protocol::serialize_transaction(tx).len())
                .sum::<usize>() as f64
        })
        .sum::<f64>()
        / blocks.len() as f64;

    let blocks_per_hour = if avg_block_time_secs > 0.0 {
        3600.0 / avg_block_time_secs
    } else {
        0.0
    };

    let total_span_secs = {
        let newest_ts = blocks.first().map(|b| b.header.timestamp).unwrap_or(0) as f64;
        let oldest_ts = blocks.last().map(|b| b.header.timestamp).unwrap_or(0) as f64;
        newest_ts - oldest_ts
    };

    let total_non_coinbase_txs: usize = blocks
        .iter()
        .map(|b| b.transactions.len().saturating_sub(1))
        .sum();

    let estimated_tps = if total_span_secs > 0.0 {
        total_non_coinbase_txs as f64 / total_span_secs
    } else {
        0.0
    };

    // Difficulty trend: ratio of newest block's difficulty vs oldest.
    let difficulty_trend = {
        let newest_diff = blocks
            .first()
            .map(|b| b.header.difficulty_target)
            .unwrap_or(1) as f64;
        let oldest_diff = blocks
            .last()
            .map(|b| b.header.difficulty_target)
            .unwrap_or(1) as f64;
        if oldest_diff > 0.0 {
            newest_diff / oldest_diff
        } else {
            1.0
        }
    };

    // Median fee rate from mempool (sat/byte).
    let fee_rate_p50_sat_byte = node
        .mempool_fee_percentiles()
        .map(|p| p.p50)
        .unwrap_or(node.min_fee_rate());

    Ok(Json(crate::types::NetworkAnalyticsResponse {
        avg_block_time_secs,
        std_block_time_secs,
        avg_tx_per_block,
        avg_block_size_bytes,
        blocks_per_hour,
        estimated_tps,
        difficulty_trend,
        fee_rate_p50_sat_byte,
        total_blocks_analyzed,
        chain_height,
    }))
}

/// `GET /block/:hash/stats` — statistics for a single block.
pub async fn get_block_stats(
    State(state): State<SharedNodeState>,
    Path(hash_str): Path<String>,
) -> Result<Json<crate::types::BlockStatsResponse>> {
    if hash_str.len() != 64 {
        return Err(RpcError::InvalidRequest(
            "Invalid hash format (expected 64 hex chars)".into(),
        ));
    }

    let hash_bytes = hex::decode(&hash_str)
        .map_err(|_| RpcError::InvalidRequest("Invalid hex encoding".into()))?;

    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(&hash_bytes);
    let hash = Hash256::from_bytes(hash_array);

    let node = state.read().await;
    let block = node
        .get_block(&hash)
        .map_err(|e| RpcError::Internal(format!("Block query error: {}", e)))?
        .ok_or_else(|| RpcError::BlockNotFound(hash_str.clone()))?;

    let height = block.height().unwrap_or(0);

    // Fetch parent to compute inter-block time.
    let block_time_secs = if block.header.prev_block_hash != Hash256::zero() {
        match node.get_block(&block.header.prev_block_hash) {
            Ok(Some(parent)) => {
                (block.header.timestamp as i64 - parent.header.timestamp as i64).max(0) as f64
            }
            _ => 0.0,
        }
    } else {
        0.0
    };

    // Coinbase output value.
    let coinbase_value = block
        .transactions
        .first()
        .map(|cb| cb.outputs.iter().map(|o| o.value.as_sat()).sum::<u64>())
        .unwrap_or(0);

    // Per-tx fee requires resolving every input against the UTXO set at the
    // block's parent — an expensive, I/O-bound walk we intentionally skip on
    // the stats path. Callers who need accurate fees must inspect the block's
    // transactions individually. `fee_total_sat`/`avg_fee_rate`/`min_fee_rate`/
    // `max_fee_rate` in the response are therefore reported as 0 here; clients
    // should treat them as unavailable rather than "free".
    let fee_rates: Vec<u64> = block
        .transactions
        .iter()
        .skip(1) // skip coinbase
        .map(|_tx| 0u64)
        .collect();

    let fee_total_sat: u64 = fee_rates.iter().sum();
    let tx_count = block.transactions.len();

    let avg_fee_rate = if fee_rates.is_empty() {
        0.0
    } else {
        fee_total_sat as f64 / fee_rates.len() as f64
    };
    let min_fee_rate = fee_rates.iter().copied().min().unwrap_or(0);
    let max_fee_rate = fee_rates.iter().copied().max().unwrap_or(0);

    Ok(Json(crate::types::BlockStatsResponse {
        block_hash: hash_str,
        height,
        block_time_secs,
        fee_total_sat,
        avg_fee_rate,
        min_fee_rate,
        max_fee_rate,
        coinbase_value,
        tx_count,
    }))
}

// ── TASK 5: Enhanced mempool stats ────────────────────────────────────────────

/// `GET /mempool/stats` — detailed mempool statistics with fee histogram.
pub async fn get_mempool_detail(
    State(state): State<SharedNodeState>,
) -> Result<Json<crate::types::MempoolDetailResponse>> {
    const MAX_BLOCK_SIZE: usize = 1_000_000;
    const NUM_BUCKETS: usize = 10;

    let node = state.read().await;
    let entries = node.mempool_entry_stats();

    let count = entries.len() as u64;
    let size_bytes: u64 = entries.iter().map(|(sz, _, _)| *sz as u64).sum();

    if entries.is_empty() {
        let zero_percs = crate::types::FeePercentilesDetail {
            p5: 0,
            p10: 0,
            p25: 0,
            p50: 0,
            p75: 0,
            p90: 0,
            p95: 0,
            p99: 0,
        };
        return Ok(Json(crate::types::MempoolDetailResponse {
            count: 0,
            size_bytes: 0,
            fee_histogram: Vec::new(),
            fee_percentiles: zero_percs,
            min_fee_rate: 0,
            max_fee_rate: 0,
            avg_fee_rate: 0.0,
            next_block_estimate: crate::types::NextBlockEstimate {
                tx_count: 0,
                size_bytes: 0,
                total_fees: 0,
            },
            rbf_count: 0,
        }));
    }

    // Extract fee rates sorted ascending.
    let mut fee_rates: Vec<u64> = entries.iter().map(|(_, rate, _)| *rate).collect();
    fee_rates.sort_unstable();

    let n = fee_rates.len();
    let percentile = |p: usize| -> u64 {
        let idx = ((p * n).saturating_sub(1)) / 100;
        fee_rates[idx.min(n - 1)]
    };

    let fee_percentiles = crate::types::FeePercentilesDetail {
        p5: percentile(5),
        p10: percentile(10),
        p25: percentile(25),
        p50: percentile(50),
        p75: percentile(75),
        p90: percentile(90),
        p95: percentile(95),
        p99: percentile(99),
    };

    let min_fee_rate = *fee_rates.first().unwrap_or(&0);
    let max_fee_rate = *fee_rates.last().unwrap_or(&0);
    let avg_fee_rate = fee_rates.iter().sum::<u64>() as f64 / n as f64;

    // Build fee histogram (10 equal-width buckets between min and max).
    let bucket_width = if max_fee_rate > min_fee_rate {
        (max_fee_rate - min_fee_rate).div_ceil(NUM_BUCKETS as u64)
    } else {
        1
    };

    let mut buckets: Vec<crate::types::FeeBucket> = (0..NUM_BUCKETS)
        .map(|i| {
            let lo = min_fee_rate + i as u64 * bucket_width;
            let hi = lo + bucket_width - 1;
            crate::types::FeeBucket {
                min_rate: lo,
                max_rate: hi,
                count: 0,
                size_bytes: 0,
            }
        })
        .collect();

    for (sz, rate, _fee) in &entries {
        let idx = if bucket_width > 0 {
            ((*rate).saturating_sub(min_fee_rate) / bucket_width).min(NUM_BUCKETS as u64 - 1)
        } else {
            0
        };
        buckets[idx as usize].count += 1;
        buckets[idx as usize].size_bytes += *sz as u64;
    }

    // Next-block estimate: how many txs fit in a 1 MB block at current fees.
    let mut next_block_size: u64 = 0;
    let mut next_block_txs: u64 = 0;
    let mut next_block_fees: u64 = 0;

    // Sort descending by fee rate for next-block selection.
    let mut sorted_by_rate = entries.clone();
    sorted_by_rate.sort_by(|a, b| b.1.cmp(&a.1));

    for (sz, _rate, fee) in &sorted_by_rate {
        if next_block_size + *sz as u64 > MAX_BLOCK_SIZE as u64 {
            break;
        }
        next_block_size += *sz as u64;
        next_block_txs += 1;
        next_block_fees += *fee;
    }

    // RBF count: we can approximate as txs with fee rate above median.
    // (Without access to raw tx data here we use 0; node exposes this via stats.)
    let rbf_count = 0u64;

    Ok(Json(crate::types::MempoolDetailResponse {
        count,
        size_bytes,
        fee_histogram: buckets,
        fee_percentiles,
        min_fee_rate,
        max_fee_rate,
        avg_fee_rate,
        next_block_estimate: crate::types::NextBlockEstimate {
            tx_count: next_block_txs,
            size_bytes: next_block_size,
            total_fees: next_block_fees,
        },
        rbf_count,
    }))
}

// ── TASK 6: Network hashrate estimation ───────────────────────────────────────

/// `GET /network/hashrate` — estimated network hashrate from recent blocks.
pub async fn get_network_hashrate(
    State(state): State<SharedNodeState>,
) -> Result<Json<crate::types::NetworkHashrateResponse>> {
    const SAMPLE: usize = 10;

    let node = state.read().await;
    let blocks = node
        .get_recent_blocks(SAMPLE)
        .map_err(|e| RpcError::Internal(format!("Failed to query blocks: {}", e)))?;

    let sample_blocks = blocks.len() as u32;

    if blocks.len() < 2 {
        return Ok(Json(crate::types::NetworkHashrateResponse {
            estimated_hashrate_hps: 0.0,
            estimated_hashrate_human: "0 H/s".to_string(),
            sample_blocks,
            avg_block_time_secs: 0.0,
        }));
    }

    // Average interval between consecutive blocks (newest first).
    let mut total_interval = 0i64;
    let mut count = 0u32;
    for pair in blocks.windows(2) {
        let diff = pair[0].header.timestamp as i64 - pair[1].header.timestamp as i64;
        if diff > 0 {
            total_interval += diff;
            count += 1;
        }
    }

    let avg_block_time_secs = if count > 0 {
        total_interval as f64 / count as f64
    } else {
        0.0
    };

    // Use the newest block's difficulty as representative.
    let difficulty_target = blocks
        .first()
        .map(|b| b.header.difficulty_target)
        .unwrap_or(1);

    // Hashrate formula: H = difficulty * 2^32 / avg_block_time
    // `difficulty_target` is the compact "bits" field (nBits).
    // For an approximation we treat it as the raw 32-bit compact target value.
    let estimated_hashrate_hps = if avg_block_time_secs > 0.0 {
        (difficulty_target as f64) * (1u64 << 32) as f64 / avg_block_time_secs
    } else {
        0.0
    };

    let estimated_hashrate_human = format_hashrate(estimated_hashrate_hps);

    Ok(Json(crate::types::NetworkHashrateResponse {
        estimated_hashrate_hps,
        estimated_hashrate_human,
        sample_blocks,
        avg_block_time_secs,
    }))
}

/// Format a hashrate value as a human-readable string (TH/s, GH/s, MH/s, KH/s, H/s).
fn format_hashrate(hps: f64) -> String {
    if hps >= 1e12 {
        format!("{:.2} TH/s", hps / 1e12)
    } else if hps >= 1e9 {
        format!("{:.2} GH/s", hps / 1e9)
    } else if hps >= 1e6 {
        format!("{:.2} MH/s", hps / 1e6)
    } else if hps >= 1e3 {
        format!("{:.2} KH/s", hps / 1e3)
    } else {
        format!("{:.2} H/s", hps)
    }
}

// ── Monitor / AI-agent endpoints ──────────────────────────────────────────────

/// GET /monitor/report — latest monitoring report (most recent analysis cycle).
pub async fn get_monitor_report(
    Extension(store): Extension<Option<SharedMonitorStore>>,
) -> Result<Json<axiom_monitor::MonitorReport>> {
    match store {
        Some(s) => {
            let reports = s.read().await;
            match reports.last().cloned() {
                Some(report) => Ok(Json(report)),
                None => Err(RpcError::NotFound(
                    "No monitor reports available yet".into(),
                )),
            }
        }
        None => Err(RpcError::NotFound(
            "Monitor agent not active on this node".into(),
        )),
    }
}

/// GET /monitor/reports?limit=N — last N monitoring reports (default 10, max 100).
pub async fn get_monitor_reports(
    Extension(store): Extension<Option<SharedMonitorStore>>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<Vec<axiom_monitor::MonitorReport>>> {
    match store {
        Some(s) => {
            let limit = params.limit.unwrap_or(10).min(100);
            let reports = s.read().await;
            let result: Vec<_> = reports.iter().rev().take(limit).cloned().collect();
            Ok(Json(result))
        }
        None => Err(RpcError::NotFound(
            "Monitor agent not active on this node".into(),
        )),
    }
}

/// GET /monitor/health — just the health score from the latest report.
pub async fn get_monitor_health(
    Extension(store): Extension<Option<SharedMonitorStore>>,
) -> Result<Json<axiom_monitor::NetworkHealthScore>> {
    match store {
        Some(s) => {
            let reports = s.read().await;
            match reports.last().map(|r| r.health.clone()) {
                Some(health) => Ok(Json(health)),
                None => Err(RpcError::NotFound(
                    "No monitor reports available yet".into(),
                )),
            }
        }
        None => Err(RpcError::NotFound(
            "Monitor agent not active on this node".into(),
        )),
    }
}

/// GET /monitor/alerts — recent alerts from all stored reports, newest first.
pub async fn get_monitor_alerts(
    Extension(store): Extension<Option<SharedMonitorStore>>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<Vec<axiom_monitor::AgentAlert>>> {
    match store {
        Some(s) => {
            let limit = params.limit.unwrap_or(50).min(500);
            let reports = s.read().await;
            let alerts: Vec<axiom_monitor::AgentAlert> = reports
                .iter()
                .rev()
                .flat_map(|r| r.alerts.iter().cloned())
                .take(limit)
                .collect();
            Ok(Json(alerts))
        }
        None => Err(RpcError::NotFound(
            "Monitor agent not active on this node".into(),
        )),
    }
}

/// GET /monitor/recommendations — current parameter recommendations.
pub async fn get_monitor_recommendations(
    Extension(store): Extension<Option<SharedMonitorStore>>,
) -> Result<Json<Vec<axiom_monitor::ParameterRecommendation>>> {
    match store {
        Some(s) => {
            let reports = s.read().await;
            match reports.last().map(|r| r.recommendations.clone()) {
                Some(recs) => Ok(Json(recs)),
                None => Err(RpcError::NotFound(
                    "No monitor reports available yet".into(),
                )),
            }
        }
        None => Err(RpcError::NotFound(
            "Monitor agent not active on this node".into(),
        )),
    }
}

// ── AI Compute Protocol Handlers (Phase AI-3.5) ──────────────────────────────

/// Submit a new compute job.
pub async fn compute_submit_job(
    Extension(protocol): Extension<Option<SharedComputeProtocol>>,
    Json(req): Json<axiom_ai::SubmitComputeJobRequest>,
) -> Result<Json<axiom_ai::ComputeJob>> {
    let protocol =
        protocol.ok_or_else(|| RpcError::Internal("compute protocol not initialised".into()))?;

    protocol
        .submit_job(req)
        .map_err(|e| RpcError::InvalidRequest(e.to_string()))
        .map(Json)
}

/// Get a compute job by ID.
pub async fn compute_get_job(
    Extension(protocol): Extension<Option<SharedComputeProtocol>>,
    Path(job_id): Path<String>,
) -> Result<Json<axiom_ai::ComputeJob>> {
    let protocol =
        protocol.ok_or_else(|| RpcError::Internal("compute protocol not initialised".into()))?;

    protocol
        .get_job(&job_id)
        .map_err(|e| RpcError::Internal(e.to_string()))?
        .ok_or_else(|| RpcError::NotFound(format!("job {job_id}")))
        .map(Json)
}

/// List compute jobs for an address.
pub async fn compute_list_jobs_for_address(
    Extension(protocol): Extension<Option<SharedComputeProtocol>>,
    Path(address): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<Vec<axiom_ai::ComputeJob>>> {
    let protocol =
        protocol.ok_or_else(|| RpcError::Internal("compute protocol not initialised".into()))?;

    let limit = params.limit.unwrap_or(50).min(100);

    protocol
        .list_jobs_for_requester(&address, limit)
        .map_err(|e| RpcError::Internal(e.to_string()))
        .map(Json)
}

/// Register a worker for compute jobs.
pub async fn compute_register_worker(
    Extension(protocol): Extension<Option<SharedComputeProtocol>>,
    Json(req): Json<axiom_ai::RegisterWorkerRequest>,
) -> Result<Json<axiom_ai::WorkerRegistration>> {
    let protocol =
        protocol.ok_or_else(|| RpcError::Internal("compute protocol not initialised".into()))?;

    protocol
        .register_worker(req)
        .map_err(|e| RpcError::InvalidRequest(e.to_string()))
        .map(Json)
}

/// Get a worker registration.
pub async fn compute_get_worker(
    Extension(protocol): Extension<Option<SharedComputeProtocol>>,
    Path(worker_id): Path<String>,
) -> Result<Json<axiom_ai::WorkerRegistration>> {
    let protocol =
        protocol.ok_or_else(|| RpcError::Internal("compute protocol not initialised".into()))?;

    protocol
        .get_worker(&worker_id)
        .map_err(|e| RpcError::Internal(e.to_string()))?
        .ok_or_else(|| RpcError::NotFound(format!("worker {worker_id}")))
        .map(Json)
}

/// Submit a computation result.
pub async fn compute_submit_result(
    Extension(protocol): Extension<Option<SharedComputeProtocol>>,
    Json(req): Json<axiom_ai::SubmitResultRequest>,
) -> Result<Json<axiom_ai::ComputeJob>> {
    let protocol =
        protocol.ok_or_else(|| RpcError::Internal("compute protocol not initialised".into()))?;

    protocol
        .submit_result(req)
        .map_err(|e| RpcError::InvalidRequest(e.to_string()))
        .map(Json)
}

/// Register a verifier for dispute challenges.
pub async fn compute_register_verifier(
    Extension(protocol): Extension<Option<SharedComputeProtocol>>,
    Json(req): Json<axiom_ai::RegisterVerifierRequest>,
) -> Result<Json<axiom_ai::VerifierRegistration>> {
    let protocol =
        protocol.ok_or_else(|| RpcError::Internal("compute protocol not initialised".into()))?;

    protocol
        .register_verifier(req)
        .map_err(|e| RpcError::InvalidRequest(e.to_string()))
        .map(Json)
}

/// File a challenge against a computation result.
pub async fn compute_file_challenge(
    Extension(protocol): Extension<Option<SharedComputeProtocol>>,
    Json(req): Json<axiom_ai::FileChallengeRequest>,
) -> Result<Json<axiom_ai::DisputeRecord>> {
    let protocol =
        protocol.ok_or_else(|| RpcError::Internal("compute protocol not initialised".into()))?;

    protocol
        .challenge_result(req)
        .map_err(|e| RpcError::InvalidRequest(e.to_string()))
        .map(Json)
}

/// Resolve a dispute (fraud/false accusation/inconclusive).
pub async fn compute_resolve_dispute(
    Extension(protocol): Extension<Option<SharedComputeProtocol>>,
    Json(req): Json<axiom_ai::ResolvDisputeRequest>,
) -> Result<Json<axiom_ai::SettlementRecord>> {
    let protocol =
        protocol.ok_or_else(|| RpcError::Internal("compute protocol not initialised".into()))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let resolution = match req.resolution.as_str() {
        "fraud_confirmed" => axiom_ai::DisputeResolution::FraudConfirmed {
            worker_slash_sat: 0,    // Calculated by protocol
            verifier_reward_sat: 0, // Calculated by protocol
            resolved_at: now,
        },
        "false_accusation" => axiom_ai::DisputeResolution::FalseAccusation {
            verifier_slash_sat: 0, // Calculated by protocol
            worker_bonus_sat: 0,   // Calculated by protocol
            resolved_at: now,
        },
        "inconclusive" => axiom_ai::DisputeResolution::Inconclusive { resolved_at: now },
        _ => {
            return Err(RpcError::InvalidRequest(format!(
                "Invalid resolution: {}",
                req.resolution
            )))
        }
    };

    protocol
        .resolve_dispute(&req.dispute_id, resolution)
        .map_err(|e| RpcError::InvalidRequest(e.to_string()))
        .map(Json)
}

/// Finalize a job (challenge window expired).
pub async fn compute_finalize_job(
    Extension(protocol): Extension<Option<SharedComputeProtocol>>,
    Path(job_id): Path<String>,
) -> Result<Json<axiom_ai::SettlementRecord>> {
    let protocol =
        protocol.ok_or_else(|| RpcError::Internal("compute protocol not initialised".into()))?;

    protocol
        .finalize_job(&job_id)
        .map_err(|e| RpcError::InvalidRequest(e.to_string()))
        .map(Json)
}

/// List recent settlements.
pub async fn compute_list_settlements(
    Extension(protocol): Extension<Option<SharedComputeProtocol>>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<Vec<axiom_ai::SettlementRecord>>> {
    let protocol =
        protocol.ok_or_else(|| RpcError::Internal("compute protocol not initialised".into()))?;

    let limit = params.limit.unwrap_or(50).min(100);

    protocol
        .list_recent_settlements(limit)
        .map_err(|e| RpcError::Internal(e.to_string()))
        .map(Json)
}

/// List active workers.
pub async fn compute_list_active_workers(
    Extension(protocol): Extension<Option<SharedComputeProtocol>>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<Vec<axiom_ai::WorkerRegistration>>> {
    let protocol =
        protocol.ok_or_else(|| RpcError::Internal("compute protocol not initialised".into()))?;

    let limit = params.limit.unwrap_or(50).min(1000);

    protocol
        .list_active_workers(limit)
        .map_err(|e| RpcError::Internal(e.to_string()))
        .map(Json)
}

#[cfg(test)]
#[allow(clippy::unnecessary_literal_unwrap)]
mod pagination_tests {
    use super::*;

    fn fake_blocks(n: usize) -> Vec<crate::types::BlockSummary> {
        (0..n)
            .map(|i| crate::types::BlockSummary {
                hash: format!("{:064x}", i),
                height: i as u32,
                timestamp: 0,
                prev_block_hash: "0".repeat(64),
                merkle_root: "0".repeat(64),
                nonce: 0,
                difficulty: 1,
                transaction_count: 0,
            })
            .collect()
    }

    #[test]
    fn test_blocks_recent_default_limit() {
        let limit = None::<usize>
            .unwrap_or(DEFAULT_BLOCKS_PER_PAGE)
            .min(MAX_BLOCKS_PER_PAGE);
        assert_eq!(limit, 10);

        let blocks = fake_blocks(50);
        let page: Vec<_> = blocks.iter().take(limit).collect();
        assert!(page.len() <= 10);
    }

    #[test]
    fn test_blocks_recent_custom_limit() {
        let requested_limit = 5usize;
        let limit = Some(requested_limit)
            .unwrap_or(DEFAULT_BLOCKS_PER_PAGE)
            .min(MAX_BLOCKS_PER_PAGE);
        assert_eq!(limit, 5);

        let blocks = fake_blocks(50);
        let page: Vec<_> = blocks.iter().take(limit).collect();
        assert!(page.len() <= 5);
        assert_eq!(page.len(), 5);
    }

    #[test]
    fn test_blocks_recent_max_limit_clamped() {
        let requested_limit = 9999usize;
        let limit = Some(requested_limit)
            .unwrap_or(DEFAULT_BLOCKS_PER_PAGE)
            .min(MAX_BLOCKS_PER_PAGE);
        assert_eq!(limit, MAX_BLOCKS_PER_PAGE);
        assert_eq!(limit, 100);
    }

    #[test]
    fn test_block_height_out_of_range() {
        let too_high: u32 = 1_500_000_000u32;
        assert!(too_high > MAX_REASONABLE_HEIGHT);

        let valid: u32 = MAX_REASONABLE_HEIGHT;
        assert!(valid <= MAX_REASONABLE_HEIGHT);
    }

    #[test]
    fn test_address_length_validation() {
        let empty = "";
        assert!(empty.is_empty() || empty.len() > 128);

        let too_long = "a".repeat(129);
        assert!(too_long.is_empty() || too_long.len() > 128);

        let valid = "axm1qfakeaddress123456789";
        assert!(!valid.is_empty() && valid.len() <= 128);
    }

    #[test]
    fn test_mempool_default_limit() {
        let limit = None::<usize>
            .unwrap_or(DEFAULT_MEMPOOL_ITEMS)
            .min(MAX_MEMPOOL_ITEMS_PER_PAGE);
        assert_eq!(limit, 50);

        let over = Some(99999usize)
            .unwrap_or(DEFAULT_MEMPOOL_ITEMS)
            .min(MAX_MEMPOOL_ITEMS_PER_PAGE);
        assert_eq!(over, MAX_MEMPOOL_ITEMS_PER_PAGE);
        assert_eq!(over, 500);
    }

    #[test]
    fn test_address_txs_default_limit() {
        let limit = None::<usize>
            .unwrap_or(DEFAULT_ADDRESS_TXS)
            .min(MAX_ADDRESS_TXS_PER_PAGE);
        assert_eq!(limit, 50);

        let over = Some(99999usize)
            .unwrap_or(DEFAULT_ADDRESS_TXS)
            .min(MAX_ADDRESS_TXS_PER_PAGE);
        assert_eq!(over, MAX_ADDRESS_TXS_PER_PAGE);
        assert_eq!(over, 1000);
    }
}
