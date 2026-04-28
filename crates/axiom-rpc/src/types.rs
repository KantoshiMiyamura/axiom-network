// Copyright (c) 2026 Kantoshi Miyamura

//! RPC request and response types.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub best_block_hash: Option<String>,
    pub best_height: Option<u32>,
    pub mempool_size: usize,
    pub orphan_count: usize,
    pub version: String,
    pub network: String,
    pub peers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockSummary {
    pub hash: String,
    pub height: u32,
    pub timestamp: u32,
    pub prev_block_hash: String,
    pub merkle_root: String,
    pub nonce: u64,
    pub difficulty: u32,
    pub transaction_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionDetail {
    pub txid: String,
    pub version: u32,
    pub tx_type: String,
    pub inputs: Vec<TxInputDetail>,
    pub outputs: Vec<TxOutputDetail>,
    pub nonce: u64,
    pub locktime: u32,
    pub memo: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInputDetail {
    pub prev_tx_hash: String,
    pub prev_output_index: u32,
    pub signature: String,
    pub pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutputDetail {
    pub value: u64,
    pub pubkey_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentBlocksResponse {
    pub blocks: Vec<BlockSummary>,
    pub count: usize,
    #[serde(default)]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTransactionsResponse {
    pub transactions: Vec<TransactionDetail>,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressTransactionsResponse {
    pub transactions: Vec<AddressTxSummary>,
    pub count: usize,
    /// Total before pagination.
    #[serde(default)]
    pub total: usize,
    #[serde(default)]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressTxSummary {
    pub txid: String,
    pub block_height: Option<u32>,
    pub timestamp: Option<u32>,
    pub value_change: i64, // Positive for received, negative for sent
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsResponse {
    pub block_height: Option<u32>,
    pub best_block_hash: Option<String>,
    pub mempool_size: usize,
    pub peer_count: usize,
    pub orphan_block_count: usize,
    pub chain_work: Option<String>,
    pub uptime_seconds: u64,
    /// Confirmed tx/s over recent blocks (0.0 when unavailable).
    pub tx_rate: f64,
    pub reorg_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub height: Option<u32>,
    pub peers: usize,
    pub mempool: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTransactionRequest {
    pub transaction_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTransactionResponse {
    pub txid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceResponse {
    pub balance: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceResponse {
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoEntry {
    pub txid: String,
    pub output_index: u32,
    pub value: u64,
    pub block_height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoListResponse {
    pub utxos: Vec<UtxoEntry>,
    pub total_value: u64,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimateResponse {
    pub low: u64,
    pub medium: u64,
    pub high: u64,
    pub typical_fee_sat: u64,
    pub min_fee_rate: u64,
    pub typical_tx_size: u64,
    // Percentile-based estimates derived from mempool distribution.
    pub slow_sat_per_byte: u64,
    pub medium_sat_per_byte: u64,
    pub fast_sat_per_byte: u64,
    pub next_block_sat_per_byte: u64,
    pub min_relay_sat_per_byte: u64,
    pub mempool_tx_count: usize,
    pub note: String,
}

// ── AI anomaly detection ───────────────────────────────────────────────────

pub use axiom_node::anomaly::{AiAnalysisReport, AnomalyAlert, EngineStats, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolTxSummary {
    pub txid: String,
    pub size: usize,
    /// 0 when fee cannot be computed without UTXO lookup.
    pub fee_sat: u64,
    pub nonce: u64,
    pub input_count: usize,
    pub output_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolResponse {
    pub transactions: Vec<MempoolTxSummary>,
    pub count: usize,
    /// Full mempool count before pagination.
    #[serde(default)]
    pub total: usize,
    /// Aggregate size of all mempool transactions in bytes.
    pub total_size: usize,
    #[serde(default)]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub address: String,
    pub connected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerListResponse {
    pub peers: Vec<PeerInfo>,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectPeerRequest {
    /// Peer address as `host:port` (IPv4 or IPv6, e.g. "203.0.113.5:9000").
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectPeerResponse {
    pub success: bool,
    pub address: String,
    pub message: String,
}

// ── SPV / light-client types ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStepResponse {
    pub is_right: bool,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProofResponse {
    pub txid: String,
    pub block_hash: String,
    pub block_height: u32,
    pub tx_index: u32,
    pub proof_path: Vec<ProofStepResponse>,
    pub merkle_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeaderResponse {
    pub hash: String,
    pub version: u32,
    pub prev_block_hash: String,
    pub merkle_root: String,
    pub timestamp: u32,
    pub difficulty_target: u32,
    pub nonce: u32,
    /// `None` when coinbase is unavailable.
    pub height: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStepRequest {
    pub is_right: bool,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpvVerifyRequest {
    pub txid: String,
    pub block_hash: String,
    pub tx_index: u32,
    pub proof_path: Vec<ProofStepRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpvVerifyResponse {
    pub valid: bool,
    pub merkle_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodeRawTxRequest {
    pub raw_tx_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastRawTxRequest {
    pub raw_tx_hex: String,
}

// ── Analytics / Statistics ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAnalyticsResponse {
    pub avg_block_time_secs: f64,
    pub std_block_time_secs: f64,
    pub avg_tx_per_block: f64,
    pub avg_block_size_bytes: f64,
    pub blocks_per_hour: f64,
    pub estimated_tps: f64,
    pub difficulty_trend: f64,
    pub fee_rate_p50_sat_byte: u64,
    pub total_blocks_analyzed: u32,
    pub chain_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockStatsResponse {
    pub block_hash: String,
    pub height: u32,
    pub block_time_secs: f64,
    pub fee_total_sat: u64,
    pub avg_fee_rate: f64,
    pub min_fee_rate: u64,
    pub max_fee_rate: u64,
    pub coinbase_value: u64,
    pub tx_count: usize,
}

// ── Mempool Detail ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeBucket {
    pub min_rate: u64,
    pub max_rate: u64,
    pub count: u64,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeePercentilesDetail {
    pub p5: u64,
    pub p10: u64,
    pub p25: u64,
    pub p50: u64,
    pub p75: u64,
    pub p90: u64,
    pub p95: u64,
    pub p99: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextBlockEstimate {
    pub tx_count: u64,
    pub size_bytes: u64,
    pub total_fees: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolDetailResponse {
    pub count: u64,
    pub size_bytes: u64,
    pub fee_histogram: Vec<FeeBucket>,
    pub fee_percentiles: FeePercentilesDetail,
    pub min_fee_rate: u64,
    pub max_fee_rate: u64,
    pub avg_fee_rate: f64,
    pub next_block_estimate: NextBlockEstimate,
    pub rbf_count: u64,
}

// ── Network Hashrate ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHashrateResponse {
    pub estimated_hashrate_hps: f64,
    pub estimated_hashrate_human: String,
    pub sample_blocks: u32,
    pub avg_block_time_secs: f64,
}
