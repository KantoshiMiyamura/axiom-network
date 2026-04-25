use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::error::{AppError, AppResult};

const TIMEOUT: Duration = Duration::from_secs(10);

pub struct RpcClient {
    client: reqwest::Client,
    base: String,
}

#[derive(Debug, Deserialize)]
pub struct BalanceResponse {
    pub balance: u64,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
pub struct UtxoListResponse {
    pub utxos: Vec<UtxoEntry>,
    pub total_value: u64,
    pub count: usize,
}

#[derive(Debug, Serialize)]
struct SubmitReq {
    transaction_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct SubmitResp {
    pub txid: String,
}

#[derive(Debug, Deserialize)]
pub struct FeeEstimate {
    pub low: u64,
    pub medium: u64,
    pub high: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxSummary {
    pub txid: String,
    pub block_height: Option<u32>,
    pub timestamp: Option<u32>,
    pub value_change: i64,
}

#[derive(Debug, Deserialize)]
pub struct TxHistoryResp {
    pub transactions: Vec<TxSummary>,
    pub count: usize,
}

#[derive(Debug, Deserialize)]
pub struct StatusResp {
    pub block_height: Option<u32>,
    pub best_block_hash: Option<String>,
    pub peer_count: usize,
    /// Chain identifier returned by the node ("axiom-test-1", "axiom-mainnet-1", etc.).
    /// Required for transaction signing; replay protection lives here.
    pub network: Option<String>,
}

impl RpcClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(TIMEOUT)
                .build()
                .expect("http client"),
            base: base_url.trim_end_matches('/').to_string(),
        }
    }

    pub async fn balance(&self, addr: &str) -> AppResult<u64> {
        Ok(self
            .get::<BalanceResponse>(&format!("{}/balance/{}", self.base, addr))
            .await?
            .balance)
    }

    pub async fn nonce(&self, addr: &str) -> AppResult<u64> {
        Ok(self
            .get::<NonceResponse>(&format!("{}/nonce/{}", self.base, addr))
            .await?
            .nonce)
    }

    pub async fn utxos(&self, addr: &str) -> AppResult<Vec<UtxoEntry>> {
        Ok(self
            .get::<UtxoListResponse>(&format!("{}/utxos/{}", self.base, addr))
            .await?
            .utxos)
    }

    pub async fn fee_estimate(&self) -> AppResult<FeeEstimate> {
        self.get(&format!("{}/fee/estimate", self.base)).await
    }

    pub async fn submit_tx(&self, hex: &str) -> AppResult<String> {
        let url = format!("{}/submit_transaction", self.base);
        let resp = self
            .client
            .post(&url)
            .json(&SubmitReq {
                transaction_hex: hex.to_string(),
            })
            .send()
            .await
            .map_err(|e| AppError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            let s = resp.status();
            let t = resp.text().await.unwrap_or_default();
            return Err(AppError::Network(format!("{s}: {t}")));
        }
        Ok(resp
            .json::<SubmitResp>()
            .await
            .map_err(|e| AppError::Network(e.to_string()))?
            .txid)
    }

    pub async fn tx_history(&self, addr: &str) -> AppResult<Vec<TxSummary>> {
        let url = format!("{}/address/{}/txs?limit=50&offset=0", self.base, addr);
        Ok(self.get::<TxHistoryResp>(&url).await?.transactions)
    }

    pub async fn status(&self) -> AppResult<StatusResp> {
        self.get(&format!("{}/status", self.base)).await
    }

    /// Fetch the node's chain identifier. Used to bind transaction signatures
    /// to a specific chain — a signature for chain X must not be valid on chain Y.
    pub async fn chain_id(&self) -> AppResult<String> {
        let s: StatusResp = self.get(&format!("{}/status", self.base)).await?;
        s.network
            .ok_or_else(|| AppError::Network("node /status missing 'network' field".into()))
    }

    pub async fn is_online(&self) -> bool {
        self.client
            .get(&format!("{}/health", self.base))
            .send()
            .await
            .is_ok()
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, url: &str) -> AppResult<T> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| AppError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            let s = resp.status();
            let t = resp.text().await.unwrap_or_default();
            return Err(AppError::Network(format!("{s}: {t}")));
        }
        resp.json()
            .await
            .map_err(|e| AppError::Network(format!("parse: {e}")))
    }
}
