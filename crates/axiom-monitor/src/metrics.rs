// Copyright (c) 2026 Kantoshi Miyamura

//! System-level metrics collection.

use axiom_node::Node;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub timestamp_ms: u64,
    pub chain_height: u64,
    pub best_block_hash: String,
    pub mempool_count: usize,
    pub mempool_bytes: usize,
    pub peer_count: usize,
    pub is_mining: bool,
    pub uptime_secs: u64,
    pub blocks_validated_total: u64,
    pub txs_validated_total: u64,
}

pub struct MetricsCollector {
    start_time: SystemTime,
    blocks_validated: u64,
    txs_validated: u64,
}

impl MetricsCollector {
    pub fn new() -> Self {
        MetricsCollector {
            start_time: SystemTime::now(),
            blocks_validated: 0,
            txs_validated: 0,
        }
    }

    pub fn record_block_validated(&mut self) {
        self.blocks_validated += 1;
    }

    pub fn record_tx_validated(&mut self) {
        self.txs_validated += 1;
    }

    pub fn collect(&self, node: &Node) -> SystemMetrics {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let uptime = self
            .start_time
            .elapsed()
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let height = node.best_height().unwrap_or(0);
        let best_hash = node
            .best_block_hash()
            .map(|h| hex::encode(h.as_bytes()))
            .unwrap_or_default();

        SystemMetrics {
            timestamp_ms: now_ms,
            chain_height: height as u64,
            best_block_hash: best_hash,
            mempool_count: node.mempool_size(),
            mempool_bytes: node.mempool_byte_size(),
            peer_count: 0, // peer count lives in NetworkService, not Node
            is_mining: false,
            uptime_secs: uptime,
            blocks_validated_total: self.blocks_validated,
            txs_validated_total: self.txs_validated,
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}
