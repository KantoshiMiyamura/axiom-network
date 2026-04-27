// Copyright (c) 2026 Kantoshi Miyamura

//! Node runtime for Axiom Network.

pub mod anomaly;
pub mod block_index;
pub mod checkpoints;
pub mod community;
mod config;
mod fork;
mod fork_choice_log;
mod genesis;
mod mempool;
pub mod mining_snapshot;
pub mod network;
mod node;
mod reorg;
mod state;
pub mod testnet;
pub mod validation;
pub mod watchdog;

pub use anomaly::{AiAnalysisReport, AnomalyAlert, AnomalyDetector, EngineStats, Severity};
pub use block_index::{BlockIndex, BlockIndexEntry, BlockSource, BlockValidationStatus};
pub use checkpoints::{
    assumevalid_height, is_before_last_checkpoint, verify_checkpoint, Checkpoint, CheckpointError,
};
pub use community::CommunityService;
pub use config::{Config, ConfigError, Network};
pub use fork::{ChainTip, ForkError, OrphanPool};
pub use fork_choice_log::*;
pub use genesis::{create_genesis_block, expected_genesis_hash};
pub use mempool::{
    FeePercentiles, Mempool, MempoolEntry, MempoolError, MempoolStats, RecommendedFeeRates,
    DUST_LIMIT,
};
pub use mining_snapshot::MiningSnapshot;
pub use node::{Node, NodeError, MAX_REORG_DEPTH};
pub use reorg::{ReorgEngine, ReorgError};
pub use state::{ChainState, StateError};
pub use testnet::TestnetConfig;
pub use validation::{TransactionValidator, ValidationError, ValidationMode};
pub use watchdog::{install_panic_hook, spawn_resilient, Watchdog, WatchdogConfig};
