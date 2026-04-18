// Copyright (c) 2026 Kantoshi Miyamura

//! Network and resource limits.

pub const MAX_INBOUND_PEERS: usize = 64;
pub const MAX_OUTBOUND_PEERS: usize = 32;
pub const MAX_PEERS: usize = MAX_INBOUND_PEERS + MAX_OUTBOUND_PEERS;
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 30;
pub const MESSAGE_READ_TIMEOUT_SECS: u64 = 60;
pub const IDLE_PEER_TIMEOUT_SECS: u64 = 300;
pub const MAX_MESSAGE_SIZE: usize = 10_000_000;
pub const MAX_TXNS_PER_MESSAGE: usize = 1000;
pub const MAX_BLOCKS_PER_RESPONSE: usize = 500;
pub const PEER_BAN_THRESHOLD: i32 = -100;
pub const PEER_PENALTY_INVALID_MESSAGE: i32 = -10;
pub const PEER_PENALTY_PROTOCOL_VIOLATION: i32 = -20;
pub const PEER_PENALTY_SPAM: i32 = -5;
pub const PEER_REWARD_VALID_BLOCK: i32 = 1;
pub const PEER_REWARD_VALID_TX: i32 = 1;
pub const MEMPOOL_MAX_SIZE: usize = 100_000_000;
pub const MEMPOOL_MAX_COUNT: usize = 10_000;
pub const MIN_FEE_RATE: u64 = 1;
pub const ORPHAN_POOL_MAX_SIZE: usize = 10_000;
pub const ORPHAN_POOL_MAX_MEMORY: usize = 50_000_000;
pub const RPC_RATE_LIMIT_PER_MINUTE: u32 = 100;
pub const RPC_RATE_LIMIT_PER_SECOND: u32 = 10;
pub const RPC_REQUEST_TIMEOUT_SECS: u64 = 30;
pub const MAX_RPC_REQUEST_SIZE: usize = 1_000_000;
pub const MAX_RPC_RESPONSE_SIZE: usize = 10_000_000;
pub const MAX_CONCURRENT_RPC_REQUESTS_PER_IP: usize = 10;
pub const BLOCK_TIMESTAMP_DRIFT_SECS: u64 = 7200;
pub const MAX_BLOCK_SIZE: usize = 1_000_000;
pub const MAX_BLOCK_TRANSACTIONS: usize = 10_000;
pub const MAX_TRANSACTION_SIZE: usize = 100_000;
pub const TEMPORARY_BAN_DURATION_SECS: u64 = 3600;
pub const PEER_INACTIVITY_CHECK_INTERVAL_SECS: u64 = 60;
pub const ORPHAN_CLEANUP_INTERVAL_SECS: u64 = 300;
pub const ORPHAN_TTL_SECS: u64 = 3600;
