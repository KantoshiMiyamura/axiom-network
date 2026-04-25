// Copyright (c) 2026 Kantoshi Miyamura

//! Testnet configuration and bootstrap.

use std::net::SocketAddr;
use std::str::FromStr;

pub const TESTNET_SEED_NODES: &[&str] = &[
    "seed1.axiom.network:9100",
    "seed2.axiom.network:9100",
    "seed3.axiom.network:9100",
];

pub const TESTNET_NETWORK_ID: &str = "axiom-testnet-v1";

pub const TESTNET_GENESIS_HASH: &str =
    "98474bd9866dcec530767a7e2a7cfd696227d4f47d873c1518bdb2d79c56e750";

pub const TESTNET_INITIAL_DIFFICULTY: u32 = 0x00000fff;
pub const TESTNET_BLOCK_REWARD: u64 = 5_000_000_000;
pub const TESTNET_COINBASE_MATURITY: u32 = 100;
pub const TESTNET_BLOCK_TIME_TARGET: u64 = 600;
pub const TESTNET_DIFFICULTY_INTERVAL: u32 = 2016;

#[derive(Debug, Clone)]
pub struct TestnetConfig {
    pub seed_nodes: Vec<SocketAddr>,
    pub network_id: String,
    pub genesis_hash: String,
    pub initial_difficulty: u32,
    pub block_reward: u64,
    pub coinbase_maturity: u32,
    pub block_time_target: u64,
    pub difficulty_interval: u32,
}

impl Default for TestnetConfig {
    fn default() -> Self {
        let seed_nodes = vec![SocketAddr::from_str("127.0.0.1:9100")
            .unwrap_or_else(|_| "127.0.0.1:9100".parse().unwrap())];

        TestnetConfig {
            seed_nodes,
            network_id: TESTNET_NETWORK_ID.to_string(),
            genesis_hash: TESTNET_GENESIS_HASH.to_string(),
            initial_difficulty: TESTNET_INITIAL_DIFFICULTY,
            block_reward: TESTNET_BLOCK_REWARD,
            coinbase_maturity: TESTNET_COINBASE_MATURITY,
            block_time_target: TESTNET_BLOCK_TIME_TARGET,
            difficulty_interval: TESTNET_DIFFICULTY_INTERVAL,
        }
    }
}

impl TestnetConfig {
    pub fn get_seed_nodes(&self) -> Vec<SocketAddr> {
        self.seed_nodes.clone()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.seed_nodes.is_empty() {
            return Err("No seed nodes configured".to_string());
        }

        if self.network_id.is_empty() {
            return Err("Network ID cannot be empty".to_string());
        }

        if self.block_reward == 0 {
            return Err("Block reward must be greater than 0".to_string());
        }

        if self.block_time_target == 0 {
            return Err("Block time target must be greater than 0".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_testnet_config_default() {
        let config = TestnetConfig::default();
        assert!(!config.seed_nodes.is_empty());
        assert_eq!(config.network_id, TESTNET_NETWORK_ID);
    }

    #[test]
    fn test_testnet_config_validate() {
        let config = TestnetConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_testnet_seed_nodes_count() {
        let config = TestnetConfig::default();
        assert!(!config.seed_nodes.is_empty());
    }

    #[test]
    fn test_testnet_genesis_hash_matches_constant() {
        let actual =
            hex::encode(crate::genesis::expected_genesis_hash(crate::Network::Test).as_bytes());
        assert_eq!(
            actual, TESTNET_GENESIS_HASH,
            "TESTNET_GENESIS_HASH is stale — update it to: {}",
            actual
        );
    }
}
