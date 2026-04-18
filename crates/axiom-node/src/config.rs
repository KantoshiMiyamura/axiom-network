// Copyright (c) 2026 Kantoshi Miyamura

use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("invalid data directory: {0}")]
    InvalidDataDir(String),

    #[error("invalid mempool size: {0}")]
    InvalidMempoolSize(String),

    #[error("invalid network: {0}")]
    InvalidNetwork(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Dev,
    Test,
    Mainnet,
}

impl Network {
    pub fn parse_str(s: &str) -> Result<Self, ConfigError> {
        match s {
            "dev" | "devnet" => Ok(Network::Dev),
            "test" | "testnet" => Ok(Network::Test),
            "main" | "mainnet" => Ok(Network::Mainnet),
            _ => Err(ConfigError::InvalidNetwork(s.to_string())),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Network::Dev => "dev",
            Network::Test => "test",
            Network::Mainnet => "mainnet",
        }
    }

    pub fn chain_id(&self) -> &'static str {
        match self {
            Network::Dev => "axiom-dev-1",
            Network::Test => "axiom-test-1",
            Network::Mainnet => "axiom-mainnet-1",
        }
    }

    pub fn requires_pow(&self) -> bool {
        matches!(self, Network::Test | Network::Mainnet)
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub network: Network,
    pub rpc_bind: String,
    pub mempool_max_size: usize,
    pub mempool_max_count: usize,
    pub min_fee_rate: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            data_dir: PathBuf::from("./data"),
            network: Network::Dev,
            rpc_bind: "127.0.0.1:8332".to_string(),
            mempool_max_size: 300_000_000,
            mempool_max_count: 50_000,
            min_fee_rate: 1,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.mempool_max_size == 0 {
            return Err(ConfigError::InvalidMempoolSize("must be > 0".into()));
        }

        if self.mempool_max_count == 0 {
            return Err(ConfigError::InvalidMempoolSize("count must be > 0".into()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.network, Network::Dev);
    }

    #[test]
    fn test_network_from_str() {
        assert_eq!(Network::parse_str("dev").unwrap(), Network::Dev);
        assert_eq!(Network::parse_str("test").unwrap(), Network::Test);
        assert!(Network::parse_str("invalid").is_err());
    }

    #[test]
    fn test_invalid_mempool_size() {
        let mut config = Config::default();
        config.mempool_max_size = 0;
        assert!(config.validate().is_err());
    }
}
