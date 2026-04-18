// Copyright (c) 2026 Kantoshi Miyamura

//! Hard-coded block checkpoints.

use crate::Network;
use axiom_primitives::Hash256;

#[derive(Debug, Clone, Copy)]
pub struct Checkpoint {
    pub height: u32,
    pub hash: &'static str,
}

pub const MAINNET_CHECKPOINTS: &[Checkpoint] = &[
    Checkpoint {
        height: 0,
        hash: "881cc7fb1e1f9937d1b396184f5257f79e0379d26f7824fef019ac4b08007c19",
    },
    // Checkpoint maintenance procedure:
    // 1. Wait for the network to mine past the target height.
    // 2. Verify the block hash at that height across multiple independent nodes.
    // 3. Add the checkpoint entry here in a maintenance release.
    // Target heights: 52,560 (~6 months), 525,600 (~5 years), 2,628,000 (~25 years).
];

pub const TESTNET_CHECKPOINTS: &[Checkpoint] = &[
    Checkpoint {
        height: 0,
        hash: "98474bd9866dcec530767a7e2a7cfd696227d4f47d873c1518bdb2d79c56e750",
    },
    // Testnet checkpoints added via same procedure as mainnet.
];

pub const DEV_CHECKPOINTS: &[Checkpoint] = &[];

pub fn checkpoints_for(network: Network) -> &'static [Checkpoint] {
    match network {
        Network::Mainnet => MAINNET_CHECKPOINTS,
        Network::Test => TESTNET_CHECKPOINTS,
        Network::Dev => DEV_CHECKPOINTS,
    }
}

pub fn verify_checkpoint(
    network: Network,
    height: u32,
    block_hash: &Hash256,
) -> Result<(), CheckpointError> {
    let checkpoints = checkpoints_for(network);
    for cp in checkpoints {
        if cp.height == height {
            let expected = hex_to_hash256(cp.hash)
                .map_err(|_| CheckpointError::InvalidCheckpointData(cp.height))?;
            if *block_hash != expected {
                return Err(CheckpointError::HashMismatch {
                    height,
                    expected: cp.hash.to_string(),
                    actual: hex_encode(block_hash.as_bytes()),
                });
            }
            return Ok(());
        }
    }
    Ok(())
}

pub fn assumevalid_height() -> u32 {
    0
}

pub fn is_before_last_checkpoint(network: Network, height: u32) -> bool {
    let checkpoints = checkpoints_for(network);
    if let Some(last) = checkpoints.last() {
        height <= last.height
    } else {
        false
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("block at height {height} has hash {actual}, expected checkpoint {expected}")]
    HashMismatch {
        height: u32,
        expected: String,
        actual: String,
    },
    #[error("invalid checkpoint data at height {0}")]
    InvalidCheckpointData(u32),
}

fn hex_to_hash256(s: &str) -> Result<Hash256, ()> {
    let bytes = hex::decode(s).map_err(|_| ())?;
    if bytes.len() != 32 {
        return Err(());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Hash256::from_bytes(arr))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_genesis_checkpoint() {
        let genesis = crate::genesis::expected_genesis_hash(Network::Mainnet);
        let result = verify_checkpoint(Network::Mainnet, 0, &genesis);
        assert!(result.is_ok());
    }

    #[test]
    fn test_testnet_genesis_checkpoint() {
        let genesis = crate::genesis::expected_genesis_hash(Network::Test);
        let result = verify_checkpoint(Network::Test, 0, &genesis);
        assert!(result.is_ok());
    }

    #[test]
    fn test_wrong_hash_fails() {
        let wrong = Hash256::zero();
        let result = verify_checkpoint(Network::Mainnet, 0, &wrong);
        assert!(result.is_err());
    }

    #[test]
    fn test_no_checkpoint_at_height_passes() {
        let any = Hash256::zero();
        let result = verify_checkpoint(Network::Mainnet, 999, &any);
        assert!(result.is_ok());
    }

    #[test]
    fn test_dev_no_checkpoints() {
        assert!(DEV_CHECKPOINTS.is_empty());
    }
}
