// Copyright (c) 2026 Kantoshi Miyamura

use crate::config::Network;
use axiom_consensus::{Block, BlockHeader};
use axiom_primitives::{Amount, Hash256};
use axiom_protocol::{Transaction, TxOutput};

pub const MAINNET_GENESIS_MESSAGE: &str =
    "I make it look easy, but this shit really a process. I'm really a millionaire, still in the projects";

pub const MAINNET_GENESIS_TIMESTAMP: u32 = 1_774_051_200;
pub const TESTNET_GENESIS_TIMESTAMP: u32 = 1_774_051_200;

pub struct GenesisParams {
    pub timestamp: u32,
    pub difficulty_target: u32,
    pub message: Option<&'static str>,
}

impl GenesisParams {
    pub fn for_network(network: Network) -> Self {
        match network {
            Network::Dev => GenesisParams {
                timestamp: 1_704_067_200,
                difficulty_target: 0x1f00_ffff,
                message: None,
            },
            Network::Test => GenesisParams {
                timestamp: TESTNET_GENESIS_TIMESTAMP,
                difficulty_target: 0x1e00_ffff,
                message: Some("Axiom Testnet - 21 March 2026"),
            },
            Network::Mainnet => GenesisParams {
                timestamp: MAINNET_GENESIS_TIMESTAMP,
                difficulty_target: 0x1e00_ffff,
                message: Some(MAINNET_GENESIS_MESSAGE),
            },
        }
    }
}

pub fn create_genesis_block(network: Network) -> Block {
    let params = GenesisParams::for_network(network);

    let coinbase_output = TxOutput {
        value: Amount::from_sat(5_000_000_000).unwrap(),
        pubkey_hash: Hash256::zero(),
    };

    let mut coinbase = Transaction::new_coinbase(vec![coinbase_output], 0);

    if let Some(msg) = params.message {
        coinbase = coinbase.with_memo(msg);
    }

    let merkle_root =
        axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(&coinbase));

    let header = BlockHeader {
        version: 1,
        prev_block_hash: Hash256::zero(),
        merkle_root,
        timestamp: params.timestamp,
        difficulty_target: params.difficulty_target,
        nonce: 0,
    };

    Block {
        header,
        transactions: vec![coinbase],
    }
}

pub fn expected_genesis_hash(network: Network) -> Hash256 {
    create_genesis_block(network).hash()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_deterministic() {
        let g1 = create_genesis_block(Network::Dev);
        let g2 = create_genesis_block(Network::Dev);
        assert_eq!(g1.hash(), g2.hash());
    }

    #[test]
    fn test_mainnet_genesis_deterministic() {
        let g1 = create_genesis_block(Network::Mainnet);
        let g2 = create_genesis_block(Network::Mainnet);
        assert_eq!(g1.hash(), g2.hash());
    }

    #[test]
    fn test_all_networks_have_different_genesis() {
        let dev_hash = create_genesis_block(Network::Dev).hash();
        let test_hash = create_genesis_block(Network::Test).hash();
        let main_hash = create_genesis_block(Network::Mainnet).hash();

        assert_ne!(dev_hash, test_hash, "dev and test genesis must differ");
        assert_ne!(dev_hash, main_hash, "dev and mainnet genesis must differ");
        assert_ne!(test_hash, main_hash, "test and mainnet genesis must differ");
    }

    #[test]
    fn test_mainnet_genesis_has_message() {
        let genesis = create_genesis_block(Network::Mainnet);
        let coinbase = &genesis.transactions[0];
        assert!(
            coinbase.memo.is_some(),
            "mainnet genesis coinbase must carry memo"
        );

        let memo_bytes = coinbase.memo.unwrap();
        let end = memo_bytes
            .iter()
            .rposition(|&b| b != 0)
            .map(|i| i + 1)
            .unwrap_or(0);
        let text = std::str::from_utf8(&memo_bytes[..end]).unwrap();
        assert!(
            text.contains("millionaire"),
            "memo must contain the genesis message"
        );
        assert!(
            text.contains("process"),
            "memo must contain the genesis message"
        );
    }

    #[test]
    fn test_genesis_structure() {
        for net in [Network::Dev, Network::Test, Network::Mainnet] {
            let genesis = create_genesis_block(net);
            assert_eq!(genesis.transactions.len(), 1);
            assert!(genesis.transactions[0].is_coinbase());
            assert_eq!(genesis.header.prev_block_hash, Hash256::zero());
            assert_eq!(genesis.height(), Some(0));
        }
    }

    #[test]
    fn test_mainnet_genesis_hash_is_stable() {
        // Hash is deterministic — value updates whenever the protocol changes.
        let h1 = expected_genesis_hash(Network::Mainnet);
        let h2 = expected_genesis_hash(Network::Mainnet);
        assert_eq!(h1, h2, "mainnet genesis must be deterministic");
        let hex = hex::encode(h1.as_bytes());
        assert_eq!(hex.len(), 64, "genesis hash must be 32 bytes");
    }

    #[test]
    fn test_testnet_genesis_hash_is_stable() {
        let h1 = expected_genesis_hash(Network::Test);
        let h2 = expected_genesis_hash(Network::Test);
        assert_eq!(h1, h2, "testnet genesis must be deterministic");
        let hex = hex::encode(h1.as_bytes());
        assert_eq!(hex.len(), 64);
    }
}
