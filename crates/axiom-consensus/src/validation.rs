// Copyright (c) 2026 Kantoshi Miyamura

use crate::{Block, Error, Result};
use std::time::{SystemTime, UNIX_EPOCH};

/// Max block size in bytes. ML-DSA-87 txs are ~7.4 KB; 4 MB supports ~540 tx/block.
pub const MAX_BLOCK_SIZE: usize = 4_000_000;

/// Max transactions per block.
pub const MAX_BLOCK_TRANSACTIONS: usize = 10_000;

/// Max transaction size in bytes. ML-DSA-87 single-input tx is ~7.4 KB; 100 KB allows multi-input.
/// CRITICAL FIX: Unified with consensus.rs (was 10KB here, 100KB there — consensus split risk).
pub const MAX_TRANSACTION_SIZE: usize = 100_000;

/// Block timestamp may not exceed wall clock by more than 10 minutes.
/// CRITICAL FIX: Reduced from 7200 seconds (2 hours) to 600 seconds (10 minutes).
/// Prevents attackers from manipulating LWMA-3 difficulty by setting timestamps far in future.
pub const BLOCK_TIMESTAMP_DRIFT_SECS: u64 = 600;

/// Validate block structure. Does not check PoW, signatures, or UTXO state.
pub fn validate_block_structure(block: &Block) -> Result<()> {
    if block.transactions.is_empty() {
        return Err(Error::InvalidBlock("block has no transactions".into()));
    }

    if block.transactions.len() > MAX_BLOCK_TRANSACTIONS {
        return Err(Error::InvalidBlock(format!(
            "block has too many transactions: {} (max: {})",
            block.transactions.len(),
            MAX_BLOCK_TRANSACTIONS
        )));
    }

    let block_size = estimate_block_size(block);
    if block_size > MAX_BLOCK_SIZE {
        return Err(Error::InvalidBlock(format!(
            "block size {} exceeds maximum {}",
            block_size, MAX_BLOCK_SIZE
        )));
    }

    for (i, tx) in block.transactions.iter().enumerate() {
        let tx_size = estimate_transaction_size(tx);
        if tx_size > MAX_TRANSACTION_SIZE {
            return Err(Error::InvalidBlock(format!(
                "transaction {} size {} exceeds maximum {}",
                i, tx_size, MAX_TRANSACTION_SIZE
            )));
        }
    }

    let now = current_timestamp();
    if (block.header.timestamp as u64) > now + BLOCK_TIMESTAMP_DRIFT_SECS {
        return Err(Error::InvalidBlock(format!(
            "block timestamp {} is too far in future (now: {})",
            block.header.timestamp, now
        )));
    }

    if !block.transactions[0].is_coinbase() {
        return Err(Error::InvalidBlock(
            "first transaction is not coinbase".into(),
        ));
    }

    for tx in &block.transactions[1..] {
        if tx.is_coinbase() {
            return Err(Error::InvalidBlock("non-first coinbase transaction".into()));
        }
    }

    for tx in &block.transactions {
        tx.output_value()?;
    }

    Ok(())
}

fn estimate_block_size(block: &Block) -> usize {
    let header_size = 80;
    let mut total = header_size;

    for tx in &block.transactions {
        total += estimate_transaction_size(tx);
    }

    total
}

fn estimate_transaction_size(tx: &axiom_protocol::Transaction) -> usize {
    let serialized = axiom_protocol::serialize_transaction(tx);
    serialized.len()
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlockHeader;
    use axiom_primitives::{Amount, Hash256};
    use axiom_protocol::{Transaction, TxOutput};

    #[test]
    fn test_validate_empty_block() {
        let header = BlockHeader {
            version: 1,
            prev_block_hash: Hash256::zero(),
            merkle_root: Hash256::zero(),
            timestamp: 0,
            difficulty_target: 0,
            nonce: 0,
        };

        let block = Block {
            header,
            transactions: vec![],
        };

        assert!(validate_block_structure(&block).is_err());
    }

    #[test]
    fn test_validate_valid_block() {
        let header = BlockHeader {
            version: 1,
            prev_block_hash: Hash256::zero(),
            merkle_root: Hash256::zero(),
            timestamp: 0,
            difficulty_target: 0,
            nonce: 0,
        };

        let output = TxOutput {
            value: Amount::from_sat(5_000_000_000).unwrap(),
            pubkey_hash: Hash256::zero(),
        };

        let coinbase = Transaction::new_coinbase(vec![output], 0);

        let block = Block {
            header,
            transactions: vec![coinbase],
        };

        assert!(validate_block_structure(&block).is_ok());
    }

    #[test]
    fn test_max_block_size_constant() {
        assert_eq!(MAX_BLOCK_SIZE, 4_000_000);
    }

    #[test]
    fn test_max_txs_per_block_constant() {
        assert_eq!(MAX_BLOCK_TRANSACTIONS, 10_000);
    }

    #[test]
    fn test_validate_no_coinbase() {
        let header = BlockHeader {
            version: 1,
            prev_block_hash: Hash256::zero(),
            merkle_root: Hash256::zero(),
            timestamp: 0,
            difficulty_target: 0,
            nonce: 0,
        };

        let tx = Transaction::new_transfer(vec![], vec![], 1, 0);

        let block = Block {
            header,
            transactions: vec![tx],
        };

        assert!(validate_block_structure(&block).is_err());
    }
}
