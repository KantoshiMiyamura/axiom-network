// Copyright (c) 2026 Kantoshi Miyamura

// Storage key namespaces. All keys: [1-byte prefix][data].
//
//   0x01 block data       0x02 tx data         0x03 UTXO set
//   0x04 chain metadata   0x05 nonce tracking  0x06 chain work
//   0x07 block undo       0x08 tx location     0x09 address-tx index
//   0x0A block header     0x0B height index

use axiom_primitives::Hash256;

const PREFIX_BLOCK: u8 = 0x01;
const PREFIX_TX: u8 = 0x02;
const PREFIX_UTXO: u8 = 0x03;
const PREFIX_META: u8 = 0x04;
const PREFIX_NONCE: u8 = 0x05;
const PREFIX_CHAIN_WORK: u8 = 0x06;
const PREFIX_UNDO: u8 = 0x07;
const PREFIX_TX_LOCATION: u8 = 0x08;
const PREFIX_ADDR_TX: u8 = 0x09;
const PREFIX_BLOCK_HEADER: u8 = 0x0A;
// Big-endian u32 so height keys sort numerically.
const PREFIX_HEIGHT_INDEX: u8 = 0x0B;

pub const META_BEST_BLOCK_HASH: &[u8] = b"best_block_hash";
pub const META_BEST_HEIGHT: &[u8] = b"best_height";
pub const META_GENESIS_HASH: &[u8] = b"genesis_hash";

pub fn block_key(block_hash: &Hash256) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(PREFIX_BLOCK);
    key.extend_from_slice(block_hash.as_bytes());
    key
}

pub fn tx_key(txid: &Hash256) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(PREFIX_TX);
    key.extend_from_slice(txid.as_bytes());
    key
}

pub fn utxo_key(txid: &Hash256, output_index: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(37);
    key.push(PREFIX_UTXO);
    key.extend_from_slice(txid.as_bytes());
    key.extend_from_slice(&output_index.to_le_bytes());
    key
}

pub fn meta_key(meta_type: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + meta_type.len());
    key.push(PREFIX_META);
    key.extend_from_slice(meta_type);
    key
}

pub fn nonce_key(pubkey_hash: &Hash256) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(PREFIX_NONCE);
    key.extend_from_slice(pubkey_hash.as_bytes());
    key
}

pub fn chain_work_key(block_hash: &Hash256) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(PREFIX_CHAIN_WORK);
    key.extend_from_slice(block_hash.as_bytes());
    key
}

pub fn undo_key(block_hash: &Hash256) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(PREFIX_UNDO);
    key.extend_from_slice(block_hash.as_bytes());
    key
}

pub fn tx_location_key(txid: &Hash256) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(PREFIX_TX_LOCATION);
    key.extend_from_slice(txid.as_bytes());
    key
}

/// Composite key prefix || pubkey_hash || txid — enables range scan by address.
pub fn addr_tx_key(pubkey_hash: &Hash256, txid: &Hash256) -> Vec<u8> {
    let mut key = Vec::with_capacity(65);
    key.push(PREFIX_ADDR_TX);
    key.extend_from_slice(pubkey_hash.as_bytes());
    key.extend_from_slice(txid.as_bytes());
    key
}

/// Address prefix for scanning all txids for a pubkey_hash.
pub fn addr_tx_prefix(pubkey_hash: &Hash256) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(PREFIX_ADDR_TX);
    key.extend_from_slice(pubkey_hash.as_bytes());
    key
}

/// Block header key — written alongside the full block, survives pruning.
pub fn block_header_key(block_hash: &Hash256) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(PREFIX_BLOCK_HEADER);
    key.extend_from_slice(block_hash.as_bytes());
    key
}

/// Height index key — big-endian so keys sort numerically in range scans.
pub fn height_index_key(height: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(5);
    key.push(PREFIX_HEIGHT_INDEX);
    key.extend_from_slice(&height.to_be_bytes());
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_prefixes_unique() {
        assert_ne!(PREFIX_BLOCK, PREFIX_TX);
        assert_ne!(PREFIX_BLOCK, PREFIX_UTXO);
        assert_ne!(PREFIX_BLOCK, PREFIX_META);
        assert_ne!(PREFIX_BLOCK, PREFIX_NONCE);
        assert_ne!(PREFIX_TX, PREFIX_UTXO);
        assert_ne!(PREFIX_TX, PREFIX_META);
        assert_ne!(PREFIX_TX, PREFIX_NONCE);
        assert_ne!(PREFIX_UTXO, PREFIX_META);
        assert_ne!(PREFIX_UTXO, PREFIX_NONCE);
        assert_ne!(PREFIX_META, PREFIX_NONCE);
    }

    #[test]
    fn test_block_key_format() {
        let hash = Hash256::zero();
        let key = block_key(&hash);
        assert_eq!(key.len(), 33);
        assert_eq!(key[0], PREFIX_BLOCK);
    }

    #[test]
    fn test_utxo_key_format() {
        let hash = Hash256::zero();
        let key = utxo_key(&hash, 0);
        assert_eq!(key.len(), 37);
        assert_eq!(key[0], PREFIX_UTXO);
    }
}
