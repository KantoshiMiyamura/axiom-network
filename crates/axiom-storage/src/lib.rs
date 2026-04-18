// Copyright (c) 2026 Kantoshi Miyamura

// Storage layer for Axiom Network. Key layout:
//   0x01 block data, 0x02 tx data, 0x03 UTXO set, 0x04 chain metadata,
//   0x05 nonces, 0x06 chain work, 0x07 block undo, 0x08 tx location index,
//   0x09 address-tx index, 0x0A block header (survives pruning).

mod batch;
mod db;
mod error;
mod keys;
mod nonce;
mod tx_index;
mod undo;
mod utxo;

pub use batch::StorageBatch;
pub use db::Database;
pub use error::{Error, Result};
pub use nonce::NonceTracker;
pub use tx_index::{TxIndex, TxLocation};
pub use undo::{BlockUndo, NonceUndo, UtxoUndo};
pub use utxo::{UtxoEntry, UtxoSet};

pub use axiom_crypto;
