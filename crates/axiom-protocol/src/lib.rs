// Copyright (c) 2026 Kantoshi Miyamura

// Protocol structures for Axiom Network: transactions and serialization.

mod error;
mod serialize;
mod transaction;

// v2-dev: skeleton-only. Spec: docs/V2_PROTOCOL.md §5. Not consulted by
// the v1 serialize / validate paths.
pub mod transaction_v2;

pub use error::{Error, Result};
pub use serialize::{
    deserialize_transaction, serialize_transaction, serialize_transaction_unsigned,
};
pub use transaction::{ConfidentialTxOutput, Transaction, TransactionType, TxInput, TxOutput};
