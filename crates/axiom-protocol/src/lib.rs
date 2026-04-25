// Copyright (c) 2026 Kantoshi Miyamura

// Protocol structures for Axiom Network: transactions and serialization.

mod error;
mod serialize;
mod transaction;

pub use error::{Error, Result};
pub use serialize::{
    deserialize_transaction, serialize_transaction, serialize_transaction_unsigned,
};
pub use transaction::{ConfidentialTxOutput, Transaction, TransactionType, TxInput, TxOutput};
