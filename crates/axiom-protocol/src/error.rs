// Copyright (c) 2026 Kantoshi Miyamura

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("deserialization error: {0}")]
    Deserialization(String),

    #[error("primitives error: {0}")]
    Primitives(#[from] axiom_primitives::Error),

    #[error("crypto error: {0}")]
    Crypto(#[from] axiom_crypto::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
