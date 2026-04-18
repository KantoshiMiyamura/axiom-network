// Copyright (c) 2026 Kantoshi Miyamura

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("database error: {0}")]
    Database(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("deserialization error: {0}")]
    Deserialization(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("corruption detected: {0}")]
    Corruption(String),

    #[error("primitives error: {0}")]
    Primitives(#[from] axiom_primitives::Error),

    #[error("protocol error: {0}")]
    Protocol(#[from] axiom_protocol::Error),

    #[error("consensus error: {0}")]
    Consensus(#[from] axiom_consensus::Error),
}

impl From<fjall::Error> for Error {
    fn from(e: fjall::Error) -> Self {
        Error::Database(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
