// Copyright (c) 2026 Kantoshi Miyamura

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid block: {0}")]
    InvalidBlock(String),

    #[error("invalid block header: {0}")]
    InvalidBlockHeader(String),

    #[error("primitives error: {0}")]
    Primitives(#[from] axiom_primitives::Error),

    #[error("protocol error: {0}")]
    Protocol(#[from] axiom_protocol::Error),

    #[error("crypto error: {0}")]
    Crypto(#[from] axiom_crypto::Error),

    /// A consensus invariant was violated (value conservation, supply, etc.).
    /// Carried verbatim so the caller can emit the exact invariant name that failed.
    #[error("consensus invariant violation: {0}")]
    InvariantViolation(String),
}

pub type Result<T> = std::result::Result<T, Error>;
