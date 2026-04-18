// Copyright (c) 2026 Kantoshi Miyamura

use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("arithmetic overflow")]
    Overflow,

    #[error("arithmetic underflow")]
    Underflow,

    #[error("invalid amount: {0}")]
    InvalidAmount(String),

    #[error("invalid hash length: expected 32, got {0}")]
    InvalidHashLength(usize),

    #[error("invalid public key length: expected 2592, got {0}")]
    InvalidPublicKeyLength(usize),

    #[error("invalid private key length: expected 32, got {0}")]
    InvalidPrivateKeyLength(usize),

    #[error("invalid signature length: expected 4627, got {0}")]
    InvalidSignatureLength(usize),
}

pub type Result<T> = std::result::Result<T, Error>;
