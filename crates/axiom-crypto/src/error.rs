// Copyright (c) 2026 Kantoshi Miyamura

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("signature verification failed")]
    InvalidSignature,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid private key")]
    InvalidPrivateKey,

    #[error("primitives error: {0}")]
    Primitives(#[from] axiom_primitives::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
