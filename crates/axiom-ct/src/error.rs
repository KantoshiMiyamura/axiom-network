// Copyright (c) 2026 Kantoshi Miyamura

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CtError {
    #[error("range proof verification failed")]
    RangeProofInvalid,

    #[error("balance check failed: input commitments do not equal output commitments + fee")]
    BalanceCheckFailed,

    #[error("value {0} is out of range (must be 0..2^64)")]
    ValueOutOfRange(u128),

    #[error("commitment deserialization failed")]
    DeserializationFailed,

    #[error("range proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("empty input: cannot create proof for zero outputs")]
    EmptyOutputs,

    #[error("too many outputs: maximum {max}, got {count}")]
    TooManyOutputs { max: usize, count: usize },
}

pub type Result<T> = std::result::Result<T, CtError>;
