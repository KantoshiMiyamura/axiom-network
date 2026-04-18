// Copyright (c) 2026 Kantoshi Miyamura

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("wallet error: {0}")]
    Wallet(#[from] axiom_wallet::WalletError),

    #[error("invalid seed length: expected 32 or more, got {0}")]
    InvalidSeedLength(usize),

    #[error("seed phrase recovery failed")]
    SeedRecoveryFailed,

    #[error("keypair generation failed")]
    KeypairGenerationFailed,

    #[error("transaction signing failed: {0}")]
    SigningFailed(String),

    #[error("address derivation failed: {0}")]
    AddressDerivationFailed(String),

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("transaction validation failed: {0}")]
    TransactionValidationFailed(String),

    #[error("replay protection violation: {0}")]
    ReplayProtectionViolation(String),

    #[error("fee validation failed: {0}")]
    FeeValidationFailed(String),

    #[error("nonce validation failed: expected {expected}, got {got}")]
    NonceValidationFailed { expected: u64, got: u64 },
}

pub type Result<T> = std::result::Result<T, Error>;
