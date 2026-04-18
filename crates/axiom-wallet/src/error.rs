// Copyright (c) 2026 Kantoshi Miyamura

use thiserror::Error;

pub type Result<T> = std::result::Result<T, WalletError>;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("invalid private key")]
    InvalidPrivateKey,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid address format")]
    InvalidAddress,

    #[error("address checksum mismatch — possible typo")]
    InvalidChecksum,

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },

    #[error("invalid amount: {0}")]
    InvalidAmount(String),

    #[error("amount below dust threshold: {amount} sat (min {min} sat)")]
    DustAmount { amount: u64, min: u64 },

    #[error("fee unreasonably high: {fee} sat on {amount} sat transfer")]
    FeeTooHigh { fee: u64, amount: u64 },

    #[error("invalid nonce")]
    InvalidNonce,

    #[error("transaction builder incomplete: {0}")]
    BuilderIncomplete(String),

    #[error("keystore encryption error: {0}")]
    KeystoreEncryption(String),

    #[error("keystore decryption failed — wrong password or corrupted data")]
    KeystoreDecryption,

    #[error("invalid keystore: {0}")]
    InvalidKeystore(String),

    #[error("invalid seed phrase")]
    InvalidSeedPhrase,

    #[error("wallet is locked — call unlock_keystore() first")]
    WalletLocked,

    #[error("password too weak: {0}")]
    WeakPassword(String),

    #[error("insufficient funds for confidential transaction")]
    InsufficientFunds,

    #[error("{0}")]
    Other(String),

    #[error("crypto error: {0}")]
    Crypto(#[from] axiom_crypto::Error),

    #[error("primitives error: {0}")]
    Primitives(#[from] axiom_primitives::Error),

    #[error("protocol error: {0}")]
    Protocol(#[from] axiom_protocol::Error),
}
