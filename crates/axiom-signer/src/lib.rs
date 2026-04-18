// Copyright (c) 2026 Kantoshi Miyamura
//
// Axiom Network Local Transaction Signer
//
// This crate provides secure local signing of transactions without exposing
// private keys to the network or RPC layer. Private keys are derived from
// encrypted seed phrases and used only in memory for signing, then discarded.
//
// Architecture:
// - Python wallet decrypts seed → passes to Rust signer
// - Rust signer derives keys locally → signs transactions → returns signature only
// - RPC receives only signed transactions (no private keys)
// - All keys zeroized after use

pub mod error;
pub mod signer;

pub use error::{Error, Result};
pub use signer::LocalSigner;

/// Axiom Signer Version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
