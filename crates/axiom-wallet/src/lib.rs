// Copyright (c) 2026 Kantoshi Miyamura

// Axiom Network wallet. Private keys stay local; only signed transactions
// reach the network.

mod address;
mod builder;
mod error;
mod keypair;
pub mod keystore;
pub mod safety;
pub mod seed;
pub mod signing;
pub mod wallet;

// v2-dev: skeleton-only. Spec: docs/V2_PROTOCOL.md §7. Not consulted by
// the existing keystore, signer, or transaction-builder code paths.
pub mod rotation_v2;

pub use address::Address;
pub use builder::TransactionBuilder;
pub use error::{Result, WalletError};
pub use keypair::KeyPair;
pub use keystore::{
    create_keystore, create_keystore_with_params, export_keystore, import_keystore,
    unlock_keystore, KeystoreFile,
};
pub use safety::{
    validate_address, validate_amount_not_dust, validate_fee_reasonable, validate_password_strength,
};
pub use seed::{derive_account, generate_seed_phrase, recover_wallet_from_seed};
pub use signing::SignatureBackend;
pub use wallet::{
    create_wallet, create_wallet_from_phrase, create_wallet_from_phrase_with_params,
    create_wallet_with_params, save_wallet, save_wallet_with_params, unlock_wallet, WalletSession,
    WalletState,
};

#[cfg(test)]
mod tests;
