// Copyright (c) 2026 Kantoshi Miyamura
//
// LocalSigner: Transaction signing without exposing private keys
//
// This module provides secure transaction signing:
// 1. Keys are derived from encrypted seed phrases
// 2. Keys exist only in memory during signing
// 3. Keys are automatically zeroized after use
// 4. Only signed transactions leave this process
// 5. Private key material NEVER transmitted to RPC

use crate::error::{Error, Result};
use axiom_primitives::SecretSigningKey;
use axiom_wallet::KeyPair;

/// Local transaction signer.
///
/// This type manages the secure signing of transactions without exposing
/// private key material to the network or RPC layer.
///
/// Private keys are:
/// - Derived from encrypted seed phrases (passed by caller)
/// - Stored only in memory (overwritten on drop via KeyPair's Drop impl)
/// - Used only for signing operations
/// - NEVER transmitted to RPC
/// - NEVER logged or printed
/// - NEVER cloned or copied
pub struct LocalSigner {
    /// The keypair used for signing.
    /// Stored as Option to handle initialization failures gracefully.
    /// Keypair's Drop impl ensures key material is zeroized.
    keypair: Option<KeyPair>,
}

impl LocalSigner {
    /// Create a new LocalSigner from an encrypted seed phrase.
    ///
    /// This function:
    /// 1. Takes an encrypted seed (from disk)
    /// 2. Decrypts it using the provided password
    /// 3. Derives a keypair locally
    /// 4. Stores the keypair in Zeroizing memory
    /// 5. Does NOT persist anything to disk
    ///
    /// # Arguments
    /// * `encrypted_seed` - Encrypted seed phrase bytes
    /// * `password` - Password for decryption
    ///
    /// Create a LocalSigner from raw seed bytes.
    ///
    /// # Arguments
    /// * `seed_bytes` - Raw seed bytes (32+ bytes)
    ///
    /// # Returns
    /// A LocalSigner instance
    pub fn from_seed_bytes(seed_bytes: &[u8]) -> Result<Self> {
        if seed_bytes.len() < 32 {
            return Err(Error::InvalidSeedLength(seed_bytes.len()));
        }

        // Create a SecretSigningKey from the seed
        let secret_key = SecretSigningKey::from_seed(&seed_bytes[..32])
            .map_err(|e| Error::SigningFailed(e.to_string()))?;

        // Derive keypair from the seed
        let keypair = KeyPair::from_private_key(secret_key.as_bytes().to_vec())
            .map_err(|_| Error::KeypairGenerationFailed)?;

        Ok(LocalSigner {
            keypair: Some(keypair),
        })
    }

    /// Get the public address (derived from public key).
    ///
    /// This operation is purely local and requires no network access.
    ///
    /// # Returns
    /// The address derived from the public key
    pub fn address(&self) -> Result<String> {
        let keypair = self
            .keypair
            .as_ref()
            .ok_or(Error::KeypairGenerationFailed)?;

        let pubkey_hash = keypair.public_key_hash();
        let address = axiom_wallet::Address::from_pubkey_hash(pubkey_hash);
        Ok(address.to_string())
    }

    /// Get the public key bytes.
    ///
    /// The public key is safe to transmit and log.
    /// It is NOT sensitive information.
    ///
    /// # Returns
    /// The public key as a slice (2592 bytes for ML-DSA-87)
    pub fn public_key(&self) -> Result<&[u8]> {
        let keypair = self
            .keypair
            .as_ref()
            .ok_or(Error::KeypairGenerationFailed)?;

        Ok(keypair.public_key())
    }

    /// Sign a transaction locally.
    ///
    /// This function:
    /// 1. Takes an unsigned transaction
    /// 2. Signs it using the local keypair
    /// 3. Returns only the signature bytes
    /// 4. DOES NOT expose the private key
    ///
    /// # Arguments
    /// * `transaction_hash` - Hash of the unsigned transaction to sign
    ///
    /// # Returns
    /// The signature bytes (4627 bytes for ML-DSA-87)
    ///
    /// # Security
    /// - The transaction hash is signed locally
    /// - The private key NEVER leaves this function
    /// - The private key NEVER is transmitted to the caller
    /// - The signature can be verified using the public key
    pub fn sign_transaction(&self, transaction_hash: &[u8]) -> Result<Vec<u8>> {
        let keypair = self
            .keypair
            .as_ref()
            .ok_or(Error::KeypairGenerationFailed)?;

        keypair
            .sign(transaction_hash)
            .map_err(|e| Error::SigningFailed(e.to_string()))
    }

    /// Verify a signature locally.
    ///
    /// This function:
    /// 1. Takes a signature and a transaction hash
    /// 2. Verifies the signature using the local public key
    /// 3. Returns Ok(()) if valid, Err if invalid
    ///
    /// # Arguments
    /// * `transaction_hash` - Hash of the transaction
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    /// Ok(()) if the signature is valid, Error otherwise
    pub fn verify_signature(&self, transaction_hash: &[u8], signature: &[u8]) -> Result<()> {
        let keypair = self
            .keypair
            .as_ref()
            .ok_or(Error::KeypairGenerationFailed)?;

        match keypair.verify(transaction_hash, signature) {
            Ok(true) => Ok(()),
            Ok(false) => Err(Error::SigningFailed(
                "Signature verification failed".to_string(),
            )),
            Err(e) => Err(Error::SigningFailed(format!(
                "Signature verification failed: {}",
                e
            ))),
        }
    }

    /// Validate replay protection parameters.
    ///
    /// This function checks that a transaction is not a replay:
    /// - chain_id matches the current network
    /// - tx_version is valid for this chain
    /// - nonce is correct (no double-spend)
    ///
    /// # Arguments
    /// * `chain_id` - The network identifier (e.g., "axiom-mainnet-1")
    /// * `tx_version` - The transaction version
    /// * `nonce` - The transaction nonce
    /// * `expected_nonce` - The expected nonce for this account
    ///
    /// # Returns
    /// Ok(()) if replay protection passes, Error otherwise
    pub fn validate_replay_protection(
        &self,
        chain_id: &str,
        tx_version: u32,
        nonce: u64,
        expected_nonce: u64,
    ) -> Result<()> {
        // Verify chain_id
        if chain_id != "axiom-mainnet-1" && !chain_id.starts_with("axiom-testnet-") {
            return Err(Error::ReplayProtectionViolation(format!(
                "Invalid chain_id: {}",
                chain_id
            )));
        }

        // Verify tx_version is current
        if tx_version != 1 {
            return Err(Error::ReplayProtectionViolation(format!(
                "Invalid tx_version: {}",
                tx_version
            )));
        }

        // Verify nonce
        if nonce != expected_nonce {
            return Err(Error::NonceValidationFailed {
                expected: expected_nonce,
                got: nonce,
            });
        }

        Ok(())
    }

    /// Validate transaction fees.
    ///
    /// This function checks that fees are reasonable:
    /// - Not dust (too low)
    /// - Not excessive (too high)
    /// - Calculated correctly for the transaction size
    ///
    /// # Arguments
    /// * `fee_amount` - The total fee in satoshis
    /// * `tx_size_bytes` - The transaction size in bytes
    ///
    /// # Returns
    /// Ok(()) if fees are valid, Error otherwise
    pub fn validate_fee(&self, fee_amount: u64, tx_size_bytes: usize) -> Result<()> {
        const MIN_FEE_RATE: u64 = 1; // satoshis per byte
        const MAX_FEE_RATE: u64 = 1000; // satoshis per byte

        if tx_size_bytes == 0 {
            return Err(Error::FeeValidationFailed(
                "Transaction size must be > 0".to_string(),
            ));
        }

        let fee_rate = fee_amount / tx_size_bytes as u64;

        if fee_rate < MIN_FEE_RATE {
            return Err(Error::FeeValidationFailed(format!(
                "Fee too low: {} sat/byte (minimum: {} sat/byte)",
                fee_rate, MIN_FEE_RATE
            )));
        }

        if fee_rate > MAX_FEE_RATE {
            return Err(Error::FeeValidationFailed(format!(
                "Fee too high: {} sat/byte (maximum: {} sat/byte)",
                fee_rate, MAX_FEE_RATE
            )));
        }

        Ok(())
    }
}

impl Drop for LocalSigner {
    /// Zeroize all key material when dropped.
    ///
    /// The KeyPair's Drop impl will ensure all keys are overwritten
    /// with zeros before the memory is freed.
    fn drop(&mut self) {
        // Explicit drop of Option<KeyPair> will trigger KeyPair's Drop impl,
        // which zeroizes the private key material via Zeroizing<Vec<u8>>
        // in the axiom_wallet crate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_from_seed_bytes() {
        let seed = vec![0x42u8; 32];
        let signer = LocalSigner::from_seed_bytes(&seed);
        assert!(signer.is_ok());
    }

    #[test]
    fn test_signer_rejects_short_seed() {
        let seed = vec![0x42u8; 16]; // Too short
        let signer = LocalSigner::from_seed_bytes(&seed);
        assert!(signer.is_err());
    }

    #[test]
    fn test_replay_protection_validation() {
        let seed = vec![0x42u8; 32];
        let signer = LocalSigner::from_seed_bytes(&seed).unwrap();

        // Valid mainnet
        assert!(signer
            .validate_replay_protection("axiom-mainnet-1", 1, 100, 100)
            .is_ok());

        // Valid testnet
        assert!(signer
            .validate_replay_protection("axiom-testnet-1", 1, 50, 50)
            .is_ok());

        // Invalid chain_id
        assert!(signer
            .validate_replay_protection("axiom-invalid", 1, 100, 100)
            .is_err());

        // Invalid tx_version
        assert!(signer
            .validate_replay_protection("axiom-mainnet-1", 2, 100, 100)
            .is_err());

        // Invalid nonce
        assert!(signer
            .validate_replay_protection("axiom-mainnet-1", 1, 99, 100)
            .is_err());
    }

    #[test]
    fn test_fee_validation() {
        let seed = vec![0x42u8; 32];
        let signer = LocalSigner::from_seed_bytes(&seed).unwrap();

        // Valid fee (10 sat/byte for 100 byte tx)
        assert!(signer.validate_fee(1000, 100).is_ok());

        // Too low fee (0.5 sat/byte)
        assert!(signer.validate_fee(50, 100).is_err());

        // Too high fee (2000 sat/byte)
        assert!(signer.validate_fee(200_000, 100).is_err());

        // Zero size transaction
        assert!(signer.validate_fee(1000, 0).is_err());
    }

    #[test]
    fn test_address_derivation_consistency() {
        // Same seed should produce same address every time
        let seed = vec![0x42u8; 32];

        let signer1 = LocalSigner::from_seed_bytes(&seed).unwrap();
        let addr1 = signer1.address().unwrap();

        let signer2 = LocalSigner::from_seed_bytes(&seed).unwrap();
        let addr2 = signer2.address().unwrap();

        assert_eq!(addr1, addr2, "Same seed should produce same address");
    }

    #[test]
    fn test_signer_accepts_all_zeros_seed() {
        // All-zero seed should be valid (but not recommended)
        let seed = vec![0x00u8; 32];
        let signer = LocalSigner::from_seed_bytes(&seed);
        assert!(signer.is_ok(), "All-zero seed should be accepted");
    }

    #[test]
    fn test_signer_accepts_all_ones_seed() {
        // All-ones seed should be valid
        let seed = vec![0xFFu8; 32];
        let signer = LocalSigner::from_seed_bytes(&seed);
        assert!(signer.is_ok(), "All-ones seed should be accepted");
    }

    #[test]
    fn test_signature_generation() {
        // Verify that signing works without panicking
        let seed = vec![0x42u8; 32];
        let signer = LocalSigner::from_seed_bytes(&seed).unwrap();

        let tx_hash = vec![0x00u8; 32];
        let signature = signer.sign_transaction(&tx_hash);
        assert!(signature.is_ok(), "Signing should succeed");

        // ML-DSA-87 signature should be 4627 bytes
        let sig = signature.unwrap();
        assert_eq!(sig.len(), 4627, "ML-DSA-87 signature should be 4627 bytes");
    }

    #[test]
    fn test_address_format() {
        // Address should start with "axm"
        let seed = vec![0x42u8; 32];
        let signer = LocalSigner::from_seed_bytes(&seed).unwrap();
        let addr = signer.address().unwrap();

        assert!(addr.starts_with("axm"), "Address should start with 'axm'");
        assert!(addr.len() > 10, "Address should be reasonably long");
    }

    #[test]
    fn test_chain_validation_specific_networks() {
        let seed = vec![0x42u8; 32];
        let signer = LocalSigner::from_seed_bytes(&seed).unwrap();

        // Valid networks
        assert!(signer
            .validate_replay_protection("axiom-mainnet-1", 1, 0, 0)
            .is_ok());
        assert!(signer
            .validate_replay_protection("axiom-testnet-1", 1, 0, 0)
            .is_ok());

        // Invalid networks
        assert!(signer
            .validate_replay_protection("bitcoin-mainnet", 1, 0, 0)
            .is_err());
        assert!(signer
            .validate_replay_protection("ethereum-mainnet", 1, 0, 0)
            .is_err());
    }
}
