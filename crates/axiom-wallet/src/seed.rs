// Copyright (c) 2026 Kantoshi Miyamura

// BIP39 seed, HKDF per account index.
//
// Master seed: 24-word BIP39 mnemonic, PBKDF2-HMAC-SHA512, empty passphrase, 64 bytes.
// Account derivation: HKDF-SHA512(ikm=master_seed, info="axiom-network:wallet:v1:account:{index}").
// First 32 bytes of output used as ML-DSA-87 xi seed. Not BIP32-compatible.

use bip39::Mnemonic;
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::keypair::KeyPair;
use crate::signing::{MlDsa87Backend, SignatureBackend};
use crate::{Result, WalletError};

const AXIOM_DOMAIN: &str = "axiom-network:wallet:v1";

/// Generate a 24-word BIP39 mnemonic from OS entropy.
/// Returns `(phrase_string, master_seed)`. The phrase is the only recovery key.
pub fn generate_seed_phrase() -> (String, Zeroizing<Vec<u8>>) {
    use rand::RngCore;
    // SECURITY: Entropy wrapped in Zeroizing so it is scrubbed from the stack on drop.
    let mut entropy = Zeroizing::new([0u8; 32]); // 256-bit -> 24 words
    rand::rngs::OsRng.fill_bytes(entropy.as_mut());
    let mnemonic = Mnemonic::from_entropy(entropy.as_ref()).expect("32 bytes is valid BIP39 entropy");
    let seed = Zeroizing::new(mnemonic.to_seed("").to_vec());
    (mnemonic.to_string(), seed)
}

/// Derive the 64-byte master seed from a BIP39 phrase.
pub fn recover_wallet_from_seed(phrase: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mnemonic: Mnemonic = phrase.parse().map_err(|_| WalletError::InvalidSeedPhrase)?;
    Ok(Zeroizing::new(mnemonic.to_seed("").to_vec()))
}

/// Derive the keypair for account `index` from `master_seed`.
/// HKDF info = "axiom-network:wallet:v1:account:{index}". Deterministic.
pub fn derive_account(master_seed: &[u8], index: u32) -> Result<KeyPair> {
    let hk = Hkdf::<Sha512>::new(None, master_seed);
    let info = format!("{}:account:{}", AXIOM_DOMAIN, index);
    let mut okm = Zeroizing::new([0u8; 64]);
    hk.expand(info.as_bytes(), okm.as_mut())
        .map_err(|_| WalletError::InvalidSeedPhrase)?;
    let (priv_key, pub_key): (zeroize::Zeroizing<Vec<u8>>, Vec<u8>) = MlDsa87Backend.keypair_from_seed(&okm[..32])?;
    KeyPair::from_key_bytes_zeroized(priv_key, pub_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_phrase_is_24_words() {
        let (phrase, _seed) = generate_seed_phrase();
        assert_eq!(phrase.split_whitespace().count(), 24);
    }

    #[test]
    fn seed_recovery_roundtrip() {
        let (phrase, original_seed) = generate_seed_phrase();
        let recovered_seed = recover_wallet_from_seed(&phrase).unwrap();
        assert_eq!(*original_seed, *recovered_seed);
    }

    #[test]
    fn invalid_phrase_rejected() {
        assert!(matches!(
            recover_wallet_from_seed("abandon abandon abandon").unwrap_err(),
            WalletError::InvalidSeedPhrase
        ));
    }

    #[test]
    fn deterministic_account_derivation() {
        let (phrase, _) = generate_seed_phrase();
        let seed = recover_wallet_from_seed(&phrase).unwrap();
        let kp1 = derive_account(&seed, 0).unwrap();
        let kp2 = derive_account(&seed, 0).unwrap();
        assert_eq!(kp1.public_key(), kp2.public_key());
        assert_eq!(kp1.export_private_key(), kp2.export_private_key());
    }

    #[test]
    fn different_indices_produce_different_keys() {
        let (_, seed) = generate_seed_phrase();
        let kp0 = derive_account(&seed, 0).unwrap();
        let kp1 = derive_account(&seed, 1).unwrap();
        assert_ne!(kp0.public_key(), kp1.public_key());
    }

    #[test]
    fn different_seeds_produce_different_keys() {
        let (_, seed1) = generate_seed_phrase();
        let (_, seed2) = generate_seed_phrase();
        let kp1 = derive_account(&seed1, 0).unwrap();
        let kp2 = derive_account(&seed2, 0).unwrap();
        assert_ne!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn derived_keypair_can_sign() {
        let (_, seed) = generate_seed_phrase();
        let kp = derive_account(&seed, 0).unwrap();
        let msg = b"test axiom tx";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
    }
}
