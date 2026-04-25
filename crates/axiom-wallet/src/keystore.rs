// Copyright (c) 2026 Kantoshi Miyamura

// Argon2id-derived key, XChaCha20-Poly1305 encrypted. Auth tag catches wrong
// password and corruption. Exported as self-contained JSON; never contains
// plaintext key material.

use crate::{Result, WalletError};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const KEYSTORE_VERSION: u32 = 1;
pub const ARGON2_M_COST: u32 = 65536;
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 4;
const ARGON2_HASH_LEN: usize = 32;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 24;

// Hostile-input bounds applied when decoding a foreign keystore. These bracket
// *any reasonable legitimate keystore* while rejecting malicious payloads that
// would OOM the process or spin Argon2 for hours.
//
// Legitimate production values: m=65_536 KiB, t=3, p=4. Legitimate test values:
// m=8, t=1, p=1. The bounds below accept both while rejecting adversarial
// u32::MAX-style inputs.
const KDF_MIN_M_COST: u32 = 8; // 8 KiB  — Argon2 minimum
const KDF_MAX_M_COST: u32 = 1_048_576; // 1 GiB  — upper bound for a wallet unlock
const KDF_MIN_T_COST: u32 = 1;
const KDF_MAX_T_COST: u32 = 100; // anything higher is almost certainly an attack
const KDF_MIN_P_COST: u32 = 1;
const KDF_MAX_P_COST: u32 = 16;
const KDF_MIN_SALT_LEN: usize = 8; // Argon2 spec minimum
const KDF_MAX_SALT_LEN: usize = 64;
// ML-DSA-87 private-key seed is 32 bytes; full secret key encoding is ~4.6 KiB.
// A 64 KiB ceiling leaves plenty of headroom for any legitimate wallet payload
// while rejecting gigabyte-scale adversarial ciphertext blobs.
const MAX_CIPHERTEXT_LEN: usize = 65_536;
// Bound the JSON input itself. 128 KiB is ~20x the biggest legitimate keystore.
const MAX_KEYSTORE_JSON_LEN: usize = 131_072;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreFile {
    pub version: u32,
    pub id: String,
    pub created_at: u64,
    pub kdf: KdfParams,
    pub cipher: CipherParams,
    pub ciphertext_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String,
    pub salt_hex: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    pub algorithm: String,
    pub nonce_hex: String,
}

/// Reject KDF parameters that are outside any plausible legitimate range.
///
/// Bitcoin Core-style principle: never trust inputs from disk or the network.
/// A malicious keystore with `m_cost = u32::MAX` would OOM the process during
/// unlock; `t_cost = u32::MAX` would spin forever. Validate before we dispatch
/// to Argon2.
fn validate_kdf_params(kdf: &KdfParams) -> Result<Vec<u8>> {
    if !(KDF_MIN_M_COST..=KDF_MAX_M_COST).contains(&kdf.m_cost) {
        return Err(WalletError::InvalidKeystore(format!(
            "KDF m_cost out of range: {} (allowed {}..={})",
            kdf.m_cost, KDF_MIN_M_COST, KDF_MAX_M_COST
        )));
    }
    if !(KDF_MIN_T_COST..=KDF_MAX_T_COST).contains(&kdf.t_cost) {
        return Err(WalletError::InvalidKeystore(format!(
            "KDF t_cost out of range: {} (allowed {}..={})",
            kdf.t_cost, KDF_MIN_T_COST, KDF_MAX_T_COST
        )));
    }
    if !(KDF_MIN_P_COST..=KDF_MAX_P_COST).contains(&kdf.p_cost) {
        return Err(WalletError::InvalidKeystore(format!(
            "KDF p_cost out of range: {} (allowed {}..={})",
            kdf.p_cost, KDF_MIN_P_COST, KDF_MAX_P_COST
        )));
    }
    let salt = hex::decode(&kdf.salt_hex)
        .map_err(|_| WalletError::InvalidKeystore("bad salt hex".into()))?;
    if !(KDF_MIN_SALT_LEN..=KDF_MAX_SALT_LEN).contains(&salt.len()) {
        return Err(WalletError::InvalidKeystore(format!(
            "salt length out of range: {} (allowed {}..={})",
            salt.len(),
            KDF_MIN_SALT_LEN,
            KDF_MAX_SALT_LEN
        )));
    }
    Ok(salt)
}

fn derive_key(password: &str, kdf: &KdfParams) -> Result<Zeroizing<[u8; ARGON2_HASH_LEN]>> {
    let salt = validate_kdf_params(kdf)?;
    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(ARGON2_HASH_LEN))
        .map_err(|e| WalletError::KeystoreEncryption(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; ARGON2_HASH_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), &salt, key.as_mut())
        .map_err(|e| WalletError::KeystoreEncryption(e.to_string()))?;
    Ok(key)
}

fn random_id() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    format!(
        "{}-{}-{}-{}-{}",
        hex::encode(&b[0..4]),
        hex::encode(&b[4..6]),
        hex::encode(&b[6..8]),
        hex::encode(&b[8..10]),
        hex::encode(&b[10..16])
    )
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Encrypt `plaintext` with production Argon2id parameters (m=64 MiB, t=3, p=4).
pub fn create_keystore(plaintext: &[u8], password: &str) -> Result<KeystoreFile> {
    create_keystore_with_params(
        plaintext,
        password,
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
    )
}

/// Encrypt `plaintext` with explicit Argon2id parameters.
/// Use low values (m=8, t=1, p=1) in tests to keep suite fast.
pub fn create_keystore_with_params(
    plaintext: &[u8],
    password: &str,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<KeystoreFile> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);
    let kdf = KdfParams {
        algorithm: "argon2id".into(),
        salt_hex: hex::encode(salt),
        m_cost,
        t_cost,
        p_cost,
    };
    let key_bytes = derive_key(password, &kdf)?;
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key_bytes.as_ref()));
    let nonce = chacha20poly1305::XNonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| WalletError::KeystoreEncryption(e.to_string()))?;
    Ok(KeystoreFile {
        version: KEYSTORE_VERSION,
        id: random_id(),
        created_at: now_secs(),
        kdf,
        cipher: CipherParams {
            algorithm: "xchacha20-poly1305".into(),
            nonce_hex: hex::encode(nonce_bytes),
        },
        ciphertext_hex: hex::encode(ciphertext),
    })
}

/// Decrypt `keystore` with `password`. Returns `Err(KeystoreDecryption)` on wrong password or corruption.
pub fn unlock_keystore(keystore: &KeystoreFile, password: &str) -> Result<Zeroizing<Vec<u8>>> {
    if keystore.version != KEYSTORE_VERSION {
        return Err(WalletError::InvalidKeystore(format!(
            "unsupported keystore version: {}",
            keystore.version
        )));
    }
    if keystore.kdf.algorithm != "argon2id" {
        return Err(WalletError::InvalidKeystore(format!(
            "unsupported KDF: {}",
            keystore.kdf.algorithm
        )));
    }
    if keystore.cipher.algorithm != "xchacha20-poly1305" {
        return Err(WalletError::InvalidKeystore(format!(
            "unsupported cipher: {}",
            keystore.cipher.algorithm
        )));
    }
    let key_bytes = derive_key(password, &keystore.kdf)?;
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key_bytes.as_ref()));
    let nonce_bytes = hex::decode(&keystore.cipher.nonce_hex)
        .map_err(|_| WalletError::InvalidKeystore("bad nonce hex".into()))?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(WalletError::InvalidKeystore("nonce length mismatch".into()));
    }
    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(&nonce_bytes);
    let nonce = chacha20poly1305::XNonce::from(nonce_arr);
    // Bound ciphertext length *before* hex-decoding so a malicious 2 GB hex
    // string cannot force a multi-GB allocation. Each hex byte is 2 chars.
    if keystore.ciphertext_hex.len() > MAX_CIPHERTEXT_LEN * 2 {
        return Err(WalletError::InvalidKeystore(format!(
            "ciphertext exceeds {} bytes",
            MAX_CIPHERTEXT_LEN
        )));
    }
    let ciphertext = hex::decode(&keystore.ciphertext_hex)
        .map_err(|_| WalletError::InvalidKeystore("bad ciphertext hex".into()))?;
    if ciphertext.len() > MAX_CIPHERTEXT_LEN {
        return Err(WalletError::InvalidKeystore(format!(
            "ciphertext exceeds {} bytes",
            MAX_CIPHERTEXT_LEN
        )));
    }
    let plaintext = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|_| WalletError::KeystoreDecryption)?;
    Ok(Zeroizing::new(plaintext))
}

/// Serialize keystore to pretty-printed JSON (safe to write to disk).
pub fn export_keystore(keystore: &KeystoreFile) -> Result<String> {
    serde_json::to_string_pretty(keystore)
        .map_err(|e| WalletError::KeystoreEncryption(e.to_string()))
}

/// Deserialize keystore from JSON. Rejects over-sized payloads up-front.
///
/// Cap the input length *before* handing to serde_json so a hostile 1 GB blob
/// cannot force the parser to allocate its way through the whole thing.
pub fn import_keystore(json: &str) -> Result<KeystoreFile> {
    if json.len() > MAX_KEYSTORE_JSON_LEN {
        return Err(WalletError::InvalidKeystore(format!(
            "keystore JSON exceeds {} bytes",
            MAX_KEYSTORE_JSON_LEN
        )));
    }
    serde_json::from_str(json).map_err(|e| WalletError::InvalidKeystore(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast(secret: &[u8], pwd: &str) -> KeystoreFile {
        create_keystore_with_params(secret, pwd, 8, 1, 1).unwrap()
    }

    #[test]
    fn roundtrip() {
        let secret = b"super secret private key bytes32";
        let ks = fast(secret, "password123");
        assert_eq!(
            unlock_keystore(&ks, "password123").unwrap().as_slice(),
            secret
        );
    }

    #[test]
    fn wrong_password_rejected() {
        let ks = fast(b"secret", "correct");
        assert!(matches!(
            unlock_keystore(&ks, "wrong").unwrap_err(),
            WalletError::KeystoreDecryption
        ));
    }

    #[test]
    fn corrupted_ciphertext_rejected() {
        let mut ks = fast(b"secret", "pw");
        let mut hex = ks.ciphertext_hex.clone();
        let last = hex.pop().unwrap();
        hex.push(if last == 'a' { 'b' } else { 'a' });
        ks.ciphertext_hex = hex;
        assert!(matches!(
            unlock_keystore(&ks, "pw").unwrap_err(),
            WalletError::KeystoreDecryption
        ));
    }

    #[test]
    fn export_import_roundtrip() {
        let ks = fast(b"seed bytes here seed bytes here!", "pass");
        let json = export_keystore(&ks).unwrap();
        assert!(!json.contains("seed bytes here"));
        let dec = unlock_keystore(&import_keystore(&json).unwrap(), "pass").unwrap();
        assert_eq!(dec.as_slice(), b"seed bytes here seed bytes here!");
    }

    #[test]
    fn wrong_version_rejected() {
        let mut ks = fast(b"x", "pw");
        ks.version = 99;
        assert!(matches!(
            unlock_keystore(&ks, "pw").unwrap_err(),
            WalletError::InvalidKeystore(_)
        ));
    }

    #[test]
    fn export_contains_no_plaintext() {
        let secret = b"private_key_must_not_appear_here";
        let ks = fast(secret, "pw");
        let json = export_keystore(&ks).unwrap();
        assert!(!json.contains(std::str::from_utf8(secret).unwrap()));
    }

    #[test]
    fn unique_ids_and_salts() {
        let ks1 = fast(b"x", "pw");
        let ks2 = fast(b"x", "pw");
        assert_ne!(ks1.id, ks2.id);
        assert_ne!(ks1.kdf.salt_hex, ks2.kdf.salt_hex);
    }

    // ── Hostile-input hardening tests ──

    #[test]
    fn reject_absurd_m_cost() {
        let mut ks = fast(b"x", "pw");
        ks.kdf.m_cost = u32::MAX;
        assert!(matches!(
            unlock_keystore(&ks, "pw").unwrap_err(),
            WalletError::InvalidKeystore(_)
        ));
    }

    #[test]
    fn reject_absurd_t_cost() {
        let mut ks = fast(b"x", "pw");
        ks.kdf.t_cost = 100_000;
        assert!(matches!(
            unlock_keystore(&ks, "pw").unwrap_err(),
            WalletError::InvalidKeystore(_)
        ));
    }

    #[test]
    fn reject_zero_m_cost() {
        let mut ks = fast(b"x", "pw");
        ks.kdf.m_cost = 0;
        assert!(matches!(
            unlock_keystore(&ks, "pw").unwrap_err(),
            WalletError::InvalidKeystore(_)
        ));
    }

    #[test]
    fn reject_short_salt() {
        let mut ks = fast(b"x", "pw");
        ks.kdf.salt_hex = "00".into(); // 1-byte salt
        assert!(matches!(
            unlock_keystore(&ks, "pw").unwrap_err(),
            WalletError::InvalidKeystore(_)
        ));
    }

    #[test]
    fn reject_huge_salt() {
        let mut ks = fast(b"x", "pw");
        ks.kdf.salt_hex = hex::encode(vec![0u8; 1024]); // 1 KiB
        assert!(matches!(
            unlock_keystore(&ks, "pw").unwrap_err(),
            WalletError::InvalidKeystore(_)
        ));
    }

    #[test]
    fn reject_huge_ciphertext() {
        let mut ks = fast(b"x", "pw");
        // 128 KiB of ciphertext bytes → 256 KiB of hex.
        ks.ciphertext_hex = hex::encode(vec![0u8; MAX_CIPHERTEXT_LEN + 1]);
        assert!(matches!(
            unlock_keystore(&ks, "pw").unwrap_err(),
            WalletError::InvalidKeystore(_)
        ));
    }

    #[test]
    fn reject_oversize_json_in_import() {
        // Craft a JSON string larger than the import bound.
        let huge = "a".repeat(MAX_KEYSTORE_JSON_LEN + 1);
        assert!(matches!(
            import_keystore(&huge).unwrap_err(),
            WalletError::InvalidKeystore(_)
        ));
    }

    #[test]
    fn legitimate_keystore_still_accepted() {
        // Sanity check: nothing about the hardening breaks the normal flow.
        let ks = fast(b"a legitimate private key seed 32", "good-password");
        let pt = unlock_keystore(&ks, "good-password").unwrap();
        assert_eq!(pt.as_slice(), b"a legitimate private key seed 32");
    }
}
