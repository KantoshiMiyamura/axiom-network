//! OS-level key protection via platform credential stores.
//! Windows: DPAPI  |  macOS: Keychain  |  Linux: Secret Service

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

const SERVICE: &str = "axiom-wallet";
const DEVICE_KEY_USER: &str = "device-secret-v1";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

/// Retrieve the device secret from OS keyring. Returned bytes are wrapped in
/// `Zeroizing` so they are erased from memory on drop.
pub fn get_device_secret() -> Option<Zeroizing<Vec<u8>>> {
    let entry = keyring::Entry::new(SERVICE, DEVICE_KEY_USER).ok()?;
    let encoded = Zeroizing::new(entry.get_password().ok()?);
    let bytes = Zeroizing::new(STANDARD.decode(encoded.as_bytes()).ok()?);
    if bytes.len() != KEY_LEN {
        return None;
    }
    Some(bytes)
}

/// Retrieve or create the device secret in the OS keyring.
pub fn get_or_create_device_secret() -> Option<Zeroizing<Vec<u8>>> {
    if let Some(s) = get_device_secret() {
        return Some(s);
    }
    let mut key = Zeroizing::new(vec![0u8; KEY_LEN]);
    rand::rngs::OsRng.fill_bytes(key.as_mut_slice());
    let encoded = Zeroizing::new(STANDARD.encode(key.as_slice()));
    let entry = keyring::Entry::new(SERVICE, DEVICE_KEY_USER).ok()?;
    entry.set_password(encoded.as_str()).ok()?;
    Some(key)
}

/// Delete device secret from OS keyring.
pub fn delete_device_secret() -> bool {
    keyring::Entry::new(SERVICE, DEVICE_KEY_USER)
        .and_then(|e| e.delete_password())
        .is_ok()
}

/// Derive a purpose-specific sub-key via HKDF-SHA256.
fn derive_subkey(secret: &[u8], purpose: &[u8]) -> Zeroizing<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut out = Zeroizing::new(vec![0u8; 32]);
    hk.expand(purpose, out.as_mut_slice())
        .expect("HKDF-SHA256 expand to 32 bytes");
    out
}

/// Encrypt data with a device-derived key. Returns `nonce(24) || ciphertext`.
pub fn seal(data: &[u8], device_secret: &[u8], purpose: &[u8]) -> Option<Vec<u8>> {
    let key = derive_subkey(device_secret, purpose);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).ok()?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, data).ok()?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Some(out)
}

/// Decrypt data sealed with `seal()`.
pub fn unseal(blob: &[u8], device_secret: &[u8], purpose: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < NONCE_LEN + 16 {
        return None;
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    let nonce = XNonce::from_slice(nonce_bytes);
    let key = derive_subkey(device_secret, purpose);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).ok()?;
    cipher.decrypt(nonce, ct).ok()
}
