// Copyright (c) 2026 Kantoshi Miyamura

// HD wallet: master seed encrypted in a keystore, accounts derived sequentially
// via HKDF. Account counter persists inside the encrypted blob.
// Gap-limit scanning after recovery is the caller's responsibility.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    address::Address,
    keypair::KeyPair,
    keystore::{
        create_keystore_with_params, unlock_keystore, KeystoreFile, ARGON2_M_COST, ARGON2_P_COST,
        ARGON2_T_COST,
    },
    seed::{derive_account, generate_seed_phrase, recover_wallet_from_seed},
    Result, WalletError,
};

// ── Persistent state ─────────────────────────────────────────────────────────

/// Wallet state stored as JSON in the encrypted keystore plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletState {
    /// Hex-encoded 64-byte master seed.
    pub seed_hex: String,
    /// Number of accounts issued so far.
    pub account_count: u32,
}

// ── In-memory session ─────────────────────────────────────────────────────────

/// Unlocked wallet session. Master seed zeroized on drop.
/// Mutations are in-memory only until [`save_wallet`] re-encrypts state to disk.
pub struct WalletSession {
    seed: Zeroizing<Vec<u8>>,
    /// Number of accounts issued (next unused index).
    pub account_count: u32,
}

impl WalletSession {
    fn from_state(state: WalletState) -> Result<Self> {
        let seed_bytes = hex::decode(&state.seed_hex)
            .map_err(|_| WalletError::InvalidKeystore("bad seed hex in wallet state".into()))?;
        Ok(WalletSession {
            seed: Zeroizing::new(seed_bytes),
            account_count: state.account_count,
        })
    }

    /// Derive a new address at the next unused account index. Advances the counter.
    /// Call [`save_wallet`] afterwards to persist.
    pub fn new_address(&mut self) -> Result<(Address, KeyPair)> {
        let index = self.account_count;
        let kp = derive_account(&self.seed, index)?;
        let addr = Address::from_pubkey_hash(kp.public_key_hash());
        self.account_count += 1;
        Ok((addr, kp))
    }

    /// Get the keypair for account `index` without advancing the counter.
    /// Returns an error if `index >= account_count`.
    pub fn keypair_at(&self, index: u32) -> Result<KeyPair> {
        if index >= self.account_count {
            return Err(WalletError::InvalidAddress);
        }
        derive_account(&self.seed, index)
    }

    /// Get the address at account `index`.
    pub fn address_at(&self, index: u32) -> Result<Address> {
        let kp = self.keypair_at(index)?;
        Ok(Address::from_pubkey_hash(kp.public_key_hash()))
    }

    /// Return all derived addresses as `(index, address)` pairs (0..account_count).
    pub fn all_addresses(&self) -> Result<Vec<(u32, Address)>> {
        (0..self.account_count)
            .map(|i| {
                let kp = derive_account(&self.seed, i)?;
                Ok((i, Address::from_pubkey_hash(kp.public_key_hash())))
            })
            .collect()
    }

    /// Export current state for re-encryption via [`save_wallet`].
    pub fn export_state(&self) -> WalletState {
        WalletState {
            seed_hex: hex::encode(self.seed.as_slice()),
            account_count: self.account_count,
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Create a new wallet from OS entropy. Returns `(keystore_file, seed_phrase)`.
/// The phrase is not stored anywhere — display it to the user immediately.
pub fn create_wallet(password: &str) -> Result<(KeystoreFile, String)> {
    create_wallet_with_params(password, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)
}

/// Create a wallet with explicit Argon2id parameters.
/// Use low values (m=8, t=1, p=1) in tests.
pub fn create_wallet_with_params(
    password: &str,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<(KeystoreFile, String)> {
    let (phrase, seed) = generate_seed_phrase();
    let state = WalletState {
        seed_hex: hex::encode(seed.as_slice()),
        account_count: 0,
    };
    let plaintext =
        serde_json::to_vec(&state).map_err(|e| WalletError::KeystoreEncryption(e.to_string()))?;
    let ks = create_keystore_with_params(&plaintext, password, m_cost, t_cost, p_cost)?;
    Ok((ks, phrase))
}

/// Restore a wallet from an existing seed phrase. `account_count` starts at 0.
pub fn create_wallet_from_phrase(phrase: &str, password: &str) -> Result<KeystoreFile> {
    create_wallet_from_phrase_with_params(
        phrase,
        password,
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
    )
}

/// Restore from seed phrase with explicit Argon2id parameters.
pub fn create_wallet_from_phrase_with_params(
    phrase: &str,
    password: &str,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<KeystoreFile> {
    let seed = recover_wallet_from_seed(phrase)?;
    let state = WalletState {
        seed_hex: hex::encode(seed.as_slice()),
        account_count: 0,
    };
    let plaintext =
        serde_json::to_vec(&state).map_err(|e| WalletError::KeystoreEncryption(e.to_string()))?;
    create_keystore_with_params(&plaintext, password, m_cost, t_cost, p_cost)
}

/// Decrypt a wallet keystore and return an in-memory [`WalletSession`].
pub fn unlock_wallet(keystore: &KeystoreFile, password: &str) -> Result<WalletSession> {
    let plaintext = unlock_keystore(keystore, password)?;
    let state: WalletState = serde_json::from_slice(&plaintext)
        .map_err(|e| WalletError::InvalidKeystore(format!("wallet state parse failed: {e}")))?;
    WalletSession::from_state(state)
}

/// Re-encrypt and return a fresh [`KeystoreFile`] after session mutations.
/// Write the result atomically (temp file + rename) to avoid partial writes.
pub fn save_wallet(session: &WalletSession, password: &str) -> Result<KeystoreFile> {
    save_wallet_with_params(
        session,
        password,
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
    )
}

/// Save with explicit Argon2id parameters.
pub fn save_wallet_with_params(
    session: &WalletSession,
    password: &str,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<KeystoreFile> {
    let state = session.export_state();
    let plaintext =
        serde_json::to_vec(&state).map_err(|e| WalletError::KeystoreEncryption(e.to_string()))?;
    create_keystore_with_params(&plaintext, password, m_cost, t_cost, p_cost)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_create(password: &str) -> (KeystoreFile, String) {
        create_wallet_with_params(password, 8, 1, 1).unwrap()
    }

    fn fast_unlock(ks: &KeystoreFile, password: &str) -> WalletSession {
        unlock_wallet(ks, password).unwrap()
    }

    fn fast_save(session: &WalletSession, password: &str) -> KeystoreFile {
        save_wallet_with_params(session, password, 8, 1, 1).unwrap()
    }

    // ── create_wallet ────────────────────────────────────────────────────────

    #[test]
    fn create_wallet_returns_24_word_phrase() {
        let (_, phrase) = fast_create("pw");
        assert_eq!(phrase.split_whitespace().count(), 24);
    }

    #[test]
    fn created_wallet_unlocks_with_correct_password() {
        let (ks, _) = fast_create("correct-pw");
        assert!(unlock_wallet(&ks, "correct-pw").is_ok());
    }

    #[test]
    fn created_wallet_rejects_wrong_password() {
        let (ks, _) = fast_create("correct-pw");
        assert!(unlock_wallet(&ks, "wrong-pw").is_err());
    }

    #[test]
    fn new_wallet_has_zero_account_count() {
        let (ks, _) = fast_create("pw");
        let session = fast_unlock(&ks, "pw");
        assert_eq!(session.account_count, 0);
    }

    // ── new_address ──────────────────────────────────────────────────────────

    #[test]
    fn new_address_increments_counter() {
        let (ks, _) = fast_create("pw");
        let mut session = fast_unlock(&ks, "pw");
        session.new_address().unwrap();
        assert_eq!(session.account_count, 1);
        session.new_address().unwrap();
        assert_eq!(session.account_count, 2);
    }

    #[test]
    fn new_address_returns_distinct_addresses() {
        let (ks, _) = fast_create("pw");
        let mut session = fast_unlock(&ks, "pw");
        let (addr0, _) = session.new_address().unwrap();
        let (addr1, _) = session.new_address().unwrap();
        assert_ne!(addr0, addr1);
    }

    #[test]
    fn new_address_is_deterministic_across_sessions() {
        let (ks, phrase) = fast_create("pw");
        let mut s1 = fast_unlock(&ks, "pw");
        let (addr0, _) = s1.new_address().unwrap();

        let ks2 = create_wallet_from_phrase_with_params(&phrase, "pw2", 8, 1, 1).unwrap();
        let mut s2 = fast_unlock(&ks2, "pw2");
        let (addr0_restored, _) = s2.new_address().unwrap();
        assert_eq!(addr0, addr0_restored);
    }

    // ── keypair_at / address_at ──────────────────────────────────────────────

    #[test]
    fn keypair_at_out_of_range_returns_error() {
        let (ks, _) = fast_create("pw");
        let session = fast_unlock(&ks, "pw");
        assert!(session.keypair_at(0).is_err());
    }

    #[test]
    fn keypair_at_returns_consistent_keypair() {
        let (ks, _) = fast_create("pw");
        let mut session = fast_unlock(&ks, "pw");
        let (addr, kp_from_new) = session.new_address().unwrap();
        let kp_from_at = session.keypair_at(0).unwrap();
        assert_eq!(kp_from_new.public_key(), kp_from_at.public_key());
        assert_eq!(
            addr,
            Address::from_pubkey_hash(kp_from_at.public_key_hash())
        );
    }

    #[test]
    fn address_at_matches_new_address() {
        let (ks, _) = fast_create("pw");
        let mut session = fast_unlock(&ks, "pw");
        let (addr, _) = session.new_address().unwrap();
        assert_eq!(addr, session.address_at(0).unwrap());
    }

    // ── all_addresses ────────────────────────────────────────────────────────

    #[test]
    fn all_addresses_empty_on_fresh_wallet() {
        let (ks, _) = fast_create("pw");
        let session = fast_unlock(&ks, "pw");
        assert!(session.all_addresses().unwrap().is_empty());
    }

    #[test]
    fn all_addresses_returns_correct_count_and_order() {
        let (ks, _) = fast_create("pw");
        let mut session = fast_unlock(&ks, "pw");
        session.new_address().unwrap();
        session.new_address().unwrap();
        session.new_address().unwrap();
        let addrs = session.all_addresses().unwrap();
        assert_eq!(addrs.len(), 3);
        assert_eq!(addrs[0].0, 0);
        assert_eq!(addrs[1].0, 1);
        assert_eq!(addrs[2].0, 2);
        assert_ne!(addrs[0].1, addrs[1].1);
        assert_ne!(addrs[1].1, addrs[2].1);
    }

    // ── save / restore ───────────────────────────────────────────────────────

    #[test]
    fn save_and_reload_preserves_account_count() {
        let (ks, _) = fast_create("pw");
        let mut session = fast_unlock(&ks, "pw");
        session.new_address().unwrap();
        session.new_address().unwrap();
        let saved_ks = fast_save(&session, "pw");
        let reloaded = fast_unlock(&saved_ks, "pw");
        assert_eq!(reloaded.account_count, 2);
    }

    #[test]
    fn save_and_reload_preserves_addresses() {
        let (ks, _) = fast_create("pw");
        let mut session = fast_unlock(&ks, "pw");
        let (addr0, _) = session.new_address().unwrap();
        let saved_ks = fast_save(&session, "pw");
        let reloaded = fast_unlock(&saved_ks, "pw");
        assert_eq!(reloaded.address_at(0).unwrap(), addr0);
    }

    // ── create_wallet_from_phrase ────────────────────────────────────────────

    #[test]
    fn restore_from_phrase_produces_same_addresses() {
        let (ks, phrase) = fast_create("pw");
        let mut original = fast_unlock(&ks, "pw");
        let (addr0, _) = original.new_address().unwrap();

        let ks2 = create_wallet_from_phrase_with_params(&phrase, "new-pw", 8, 1, 1).unwrap();
        let mut restored = fast_unlock(&ks2, "new-pw");
        let (addr0_restored, _) = restored.new_address().unwrap();
        assert_eq!(addr0, addr0_restored);
    }

    #[test]
    fn invalid_phrase_rejected() {
        let result = create_wallet_from_phrase_with_params("not a valid phrase", "pw", 8, 1, 1);
        assert!(result.is_err());
    }

    // ── misc ─────────────────────────────────────────────────────────────────

    #[test]
    fn export_state_roundtrip() {
        let (ks, _) = fast_create("pw");
        let mut session = fast_unlock(&ks, "pw");
        session.new_address().unwrap();
        let state = session.export_state();
        assert_eq!(state.account_count, 1);
        assert_eq!(state.seed_hex.len(), 128); // 64 bytes * 2 hex chars
    }
}
