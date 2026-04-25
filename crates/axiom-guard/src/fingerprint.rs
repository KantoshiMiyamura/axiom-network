// Copyright (c) 2026 Kantoshi Miyamura
// Cognitive Fingerprint — AxiomMind's per-node cryptographic identity.
//
// Each node generates its own unique ML-DSA-87 keypair on first run and
// persists the seed to `{data_dir}/guard_identity.key`. This ensures that
// every node has a distinct, verifiable identity — no global shared secret.

use axiom_wallet::{Address, KeyPair};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const IDENTITY_FILE: &str = "guard_identity.key";

pub struct CognitiveFingerprint {
    keypair: KeyPair,
    pub public_key: Vec<u8>,
    pub address: String,
}

impl CognitiveFingerprint {
    /// Load existing identity from `data_dir`, or generate a new one and persist it.
    ///
    /// The identity is a 32-byte ML-DSA-87 seed stored as hex in
    /// `{data_dir}/guard_identity.key`. Each node gets its own keypair.
    pub fn load_or_create(
        data_dir: &Path,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let path = data_dir.join(IDENTITY_FILE);

        let seed = if path.exists() {
            Self::load_seed(&path)?
        } else {
            Self::generate_and_save(&path)?
        };

        let keypair = KeyPair::from_private_key(seed.to_vec())
            .map_err(|e| format!("guard identity keypair error: {}", e))?;
        let address = Address::from_pubkey_hash(keypair.public_key_hash()).to_string();
        let public_key = keypair.public_key().to_vec();

        Ok(Self {
            keypair,
            public_key,
            address,
        })
    }

    /// Sign `message` using this node's ML-DSA-87 private key.
    pub fn sign(&self, message: &[u8]) -> axiom_wallet::Result<Vec<u8>> {
        self.keypair.sign(message)
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    /// Returns the path to the identity file for a given data directory.
    pub fn identity_path(data_dir: &Path) -> PathBuf {
        data_dir.join(IDENTITY_FILE)
    }

    fn load_seed(
        path: &Path,
    ) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        let hex_str = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read guard identity {}: {}", path.display(), e))?;
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| format!("invalid guard identity hex: {}", e))?;
        if bytes.len() != 32 {
            return Err(
                format!("guard identity seed must be 32 bytes, got {}", bytes.len()).into(),
            );
        }
        Ok(Zeroizing::new(bytes))
    }

    fn generate_and_save(
        path: &Path,
    ) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        // Generate a fresh random keypair — extract the 32-byte seed.
        let keypair =
            KeyPair::generate().map_err(|e| format!("guard identity generation failed: {}", e))?;
        let seed = Zeroizing::new(keypair.export_private_key().to_vec());

        // Write seed as hex. File permissions are inherited from the data dir.
        std::fs::write(path, hex::encode(&*seed))
            .map_err(|e| format!("failed to write guard identity {}: {}", path.display(), e))?;

        Ok(seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn per_node_identity_is_persistent() {
        let tmp = TempDir::new().unwrap();

        let fp1 = CognitiveFingerprint::load_or_create(tmp.path()).unwrap();
        let fp2 = CognitiveFingerprint::load_or_create(tmp.path()).unwrap();

        assert_eq!(
            fp1.address, fp2.address,
            "same data_dir must produce the same identity"
        );
        assert_eq!(fp1.public_key, fp2.public_key);
    }

    #[test]
    fn different_nodes_have_different_keys() {
        let tmp1 = TempDir::new().unwrap();
        let tmp2 = TempDir::new().unwrap();

        let fp1 = CognitiveFingerprint::load_or_create(tmp1.path()).unwrap();
        let fp2 = CognitiveFingerprint::load_or_create(tmp2.path()).unwrap();

        assert_ne!(
            fp1.address, fp2.address,
            "different data_dirs must produce different identities"
        );
        assert_ne!(fp1.public_key, fp2.public_key);
    }

    #[test]
    fn key_sizes_correct() {
        let tmp = TempDir::new().unwrap();
        let fp = CognitiveFingerprint::load_or_create(tmp.path()).unwrap();

        assert_eq!(fp.public_key.len(), 2592, "ML-DSA-87 VK must be 2592 bytes");
        assert!(fp.address.starts_with("axm"), "address must start with axm");
    }

    #[test]
    fn sign_and_verify() {
        let tmp = TempDir::new().unwrap();
        let fp = CognitiveFingerprint::load_or_create(tmp.path()).unwrap();

        let msg = b"axiom-guard-test-message";
        let sig = fp.sign(msg).unwrap();
        assert_eq!(sig.len(), 4627, "ML-DSA-87 signature must be 4627 bytes");

        // Reload and verify
        let fp2 = CognitiveFingerprint::load_or_create(tmp.path()).unwrap();
        assert!(
            fp2.keypair.verify(msg, &sig).is_ok(),
            "signature must verify"
        );
    }

    #[test]
    fn identity_file_is_hex_seed() {
        let tmp = TempDir::new().unwrap();
        let _fp = CognitiveFingerprint::load_or_create(tmp.path()).unwrap();

        let path = tmp.path().join("guard_identity.key");
        assert!(path.exists(), "identity file must be created");

        let content = std::fs::read_to_string(&path).unwrap();
        let bytes = hex::decode(content.trim()).unwrap();
        assert_eq!(bytes.len(), 32, "seed must be 32 bytes");
    }
}
