// Copyright (c) 2026 Kantoshi Miyamura
// Integration and security tests for the wallet.

use crate::keystore::{
    create_keystore_with_params, export_keystore, import_keystore, unlock_keystore,
};
use crate::*;
use axiom_primitives::{Amount, Hash256};

#[test]
fn keystore_encrypt_decrypt_roundtrip() {
    let kp = KeyPair::generate().unwrap();
    let secret = kp.export_private_key().to_vec();
    let ks = create_keystore_with_params(&secret, "Secure1!", 8, 1, 1).unwrap();
    let decrypted = unlock_keystore(&ks, "Secure1!").unwrap();
    assert_eq!(*decrypted, secret);
}

#[test]
fn keystore_wrong_password_rejected() {
    let ks = create_keystore_with_params(b"key_material", "CorrectPass1!", 8, 1, 1).unwrap();
    assert!(matches!(
        unlock_keystore(&ks, "WrongPass1!").unwrap_err(),
        WalletError::KeystoreDecryption
    ));
}

#[test]
fn keystore_corrupted_ciphertext_rejected() {
    let mut ks = create_keystore_with_params(b"key_material", "Pass1!", 8, 1, 1).unwrap();
    let mut hex = ks.ciphertext_hex.clone();
    let last = hex.pop().unwrap();
    hex.push(if last == 'a' { 'b' } else { 'a' });
    ks.ciphertext_hex = hex;
    assert!(matches!(
        unlock_keystore(&ks, "Pass1!").unwrap_err(),
        WalletError::KeystoreDecryption
    ));
}

#[test]
fn seed_generation_recovery_roundtrip() {
    let (phrase, original_seed) = generate_seed_phrase();
    assert_eq!(phrase.split_whitespace().count(), 24);
    let recovered = recover_wallet_from_seed(&phrase).unwrap();
    assert_eq!(*original_seed, *recovered);
}

#[test]
fn invalid_seed_phrase_rejected() {
    assert!(matches!(
        recover_wallet_from_seed("abandon abandon abandon").unwrap_err(),
        WalletError::InvalidSeedPhrase
    ));
}

#[test]
fn deterministic_address_derivation_from_seed() {
    let (phrase, _) = generate_seed_phrase();
    let seed = recover_wallet_from_seed(&phrase).unwrap();
    let kp1 = derive_account(&seed, 0).unwrap();
    let kp2 = derive_account(&seed, 0).unwrap();
    let addr1 = Address::from_pubkey_hash(kp1.public_key_hash());
    let addr2 = Address::from_pubkey_hash(kp2.public_key_hash());
    assert_eq!(addr1, addr2);
}

#[test]
fn different_account_indices_differ() {
    let (_, seed) = generate_seed_phrase();
    let kp0 = derive_account(&seed, 0).unwrap();
    let kp1 = derive_account(&seed, 1).unwrap();
    assert_ne!(kp0.public_key_hash(), kp1.public_key_hash());
}

#[test]
fn valid_checksummed_address_accepted() {
    let kp = KeyPair::generate().unwrap();
    let addr = Address::from_pubkey_hash(kp.public_key_hash());
    let s = addr.to_string();
    assert_eq!(s.len(), 75);
    assert!(Address::from_string(&s).is_ok());
}

#[test]
fn checksum_mismatch_rejected() {
    let mut s = Address::from_pubkey_hash(Hash256::zero()).to_string();
    let last = s.pop().unwrap();
    s.push(if last == 'a' { 'b' } else { 'a' });
    assert!(matches!(
        Address::from_string(&s).unwrap_err(),
        WalletError::InvalidChecksum
    ));
}

#[test]
fn prefix_mismatch_rejected() {
    let s = Address::from_pubkey_hash(Hash256::zero())
        .to_string()
        .replacen("axm", "btc", 1);
    assert!(matches!(
        Address::from_string(&s).unwrap_err(),
        WalletError::InvalidAddress
    ));
}

#[test]
fn truncated_address_rejected() {
    assert!(Address::from_string("axm1234").is_err());
    assert!(Address::from_string("axm").is_err());
}

#[test]
fn local_signing_flow_correct() {
    let keypair = KeyPair::generate().unwrap();
    let amount = Amount::from_sat(1000).unwrap();
    let tx = TransactionBuilder::new()
        .add_input(Hash256::zero(), 0)
        .add_output(amount, Hash256::zero())
        .nonce(1)
        .keypair(keypair.clone())
        .build()
        .unwrap();
    let pubkey = keypair.public_key_struct().unwrap();
    let placeholder = axiom_primitives::Signature::placeholder();
    let unsigned_inputs = vec![axiom_protocol::TxInput {
        prev_tx_hash: Hash256::zero(),
        prev_output_index: 0,
        signature: placeholder,
        pubkey,
    }];
    let unsigned_tx = axiom_protocol::Transaction::new_transfer(
        unsigned_inputs,
        tx.outputs.clone(),
        tx.nonce,
        tx.locktime,
    );
    let unsigned_bytes = axiom_protocol::serialize_transaction(&unsigned_tx);
    // Must go through the canonical public API, not re-hash with double_hash256 —
    // the builder uses `transaction_signing_hash` (tagged-hash, length-prefixed).
    let sign_hash = axiom_crypto::transaction_signing_hash("", &unsigned_bytes);
    let sig_bytes = tx.inputs[0].signature.as_bytes();
    assert!(keypair.verify(sign_hash.as_bytes(), sig_bytes).unwrap());
}

#[test]
fn wrong_keypair_signature_rejected() {
    let kp1 = KeyPair::generate().unwrap();
    let kp2 = KeyPair::generate().unwrap();
    let sig = kp1.sign(b"message").unwrap();
    assert!(!kp2.verify(b"message", &sig).unwrap());
}

#[test]
fn tampered_message_signature_rejected() {
    let kp = KeyPair::generate().unwrap();
    let sig = kp.sign(b"original").unwrap();
    assert!(!kp.verify(b"tampered", &sig).unwrap());
}

#[test]
fn keystore_export_no_plaintext() {
    let kp = KeyPair::generate().unwrap();
    let priv_bytes = kp.export_private_key().to_vec();
    let ks = create_keystore_with_params(&priv_bytes, "Safe1!", 8, 1, 1).unwrap();
    let json = export_keystore(&ks).unwrap();
    assert!(!json.contains(&hex::encode(&priv_bytes)));
}

#[test]
fn keystore_import_export_roundtrip() {
    let secret = b"deterministic seed bytes 123456!";
    let ks = create_keystore_with_params(secret, "Round1!", 8, 1, 1).unwrap();
    let json = export_keystore(&ks).unwrap();
    let dec = unlock_keystore(&import_keystore(&json).unwrap(), "Round1!").unwrap();
    assert_eq!(dec.as_slice(), secret);
}

#[test]
fn v1_legacy_address_parseable() {
    let hash = Hash256::zero();
    let v1 = format!("axm{}", hex::encode(hash.as_bytes()));
    assert_eq!(v1.len(), 67);
    let addr = Address::from_string(&v1).unwrap();
    assert_eq!(addr.pubkey_hash(), &hash);
}

#[test]
fn from_key_bytes_restoration() {
    let original = KeyPair::generate().unwrap();
    let restored = KeyPair::from_key_bytes(
        original.export_private_key().to_vec(),
        original.public_key().to_vec(),
    )
    .unwrap();
    let sig = restored.sign(b"test").unwrap();
    assert!(original.verify(b"test", &sig).unwrap());
}

#[test]
fn password_strength_checks() {
    assert!(validate_password_strength("Axiom1!Secure").is_ok());
    assert!(validate_password_strength("short").is_err());
    assert!(validate_password_strength("alllowercase1!").is_err());
    assert!(validate_password_strength("ALLUPPERCASE1!").is_err());
    assert!(validate_password_strength("NoDigitsHere!").is_err());
    assert!(validate_password_strength("NoSpecialChar1").is_err());
}

#[test]
fn dust_and_fee_safety_checks() {
    assert!(matches!(
        validate_amount_not_dust(100).unwrap_err(),
        WalletError::DustAmount { .. }
    ));
    assert!(validate_amount_not_dust(546).is_ok());
    assert!(matches!(
        validate_fee_reasonable(6_000, 10_000).unwrap_err(),
        WalletError::FeeTooHigh { .. }
    ));
    assert!(validate_fee_reasonable(100, 10_000).is_ok());
}

#[test]
fn full_lifecycle_seed_to_signed_tx() {
    let (phrase, _) = generate_seed_phrase();
    let master_seed = recover_wallet_from_seed(&phrase).unwrap();
    let kp = derive_account(&master_seed, 0).unwrap();
    let ks = create_keystore_with_params(kp.export_private_key(), "Wallet1!", 8, 1, 1).unwrap();
    let priv_bytes = unlock_keystore(&ks, "Wallet1!").unwrap();
    let restored = KeyPair::from_private_key(priv_bytes.to_vec()).unwrap();
    assert_eq!(kp.public_key(), restored.public_key());
    let addr = Address::from_pubkey_hash(kp.public_key_hash());
    validate_address(&addr.to_string()).unwrap();
    let tx = TransactionBuilder::new()
        .add_input(Hash256::zero(), 0)
        .add_output(Amount::from_sat(1_000).unwrap(), Hash256::zero())
        .nonce(1)
        .keypair(restored.clone())
        .build()
        .unwrap();
    let sig_bytes = tx.inputs[0].signature.as_bytes();
    let pk = restored.public_key_struct().unwrap();
    let ui = vec![axiom_protocol::TxInput {
        prev_tx_hash: Hash256::zero(),
        prev_output_index: 0,
        signature: axiom_primitives::Signature::placeholder(),
        pubkey: pk,
    }];
    let utx =
        axiom_protocol::Transaction::new_transfer(ui, tx.outputs.clone(), tx.nonce, tx.locktime);
    let msg = axiom_protocol::serialize_transaction(&utx);
    let sign_hash = axiom_crypto::transaction_signing_hash("", &msg);
    assert!(restored.verify(sign_hash.as_bytes(), sig_bytes).unwrap());
}

#[test]
fn wallet_key_generation() {
    let keypair = KeyPair::generate().unwrap();
    assert_eq!(keypair.public_key().len(), 2592); // ML-DSA-87 verifying key
}

#[test]
fn wallet_address_derivation() {
    let keypair = KeyPair::generate().unwrap();
    let pubkey_hash = keypair.public_key_hash();
    let address = Address::from_pubkey_hash(pubkey_hash);
    let addr_str = address.to_string();
    assert!(addr_str.starts_with("axm"));
    let parsed = Address::from_string(&addr_str).unwrap();
    assert_eq!(address, parsed);
}

#[test]
fn wallet_transaction_signing() {
    let keypair = KeyPair::generate().unwrap();
    let amount = Amount::from_sat(1000).unwrap();
    let tx = TransactionBuilder::new()
        .add_input(Hash256::zero(), 0)
        .add_output(amount, Hash256::zero())
        .nonce(1)
        .keypair(keypair.clone())
        .build()
        .unwrap();
    let pubkey = keypair.public_key_struct().unwrap();
    let placeholder_sig = axiom_primitives::Signature::placeholder();
    let unsigned_inputs: Vec<axiom_protocol::TxInput> = vec![axiom_protocol::TxInput {
        prev_tx_hash: Hash256::zero(),
        prev_output_index: 0,
        signature: placeholder_sig,
        pubkey,
    }];
    let unsigned_tx = axiom_protocol::Transaction::new_transfer(
        unsigned_inputs,
        tx.outputs.clone(),
        tx.nonce,
        tx.locktime,
    );
    let unsigned_data = axiom_protocol::serialize_transaction(&unsigned_tx);
    let sign_hash = axiom_crypto::transaction_signing_hash("", &unsigned_data);
    let sig_bytes = tx.inputs[0].signature.as_bytes();
    assert!(keypair.verify(sign_hash.as_bytes(), sig_bytes).unwrap());
}

#[test]
fn wallet_multiple_outputs() {
    let keypair = KeyPair::generate().unwrap();
    let tx = TransactionBuilder::new()
        .add_input(Hash256::zero(), 0)
        .add_output(Amount::from_sat(1000).unwrap(), Hash256::zero())
        .add_output(Amount::from_sat(2000).unwrap(), Hash256::zero())
        .nonce(1)
        .keypair(keypair)
        .build()
        .unwrap();
    assert_eq!(tx.outputs.len(), 2);
}

#[test]
fn wallet_nonce_handling() {
    let keypair = KeyPair::generate().unwrap();
    let tx = TransactionBuilder::new()
        .add_input(Hash256::zero(), 0)
        .add_output(Amount::from_sat(1000).unwrap(), Hash256::zero())
        .nonce(42)
        .keypair(keypair)
        .build()
        .unwrap();
    assert_eq!(tx.nonce, 42);
}

// Fee-bump logic: deducts extra fee from the last (change) output.
fn compute_bumped_outputs(
    old_fee_rate: u64,
    new_fee_rate: u64,
    tx_size_bytes: u64,
    output_values: &[u64],
) -> std::result::Result<Vec<u64>, String> {
    if new_fee_rate <= old_fee_rate {
        return Err(format!(
            "new fee rate ({} sat/byte) must be higher than original ({} sat/byte)",
            new_fee_rate, old_fee_rate
        ));
    }
    if output_values.is_empty() {
        return Err("transaction has no outputs".into());
    }
    let extra_fee = (new_fee_rate - old_fee_rate)
        .checked_mul(tx_size_bytes)
        .ok_or_else(|| "fee calculation overflow".to_string())?;
    let mut new_values = output_values.to_vec();
    let last = new_values.last_mut().unwrap();
    if *last < extra_fee {
        return Err(format!(
            "not enough change to bump fee: change output is {} sat but extra fee required is {} sat",
            *last, extra_fee
        ));
    }
    *last -= extra_fee;
    Ok(new_values)
}

#[test]
fn test_bump_fee_requires_higher_rate() {
    assert!(
        compute_bumped_outputs(5, 5, 250, &[10_000, 5_000]).is_err(),
        "equal fee rates must be rejected"
    );
    assert!(
        compute_bumped_outputs(10, 5, 250, &[10_000, 5_000]).is_err(),
        "lower fee rate must be rejected"
    );
    assert!(
        compute_bumped_outputs(5, 10, 250, &[10_000, 5_000]).is_ok(),
        "higher fee rate must be accepted"
    );
}

#[test]
fn test_bump_fee_reduces_change_output() {
    // old=1 sat/byte, new=5 sat/byte, size=200 bytes → extra_fee=800 sat
    let result = compute_bumped_outputs(1, 5, 200, &[10_000, 5_000]).unwrap();
    assert_eq!(result.len(), 2, "output count must not change");
    assert_eq!(result[0], 10_000, "payment output must be unchanged");
    assert_eq!(
        result[1], 4_200,
        "change output must decrease by extra_fee (800 sat)"
    );
}

// ── High-assurance keygen audit tests ────────────────────────────────────────

/// Generate N keypairs and assert every private key, public key, and
/// address is distinct. Catches CSPRNG seeding bugs and any accidental
/// constant-seed regressions.
#[test]
fn keygen_large_scale_uniqueness() {
    use std::collections::HashSet;
    const N: usize = 512;
    let mut priv_set = HashSet::new();
    let mut pub_set = HashSet::new();
    let mut addr_set = HashSet::new();
    for _ in 0..N {
        let kp = KeyPair::generate().unwrap();
        let priv_hex = hex::encode(kp.export_private_key());
        let pub_hex = hex::encode(kp.public_key());
        let addr = Address::from_pubkey_hash(kp.public_key_hash()).to_string();
        assert!(priv_set.insert(priv_hex), "duplicate private key in {} trials", N);
        assert!(pub_set.insert(pub_hex), "duplicate public key in {} trials", N);
        assert!(addr_set.insert(addr), "duplicate address in {} trials", N);
    }
    assert_eq!(priv_set.len(), N);
    assert_eq!(pub_set.len(), N);
    assert_eq!(addr_set.len(), N);
}

/// The CSPRNG should never produce a trivially bad private key
/// (all-zero, all-ones, or low entropy). Catches a fully broken RNG.
#[test]
fn keygen_private_key_non_trivial() {
    for _ in 0..32 {
        let kp = KeyPair::generate().unwrap();
        let priv_bytes = kp.export_private_key();
        assert_eq!(priv_bytes.len(), 32, "ML-DSA-87 xi seed is 32 bytes");
        assert!(
            priv_bytes.iter().any(|&b| b != 0),
            "private key is all zero"
        );
        assert!(
            priv_bytes.iter().any(|&b| b != 0xFF),
            "private key is all ones"
        );
        let unique_bytes: std::collections::HashSet<u8> = priv_bytes.iter().copied().collect();
        assert!(
            unique_bytes.len() > 4,
            "private key has suspiciously low byte diversity: {:?}",
            priv_bytes
        );
    }
}

/// Address encoding must be deterministic from the pubkey, round-trip losslessly,
/// and differ for different pubkey hashes in a large sample.
#[test]
fn keygen_address_derivation_deterministic_and_distinct() {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    for _ in 0..256 {
        let kp = KeyPair::generate().unwrap();
        let h = kp.public_key_hash();
        let a1 = Address::from_pubkey_hash(h).to_string();
        let a2 = Address::from_pubkey_hash(h).to_string();
        assert_eq!(a1, a2, "address derivation must be deterministic");
        let parsed = Address::from_string(&a1).unwrap();
        assert_eq!(parsed.pubkey_hash(), &h, "address round-trip lost the hash");
        assert!(seen.insert(a1), "collision in 256 keypairs — CSPRNG or derivation bug");
    }
}

/// Every freshly generated keypair must produce a signature that verifies
/// against itself and fails against a different key. This is the core
/// guarantee the keygen binary ultimately produces.
#[test]
fn keygen_signature_roundtrip_per_key() {
    for _ in 0..32 {
        let kp = KeyPair::generate().unwrap();
        let other = KeyPair::generate().unwrap();
        let msg = b"audit: signatures must verify only with the generating key";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap(), "self-verify must succeed");
        assert!(!other.verify(msg, &sig).unwrap(), "foreign key must reject");
    }
}

/// Simulate the full axiom-keygen artifact flow: generate, encrypt with
/// Argon2id/XChaCha20, export JSON, re-import, unlock, reconstruct, and
/// confirm the public key/address derivation is identical. Also confirm
/// the export contains no plaintext key material.
#[test]
fn keygen_encrypted_artifact_roundtrip_preserves_identity() {
    let kp = KeyPair::generate().unwrap();
    let priv_bytes = kp.export_private_key().to_vec();
    let expected_pub = kp.public_key().to_vec();
    let expected_addr = Address::from_pubkey_hash(kp.public_key_hash()).to_string();

    let ks = create_keystore_with_params(&priv_bytes, "Audit1!Secure", 8, 1, 1).unwrap();
    let json = export_keystore(&ks).unwrap();

    // No plaintext private key or xi bytes anywhere in the serialized artifact.
    assert!(!json.contains(&hex::encode(&priv_bytes)));
    assert!(!json.to_lowercase().contains("private_key_hex"));

    let imported = import_keystore(&json).unwrap();
    let plaintext = unlock_keystore(&imported, "Audit1!Secure").unwrap();
    assert_eq!(plaintext.as_slice(), priv_bytes.as_slice());

    let rebuilt = KeyPair::from_private_key(plaintext.to_vec()).unwrap();
    assert_eq!(rebuilt.public_key(), expected_pub.as_slice());
    let rebuilt_addr = Address::from_pubkey_hash(rebuilt.public_key_hash()).to_string();
    assert_eq!(rebuilt_addr, expected_addr);

    // Wrong password must fail.
    assert!(matches!(
        unlock_keystore(&imported, "WrongPass!").unwrap_err(),
        WalletError::KeystoreDecryption
    ));
}

/// The KeyPair's Debug impl must not reveal private key bytes. Catches
/// accidental `#[derive(Debug)]` regressions that would expose the key
/// in panic messages or tracing output.
#[test]
fn keygen_keypair_debug_never_leaks_private_key() {
    let kp = KeyPair::generate().unwrap();
    let debug_str = format!("{:?}", kp);
    let priv_hex = hex::encode(kp.export_private_key());
    assert!(!debug_str.contains(&priv_hex), "Debug leaked private key");
    assert!(debug_str.contains("<redacted>"));
}

// ── High-assurance bump-fee audit tests ──────────────────────────────────────

/// Replacement transactions must be signed with the node's chain_id —
/// an empty or wrong chain_id breaks validation. The builder already wires
/// chain_id into the signing hash; this test pins that behavior so any
/// regression immediately fails.
#[test]
fn bump_fee_signature_uses_chain_id() {
    let keypair = KeyPair::generate().unwrap();
    let tx_with_chain = TransactionBuilder::new()
        .add_input(Hash256::zero(), 0)
        .add_output(Amount::from_sat(1000).unwrap(), Hash256::zero())
        .nonce(1)
        .chain_id("axiom-mainnet-1")
        .keypair(keypair.clone())
        .build()
        .unwrap();
    let tx_no_chain = TransactionBuilder::new()
        .add_input(Hash256::zero(), 0)
        .add_output(Amount::from_sat(1000).unwrap(), Hash256::zero())
        .nonce(1)
        .keypair(keypair.clone())
        .build()
        .unwrap();

    // Same tx bytes but signed against different chain_id messages → different signatures.
    assert_ne!(
        tx_with_chain.inputs[0].signature.as_bytes(),
        tx_no_chain.inputs[0].signature.as_bytes(),
        "chain_id must enter the signing hash"
    );

    // The chain-id signature must verify against the chain-id signing hash only.
    let pubkey = keypair.public_key_struct().unwrap();
    let ui = vec![axiom_protocol::TxInput {
        prev_tx_hash: Hash256::zero(),
        prev_output_index: 0,
        signature: axiom_primitives::Signature::placeholder(),
        pubkey,
    }];
    let unsigned =
        axiom_protocol::Transaction::new_transfer(ui, tx_with_chain.outputs.clone(), 1, 0);
    let tx_bytes = axiom_protocol::serialize_transaction(&unsigned);
    let correct_hash = axiom_crypto::transaction_signing_hash("axiom-mainnet-1", &tx_bytes);
    let wrong_hash = axiom_crypto::transaction_signing_hash("axiom-testnet-1", &tx_bytes);
    let sig = tx_with_chain.inputs[0].signature.as_bytes();
    assert!(keypair.verify(correct_hash.as_bytes(), sig).unwrap());
    assert!(!keypair.verify(wrong_hash.as_bytes(), sig).unwrap());
}

/// A full bump-fee simulation: build the original tx, reduce the change
/// output, re-sign with the same chain_id, verify the new signature is
/// valid, and confirm destination outputs and their pubkey_hashes are
/// untouched.
#[test]
fn bump_fee_end_to_end_preserves_destination() {
    let keypair = KeyPair::generate().unwrap();
    let own_hash = keypair.public_key_hash();
    let dest_hash = Hash256::from_slice(&[9u8; 32]).unwrap();
    let chain = "axiom-mainnet-1";

    let original = TransactionBuilder::new()
        .add_input(Hash256::zero(), 0)
        .add_output(Amount::from_sat(50_000).unwrap(), dest_hash) // destination
        .add_output(Amount::from_sat(10_000).unwrap(), own_hash)  // change (last)
        .nonce(7)
        .chain_id(chain)
        .keypair(keypair.clone())
        .build()
        .unwrap();

    // Reduce the change output by 1200 sat, re-sign.
    let extra_fee = 1200u64;
    let new_change = original.outputs[1].value.as_sat() - extra_fee;

    let bumped = TransactionBuilder::new()
        .add_input(Hash256::zero(), 0)
        .add_output(original.outputs[0].value, original.outputs[0].pubkey_hash)
        .add_output(Amount::from_sat(new_change).unwrap(), original.outputs[1].pubkey_hash)
        .nonce(7)
        .chain_id(chain)
        .keypair(keypair.clone())
        .build()
        .unwrap();

    // Destination untouched.
    assert_eq!(bumped.outputs[0].value, original.outputs[0].value);
    assert_eq!(bumped.outputs[0].pubkey_hash, original.outputs[0].pubkey_hash);
    // Change reduced by exactly extra_fee.
    assert_eq!(bumped.outputs[1].value.as_sat(), new_change);
    assert_eq!(bumped.outputs[1].pubkey_hash, own_hash);

    // Signature on the bumped tx verifies.
    let pubkey = keypair.public_key_struct().unwrap();
    let ui = vec![axiom_protocol::TxInput {
        prev_tx_hash: Hash256::zero(),
        prev_output_index: 0,
        signature: axiom_primitives::Signature::placeholder(),
        pubkey,
    }];
    let unsigned =
        axiom_protocol::Transaction::new_transfer(ui, bumped.outputs.clone(), 7, 0);
    let bytes = axiom_protocol::serialize_transaction(&unsigned);
    let sign_hash = axiom_crypto::transaction_signing_hash(chain, &bytes);
    let sig = bumped.inputs[0].signature.as_bytes();
    assert!(keypair.verify(sign_hash.as_bytes(), sig).unwrap());

    // Original signature no longer valid for the bumped tx (different outputs).
    assert!(!keypair.verify(sign_hash.as_bytes(), original.inputs[0].signature.as_bytes()).unwrap());
}
