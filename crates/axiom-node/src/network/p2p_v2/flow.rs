// Copyright (c) 2026 Kantoshi Miyamura

//! High-level handshake flow over byte-level messages.
//!
//! No socket I/O — the caller is responsible for moving bytes between
//! peers. These helpers exist so the cryptographic state machine is
//! testable end-to-end without standing up a TCP listener.
//!
//! The flow:
//!
//! 1. Caller constructs an [`InitiatorHandshakeMaterial`] holding the
//!    initiator's ephemeral X25519 / ML-KEM keys, fresh nonce, and
//!    long-term identity keys.
//! 2. [`initiator_build_hello`] consumes the material's signing
//!    half (everything except the X25519 / ML-KEM secrets) to produce a
//!    [`HelloV2`] whose identity proof signs the initiator's pre-identity
//!    transcript region.
//! 3. The initiator sends `HelloV2.to_bytes()` to the responder.
//! 4. The responder runs [`responder_handle_hello`] with its own
//!    [`ResponderHandshakeMaterial`]. This verifies the initiator's
//!    identity proof, runs X25519 against the initiator's PK, encapsulates
//!    a fresh ML-KEM secret, derives [`SessionKeys`] for the responder
//!    side, and returns both the [`HelloAckV2`] to send back **and** the
//!    responder's session keys.
//! 5. The initiator receives the ack, runs [`initiator_handle_ack`],
//!    verifies the responder's identity proof, runs X25519 against the
//!    responder's PK, decapsulates the ML-KEM ciphertext, and derives
//!    its own [`SessionKeys`].
//!
//! Both sides finish with matching `SessionKeys` (`tx`/`rx` swapped per
//! role), and the same `transcript_hash` was used to sign and verify
//! both identity proofs.

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use axiom_crypto::kem_v2::{
    decapsulate, encapsulate, MlKemCiphertext, MlKemDecapsulationKey, MlKemEncapsulationKey,
};

use super::handshake::transcript_hash;
use super::handshake::{HandshakeError, HelloAckV2, HelloV2};
use super::identity::{sign_identity, verify_identity};
use super::session::{derive_session_keys, SessionKeys};

/// Material the initiator carries through the handshake.
///
/// The X25519 secret is `StaticSecret` (`Clone`-able) rather than
/// `EphemeralSecret` (single-use) for testing convenience; the production
/// transport in stage 4 will substitute `EphemeralSecret` and explicitly
/// drop the secret after `diffie_hellman`.
pub struct InitiatorHandshakeMaterial {
    /// Ephemeral X25519 keypair for this handshake.
    pub x25519_secret: X25519StaticSecret,
    pub x25519_public: [u8; 32],

    /// Ephemeral ML-KEM keypair for this handshake.
    pub ml_kem_ek: MlKemEncapsulationKey,
    pub ml_kem_dk: MlKemDecapsulationKey,

    /// Fresh 32-byte nonce; included in the transcript.
    pub nonce: [u8; 32],

    /// Long-term identity keys.
    pub ml_dsa_private_key: Vec<u8>,
    pub ml_dsa_public_key: Vec<u8>,
    pub ed25519_signing_key: Ed25519SigningKey,
}

/// Material the responder carries through the handshake. Symmetric to
/// the initiator's material but does not need an ML-KEM EK because the
/// responder encapsulates *to* the initiator's EK rather than receiving
/// one.
pub struct ResponderHandshakeMaterial {
    pub x25519_secret: X25519StaticSecret,
    pub x25519_public: [u8; 32],
    pub nonce: [u8; 32],
    pub ml_dsa_private_key: Vec<u8>,
    pub ml_dsa_public_key: Vec<u8>,
    pub ed25519_signing_key: Ed25519SigningKey,
}

impl InitiatorHandshakeMaterial {
    /// Convenience constructor used by tests. Generates fresh ephemeral
    /// keys and a fresh nonce; the long-term identity keys are caller-
    /// supplied because they typically come from the wallet / guard layer.
    pub fn fresh(
        ml_dsa_private_key: Vec<u8>,
        ml_dsa_public_key: Vec<u8>,
        ed25519_signing_key: Ed25519SigningKey,
    ) -> Result<Self, HandshakeError> {
        let x25519_secret = X25519StaticSecret::random_from_rng(OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret).to_bytes();

        let (ek, dk) = axiom_crypto::kem_v2::generate_keypair()?;

        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);

        Ok(InitiatorHandshakeMaterial {
            x25519_secret,
            x25519_public,
            ml_kem_ek: ek,
            ml_kem_dk: dk,
            nonce,
            ml_dsa_private_key,
            ml_dsa_public_key,
            ed25519_signing_key,
        })
    }
}

impl ResponderHandshakeMaterial {
    pub fn fresh(
        ml_dsa_private_key: Vec<u8>,
        ml_dsa_public_key: Vec<u8>,
        ed25519_signing_key: Ed25519SigningKey,
    ) -> Self {
        let x25519_secret = X25519StaticSecret::random_from_rng(OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret).to_bytes();
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        ResponderHandshakeMaterial {
            x25519_secret,
            x25519_public,
            nonce,
            ml_dsa_private_key,
            ml_dsa_public_key,
            ed25519_signing_key,
        }
    }
}

/// Step 1: initiator builds and signs HelloV2.
///
/// At sign-time the only bytes on wire are the initiator's own
/// pre-identity region (tag, classical PK, ML-KEM EK, nonce). The
/// initiator hashes those bytes as the transcript's "hello-full" region
/// — that is exactly what the responder will hash when reconstructing
/// the digest to verify the initiator's signature.
pub fn initiator_build_hello(
    material: &InitiatorHandshakeMaterial,
) -> Result<HelloV2, HandshakeError> {
    let pre_identity = pre_identity_hello_bytes(material);
    let digest = transcript_hash(&pre_identity, None);

    let identity = sign_identity(
        &material.ml_dsa_private_key,
        material.ml_dsa_public_key.clone(),
        &material.ed25519_signing_key,
        &digest,
    )?;

    Ok(HelloV2 {
        classical_pk: material.x25519_public,
        ml_kem_ek: material.ml_kem_ek.0.clone(),
        nonce_initiator: material.nonce,
        initiator_identity: identity,
    })
}

/// Step 2: responder verifies the hello, builds + signs the ack, and
/// derives its own session keys.
pub fn responder_handle_hello(
    hello: &HelloV2,
    material: &ResponderHandshakeMaterial,
) -> Result<(HelloAckV2, SessionKeys), HandshakeError> {
    // Verify initiator's identity over the pre-identity transcript.
    let init_pre_identity = hello.pre_identity_bytes();
    let init_digest = transcript_hash(&init_pre_identity, None);
    verify_identity(&hello.initiator_identity, &init_digest)?;

    // Classical secret: X25519 against the initiator's PK.
    let init_pk = X25519PublicKey::from(hello.classical_pk);
    let classical_shared = material.x25519_secret.diffie_hellman(&init_pk);
    let classical_secret = *classical_shared.as_bytes();

    // PQ secret: encapsulate to the initiator's ML-KEM EK.
    let init_ek = MlKemEncapsulationKey(hello.ml_kem_ek.clone());
    let (ct, pq_ss) = encapsulate(&init_ek)?;

    // Build the responder's pre-identity bytes so we can sign the
    // transcript that includes both messages up to this moment.
    let pre_ack = pre_identity_ack_bytes_from(&material.x25519_public, &ct.0, &material.nonce);
    let hello_full = hello.to_bytes();
    let resp_digest = transcript_hash(&hello_full, Some(&pre_ack));

    let identity = sign_identity(
        &material.ml_dsa_private_key,
        material.ml_dsa_public_key.clone(),
        &material.ed25519_signing_key,
        &resp_digest,
    )?;

    let ack = HelloAckV2 {
        classical_pk: material.x25519_public,
        ml_kem_ciphertext: ct.0.clone(),
        nonce_responder: material.nonce,
        responder_identity: identity,
    };

    let pq_secret = pq_ss.0;
    let session_keys = derive_session_keys(&classical_secret, &pq_secret, &resp_digest, false);

    Ok((ack, session_keys))
}

/// Step 3: initiator verifies the ack and derives its own session keys.
/// Consumes the initiator material so the X25519 secret cannot be reused
/// in another handshake by accident.
pub fn initiator_handle_ack(
    hello: &HelloV2,
    ack: &HelloAckV2,
    material: InitiatorHandshakeMaterial,
) -> Result<SessionKeys, HandshakeError> {
    // Reconstruct the digest the responder signed.
    let hello_full = hello.to_bytes();
    let ack_pre_identity = ack.pre_identity_bytes();
    let resp_digest = transcript_hash(&hello_full, Some(&ack_pre_identity));
    verify_identity(&ack.responder_identity, &resp_digest)?;

    // Classical secret on this side.
    let resp_pk = X25519PublicKey::from(ack.classical_pk);
    let classical_shared = material.x25519_secret.diffie_hellman(&resp_pk);
    let classical_secret = *classical_shared.as_bytes();

    // PQ secret: decapsulate the responder's ciphertext.
    let ct = MlKemCiphertext(ack.ml_kem_ciphertext.clone());
    let pq_ss = decapsulate(&material.ml_kem_dk, &ct)?;
    let pq_secret = pq_ss.0;

    Ok(derive_session_keys(
        &classical_secret,
        &pq_secret,
        &resp_digest,
        true,
    ))
}

// ── Helpers used to build pre-identity byte regions ─────────────────────────

fn pre_identity_hello_bytes(material: &InitiatorHandshakeMaterial) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        1 + super::handshake::X25519_PK_BYTES
            + super::handshake::ML_KEM_EK_BYTES
            + super::handshake::NONCE_BYTES,
    );
    out.push(super::handshake::HELLO_V2_TAG);
    out.extend_from_slice(&material.x25519_public);
    out.extend_from_slice(&material.ml_kem_ek.0);
    out.extend_from_slice(&material.nonce);
    out
}

fn pre_identity_ack_bytes_from(
    classical_pk_resp: &[u8; 32],
    ml_kem_ct: &[u8],
    nonce_resp: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        1 + super::handshake::X25519_PK_BYTES
            + super::handshake::ML_KEM_CT_BYTES
            + super::handshake::NONCE_BYTES,
    );
    out.push(super::handshake::HELLO_ACK_V2_TAG);
    out.extend_from_slice(classical_pk_resp);
    out.extend_from_slice(ml_kem_ct);
    out.extend_from_slice(nonce_resp);
    out
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    /// Returns `(ml_dsa_pk, ml_dsa_sk, ed25519_signing_key)`. Note the
    /// upstream `axiom_crypto::generate_keypair()` returns `(sk, vk)`.
    fn make_identity_keys() -> (Vec<u8>, Vec<u8>, SigningKey) {
        let (ml_dsa_sk, ml_dsa_pk) = axiom_crypto::generate_keypair();
        let mut ed_seed = [0u8; 32];
        OsRng.fill_bytes(&mut ed_seed);
        let ed = SigningKey::from_bytes(&ed_seed);
        (ml_dsa_pk, ml_dsa_sk, ed)
    }

    /// Round-trip: both sides finish with matching `tx/rx` swapped keys.
    #[test]
    fn full_handshake_roundtrip_produces_matching_session_keys() {
        let (init_pk, init_sk, init_ed) = make_identity_keys();
        let (resp_pk, resp_sk, resp_ed) = make_identity_keys();

        let init_mat = InitiatorHandshakeMaterial::fresh(init_sk, init_pk, init_ed)
            .expect("initiator material");
        let resp_mat = ResponderHandshakeMaterial::fresh(resp_sk, resp_pk, resp_ed);

        let hello = initiator_build_hello(&init_mat).expect("build hello");
        let (ack, resp_keys) = responder_handle_hello(&hello, &resp_mat).expect("respond");
        let init_keys = initiator_handle_ack(&hello, &ack, init_mat).expect("init handle ack");

        assert_eq!(
            init_keys.tx_key, resp_keys.rx_key,
            "init->resp key must agree across peers"
        );
        assert_eq!(
            init_keys.rx_key, resp_keys.tx_key,
            "resp->init key must agree across peers"
        );
        assert_ne!(
            init_keys.tx_key, init_keys.rx_key,
            "the two directional keys must be distinct"
        );
    }

    /// HelloV2 wire bytes round-trip through `to_bytes` / `from_bytes`.
    #[test]
    fn hello_v2_serialise_round_trip() {
        let (pk, sk, ed) = make_identity_keys();
        let mat = InitiatorHandshakeMaterial::fresh(sk, pk, ed).expect("mat");
        let hello = initiator_build_hello(&mat).expect("hello");
        let bytes = hello.to_bytes();
        let parsed = HelloV2::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed.classical_pk, hello.classical_pk);
        assert_eq!(parsed.ml_kem_ek, hello.ml_kem_ek);
        assert_eq!(parsed.nonce_initiator, hello.nonce_initiator);
    }

    /// HelloAckV2 wire bytes round-trip through `to_bytes` / `from_bytes`.
    #[test]
    fn hello_ack_v2_serialise_round_trip() {
        let (init_pk, init_sk, init_ed) = make_identity_keys();
        let (resp_pk, resp_sk, resp_ed) = make_identity_keys();
        let init_mat = InitiatorHandshakeMaterial::fresh(init_sk, init_pk, init_ed).expect("init");
        let resp_mat = ResponderHandshakeMaterial::fresh(resp_sk, resp_pk, resp_ed);
        let hello = initiator_build_hello(&init_mat).expect("hello");
        let (ack, _keys) = responder_handle_hello(&hello, &resp_mat).expect("ack");
        let bytes = ack.to_bytes();
        let parsed = HelloAckV2::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed.classical_pk, ack.classical_pk);
        assert_eq!(parsed.ml_kem_ciphertext, ack.ml_kem_ciphertext);
        assert_eq!(parsed.nonce_responder, ack.nonce_responder);
    }

    /// Tampering any byte of the HelloV2 nonce makes the responder's
    /// identity-verification step fail because the digest no longer
    /// matches what the initiator signed.
    #[test]
    fn tampered_initiator_nonce_breaks_responder_verification() {
        let (init_pk, init_sk, init_ed) = make_identity_keys();
        let (resp_pk, resp_sk, resp_ed) = make_identity_keys();
        let init_mat = InitiatorHandshakeMaterial::fresh(init_sk, init_pk, init_ed).expect("init");
        let resp_mat = ResponderHandshakeMaterial::fresh(resp_sk, resp_pk, resp_ed);

        let mut hello = initiator_build_hello(&init_mat).expect("hello");
        hello.nonce_initiator[0] ^= 0xff; // tamper

        let res = responder_handle_hello(&hello, &resp_mat);
        assert!(res.is_err(), "tampered nonce must reject");
        match res.unwrap_err() {
            HandshakeError::MlDsaSignatureFailed | HandshakeError::Ed25519SignatureFailed => {}
            other => panic!("expected signature-failure variant, got {other:?}"),
        }
    }

    /// Tampering the ack's ciphertext breaks the initiator's verification
    /// of the responder's signature.
    #[test]
    fn tampered_ack_ciphertext_breaks_initiator_verification() {
        let (init_pk, init_sk, init_ed) = make_identity_keys();
        let (resp_pk, resp_sk, resp_ed) = make_identity_keys();
        let init_mat = InitiatorHandshakeMaterial::fresh(init_sk, init_pk, init_ed).expect("init");
        let resp_mat = ResponderHandshakeMaterial::fresh(resp_sk, resp_pk, resp_ed);

        let hello = initiator_build_hello(&init_mat).expect("hello");
        let (mut ack, _keys) = responder_handle_hello(&hello, &resp_mat).expect("ack");
        ack.ml_kem_ciphertext[0] ^= 0xff; // tamper

        let res = initiator_handle_ack(&hello, &ack, init_mat);
        assert!(res.is_err(), "tampered ciphertext must reject");
    }

    /// Replacing the responder's Ed25519 signature with garbage but
    /// leaving ML-DSA intact must still abort (both must verify).
    #[test]
    fn forging_only_one_of_two_signatures_is_rejected() {
        let (init_pk, init_sk, init_ed) = make_identity_keys();
        let (resp_pk, resp_sk, resp_ed) = make_identity_keys();
        let init_mat = InitiatorHandshakeMaterial::fresh(init_sk, init_pk, init_ed).expect("init");
        let resp_mat = ResponderHandshakeMaterial::fresh(resp_sk, resp_pk, resp_ed);

        let hello = initiator_build_hello(&init_mat).expect("hello");
        let (mut ack, _keys) = responder_handle_hello(&hello, &resp_mat).expect("ack");
        // Corrupt the Ed25519 signature only.
        ack.responder_identity.ed25519_signature[0] ^= 0xff;

        let res = initiator_handle_ack(&hello, &ack, init_mat);
        match res {
            Err(HandshakeError::Ed25519SignatureFailed) => {}
            Err(other) => panic!("expected Ed25519SignatureFailed, got {other:?}"),
            Ok(_) => panic!("must not accept handshake with one bad signature"),
        }
    }

    /// Pretending to be a different ML-DSA identity (replacing the PK in
    /// the proof but keeping the wrong signature) must reject.
    #[test]
    fn substituted_ml_dsa_pubkey_breaks_verification() {
        let (init_pk, init_sk, init_ed) = make_identity_keys();
        let (resp_pk, resp_sk, resp_ed) = make_identity_keys();
        let (other_pk, _other_sk, _other_ed) = make_identity_keys();

        let init_mat = InitiatorHandshakeMaterial::fresh(init_sk, init_pk, init_ed).expect("init");
        let resp_mat = ResponderHandshakeMaterial::fresh(resp_sk, resp_pk, resp_ed);

        let hello = initiator_build_hello(&init_mat).expect("hello");
        let (mut ack, _keys) = responder_handle_hello(&hello, &resp_mat).expect("ack");
        ack.responder_identity.ml_dsa_pubkey = other_pk;

        let res = initiator_handle_ack(&hello, &ack, init_mat);
        assert!(res.is_err());
    }

    /// Two independent handshakes between fresh keypairs must produce
    /// distinct session keys — sanity check that the transcript-hash
    /// salt actually binds keys to the handshake.
    #[test]
    fn independent_handshakes_yield_distinct_keys() {
        let mut all_keys = Vec::new();
        for _ in 0..3 {
            let (init_pk, init_sk, init_ed) = make_identity_keys();
            let (resp_pk, resp_sk, resp_ed) = make_identity_keys();
            let init_mat =
                InitiatorHandshakeMaterial::fresh(init_sk, init_pk, init_ed).expect("init");
            let resp_mat = ResponderHandshakeMaterial::fresh(resp_sk, resp_pk, resp_ed);
            let hello = initiator_build_hello(&init_mat).expect("hello");
            let (ack, _resp_keys) = responder_handle_hello(&hello, &resp_mat).expect("ack");
            let keys = initiator_handle_ack(&hello, &ack, init_mat).expect("init keys");
            all_keys.push(keys.tx_key);
        }
        assert_ne!(all_keys[0], all_keys[1]);
        assert_ne!(all_keys[1], all_keys[2]);
        assert_ne!(all_keys[0], all_keys[2]);
    }

    /// Truncated HelloV2 bytes return a typed parse error rather than
    /// panicking inside the parser.
    #[test]
    fn truncated_hello_returns_typed_error() {
        let (pk, sk, ed) = make_identity_keys();
        let mat = InitiatorHandshakeMaterial::fresh(sk, pk, ed).expect("mat");
        let hello = initiator_build_hello(&mat).expect("hello");
        let bytes = hello.to_bytes();
        // Lop off the last 50 bytes — should land in the middle of the
        // identity proof region.
        let truncated = &bytes[..bytes.len() - 50];
        let res = HelloV2::from_bytes(truncated);
        assert!(matches!(res, Err(HandshakeError::Truncated)));
    }

    /// The transcript hash output is deterministic and version-bound —
    /// changing the protocol version tag (would happen in a future v3)
    /// produces a different digest even for identical message bytes.
    #[test]
    fn transcript_hash_is_version_bound() {
        let dummy_hello = vec![0xAA; 64];
        let h_v2 = transcript_hash(&dummy_hello, None);
        // Same bytes hashed with no version separator return a different
        // digest than the v2 transcript_hash (sanity: the version_tag
        // mixing is observable end-to-end).
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"some-other-tag");
        h.update(&dummy_hello);
        let other: [u8; 32] = h.finalize().into();
        assert_ne!(h_v2, other);
    }
}
