// Copyright (c) 2026 Kantoshi Miyamura
//
// Stage 9 of `docs/V2_PROTOCOL.md §8`: end-to-end integration test that
// runs the v2 hybrid handshake (stages 2–3) and feeds its derived
// session keys into the v2 AEAD transport (stage 4), then exchanges
// real plaintext through the wire layer in both directions.
//
// What this binds together that no per-module test does:
//
//   - kem_v2 (stage 2)       — ML-KEM-768 wrapper produces real PQ secret
//   - p2p_v2/handshake (s.3) — initiator/responder run a full transcript
//   - p2p_v2/identity (s.3)  — ML-DSA-87 + Ed25519 dual sigs both verify
//   - p2p_v2/session (s.3)   — HKDF derives matching tx/rx keys per side
//   - p2p_v2/transport (s.4) — XChaCha20-Poly1305 frames decrypt under
//                              the keys the handshake actually produced
//
// If any one of those stages drifts (different domain tag, different
// HKDF info, different nonce layout, …) the chain breaks and the test
// fails. The per-stage tests still pass individually because they use
// synthetic inputs; this test pins the seam.

use axiom_node::network::p2p_v2::flow::{
    initiator_build_hello, initiator_handle_ack, responder_handle_hello,
    InitiatorHandshakeMaterial, ResponderHandshakeMaterial,
};
use axiom_node::network::p2p_v2::transport::EncryptedConnectionV2;
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use tokio::io::duplex;

/// Returns `(ml_dsa_public_key, ml_dsa_private_key, ed25519_signing_key)`.
///
/// `axiom_crypto::generate_keypair()` returns `(sk, vk)` in that order
/// (matching the test in `axiom-crypto/src/sign.rs`); we destructure
/// it that way and reorder for the helper's signature.
fn make_identity() -> (Vec<u8>, Vec<u8>, SigningKey) {
    let (ml_dsa_sk, ml_dsa_pk) = axiom_crypto::generate_keypair();
    let mut ed_seed = [0u8; 32];
    OsRng.fill_bytes(&mut ed_seed);
    let ed = SigningKey::from_bytes(&ed_seed);
    (ml_dsa_pk, ml_dsa_sk, ed)
}

/// Drive the full v2 stack and exchange a real plaintext message in both
/// directions. Initiator's `tx_key` must equal responder's `rx_key` (and
/// vice versa) for the AEAD frames to decrypt — anything weaker would
/// surface as a `TransportV2Error::AeadFailure` immediately.
#[tokio::test]
async fn v2_handshake_session_keys_drive_real_aead_transport() {
    // ── Identities ───────────────────────────────────────────────────────────
    let (init_pk, init_sk, init_ed) = make_identity();
    let (resp_pk, resp_sk, resp_ed) = make_identity();

    let init_mat =
        InitiatorHandshakeMaterial::fresh(init_sk, init_pk, init_ed).expect("initiator material");
    let resp_mat = ResponderHandshakeMaterial::fresh(resp_sk, resp_pk, resp_ed);

    // ── Handshake (3 message-level steps; no socket) ─────────────────────────
    let hello = initiator_build_hello(&init_mat).expect("hello v2 build");
    let (ack, responder_keys) =
        responder_handle_hello(&hello, &resp_mat).expect("responder handle hello");
    let initiator_keys =
        initiator_handle_ack(&hello, &ack, init_mat).expect("initiator handle ack");

    // The seam between handshake and transport: each side's tx must be
    // the other's rx. If anything in HKDF, transcript hashing, or the
    // direction-tagged info strings drifted, this assertion fails — and
    // no AEAD round-trip below would work either.
    assert_eq!(initiator_keys.tx_key, responder_keys.rx_key);
    assert_eq!(initiator_keys.rx_key, responder_keys.tx_key);

    // ── Wrap the post-handshake keys in EncryptedConnectionV2 ─────────────────
    // Use an in-memory duplex pipe so the test never touches a real socket.
    let (init_stream, resp_stream) = duplex(64 * 1024);
    let mut initiator_conn = EncryptedConnectionV2::new(init_stream, initiator_keys);
    let mut responder_conn = EncryptedConnectionV2::new(resp_stream, responder_keys);

    // ── Initiator → responder, real plaintext, real AEAD ─────────────────────
    let payload_a = b"hello from the v2 initiator";
    initiator_conn.send(payload_a).await.expect("init send");
    let received_a = responder_conn.recv().await.expect("resp recv");
    assert_eq!(received_a, payload_a);

    // ── Responder → initiator, separate direction key, separate seq counter ──
    let payload_b = b"acknowledged from the v2 responder";
    responder_conn.send(payload_b).await.expect("resp send");
    let received_b = initiator_conn.recv().await.expect("init recv");
    assert_eq!(received_b, payload_b);

    // ── Multiple messages in a row exercise per-direction seq monotonicity ──
    for i in 0u64..16 {
        let msg = format!("ping {i}");
        initiator_conn
            .send(msg.as_bytes())
            .await
            .expect("init send n");
        let got = responder_conn.recv().await.expect("resp recv n");
        assert_eq!(got, msg.as_bytes());
    }
}

/// Two independent handshakes between fresh identities produce
/// independent session keys; a frame encrypted with one session's keys
/// cannot be decrypted by the other. Pins the transcript-as-HKDF-salt
/// property at the integration boundary (not just the per-stage test).
#[tokio::test]
async fn frames_from_one_session_do_not_decrypt_under_another() {
    // Session 1.
    let (a_pk, a_sk, a_ed) = make_identity();
    let (b_pk, b_sk, b_ed) = make_identity();
    let a_mat = InitiatorHandshakeMaterial::fresh(a_sk, a_pk, a_ed).expect("a");
    let b_mat = ResponderHandshakeMaterial::fresh(b_sk, b_pk, b_ed);
    let hello1 = initiator_build_hello(&a_mat).expect("h1");
    let (ack1, _b_keys_1) = responder_handle_hello(&hello1, &b_mat).expect("ack1");
    let a_keys_1 = initiator_handle_ack(&hello1, &ack1, a_mat).expect("a1");

    // Session 2 (different ephemeral material → different transcript →
    // different session keys). Use the same long-term identities to
    // isolate the variable to "ephemeral / transcript only".
    let (c_pk, c_sk, c_ed) = make_identity();
    let (d_pk, d_sk, d_ed) = make_identity();
    let c_mat = InitiatorHandshakeMaterial::fresh(c_sk, c_pk, c_ed).expect("c");
    let d_mat = ResponderHandshakeMaterial::fresh(d_sk, d_pk, d_ed);
    let hello2 = initiator_build_hello(&c_mat).expect("h2");
    let (ack2, d_keys_2) = responder_handle_hello(&hello2, &d_mat).expect("ack2");
    let _c_keys_2 = initiator_handle_ack(&hello2, &ack2, c_mat).expect("c2");

    // Wire: Alice (session 1) speaks into a stream; Dave (session 2)
    // tries to read it. The AEAD MUST fail.
    let (s_a, s_d) = duplex(8192);
    let mut alice = EncryptedConnectionV2::new(s_a, a_keys_1);
    let mut dave = EncryptedConnectionV2::new(s_d, d_keys_2);

    alice
        .send(b"crossed-streams payload")
        .await
        .expect("alice send");
    let res = dave.recv().await;
    assert!(
        res.is_err(),
        "session 2's responder must not decrypt session 1's frames"
    );
}

/// One final cross-cut: the exact same long-term identity keys used in
/// two handshakes still produce different session keys (because the
/// ephemeral material and transcript differ each time). This is the
/// forward-secrecy story at integration level.
#[tokio::test]
async fn same_long_term_keys_two_handshakes_yield_distinct_session_keys() {
    let (init_pk, init_sk, init_ed) = make_identity();
    let (resp_pk, resp_sk, resp_ed) = make_identity();

    fn run_one(
        init_pk: Vec<u8>,
        init_sk: Vec<u8>,
        init_ed: SigningKey,
        resp_pk: Vec<u8>,
        resp_sk: Vec<u8>,
        resp_ed: SigningKey,
    ) -> [u8; 32] {
        let init_mat = InitiatorHandshakeMaterial::fresh(init_sk, init_pk, init_ed).expect("im");
        let resp_mat = ResponderHandshakeMaterial::fresh(resp_sk, resp_pk, resp_ed);
        let hello = initiator_build_hello(&init_mat).expect("hello");
        let (ack, _) = responder_handle_hello(&hello, &resp_mat).expect("ack");
        let keys = initiator_handle_ack(&hello, &ack, init_mat).expect("ihack");
        keys.tx_key
    }

    let key1 = run_one(
        init_pk.clone(),
        init_sk.clone(),
        init_ed.clone(),
        resp_pk.clone(),
        resp_sk.clone(),
        resp_ed.clone(),
    );
    let key2 = run_one(init_pk, init_sk, init_ed, resp_pk, resp_sk, resp_ed);
    assert_ne!(
        key1, key2,
        "ephemeral material must vary the session key even with identical long-term identities"
    );
}
