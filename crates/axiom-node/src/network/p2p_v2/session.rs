// Copyright (c) 2026 Kantoshi Miyamura

//! v2 session-key derivation. Spec: `V2_PROTOCOL.md §4.2`.
//!
//! Derives two ChaCha20-Poly1305 keys from the (classical || PQ) shared
//! secret concatenation. The HKDF stage takes the transcript hash as
//! salt — binding the keys to this exact handshake — and uses
//! direction-tagged `info` strings so the AEAD key for `init -> resp`
//! traffic is independent of the key for `resp -> init`.
//!
//! Drop manually clears the key bytes; we keep this module free of a
//! `zeroize` crate dependency until stage 4 wires the live transport.
//! At that point the wipe should be promoted to `zeroize` so it survives
//! compiler optimisation.

use hkdf::Hkdf;
use sha2::Sha256;

use super::{V2_KEY_INFO_INIT_TO_RESP, V2_KEY_INFO_RESP_TO_INIT, V2_SESSION_INFO};

/// Per-direction symmetric keys for the AEAD transport. ChaCha20-Poly1305
/// keys are 32 bytes; nonces are framed per-message in the transport
/// layer (see `V2_PROTOCOL.md §4.4`).
#[derive(Clone)]
pub struct SessionKeys {
    pub rx_key: [u8; 32],
    pub tx_key: [u8; 32],
}

impl SessionKeys {
    /// Placeholder constructor used by tests that need a value-shaped key.
    /// Calling code must replace it with the output of
    /// [`derive_session_keys`] before using it for real traffic.
    pub fn zero() -> Self {
        Self {
            rx_key: [0u8; 32],
            tx_key: [0u8; 32],
        }
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        for b in self.rx_key.iter_mut() {
            *b = 0;
        }
        for b in self.tx_key.iter_mut() {
            *b = 0;
        }
    }
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("rx_key", &"[redacted; 32 bytes]")
            .field("tx_key", &"[redacted; 32 bytes]")
            .finish()
    }
}

/// Derive `(rx_key, tx_key)` for one side of the handshake.
///
/// `is_initiator = true` returns `tx_key = init->resp, rx_key = resp->init`.
/// `is_initiator = false` returns the reverse — same shared secret, but
/// the role of each direction is swapped so each side can `tx`-encrypt
/// with one key and `rx`-decrypt with the other without the peer ever
/// using the same key for both directions.
pub fn derive_session_keys(
    classical_secret: &[u8; 32],
    pq_secret: &[u8; 32],
    transcript_hash: &[u8; 32],
    is_initiator: bool,
) -> SessionKeys {
    // IKM for HKDF is the concatenation of the two shared secrets so the
    // adversary needs to break both X25519 and ML-KEM-768 to recover the
    // session keys (the standard hybrid construction).
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(classical_secret);
    ikm[32..].copy_from_slice(pq_secret);

    // Salt is the transcript hash — binds the keys to this specific
    // handshake. Different transcript = different keys.
    let hkdf = Hkdf::<Sha256>::new(Some(transcript_hash), &ikm);

    // Both sides expand to the same direction-tagged keys, then assign
    // tx/rx based on role.
    let mut init_to_resp = [0u8; 32];
    let mut resp_to_init = [0u8; 32];

    // Two-step expand: first extract a session-bound PRK with V2_SESSION_INFO,
    // then expand that into directional keys. Equivalently we could expand
    // from `hkdf` directly with the per-direction info strings; we keep the
    // two-step form because it matches the spec's narrative in §4.2 and
    // makes future expansions (replay-window key, rekey trigger, etc.)
    // straightforward to add.
    let mut session_prk_buf = [0u8; 32];
    hkdf.expand(V2_SESSION_INFO, &mut session_prk_buf)
        .expect("HKDF expand of 32 bytes never fails");
    let session_hkdf = Hkdf::<Sha256>::from_prk(&session_prk_buf)
        .expect("32-byte PRK is always valid for HKDF<SHA-256>");

    session_hkdf
        .expand(V2_KEY_INFO_INIT_TO_RESP, &mut init_to_resp)
        .expect("HKDF expand of 32 bytes never fails");
    session_hkdf
        .expand(V2_KEY_INFO_RESP_TO_INIT, &mut resp_to_init)
        .expect("HKDF expand of 32 bytes never fails");

    // Wipe local IKM and intermediate PRK after use.
    for b in ikm.iter_mut() {
        *b = 0;
    }
    for b in session_prk_buf.iter_mut() {
        *b = 0;
    }

    if is_initiator {
        SessionKeys {
            tx_key: init_to_resp,
            rx_key: resp_to_init,
        }
    } else {
        SessionKeys {
            tx_key: resp_to_init,
            rx_key: init_to_resp,
        }
    }
}
