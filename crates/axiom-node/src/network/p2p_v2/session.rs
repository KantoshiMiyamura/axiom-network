// Copyright (c) 2026 Kantoshi Miyamura

//! v2 session-key derivation — skeleton. Spec: V2_PROTOCOL.md §4.2.
//!
//! Drop manually clears the key bytes; we keep this skeleton free of a
//! `zeroize` crate dependency so the v2 module surface compiles without
//! adding to `axiom-node`'s dep graph until stage 3 actually wires the
//! transport. When stage 3 lands the wipe should be promoted to `zeroize`
//! so it survives compiler optimisation.

/// Per-direction symmetric keys for the AEAD transport. ChaCha20-Poly1305
/// keys are 32 bytes; nonces are framed per-message in the transport layer
/// (see V2_PROTOCOL.md §4.4).
#[derive(Clone)]
pub struct SessionKeys {
    pub rx_key: [u8; 32],
    pub tx_key: [u8; 32],
}

impl SessionKeys {
    /// Placeholder constructor used by tests that need a value-shaped key
    /// (it does not authenticate anything; calling code must replace it
    /// with a real derive once stage 3 lands).
    pub fn zero() -> Self {
        Self {
            rx_key: [0u8; 32],
            tx_key: [0u8; 32],
        }
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        // Best-effort wipe. `volatile_set_memory` is unstable, so we use the
        // standard fill — the optimiser may elide it on a non-`#[inline(never)]`
        // call site, which is why stage 3 must replace this with `zeroize`.
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
        // Never print key material, even in debug. Length only.
        f.debug_struct("SessionKeys")
            .field("rx_key", &"[redacted; 32 bytes]")
            .field("tx_key", &"[redacted; 32 bytes]")
            .finish()
    }
}

/// Derive `(rx_key, tx_key)` from the classical and post-quantum shared
/// secrets. Stub — stage 3 in V2_PROTOCOL.md §8.
pub fn derive_session_keys(
    _classical_secret: &[u8; 32],
    _pq_secret: &[u8; 32],
    _transcript_hash: &[u8; 32],
    _is_initiator: bool,
) -> SessionKeys {
    unimplemented!("stage 3 — V2_PROTOCOL.md §4.2")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-only sanity: the skeleton type is constructible and its
    /// Debug impl never leaks key bytes.
    #[test]
    fn session_keys_debug_does_not_leak() {
        let keys = SessionKeys::zero();
        let s = format!("{:?}", keys);
        assert!(s.contains("redacted"));
        assert!(!s.contains("[0, 0, 0"));
    }
}
