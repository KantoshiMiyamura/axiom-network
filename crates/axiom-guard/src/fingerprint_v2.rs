// Copyright (c) 2026 Kantoshi Miyamura

//! Hybrid v2 node fingerprint — stage 5 of `docs/V2_PROTOCOL.md §8`.
//!
//! A v2 peer's identity is the pair (`ml_dsa_pubkey`, `ed25519_pubkey`).
//! This module turns that pair into a stable 32-byte [`PeerId`] that:
//!
//! - is deterministic in the keys (same keys → same ID, forever);
//! - changes if **either** key changes (no key-substitution attack can
//!   keep the same ID);
//! - is domain-separated from every other hash use in the codebase via
//!   [`FINGERPRINT_V2_TAG`] so a future hash extension cannot collide
//!   with an unrelated digest.
//!
//! The peer ID is **derived from the long-term identity keys only** — not
//! from the handshake transcript, the ephemeral X25519 / ML-KEM keys, or
//! any session-specific value. That is the whole point: the ID lets the
//! caller cache "address X belongs to peer Y" across reconnections, and
//! reject a session at address X that produces a different Y as a key
//! rotation that needs explicit operator opt-in.
//!
//! INVARIANT: this module is read-only with respect to consensus, the
//! mempool, the chain state, and the wallet. It computes hashes from
//! caller-supplied bytes; it does no I/O and stores no state.
//!
//! **Not wired into the runtime.** The v2 handshake in
//! `axiom-node::network::p2p_v2` does not consult this module yet —
//! integration is the boundary between this stage and stage 6.

use thiserror::Error;

/// Length in bytes of a [`PeerId`].
pub const PEER_ID_BYTES: usize = 32;

/// Domain-separation tag for the peer-id hash. Changing this string
/// produces an entirely disjoint identity space — a v1 fingerprint
/// hashed with `axiom-id-v1` (does not exist today; reserved if v1
/// ever gets a fingerprint scheme) cannot collide with a v2 ID.
pub const FINGERPRINT_V2_TAG: &[u8] = b"axiom-id-v2";

/// Length in bytes of an Ed25519 public key (RFC 8032 §3).
pub const ED25519_PUBKEY_BYTES: usize = 32;

/// Stable v2 peer identifier. Equality is byte-for-byte; clone is cheap.
///
/// Display is hex-lowercase. Debug is also hex but wrapped so it
/// renders as `PeerId(<hex>)` in formatted output. Neither leaks
/// underlying key material — the ID is a public hash of public keys.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId([u8; PEER_ID_BYTES]);

impl PeerId {
    /// Construct directly from the underlying bytes. Useful when reading
    /// a previously-computed ID from configuration or the address book.
    pub fn from_bytes(bytes: [u8; PEER_ID_BYTES]) -> Self {
        PeerId(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; PEER_ID_BYTES] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PeerId({})", hex::encode(self.0))
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

#[derive(Error, Debug)]
pub enum FingerprintV2Error {
    #[error(
        "ed25519 pubkey length: expected {expected}, got {actual}",
        expected = ED25519_PUBKEY_BYTES
    )]
    InvalidEd25519PubkeyLength { actual: usize },

    #[error(
        "announced peer id does not match computed id from received pubkeys: announced={announced}, computed={computed}"
    )]
    AnnouncedIdMismatch { announced: PeerId, computed: PeerId },
}

/// Compute the canonical [`PeerId`] from the pair of v2 identity public
/// keys. Hash construction:
///
/// ```text
///     SHA-256-tagged(
///         FINGERPRINT_V2_TAG,
///         u32 LE ml_dsa_len || ml_dsa_pubkey || ed25519_pubkey
///     )
/// ```
///
/// The length prefix on the ML-DSA pubkey eliminates concatenation
/// boundary ambiguity — `("aab", "cd")` and `("aa", "bcd")` produce
/// distinct preimages. Same rationale as
/// [`axiom_crypto::transaction_signing_hash`] in the v1 codebase.
pub fn compute_peer_id(
    ml_dsa_pubkey: &[u8],
    ed25519_pubkey: &[u8; ED25519_PUBKEY_BYTES],
) -> PeerId {
    let mut preimage = Vec::with_capacity(4 + ml_dsa_pubkey.len() + ED25519_PUBKEY_BYTES);
    preimage.extend_from_slice(&(ml_dsa_pubkey.len() as u32).to_le_bytes());
    preimage.extend_from_slice(ml_dsa_pubkey);
    preimage.extend_from_slice(ed25519_pubkey);
    let h = axiom_crypto::tagged_hash(FINGERPRINT_V2_TAG, &preimage);
    PeerId(*h.as_bytes())
}

/// Verify that an `announced` peer id matches the keys carried in the
/// proof. This is what the receiver runs at handshake time when the
/// dialer (or an out-of-band record) named the peer it expected to talk
/// to: if the keys we just observed do not hash to that announced ID,
/// the connection is **either a key-substitution attack or a key
/// rotation** and must be refused at the handshake layer.
///
/// Returns `Ok(())` only when `announced == compute_peer_id(...)`.
pub fn verify_announced_peer_id(
    announced: &PeerId,
    ml_dsa_pubkey: &[u8],
    ed25519_pubkey: &[u8; ED25519_PUBKEY_BYTES],
) -> Result<(), FingerprintV2Error> {
    let computed = compute_peer_id(ml_dsa_pubkey, ed25519_pubkey);
    if &computed == announced {
        Ok(())
    } else {
        Err(FingerprintV2Error::AnnouncedIdMismatch {
            announced: *announced,
            computed,
        })
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: deterministic key fixtures so tests do not depend on RNG
    /// state. The bytes are not real ML-DSA / Ed25519 keys; this module
    /// hashes its inputs and never tries to verify them, so any byte
    /// pattern is acceptable for these unit tests.
    fn fake_ml_dsa_pk(seed: u8) -> Vec<u8> {
        // Real ML-DSA-87 verification key is 2592 bytes; we use a
        // similar shape so the hash exercises a realistic preimage size.
        vec![seed; 2592]
    }

    fn fake_ed25519_pk(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    /// Determinism: same keys produce the same peer id every time.
    #[test]
    fn compute_peer_id_is_deterministic() {
        let ml = fake_ml_dsa_pk(0x11);
        let ed = fake_ed25519_pk(0x22);
        let id1 = compute_peer_id(&ml, &ed);
        let id2 = compute_peer_id(&ml, &ed);
        assert_eq!(id1, id2);
        assert_eq!(id1.as_bytes().len(), PEER_ID_BYTES);
    }

    /// Different ML-DSA pubkey → different ID. This catches a
    /// key-substitution attempt where the attacker tries to keep the
    /// Ed25519 key but swap the ML-DSA key for one they control.
    #[test]
    fn changing_ml_dsa_changes_id() {
        let ed = fake_ed25519_pk(0x22);
        let id_a = compute_peer_id(&fake_ml_dsa_pk(0x11), &ed);
        let id_b = compute_peer_id(&fake_ml_dsa_pk(0x12), &ed);
        assert_ne!(id_a, id_b);
    }

    /// Different Ed25519 pubkey → different ID. Symmetric to the above:
    /// substituting Ed25519 alone also breaks the ID.
    #[test]
    fn changing_ed25519_changes_id() {
        let ml = fake_ml_dsa_pk(0x11);
        let id_a = compute_peer_id(&ml, &fake_ed25519_pk(0x22));
        let id_b = compute_peer_id(&ml, &fake_ed25519_pk(0x23));
        assert_ne!(id_a, id_b);
    }

    /// Single-bit flips in either key produce a different ID — verifies
    /// the hash is not silently ignoring the trailing bytes of either
    /// input region.
    #[test]
    fn single_bit_flip_in_either_key_changes_id() {
        let ml = fake_ml_dsa_pk(0x55);
        let ed = fake_ed25519_pk(0x66);
        let baseline = compute_peer_id(&ml, &ed);

        let mut ml_flipped = ml.clone();
        let last = ml_flipped.len() - 1;
        ml_flipped[last] ^= 0x01;
        assert_ne!(compute_peer_id(&ml_flipped, &ed), baseline);

        let mut ed_flipped = ed;
        ed_flipped[31] ^= 0x01;
        assert_ne!(compute_peer_id(&ml, &ed_flipped), baseline);
    }

    /// Length-prefix anti-collision: `("ab", "cd")` and `("a", "bcd")`
    /// must produce different IDs even though the concatenation
    /// `ab || cd == a || bcd` would not. Locks in the same property
    /// `transaction_signing_hash` enforces in axiom-crypto.
    #[test]
    fn length_prefix_disambiguates_concatenation() {
        let ml_a: Vec<u8> = b"ab".to_vec();
        let ed_a = {
            let mut e = [0u8; 32];
            e[..2].copy_from_slice(b"cd");
            e
        };
        let ml_b: Vec<u8> = b"a".to_vec();
        let ed_b = {
            let mut e = [0u8; 32];
            e[..3].copy_from_slice(b"bcd");
            e
        };
        let id_a = compute_peer_id(&ml_a, &ed_a);
        let id_b = compute_peer_id(&ml_b, &ed_b);
        assert_ne!(id_a, id_b);
    }

    /// Cross-session stability: two simulated handshakes with the same
    /// long-term keys but different ephemeral material (different
    /// transcripts, different session keys) MUST yield the same peer
    /// ID. This is the whole point of having a peer ID — it lets the
    /// caller cache "this address belongs to this peer" across
    /// reconnections.
    #[test]
    fn peer_id_is_stable_across_sessions() {
        // Same long-term identity.
        let ml = fake_ml_dsa_pk(0xAB);
        let ed = fake_ed25519_pk(0xCD);

        // "Session 1" and "Session 2" each have their own ephemeral
        // X25519 / ML-KEM material and transcript, but the only thing
        // that feeds the peer-id is the long-term identity, so the
        // peer-id is unchanged.
        let id_session1 = compute_peer_id(&ml, &ed);
        let id_session2 = compute_peer_id(&ml, &ed);

        assert_eq!(id_session1, id_session2);
    }

    /// verify_announced_peer_id accepts a matching announced ID.
    #[test]
    fn verify_accepts_matching_announced_id() {
        let ml = fake_ml_dsa_pk(0x77);
        let ed = fake_ed25519_pk(0x88);
        let announced = compute_peer_id(&ml, &ed);
        assert!(verify_announced_peer_id(&announced, &ml, &ed).is_ok());
    }

    /// verify_announced_peer_id rejects a mismatched announced ID, and
    /// the rejection error names both ids so the operator log shows
    /// which side disagreed.
    #[test]
    fn verify_rejects_mismatched_announced_id() {
        let ml = fake_ml_dsa_pk(0x77);
        let ed = fake_ed25519_pk(0x88);
        let computed = compute_peer_id(&ml, &ed);

        // Pretend the dialer announced a different ID.
        let mut wrong = *computed.as_bytes();
        wrong[0] ^= 0xFF;
        let wrong_id = PeerId::from_bytes(wrong);

        let res = verify_announced_peer_id(&wrong_id, &ml, &ed);
        match res {
            Err(FingerprintV2Error::AnnouncedIdMismatch {
                announced,
                computed: returned,
            }) => {
                assert_eq!(announced, wrong_id);
                assert_eq!(returned, computed);
            }
            other => panic!("expected AnnouncedIdMismatch, got {other:?}"),
        }
    }

    /// verify_announced_peer_id rejects key substitution: announce ID
    /// derived from one keypair, present a different keypair on the
    /// wire — must reject. This is the canonical MITM defence at the
    /// peer-id layer.
    #[test]
    fn verify_rejects_key_substitution() {
        // Honest peer's announced ID.
        let ml_honest = fake_ml_dsa_pk(0x11);
        let ed_honest = fake_ed25519_pk(0x22);
        let announced = compute_peer_id(&ml_honest, &ed_honest);

        // Attacker presents a substituted Ed25519 pubkey.
        let ed_attacker = fake_ed25519_pk(0x99);
        let res = verify_announced_peer_id(&announced, &ml_honest, &ed_attacker);
        assert!(matches!(
            res,
            Err(FingerprintV2Error::AnnouncedIdMismatch { .. })
        ));

        // ...or a substituted ML-DSA pubkey.
        let ml_attacker = fake_ml_dsa_pk(0x99);
        let res = verify_announced_peer_id(&announced, &ml_attacker, &ed_honest);
        assert!(matches!(
            res,
            Err(FingerprintV2Error::AnnouncedIdMismatch { .. })
        ));
    }

    /// PeerId Display / Debug never embed key material directly — the
    /// peer id IS the public hash of public keys, and is itself public,
    /// but we verify the format is stable hex so log parsers do not
    /// have to handle multiple representations.
    #[test]
    fn peer_id_formats_are_hex_lowercase() {
        let ml = fake_ml_dsa_pk(0xFE);
        let ed = fake_ed25519_pk(0xDC);
        let id = compute_peer_id(&ml, &ed);

        let disp = format!("{}", id);
        let dbg = format!("{:?}", id);
        let hex = id.to_hex();

        assert_eq!(disp.len(), 64);
        assert!(disp
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert!(dbg.starts_with("PeerId("));
        assert!(dbg.contains(&hex));
        assert_eq!(disp, hex);
    }

    /// The PEER_ID_BYTES constant matches the SHA-256 output size.
    /// Locks the assumption — if `tagged_hash`'s output ever changes
    /// length this will break loudly.
    #[test]
    fn peer_id_is_32_bytes() {
        let id = compute_peer_id(&fake_ml_dsa_pk(0), &fake_ed25519_pk(0));
        assert_eq!(id.as_bytes().len(), 32);
        assert_eq!(PEER_ID_BYTES, 32);
    }

    /// PeerId round-trips through bytes.
    #[test]
    fn peer_id_from_bytes_round_trip() {
        let bytes = [42u8; PEER_ID_BYTES];
        let id = PeerId::from_bytes(bytes);
        assert_eq!(id.as_bytes(), &bytes);
        let id2 = PeerId::from_bytes(*id.as_bytes());
        assert_eq!(id, id2);
    }
}
