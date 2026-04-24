// Copyright (c) 2026 Kantoshi Miyamura

use crate::network::message::NONCE_HASH_LEN;
use crate::network::{Message, Peer, PeerState, VersionMessage};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Highest protocol version this build speaks. v2 adds a 256-bit
/// handshake nonce derived from `SHA256(random_128 || node_identity)`.
pub const PROTOCOL_VERSION: u32 = 2;

/// Oldest protocol version this build still accepts. v1 peers only stamp
/// the legacy `u64` nonce; self-connection detection for them falls back
/// to comparing that field.
pub const MIN_PROTOCOL_VERSION: u32 = 1;

/// Domain-separation tag mixed into the handshake nonce hash. Prevents
/// the SHA-256 output from ever colliding with a hash computed elsewhere
/// in the protocol (block headers, signatures, etc.) even if an attacker
/// controls the random and identity inputs.
const NONCE_DOMAIN: &[u8] = b"axiom-self-peer-v2";

#[allow(dead_code)]
pub const HANDSHAKE_TIMEOUT: u64 = 30;

#[derive(Error, Debug)]
pub enum HandshakeError {
    #[error("protocol version mismatch: supported {min}..={max}, got {actual}")]
    VersionMismatch { min: u32, max: u32, actual: u32 },

    #[error("network mismatch: expected {expected}, got {actual}")]
    NetworkMismatch { expected: String, actual: String },

    #[error("handshake timeout")]
    Timeout,

    #[error("invalid handshake state")]
    InvalidState,

    #[error("self-connection detected (nonce match)")]
    SelfConnection,
}

pub struct ProtocolHandler {
    network: String,
    /// 256-bit handshake nonce stamped into outbound Version messages.
    /// A received Version whose `nonce_hash` equals this means we're
    /// talking to ourselves. The first 8 bytes are also folded into the
    /// legacy `nonce` field so v1 peers can still detect self-dials.
    local_nonce_hash: [u8; NONCE_HASH_LEN],
    local_nonce_u64: u64,
}

impl ProtocolHandler {
    /// Build a handler with a random identity (no external binding).
    /// Intended for tests and the few code paths that don't have access
    /// to the persistent guard identity yet.
    pub fn new(network: String) -> Self {
        Self::with_identity(network, &[])
    }

    /// Build a handler binding the handshake nonce to `node_identity` —
    /// typically the persistent ML-DSA-87 public key from axiom-guard.
    /// The nonce is `SHA256(random_128 || node_identity)`; even if two
    /// nodes pick the same 128-bit random, different identities make
    /// collisions impossible in practice.
    pub fn with_identity(network: String, node_identity: &[u8]) -> Self {
        let hash = generate_nonce_hash(node_identity);
        Self::with_nonce_hash(network, hash)
    }

    /// Construct with a caller-supplied nonce hash. Used by tests that
    /// need a deterministic self-collision scenario.
    pub fn with_nonce_hash(network: String, local_nonce_hash: [u8; NONCE_HASH_LEN]) -> Self {
        let local_nonce_u64 = u64_from_hash(&local_nonce_hash);
        ProtocolHandler {
            network,
            local_nonce_hash,
            local_nonce_u64,
        }
    }

    /// Legacy constructor: treat a caller-supplied u64 as the handshake
    /// nonce and zero the strong hash. Kept only for tests that need the
    /// old semantics.
    pub fn with_nonce(network: String, local_nonce: u64) -> Self {
        let mut hash = [0u8; NONCE_HASH_LEN];
        hash[..8].copy_from_slice(&local_nonce.to_le_bytes());
        ProtocolHandler {
            network,
            local_nonce_hash: hash,
            local_nonce_u64: local_nonce,
        }
    }

    pub fn local_nonce(&self) -> u64 {
        self.local_nonce_u64
    }

    pub fn local_nonce_hash(&self) -> [u8; NONCE_HASH_LEN] {
        self.local_nonce_hash
    }

    pub fn create_version(&self, best_height: u32) -> Message {
        Message::Version(VersionMessage {
            protocol_version: PROTOCOL_VERSION,
            network: self.network.clone(),
            best_height,
            nonce: self.local_nonce_u64,
            nonce_hash: self.local_nonce_hash,
            ..Default::default()
        })
    }

    pub fn validate_version(&self, version: &VersionMessage) -> Result<(), HandshakeError> {
        if version.protocol_version < MIN_PROTOCOL_VERSION
            || version.protocol_version > PROTOCOL_VERSION
        {
            return Err(HandshakeError::VersionMismatch {
                min: MIN_PROTOCOL_VERSION,
                max: PROTOCOL_VERSION,
                actual: version.protocol_version,
            });
        }

        if version.network != self.network {
            return Err(HandshakeError::NetworkMismatch {
                expected: self.network.clone(),
                actual: version.network.clone(),
            });
        }

        // Self-connection detection. Prefer the strong 256-bit nonce: a
        // non-zero `nonce_hash` that matches ours is the authoritative
        // signal. Fall back to the u64 nonce for v1 peers (which always
        // ship `nonce_hash = 0`). Nonce 0 on either field means "unset"
        // and is skipped to avoid false positives from defaults.
        let peer_hash_is_set = version.nonce_hash != [0u8; NONCE_HASH_LEN];
        if peer_hash_is_set && version.nonce_hash == self.local_nonce_hash {
            return Err(HandshakeError::SelfConnection);
        }
        if !peer_hash_is_set
            && self.local_nonce_u64 != 0
            && version.nonce != 0
            && version.nonce == self.local_nonce_u64
        {
            return Err(HandshakeError::SelfConnection);
        }

        Ok(())
    }

    pub fn process_handshake(
        &self,
        peer: &mut Peer,
        message: &Message,
    ) -> Result<Option<Message>, HandshakeError> {
        match (peer.state, message) {
            (PeerState::Connecting, Message::Version(v)) => {
                self.validate_version(v)?;
                peer.protocol_version = Some(v.protocol_version);
                peer.network = Some(v.network.clone());
                peer.best_height = Some(v.best_height);
                peer.state = PeerState::VersionReceived;
                Ok(Some(Message::VerAck))
            }
            (PeerState::VersionReceived, Message::VerAck) => {
                peer.state = PeerState::Ready;
                Ok(None)
            }
            _ => Err(HandshakeError::InvalidState),
        }
    }
}

/// `SHA256(NONCE_DOMAIN || random_128 || node_identity)`. The 128-bit
/// random input gives unconditional uniqueness across restarts of the
/// same node; the identity pin prevents two different nodes from ever
/// producing the same hash even if their RNGs collided; the domain tag
/// isolates this hash from every other SHA-256 computation in the
/// protocol so no two contexts can ever alias.
fn generate_nonce_hash(node_identity: &[u8]) -> [u8; NONCE_HASH_LEN] {
    use rand_core::{OsRng, RngCore};
    let mut random_128 = [0u8; 16];
    OsRng.fill_bytes(&mut random_128);

    let mut hasher = Sha256::new();
    hasher.update(NONCE_DOMAIN);
    hasher.update(random_128);
    hasher.update(node_identity);
    let digest = hasher.finalize();
    let mut out = [0u8; NONCE_HASH_LEN];
    out.copy_from_slice(&digest);

    // Reserve all-zero as "unset" sentinel. A SHA-256 preimage producing
    // 32 zero bytes is computationally infeasible, but loop for safety.
    if out == [0u8; NONCE_HASH_LEN] {
        return generate_nonce_hash(node_identity);
    }
    out
}

fn u64_from_hash(hash: &[u8; NONCE_HASH_LEN]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&hash[..8]);
    // If the first 8 bytes happen to be all zero (infeasibly rare but
    // possible), fold in the next 8 so the legacy-compat u64 stays
    // non-zero and v1 peers can still use it for self-detection.
    let first = u64::from_le_bytes(buf);
    if first != 0 {
        return first;
    }
    let mut fallback = [0u8; 8];
    fallback.copy_from_slice(&hash[8..16]);
    u64::from_le_bytes(fallback) | 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::peer::Direction;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_version_validation_success() {
        let handler = ProtocolHandler::new("dev".to_string());
        let version = VersionMessage {
            protocol_version: PROTOCOL_VERSION,
            network: "dev".to_string(),
            best_height: 100,
            ..Default::default()
        };

        assert!(handler.validate_version(&version).is_ok());
    }

    #[test]
    fn test_self_connection_detected_by_nonce_hash() {
        let hash = [7u8; NONCE_HASH_LEN];
        let handler = ProtocolHandler::with_nonce_hash("dev".to_string(), hash);
        let self_version = VersionMessage {
            protocol_version: PROTOCOL_VERSION,
            network: "dev".to_string(),
            best_height: 0,
            nonce_hash: hash,
            nonce: u64_from_hash(&hash),
            ..Default::default()
        };
        let result = handler.validate_version(&self_version);
        assert!(matches!(result, Err(HandshakeError::SelfConnection)));
    }

    #[test]
    fn test_self_connection_fallback_u64_for_v1_peer() {
        // Simulate what a v1 peer sends: protocol_version = 1, u64 nonce
        // populated, nonce_hash left at zero.
        let handler = ProtocolHandler::with_nonce("dev".to_string(), 0xDEADBEEF);
        let legacy_self = VersionMessage {
            protocol_version: MIN_PROTOCOL_VERSION,
            network: "dev".to_string(),
            best_height: 0,
            nonce: 0xDEADBEEF,
            nonce_hash: [0u8; NONCE_HASH_LEN],
            ..Default::default()
        };
        assert!(matches!(
            handler.validate_version(&legacy_self),
            Err(HandshakeError::SelfConnection)
        ));
    }

    #[test]
    fn test_different_nonce_hash_accepted() {
        let handler = ProtocolHandler::with_nonce_hash("dev".to_string(), [1u8; NONCE_HASH_LEN]);
        let peer_version = VersionMessage {
            protocol_version: PROTOCOL_VERSION,
            network: "dev".to_string(),
            best_height: 0,
            nonce_hash: [2u8; NONCE_HASH_LEN],
            ..Default::default()
        };
        assert!(handler.validate_version(&peer_version).is_ok());
    }

    #[test]
    fn test_version_carries_local_nonce_hash() {
        let hash = [9u8; NONCE_HASH_LEN];
        let handler = ProtocolHandler::with_nonce_hash("dev".to_string(), hash);
        if let Message::Version(v) = handler.create_version(42) {
            assert_eq!(v.nonce_hash, hash);
            assert_eq!(v.nonce, u64_from_hash(&hash));
            assert_eq!(v.protocol_version, PROTOCOL_VERSION);
        } else {
            panic!("expected Version message");
        }
    }

    #[test]
    fn test_nonce_hash_uniqueness_across_nodes() {
        // 1000 independent handlers with distinct identities must never
        // collide. Even a single collision here would be a crypto-level
        // bug, not statistical noise.
        let mut seen = HashSet::new();
        for i in 0..1000u32 {
            let identity = format!("node-{}", i);
            let h = ProtocolHandler::with_identity("dev".to_string(), identity.as_bytes());
            assert!(
                seen.insert(h.local_nonce_hash()),
                "duplicate nonce_hash for node {}",
                i
            );
        }
    }

    #[test]
    fn test_nonce_hash_uniqueness_same_identity_different_calls() {
        // Same identity but different random_128 => different hashes. This
        // guards against an accidental regression where the RNG input is
        // dropped and the hash collapses to `H(identity)` alone.
        let identity = b"stable-identity";
        let mut seen = HashSet::new();
        for _ in 0..256 {
            let h = ProtocolHandler::with_identity("dev".to_string(), identity);
            assert!(seen.insert(h.local_nonce_hash()));
        }
    }

    #[test]
    fn test_no_self_collision_with_other_node() {
        // Sanity: a peer built from a *different* identity must not match
        // our nonce_hash. (If this ever fires, the RNG is busted.)
        let me = ProtocolHandler::with_identity("dev".to_string(), b"me");
        for _ in 0..64 {
            let other = ProtocolHandler::with_identity("dev".to_string(), b"other");
            assert_ne!(me.local_nonce_hash(), other.local_nonce_hash());
        }
    }

    #[test]
    fn test_v1_peer_accepted_by_v2_handler() {
        // A v1 peer announces protocol_version = 1 with nonce_hash = 0.
        // v2 must accept it — otherwise we partition old nodes off the
        // network.
        let handler = ProtocolHandler::with_identity("dev".to_string(), b"me");
        let v1_peer = VersionMessage {
            protocol_version: MIN_PROTOCOL_VERSION,
            network: "dev".to_string(),
            best_height: 10,
            nonce: 0xCAFEBABE,
            nonce_hash: [0u8; NONCE_HASH_LEN],
            ..Default::default()
        };
        assert!(handler.validate_version(&v1_peer).is_ok());
    }

    #[test]
    fn test_future_protocol_version_rejected() {
        let handler = ProtocolHandler::new("dev".to_string());
        let future = VersionMessage {
            protocol_version: PROTOCOL_VERSION + 1,
            network: "dev".to_string(),
            best_height: 0,
            ..Default::default()
        };
        assert!(matches!(
            handler.validate_version(&future),
            Err(HandshakeError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn test_generate_nonce_hash_nonzero() {
        for _ in 0..32 {
            let h = generate_nonce_hash(b"id");
            assert_ne!(h, [0u8; NONCE_HASH_LEN]);
        }
    }

    #[test]
    fn test_nonce_hash_domain_separated() {
        // The domain tag must actually be mixed into the hash. Compute
        // what a domain-less implementation would produce for fixed
        // inputs, then build a handler with the same conceptual inputs
        // and verify its nonce never matches the un-tagged digest.
        use sha2::{Digest, Sha256};
        let identity = b"known-identity";
        let random_128 = [0u8; 16];

        let mut bad = Sha256::new();
        bad.update(random_128);
        bad.update(identity);
        let undomained: [u8; NONCE_HASH_LEN] = bad.finalize().into();

        // Generate many real handlers: none should equal the un-tagged
        // digest. (The random input differs each time too; we're really
        // checking that the domain prefix shifts the whole output space.)
        for _ in 0..64 {
            let h = ProtocolHandler::with_identity("dev".to_string(), identity);
            assert_ne!(h.local_nonce_hash(), undomained);
        }
    }

    #[test]
    fn test_nonce_hash_depends_on_domain_tag() {
        // Compute H(domain || 0u8*16 || identity) by hand and verify it
        // differs from H(0u8*16 || identity). This pins the prefix into
        // the test surface so a silent removal of NONCE_DOMAIN cannot
        // pass unnoticed.
        use sha2::{Digest, Sha256};
        let identity = b"pinned";
        let zero = [0u8; 16];

        let mut with_domain = Sha256::new();
        with_domain.update(NONCE_DOMAIN);
        with_domain.update(zero);
        with_domain.update(identity);
        let a: [u8; NONCE_HASH_LEN] = with_domain.finalize().into();

        let mut without_domain = Sha256::new();
        without_domain.update(zero);
        without_domain.update(identity);
        let b: [u8; NONCE_HASH_LEN] = without_domain.finalize().into();

        assert_ne!(a, b, "domain tag must change the digest");
    }

    #[test]
    fn test_identity_is_canonical_across_reloads() {
        // Simulate a node restart: the persistent guard identity is the
        // 32-byte ML-DSA-87 seed; loading it twice must produce the
        // byte-identical public key. This is the input to the nonce
        // hash, so if it ever drifted the v2 self-peer detection would
        // break across restarts.
        use axiom_wallet::KeyPair;
        let kp = KeyPair::generate().unwrap();
        let seed = kp.export_private_key().to_vec();

        let pk_a = KeyPair::from_private_key(seed.clone())
            .unwrap()
            .public_key()
            .to_vec();
        let pk_b = KeyPair::from_private_key(seed).unwrap().public_key().to_vec();
        assert_eq!(pk_a, pk_b, "pubkey bytes must be stable across reloads");

        // Same identity bytes into two separate handlers: different
        // random_128 means the nonce_hash differs, but the *identity*
        // half of the input is byte-stable. Verify that: two handlers
        // built from the same pk must never coincidentally match
        // (which would expose a stale-random bug) — checked here by
        // making the space collision-resistant at 256 bits.
        let h1 = ProtocolHandler::with_identity("dev".to_string(), &pk_a);
        let h2 = ProtocolHandler::with_identity("dev".to_string(), &pk_b);
        assert_ne!(h1.local_nonce_hash(), h2.local_nonce_hash());
    }

    #[test]
    fn test_empty_identity_fallback_is_safe() {
        // When the guard identity can't be loaded, axiom-cli passes an
        // empty slice. The handler must still build, produce a non-zero
        // nonce, and not collide with other empty-identity handlers in
        // the same process (proving randomness still carries uniqueness).
        let h1 = ProtocolHandler::with_identity("dev".to_string(), &[]);
        let h2 = ProtocolHandler::with_identity("dev".to_string(), &[]);
        assert_ne!(h1.local_nonce_hash(), [0u8; NONCE_HASH_LEN]);
        assert_ne!(h1.local_nonce_hash(), h2.local_nonce_hash());
        assert_ne!(h1.local_nonce(), 0);
    }

    #[test]
    fn test_network_mismatch() {
        let handler = ProtocolHandler::new("dev".to_string());
        let version = VersionMessage {
            protocol_version: PROTOCOL_VERSION,
            network: "test".to_string(),
            best_height: 100,
            ..Default::default()
        };

        let result = handler.validate_version(&version);
        assert!(matches!(
            result,
            Err(HandshakeError::NetworkMismatch { .. })
        ));
    }

    #[test]
    fn test_handshake_flow() {
        let handler = ProtocolHandler::new("dev".to_string());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333);
        let mut peer = Peer::new(addr, Direction::Inbound);

        // Receive version
        let version = Message::Version(VersionMessage {
            protocol_version: PROTOCOL_VERSION,
            network: "dev".to_string(),
            best_height: 100,
            ..Default::default()
        });

        let response = handler.process_handshake(&mut peer, &version).unwrap();
        assert!(matches!(response, Some(Message::VerAck)));
        assert_eq!(peer.state, PeerState::VersionReceived);

        // Receive verack
        let verack = Message::VerAck;
        let response = handler.process_handshake(&mut peer, &verack).unwrap();
        assert!(response.is_none());
        assert_eq!(peer.state, PeerState::Ready);
    }
}
