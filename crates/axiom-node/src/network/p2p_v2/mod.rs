// Copyright (c) 2026 Kantoshi Miyamura

//! Axiom v2 peer transport — **handshake layer**.
//!
//! Stage 3 of [`docs/V2_PROTOCOL.md §8`](../../../../../docs/V2_PROTOCOL.md):
//! the cryptographic core of the v2 handshake (transcript hashing, hybrid
//! key agreement, session-key derivation, hybrid identity proof) is now
//! implemented. **The runtime is still on v1** — `service.rs`, `manager.rs`,
//! and `transport.rs` continue to use the v1 [`super::encryption`] module.
//! Wiring this layer into the listener is stage 4.
//!
//! All entry points operate on bytes / structs only — there is no socket
//! I/O in this module. A caller drives the handshake by calling
//! [`flow::initiator_build_hello`], sending the bytes, calling
//! [`flow::responder_handle_hello`] on the receiving side, sending the
//! ack back, and finally [`flow::initiator_handle_ack`] on the original
//! caller. Both ends end up with a matching [`session::SessionKeys`].

pub mod flow;
pub mod handshake;
pub mod identity;
pub mod session;
pub mod transport;

pub use flow::{
    initiator_build_hello, initiator_handle_ack, responder_handle_hello,
    InitiatorHandshakeMaterial, ResponderHandshakeMaterial,
};
pub use handshake::{transcript_hash, HandshakeError, HelloAckV2, HelloV2};
pub use identity::{sign_identity, verify_identity, NodeIdentityProof};
pub use session::{derive_session_keys, SessionKeys};
pub use transport::{EncryptedConnectionV2, TransportV2Error, MAX_FRAME_BODY_BYTES};

/// Domain-separation tag mixed into the v2 handshake transcript hash.
/// Bumping this string produces an entirely disjoint transcript space —
/// a v1 handshake replayed against a v2 listener cannot match.
pub const V2_TRANSCRIPT_TAG: &[u8] = b"axiom-p2p-v2/transcript";

/// Domain-separation tag for the HKDF stage that produces session keys
/// from the (classical || PQ) shared-secret concatenation.
pub const V2_SESSION_INFO: &[u8] = b"axiom-p2p-v2/session";

/// Protocol version string bound into every transcript so a v1 attacker
/// cannot fool a v2 peer into thinking it negotiated a v1 handshake. There
/// is no negotiation — v2 nodes only speak v2 — but binding the version
/// in the transcript makes any cross-version replay break the signature
/// verification step.
pub const V2_PROTOCOL_VERSION_TAG: &[u8] = b"p2p-v2";

/// Per-direction HKDF info for `init -> resp` traffic.
pub const V2_KEY_INFO_INIT_TO_RESP: &[u8] = b"axiom-p2p-v2/key/init->resp";

/// Per-direction HKDF info for `resp -> init` traffic.
pub const V2_KEY_INFO_RESP_TO_INIT: &[u8] = b"axiom-p2p-v2/key/resp->init";
