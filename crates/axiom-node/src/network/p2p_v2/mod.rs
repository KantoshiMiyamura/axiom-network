// Copyright (c) 2026 Kantoshi Miyamura

//! Axiom v2 peer transport — **skeleton only**.
//!
//! This module declares the type surface for the v2 P2P handshake described
//! in [`docs/V2_PROTOCOL.md`](../../../../../docs/V2_PROTOCOL.md). Nothing
//! here is wired into the runtime — `service.rs`, `manager.rs`, and
//! `transport.rs` continue to use the v1 [`super::encryption`] module.
//!
//! Every function that would touch network state returns `unimplemented!()`.
//! Every type carries a comment naming its v2-spec section. The file is
//! checked by `cargo check` so the API stays buildable while the
//! corresponding stage in `V2_PROTOCOL.md §8` is in flight.

pub mod handshake;
pub mod identity;
pub mod session;

pub use handshake::{HandshakeError, HelloAckV2, HelloV2};
pub use identity::NodeIdentityProof;
pub use session::SessionKeys;

/// Domain-separation tag mixed into the v2 handshake transcript hash.
/// Bumping this string produces an entirely disjoint transcript space —
/// a v1 handshake replayed against a v2 listener cannot match.
pub const V2_TRANSCRIPT_TAG: &[u8] = b"axiom-p2p-v2/transcript";

/// Domain-separation tag for the HKDF stage that produces session keys
/// from the (classical || PQ) shared-secret concatenation.
pub const V2_SESSION_INFO: &[u8] = b"axiom-p2p-v2/session";
