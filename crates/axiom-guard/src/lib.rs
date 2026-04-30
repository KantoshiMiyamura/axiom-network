// Copyright (c) 2026 Kantoshi Miyamura
//! NetworkGuard — heuristic attack-pattern detector over already-accepted blocks.
//!
//! Subscribes to the post-validation `block_accepted_hook` and produces
//! `GuardAlert` records for selfish-mining, fork-race, and timestamp-skew
//! patterns. EWMA baselines and peer reputation are tracked in RAM and
//! exposed via RPC.
//!
//! INVARIANT: this crate is read-only with respect to consensus. It MUST NOT
//! reject blocks, evict transactions, or disconnect peers — alert consumers
//! decide policy. See AI-CONSENSUS-AUDIT.md §3.2 for the isolation argument.

pub mod alerts;
pub mod detector;
pub mod fingerprint;
// v2-dev: hybrid (ML-DSA + Ed25519) peer fingerprint per
// `docs/V2_PROTOCOL.md §8 stage 5`. Compile-only from the runtime's
// perspective — `fingerprint::CognitiveFingerprint` (v1) is unchanged
// and remains the only fingerprint consulted at boot.
pub mod fingerprint_v2;
pub mod guard;
pub mod learning;
pub mod reputation;
pub mod threat;

pub use alerts::{AlertKind, AlertSeverity, GuardAlert};
pub use detector::AnomalyDetector;
pub use fingerprint::CognitiveFingerprint;
pub use fingerprint_v2::{
    compute_peer_id, verify_announced_peer_id, FingerprintV2Error, PeerId, ED25519_PUBKEY_BYTES,
    FINGERPRINT_V2_TAG, PEER_ID_BYTES,
};
pub use guard::{GuardStatus, NetworkGuard};
pub use learning::{EwmaBaseline, NetworkBaselines};
pub use reputation::{Ewma, PeerReputationTable, PeerScore, ReputationRegistry, Violation};
pub use threat::ThreatLevel;
