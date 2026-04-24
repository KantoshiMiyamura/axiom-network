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
pub mod guard;
pub mod learning;
pub mod reputation;
pub mod threat;

pub use alerts::{AlertKind, AlertSeverity, GuardAlert};
pub use detector::AnomalyDetector;
pub use fingerprint::CognitiveFingerprint;
pub use guard::{GuardStatus, NetworkGuard};
pub use learning::{EwmaBaseline, NetworkBaselines};
pub use reputation::{Ewma, PeerScore, PeerReputationTable, ReputationRegistry, Violation};
pub use threat::ThreatLevel;
