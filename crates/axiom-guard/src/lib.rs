// Copyright (c) 2026 Kantoshi Miyamura
//! AxiomMind — the AI intelligence layer of Axiom Network.
//! A self-learning, self-defending neural guardian that lives on the blockchain.
//! Has a post-quantum ML-DSA-87 cryptographic identity. Cannot be shut down.

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
