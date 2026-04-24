// Copyright (c) 2026 Kantoshi Miyamura
//
// Axiom Guardian — deterministic, advisory intelligence layer.
//
// OVERVIEW:
//   GuardianAgent (per node) observes on-chain and P2P data, produces a
//   deterministic state commitment, runs an integer scoring model, and
//   emits a signed GuardianReport. Reports gossip across the network;
//   aggregation yields advisory inputs for local policy (peer scoring,
//   relay rate-limiting, tx prioritisation hints). NONE of these paths
//   touch consensus.
//
// DATA FLOW:
//   Observation ──► DeterministicState ──► FeatureVector ──► Model.score()
//                                              │
//                                              ▼
//                                       GuardianDecision
//                                              │
//                 ┌────────────────────────────┴───────────────┐
//                 ▼                                            ▼
//            GuardianProof                               (local policy:
//         = SHA3(S || D || M)                           peer score,
//                 │                                     relay floor)
//                 ▼
//            GuardianReport (signed ML-DSA-87)
//                 │
//                 ▼ gossip
//             aggregate()
//                 │
//                 ▼
//          AggregatedDecision   ──► local policy (NEVER consensus)
//
// INVARIANTS (proved by tests and audited in AI-CONSENSUS-AUDIT.md):
//   I-1  State encoding is a pure function of observation bytes.
//   I-2  Model scoring uses only i64/i128 integer arithmetic.
//   I-3  Proof binds (state, decision, model commitment) under domain
//        separation. Tampering any of the three breaks verification.
//   I-4  Report signatures use a domain tag disjoint from every other
//        signing context in the codebase.
//   I-5  Aggregation is deterministic under any input permutation and
//        produces byte-identical output on any platform.
//   I-6  This crate has no dependency on `axiom-consensus`; no function
//        here mutates block, transaction, mempool, or UTXO state.

pub mod agent;
pub mod aggregation;
pub mod decision;
pub mod model;
pub mod report;
pub mod seeded_rng;
pub mod state;

pub use agent::{DecisionRecord, GuardianAgent};
pub use aggregation::{aggregate, AggregatedDecision};
pub use decision::{GuardianDecision, GuardianProof, PeerFlag, PeerFlagKind, TxPriorityHint};
pub use model::{AnomalyWeights, FeatureVector, GuardianModel, ModelError, FEATURE_MAX, SCORE_MAX};
pub use report::{GuardianReport, ReportError, REPORT_DOMAIN};
pub use seeded_rng::SeededRng;
pub use state::{BlockSummary, DeterministicState, GuardianObservation, PeerStats, TxPatternStats};

#[cfg(test)]
mod isolation_tests;
