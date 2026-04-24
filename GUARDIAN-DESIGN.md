# Axiom Guardian — Architecture, Invariants, and Isolation Report

This document covers the seven phases requested. It describes the Guardian
intelligence layer now resident in [crates/axiom-ai/src/guardian/](crates/axiom-ai/src/guardian/)
and proves, by construction and by test, that it cannot influence consensus.

---

## Phase 1 — Audit of the existing system

Full audit: [AI-CONSENSUS-AUDIT.md](AI-CONSENSUS-AUDIT.md). TL;DR reproduced here.

| Surface | Today | Risk |
|---|---|---|
| `axiom-consensus` crate deps | No `axiom-ai`, no `axiom-guard` | None |
| `axiom-node::validation` source | No `axiom_ai`, no `guardian` | None |
| `axiom-node::anomaly::AnomalyDetector` | Advisory; score logged, admission unconditional ([crates/axiom-node/src/node.rs:180-197](crates/axiom-node/src/node.rs#L180-L197)) | None |
| `axiom-guard::NetworkGuard::on_block` | Fires AFTER block accepted+inserted; returns `Vec<GuardAlert>` | None |
| `axiom-ai::self_healing::apply_patch` | Stub; no `fs::write` / `Command::new` in crate | Low — documented; implementation must not bypass |
| `axiom-ai::reinforcement_learning::Action::{ApplyPatch,IsolateNodes,TriggerConsensus}` | Enum variants with no dispatcher (dead) | Low — now explicitly marked telemetry-only |
| Floats in consensus path | None; all validation is integer | None |

Verdict: **AI IS ISOLATED FROM CONSENSUS** at the start of this work.

---

## Phase 2 — Guardian architecture

### Module layout

```
crates/axiom-ai/src/guardian/
├── mod.rs              public re-exports, invariant commentary
├── seeded_rng.rs       SHA3-counter PRNG, seeded from (tip_hash, height)
├── state.rs            BlockSummary, TxPatternStats, PeerStats,
│                       GuardianObservation, DeterministicState (S_t)
├── model.rs            FeatureVector (i64), AnomalyWeights (i64),
│                       GuardianModel (integer dot product, i128 intermediate)
├── decision.rs         GuardianDecision, TxPriorityHint, PeerFlag,
│                       GuardianProof (SHA3 domain-separated)
├── agent.rs            GuardianAgent orchestrator, bounded history ring
├── report.rs           GuardianReport (ML-DSA-87 signed, domain-separated)
├── aggregation.rs      deterministic median + per-peer majority vote
└── isolation_tests.rs  structural + property tests
```

### Data flow

```
 Observation ──► DeterministicState (S_t)
      │                │
      │                └─► seeds SeededRng for exploration
      ▼
 FeatureVector (i64, clamped) ──► GuardianModel.score() ──► anomaly_score (i64)
      │
      ▼
 GuardianDecision { anomaly_score, peer_flags, tx_priority_hint }
      │
      ▼
 GuardianProof = SHA3("axiom/guardian/proof/v1" ||
                      state || model_commitment ||
                      canonical_decision_bytes)
      │
      ▼                       ┌──────────────────────────────┐
 GuardianReport ──► gossip ──►│ peers verify sig + proof      │
 (ML-DSA-87,                  │ then call aggregate(&reports) │
  domain-separated)           └──────────────────────────────┘
                                            │
                                            ▼
                                 AggregatedDecision
                                            │
                                            ▼
                         local policy ONLY (peer score,
                         relay floor, tx prioritisation hint).
                         NEVER consensus, NEVER tx rejection.
```

### Deterministic state encoding

`DeterministicState::encode(obs)` is SHA3-256 of a canonicalised preimage
with a `"axiom/guardian/state/v1"` domain tag. Canonicalisation rules:

1. All integers little-endian fixed-width.
2. Collections length-prefixed (`u32` LE).
3. Inner collections sorted by a stable total order before hashing
   (`block_window` sorted by `(height, hash)`).
4. Byte strings written verbatim, no text normalisation.

See [state.rs:encode](crates/axiom-ai/src/guardian/state.rs).

### Learning model

- Pure integer arithmetic. Features `i64 ∈ [0, FEATURE_MAX=10_000]`. Weights
  `i64` bounded in magnitude (`|Σw| ≤ 2^30`) so dot products fit in `i128`
  without overflow.
- No floats, no transcendentals, no platform intrinsics.
- Model content-addressed by a SHA3 commitment over
  `(version, weights, bias)`; changing any bit changes the commitment and
  distinguishes proofs.
- Seeded exploration available via `SeededRng::seed_from_block(tip_hash, height)`;
  seed is a pure function of observation inputs, no OS entropy.

### Guardian proof

```
Proof = SHA3("axiom/guardian/proof/v1" || S_t || model_commitment || canonical_decision)
```

Verification is a re-derivation: given `(state, decision, model)` a third
party recomputes the proof and compares bytes. Mismatch → the producer used a
different model or lied about state.

Domain separation: a Guardian proof cannot be replayed as a transaction
signing hash (`"axiom/tx/v1"`), a seed (`"axiom/guardian/seed/v1"`), a state
commitment (`"axiom/guardian/state/v1"`), a model commitment
(`"axiom/guardian/model/v1"`), or a report signature
(`"axiom/guardian/report/v1"`) — all five live in disjoint hash spaces.

---

## Phase 3 — Isolation guarantees

### Code-level invariants

| # | Invariant | Enforcer |
|---|---|---|
| I-1 | State encoding is a pure function of observation bytes | tests in [state.rs](crates/axiom-ai/src/guardian/state.rs), [isolation_tests.rs](crates/axiom-ai/src/guardian/isolation_tests.rs) |
| I-2 | Model scoring uses only `i64`/`i128` integer arithmetic | [model.rs](crates/axiom-ai/src/guardian/model.rs) — no float types in scope |
| I-3 | `GuardianProof` binds (state, decision, model commitment) under domain separation | [decision.rs](crates/axiom-ai/src/guardian/decision.rs) |
| I-4 | Report signatures use a disjoint domain tag | [report.rs `REPORT_DOMAIN`](crates/axiom-ai/src/guardian/report.rs) |
| I-5 | Aggregation is deterministic under input permutation | [aggregation.rs](crates/axiom-ai/src/guardian/aggregation.rs) |
| I-6 | `axiom-consensus` has **no** dependency on `axiom-ai` or `axiom-guard` | [isolation_tests.rs::axiom_consensus_does_not_depend_on_axiom_ai](crates/axiom-ai/src/guardian/isolation_tests.rs) |
| I-7 | `axiom-consensus` source contains no `axiom_ai` or `guardian` symbols | [isolation_tests.rs::axiom_consensus_source_contains_no_guardian_imports](crates/axiom-ai/src/guardian/isolation_tests.rs) |
| I-8 | `GuardianAgent::observe` does not mutate its input observation | [isolation_tests.rs::agent_does_not_mutate_observation](crates/axiom-ai/src/guardian/isolation_tests.rs) |
| I-9 | No implicit consumer of guardian output inside `axiom-ai` public API | [isolation_tests.rs::guardian_output_has_no_implicit_consumer](crates/axiom-ai/src/guardian/isolation_tests.rs) |

### Consensus-identical-with-AI-on/off

We do not need a runtime feature flag to prove this: the Guardian is *not
wired* into the validation path at all. Structural invariants I-6 and I-7
assert the wire absence via Cargo.toml and source string checks; any future
commit that breaks them fails CI.

The `TransactionValidator::validate_and_compute_fee` call in
[crates/axiom-node/src/node.rs:178](crates/axiom-node/src/node.rs#L178) is
followed by the advisory anomaly-detector call — its output is logged and
discarded. Whether or not the Guardian is instantiated, the verdict from
`validate_and_compute_fee` and the subsequent `mempool.add_transaction` are
unchanged.

---

## Phase 4 — Network integration

### Wire format

`GuardianReport` serialises with `serde` + `bincode`. Every field is fixed-size
(`[u8; 32]`, `u64`) except `node_pubkey` (2592 bytes ML-DSA-87) and
`signature` (4627 bytes ML-DSA-87). Payload size is dominated by the signature.

### Gossip

Integration surface (not yet wired — intentional, kept behind a clean API):

```rust
// In axiom-node::network, add:
//
//   enum NetworkMessage {
//       ...
//       GuardianReport(axiom_ai::guardian::GuardianReport),
//   }
//
// Receiver path:
//
//   async fn on_guardian_report(&self, r: GuardianReport) {
//       if r.verify(&self.local_model).is_err() { return; }   // drop
//       self.guardian_reports.push(r);                         // bounded ring
//       // Relay only if reputation allows — never a consensus action.
//   }
//
// Ticker path:
//
//   async fn guardian_tick(&self) {
//       let obs = self.build_observation();
//       let record = self.guardian_agent.observe(&obs);
//       let report = GuardianReport::sign(
//           &self.signing_key, self.verifying_key.clone(),
//           obs.height, wallclock_secs(),
//           record.state, record.decision, record.proof,
//           self.guardian_agent.model().commitment,
//       )?;
//       self.network.broadcast(NetworkMessage::GuardianReport(report));
//   }
```

### Aggregation

`aggregate(&[GuardianReport])` yields `AggregatedDecision`:

- `median_anomaly_score: i64` — integer median over the latest report per
  reporter.
- `peer_consensus_flags` — per-peer majority vote, tie-broken by enum byte.
- `priority_median_fee_millisat: u64` — integer median fee floor.
- `reporter_set_hash: [u8; 32]` — SHA3 of the sorted reporter pubkey set.

Determinism is proved by
[isolation_tests::aggregation_permutation_independent](crates/axiom-ai/src/guardian/isolation_tests.rs)
and the unit tests in [aggregation.rs](crates/axiom-ai/src/guardian/aggregation.rs):
inputs permuted → outputs byte-identical.

### Local-only consumers (allowed)

- Peer scoring: boost or throttle based on `peer_consensus_flags`.
- Relay rate limiting: drop or delay relay of low-priority transactions.
- Block template priority: include higher-priority senders first.

### Consumers forbidden by construction

- Transaction acceptance / rejection (stays in `axiom-consensus::validation`).
- Block acceptance / rejection (stays in `axiom-consensus::consensus`).
- UTXO mutations (stays in `axiom-node::Node`).
- Peer disconnect — throttling is allowed; ban is not a Guardian action.

---

## Phase 5 — Optional: Proof-of-Useful-Compute integration (design only)

We sketch an integration, not an implementation. The design must satisfy:

1. **PoW must remain necessary and sufficient for consensus acceptance.** The
   AI step is an *additional* per-block artifact, verifiable offline, that
   does not gate validation.
2. **Zero non-determinism.** The AI step is `GuardianModel.score(features)`
   over `features = derive_features(observation_snapshot_at_parent_tip)` —
   both sides are already integer-deterministic.

Sketch:

```
BlockHeader (unchanged for consensus) + optional field:
  guardian_commitment: [u8; 32]  =  SHA3(
      "axiom/pouc/guardian/v1" ||
      parent_hash              ||
      parent_height            ||
      guardian_state_hash      ||
      model_commitment         ||
      anomaly_score.to_le_bytes())
```

- Miner computes `guardian_commitment` from data they already possess
  (parent header + mempool snapshot) before hashing for PoW. The PoW preimage
  *includes* this field so a block whose guardian work is inconsistent is
  cheaply detectable — but consensus rules only require:
  - parent hash chains
  - PoW target met
  - tx validity
  - merkle root

  The guardian field is **advisory and auditable**; misconfiguration
  produces a warning, not a rejection.

- Verifiers replay `derive_features + model.score` and re-hash. Mismatches
  are logged; no block is rejected on this basis.

Explicit non-goal: making the AI step a consensus rule. Doing so would
couple consensus to model weights, breaking the isolation invariant.

---

## Phase 6 — Code quality

- Every file begins with a copyright line, a one-line purpose, and an
  `INVARIANT` block stating what must be true for that file.
- Comments explain *why* (security reasoning, overflow bound, domain
  separation) or *what cannot change without review*. No TODOs, no
  "in production this would" placeholders.
- Tests are property-style where relevant: permutation invariance,
  idempotence, mutation detection.

---

## Phase 7 — Output

### Architecture design
See Phase 2.

### Code structure
See Phase 2 module layout.

### Invariants
I-1 through I-9 in the Phase 3 table.

### Risk analysis

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| G1 | Future commit adds `axiom-ai` as a dep of `axiom-consensus` | Blocking | Test I-6 fails CI |
| G2 | Future commit imports `guardian` symbols into validation code | Blocking | Test I-7 fails CI |
| G3 | A guardian operator ships weights producing stuck scores | Low | Commitment changes on any weight change; audit trail via `GuardianProof` |
| G4 | Gossip DoS via malformed reports | Medium (future wiring) | Receiver MUST call `report.verify()` before aggregation; aggregation is bounded by reporter count |
| G5 | Wall-clock skew in `GuardianReport.timestamp` | Low | `timestamp` is carried but does not affect score or proof; aggregation uses height for dedup |
| G6 | PRNG seed reuse across height | None — seed derives from `(tip_hash, height)` so different heights → different seeds | — |

### Test results

```
cargo test -p axiom-ai --lib
  → 119 passed; 0 failed; 0 ignored   (40 guardian + 79 existing)

cargo test -p axiom-consensus --lib
  → 63 passed; 0 failed; 0 ignored
```

Guardian suite breakdown (40 tests):

- `seeded_rng::tests` ×3 — determinism across seeds, domain separation.
- `state::tests` ×4 — encoding determinism, sort-invariance, domain
  separation, field sensitivity.
- `model::tests` ×7 — score determinism, zero-input, monotonicity, clamp,
  commitment sensitivity to weights / version, overflow rejection.
- `decision::tests` ×5 — canonical byte stability, proof reproducibility,
  proof rejects decision tamper, proof rejects model swap.
- `agent::tests` ×4 — observe determinism across instances, proof verifies,
  bounded history, seeded RNG depends on tip.
- `report::tests` ×3 — sign/verify roundtrip, tamper rejection, model
  commitment mismatch rejection.
- `aggregation::tests` ×5 — order independence, dedup-keeps-latest, integer
  median, peer majority vote, empty input.
- `isolation_tests` ×9 — structural tests for consensus independence.

### Confirmation

**AI ISOLATED FROM CONSENSUS.**

Structural: `axiom-consensus` has zero dependency on `axiom-ai` or
`axiom-guard` (tests I-6, I-7 enforce this going forward).
Behavioural: every guardian output is either consumed by the guardian itself
(history, proof) or returned to the caller as advisory data. No consumer
inside `axiom-consensus::validation`, `axiom-consensus::pow`,
`axiom-consensus::consensus`, or the `axiom-node` validation surface.
Consensus validation produces bit-identical results with or without a
`GuardianAgent` instantiated — the agent is not on that code path.

---

## Files changed / added in this work

Added:
- [crates/axiom-ai/src/guardian/mod.rs](crates/axiom-ai/src/guardian/mod.rs)
- [crates/axiom-ai/src/guardian/seeded_rng.rs](crates/axiom-ai/src/guardian/seeded_rng.rs)
- [crates/axiom-ai/src/guardian/state.rs](crates/axiom-ai/src/guardian/state.rs)
- [crates/axiom-ai/src/guardian/model.rs](crates/axiom-ai/src/guardian/model.rs)
- [crates/axiom-ai/src/guardian/decision.rs](crates/axiom-ai/src/guardian/decision.rs)
- [crates/axiom-ai/src/guardian/agent.rs](crates/axiom-ai/src/guardian/agent.rs)
- [crates/axiom-ai/src/guardian/report.rs](crates/axiom-ai/src/guardian/report.rs)
- [crates/axiom-ai/src/guardian/aggregation.rs](crates/axiom-ai/src/guardian/aggregation.rs)
- [crates/axiom-ai/src/guardian/isolation_tests.rs](crates/axiom-ai/src/guardian/isolation_tests.rs)
- [GUARDIAN-DESIGN.md](GUARDIAN-DESIGN.md) (this file)

Modified:
- [crates/axiom-ai/Cargo.toml](crates/axiom-ai/Cargo.toml) — added
  `axiom-primitives`, `axiom-crypto`, `sha3` deps.
- [crates/axiom-ai/src/lib.rs](crates/axiom-ai/src/lib.rs) — exposed
  `guardian` module.
