# AI ↔ Consensus Isolation Audit

Goal: prove the AI subsystem cannot influence consensus rules, transaction
validation, or block validation. AI outputs must be advisory only and no
non-deterministic AI behaviour may leak into the consensus path.

## TL;DR

**PASS.** AI is structurally isolated from consensus by crate dependencies and
runtime data flow. Every AI consumer is read-only against consensus state, and
every "action" the AI selects (patches, RL actions) terminates inside its own
module without dispatch.

---

## 1. Where AI lives

| Crate / module | Role |
|---|---|
| `axiom-ai` | Model registry, inference jobs, PoUC compute settlement, AxiomMind v2 (neural net stub, anomaly detector, RL, self-healing, monitoring) |
| `axiom-guard` | NetworkGuard — detects attack patterns (selfish mining, fork race, timestamp skew) on already-accepted blocks |
| `axiom-node::anomaly` | Heuristic transaction anomaly scorer (deterministic, no ML) |
| `axiom-node::community` | AxiomMind v1 — keyword/pattern moderation for ephemeral chat (no ML) |

## 2. Crate-dependency graph (consensus side)

```
axiom-consensus -> { axiom-primitives, axiom-crypto, axiom-protocol }
axiom-node      -> { axiom-primitives, axiom-crypto, axiom-protocol,
                     axiom-consensus, axiom-storage, axiom-ct, axiom-wallet }
```

**Neither `axiom-consensus` nor `axiom-node` depends on `axiom-ai` or
`axiom-guard`.** Verified by inspection of `Cargo.toml` and by grepping for
`use axiom_ai::` / `use axiom_guard::` across both crates: zero matches.

## 3. AI outputs — every one is dead-ends

### 3.1 `axiom-node::anomaly::AnomalyDetector`
- Called from `Node::add_transaction` after `validate_and_compute_fee`.
- Returns `f64` score; the call site (`crates/axiom-node/src/node.rs:180-187`)
  logs the score and proceeds to `mempool.add_transaction(tx, fee_sat)`
  unconditionally. The score never gates admission.
- Detector is pure deterministic heuristics (output count, dust, address-rate
  window). No floats from ML, no global RNG, no time-dependent classification.

### 3.2 `axiom-guard::NetworkGuard`
- Hooked into block reception via `NetworkService::set_block_accepted_hook`.
  Hook is fired **after** the block has already been validated and inserted
  (`crates/axiom-node/src/network/service.rs:955-958`).
- `NetworkGuard::on_block` returns `Vec<GuardAlert>`; alerts are stored in
  RAM and exposed by RPC. There is no path from an alert back to block
  rejection or mempool eviction.

### 3.3 `axiom-ai::self_healing::SelfHealingSystem`
- `apply_patch` (line 440) is a **stub** that returns `Ok(())` without
  touching the filesystem.
- No `fs::write`, `Command::new`, or `process::*` calls anywhere in
  `crates/axiom-ai/src/`. Verified by grep.
- The "patch" data structures (`Patch`, `CodeChange`) are pure metadata for
  reporting/dashboards.

### 3.4 `axiom-ai::reinforcement_learning::ReinforcementLearningEngine`
- `Action` enum includes variants like `ApplyPatch`, `TriggerConsensus`,
  `IsolateNodes`. **None of these variants are dispatched anywhere.**
- `select_action` is called only from `ReinforcementLearningEngine::update_state`
  and used solely as input to `q_learning.learn()` for Q-value updates. The
  selected action never escapes the module.

### 3.5 `axiom-ai::inference` / `model::registry` / `compute::*`
- Pure key-value registries backed by their own fjall partitions
  (`<data_dir>/ai_registry/`, `<data_dir>/ai_jobs/`, etc.).
- No interaction with the chain's UtxoSet, mempool, or block validator.
- `amount_sat` fields on inference jobs are accounting numbers within the
  AI registry — they do **not** lock or move on-chain UTXOs.

### 3.6 `axiom-node::community::axiom_mind_classify`
- Pure keyword and run-length classifier over chat message strings.
- Affects the in-RAM gossip ring and ban-vote relay only.
- No effect on blocks, transactions, or persisted chain state.

## 4. Determinism check

Consensus validation lives in `crates/axiom-consensus/src/{validation,pow,
consensus,merkle_proof}.rs` and `crates/axiom-node/src/validation.rs`. Grep for
AI types in those files: zero hits. Grep for `rand`, `SystemTime::now`, and
any non-deterministic source in those files: only the expected uses (timestamp
checks against caller-supplied `now`, none from AI).

The AI subsystem internally uses `rand::random` (e.g.
`reinforcement_learning.rs` epsilon-greedy exploration) — but those values
never leave the RL module, so they cannot perturb the consensus state machine.

## 5. Risks found

| # | Risk | Severity | Notes |
|---|---|---|---|
| R1 | `Action::ApplyPatch` / `Action::TriggerConsensus` enum variants exist with no consumer | Low | Confusing: future code might wire them up. Currently dead. |
| R2 | `apply_patch` is a stub returning `Ok(())` | Low (today) → High (if implemented naïvely) | If a future commit makes this actually rewrite source files, it must be gated behind operator signature, never auto-applied, and never run on a node that participates in mining. |
| R3 | `SharedGuardState` uses `RwLock<NetworkGuard>` with mutable `on_block` | Low | Hook spawns a `tokio::spawn` per block (`axiom-cli/src/main.rs:222-228`). If guard locks contend, spawned tasks pile up — a memory pressure issue but not a consensus issue. |
| R4 | AI handlers in `axiom-rpc/src/handlers.rs` use `SystemTime::now()` for `registered_at` | Informational | Per-handler timestamps; not part of any signed/hashed payload that consensus sees. |

## 6. Recommended fixes

1. **R1 / R2 (dead-action hardening).** Either remove the unused
   `ApplyPatch` / `TriggerConsensus` variants from
   `crates/axiom-ai/src/reinforcement_learning.rs:36-46`, or document at the
   variant that "no dispatcher exists; this variant is for telemetry only —
   wiring this to chain mutation requires a separate security review."
2. **R2 (patch dispatcher policy).** Add a unit test that asserts
   `SelfHealingSystem::apply_patch` does not touch the filesystem
   (`assert!(!Path::new("crates/axiom-consensus/src/pow.rs").was_modified())`
   or equivalent), so a future commit can't quietly enable it.
3. **R3 (hook back-pressure).** Cap concurrent `tokio::spawn`s in the
   block-accepted hook with a bounded channel + worker pool. Out of scope
   for consensus correctness but worth fixing.

## 7. Verdict

The AI subsystem **cannot** influence consensus today. The code is laid out
deliberately — registries in their own crate, no consensus-crate dependency,
all AI hooks are post-validation observers, all AI "actions" terminate inside
the AI module — and the audit finds no path through which AI output could
mutate block, transaction, or chain state.
