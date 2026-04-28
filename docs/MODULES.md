# Modules

Axiom Network ships as a blockchain core (the `crates/axiom-*` set under
`crates/`) plus a set of **experimental modules** that live in this repo
for development convenience. The experimental modules are **not** part of
the `v1.0.1-testnet.7` release: they are not built by the release
pipeline, not signed, not packaged, and not advertised on the downloads
page.

This document gives the status of each experimental module and what is
required before it can be promoted to stable.

---

## Stability levels

| Level | Meaning |
|-------|---------|
| **Stable (testnet)** | Built, tested, signed, and shipped as part of the testnet release. Backwards-compatible changes only within a release line. |
| **Experimental** | Tracked in this repo, compiles in the workspace, may be incomplete or insecure. No release artifacts. May change without notice. |

The blockchain core (`crates/axiom-*`) is **Stable (testnet)**. Everything
listed below is **Experimental** unless explicitly marked otherwise in a
later release.

---

## `wallet/` — Desktop wallet (Tauri 2)

**Crate:** `axiom-desktop-wallet` (`wallet/src-tauri/`)
**Frontend:** React + TypeScript + Vite (`wallet/src/`)
**Status:** Experimental. Build gated off in `.github/workflows/release.yml` (`build-wallet` job has `if: false`).

Cross-platform desktop wallet. Talks to a local node via the RPC layer.
Uses the OS keyring plus an additional ChaCha20-Poly1305 + HKDF
encrypted-at-rest layer for seed/keystore data. Pages: Welcome, Unlock,
Dashboard, Send, Receive, History, Backup, Settings. Session
auto-locks on a watchdog timer.

What's implemented:

- BIP39 seed phrase create / import
- ML-DSA-87 signing through `axiom-wallet`
- Encrypted at-rest storage (keyring + ChaCha20-Poly1305)
- Send / receive / history / backup UI
- Per-session auto-lock

What's missing before promotion:

- Independent security review of the keyring + AEAD layer
- Hardware wallet path (intentionally out of scope for v1)
- Multi-account UX polish
- Re-enabling the `build-wallet` matrix in CI and signing the installers

When to use today: local development against a node you control. **Do
not** treat this wallet as a production-grade key custodian until it
has shipped a signed installer.

---

## `shared/` — Community platform shared types

**Crate:** `axiom-community-shared`
**Status:** Experimental. Library only — no binary, no surface to users.

Common types, error enum, ML-DSA-87 helpers, and wire-protocol structs
used by the community `server/` and `client/`. Has no dependency on the
blockchain core beyond the cryptographic primitives.

What's missing before promotion:

- Pin the wire format (versioning, breaking-change policy)
- Public API documentation pass

---

## `server/` (Rust) — Community platform server

**Crate:** `axiom-community-server`
**Status:** Experimental. Compiles cleanly but has a known security
refactor pending.

Off-chain HTTP service: challenge-response authentication using
ML-DSA-87 signatures, role-based access control (5 levels: Member →
CoreDev), Postgres-backed persistence (`server/migrations/`), rate
limiting, audit logging, and handlers for messaging, jobs, disputes,
moderation, and roles.

What's missing before promotion:

- Apply the security refactor tracked in `.claude/plans/typed-jumping-mochi.md`
  (middleware ordering, in-handler RBAC defense-in-depth, complete
  `UserContext` extraction across all protected handlers)
- Lock down `CorsLayer::permissive()` for any non-dev deployment
- Document the API in `docs/COMMUNITY-API.md` (does not yet exist)
- TLS termination guidance + production secrets handling docs
- Independent review of the JWT + session lifecycle

This service has **no consensus role**. It cannot affect the chain.

---

## `client/` — Community platform CLI/TUI client

**Crate:** `axiom-community-client`
**Binary:** `axiom-community`
**Status:** Experimental. **Skeleton only** — see warnings below.

Terminal client intended to talk to `axiom-community-server`. The CLI
sub-commands (`login`, `post`, `messages`, `jobs`, `create-job`,
`version`, `help`) are wired through `client/src/cli.rs`. The
interactive TUI is **not yet implemented**: `client/src/ui/mod.rs`
exposes `App`, but `draw()`, `App::handle_key()`, and
`App::select_item()` are empty stubs.

What's missing before promotion:

- Implement TUI rendering (`draw()`)
- Implement key dispatch (`App::handle_key`, `App::select_item`)
- Wire CLI commands to live server APIs end-to-end
- Remove `#![allow(dead_code)]` once the surface is consumed
- Integration tests against a local server

The binary prints a startup banner stating it is experimental.

---

## `server/axiom-mind/` and `server/axiom_mind.py` — AxiomMind guardian

**Status:** Experimental. **Standalone Python service.** Not part of any
Rust workspace and not built by CI.

`axiom_mind.py` is a long-running Python daemon that monitors a node,
optionally calls an LLM (Anthropic API) for advisory analysis, and
exposes a FastAPI HTTP + WebSocket dashboard on port 7777. The
`server/axiom-mind/` package contains the rule, anomaly, correlation,
risk-scoring, audit, and policy engines that back the daemon.

This is **advisory only**. AxiomMind:

- Cannot modify chain state
- Cannot accept or reject blocks
- Cannot affect mempool admission
- Has no path into consensus

It runs out-of-process from the node. If it goes down, the node is
unaffected. If the LLM is unreachable or no `ANTHROPIC_API_KEY` is
set, the rule and anomaly engines still run locally.

Note: this is **not** the same as the `axiom-guard` Rust crate, which
provides a per-node persistent ML-DSA-87 identity keypair. The names
are unfortunately similar; they are independent components.

What's missing before promotion:

- Document the service contract: what reports it produces, how to
  consume them, and the (signed) format of those reports
- Decide whether it lives in this repo or in its own
- A clean systemd / container deployment story
- Test coverage in CI (currently tested only by the Python tests
  in `server/axiom-mind/tests/`)

---

## How to build experimental modules locally

```bash
# Community shared library
cargo build -p axiom-community-shared

# Community server (requires PostgreSQL + DATABASE_URL)
cargo build -p axiom-community-server

# Community CLI/TUI client
cargo build -p axiom-community-client

# Desktop wallet (requires Node.js + Tauri CLI)
cd wallet
npm ci
cargo install --locked --version ^2 tauri-cli
cargo tauri build
```

The full workspace check passes:

```bash
cargo check --workspace
```

---

## Promotion criteria

A module is considered for promotion from Experimental to Stable when:

1. It compiles and tests cleanly on the supported targets in CI.
2. It has user-facing documentation in `docs/`.
3. Its security model is reviewed and any critical findings are closed.
4. The release pipeline builds, signs, and publishes its artifacts.
5. The README and downloads page advertise it without caveats.

Until all five hold for a module, it stays in this file.
