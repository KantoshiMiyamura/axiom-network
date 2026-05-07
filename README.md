# Axiom Network — v2 Testnet

> ⚠️ **TESTNET — not for real funds.** Tokens mined or transferred on this
> network have **no monetary value, ever**. Do not move real money through
> this chain. Wait for an explicit mainnet announcement.
>
> - **Network identifier:** `axiom-test-v2` (separate from the v1 testnet,
>   `axiom-test-1`). v1 and v2 nodes refuse each other at the version-message
>   exchange — chains do not converge, tokens do not cross.
> - **Branch:** `v2-testnet-release`. Tagged signed releases ship from this
>   branch as `v2.0.0-testnet.x`.
> - **What's new in v2:** post-quantum hybrid P2P handshake (X25519 + ML-KEM-768),
>   AEAD-framed encrypted transport (XChaCha20-Poly1305), hybrid node identity
>   (ML-DSA-87 + Ed25519), strict-next replay protection, wallet key rotation,
>   best-effort UPnP port-forward, `axiom connect` / `axiom myip` /
>   `axiom wallet rotate` CLI commands. Full design at
>   [docs/V2_PROTOCOL.md](docs/V2_PROTOCOL.md).
> - **Verify before running:** every release binary is hashed in `SHA256SUMS`
>   and signed with `SHA256SUMS.minisig`. The signing public key is
>   [docs/minisign.pub](docs/minisign.pub). Instructions:
>   [docs/VERIFYING_RELEASES.md](docs/VERIFYING_RELEASES.md).

---

**Status:** v2 Testnet — `v2.0.0-testnet.1` — **not mainnet**
**License:** MIT
**Source:** <https://github.com/KantoshiMiyamura/axiom-network>

Axiom Network is a post-quantum blockchain implementing Proof of Useful Compute
(PoUC). Transactions are signed with ML-DSA-87 (FIPS 204). The chain-local
token, `AXM`, has **no monetary value on this testnet** — coins mined here are
throwaway test tokens, not an asset.

> This is a community-run, open-source research and engineering release. Do not
> rely on testnet tokens having any value, ever. Do not move real funds through
> this network until an explicit mainnet announcement.

---

## What's in this repo

This repository contains two layers of code with **different maturity levels**:

- **Stable (testnet):** the blockchain core — node, RPC, wallet library, CLI, consensus, networking. This is what `v2.0.0-testnet.1` ships and what the release pipeline builds.
- **Experimental (in development):** the desktop wallet, the off-chain community platform, and the AxiomMind guardian daemon. These live in this repo for development convenience but are **not part of the released testnet binaries**. See [docs/MODULES.md](docs/MODULES.md) for status, scope, and what's missing per module.

### Stable — blockchain core

| Crate / dir          | Purpose                                              |
|----------------------|------------------------------------------------------|
| `crates/axiom-primitives` | Hash, address, byte types                       |
| `crates/axiom-crypto` | ML-DSA-87 signing, BIP39 seed handling              |
| `crates/axiom-protocol` | Transaction / block wire format                   |
| `crates/axiom-consensus` | PoW header validation, LWMA difficulty retarget  |
| `crates/axiom-node`  | P2P, mempool, orphan pool, validation, state        |
| `crates/axiom-rpc`   | HTTP/WebSocket RPC                                   |
| `crates/axiom-wallet` | Keys, addresses, UTXO tracking                     |
| `crates/axiom-cli`   | `axiom`, `axiom-node`, `axiom-keygen`, `axiom-bump-fee` |
| `crates/axiom-signer` | `axiom-sign` transaction signer                    |
| `crates/axiom-ai`    | PoUC compute market                                  |
| `crates/axiom-guard` | Per-node persistent identity (ML-DSA-87 keypair)    |
| `web/`               | Static website (downloads, docs, releases pages)    |
| `docs/`              | Architecture, protocol, operator, security docs     |
| `scripts/testnet/`   | Local 4-node testnet harness (docker-compose + drivers) |

### Experimental — optional modules (not part of the testnet release)

| Crate / dir          | Purpose                                              | Status |
|----------------------|------------------------------------------------------|--------|
| `wallet/`            | Tauri 2 desktop wallet (React + Rust)                | Build gated off in CI; ready for hardening pass |
| `shared/`            | Community-platform shared types and crypto           | Compiles; library only |
| `server/` (Rust)     | Off-chain community server (auth, jobs, messaging)   | Compiles; security refactor pending |
| `client/`            | Community CLI/TUI client                             | Skeleton — TUI rendering not implemented |
| `server/axiom-mind/` | AxiomMind guardian daemon (Python, advisory only)    | Standalone; not wired to consensus |

Read [docs/MODULES.md](docs/MODULES.md) before depending on any experimental module.

---

## Build from source

```bash
# Rust 1.93.1 (pinned via rust-toolchain.toml)
cargo build --release --workspace
cargo test  --release --workspace
```

The test suite currently reports **993 passed, 0 failed, 4 ignored** on the
tracked revision. `cargo clippy --workspace --release --all-targets` reports
**0 errors**.

---

## Run a node

Axiom has no project-operated bootstrap servers and no project-operated DNS
seeds. A fresh node starts as a sovereign chain. To join an existing network,
you connect to peers you know.

The release archive ships with one main binary at the root: **`axiom`**. The
internal binaries (`axiom-node`, `axiom-keygen`, `axiom-sign`, `axiom-bump-fee`)
live under `tools/` for advanced use.

### Quick start (one command)

```bash
./axiom mine
```

That creates a wallet, starts a node, and begins mining on your own chain.
Run `./axiom` with no arguments for a quick-start menu.

### Join a known peer

```bash
./axiom mine --peer <host>:9000
```

`--peer` is repeatable — pass it multiple times to wire several known peers.

### Useful commands

```bash
./axiom               # quick-start menu (status if a wallet already exists)
./axiom status        # node + chain status
./axiom wallet balance  # wallet balance
./axiom version       # build info
```

### Advanced — direct node binary

```bash
./tools/axiom-node \
  --network test \
  --data-dir ./testnet-data \
  --p2p-bind 0.0.0.0:9000 \
  --rpc-bind 127.0.0.1:8332
```

Query the node:

```bash
curl -s http://127.0.0.1:8332/tip
curl -s http://127.0.0.1:8332/peer_count
curl -s http://127.0.0.1:8332/metrics
```

---

## Wallet & keys (local only)

```bash
./target/release/axiom-keygen        # writes wallet.json to the current dir
./target/release/axiom               # interactive wallet CLI
```

**Wallet keys never leave the local machine.** The node does not know your
seed phrase, never stores it, and has no RPC to retrieve it.

If you lose your wallet file and seed phrase, the coins it controls are
permanently unrecoverable. This is testnet — treat all keys as disposable.

---

## Mining (testnet)

The node mines by default when started with a miner address. See
[docs/OPERATOR_RUNBOOK.md](docs/OPERATOR_RUNBOOK.md) for the mining flags,
expected hashrate on commodity hardware, and the LWMA retarget behavior.

Testnet difficulty adapts — early blocks are fast, later blocks slow down to
the target interval. This is expected and documented.

---

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — component topology
- [docs/PROTOCOL.md](docs/PROTOCOL.md) — wire format, message types
- [docs/CONSENSUS-RULES.md](docs/CONSENSUS-RULES.md) — validation rules
- [docs/ECONOMICS.md](docs/ECONOMICS.md) — supply, subsidy, fees
- [docs/OPERATOR_RUNBOOK.md](docs/OPERATOR_RUNBOOK.md) — running a node
- [docs/RPC-REFERENCE.md](docs/RPC-REFERENCE.md) — endpoint catalog
- [docs/API.md](docs/API.md) — HTTP API reference
- [docs/SECURITY.md](docs/SECURITY.md) — threat model, disclosure policy
- [docs/VERIFYING_RELEASES.md](docs/VERIFYING_RELEASES.md) — checksum + minisign
- [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) — release runbook

---

## Known limitations of this release

1. **No multi-host WAN stability evidence.** Local 4-node simulations on a
   single host are reproducible via `scripts/testnet/`. Multi-host WAN evidence
   is not yet published.
2. **No funded mempool stress evidence.** Mempool admission has been exercised
   with the validation path; a real funded-flood test is pending.
3. **No mainnet genesis has been declared.** Anyone running `--network main`
   does so at their own risk on an undefined chain.
4. **Wallet installer is not part of this release.** Only the node binaries
   are shipped. Use the CLI wallet (`axiom-keygen`, `axiom`).

These are tracked and will be closed before any mainnet announcement.

---

## Contributing & security

- Bugs / issues: open a GitHub issue.
- Security reports: follow [docs/SECURITY.md](docs/SECURITY.md).
- Do not report security issues through public channels.

---

## License

MIT — see [LICENSE](LICENSE).
