# Axiom Network v2.0.0-testnet.1 — Release Notes

> ⚠️ **TESTNET — NOT FOR REAL FUNDS.** Tokens on `axiom-test-v2` have no
> monetary value. Mainnet has not launched. Wait for an explicit mainnet
> announcement before moving real money.

This is the **first signed release of the v2 line**. It supersedes the v1
testnet (`axiom-test-1`, master branch) for anyone wanting the new
post-quantum transport, hybrid signatures, replay protection, key
rotation, and friend-to-friend UX.

---

## What v2 changes

The v2 line is a deliberate, breaking iteration of the v1 protocol. v1
and v2 nodes refuse each other at handshake time — different chain id
(`axiom-test-1` vs `axiom-test-v2`), different domain-separated tx
signing tag, no cross-talk.

### Headline features

| Feature | Where | What it gives you |
|---|---|---|
| Post-quantum P2P transport | `axiom-node::network::p2p_v2` | Hybrid X25519 + ML-KEM-768 (FIPS 203) handshake + XChaCha20-Poly1305 AEAD framing. Breaking either curve alone does not unmask traffic. |
| Hybrid node identity | `axiom-guard::fingerprint_v2` | Each peer is identified by a stable 32-byte hash of (ML-DSA-87 ⨯ Ed25519) pubkeys. Substituting either key changes the peer ID — no key-substitution attack survives. |
| Replay protection | `axiom-node::validation` | Strict-next per-address nonce at the consensus validation layer with reorg-safe storage. On-chain `tx.nonce` equals the 1-indexed transaction number per address. |
| Wallet key rotation | `axiom-wallet::rotation_v2` + `axiom wallet rotate` | Roll a wallet's identity to a fresh ML-DSA-87 keypair without burning historical UTXOs. Records signed by the old key, persisted as a local linkage chain. |
| UPnP / IGD port-forward | `axiom-node::network::upnp` | Best-effort, non-blocking, opt-out (`--no-upnp`). Routers that speak IGD give automatic inbound peer reachability; routers that don't get clear manual port-forward instructions. |
| Friend-to-friend connect UX | CLI: `axiom myip`, `axiom connect <ip>:port`, `axiom status` | Two-command path to peer with someone you know. No project-operated bootstrap servers, no DNS seeds, no central infrastructure. |
| End-to-end replay-protection fix | `axiom-node::state::ChainState::apply_block` | On-chain `tx.nonce` is now consecutive (1, 2, 3, …) instead of odd-only (1, 3, 5, …). v2-only consensus change. |

### Local-first peer model

There are **no project-operated bootstrap servers and no project-operated
DNS seeds** in v2. A fresh node starts as a sovereign chain on its own;
you join an existing network by connecting to peers you know.

```
# Start your own chain
./axiom mine

# Join a known peer
./axiom mine --peer 203.0.113.5:9000

# Or connect dynamically to a running node
./axiom connect 203.0.113.5:9000
```

### Network identity

| Setting | Value |
|---|---|
| Chain id | `axiom-test-v2` |
| P2P default port | `9000` |
| RPC default bind | `127.0.0.1:8332` (localhost only) |
| Genesis | embedded, fresh; not shared with v1 |

A v2 node will refuse to handshake with a v1 node (chain-id mismatch at
the `version`-message exchange) and vice versa. Tokens cannot cross.

---

## Migrating from v1

You don't migrate. v1 (`axiom-test-1`) is a separate testnet on `master`
that continues to ship `v1.0.1-testnet.x` releases. v2 is a fresh chain
with its own genesis. Old v1 keystores are not loadable as v2 wallets
without re-running `axiom wallet create` (the keystore format itself is
compatible, but the addresses live on different chains).

---

## CLI surface (recap)

| Command | What it does |
|---|---|
| `axiom mine` | One-step: creates wallet, starts node, mines locally |
| `axiom mine --peer HOST:9000` | Same, but joins a known peer |
| `axiom start` | Run a node without auto-mining |
| `axiom status` | Show node + chain + peer + external-mapping status |
| `axiom myip` | Print this machine's public IP + port |
| `axiom connect HOST:9000` | Dial a peer dynamically (node must be running) |
| `axiom wallet balance` | Local wallet balance |
| `axiom wallet send` | Build, sign, and submit a transaction |
| `axiom wallet rotate` | Rotate wallet identity to a fresh keypair |
| `axiom wallet address` | Print the wallet's current address |
| `axiom version` | Build info |
| `axiom` | Quick-start menu (wallet-aware) |

`axiom-node`, `axiom-keygen`, `axiom-sign`, `axiom-bump-fee` are under
`tools/` for advanced use.

---

## Test posture

`cargo test --release -p axiom-node --tests` on the release commit:

| Metric | Value |
|---|---|
| Test binaries | 26 |
| Active tests | **418** |
| Passed | **418** |
| Failed | 0 |
| Ignored | 4 (pre-existing externally-networked gates — not regressions) |

Plus 191 library unit tests (`--lib`). The full pass/fail matrix is
documented in [V2_PROTOCOL.md §11](V2_PROTOCOL.md#11-integration-test-passfail-matrix-stage-9).

---

## Verification

Every release artifact is hashed in `SHA256SUMS` and signed with
`SHA256SUMS.minisig`. The signing public key is in
[`docs/minisign.pub`](minisign.pub). Verification:

```bash
# 1. Download artifacts + signature + pubkey
curl -fsSLO https://github.com/KantoshiMiyamura/axiom-network/releases/download/v2.0.0-testnet.1/SHA256SUMS
curl -fsSLO https://github.com/KantoshiMiyamura/axiom-network/releases/download/v2.0.0-testnet.1/SHA256SUMS.minisig
curl -fsSLO https://raw.githubusercontent.com/KantoshiMiyamura/axiom-network/v2.0.0-testnet.1/docs/minisign.pub

# 2. Verify the signature on the manifest
minisign -Vm SHA256SUMS -p minisign.pub
# expect: Signature and comment signature verified

# 3. Verify each artifact's hash
sha256sum -c SHA256SUMS
```

If `minisign` is not installed, see
[`docs/VERIFYING_RELEASES.md`](VERIFYING_RELEASES.md) for the upstream
binary install instructions.

---

## Artifacts

| Platform | Filename |
|---|---|
| Windows x86_64 | `axiom-v2.0.0-testnet.1-x86_64-pc-windows-msvc.zip` |
| Linux x86_64, glibc 2.31+ | `axiom-v2.0.0-testnet.1-x86_64-unknown-linux-gnu.tar.gz` |
| macOS | not produced for this release; build from source: `cargo build --release -p axiom-cli` |

Each archive contains:

```
axiom-v2.0.0-testnet.1-<target>/
├── axiom(.exe)             ← user-facing binary
├── README.txt              ← quick-start guide (TESTNET banner, security model, etc.)
└── tools/
    ├── axiom-node(.exe)    ← direct full-node binary
    ├── axiom-keygen(.exe)  ← standalone keypair generator
    ├── axiom-sign(.exe)    ← offline transaction signer
    └── axiom-bump-fee(.exe)← replace-by-fee helper
```

---

## Known limitations

1. **macOS binaries** are not produced in this release. macOS users can
   build from source: `cargo build --release -p axiom-cli`. macOS will
   return in a later testnet release once a stable runner + toolchain
   combination is confirmed.
2. **End-to-end UPnP** cannot be CI-verified (requires a live IGD
   router). The 6 unit tests cover formatting / error / lease math; live
   verification is manual on a personal LAN.
3. **No multi-host WAN stress evidence published.** Local 4-node
   simulations are reproducible via `scripts/testnet/launch-local.sh`.
4. **Wallet rotation records** stay local — they are not yet threaded
   onto the chain. Anyone observing only the public ledger cannot tell
   that two addresses belong to the same operator without out-of-band
   linkage publication.
5. **No mainnet announcement.** Anyone running `--network mainnet`
   does so at their own risk on an undefined chain.

---

## Source of truth

- **Spec:** [docs/V2_PROTOCOL.md](V2_PROTOCOL.md)
- **Branch:** [`v2-testnet-release`](https://github.com/KantoshiMiyamura/axiom-network/tree/v2-testnet-release)
- **Tag (when published):** `v2.0.0-testnet.1`
- **Bug reports:** open an issue on GitHub.
- **Security:** see [docs/SECURITY.md](SECURITY.md) for the disclosure
  policy.
