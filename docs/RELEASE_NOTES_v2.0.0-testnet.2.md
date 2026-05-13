# Axiom Network v2.0.0-testnet.2 — Release Notes

> ⚠️ **TESTNET — NOT FOR REAL FUNDS.** Tokens on `axiom-test-v2` have no
> monetary value. Mainnet has not launched. Wait for an explicit mainnet
> announcement before moving real money.

This is a **single-purpose hotfix** on top of `v2.0.0-testnet.1`. It fixes
a CLI default-network bug so that `axiom mine` actually joins the v2
testnet chain (`axiom-test-v2`) instead of an unintended mainnet chain
(`axiom-mainnet-1`).

The protocol, wire format, consensus rules, signing tag, and on-chain
state machine are **unchanged** from `v2.0.0-testnet.1`. This release
ships the same binaries with the corrected default.

---

## The bug in `v2.0.0-testnet.1`

`v2.0.0-testnet.1` advertises itself as the v2 testnet release, but the
`axiom mine` quick-start command (the recommended way to run a node)
hard-coded `"mainnet"` as the network string in three places inside
`crates/axiom-cli/src/bin/axiom.rs`:

1. The wallet-metadata `"network"` field saved to `wallet.dat`.
2. The pre-mining console banner shown to the user.
3. The `network` argument passed into the internal `cmd_start(…)` call
   that actually constructs the node config.

Item 3 is the one with observable effect. With `network = "mainnet"`,
`parse_network` returns `Network::Mainnet`, whose `chain_id()` is
`axiom-mainnet-1` — not the intended `axiom-test-v2`.

### What this did and did not affect

| Concern | Affected? | Why |
|---|---|---|
| Consensus / fork risk | **No** | Domain-separated tx signing tag includes the chain id, so a transaction signed under `axiom-mainnet-1` is not a valid signature under `axiom-test-v2` and vice versa. No cross-chain replay possible. |
| Peering with v1 (`axiom-test-1`) | **No** | The chain id is checked at the `version`-message handshake. v1 and v2 nodes refuse each other regardless. |
| Peering with intended v2 testnet (`axiom-test-v2`) | **Yes** | A `v2.0.0-testnet.1` node defaulting to `axiom-mainnet-1` cannot peer with anyone running on `axiom-test-v2`. The two formed disjoint chains. |
| Wallet keys / funds | **No** | Keystore format is identical. Keys are reusable on whichever chain they end up on. There are no real funds — this is testnet. |

This is a UX / deployment bug, not a consensus or security bug.

---

## The fix

Three lines in `crates/axiom-cli/src/bin/axiom.rs`:

```diff
@@ axiom.rs:1927 (wallet.dat metadata)
-            "network": "axiom-mainnet-v1",
+            "network": "axiom-test-v2",

@@ axiom.rs:1990 (pre-mining banner)
-    println!("  Network: axiom-mainnet-v1");
+    println!("  Network: axiom-test-v2");

@@ axiom.rs:2022 (network arg passed into cmd_start)
-        "mainnet".to_string(),
+        "test".to_string(),
```

Plus two policy fixes flipping the default `--network` value of the
`axiom start` subcommand and the raw `axiom-node` binary from `mainnet`
to `test`. There is no production mainnet to default to yet, and a
"mainnet" default that points at the chain id `axiom-mainnet-1` is
misleading — anyone running it would join a non-existent fake mainnet.

---

## Migration

### If you ran `v2.0.0-testnet.1`

Your node has been running on `axiom-mainnet-1`, not the intended
`axiom-test-v2` testnet. To switch to the real v2 testnet:

1. Stop the node.
2. Delete the data directory it created
   (`%APPDATA%\Axiom\Network\data` on Windows, `~/.axiom/data` on
   Linux, or wherever you pointed `--data-dir`). The state, blocks,
   peers, and mempool there are from the wrong chain.
3. Optionally back up your `wallet.dat` and seed phrase first — the
   keystore format is unchanged and the same keys work on the v2
   testnet. The `"network"` metadata inside `wallet.dat` will say
   `axiom-mainnet-v1` in the old file; that field is informational
   and not load-bearing.
4. Install `v2.0.0-testnet.2` and run `axiom mine` (or `axiom start
   --network test`) as normal.

There is nothing on the old `axiom-mainnet-1` chain worth migrating —
no funds, no users, no meaningful state. The clean restart is the
recommended path.

### Fresh installs

Just download `v2.0.0-testnet.2` and run `axiom mine`. No special
steps. The default network is now `test`.

---

## Network identity (unchanged)

| Setting | Value |
|---|---|
| Chain id | `axiom-test-v2` |
| P2P default port | `9000` |
| RPC default bind | `127.0.0.1:8332` (localhost only) |
| Genesis | embedded, fresh; not shared with v1 |

---

## Verification

Every release artifact is hashed in `SHA256SUMS` and signed with
`SHA256SUMS.minisig`. The signing public key is in
[`docs/minisign.pub`](minisign.pub). Verification:

```bash
# 1. Download artifacts + signature + pubkey
curl -fsSLO https://github.com/KantoshiMiyamura/axiom-network/releases/download/v2.0.0-testnet.2/SHA256SUMS
curl -fsSLO https://github.com/KantoshiMiyamura/axiom-network/releases/download/v2.0.0-testnet.2/SHA256SUMS.minisig
curl -fsSLO https://raw.githubusercontent.com/KantoshiMiyamura/axiom-network/v2.0.0-testnet.2/docs/minisign.pub

# 2. Verify the signature on the manifest
minisign -Vm SHA256SUMS -p minisign.pub
# expect: Signature and comment signature verified

# 3. Verify each artifact's hash
sha256sum -c SHA256SUMS
```

See [`docs/VERIFYING_RELEASES.md`](VERIFYING_RELEASES.md) for the upstream
`minisign` install instructions if you don't already have it.

---

## Artifacts

| Platform | Filename |
|---|---|
| Windows x86_64 | `axiom-v2.0.0-testnet.2-x86_64-pc-windows-msvc.zip` |
| Linux x86_64, glibc 2.31+ | `axiom-v2.0.0-testnet.2-x86_64-unknown-linux-gnu.tar.gz` |
| macOS | not produced for this release; build from source: `cargo build --release -p axiom-cli` |

Archive layout is identical to `v2.0.0-testnet.1`.

---

## Source of truth

- **Spec:** [docs/V2_PROTOCOL.md](V2_PROTOCOL.md)
- **Previous release notes:** [RELEASE_NOTES_v2.0.0-testnet.1.md](RELEASE_NOTES_v2.0.0-testnet.1.md)
- **Branch:** [`v2-testnet-release`](https://github.com/KantoshiMiyamura/axiom-network/tree/v2-testnet-release)
- **Tag (when published):** `v2.0.0-testnet.2`
- **Bug reports:** open an issue on GitHub.
- **Security:** see [docs/SECURITY.md](SECURITY.md) for the disclosure policy.
