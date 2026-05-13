# Axiom Network v2.0.0-testnet.3 — Release Notes

> ⚠️ **TESTNET — NOT FOR REAL FUNDS.** Tokens on `axiom-test-v2` have no
> monetary value. Mainnet has not launched. Wait for an explicit mainnet
> announcement before moving real money.

This is a **second hotfix** on top of `v2.0.0-testnet.1` /
`v2.0.0-testnet.2`. It fixes a real initial-block-download (IBD) bug
that prevented a fresh node from catching up to an already-running peer
in a local two-node test.

The protocol, wire format, consensus rules, signing tag, and on-chain
state machine are **unchanged**. The fix is entirely in the per-peer
message loop and the handshake-complete sync trigger.

---

## The bug in `v2.0.0-testnet.2`

Local two-node test:

- Node A running at height ~1410.
- Node B starts fresh at height 0, dials Node A.
- Handshake completes.
- Node B receives newly-mined blocks 1409/1410 broadcast from A.
- Their parents are unknown, so they land in B's orphan pool.
- B's per-peer orphan limit (`MAX_ORPHANS_PER_PEER = 10`) trips:
  ```
  ORPHAN_REJECTED reason=peer_limit_exceeded max=10
  ```
- IBD never completes.

Two cooperating root causes:

1. **No pull-IBD trigger on handshake-complete.** The handshake-complete
   handler in [crates/axiom-cli/src/p2p.rs](../crates/axiom-cli/src/p2p.rs)
   only kicked in when `our_height > peer_height` — and only as an
   asymmetric *push*, where the taller side blasted raw `Message::Block`
   frames at the fresh peer. The symmetric pull (a fresh node asking a
   taller peer for headers) was never wired. The fresh node was passive
   between connect and the next 5-second tick of `start_sync_task`.

2. **Every non-handshake message was processed in its own tokio task.**
   `tokio::spawn(async move { handle_message(...) })` per message meant
   that even when wire delivery was ordered, the application layer
   raced — N concurrent tasks racing through `apply_block`, parents
   missing for everything but the lucky one that scheduled first, the
   rest hitting the orphan pool.

Either bug alone would degrade IBD; together they make a fresh node
fundamentally unable to sync from a running peer once the orphan cap
trips.

This was a **sync-availability** bug, not consensus or security: no
forks possible, no replay risk, no key exposure.

---

## The fix

Two changes in [crates/axiom-cli/src/p2p.rs](../crates/axiom-cli/src/p2p.rs):

### A. Pull-IBD trigger on handshake-complete

The old `IBD_PUSH` branch (taller side pushes blocks) is removed. The
new handshake-complete path unconditionally sends `Message::GetTip` to
the peer. The existing `Tip` handler
([NetworkService::sync_with_peer](../crates/axiom-node/src/network/service.rs))
then decides — by comparing heights and chainwork — whether to follow
up with `GetHeaders` and pull a chain. The flow now is:

```
B → A : Version
A → B : Version, VerAck
B → A : VerAck
B → A : GetTip
A → B : Tip(height=1410, hash=A_tip)
B → A : GetHeaders(B_genesis, MAX)      ← B's sync_with_peer fires here
A → B : Headers(h_1 ... h_2000)
B → A : GetData(blocks for new headers)
A → B : Block(1), Block(2), ...
B → A : GetHeaders(...)                 ← IBD_CONTINUE, loops to tip
...
```

Pure pull, with backpressure: `MAX_PARALLEL_BLOCK_REQUESTS = 16` in
flight at a time, headers requested in batches of `MAX_HEADERS_PER_MESSAGE`,
and the IBD watchdog rotates a peer if a block request stalls past
`BLOCK_REQUEST_TIMEOUT = 120s`.

### B. Per-peer messages handled inline, in wire order

The peer-loop dispatch `tokio::spawn(async move { handle_message(...) })`
becomes a synchronous `handle_message(...).await` inside the loop.
Messages from a single peer now flow through `apply_block` in the order
they arrived on the wire — which is the order the peer sent them, and
during IBD that is height-ascending order.

Side effect: the read loop pauses while a single message handler runs.
For IBD blocks this is the right trade — block application takes the
node write lock either way, so spawning never actually got parallelism;
it just permuted application order. For non-block traffic (Inv, Tx,
Ping) the handlers complete in microseconds.

### C. Regression test added

[crates/axiom-node/tests/ibd_catchup_from_zero.rs](../crates/axiom-node/tests/ibd_catchup_from_zero.rs)
adds three tests:

| Test | Asserts |
|---|---|
| `getheaders_from_genesis_returns_full_chain` | A 25-block chain serves all 25 headers in one batch when the locator is genesis, forming a contiguous chain ending at A's tip. |
| `serial_block_apply_25_blocks_no_orphans` | Feeding 25 in-order blocks to a fresh node reaches height 25 with the orphan pool empty (i.e. `MAX_ORPHANS_PER_PEER` is never approached under correct ordering). |
| `out_of_order_burst_reconnects_via_orphan_pool` | If 4 future blocks arrive before their parent, they hold as orphans, then cascade-apply on parent arrival — confirming the pool is the right safety net for transient out-of-order delivery. |

---

## Migration

### If you ran `v2.0.0-testnet.2`

If you only ever ran solo (no peers), no action needed — your local
chain is unaffected by this fix.

If you tried to peer with another node and saw `ORPHAN_REJECTED`
or your node never advanced past height 0, the data directory is fine
to keep — install `v2.0.0-testnet.3` and restart. The new node will
issue `GetTip` immediately after handshake and pull the chain.

### Fresh installs

Run `axiom mine` (defaults to v2 testnet as of `v2.0.0-testnet.2`).
If you have a known peer, add `--peer host:9000`.

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
curl -fsSLO https://github.com/KantoshiMiyamura/axiom-network/releases/download/v2.0.0-testnet.3/SHA256SUMS
curl -fsSLO https://github.com/KantoshiMiyamura/axiom-network/releases/download/v2.0.0-testnet.3/SHA256SUMS.minisig
curl -fsSLO https://raw.githubusercontent.com/KantoshiMiyamura/axiom-network/v2.0.0-testnet.3/docs/minisign.pub

# 2. Verify the signature on the manifest
minisign -Vm SHA256SUMS -p minisign.pub
# expect: Signature and comment signature verified

# 3. Verify each artifact's hash
sha256sum -c SHA256SUMS
```

See [`docs/VERIFYING_RELEASES.md`](VERIFYING_RELEASES.md) for the upstream
`minisign` install instructions.

---

## Artifacts

| Platform | Filename |
|---|---|
| Windows x86_64 | `axiom-v2.0.0-testnet.3-x86_64-pc-windows-msvc.zip` |
| Linux x86_64, glibc 2.31+ | `axiom-v2.0.0-testnet.3-x86_64-unknown-linux-gnu.tar.gz` |
| macOS | not produced for this release; build from source: `cargo build --release -p axiom-cli` |

Archive layout is identical to `v2.0.0-testnet.2`.

---

## Source of truth

- **Spec:** [docs/V2_PROTOCOL.md](V2_PROTOCOL.md)
- **Previous release notes:** [RELEASE_NOTES_v2.0.0-testnet.2.md](RELEASE_NOTES_v2.0.0-testnet.2.md), [RELEASE_NOTES_v2.0.0-testnet.1.md](RELEASE_NOTES_v2.0.0-testnet.1.md)
- **Branch:** [`v2-testnet-release`](https://github.com/KantoshiMiyamura/axiom-network/tree/v2-testnet-release)
- **Tag (when published):** `v2.0.0-testnet.3`
- **Bug reports:** open an issue on GitHub.
- **Security:** see [docs/SECURITY.md](SECURITY.md) for the disclosure policy.
