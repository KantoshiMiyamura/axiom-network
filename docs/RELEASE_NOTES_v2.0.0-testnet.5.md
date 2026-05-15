# Axiom Network v2.0.0-testnet.5 — Release Notes

> ⚠️ **TESTNET — NOT FOR REAL FUNDS.** Tokens on `axiom-test-v2` have no
> monetary value. Mainnet has not launched. Wait for an explicit mainnet
> announcement before moving real money.

This is a **fourth hotfix** on top of `v2.0.0-testnet.1` / `.2` / `.3` /
`.4`. It adds the missing IBD state machine so live-broadcast blocks
during catch-up no longer fill the orphan pool.

Protocol, wire format, consensus rules, signing tag, and on-chain state
machine are **unchanged**. The fix is entirely in `NetworkService`'s
sync logic.

---

## The bug in `v2.0.0-testnet.4`

Two-node live test:

- Node A at height ~1428, still mining.
- Node B fresh at height 0, dials Node A.
- ✓ `PeerManager` sharing fixed in testnet.4 — peers connect, peers=1.
- ✓ `SYNC_CHECK` and `SYNC_NEEDED` fire — pull-IBD starts.
- ✗ Mid-sync, A broadcasts new block 1428 via Inv. B fetches it, parent
  missing, lands in B's orphan pool.
- ✗ Repeats for every new tip block. B's per-peer orphan cap trips,
  `BLOCK_ACCEPTED_ORPHAN` floods the log, IBD stalls.

### Root cause

`v2.0.0-testnet.4` had a correctly-wired pull-IBD trigger (testnet.3) and
a correctly-shared `PeerManager` (testnet.4), but the node had **no
notion of "I'm currently catching up."** Both inbound paths treated live
tip broadcasts during IBD as routine peer-to-peer traffic:

1. **`handle_inv`** for Block items blindly compared against
   `node.has_block(...)`, found the live tip wasn't stored, and shot back
   a `GetData` request — even though the live tip is hundreds or
   thousands of blocks ahead of where the header walk has reached.
2. **`handle_received_block`** for the resulting Block delivery saw the
   parent was missing and dutifully added the block to the orphan pool —
   the same orphan pool whose per-peer cap (`MAX_ORPHANS_PER_PEER = 10`)
   was designed to defend against DoS, not to absorb routine catch-up.

Every new block A mined while B was still walking the header chain
added another orphan. Ten broadcasts in, the cap tripped and the rest of
B's catch-up was silently rejected.

This is a **sync-availability** bug, not consensus or security. No fork
risk, no replay risk, no key exposure.

---

## The fix

`NetworkService` now tracks `ibd_target_height` — the highest tip any
peer has ever claimed. `is_in_ibd()` returns true while

```
local_height + IBD_SYNC_THRESHOLD < ibd_target_height
```

with `IBD_SYNC_THRESHOLD = 8` blocks of hysteresis to avoid flapping in
the final stretch of catch-up.

The target is raised in two places:

- `sync_with_peer`: when a peer's Tip claims a taller chain, record the
  claim before sending `GetHeaders`.
- `handle_headers`: each header batch reveals more of the chain; raise
  the target as the lower bound grows.

While `is_in_ibd()` is true, two gates engage:

| Gate | Path | Behavior |
|---|---|---|
| **handle_inv** | Inv → GetData | Block items are silently skipped. The header walk will fetch them in order anyway. |
| **handle_received_block** | unsolicited Block → orphan pool | A block not previously requested (`in_flight`) whose parent is missing is silently dropped. The cap-trip scenario is removed at the source. |

Solicited blocks (those we sent `GetData` for, i.e. the header-driven
IBD path itself) are unaffected — they apply normally and advance the
chain.

### When IBD exits

As `local_height` rises through the header walk, the gate condition
eventually flips and the gates re-open. From that point on:

- Inv announcements trigger `GetData` normally.
- Blocks with missing parents go to the orphan pool normally (the pool
  remains the right safety net for transient reorderings).

If a much taller peer connects later, `sync_with_peer` raises the
target again and the gates re-engage — same mechanism handles re-sync.

### Regression tests

[crates/axiom-node/tests/ibd_gates_live_traffic.rs](../crates/axiom-node/tests/ibd_gates_live_traffic.rs)
adds five tests covering the state machine and both gates:

| Test | Asserts |
|---|---|
| `tip_from_taller_peer_enters_ibd_state` | Tip(height=1410) at local_height=0 records the target and flips `is_in_ibd()` to true. |
| `inv_for_block_is_suppressed_during_ibd` | Inv for an unknown block during IBD produces NO outbound GetData. |
| `unsolicited_orphan_block_is_dropped_during_ibd` | An unsolicited Block with missing parent during IBD is silently dropped — orphan_count stays at 0. |
| `ibd_exits_when_local_catches_up_to_target` | After local crosses `target - IBD_SYNC_THRESHOLD`, `is_in_ibd()` returns false and the Inv gate re-opens. |
| `end_to_end_ibd_with_concurrent_mining_no_orphan_overflow` | Mirrors the field repro: A mines 25 blocks, B IBDs against target=20 while A "broadcasts" the 5 newer tip blocks via Inv mid-sync; B catches up to height 25 with orphan_count=0 throughout. |

---

## Migration

### If you ran `v2.0.0-testnet.4`

If you saw `BLOCK_ACCEPTED_ORPHAN` flooding the log during catch-up,
that's this bug. Install `v2.0.0-testnet.5` and restart. Data directory
is fine to keep; nothing was applied to your chain that needs reverting.

### Fresh installs

Run `axiom mine` as normal. With a known peer: `axiom mine --peer host:9000`.

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

```bash
curl -fsSLO https://github.com/KantoshiMiyamura/axiom-network/releases/download/v2.0.0-testnet.5/SHA256SUMS
curl -fsSLO https://github.com/KantoshiMiyamura/axiom-network/releases/download/v2.0.0-testnet.5/SHA256SUMS.minisig
curl -fsSLO https://raw.githubusercontent.com/KantoshiMiyamura/axiom-network/v2.0.0-testnet.5/docs/minisign.pub
minisign -Vm SHA256SUMS -p minisign.pub
sha256sum -c SHA256SUMS
```

See [`docs/VERIFYING_RELEASES.md`](VERIFYING_RELEASES.md) for upstream
`minisign` install instructions.

---

## Artifacts

| Platform | Filename |
|---|---|
| Windows x86_64 | `axiom-v2.0.0-testnet.5-x86_64-pc-windows-msvc.zip` |
| Linux x86_64, glibc 2.31+ | `axiom-v2.0.0-testnet.5-x86_64-unknown-linux-gnu.tar.gz` |
| macOS | not produced for this release; build from source: `cargo build --release -p axiom-cli` |

---

## Source of truth

- **Spec:** [docs/V2_PROTOCOL.md](V2_PROTOCOL.md)
- **Previous notes:** [.4](RELEASE_NOTES_v2.0.0-testnet.4.md) · [.3](RELEASE_NOTES_v2.0.0-testnet.3.md) · [.2](RELEASE_NOTES_v2.0.0-testnet.2.md) · [.1](RELEASE_NOTES_v2.0.0-testnet.1.md)
- **Branch:** [`v2-testnet-release`](https://github.com/KantoshiMiyamura/axiom-network/tree/v2-testnet-release)
- **Tag (when published):** `v2.0.0-testnet.5`
- **Bug reports:** open an issue on GitHub.
- **Security:** see [docs/SECURITY.md](SECURITY.md) for the disclosure policy.
