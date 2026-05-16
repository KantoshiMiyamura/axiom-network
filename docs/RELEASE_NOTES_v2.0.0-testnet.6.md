# Axiom Network v2.0.0-testnet.6 — Release Notes

> ⚠️ **TESTNET — NOT FOR REAL FUNDS.** Tokens on `axiom-test-v2` have no
> monetary value. Mainnet has not launched. Wait for an explicit mainnet
> announcement before moving real money.

This is a **fifth release** on top of `v2.0.0-testnet.1` / `.2` / `.3` /
`.4` / `.5`. It adds wire-level visibility to the IBD sync path so the
v2.0.0-testnet.5 field report ("SYNC_NEEDED fires but HEADERS_RECEIVED
never follows") becomes diagnosable, and ships two real-TCP integration
tests that exercise the full GetTip → Tip → GetHeaders → Headers →
GetData → Block round-trip — including under concurrent mining
broadcasts from the peer.

Protocol, wire format, consensus rules, signing tag, on-chain state
machine, and the IBD state machine from testnet.5 are all **unchanged**.

---

## Why no code-path fix this release

The v2.0.0-testnet.5 field report described a sync that stalled after
`SYNC_NEEDED` — no subsequent `HEADERS_RECEIVED`, no
`HEADERS_REQUEST_BLOCKS`, no `BLOCK_APPLIED`. Two new integration tests
in this release stand up the full IBD wire dance over real loopback TCP
sockets:

| Test | What it does |
|---|---|
| `ibd_full_roundtrip_via_real_tcp_loopback` | A mines 20 blocks, B connects fresh, the GetTip → Tip → GetHeaders → Headers → GetData → Block round-trip drives B to height 20 in <1 s. Passes. |
| `ibd_completes_while_peer_concurrently_mines_and_broadcasts` | Same setup plus A keeps mining and broadcasting `Message::Block(...)` to B every 200 ms throughout B's catch-up — the exact stressor in the field report. The IBD gate from testnet.5 drops the live broadcasts; the header walk reaches the moving target; B catches up with `orphan_count ≤ 3`. Passes. |

Both tests use the public `Transport`, `NetworkService`, and
`PeerManager` APIs over real `tokio::net::TcpStream`s on `127.0.0.1`,
mirroring `axiom-cli/src/p2p.rs::handle_connection` in a stripped-down
loop. If the protocol path were structurally broken, these tests would
reproduce it. They do not.

This means the reported live-test stall is **not** a wire-protocol or
NetworkService logic bug. It's something specific to the running
binary's environment that the existing log output does not surface —
the most likely candidates are slow disk-backed `db_get_hash_by_height`
walks on a chain of ~1400 blocks (header lookup for the locator), TCP
buffering on a slow link, or simply not waiting long enough for the
first Headers batch to land. **Without wire-level logs there is no way
to tell which.**

So this release does not change the IBD code path. It adds the logs
needed to localize the stall in production, and ships the tests as a
regression baseline.

---

## What changed

### Wire-level logs in the peer loop

[crates/axiom-cli/src/p2p.rs](../crates/axiom-cli/src/p2p.rs) now logs
every IBD-relevant message at INFO on both the inbound and outbound
edge of each connection:

| Direction | Log | Source |
|---|---|---|
| Outbound (via mpsc → outbound_handle) | `OUTBOUND_GETTIP`, `OUTBOUND_GETHEADERS`, `OUTBOUND_GETDATA`, `OUTBOUND_TIP`, `OUTBOUND_HEADERS`, `OUTBOUND_BLOCK` | the per-peer outbound forwarder task |
| Outbound (inline reply) | `OUTBOUND_TIP`, `OUTBOUND_HEADERS`, `OUTBOUND_BLOCK` | the receive-loop inline handler when `handle_message` returns `Some(resp)` |
| Inbound | `INBOUND_GETTIP`, `INBOUND_TIP`, `INBOUND_GETHEADERS`, `INBOUND_HEADERS`, `INBOUND_GETDATA`, `INBOUND_BLOCK` | the receive-loop, before dispatch |

With these in place, the v2.0.0-testnet.5 symptom set becomes
unambiguous. After `SYNC_NEEDED` on Node B, expect to see:

```
OUTBOUND_GETHEADERS: peer=A:9000, from=<B's genesis>, max=2000   ← B sent
INBOUND_GETHEADERS:  peer=B:9000, from=<...>, max=2000           ← A received
OUTBOUND_HEADERS:    peer=B:9000, count=1428                     ← A replied
INBOUND_HEADERS:     peer=A:9000, count=1428                     ← B received
HEADERS_RECEIVED                                                  ← handle_headers runs
HEADERS_REQUEST_BLOCKS: count=16                                  ← B asked for blocks
... INBOUND_BLOCK ... BLOCK_APPLIED ...                          ← chain advances
```

The point at which the chain of log lines stops identifies the layer
that's broken:

| Missing log | Likely cause |
|---|---|
| `OUTBOUND_GETHEADERS` | `send_to_peer` failed silently or the outbound mpsc receiver was dropped — investigate `OUTBOUND_SEND_ERROR` lines |
| `INBOUND_GETHEADERS` on A | TCP delivery problem between the two nodes |
| `OUTBOUND_HEADERS` on A | `handle_get_headers` is slow (1400-height genesis walk on cold disk) or errored — turn on debug logging for `axiom_node::network::service` |
| `INBOUND_HEADERS` on B | network back-pressure during a large Headers payload (1400 headers × ~80 B ≈ 115 KB); fits well inside MAX_MESSAGE_SIZE (2 MB) so deserialization is unlikely to fail |

### Regression tests

[crates/axiom-node/tests/ibd_real_socket_roundtrip.rs](../crates/axiom-node/tests/ibd_real_socket_roundtrip.rs)
exercises the IBD path over real loopback TCP rather than the in-process
`handle_message` direct-dispatch used by earlier tests. Both tests
construct their own short version of the p2p peer loop using only the
public Transport API.

---

## Migration

### If you saw the v2.0.0-testnet.5 stall

Install `v2.0.0-testnet.6`, restart, re-run your two-node test. The
expected log sequence above should appear within a few seconds of
`SYNC_NEEDED`. If the chain of log lines stops at a specific step,
file an issue including the surrounding 20 lines of log — that
pinpoints the layer needing further investigation.

If you ran v2.0.0-testnet.5 solo (no peers), no observable change.

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
curl -fsSLO https://github.com/KantoshiMiyamura/axiom-network/releases/download/v2.0.0-testnet.6/SHA256SUMS
curl -fsSLO https://github.com/KantoshiMiyamura/axiom-network/releases/download/v2.0.0-testnet.6/SHA256SUMS.minisig
curl -fsSLO https://raw.githubusercontent.com/KantoshiMiyamura/axiom-network/v2.0.0-testnet.6/docs/minisign.pub
minisign -Vm SHA256SUMS -p minisign.pub
sha256sum -c SHA256SUMS
```

See [`docs/VERIFYING_RELEASES.md`](VERIFYING_RELEASES.md) for upstream
`minisign` install instructions.

---

## Artifacts

| Platform | Filename |
|---|---|
| Windows x86_64 | `axiom-v2.0.0-testnet.6-x86_64-pc-windows-msvc.zip` |
| Linux x86_64, glibc 2.31+ | `axiom-v2.0.0-testnet.6-x86_64-unknown-linux-gnu.tar.gz` |
| macOS | not produced for this release; build from source: `cargo build --release -p axiom-cli` |

---

## Source of truth

- **Spec:** [docs/V2_PROTOCOL.md](V2_PROTOCOL.md)
- **Previous notes:** [.5](RELEASE_NOTES_v2.0.0-testnet.5.md) · [.4](RELEASE_NOTES_v2.0.0-testnet.4.md) · [.3](RELEASE_NOTES_v2.0.0-testnet.3.md) · [.2](RELEASE_NOTES_v2.0.0-testnet.2.md) · [.1](RELEASE_NOTES_v2.0.0-testnet.1.md)
- **Branch:** [`v2-testnet-release`](https://github.com/KantoshiMiyamura/axiom-network/tree/v2-testnet-release)
- **Tag (when published):** `v2.0.0-testnet.6`
- **Bug reports:** open an issue on GitHub.
- **Security:** see [docs/SECURITY.md](SECURITY.md) for the disclosure policy.
