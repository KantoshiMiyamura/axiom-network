# Axiom Network v2.0.0-testnet.4 — Release Notes

> ⚠️ **TESTNET — NOT FOR REAL FUNDS.** Tokens on `axiom-test-v2` have no
> monetary value. Mainnet has not launched. Wait for an explicit mainnet
> announcement before moving real money.

This is a **third hotfix** on top of `v2.0.0-testnet.1` / `.2` / `.3`.
It fixes a peer-manager-ownership bug that prevented every
`NetworkService` back-channel send from reaching its peer — including the
`GetHeaders` that `v2.0.0-testnet.3` used to drive its new pull-based IBD.

Protocol, wire format, consensus rules, signing tag, and on-chain state
machine are **unchanged**. The fix is entirely in the binary's wiring of
the shared peer registry.

---

## The bug in `v2.0.0-testnet.3`

Two-node test:

- Node B (fresh, height 0) dials Node A (height ~1410).
- `PEER_SEED_CONNECTED` ✓
- `HANDSHAKE_COMPLETE` ✓
- `SYNC_CHECK` ✓ — B's `sync_with_peer` decides to pull.
- `SYNC_NEEDED` ✓ — B tries to send `GetHeaders` to A.
- `MESSAGE_HANDLER_ERROR: peer not found: PeerId(...)` ✗
- `PEER_DISCONNECTED` → `PEER_SEED_RECONNECT` → loop forever.

Node B never advanced past height 0. The new pull-based IBD flow looked
correct in isolation but never reached the wire.

### Root cause

`axiom-cli` constructed **two** `PeerManager` instances at startup:

```rust
// crates/axiom-cli/src/main.rs (v2.0.0-testnet.3)
let peer_manager = Arc::new(PeerManager::with_identity(...));      // ← (1)
let network_service = {
    let mut svc = NetworkService::with_shared_node(
        node_state.clone(),
        PeerManager::with_identity(...),                            // ← (2)
    );
    ...
};
```

- Instance (1) was handed to `P2PNetwork`. Every connection registered
  its peer here via `add_peer` and set its outbound mpsc sender here via
  `set_peer_sender`.
- Instance (2) was handed by value to `NetworkService::with_shared_node`,
  which wrapped it in its own private `Arc` and stored it as authoritative.

`NetworkService::sync_with_peer` (and `handle_inv`, `handle_headers`,
`handle_received_block`'s relay, `handle_get_data`, `dispatch_pending_blocks`)
all reach for `self.peer_manager.send_to_peer(peer_id, ...)`. That call
looked the peer up in instance (2) — which was empty. Result:
`PeerNotFound`, propagated up as `MESSAGE_HANDLER_ERROR`, the receive loop
treated the error as fatal-ish and the connection dropped.

`v2.0.0-testnet.2` and earlier didn't trip this bug because the old IBD
path was a push: the taller side called `peer_manager.send_to_peer(...)`
directly inside `p2p.rs` using instance (1). The pull-based IBD added in
`v2.0.0-testnet.3` was the first feature to depend on `NetworkService`'s
back-channel send working — and it didn't.

This is a **sync-availability** bug, not consensus or security. No fork
risk, no replay risk, no key exposure. The two-node test never
exchanged a single block.

---

## The fix

`NetworkService::with_shared_node` now takes `Arc<PeerManager>` and
stores it directly. `axiom-cli/src/main.rs` threads the existing
`peer_manager.clone()` through both layers, so `P2PNetwork` and
`NetworkService` share one peer map:

```rust
let peer_manager = Arc::new(PeerManager::with_identity(...));
let svc = NetworkService::with_shared_node(
    node_state.clone(),
    peer_manager.clone(),     // ← same Arc as P2PNetwork
);
```

This was a one-character bug in spirit (a missing `.clone()`) and a
nine-character bug in syntax (`Arc<` and `>`). The fallout was total.

### Regression tests

[crates/axiom-node/tests/peer_manager_shared_backchannel.rs](../crates/axiom-node/tests/peer_manager_shared_backchannel.rs)
adds four tests that pin each previously-broken back-channel path. Each
test registers a peer in an `Arc<PeerManager>`, builds a `NetworkService`
that shares that same Arc, drives an inbound message through
`handle_message`, and asserts the expected outbound message arrives on
the peer's mpsc receiver:

| Test | Path |
|---|---|
| `sync_get_headers_reaches_peer_via_shared_peer_manager` | The exact failing path from the field report: receiving Tip from a taller peer must send GetHeaders to that peer. |
| `inv_triggers_get_data_via_shared_peer_manager` | Receiving Inv for an unknown block must send GetData back. |
| `accepted_block_relays_inv_to_other_peers_via_shared_peer_manager` | Accepting a block from peer A must Inv-announce it to all other registered peers. |
| `get_data_block_reply_reaches_peer_via_shared_peer_manager` | Receiving GetData for a known block must send Block back. |

Under the broken wiring, every one of these would have returned
`PeerNotFound`. Under the fix, every one delivers its message to the
peer's channel.

---

## Migration

### If you ran `v2.0.0-testnet.3`

If you saw the `MESSAGE_HANDLER_ERROR: peer not found` log and an
infinite reconnect loop — that's this bug. Install `v2.0.0-testnet.4`
and restart. Your data directory is fine to keep; nothing was applied to
the chain to begin with.

If your node was solo (no peers), no observable effect — no migration
needed.

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
curl -fsSLO https://github.com/KantoshiMiyamura/axiom-network/releases/download/v2.0.0-testnet.4/SHA256SUMS
curl -fsSLO https://github.com/KantoshiMiyamura/axiom-network/releases/download/v2.0.0-testnet.4/SHA256SUMS.minisig
curl -fsSLO https://raw.githubusercontent.com/KantoshiMiyamura/axiom-network/v2.0.0-testnet.4/docs/minisign.pub
minisign -Vm SHA256SUMS -p minisign.pub
sha256sum -c SHA256SUMS
```

See [`docs/VERIFYING_RELEASES.md`](VERIFYING_RELEASES.md) for the upstream
`minisign` install instructions.

---

## Artifacts

| Platform | Filename |
|---|---|
| Windows x86_64 | `axiom-v2.0.0-testnet.4-x86_64-pc-windows-msvc.zip` |
| Linux x86_64, glibc 2.31+ | `axiom-v2.0.0-testnet.4-x86_64-unknown-linux-gnu.tar.gz` |
| macOS | not produced for this release; build from source: `cargo build --release -p axiom-cli` |

---

## Source of truth

- **Spec:** [docs/V2_PROTOCOL.md](V2_PROTOCOL.md)
- **Previous notes:** [.3](RELEASE_NOTES_v2.0.0-testnet.3.md) · [.2](RELEASE_NOTES_v2.0.0-testnet.2.md) · [.1](RELEASE_NOTES_v2.0.0-testnet.1.md)
- **Branch:** [`v2-testnet-release`](https://github.com/KantoshiMiyamura/axiom-network/tree/v2-testnet-release)
- **Tag (when published):** `v2.0.0-testnet.4`
- **Bug reports:** open an issue on GitHub.
- **Security:** see [docs/SECURITY.md](SECURITY.md) for the disclosure policy.
