# Axiom Network — Operator Runbook

Copyright (c) 2026 Kantoshi Miyamura

> **Scope**: Public testnet operations.
> This runbook covers day-to-day operation, troubleshooting, and incident
> response for Axiom Network testnet nodes.

---

## Contents

1. [Startup Procedures](#1-startup-procedures)
2. [Shutdown Procedures](#2-shutdown-procedures)
3. [Health Checks](#3-health-checks)
4. [Peer Troubleshooting](#4-peer-troubleshooting)
5. [Sync Troubleshooting](#5-sync-troubleshooting)
6. [RPC Troubleshooting](#6-rpc-troubleshooting)
7. [Mining Troubleshooting](#7-mining-troubleshooting)
8. [Chain Reorg Events](#8-chain-reorg-events)
9. [Disk / Storage Issues](#9-disk--storage-issues)
10. [Recovery Procedures](#10-recovery-procedures)
11. [Log Reference](#11-log-reference)

---

## 1. Startup Procedures

### Normal start

```bash
sudo systemctl start axiom-seed    # or axiom-relay / axiom-miner
sudo systemctl status axiom-seed
```

### Verify startup completed

```bash
# Should show best_height and a block hash (not null) within ~5 seconds
curl -s http://127.0.0.1:8332/status | jq .
```

Expected on a fresh chain:
```json
{"best_block_hash": "<genesis_hash>", "best_height": 0, "mempool_size": 0, "orphan_count": 0}
```

Expected on a synced node:
```json
{"best_block_hash": "...", "best_height": 2508, "mempool_size": 7, "orphan_count": 0}
```

### First-run (empty data directory)

On first start with an empty `--data-dir`, the node initialises the genesis
block automatically. You will see:

```
INFO  axiom_node::node  Initialized genesis block: <hash>
INFO  axiom_rpc::server RPC server listening on 127.0.0.1:8332
```

No manual genesis configuration is required.

---

## 2. Shutdown Procedures

### Graceful shutdown

```bash
sudo systemctl stop axiom-seed
```

The node handles `SIGTERM` and `SIGINT`. It flushes the sled database before
exiting. Allow up to 30 seconds for a clean shutdown.

### Verify stopped

```bash
sudo systemctl is-active axiom-seed   # should print "inactive"
```

### Emergency kill (if graceful shutdown hangs)

```bash
sudo systemctl kill -s SIGKILL axiom-seed
# Sled is crash-safe; data is not corrupted by a hard kill.
# The node will recover on next start.
```

---

## 3. Health Checks

Run these checks after any startup, upgrade, or incident.

### Check 1: Node is reachable

```bash
curl -s http://127.0.0.1:8332/status
# Expect: JSON with best_height field. Any non-JSON response = problem.
```

### Check 2: Block height is advancing

```bash
HEIGHT1=$(curl -s http://127.0.0.1:8332/best_height)
sleep 60
HEIGHT2=$(curl -s http://127.0.0.1:8332/best_height)
echo "Height before: $HEIGHT1  Height after: $HEIGHT2"
# Expect: HEIGHT2 > HEIGHT1 if there is a miner on the network.
# If HEIGHT2 == HEIGHT1 after 60s, the chain may be stalled (check mining).
```

### Check 3: Peer connectivity

```bash
curl -s http://127.0.0.1:8332/peer_count
# Current limitation: always returns 0.
# Use logs to verify peer connections instead (see §4).
```

### Check 4: Mempool accepting transactions

```bash
curl -s http://127.0.0.1:8332/status | jq .mempool_size
# Non-zero if there is activity. Zero is normal on an idle network.
```

### Check 5: No orphans accumulating

```bash
curl -s http://127.0.0.1:8332/status | jq .orphan_count
# Should be 0 or very low (1-2). Persistent high count = fork / sync issue.
```

---

## 4. Peer Troubleshooting

### Symptom: Node not connecting to any peers

**Diagnose:**
```bash
sudo journalctl -u axiom-seed --since "5 minutes ago" | grep -i "peer\|connect\|seed"
```

**Causes and fixes:**

| Cause | Fix |
|-------|-----|
| Seeds file missing or wrong path | Check `--seeds` flag; verify file exists and is valid JSON |
| Seeds are offline | Try alternative seed addresses; start at least one other node first |
| Port 9000 blocked by firewall | `sudo ufw allow 9000/tcp`; verify `telnet <seed_ip> 9000` |
| Wrong IP in seeds file | Verify seed IPs are correct and DNS resolves |
| Node bound to wrong P2P address | Ensure `--p2p-bind 0.0.0.0:9000` is set |

**Verify seed file:**
```bash
cat /etc/axiom/seeds.json
# Must be valid JSON: {"seeds": ["ip:port", ...]}
python3 -c "import json,sys; json.load(open(sys.argv[1]))" /etc/axiom/seeds.json
```

### Symptom: Peers connect then disconnect immediately

Look for handshake errors in logs:
```bash
sudo journalctl -u axiom-seed | grep -i "handshake\|version\|disconnect"
```

Possible causes:
- Peers are running a different protocol version (version mismatch).
- Network MTU issues causing truncated messages.

### Symptom: Only connecting to 1-2 peers

This is expected in a small testnet. The `GetPeers` exchange will discover more
peers over time as they join. A 3-node testnet will have at most 2 peers per node.

---

## 5. Sync Troubleshooting

### Symptom: Block height not advancing

**Step 1: Check if a miner exists on the network**
```bash
# On a second node, check if blocks are appearing
watch -n 5 'curl -s http://127.0.0.1:8332/best_height'
```

If the miner's node is running and height is still not advancing, check:
```bash
sudo journalctl -u axiom-miner | grep -i "mine\|block\|error"
```

**Step 2: Check block propagation**
```bash
# On the miner node:
sudo journalctl -u axiom-miner | grep "Applied block\|Mined block"
# On a relay:
sudo journalctl -u axiom-relay | grep "Applied block\|Received block"
```

If the miner is producing blocks but the relay is not receiving them, check P2P
connectivity between the two nodes.

### Symptom: Node falls behind and never catches up (IBD)

The node implements IBD (Initial Block Download): after handshake, it pushes
canonical blocks to peers that are behind. If a node starts from genesis and
connects to a node at height 2000, it should receive all 2000 blocks.

```bash
sudo journalctl -u axiom-seed | grep "Applied block" | tail -20
# Should show increasing height numbers
```

If IBD stalls:
1. Verify the peer's height (`curl http://<peer>:8332/best_height`).
2. Restart the lagging node — it will re-connect and restart IBD.
3. If still stuck, wipe the data directory and re-sync from scratch.

### Symptom: Height goes backward (unexpected reorg)

A reorg is normal when two miners find blocks simultaneously. Short reorgs (1-2
blocks) are expected. Long reorgs on a testnet usually mean:

- **Two miners with equal-work chains** — known issue when PoW is disabled.
  Solution: run only one miner, or activate PoW (Phase 13A-3).
- **Network partition** — two network segments both progressing, then merging.

Log evidence of a reorg:
```bash
sudo journalctl -u axiom-seed | grep -i "reorg\|reorgani"
```

---

## 6. RPC Troubleshooting

### Symptom: RPC returns 401 Unauthorized

The node was started with `--rpc-auth-token` but the request is missing the
header or has the wrong token.

```bash
# Test with correct token
TOKEN=$(cat /etc/axiom/rpc-token)
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8332/status

# Test without token (expect 401 if auth is configured)
curl http://127.0.0.1:8332/status
```

If you have lost the token:
1. Stop the node.
2. Generate a new token: `openssl rand -hex 32 > /etc/axiom/rpc-token`
3. Update the systemd environment file with the new token.
4. Restart the node.

### Symptom: RPC returns 429 Too Many Requests

The per-IP rate limiter has triggered. The built-in limit is 10 req/s.

If triggered by a legitimate client:
- Reduce client polling frequency.
- The ban lifts automatically after 1 hour.

If triggered by an attack or runaway client:
- The node bans the IP automatically.
- No manual intervention needed.

### Symptom: RPC returns connection refused

```bash
sudo systemctl is-active axiom-seed   # is the node running?
ss -tlnp | grep 8332                  # is the port listening?
```

If the port is not listening, the node failed to start. Check logs:
```bash
sudo journalctl -u axiom-seed -n 50
```

### Symptom: /tx/:txid returns "Transaction not found"

Two possible cases:

1. **Transaction is in the mempool** — search mempool first (the handler does
   this automatically). If the response says "not found", the txid is not in
   the mempool and not in any confirmed block.

2. **Transaction is confirmed but index is missing** — this can happen if the
   node was started from a pre-Phase-14B database (index was added in Phase 14B).
   Solution: wipe the data directory and re-sync to rebuild the index.

### Symptom: /address/:address/txs returns empty

- The address has no confirmed transactions (correct behavior).
- The address was used before Phase 14B (index not built for historical data).
  Solution: wipe data and re-sync.
- The address format is wrong. Axiom v2 addresses are 75 characters starting
  with `axm`. Run validation: `curl http://127.0.0.1:8332/balance/<address>`.

---

## 7. Mining Troubleshooting

### Symptom: Miner running but no blocks produced

**Step 1: Check that mining is enabled**
```bash
sudo journalctl -u axiom-miner | grep -i "mine\|mining"
# Should see "Mining: enabled"
```

**Step 2: Check miner address is set**
```bash
sudo journalctl -u axiom-miner | grep -i "miner_address\|coinbase"
# If missing, the miner uses a zero address (still mines, just sends rewards nowhere)
```

**Step 3: Understand PoW is disabled**

In the current codebase (`validate_pow: false`), blocks are accepted regardless
of the nonce/PoW. Mining still runs (iterates nonce) but the loop exits as soon
as it builds a valid block structure — it does not need to find a low-hash nonce.
Blocks should be produced quickly (seconds, not minutes).

If the miner is not producing blocks at all:
```bash
sudo journalctl -u axiom-miner | grep "error\|ERROR\|panic"
```

Common causes:
- `--miner-address` is set to an invalid address format.
- The node failed to connect to any peers (mining continues but blocks are not
  propagated).
- The mempool is at capacity (blocks are produced but contain no txs).

### Symptom: Mined blocks not appearing on other nodes

```bash
# On the miner
sudo journalctl -u axiom-miner | grep "Applied block" | tail -5

# On a relay (should receive the same blocks)
sudo journalctl -u axiom-relay | grep "Applied block" | tail -5
```

If the miner shows height N but the relay shows height M < N, P2P propagation
is broken. Check P2P connectivity (see §4).

---

## 8. Chain Reorg Events

Reorgs are normal on a multi-miner network. Typical reorg log:

```
WARN  axiom_node::node  Chain reorganization: old_tip=<hash1> new_tip=<hash2> depth=1
INFO  axiom_node::node  Rolled back 1 block(s)
INFO  axiom_node::node  Applied 2 block(s) on new chain
```

A depth-1 reorg is routine. A depth > 5 reorg warrants investigation.

**During a reorg:**
- UTXO set is rolled back and re-applied atomically.
- Transaction index (`TxIndex`) is updated: rolled-back block txs are unindexed,
  new chain block txs are indexed.
- Mempool transactions from the rolled-back block are restored to the mempool.

**After a deep reorg**, verify chain consistency:
```bash
curl -s http://127.0.0.1:8332/status | jq .orphan_count
# Should return to 0 shortly after the reorg completes
```

---

## 9. Disk / Storage Issues

### Check disk usage

```bash
du -sh /var/axiom/data
df -h /var/axiom
```

### Sled database corruption

Sled is crash-safe. On a hard kill or power failure, sled recovers via its
internal write-ahead log on next open. No manual repair is needed.

If you see sled errors in the logs that persist across restarts:
```
ERROR sled: ...
```

This indicates genuine corruption (rare; usually caused by hardware failure).
Recovery: wipe the data directory and re-sync.

### Storage growing too fast

Expected growth rate depends on block rate and transaction volume. At 16 TPS
(Phase 13C validation), 1 hour of operation produced ~100 MB of chain data.

If disk is filling up:
1. Add more disk space.
2. Prune old backups.
3. Consider pruned node mode (not yet implemented — Phase 14D scope).

---

## 10. Recovery Procedures

### Full re-sync (wipe and resync)

Use when: database is corrupt, index is missing (pre-14B data), or you want a
clean start.

```bash
sudo systemctl stop axiom-seed
sudo rm -rf /var/axiom/data
sudo mkdir -p /var/axiom/data
sudo chown axiom:axiom /var/axiom/data
sudo systemctl start axiom-seed
```

The node will re-initialize genesis and sync from peers. All chain data is
derived from peers — no manual intervention is needed.

### Restore from backup

```bash
sudo systemctl stop axiom-seed
sudo rm -rf /var/axiom/data
sudo tar -xzf /backups/axiom-20260313-020000.tar.gz -C /
sudo chown -R axiom:axiom /var/axiom/data
sudo systemctl start axiom-seed
```

### Roll back to previous binary

```bash
sudo systemctl stop axiom-seed
sudo cp /usr/local/bin/axiom-node.old /usr/local/bin/axiom-node
sudo systemctl start axiom-seed
```

---

## 11. Log Reference

Key log patterns and their meaning:

| Pattern | Level | Meaning |
|---------|-------|---------|
| `RPC server listening on ...` | INFO | Startup complete |
| `Initialized genesis block` | INFO | Fresh chain |
| `Applied block at height N` | INFO | Normal operation |
| `Reorganization: switching` | WARN | Chain reorg (investigate if depth > 5) |
| `Rolled back N block(s)` | WARN | Part of a reorg |
| `Rate limit exceeded` | WARN | Client hit rate limit |
| `Peer banned` | WARN | IP banned by rate limiter |
| `Handshake failed` | WARN | P2P handshake error |
| `Failed to connect to seed` | WARN | Seed unreachable at startup |
| `ERROR` | ERROR | Always investigate |
| `panic` | ERROR | Process will crash; check for updated binary |

### Increasing log verbosity

```bash
# Add --log-level debug to the ExecStart line, then:
sudo systemctl daemon-reload
sudo systemctl restart axiom-seed
sudo journalctl -u axiom-seed -f
```
