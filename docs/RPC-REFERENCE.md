# Axiom Network — RPC API Reference

> **Base URL:** `http://127.0.0.1:8332`
>
> All responses are JSON unless noted otherwise. All currency values are in **satoshis** (1 AXM = 100,000,000 sat).

---

## Authentication

By default the RPC server has **open access** (suitable for devnet and local testing only). When the node is started with `--rpc-auth-token <token>`, every request must carry a Bearer token:

```
Authorization: Bearer <token>
```

**Example:**

```bash
curl -H "Authorization: Bearer my-secret-token" http://127.0.0.1:8332/health
```

Requests without a valid token return `401 Unauthorized`.

> ⚠️ **WARNING:** Never expose port 8332 to the public internet without an auth token and a TLS-terminating reverse proxy. See `docs/DEPLOYMENT_GUIDE.md` for the recommended nginx/TLS setup.

---

## Rate Limiting

The server applies per-IP rate limiting to all endpoints. Exceeding the limit returns `429 Too Many Requests`. Persistent abusers are temporarily banned.

---

## Endpoints

### Chain Info

---

#### `GET /status`

Returns a summary of the current chain tip and mempool state.

**Query parameters:** none

**Example:**

```bash
curl http://127.0.0.1:8332/status
```

**Response:**

```json
{
  "best_block_hash": "a1b2c3d4e5f6...64 hex chars",
  "best_height": 14200,
  "mempool_size": 5,
  "orphan_count": 0
}
```

| Field | Type | Description |
|-------|------|-------------|
| `best_block_hash` | `string \| null` | Hex-encoded hash of the best block |
| `best_height` | `number \| null` | Block height of the best block |
| `mempool_size` | `number` | Number of transactions in the mempool |
| `orphan_count` | `number` | Number of orphaned blocks currently held |

---

#### `GET /best_height`

Returns the current best block height as a bare integer.

**Example:**

```bash
curl http://127.0.0.1:8332/best_height
```

**Response:**

```json
14200
```

---

#### `GET /best_block_hash`

Returns the current best block hash as a hex string.

**Example:**

```bash
curl http://127.0.0.1:8332/best_block_hash
```

**Response:**

```json
"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
```

---

#### `GET /tip`

Alias for `GET /status`. Returns the same `NodeStatus` object.

**Example:**

```bash
curl http://127.0.0.1:8332/tip
```

---

### Blocks

---

#### `GET /block/:hash`

Returns a summary of the block with the given hash.

**Path parameters:**

| Parameter | Description |
|-----------|-------------|
| `hash` | 64-character hex-encoded block hash |

**Example:**

```bash
curl http://127.0.0.1:8332/block/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
```

**Response:**

```json
{
  "hash": "a1b2c3d4e5f6...64 chars",
  "height": 42,
  "timestamp": 1743200000,
  "prev_block_hash": "0000000000...64 chars",
  "merkle_root": "feedbeef...64 chars",
  "nonce": 182736450,
  "difficulty": 486604799,
  "transaction_count": 3
}
```

| Field | Type | Description |
|-------|------|-------------|
| `hash` | `string` | Block hash (hex) |
| `height` | `number` | Block height |
| `timestamp` | `number` | Unix timestamp (seconds) |
| `prev_block_hash` | `string` | Previous block hash (hex) |
| `merkle_root` | `string` | Merkle root of transactions (hex) |
| `nonce` | `number` | PoW nonce |
| `difficulty` | `number` | Compact difficulty target |
| `transaction_count` | `number` | Number of transactions in the block |

Returns `404` if the block is not found.

---

#### `GET /block/height/:height`

Returns the block at the given height.

**Path parameters:**

| Parameter | Description |
|-----------|-------------|
| `height` | Block height (integer, max 1,000,000,000) |

**Example:**

```bash
curl http://127.0.0.1:8332/block/height/42
```

**Response:** Same `BlockSummary` object as `GET /block/:hash`.

Returns `400` if height exceeds the maximum. Returns `404` if no block at that height is found.

---

#### `GET /blocks/recent`

Returns a paginated list of recent blocks, newest first.

**Query parameters:**

| Parameter | Default | Max | Description |
|-----------|---------|-----|-------------|
| `limit` | `10` | `100` | Number of blocks to return |
| `offset` | `0` | — | Number of blocks to skip |

**Example:**

```bash
# Get the 5 most recent blocks
curl "http://127.0.0.1:8332/blocks/recent?limit=5&offset=0"

# Get the next page
curl "http://127.0.0.1:8332/blocks/recent?limit=5&offset=5"
```

**Response:**

```json
{
  "blocks": [
    {
      "hash": "...",
      "height": 14200,
      "timestamp": 1743200000,
      "prev_block_hash": "...",
      "merkle_root": "...",
      "nonce": 99887766,
      "difficulty": 486604799,
      "transaction_count": 1
    }
  ],
  "count": 5,
  "limit": 5,
  "offset": 0
}
```

---

#### `GET /block/:hash/txs`

Returns all transactions in the given block.

**Path parameters:**

| Parameter | Description |
|-----------|-------------|
| `hash` | 64-character hex-encoded block hash |

**Example:**

```bash
curl http://127.0.0.1:8332/block/a1b2c3d4.../txs
```

**Response:**

```json
{
  "transactions": [
    {
      "txid": "dead...beef",
      "version": 1,
      "tx_type": "coinbase",
      "inputs": [],
      "outputs": [
        {"value": 5000000000, "pubkey_hash": "aabb..."}
      ],
      "nonce": 0,
      "locktime": 0,
      "memo": null
    }
  ],
  "count": 1
}
```

See `GET /tx/:txid` for the full `TransactionDetail` field description.

---

### Transactions

---

#### `GET /tx/:txid`

Returns the full detail of a transaction. Searches the mempool first, then confirmed blocks.

**Path parameters:**

| Parameter | Description |
|-----------|-------------|
| `txid` | 64-character hex-encoded transaction ID |

**Example:**

```bash
curl http://127.0.0.1:8332/tx/deadbeef...64hexchars
```

**Response:**

```json
{
  "txid": "deadbeef...64 chars",
  "version": 1,
  "tx_type": "transfer",
  "inputs": [
    {
      "prev_tx_hash": "aabb...64 chars",
      "prev_output_index": 0,
      "signature": "<4627-byte ML-DSA-87 signature hex>",
      "pubkey": "<2592-byte ML-DSA-87 public key hex>"
    }
  ],
  "outputs": [
    {
      "value": 1000000,
      "pubkey_hash": "ccdd...64 chars"
    },
    {
      "value": 48990000,
      "pubkey_hash": "aabb...64 chars"
    }
  ],
  "nonce": 1,
  "locktime": 0,
  "memo": "payment for invoice #42"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `txid` | `string` | Transaction ID (hex) |
| `version` | `number` | Transaction version |
| `tx_type` | `string` | `"transfer"` or `"coinbase"` |
| `inputs` | `array` | List of inputs (empty for coinbase transactions) |
| `inputs[].prev_tx_hash` | `string` | Hash of the output being spent (hex) |
| `inputs[].prev_output_index` | `number` | Index of the output within that transaction |
| `inputs[].signature` | `string` | ML-DSA-87 signature (hex, 4627 bytes) |
| `inputs[].pubkey` | `string` | ML-DSA-87 public key (hex, 2592 bytes) |
| `outputs` | `array` | List of outputs |
| `outputs[].value` | `number` | Value in satoshis |
| `outputs[].pubkey_hash` | `string` | Recipient pubkey hash (hex, 32 bytes) |
| `nonce` | `number` | Anti-replay nonce |
| `locktime` | `number` | Locktime (block height `< 500,000,000` or Unix timestamp `≥ 500,000,000`) |
| `memo` | `string \| null` | Optional UTF-8 memo (max 80 bytes), `null` if not set |

Returns `404` if the transaction is not found.

---

#### `POST /submit_transaction`

Submits a signed, serialized transaction to the mempool. The node validates the transaction and, if accepted, broadcasts it to connected peers.

**Request body:**

```json
{
  "transaction_hex": "<hex-encoded bincode-serialized transaction>"
}
```

**Example:**

```bash
curl -X POST http://127.0.0.1:8332/submit_transaction \
  -H "Content-Type: application/json" \
  -d '{"transaction_hex": "0100000001..."}'
```

**Response (success):**

```json
{
  "txid": "deadbeef...64 chars"
}
```

**Error responses:**

| HTTP status | Meaning |
|-------------|---------|
| `400` | Invalid hex encoding or malformed transaction bytes |
| `422` | Transaction rejected by the node (invalid signature, insufficient fee, double-spend, etc.) |

The `422` response body contains a human-readable error message:

```json
{"error": "transaction rejected: fee rate 0 sat/byte is below minimum 1 sat/byte"}
```

---

### Address / Wallet

---

#### `GET /balance/:address`

Returns the confirmed balance for an address in satoshis.

**Path parameters:**

| Parameter | Description |
|-----------|-------------|
| `address` | Axiom address (75-char `axm...` format or 64-char pubkey hash hex) |

**Example:**

```bash
curl http://127.0.0.1:8332/balance/axm<address>
```

**Response:**

```json
{"balance": 500000000}
```

The balance is computed from the confirmed UTXO set. Unconfirmed (mempool) outputs are not included.

---

#### `GET /address/:address/txs`

Returns paginated transaction history for an address. Includes both confirmed transactions (with `block_height`) and pending mempool transactions (`block_height: null`).

**Path parameters:**

| Parameter | Description |
|-----------|-------------|
| `address` | Axiom address |

**Query parameters:**

| Parameter | Default | Max | Description |
|-----------|---------|-----|-------------|
| `limit` | `50` | `1000` | Number of transactions to return |
| `offset` | `0` | — | Number of transactions to skip |

**Example:**

```bash
curl "http://127.0.0.1:8332/address/axm<address>/txs?limit=20&offset=0"
```

**Response:**

```json
{
  "transactions": [
    {
      "txid": "deadbeef...64 chars",
      "block_height": 14190,
      "timestamp": null,
      "value_change": 1000000
    },
    {
      "txid": "cafebabe...64 chars",
      "block_height": null,
      "timestamp": null,
      "value_change": -500000
    }
  ],
  "count": 2,
  "total": 2,
  "limit": 20,
  "offset": 0
}
```

| Field | Type | Description |
|-------|------|-------------|
| `txid` | `string` | Transaction ID (hex) |
| `block_height` | `number \| null` | Block height where confirmed, or `null` if pending |
| `timestamp` | `number \| null` | Block timestamp (currently always `null`) |
| `value_change` | `number` | Net satoshi change for this address (positive = received, negative = sent) |
| `total` | `number` | Total number of transactions for this address (before pagination) |

---

#### `GET /nonce/:address`

Returns the current nonce for an address. The nonce must be included in every outgoing transaction to prevent replay attacks.

**Example:**

```bash
curl http://127.0.0.1:8332/nonce/axm<address>
```

**Response:**

```json
{"nonce": 3}
```

A nonce of `3` means this address has sent 3 confirmed transactions; the next transaction must use nonce `3` (or higher).

---

#### `GET /utxos/:address`

Returns all unspent transaction outputs (UTXOs) for an address. Use this when constructing transactions manually via `POST /submit_transaction`.

**Path parameters:**

| Parameter | Description |
|-----------|-------------|
| `address` | Axiom address |

**Example:**

```bash
curl http://127.0.0.1:8332/utxos/axm<address>
```

**Response:**

```json
{
  "utxos": [
    {
      "txid": "aabb...64 chars",
      "output_index": 0,
      "value": 500000000,
      "block_height": 14100
    },
    {
      "txid": "ccdd...64 chars",
      "output_index": 1,
      "value": 50000000,
      "block_height": 14150
    }
  ],
  "total_value": 550000000,
  "count": 2
}
```

| Field | Type | Description |
|-------|------|-------------|
| `txid` | `string` | Transaction that created this UTXO (hex) |
| `output_index` | `number` | Output index within that transaction |
| `value` | `number` | Value in satoshis |
| `block_height` | `number` | Block height at which this UTXO was created |
| `total_value` | `number` | Sum of all UTXO values in satoshis |
| `count` | `number` | Number of UTXOs returned |

---

### Local Wallet Helpers

> ⚠️ **These endpoints accept raw private keys over HTTP. They are restricted to localhost connections only.** Requests from non-loopback addresses receive `403 Forbidden`. Never expose port 8332 publicly when using these endpoints.

---

#### `POST /wallet/address`

Derives the Axiom address from a private key hex string.

**Request body:**

```json
{
  "private_key_hex": "<hex string>"
}
```

**Example:**

```bash
curl -X POST http://127.0.0.1:8332/wallet/address \
  -H "Content-Type: application/json" \
  -d '{"private_key_hex": "<your private_key_hex>"}'
```

**Response:**

```json
{"address": "axm<64 hex chars><8 hex checksum>"}
```

---

#### `POST /wallet/send`

Builds, signs, and submits a transfer transaction in one call. Handles UTXO selection and fee calculation automatically.

**Request body:**

```json
{
  "private_key_hex": "<hex string>",
  "to_address": "axm<recipient address>",
  "amount_sat": 1000000,
  "memo": "optional UTF-8 memo, max 80 bytes"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `private_key_hex` | yes | Sender's private key |
| `to_address` | yes | Recipient's Axiom address |
| `amount_sat` | yes | Amount to send in satoshis |
| `memo` | no | Optional UTF-8 memo (max 80 bytes) |

**Example:**

```bash
curl -X POST http://127.0.0.1:8332/wallet/send \
  -H "Content-Type: application/json" \
  -d '{
    "private_key_hex": "<your private_key_hex>",
    "to_address": "axm<recipient>",
    "amount_sat": 1000000
  }'
```

**Response:**

```json
{
  "txid": "deadbeef...64 chars",
  "amount_sat": 1000000,
  "to_address": "axm<recipient>",
  "change_sat": 48990000,
  "fee_sat": 10000
}
```

| Field | Type | Description |
|-------|------|-------------|
| `txid` | `string` | Transaction ID of the submitted transaction |
| `amount_sat` | `number` | Amount sent (as requested) |
| `to_address` | `string` | Recipient address (as provided) |
| `change_sat` | `number` | Change returned to sender (0 if no change output) |
| `fee_sat` | `number` | Actual fee paid in satoshis |

**Error responses:**

| HTTP status | Meaning |
|-------------|---------|
| `400` | Invalid private key, invalid address, or invalid amount |
| `403` | Request came from a non-localhost IP |
| `422` | Transaction rejected (e.g. insufficient balance) |

---

### Mempool

---

#### `GET /mempool`

Returns transactions currently waiting in the mempool.

**Query parameters:**

| Parameter | Default | Max | Description |
|-----------|---------|-----|-------------|
| `limit` | `50` | `500` | Number of transactions to return |
| `offset` | `0` | — | Number of transactions to skip |

**Example:**

```bash
# First 10 mempool transactions
curl "http://127.0.0.1:8332/mempool?limit=10&offset=0"
```

**Response:**

```json
{
  "transactions": [
    {
      "txid": "aabbcc...64 chars",
      "size": 7369,
      "fee_sat": 0,
      "nonce": 5,
      "input_count": 1,
      "output_count": 2
    }
  ],
  "count": 1,
  "total": 1,
  "total_size": 7369,
  "limit": 10,
  "offset": 0
}
```

| Field | Type | Description |
|-------|------|-------------|
| `txid` | `string` | Transaction ID (hex) |
| `size` | `number` | Transaction size in bytes |
| `fee_sat` | `number` | Fee in satoshis (`0` when input UTXO values cannot be resolved) |
| `nonce` | `number` | Transaction nonce |
| `input_count` | `number` | Number of inputs |
| `output_count` | `number` | Number of outputs |
| `total` | `number` | Total number of transactions in the mempool (before pagination) |
| `total_size` | `number` | Total byte size of all mempool transactions |

---

### Fee Estimation

---

#### `GET /fee/estimate`

Returns recommended fee rates based on current mempool conditions. Uses percentile-based estimation (Phase 33A).

**Example:**

```bash
curl http://127.0.0.1:8332/fee/estimate
```

**Response:**

```json
{
  "slow_sat_per_byte": 1,
  "medium_sat_per_byte": 2,
  "fast_sat_per_byte": 5,
  "next_block_sat_per_byte": 8,
  "min_relay_sat_per_byte": 1,
  "low": 1,
  "medium": 2,
  "high": 5,
  "typical_fee_sat": 7764,
  "typical_tx_size": 7369,
  "min_fee_rate": 1,
  "mempool_tx_count": 42,
  "note": "Based on 42 transactions in mempool"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `slow_sat_per_byte` | `number` | p25 fee rate — likely confirmation in several blocks |
| `medium_sat_per_byte` | `number` | p50 fee rate — typical confirmation time |
| `fast_sat_per_byte` | `number` | p75 fee rate — faster confirmation |
| `next_block_sat_per_byte` | `number` | p90 fee rate — likely confirmed in the next block |
| `min_relay_sat_per_byte` | `number` | Minimum rate this node will relay |
| `low` | `number` | Congestion-adjusted low rate |
| `medium` | `number` | Congestion-adjusted medium rate |
| `high` | `number` | Congestion-adjusted high rate |
| `typical_fee_sat` | `number` | Estimated fee for a typical 1-input 2-output transaction at medium rate |
| `typical_tx_size` | `number` | Size of a typical ML-DSA-87 transaction in bytes (7,369) |
| `min_fee_rate` | `number` | Minimum fee rate enforced by this node |
| `mempool_tx_count` | `number` | Number of transactions currently in the mempool |
| `note` | `string` | Human-readable description of the estimation basis |

**How to use these values:**

- For non-urgent transfers: use `slow_sat_per_byte`
- For normal transfers: use `medium_sat_per_byte`
- When you need the next confirmation: use `next_block_sat_per_byte`
- The minimum accepted rate is `min_relay_sat_per_byte`

Note that because Axiom uses ML-DSA-87 post-quantum signatures, transactions are significantly larger than Bitcoin transactions (~7,369 bytes for a 1-in 2-out transaction vs. ~226 bytes for Bitcoin). The `typical_fee_sat` field already accounts for this size.

---

### Network

---

#### `GET /peers`

Returns a list of currently connected peers.

**Example:**

```bash
curl http://127.0.0.1:8332/peers
```

**Response:**

```json
{
  "peers": [
    {"address": "1.2.3.4:9000", "connected": true},
    {"address": "5.6.7.8:9000", "connected": true}
  ],
  "count": 2
}
```

---

#### `GET /peer_count`

Returns the number of fully-handshaked (ready) peers as a bare integer.

**Example:**

```bash
curl http://127.0.0.1:8332/peer_count
```

**Response:**

```json
8
```

---

### Monitoring

---

#### `GET /health`

Liveness and readiness probe. Returns `200 OK` when the node is operational. Suitable for load balancers, uptime monitors, and deployment health checks.

**Example:**

```bash
curl http://127.0.0.1:8332/health
```

**Response:**

```json
{
  "status": "ok",
  "height": 14200,
  "peers": 8,
  "mempool": 5
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status` | `string` | Always `"ok"` when the node is running |
| `height` | `number \| null` | Current best block height |
| `peers` | `number` | Number of connected peers |
| `mempool` | `number` | Number of transactions in the mempool |

---

#### `GET /metrics`

Returns detailed node metrics as JSON.

**Example:**

```bash
curl http://127.0.0.1:8332/metrics
```

**Response:**

```json
{
  "block_height": 14200,
  "best_block_hash": "a1b2c3...64 chars",
  "mempool_size": 5,
  "peer_count": 8,
  "orphan_block_count": 0,
  "chain_work": "0000000000000000000000000000000000000000000000000000000100000000",
  "uptime_seconds": 86400,
  "tx_rate": 0.035,
  "reorg_count": 0
}
```

| Field | Type | Description |
|-------|------|-------------|
| `block_height` | `number \| null` | Best block height |
| `best_block_hash` | `string \| null` | Best block hash (hex) |
| `mempool_size` | `number` | Mempool transaction count |
| `peer_count` | `number` | Connected peer count |
| `orphan_block_count` | `number` | Orphan blocks currently held |
| `chain_work` | `string \| null` | Total chain work (32-char hex) |
| `uptime_seconds` | `number` | Seconds since the node started |
| `tx_rate` | `number` | Approximate confirmed transactions per second (recent 10-block window) |
| `reorg_count` | `number` | Number of chain reorganizations since node start |

---

#### `GET /metrics/prometheus`

Returns the same metrics as `GET /metrics` but formatted as Prometheus text exposition format (`text/plain; version=0.0.4`). Suitable for Prometheus, Grafana Agent, or any OpenMetrics-compatible scraper.

**Example:**

```bash
curl http://127.0.0.1:8332/metrics/prometheus
```

**Response (text/plain):**

```
# HELP axiom_block_height Current best block height
# TYPE axiom_block_height gauge
axiom_block_height 14200

# HELP axiom_mempool_size Number of transactions in the mempool
# TYPE axiom_mempool_size gauge
axiom_mempool_size 5

# HELP axiom_peer_count Number of connected peers
# TYPE axiom_peer_count gauge
axiom_peer_count 8

# HELP axiom_uptime_seconds Node uptime in seconds
# TYPE axiom_uptime_seconds counter
axiom_uptime_seconds 86400

# HELP axiom_tx_rate Transactions confirmed per second
# TYPE axiom_tx_rate gauge
axiom_tx_rate 0.035

# HELP axiom_reorg_count Total chain reorganizations since start
# TYPE axiom_reorg_count counter
axiom_reorg_count 0
```

---

### WebSocket Subscriptions

---

#### `GET /ws` (WebSocket upgrade)

Subscribe to real-time block and transaction events. Connect using any WebSocket client.

**Example (wscat):**

```bash
npm install -g wscat
wscat -c ws://127.0.0.1:8332/ws
```

**Example (Python):**

```python
import asyncio, websockets, json

async def listen():
    async with websockets.connect("ws://127.0.0.1:8332/ws") as ws:
        async for msg in ws:
            event = json.loads(msg)
            print(event)

asyncio.run(listen())
```

**Event: new block confirmed**

```json
{
  "type": "NewBlock",
  "data": {
    "hash": "a1b2c3...64 chars",
    "height": 14201,
    "timestamp": 1743200300,
    "prev_block_hash": "0011...64 chars",
    "merkle_root": "aabb...64 chars",
    "nonce": 99887766,
    "difficulty": 486604799,
    "transaction_count": 3
  }
}
```

**Event: new transaction in mempool**

```json
{
  "type": "NewTx",
  "data": {
    "txid": "deadbeef...64 chars"
  }
}
```

The WebSocket connection respects the same auth and rate-limit middleware as HTTP endpoints. If `--rpc-auth-token` is set, send the token as a query parameter or via the `Authorization` header during the WebSocket handshake.

---

### AI Endpoints

The following AI-related endpoints are available when the node's AI registries are initialized (data directory contains valid model/inference/reputation data). If a registry is unavailable, the corresponding endpoints return `503 Service Unavailable`.

---

#### `GET /ai/analysis`

Returns the latest anomaly detection report from the node's built-in AI engine. Includes recent alerts and aggregate statistics. No external API calls are made.

**Example:**

```bash
curl http://127.0.0.1:8332/ai/analysis
```

---

#### `POST /ai/model/register`

Register an AI model on-chain.

---

#### `GET /ai/model/:hash`

Retrieve a registered model by its hash.

---

#### `GET /ai/models/recent`

List recently registered models.

---

#### `GET /ai/models/ranked`

List models ranked by reputation score.

---

#### `POST /ai/inference/request`

Request inference from a registered model.

---

#### `POST /ai/inference/complete`

Mark an inference job as complete and release payment.

---

#### `POST /ai/inference/cancel`

Cancel a pending inference job.

---

#### `GET /ai/inference/:job_id`

Get the status and details of an inference job.

---

#### `GET /ai/inference/jobs/:address`

List inference jobs for an address.

---

#### `POST /ai/reputation/:model_hash/rate`

Submit a rating for a model.

---

#### `GET /ai/reputation/:model_hash`

Get the reputation score for a model.

---

#### `POST /ai/stake`

Add stake to back an AI model.

---

#### `GET /ai/stake/:address`

Get the stake details for an address.

---

## Error Response Format

All error responses follow a consistent JSON format:

```json
{"error": "human-readable error message"}
```

| HTTP status | When returned |
|-------------|---------------|
| `400 Bad Request` | Invalid input (bad hex, malformed address, out-of-range parameter) |
| `401 Unauthorized` | Missing or invalid `Authorization: Bearer` token |
| `403 Forbidden` | Localhost-only endpoint accessed from a remote IP |
| `404 Not Found` | Block, transaction, or address not found |
| `422 Unprocessable Entity` | Transaction rejected by the node (validation failure) |
| `429 Too Many Requests` | Rate limit exceeded |
| `500 Internal Server Error` | Unexpected node error |
| `503 Service Unavailable` | Requested subsystem (e.g. AI registry) not available |

---

## Quick Reference Table

| Method | Path | Auth required | Description |
|--------|------|---------------|-------------|
| GET | `/status` | Token (if set) | Node status |
| GET | `/best_height` | Token (if set) | Current block height |
| GET | `/best_block_hash` | Token (if set) | Current best block hash |
| GET | `/tip` | Token (if set) | Alias for `/status` |
| GET | `/block/:hash` | Token (if set) | Block by hash |
| GET | `/block/height/:height` | Token (if set) | Block by height |
| GET | `/blocks/recent` | Token (if set) | Recent blocks (paginated) |
| GET | `/block/:hash/txs` | Token (if set) | Transactions in a block |
| GET | `/tx/:txid` | Token (if set) | Transaction by ID |
| POST | `/submit_transaction` | Token (if set) | Submit signed transaction |
| GET | `/balance/:address` | Token (if set) | Address balance |
| GET | `/address/:address/txs` | Token (if set) | Address tx history (paginated) |
| GET | `/nonce/:address` | Token (if set) | Address nonce |
| GET | `/utxos/:address` | Token (if set) | Unspent outputs for address |
| POST | `/wallet/address` | Localhost only | Derive address from private key |
| POST | `/wallet/send` | Localhost only | Build, sign, and submit transaction |
| GET | `/mempool` | Token (if set) | Mempool contents (paginated) |
| GET | `/fee/estimate` | Token (if set) | Fee rate estimates |
| GET | `/peers` | Token (if set) | Connected peers |
| GET | `/peer_count` | Token (if set) | Number of connected peers |
| GET | `/health` | Token (if set) | Liveness/readiness probe |
| GET | `/metrics` | Token (if set) | Node metrics (JSON) |
| GET | `/metrics/prometheus` | Token (if set) | Node metrics (Prometheus format) |
| GET | `/ai/analysis` | Token (if set) | AI anomaly detection report |
| GET | `/ws` | Token (if set) | WebSocket event stream |
