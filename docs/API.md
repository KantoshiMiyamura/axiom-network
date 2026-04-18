# API Specification

Copyright (c) 2026 Kantoshi Miyamura

## Overview

Axiom Network provides a REST HTTP API for node interaction. The API uses JSON for request/response bodies and standard HTTP status codes for error handling.

Default port: 8332 (mainnet), 18332 (testnet)

Authentication: Not yet implemented (planned for production)

## Implemented Endpoints (Phase 8 & 9)

### Node / Chain Endpoints

#### GET /status

Get current node status.

Response:
```json
{
  "best_block_hash": "000000000000000000...",
  "best_height": 100000,
  "mempool_size": 42,
  "orphan_count": 3
}
```

#### GET /best_block_hash

Get best block hash.

Response:
```json
"000000000000000000..."
```

#### GET /best_height

Get best block height.

Response:
```json
100000
```

#### GET /tip

Get chain tip (alias for /status).

Response: Same as /status

#### GET /block/:hash

Get block by hash.

Parameters:
- `hash`: Block hash (64-character hex string)

Response:
```json
{
  "hash": "000000000000000000...",
  "height": 100000,
  "timestamp": 1234567890,
  "prev_block_hash": "000000000000000000...",
  "merkle_root": "abc123...",
  "nonce": 123456,
  "difficulty": 16,
  "transaction_count": 10
}
```

Error: 404 if block not found

#### GET /block/height/:height

Get block by height.

Parameters:
- `height`: Block height (integer)

Response: Same as /block/:hash

Error: 404 if block not found

### Wallet / State Endpoints

#### GET /balance/:address

Get balance for address.

Parameters:
- `address`: Axiom address (starts with "axm")

Response:
```json
{
  "balance": 1000000000
}
```

Note: Balance in satoshis (1 AXM = 100,000,000 satoshis)

Error: 400 if invalid address format

#### GET /nonce/:address

Get nonce for address.

Parameters:
- `address`: Axiom address (starts with "axm")

Response:
```json
{
  "nonce": 42
}
```

Error: 400 if invalid address format

### Submission Endpoints

#### POST /submit_transaction

Submit a signed transaction to the mempool.

Request:
```json
{
  "transaction_hex": "0123456789abcdef..."
}
```

Response:
```json
{
  "txid": "abc123..."
}
```

Errors:
- 400: Invalid hex encoding or malformed transaction
- 400: Transaction rejected (validation failed)

### Network / Peer Endpoints

#### GET /peers

Get list of connected peers.

Response:
```json
{
  "peers": [
    {
      "address": "192.168.1.100:8333",
      "connected": true
    }
  ],
  "count": 1
}
```

#### GET /peer_count

Get number of connected peers.

Response:
```json
5
```

## Wallet Primitives (Phase WALLET-SECURITY)

### Address Format

Axiom addresses v2: `axm` + hex(pubkey_hash[32]) + hex(checksum[4]) = 75 chars total

Checksum: `SHA256(SHA256("axiom-addr-v2:" || pubkey_hash))[0..4]`

v1 legacy (67 chars, no checksum) accepted for backward compatibility, never emitted.

### Key Generation

```rust
use axiom_wallet::{KeyPair, generate_seed_phrase, recover_wallet_from_seed, derive_account};

// Generate with seed phrase backup (recommended)
let (phrase, master_seed) = generate_seed_phrase(); // 24-word BIP39 mnemonic
let keypair = derive_account(&master_seed, 0)?;     // account index 0

// Recover from phrase
let master_seed = recover_wallet_from_seed("word1 word2 ... word24")?;
let keypair = derive_account(&master_seed, 0)?;

// Random keypair (no backup)
let keypair = KeyPair::generate()?;
```

### Keystore (encrypted key storage)

```rust
use axiom_wallet::{create_keystore, unlock_keystore, export_keystore, import_keystore};

// Encrypt
let keystore = create_keystore(&keypair.export_private_key(), "MyP@ssword1")?;
let json = export_keystore(&keystore)?;  // JSON string — save to disk

// Unlock
let keystore = import_keystore(&json)?;
let private_key = unlock_keystore(&keystore, "MyP@ssword1")?; // Zeroizing<Vec<u8>>
let keypair = KeyPair::from_private_key(private_key.to_vec())?;
```

### Safety checks

```rust
use axiom_wallet::{validate_address, validate_password_strength,
                   validate_amount_not_dust, validate_fee_reasonable};

validate_address("axm...")?;              // verifies checksum for v2
validate_password_strength("MyP@ss1!")?; // len≥8, upper+lower+digit+special
validate_amount_not_dust(1000)?;          // ≥546 satoshis
validate_fee_reasonable(100, 1000)?;      // fee ≤50% of amount
```

### Transaction Construction

```rust
use axiom_wallet::{KeyPair, TransactionBuilder};
use axiom_primitives::{Amount, Hash256};

let tx = TransactionBuilder::new()
    .add_input(prev_tx_hash, prev_output_index)
    .add_output(amount, recipient_pubkey_hash)
    .nonce(current_nonce)
    .keypair(keypair)
    .build()?;

let tx_hex = hex::encode(axiom_protocol::serialize_transaction(&tx));
```

### Transaction Signing

Transactions use Ed25519 signatures via `Ed25519Backend`. The `SignatureBackend` trait
is the integration point for future post-quantum schemes
(future-ready / post-quantum-capable architecture).

Fee is implicit: `fee = sum(inputs) - sum(outputs)`

Private keys never leave the wallet. Only signed transactions reach the RPC server.

## Explorer Query Methods

The node provides methods for explorer/web interfaces:

- `get_recent_blocks(limit)`: Get recent blocks in descending order
- `get_mempool_transactions()`: Get all mempool transactions
- `get_chain_work()`: Get cumulative chain work
- `get_block(hash)`: Get block by hash
- `get_nonce(pubkey_hash)`: Get nonce for address

## Error Handling

HTTP status codes:
- 200: Success
- 400: Bad request (invalid parameters)
- 404: Not found (block, transaction, etc.)
- 500: Internal server error

Error response format:
```json
{
  "error": "Error message description"
}
```

## Rate Limiting

Not yet implemented. Planned for production deployment.

## Authentication

Not yet implemented. Planned for production deployment with HTTP Basic Auth or API keys.

## WebSocket API

Not yet implemented. Planned for real-time updates:
- New blocks
- New transactions
- Mempool changes

## API Versioning

Not yet implemented. Breaking changes will require version bump in future.

## Security Notes

- No admin or privileged endpoints
- No node control via API
- No consensus override capabilities
- No emergency stop mechanisms
- All transactions must be properly signed
- Node validation cannot be bypassed

## Current Limitations

- RPC server is placeholder implementation (handlers return mock data)
- Balance queries not yet connected to UTXO set
- Nonce queries not yet connected to storage
- Block queries not yet connected to chain state
- Peer management not yet implemented
- No authentication or rate limiting
- No WebSocket support

## Next Steps for Production

1. Connect RPC handlers to actual node state
2. Implement authentication (HTTP Basic Auth or API keys)
3. Add rate limiting
4. Add WebSocket support for real-time updates
5. Add transaction history queries
6. Add UTXO set queries by address
7. Add mempool transaction queries
8. Add network statistics endpoints
9. Add comprehensive error handling
10. Add request validation and sanitization



## Explorer Endpoints (Phase 9)

### GET /blocks/recent

Get recent blocks (up to 20).

Response:
```json
{
  "blocks": [
    {
      "hash": "000000000000000000...",
      "height": 100000,
      "timestamp": 1234567890,
      "prev_block_hash": "000000000000000000...",
      "merkle_root": "abc123...",
      "nonce": 123456,
      "difficulty": 16,
      "transaction_count": 10
    }
  ],
  "count": 20
}
```

### GET /block/:hash/txs

Get all transactions in a block.

Parameters:
- `hash`: Block hash (64-character hex string)

Response:
```json
{
  "transactions": [
    {
      "txid": "abc123...",
      "version": 1,
      "tx_type": "coinbase",
      "inputs": [],
      "outputs": [
        {
          "value": 5000000000,
          "pubkey_hash": "def456..."
        }
      ],
      "nonce": 0,
      "locktime": 0
    }
  ],
  "count": 1
}
```

### GET /tx/:txid

Get transaction by ID.

Parameters:
- `txid`: Transaction ID (64-character hex string)

Response:
```json
{
  "txid": "abc123...",
  "version": 1,
  "tx_type": "transfer",
  "inputs": [
    {
      "prev_tx_hash": "def456...",
      "prev_output_index": 0,
      "signature": "789abc...",
      "pubkey": "012def..."
    }
  ],
  "outputs": [
    {
      "value": 1000000,
      "pubkey_hash": "345ghi..."
    }
  ],
  "nonce": 42,
  "locktime": 0
}
```

Note: Currently searches mempool only. Block storage search requires transaction index (future work).

### GET /address/:address/txs

Get transactions for an address.

Parameters:
- `address`: Axiom address (starts with "axm")

Response:
```json
{
  "transactions": [
    {
      "txid": "abc123...",
      "block_height": 100000,
      "timestamp": null,
      "value_change": 1000000
    }
  ],
  "count": 1
}
```

Note: Currently returns UTXOs only. Full transaction history requires indexing (future work).

## Metrics Endpoint (Phase 9)

### GET /metrics

Get node metrics.

Response:
```json
{
  "block_height": 100000,
  "best_block_hash": "000000000000000000...",
  "mempool_size": 42,
  "peer_count": 5,
  "chain_work": "00000000000000000000...",
  "uptime_seconds": 3600
}
```

## Web Explorer & Wallet (Phase 9)

A simple web interface is provided in the `web/` directory.

### Features

- Block explorer (view recent blocks, search by hash/address)
- Web wallet (generate keypair, view balance, send transactions)
- Node metrics dashboard

### Usage

1. Start RPC server on `localhost:8332`
2. Serve `web/` directory with any HTTP server
3. Open in browser

### Security Warning

The web wallet is for testing only:
- Private keys stored in browser localStorage (unencrypted)
- No proper key derivation
- Simplified transaction signing

**DO NOT USE WITH REAL FUNDS**

For production, use the Rust wallet library (`axiom-wallet` crate).

### Architecture

```
Browser (HTML/JS) → RPC Server (HTTP/JSON) → Node (Blockchain State)
```

See `web/README.md` for detailed documentation.
