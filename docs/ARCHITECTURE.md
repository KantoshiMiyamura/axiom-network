# Architecture

Copyright (c) 2026 Kantoshi Miyamura

## System Overview

Axiom Network is a layered peer-to-peer monetary system.

```
┌─────────────────────────────────────┐
│         Wallet / API Layer          │
├─────────────────────────────────────┤
│       Application Layer (RPC)       │
├─────────────────────────────────────┤
│         Validation Layer            │
├─────────────────────────────────────┤
│       Consensus Layer (PoW)         │
├─────────────────────────────────────┤
│      Network Layer (P2P)            │
├─────────────────────────────────────┤
│       Storage Layer (UTXO)          │
├─────────────────────────────────────┤
│    Cryptographic Primitives         │
└─────────────────────────────────────┘
```

## Crate Map

The crate map is split into the **stable blockchain core** that ships in the
testnet release and the **experimental optional modules** that live in the
repo for development convenience but are not part of the released
binaries. See [MODULES.md](MODULES.md) for the per-module status of the
experimental set.

### Stable — blockchain core

| Crate | Purpose |
|-------|---------|
| `axiom-primitives` | Block, transaction, and UTXO data structures |
| `axiom-crypto` | SHA-256, ML-DSA-87 (FIPS 204) signing, BIP39 seed handling |
| `axiom-protocol` | Wire protocol message types and serialization |
| `axiom-consensus` | PoW validation, LWMA-3 difficulty adjustment |
| `axiom-storage` | fjall-backed UTXO set, block store, nonce index |
| `axiom-node` | Node runtime: mempool, chain state, peer manager, network service |
| `axiom-rpc` | Axum HTTP/WebSocket RPC server |
| `axiom-wallet` | Keypair handling, address derivation, transaction builder |
| `axiom-signer` | Standalone `axiom-sign` transaction signer binary |
| `axiom-cli` | Node binaries: `axiom`, `axiom-node`, `axiom-keygen`, `axiom-bump-fee` |
| `axiom-ai` | PoUC compute market (consensus-adjacent, on-chain inference accounting) |
| `axiom-guard` | Per-node persistent ML-DSA-87 identity keypair |
| `axiom-ct` | Pedersen commitments + Bulletproof range proofs (optional confidential txs) |
| `axiom-monitor` | Autonomous monitoring agent, health scoring, fee optimizer |

### Experimental — optional modules

These compile in the workspace but are **not** built by the release
pipeline, **not** signed, and **not** advertised in the downloads page.
They have varying maturity and may change without notice. Read
[MODULES.md](MODULES.md) before depending on any of them.

| Crate / dir | Purpose | Status |
|-------------|---------|--------|
| `wallet/src-tauri/` (`axiom-desktop-wallet`) | Tauri 2 desktop wallet backend | Build gated off in CI; ready for hardening pass |
| `wallet/src/` | Tauri 2 desktop wallet frontend (React + TS) | Same lifecycle as `axiom-desktop-wallet` |
| `shared/` (`axiom-community-shared`) | Community-platform shared types and crypto | Compiles; library only |
| `server/` (`axiom-community-server`) | Off-chain community server (auth, jobs, messaging) | Compiles; security refactor pending |
| `client/` (`axiom-community-client`) | Community CLI/TUI client | Skeleton — TUI rendering not implemented |
| `server/axiom-mind/` + `server/axiom_mind.py` | AxiomMind guardian daemon (Python) | Standalone; advisory-only; not wired to consensus |

## Cryptographic Primitives

- Hash function: SHA-256 (double hash for commitments and address checksums)
- Signature scheme: Ed25519 (only active on-chain scheme)
- Signature abstraction: `SignatureBackend` trait (future-ready / post-quantum-capable architecture)
- Address format: `axm` prefix + hex(pubkey_hash) + hex(checksum) — v2, 75 chars
- KDF (keystore): Argon2id (m=65536 KiB / t=3 / p=4)
- AEAD (keystore): XChaCha20-Poly1305
- Seed derivation: BIP39 → PBKDF2-HMAC-SHA512 → HKDF-SHA512 per account
- Deterministic serialization for all signed data

## Consensus Layer

- Proof-of-work consensus
- Nakamoto consensus model
- Longest chain rule
- Target block time: 30 seconds
- Difficulty adjustment: LWMA-3, every block (60-block window)
- No checkpoints (deterministic from genesis)

## Ledger Model

- UTXO-based state model
- Explicit inputs and outputs
- No account balances
- No global state beyond UTXO set
- Deterministic state transitions

## Transaction Model

- Inputs: References to prior outputs
- Outputs: Value + locking script
- Signatures: Prove ownership of inputs
- Fees: Implicit (sum of inputs - sum of outputs)
- Replay protection: Input uniqueness

## Storage Layer

- UTXO set: Active unspent outputs
- Block storage: Full block history
- Transaction index: Optional for wallets
- State commitment: Merkle root of UTXO set
- Pruning: Optional for non-archival nodes

## Network Layer

- Peer-to-peer gossip protocol
- Block propagation: Inv/GetData pattern
- Transaction propagation: Mempool relay
- Peer discovery: DNS seeds + peer exchange
- DoS protection: Rate limiting + proof-of-work

## Validation Layer

- Transaction validation: Signature + script + economics
- Block validation: PoW + transactions + consensus rules
- Chain validation: Cumulative difficulty + fork choice
- Mempool validation: Pre-consensus checks

## Wallet Layer

- Key management: BIP39 seed phrase + HKDF-SHA512 flat account derivation
- Transaction construction: Nonce-aware builder + Ed25519 signing
- Balance tracking: UTXO scanning
- Address generation: Deterministic derivation with SHA-256d checksum
- Key protection: Argon2id KDF + XChaCha20-Poly1305 encrypted keystore
- Signature abstraction: `SignatureBackend` trait (future-ready / post-quantum-capable)

## API Layer

- RPC interface: JSON-RPC over HTTP
- Wallet API: Transaction submission + balance queries
- Explorer API: Block + transaction lookup
- No admin APIs
- No privileged operations

## Failure Model

- Byzantine fault tolerance: Not assumed
- Network partitions: Handled by longest chain rule
- Node crashes: Recoverable from disk state
- Reorgs: Handled by fork choice rule
- Double spends: Prevented by UTXO model

## Trust Boundaries

- Node trusts: Own validation logic only
- Wallet trusts: Own keys + connected node
- User trusts: Own wallet + network consensus
- No trusted third parties
- No admin keys
- No central coordination

## Privacy Model

- Pseudonymous addresses
- No identity requirements
- Optional address reuse (discouraged)
- Transaction graph analysis possible (mitigation: future work)
- Network privacy: Tor support recommended

## Scalability Model

- On-chain scaling: Block size limit (1 MB initial)
- Off-chain scaling: Not in initial scope
- Pruning: Optional UTXO-only mode
- Light clients: SPV verification (future work)

## Upgrade Model

- Hard forks: Require full node upgrade
- Soft forks: Backward compatible
- No automatic updates
- No governance mechanism
- Protocol changes require social consensus


## Storage Implementation

Database: fjall (pure Rust embedded LSM-tree key-value store)

Key namespaces:
- 0x01: Block data (key: block_hash)
- 0x02: Transaction data (key: txid)
- 0x03: UTXO set (key: txid || output_index)
- 0x04: Chain metadata (best block, height, genesis)
- 0x05: Nonce tracking (key: pubkey_hash)

Persistence guarantees:
- Atomic batch operations via fjall batch commits
- Durable writes with fsync
- Crash recovery via fjall's LSM-tree storage
- No in-memory-only consensus state

Restart recovery:
- Database reopens existing data directory
- Chain metadata restored from disk
- UTXO set reconstructed from storage
- No manual recovery steps required

## Node Runtime Implementation

Configuration:
- Data directory path
- Network type (dev/test)
- RPC bind address
- Mempool limits (size, count)
- Minimum fee rate

Genesis initialization:
- Deterministic genesis block per network
- Created once on first startup
- Genesis hash immutable after creation
- 50 AXM coinbase to unspendable address
- Stored in chain metadata

Chain state manager:
- Owns storage handle
- Tracks best block hash and height
- Manages UTXO set updates
- Applies blocks atomically
- Recovers state from storage on restart

Mempool:
- In-memory transaction pool
- Size and count limits
- Duplicate rejection
- FIFO eviction when full
- Cleared on block processing

Transaction validation:
- Structure checks (inputs, outputs, dust)
- Nonce validation (replay protection)
- UTXO existence checks
- Signature verification (Ed25519)
- Fee rate validation
- Balance checks (input >= output)

Block assembly:
- Collects mempool transactions
- Creates coinbase with block reward
- Computes merkle root
- No proof-of-work (development mode)
- Block reward follows halving schedule

Block processing:
- Validates block structure
- Applies transactions to UTXO set
- Updates nonces
- Removes spent UTXOs
- Adds new UTXOs
- Updates chain metadata atomically
- Removes included transactions from mempool

## P2P Networking Implementation

Transport layer:
- TCP listener for inbound connections
- TCP connector for outbound connections
- Async I/O using tokio runtime
- Length-prefixed message framing
- Connection-per-peer model

Message types:
- Version: Protocol version, network, best height
- VerAck: Handshake acknowledgment
- Ping/Pong: Keepalive
- GetTip: Request chain tip
- Tip: Chain tip response
- GetBlock: Request block by hash
- Block: Block data
- Tx: Transaction data

Message format:
- Header: [type: u8][length: u32]
- Payload: [data: bytes]
- Maximum size: 10 MB
- Deterministic serialization via bincode

Protocol handshake:
1. Node A connects to Node B
2. A sends Version message
3. B validates version (protocol version, network)
4. B sends VerAck
5. A sends VerAck
6. Both peers enter Ready state

Peer states:
- Connecting: TCP connected, awaiting version
- VersionReceived: Version validated, awaiting verack
- Ready: Handshake complete, can exchange messages
- Disconnected: Connection closed

Peer tracking:
- Peer ID (unique per connection)
- Socket address
- Connection direction (inbound/outbound)
- Protocol version
- Network name
- Best height/hash
- Last seen timestamp

Peer manager:
- Tracks all connected peers
- Manages peer state transitions
- Validates handshake messages
- Provides peer queries
- Supports broadcast operations

Network service integration:
- Bridges P2P layer with node runtime
- Handles received transactions from peers
- Validates and admits transactions to mempool
- Handles received blocks from peers
- Validates and applies blocks to chain state
- Tracks seen transactions/blocks to prevent rebroadcast loops
- Provides GetTip/Tip exchange for sync discovery
- Provides GetBlock/Block exchange for block sync
- Supports local transaction/block submission with broadcast

Transaction propagation:
- Received Tx messages validated before mempool admission
- Duplicate transactions rejected (seen tracking)
- Invalid transactions rejected silently
- No rebroadcast to originating peer

Block propagation:
- Received Block messages validated before application
- Duplicate blocks rejected (seen tracking)
- Invalid blocks rejected silently
- Mempool updated after block acceptance
- No rebroadcast to originating peer

Sync primitives:
- GetTip/Tip: Discover remote chain state
- GetBlock/Block: Request specific blocks by hash
- Sequential block application required

## Wallet Architecture

### Modules

| Module | Purpose |
|--------|---------|
| `signing.rs` | `SignatureBackend` trait + `Ed25519Backend` (only active on-chain scheme) |
| `keypair.rs` | `KeyPair` with `Zeroizing<Vec<u8>>` private key; fixed `from_private_key` |
| `address.rs` | Address v2 (75 chars, SHA-256d checksum); v1 legacy (67 chars) accepted |
| `keystore.rs` | Argon2id KDF + XChaCha20-Poly1305 AEAD encrypted keystore |
| `seed.rs` | BIP39 24-word mnemonic + HKDF-SHA512 flat account key derivation |
| `safety.rs` | Password strength, dust threshold, fee-fraction safety checks |
| `tx_builder.rs` | Nonce-aware transaction builder |

### Key management

- Ed25519 key pairs (32-byte private key, 32-byte public key)
- Private key wrapped in `Zeroizing<Vec<u8>>` — memory erased on drop
- Random key generation: OS entropy (OsRng)
- Deterministic derivation: BIP39 seed → HKDF-SHA512 → Ed25519 keypair per account index
- Signature backend abstraction: future-ready / post-quantum-capable architecture

### Address format (v2)

```
axm  +  hex(pubkey_hash[32])  +  hex(SHA256d("axiom-addr-v2:" || pubkey_hash)[0..4])
 3        64 chars                   8 chars                   = 75 chars total
```

- v1 (67 chars, no checksum): accepted for backward compatibility, never emitted
- v2 (75 chars): always emitted; invalid checksum → `WalletError::InvalidChecksum`

### Encrypted keystore

- KDF: Argon2id (m=65536 KiB / t=3 / p=4 in production)
- AEAD: XChaCha20-Poly1305 (24-byte nonce, 16-byte auth tag)
- Wrong password and data corruption both detected by auth tag
- Keystore exported as self-contained JSON

### Signing flow

```
unsigned_tx → serialize → Ed25519.sign(private_key, bytes) → embed signature → submit
```

Private key never leaves the wallet. Only signed transaction bytes reach the RPC server.

### Wallet security model

- Private keys never leave wallet (trust boundary enforced by design)
- Keys encrypted at rest (Argon2id + XChaCha20-Poly1305 keystore)
- Seed phrase is the only backup required (BIP39, 24 words)
- Deterministic signing — no nonce reuse risk
- Password strength validation enforced on keystore creation

### Notes

- No hardware wallet (Ledger/Trezor) support — future work
- No multi-signature support — future work
- No BIP32 hierarchical derivation (flat HKDF scheme)
- Ed25519 not quantum-resistant — PQ migration path designed, not yet activated
- See docs/WALLET-SECURITY.md for full details


## RPC Architecture

Server framework:
- HTTP server using axum (async Rust web framework)
- REST API (not JSON-RPC 2.0)
- JSON request/response bodies
- Standard HTTP status codes
- Tokio async runtime

Endpoint categories:
1. Node/chain: Status, block queries, chain tip
2. Wallet/state: Balance, nonce queries
3. Submission: Transaction submission
4. Network: Peer information

Implemented endpoints:
- GET /status - Node status (best block, height, mempool, orphans)
- GET /best_block_hash - Best block hash
- GET /best_height - Best block height
- GET /tip - Chain tip (alias for status)
- GET /block/:hash - Block by hash
- GET /block/height/:height - Block by height
- GET /balance/:address - Balance for address
- GET /nonce/:address - Nonce for address
- POST /submit_transaction - Submit signed transaction
- GET /peers - Connected peers list
- GET /peer_count - Peer count

Request validation:
- Hash format validation (64-character hex)
- Address format validation (axm prefix)
- Hex decoding validation
- Transaction deserialization validation

Error handling:
- 400 Bad Request: Invalid parameters
- 404 Not Found: Block/transaction not found
- 500 Internal Server Error: Node errors
- JSON error response: {"error": "message"}

State management:
- Shared node state via Arc<Mutex<NodeState>>
- Thread-safe access to node data

## Explorer Query Interface

Node query methods:
- get_recent_blocks(limit) - Recent blocks in descending order
- get_mempool_transactions() - All mempool transactions
- get_chain_work() - Cumulative chain work
- get_block(hash) - Block by hash
- get_nonce(pubkey_hash) - Nonce for address
- best_block_hash() - Current chain tip hash
- best_height() - Current chain height
- mempool_size() - Transaction count in mempool
- orphan_count() - Orphan block count

Block traversal:
- Walk chain backwards from tip
- Follow prev_block_hash links
- Stop at genesis (prev_block_hash == zero)
- Limit results for pagination

Transaction queries:
- Mempool transactions available
- Transaction index available for confirmed transactions

Address queries:
- Nonce tracking operational
- Balance queries via UTXO iteration
- Transaction history available via TxIndex
