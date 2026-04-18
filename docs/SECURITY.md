# Security Model

Copyright (c) 2026 Kantoshi Miyamura

## Security Principles

1. Cryptographic security over obscurity
2. Explicit validation at all trust boundaries
3. Deterministic behavior under all conditions
4. No privileged operations
5. No admin keys
6. Defense in depth

## Trust Model

Node trusts:
- Own validation logic
- Own cryptographic verification
- Own storage integrity

Node does not trust:
- Peers
- Network messages
- External data
- User input

Wallet trusts:
- Own key material
- Connected node (for chain state)

User trusts:
- Own wallet
- Network consensus (longest chain)

## Threat Model

### Network-Level Attacks

1. Sybil attack: Attacker creates many fake peers
   - Mitigation: Proof-of-work for consensus, not peer identity
   - Peer diversity through multiple connection strategies

2. Eclipse attack: Attacker isolates victim from honest network
   - Mitigation: Multiple peer discovery mechanisms
   - Outbound connection diversity
   - Checkpoint validation (optional)

3. DDoS attack: Attacker floods network with traffic
   - Mitigation: Rate limiting per peer
   - Connection limits
   - Proof-of-work for expensive operations

### Consensus-Level Attacks

1. 51% attack: Attacker controls majority hash rate
   - Mitigation: Economic cost of attack > potential gain
   - No protocol-level defense (fundamental to Nakamoto consensus)
   - Detection: Unusual reorg depth

2. Selfish mining: Attacker withholds blocks strategically
   - Mitigation: None at protocol level
   - Economic analysis suggests limited profitability

3. Long-range attack: Attacker rewrites deep history
   - Mitigation: Checkpoints (social consensus)
   - Nodes reject reorgs beyond certain depth

### Transaction-Level Attacks

1. Double spend: Attacker spends same UTXO twice
   - Mitigation: UTXO uniqueness enforced by consensus
   - Confirmation depth for high-value transactions

2. Replay attack: Attacker replays transaction on different chain
   - Mitigation: Domain-separated signing — `sign_with_domain(chain_id, tx_bytes)` implemented (Phase 20 / B-3)
   - Signing message: `double_hash256(chain_id_bytes || tx_bytes)`; chain IDs: `"axiom-dev-1"` / `"axiom-test-1"`
   - UTXO uniqueness provides secondary protection (spent outputs invalid)

3. Signature forgery: Attacker forges transaction signature
   - Mitigation: Ed25519 signature verification
   - Cryptographic security assumption

### Implementation-Level Attacks

1. Buffer overflow: Memory corruption vulnerabilities
   - Mitigation: Memory-safe implementation language (Rust)
   - Bounds checking
   - Fuzzing

2. Integer overflow: Arithmetic vulnerabilities
   - Mitigation: Checked arithmetic
   - Explicit overflow handling
   - Value range validation

3. Consensus bug: Implementation divergence
   - Mitigation: Comprehensive test suite
   - Deterministic serialization
   - Reference implementation

## Attack Surfaces

### Network Interface
- Peer connections
- Message parsing
- DoS vectors

### RPC Interface
- Authentication (if enabled)
- Input validation
- Rate limiting

### Storage Layer
- Disk corruption
- State inconsistency
- Rollback safety

### Cryptographic Layer
- Key generation
- Signature verification
- Hash collisions (SHA-256 assumption)

## Cryptographic Assumptions

1. SHA-256 is collision-resistant
2. SHA-256 is preimage-resistant
3. Ed25519 is existentially unforgeable
4. Discrete log problem is hard on Curve25519
5. Random number generation is cryptographically secure

If any assumption breaks, protocol security is compromised.

## Release-Blocking Security Conditions

Before mainnet launch:

1. Full test coverage of consensus rules
2. Fuzzing of all parsers
3. External security audit
4. No known critical vulnerabilities
5. Deterministic builds
6. Reproducible validation
7. Memory safety verification
8. Integer overflow checks
9. Signature verification tests
10. Reorg handling tests

## Security Development Lifecycle

1. Threat modeling during design
2. Secure coding practices during implementation
3. Code review for all changes
4. Automated testing (unit + integration)
5. Fuzzing for parser code
6. Static analysis
7. External audit before release
8. Responsible disclosure policy
9. Security patch process

## Vulnerability Disclosure

(Process to be defined before mainnet)

Expected elements:
- Security contact email
- PGP key for encrypted reports
- Response time commitment
- Coordinated disclosure timeline
- Bug bounty program (optional)

## Operational Security

Node operators should:
- Run nodes on dedicated hardware
- Use firewall rules
- Enable connection limits
- Monitor for unusual activity
- Keep software updated
- Backup wallet keys securely
- Use Tor for network privacy (optional)

## Key Management

Wallet security:
- Keys never leave wallet
- Keys encrypted at rest
- Mnemonic backup (BIP39-style)
- Hardware wallet support (future)

Node security:
- No private keys on node (unless wallet enabled)
- RPC authentication required
- No remote RPC by default

## Privacy Considerations

Privacy is not anonymity.

Axiom Network provides pseudonymity:
- Addresses are not linked to identity
- Transaction graph is public
- Network traffic is observable

Privacy improvements (future work):
- CoinJoin support
- Confidential transactions
- Tor integration
- Dandelion++ transaction relay

## Security vs. Usability Tradeoffs

Prioritize security over convenience:
- No automatic updates (user must verify)
- No trusted setup
- No recovery mechanisms for lost keys
- No account recovery
- No password reset

Users are responsible for their own security.

## Audit Scope

Pre-mainnet audit must cover:
- Consensus implementation
- Cryptographic operations
- Network protocol
- Transaction validation
- State transitions
- Storage integrity
- RPC interface
- Wallet key management

## Known Limitations

1. No quantum resistance — Ed25519 vulnerable to quantum computers; PQ migration path designed (future-ready / post-quantum-capable architecture), not yet activated
2. No protection against 51% attack
3. No privacy against chain analysis
4. No protection against network-level surveillance
5. No recovery from lost seed phrase — no server-side recovery by design
6. No hardware wallet support — Ledger/Trezor integration is future work
7. No multi-signature support — single point of failure per address

These are accepted tradeoffs for the current design.


### Wallet-Level Attacks (Phase WALLET-SECURITY)

1. Private key theft: Attacker steals wallet private keys
   - Mitigation: Argon2id + XChaCha20-Poly1305 encrypted keystore (implemented)
   - Hardware wallet support (future work)
   - Key never transmitted over network (trust boundary enforced)
   - Private key stored in `Zeroizing<Vec<u8>>` — memory erased on drop

2. Key generation weakness: Predictable keys
   - Mitigation: OS entropy source (OsRng)
   - Ed25519 standard key generation via ed25519-dalek
   - BIP39 entropy: 256 bits from OsRng

3. Signature malleability: Attacker modifies valid signature
   - Mitigation: Ed25519 signatures are non-malleable
   - Transaction ID includes signature
   - Signature verification enforced

4. Nonce reuse: Attacker replays transaction with same nonce
   - Mitigation: Nonce tracking per address
   - Nonce must increment
   - Duplicate nonce rejected

5. Fee manipulation: Attacker tricks user into high fees
   - Mitigation: Explicit fee calculation (inputs - outputs)
   - `validate_fee_reasonable` enforces max 50% fee fraction
   - `validate_amount_not_dust` enforces min 546 satoshis

6. Weak password: Low-entropy keystore password
   - Mitigation: `validate_password_strength` enforces length + character classes
   - Argon2id makes brute-force attacks expensive even with weak passwords

7. Typo in recipient address
   - Mitigation: Address v2 SHA-256d checksum (4-byte, detects single-byte flip)
   - `WalletError::InvalidChecksum` on mismatch

8. Seed phrase loss: User loses recovery material
   - Mitigation: `generate_seed_phrase` returns 24-word BIP39 phrase
   - User must write down phrase; no server-side recovery
   - All account keypairs derivable from phrase alone

### RPC-Level Attacks (Phase 14A)

1. Unauthorized access: Attacker accesses RPC without permission
   - Mitigation: Bearer token authentication implemented (`--rpc-auth-token` flag)
   - `Authorization: Bearer <token>` required on all requests when token is set
   - Bind to localhost only in development; TLS via nginx reverse proxy

2. Request flooding: Attacker floods RPC with requests
   - Mitigation: Per-IP rate limiting implemented (`RpcRateLimiter` middleware)
   - Violators banned for `RPC_BAN_DURATION_SECS` seconds
   - Request size limits enforced by HTTP framework

3. Malformed requests: Attacker sends invalid data
   - Mitigation: Request validation implemented
   - JSON parsing errors handled
   - Hex decoding validation
   - Address format validation

4. Transaction injection: Attacker submits invalid transactions
   - Mitigation: Full transaction validation before mempool admission
   - Signature verification required
   - UTXO existence checks
   - Nonce validation

5. Information disclosure: Attacker queries sensitive data
   - Mitigation: No privileged endpoints
   - No admin operations via RPC
   - Balance queries require address (no enumeration)
   - No private key exposure

## Cryptographic Assumptions

1. SHA-256 collision resistance
   - Used for: Transaction IDs, block hashes, merkle roots
   - Security level: 128 bits (birthday bound)
   - Status: Industry standard, no known attacks

2. Ed25519 signature security
   - Used for: Transaction signatures
   - Security level: 128 bits
   - Status: Modern standard, no known attacks
   - Properties: Non-malleable, deterministic

3. Random number generation
   - Used for: Key generation
   - Source: OS entropy (OsRng)
   - Status: Platform-dependent, generally secure

## Key Management Security (Phase WALLET-SECURITY)

The wallet library NOW provides key storage and protection directly.

### Implemented

1. Key encryption at rest
   - `create_keystore(plaintext, password)` — Argon2id + XChaCha20-Poly1305
   - `unlock_keystore(keystore, password)` — returns `Zeroizing<Vec<u8>>`
   - Keys never stored in plaintext
   - Auth tag detects wrong password and data corruption

2. Key backup and recovery
   - `generate_seed_phrase()` — 24-word BIP39 mnemonic
   - `recover_wallet_from_seed(phrase)` — full recovery from phrase
   - `derive_account(master_seed, index)` — deterministic account keypairs

3. Memory safety
   - Private keys: `Zeroizing<Vec<u8>>` — erased on drop
   - Keystore derived keys: `Zeroizing<[u8; 32]>` — erased on drop
   - Master seeds: `Zeroizing<Vec<u8>>` — erased on drop

4. Key access control
   - Password strength validation: `validate_password_strength`
   - Minimum: 8 chars, uppercase, lowercase, digit, special char
   - Session unlock model: unlock once, use `Zeroizing` handle

### Still required from applications

- Session timeout (wallet lock after inactivity)
- Hardware wallet support (future)
- Key rotation: migrate funds to new addresses when needed

Example usage:
```rust
let (phrase, master_seed) = generate_seed_phrase();
// user writes down phrase

let keypair = derive_account(&master_seed, 0)?;
let keystore = create_keystore(&keypair.export_private_key(), "MyP@ssword1")?;
let json = export_keystore(&keystore)?;
// save json to disk

// later: unlock
let keystore = import_keystore(&json)?;
let private_key = unlock_keystore(&keystore, "MyP@ssword1")?;
let keypair = KeyPair::from_private_key(private_key.to_vec())?;
```

## RPC Security Considerations (Phase 14A)

RPC server implements bearer token authentication and per-IP rate limiting.
Deployed behind nginx for TLS termination. See `docs/DEPLOYMENT_GUIDE.md`.

Implemented:
1. Bearer token authentication (`--rpc-auth-token` CLI flag; `AuthConfig` middleware)
2. Per-IP rate limiting (per-second + per-minute limits; IP ban on violation)
3. TLS/HTTPS via nginx reverse proxy (see `docs/DEPLOYMENT_GUIDE.md`)

Still required for production:
4. Request logging and monitoring (operator responsibility)
5. CORS configuration for web access (nginx layer)

Example secure RPC deployment:
```
- Bind to localhost only (127.0.0.1)
- Use nginx for TLS termination + HTTPS
- Set --rpc-auth-token via EnvironmentFile (not on command line)
- Rate limiting active at both nginx and node layers
- Log all requests at nginx level
- Monitor /health and /metrics endpoints
```

## Transaction Security (Phase 8)

Transaction construction security:
1. Verify recipient address format before signing
2. Verify amounts before signing (no overflow)
3. Calculate and display fee to user
4. Confirm transaction details with user
5. Sign only after user confirmation

Transaction submission security:
1. Submit over secure channel (HTTPS)
2. Verify transaction was accepted (check txid)
3. Monitor for confirmation
4. Handle rejection gracefully

## Address Security (Phase WALLET-SECURITY)

Address format: `axm` + hex-encoded public key hash + 4-byte SHA-256d checksum (v2, 75 chars)

Security properties:
- Public key hash prevents key recovery from address
- Hex encoding is unambiguous
- SHA-256d checksum (4 bytes) detects single-byte typos — `WalletError::InvalidChecksum` on mismatch
- v1 legacy addresses (67 chars, no checksum) are still accepted for compatibility

Address validation:
- Must start with "axm"
- Length: 75 chars (v2 with checksum) or 67 chars (v1 legacy)
- Checksum verified on v2 addresses before use

## Operational Security

NOT YET IMPLEMENTED:
- Secure node deployment procedures
- Key ceremony for genesis
- Incident response procedures
- Security audit process
- Vulnerability disclosure policy
- Bug bounty program

## Known Security Limitations

1. ~~No RPC authentication~~ — **Implemented (Phase 14A)**: Bearer token + per-IP rate limiter
2. ~~No rate limiting~~ — **Implemented (Phase 14A)**: per-second/per-minute limits + IP ban
3. No TLS/HTTPS support in binary — handled by nginx reverse proxy (documented)
4. ~~No key encryption in wallet~~ — **Implemented (Phase WALLET-SECURITY)**: Argon2id + XChaCha20-Poly1305
5. ~~No address checksum~~ — **Implemented (Phase WALLET-SECURITY)**: SHA-256d v2 checksum
6. ~~No HD wallet~~ — **Implemented (Phase 22 / B-6)**: `WalletSession` with HKDF-SHA512 multi-address derivation; `new_address()`, `keypair_at(index)`, `all_addresses()`
7. No hardware wallet support — Ledger/Trezor integration is future work (post-mainnet)
8. No multi-signature — single point of failure per address (B-16 post-launch)
9. ~~No DoS protection~~ — **Implemented (Phase 17)**: P2P message size limits (2 MB) + pre-allocation guard
10. No peer reputation — Sybil attack still possible; PoW enforced on `Network::Test` (B-1 closed Phase 20)
11. ~~**PoW not enforced**~~ — **RESOLVED (Phase 20 / B-1)**: `ConsensusValidator::with_pow()` called in `node.rs` on all non-`Dev` networks

## Security Roadmap

Phase 8 (complete):
- [x] Ed25519 key generation
- [x] Transaction signing
- [x] Signature verification
- [x] Nonce-based replay protection

Phase WALLET-SECURITY (complete):
- [x] Address checksum (SHA-256d, v2 format)
- [x] Key encryption at rest (Argon2id + XChaCha20-Poly1305 keystore)
- [x] BIP39 seed phrase backup and recovery
- [x] HKDF-SHA512 deterministic account key derivation
- [x] Signature backend abstraction (future-ready / post-quantum-capable architecture)
- [x] Memory-safe key storage (Zeroizing)
- [x] Password strength validation
- [x] Dust threshold and fee safety checks
- [x] 77 wallet security tests passing

Phase 14A (complete):
- [x] Bearer token RPC authentication (`auth_middleware`, `AuthConfig`)
- [x] Per-IP rate limiting (`RpcRateLimiter`, ban-on-violation)
- [x] `--rpc-auth-token` CLI flag; `into_router()` for testable server
- [x] 16 auth integration tests + 7 auth unit tests

Phase 17 (complete):
- [x] P2P message size cap: `MAX_MESSAGE_SIZE = 2 MB` (down from 10 MB)
- [x] Pre-allocation DoS guard in `transport.rs` (rejects oversized frames before alloc)
- [x] `MAX_TXS_PER_MESSAGE = 10_000`, `MAX_BLOCKS_PER_RESPONSE = 500` constants
- [x] `Network::chain_id()` — `"axiom-dev-1"` / `"axiom-test-1"`
- [x] `sign_with_domain()` + `verify_signature_with_domain()` in `axiom-crypto`
- [x] `GET /health` endpoint: `{status, height, peers, mempool}`
- [x] `peer_count` RPC wired to real `PeerManager::ready_peer_count()`
- [x] 13 Phase 17 tests (health, metrics fields, domain signing, message size limits)

Phase 20 (complete):
- [x] **PoW validation enabled** (B-1): `ConsensusValidator::with_pow()` called in `node.rs` on all non-`Dev` networks
- [x] **Chain ID wired to transaction signing** (B-3): `sign_with_domain(chain_id, tx_bytes)` in `TransactionBuilder`; `ConsensusValidator::with_chain_id()` in validator
- [x] **Real-IP extraction behind reverse proxy** (B-7): `extract_real_ip()` reads `X-Real-IP`/`X-Forwarded-For` from loopback-sourced connections only

Phase 21 (complete):
- [x] **bincode v2 migration** (B-4): `bincode 1.3.3` → `bincode 2.0.1`; all sites use `config::standard()` with explicit bounds; RUSTSEC-2025-0141 (v1) resolved
- [x] Prometheus metrics exposition: `GET /metrics/prometheus` text/plain format

Phase 22 (complete):
- [x] **Multi-address wallet / HD wallet tree** (B-6): `WalletSession` + HKDF-SHA512 account derivation; `new_address()`, `keypair_at(index)`, `all_addresses()`
- [x] Storage migration (B-5): `sled 0.34` → `fjall 2` (actively maintained LSM-tree); fxhash/instant warnings resolved

Phase 23 (complete):
- [x] WebSocket subscriptions (B-9): `GET /ws` endpoint; `WsEvent::NewBlock` + `WsEvent::NewTx`; auth + rate-limit middleware apply before upgrade

Phase 24 (complete):
- [x] Chain pruning (B-8): `prune_to_depth(depth)`; headers preserved via prefix `0x0A`; UTXO/TxIndex never pruned

Open (B-2 — P0 mainnet blocker):
- [ ] **External security audit**: engage firm; send `docs/AUDIT_HANDOFF.md`; audit package ready as of Phase 25

Future (post-mainnet):
- [ ] Hardware wallet support (Ledger/Trezor)
- [ ] Multi-signature support (B-16)
- [ ] Vulnerability disclosure policy
- [ ] Bug bounty program
- [ ] Fuzzing suite (B-13)
- [ ] PQ signature migration (post-quantum, after protocol upgrade)

## Security Contact

(To be established before public release)

For security issues, contact: [REDACTED]
PGP key: [REDACTED]

Do not disclose security issues publicly before coordinated disclosure.
# Axiom Network — Security Model

Copyright (c) 2026 Kantoshi Miyamura

## Threat Model

This document describes the threats Axiom is designed to resist and the
mechanisms that provide protection.

## 1. Cryptographic Security

| Component | Algorithm | Security Level |
|---|---|---|
| Transaction signatures | ML-DSA-87 (CRYSTALS-Dilithium, NIST FIPS 204) | 256-bit post-quantum (Level 5) |
| Block hashing | SHA-256d | 128-bit |
| P2P encryption | X25519 + ChaCha20-Poly1305 | 128-bit |
| Key derivation | HKDF-SHA256 | 256-bit |

**Post-quantum resistance:** All transaction signatures use NIST-standardized
ML-DSA-87 (FIPS 204, Level 5), providing 256-bit post-quantum security against both classical and quantum computers.
Bitcoin's ECDSA/Schnorr signatures are vulnerable to Shor's algorithm on a
sufficiently powerful quantum computer. Axiom is not.

## 2. Consensus Security

| Attack | Protection |
|---|---|
| 51% attack | Proof-of-Work with SHA-256d; requires >50% of network hashrate |
| Long-range reorg | MAX_REORG_DEPTH = 200 blocks; deeper reorgs rejected |
| Chain history erasure | Hardcoded checkpoints in checkpoints.rs |
| Fake chain during IBD | Checkpoint enforcement in handle_headers |
| Eclipse attack | 6 DNS seeds + PeerAddressBook (2048 cap) + auto-reconnect |

## 3. Transaction Security

| Attack | Protection |
|---|---|
| Double spend | UTXO set enforced; each output spendable once |
| Intra-tx double spend | DuplicateInput check before UTXO lookup |
| Coinbase theft | COINBASE_MATURITY = 100 blocks locktime |
| Fee sniping | Locktime + sequence enforcement |
| Dust spam | DUST_LIMIT = 546 sat minimum output |
| Mempool spam | Per-peer rate limit (100 tx/min, 1 MB/min) |
| Mempool flood | Dynamic fee floor (up to 8× base when full) |

## 4. Network Security

| Attack | Protection |
|---|---|
| Sybil attack | MAX_OUTBOUND_PEERS = 16 (diversity cap) |
| Inbound flood | MAX_INBOUND_PEERS = 117 |
| Peer misbehavior | ban_peer() with configurable duration |
| Traffic analysis | P2P encryption (X25519 + ChaCha20-Poly1305) |
| MitM injection | AEAD authentication on all P2P messages |
| IBD stall | 120s timeout + peer ban + block re-queue |

## 5. RPC Security

| Attack | Protection |
|---|---|
| Unauthorized access | Bearer token auth (optional, recommended for mainnet) |
| Rate abuse | 10 req/s, 100 req/min per IP; 1-hour ban on violation |
| OOM via bulk query | Pagination required; max 500 items per response |
| Height overflow | Rejects height > 1,000,000,000 |
| Request size | Max 1 MB per request body |

## 6. Node Stability

| Failure mode | Protection |
|---|---|
| Task panic | spawn_resilient: exponential backoff restart (1s→60s cap) |
| Network partition | Auto-reconnect to seeds on zero peers |
| Chain stall | Watchdog: alert after 30 min without new block |
| Memory pressure | RSS monitor: warn at 2 GB (Linux) |
| Unclean shutdown | fjall LSM-tree with WAL + atomic commits |
| Process crash | systemd Restart=always / WinSW auto-restart |

## 7. Known Limitations / Out of Scope

- **No Tor/I2P support** — IP addresses are visible to peers
- **No Dandelion++** — transaction origin is traceable
- **Single-sig only** — no multi-signature transactions yet
- **No SPV proofs** — light clients must trust a full node
- **External audit** — not yet completed (see AUDIT_HANDOFF.md)

## 8. Responsible Disclosure

To report a security vulnerability, contact: [maintainer contact info]

Do NOT open a public GitHub issue for security vulnerabilities.
# Axiom Network — Threat Model

Copyright (c) 2026 Kantoshi Miyamura

> Scope: public testnet. This threat model identifies realistic attackers,
> their capabilities, what they can achieve, and the mitigations in place.
> It is an input to the external security audit (see `docs/AUDIT_SCOPE.md`).
>
> **This system is testnet-only. No real money is at risk.**

---

## Attacker Capability Assumptions

| Capability | In scope? |
|------------|-----------|
| Controls one or more internet-connected machines | Yes |
| Can send arbitrary P2P messages to our node | Yes |
| Can send arbitrary RPC HTTP requests to our node | Yes |
| Can observe all network traffic (passive) | Yes |
| Can modify traffic in transit (active MITM) | Yes — RPC only if TLS is not deployed; P2P always |
| Controls a minority of hash power (< 50%) | Yes |
| Controls a majority of hash power (≥ 50%) | Out of scope for testnet (PoW disabled) |
| Can compromise the host OS or hardware | Out of scope |
| Can compromise the Rust compiler or supply chain | Out of scope |

---

## Attacker 1: Malicious Peer

**Profile**: An internet-connected node that connects to our P2P port (9000)
and sends well-formed or malformed messages.

### Attack surface

- TCP connection on port 9000 (P2P)
- `P2PMessage` deserialization (`bincode`)
- Handshake state machine (`network/transport.rs`, `network/message.rs`)
- Block and transaction relay handlers

### Attack vectors and impacts

| Vector | Impact | Mitigation | Residual risk |
|--------|--------|------------|---------------|
| Send oversized message to cause OOM | Node crash / DoS | `limits.rs` enforces message size caps before deserialization | **Verify**: caps are applied before `bincode::deserialize`, not after |
| Send malformed bincode bytes | Panic / crash | Rust `Result` propagation; malformed bincode returns `Err` | `bincode` does not cap allocation depth by default — size cap is the primary defense |
| Send a block with invalid structure | Accepted block that violates consensus | `ConsensusValidator::validate_block` rejects it | PoW is disabled — any block with valid structure is accepted |
| Send orphan blocks to fill orphan pool | Memory exhaustion | `OrphanPool` limited to 100 blocks | 100 orphans is ~1-10 MB; low impact |
| Replay old transactions | Double-spend | Per-address nonce enforced strictly | None |
| Eclipse attack (fill peer slots with attacker nodes) | Isolated node sees attacker's chain | Not explicitly mitigated in current code | **Mainnet blocker**: no connection diversity enforcement |
| Version message spoofing | Inconsistent protocol state | Version mismatch rejected in handshake | Low — both sides must agree |

### Mitigations implemented

- Message size caps (`limits.rs`)
- Peer scoring and ban logic (`dos_protection.rs`, `scoring.rs`)
- `ConsensusValidator` rejects structurally invalid blocks
- Orphan pool capacity limit

### Residual risks

- **Eclipse attack** — no maximum inbound/outbound peer slot diversity enforcement
- **Bincode 1.3.x** is unmaintained; no built-in allocation depth limits — size cap is the only defense
- P2P messages are not authenticated — any IP can connect and send messages

---

## Attacker 2: Malicious Miner

**Profile**: An attacker who runs their own mining node and can produce blocks.

### Attack surface

- Block submission via P2P (`process_block`)
- Coinbase transaction content
- Difficulty target field in block header

### Attack vectors and impacts

| Vector | Impact | Mitigation | Residual risk |
|--------|--------|------------|---------------|
| Mine blocks with invalid coinbase (excessive reward) | Create coins out of thin air | `validate_block` checks coinbase ≤ `calculate_block_reward(height)` | None if validation is correct |
| Mine blocks with wrong difficulty target | Violate retarget rule | `ConsensusValidator::with_expected_difficulty` enforced in `apply_block_to_chain` | None |
| Mine a longer competing chain (reorg attack) | Reverse confirmed transactions | Chain selection by cumulative work; depth-N reorgs trigger `rollback_block` | **With PoW disabled**: any miner produces equal-work blocks; two miners produce equal chains (KNOWN_LIMITATIONS §8) |
| Mine blocks with duplicate transactions | Double-spend within a block | `validate_block` checks for duplicate txids | None |
| Mine an empty block (no txs except coinbase) | Network stall (mempool not clearing) | Valid behavior — not prevented | Low impact; chain still advances |
| Selfish mining | Revenue advantage over honest miners | Not relevant without real PoW | N/A for testnet |

### Residual risks

- **PoW is disabled** (`validate_pow = false`). Without PoW, any node can produce blocks instantly. Chain security is entirely social on this testnet.
- Majority-hash-power attacks (51% attack) are not relevant until PoW is enabled.

---

## Attacker 3: RPC Attacker

**Profile**: An attacker who can reach the RPC port (8332 / 443 via nginx).

For correctly deployed nodes, 8332 is not internet-accessible. Only 443
(nginx/HTTPS) is public. However, a misconfigured node may expose 8332 directly.

### Attack surface

- HTTP endpoints (11 total): read-only GETs, `POST /submit_transaction`
- `Authorization: Bearer` header parsing
- JSON input parsing
- Rate limiter

### Attack vectors and impacts

| Vector | Impact | Mitigation | Residual risk |
|--------|--------|------------|---------------|
| Brute-force the RPC token | Full RPC access | Rate limiter (10 req/s per IP); token should be 32+ random bytes | Rate limit bypassed if behind nginx without `X-Forwarded-For` (KNOWN_LIMITATIONS §7) |
| Submit malformed transaction hex | Node crash / unexpected state | `hex::decode` + `deserialize_transaction` return errors gracefully | Verify no panic paths in transaction deserialization |
| Submit transaction with valid structure but invalid semantics | Mempool pollution | Full validation pipeline in `submit_transaction` | None — mempool validates before accepting |
| Resource exhaustion via rapid RPC polling | High CPU, connection exhaustion | Rate limiter at 10 req/s | Ineffective behind nginx without real-IP (KNOWN_LIMITATIONS §7) |
| Timing attack on Bearer token comparison | Token disclosure | **Unmitigated**: token comparison may not be constant-time | **Audit item**: verify constant-time comparison in `auth.rs` |
| CORS / SSRF via crafted RPC request | N/A for this API design | No CORS headers; no server-side URL fetching | Low |

### Mitigations implemented

- `auth_middleware` — Bearer token required when configured
- `rate_limit_middleware` — 10 req/s per IP, 1-hour ban on violation
- `axum` handles HTTP parsing; JSON deserialization errors return 400

### Residual risks

- **Token comparison timing oracle** — constant-time comparison not confirmed
- **Real-IP behind proxy** — rate limiting is ineffective when the node is behind nginx without `X-Forwarded-For` parsing (KNOWN_LIMITATIONS §7)
- **No HTTPS termination in the node** — RPC is plaintext on the wire unless nginx TLS is deployed

---

## Attacker 4: Wallet Attacker

**Profile**: An attacker with physical or filesystem access to the machine
running a wallet, or an attacker who obtains a stolen keystore file.

### Attack surface

- Keystore JSON file (encrypted private key)
- Seed phrase (if stored on disk)
- RPC API (to submit transactions)
- In-memory private key material

### Attack vectors and impacts

| Vector | Impact | Mitigation | Residual risk |
|--------|--------|------------|---------------|
| Steal keystore file, brute-force password | Private key extraction | Argon2id (m=64 MB, t=3, p=4) — ~100 ms per attempt; strong password required | Weak passwords (< 8 chars) fall quickly; `validate_password_strength` warns but does not block |
| Memory dump to extract private key | Private key in plaintext | `Zeroizing<Vec<u8>>` zeros private key on drop | Key may be in memory for the duration of a signing operation |
| Seed phrase stolen from storage | Full wallet recovery | Not an in-code issue — operational (write down, store offline) | Operational risk |
| Malicious mnemonic recovery (wrong phrase) | Funds sent to wrong address | BIP39 checksum validation rejects invalid mnemonics | None |
| Sign transaction without user confirmation | Funds sent | Not prevented — wallet is a library with no UI guard | Expected for library use; UI must add confirmation |
| Supply a malicious `recipient` address | Funds sent to wrong address | `validate_address` checks format; `Address::from_string` validates checksum | Social engineering — cannot be prevented in code |

### Residual risks

- **No hardware wallet support** — all key material lives in software
- **No transaction confirmation UX** — wallet is a library; any caller can sign and submit
- **Password strength is advisory** — `validate_password_strength` returns an error but callers can ignore it

---

## Attacker 5: Network-Level Spammer

**Profile**: An attacker who floods the network with valid transactions or
valid blocks to saturate resources.

### Attack surface

- Mempool (transaction submission)
- Block propagation
- P2P connection slots

### Attack vectors and impacts

| Vector | Impact | Mitigation | Residual risk |
|--------|--------|------------|---------------|
| Flood mempool with low-fee transactions | Mempool saturation; legitimate txs delayed | Mempool has a maximum size (transactions evicted by fee rate) | Verify fee eviction is correctly prioritized |
| Flood RPC with `POST /submit_transaction` | CPU exhaustion | RPC rate limiter at 10 req/s | Ineffective behind nginx (see Attacker 3) |
| Flood P2P with `Inv` / block announcement messages | CPU, bandwidth | Message size caps, peer scoring | Peer ban may not fire fast enough for burst floods |
| Sybil attack (many fake peers) | Fill connection table, isolate node | Not explicitly mitigated | **Mainnet blocker**: no connection diversity enforcement |

### Residual risks

- **Mempool fee eviction policy** — not fully verified under sustained load
- **No transaction relay fee policy** — any transaction ≥ 1 sat/byte is relayed; low-fee spam is cheap

---

## Attacker 6: Chain History Rewriter

**Profile**: An attacker (or coalition) with sufficient hash power to produce
a chain longer than the current canonical chain.

### Precondition

This attacker class only becomes relevant after PoW is enabled. On the
current testnet (`validate_pow = false`), **any node can produce an
arbitrarily long chain with zero computation**.

### Attack vectors and impacts (post-PoW)

| Vector | Impact | Mitigation | Residual risk |
|--------|--------|------------|---------------|
| 51% attack — mine longer chain, reorg history | Reverse confirmed transactions | Cumulative-work chain selection; any reorg triggers `rollback_block` | Requires > 50% of total hash power |
| Selfish mining | Revenue advantage; can trigger reorgs below 50% | Tie-break rule (lower hash wins) reduces orphan rate | Not fully mitigated; standard Bitcoin-class limitation |
| Long-range attack (rewrite chain from genesis) | Rewrite entire history | Checkpoints (not implemented) | **Mainnet blocker**: no checkpoint mechanism |

### Residual risks (pre-PoW, testnet)

- **Any node is a chain rewriter on testnet** — PoW is disabled, so any participant can produce a longer chain with zero computation
- This is acknowledged and accepted for testnet use

---

## Threat Model Summary

| Attacker | Testnet severity | Mainnet severity | Primary blocker |
|----------|-----------------|-----------------|-----------------|
| Malicious peer | Medium (DoS) | High | Fix bincode size caps; eclipse protection |
| Malicious miner | Low (PoW off) | Critical | Enable PoW (Phase 13A-3) |
| RPC attacker | Low (token required) | Medium | Constant-time token comparison; real-IP behind proxy |
| Wallet attacker | Low (offline key) | High | Hardware wallet support; audit Argon2id params |
| Network spammer | Low | Medium | Fee eviction policy; connection limits |
| Chain rewriter | N/A (PoW off) | Critical | Enable PoW; checkpoints |

---

## Properties This System Does NOT Guarantee

1. **Anonymity/privacy** — address reuse is expected; no CoinJoin, mixing, or stealth addresses
2. **Censorship resistance** — a miner can choose which transactions to include
3. **Finality** — there are no checkpoints; any confirmed transaction can theoretically be reversed by a sufficiently powerful reorg
4. **Protection against a compromised host** — if the OS is compromised, private keys can be extracted regardless of software controls
