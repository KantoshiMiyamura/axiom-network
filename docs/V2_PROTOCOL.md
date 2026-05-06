# Axiom v2 — Protocol Specification (work-in-progress)

> **Status:** This document is the authoritative scope for `v2-dev`. Nothing
> here is wired into the runtime yet — the matching code skeletons under
> `crates/*/src/*_v2*` and `crates/axiom-node/src/network/p2p_v2/` are
> compile-only stubs. Behaviour described below is *intended*, not *active*.
>
> The `master` branch keeps shipping v1 (`v1.0.1-testnet.x`) unchanged.

---

## 1. Goals

v2 is a deliberate, breaking iteration of the Axiom protocol. The aim is to
raise the cryptographic floor and tighten replay/identity guarantees while
keeping the user-visible model (Bitcoin-style UTXO chain, ML-DSA signatures
on every transaction, manual peering) identical. Concretely:

- **Post-quantum P2P transport.** Replace the X25519 + ChaCha20-Poly1305
  handshake with an X25519+ML-KEM hybrid, retaining ChaCha20-Poly1305 as the
  AEAD. A handshake survives only if both classical and post-quantum
  components agree, so a future break in either does not unmask traffic.
- **Hybrid signature verification on the node-identity layer.** Node
  handshake authentication adds Ed25519 alongside the existing ML-DSA
  fingerprint so an implementation bug in one library does not let an
  adversary forge node identity. **Transaction signing stays ML-DSA-87 only**
  — adding Ed25519 to consensus-level signature verification is out of scope
  for v2.
- **Replay protection at validation time.** The existing `tx.nonce: u64`
  field becomes a consensus-enforced replay barrier per `(payer_address,
  nonce)` pair, mirroring the Ethereum semantics already implied by the
  field's presence.
- **Wallet key rotation.** A wallet can mint a new ML-DSA-87 keypair and
  publish a `RotationRecord` linking the old address to the new one without
  dragging private keys through the chain. UTXOs sent to the old address
  remain spendable by the original key indefinitely.
- **Auto port-forward.** UPnP/IGD discovery on node startup, with a
  manual-instructions fallback when no IGD-capable router responds.

---

## 2. Breaking changes vs v1

| Surface | v1 (master) | v2 (v2-dev) |
|---|---|---|
| Testnet network identifier | `axiom-test-1` | `axiom-test-v2` |
| Handshake transport | X25519 → ChaCha20-Poly1305 | X25519+ML-KEM hybrid → ChaCha20-Poly1305 |
| Node identity proof in handshake | ML-DSA-87 fingerprint | ML-DSA-87 + Ed25519 (both must verify) |
| Transaction `nonce` field | present, not enforced | enforced per `(payer_address, nonce)` |
| Transaction envelope version | `Transaction { ... }` | `Transaction { ..., v2_extension: Option<TransactionV2Extension> }` |
| Wallet identities | one keypair per wallet | original keypair + zero or more rotation records |
| `axiom-mainnet-1` / `axiom-dev-1` | unchanged | unchanged |

A v2 node and a v1 node refuse each other at the version-message exchange
already (chain-id mismatch); none of the protocol changes above require a
separate compatibility shim.

---

## 3. Network identifier

`Network::Test.chain_id() == "axiom-test-v2"`. Bumping the literal makes the
domain-separated transaction signing hash on v2 disjoint from v1's, so a v2
signed transaction cannot be replayed on v1 even if the wire bytes were
forwarded by a malicious peer. Validation at any v1 node will fail on the
domain tag mismatch before any state is touched.

`axiom-mainnet-1` and `axiom-dev-1` are intentionally not modified on v2-dev.
Mainnet has not launched and v2 will inherit the chain id at launch; the dev
network is shared tooling.

---

## 4. P2P v2

Code skeleton: [`crates/axiom-node/src/network/p2p_v2/`](../crates/axiom-node/src/network/p2p_v2/).

### 4.1 Handshake

Two messages, no version negotiation — v2 nodes only speak v2.

```
INITIATOR → RESPONDER: HelloV2 {
    classical_pk: x25519::PublicKey,        // 32 bytes
    pq_ciphertext: MlKemCiphertext,         // ML-KEM-768 ciphertext encapsulated to responder's static key
    initiator_identity: NodeIdentityProof { // see §4.3
        ml_dsa_pubkey: MlDsaPublicKey,
        ed25519_pubkey: Ed25519PublicKey,
        ml_dsa_signature: MlDsaSignature,   // signs (transcript_hash || nonce)
        ed25519_signature: Ed25519Signature,
    },
    nonce_initiator: [u8; 32],              // CSPRNG, fresh per attempt
}

RESPONDER → INITIATOR: HelloAckV2 {
    classical_pk: x25519::PublicKey,
    pq_ciphertext: MlKemCiphertext,         // encapsulated to initiator's ephemeral key (this round)
    responder_identity: NodeIdentityProof,
    nonce_responder: [u8; 32],
}
```

The transcript hash is `SHA256(b"axiom-p2p-v2/transcript" || HelloV2_bytes ||
HelloAckV2_bytes_without_responder_identity)` — both peers compute it, both
peers must produce a matching identity signature over it.

### 4.2 Session-key derivation

```
classical_secret  = x25519(self_priv, peer_classical_pk)        // 32 bytes
pq_secret         = MlKem768::decapsulate(self_priv, peer_pq_ciphertext)  // 32 bytes

session_seed      = HKDF-SHA256(
    salt = transcript_hash,
    ikm  = classical_secret || pq_secret,
    info = b"axiom-p2p-v2/session"
)

(rx_key, tx_key)  = (HKDF_expand(session_seed, b"recv"), HKDF_expand(session_seed, b"send"))
```

`tx_key` and `rx_key` are 32-byte ChaCha20-Poly1305 keys. The role of each
key is determined by handshake direction so a single shared secret produces
two distinct AEAD keys.

### 4.3 Identity proof

A peer's identity is its ML-DSA-87 + Ed25519 keypair pair. Both signatures
must verify against the transcript hash for the handshake to succeed. The
Ed25519 component is *additive*: a future ML-DSA-87 implementation flaw does
not let an attacker forge node identity, and a future Ed25519 break does not
either.

The canonical 32-byte **peer ID** is a hash of the long-term identity keys:

```text
   PeerId = SHA-256-tagged(
       "axiom-id-v2",
       u32 LE ml_dsa_pk_len || ml_dsa_pubkey || ed25519_pubkey
   )
```

The length prefix on the ML-DSA pubkey eliminates concatenation boundary
ambiguity (same rationale as `axiom_crypto::transaction_signing_hash`).
The peer ID is **derived from the long-term keys only** — not from
ephemeral handshake material — so it is stable across reconnections and
can be cached in a peer address book. Implementation:
[`axiom_guard::fingerprint_v2`](../crates/axiom-guard/src/fingerprint_v2.rs).

### 4.4 Wire framing

Each post-handshake message is one length-prefixed frame:

```text
   [u32 LE  frame_body_len]
   [u64 LE  sequence_number]
   [N      ciphertext]
   [16     AEAD authentication tag]
```

`frame_body_len = 8 + ciphertext_len + 16` (excludes the 4-byte length
prefix). The receiver size-checks before allocating the read buffer so a
malicious peer cannot prompt a multi-gigabyte allocation purely from the
wire.

The AEAD is **XChaCha20-Poly1305** (24-byte nonce, 32-byte key, 16-byte
tag). Nonces are derived deterministically from the sequence number — the
seq number on the wire IS the nonce input, not a separate quantity:

```text
   nonce[0..8]  = sequence_number (LE)
   nonce[8..24] = 0
```

Each direction has its own 32-byte ChaCha key (`tx_key`, `rx_key`) from
the v2 handshake. Different keys per direction make the (key, nonce) pair
unique per encrypted message even though both sides start at seq = 0.

Ordering is **strict-monotonic**: the receiver rejects any frame whose
seq is not exactly the previous one + 1. TCP guarantees in-order
delivery, so the only way an out-of-order frame can land is an active
attacker reordering bytes — which we want to refuse. Any error from the
transport layer (AEAD failure, replay/reorder, oversized frame, IO
truncation) is fatal: the caller closes the connection. There is no
recovery, no retry, no partial state.

Cap: `MAX_FRAME_BODY_BYTES = 4_000_024` — matches the v1 4-MB block
relay limit plus the seq + tag overhead.

---

## 5. Transaction v2

Code skeleton: [`crates/axiom-protocol/src/transaction_v2.rs`](../crates/axiom-protocol/src/transaction_v2.rs).

### 5.1 Envelope

`Transaction` keeps every v1 field. v2 adds an optional extension:

```rust
pub struct Transaction {
    // …existing v1 fields…
    pub v2_extension: Option<TransactionV2Extension>,
}

pub struct TransactionV2Extension {
    pub payer_address: Address,        // for replay key (see §6)
    pub rotation_pointer: Option<RotationPointer>,
}
```

A v1 transaction has `v2_extension == None`. A v2 transaction populates the
field and serialises it after the existing payload, so wire-format readers
that don't know about the extension fail loudly on length-prefix mismatch
rather than silently truncate.

### 5.2 Signing

The signing hash on v2 is:

```
double_hash256(
    "axiom/tx/v2"  // domain tag bumped from v1's "axiom/tx/v1"
    || chain_id_bytes("axiom-test-v2")
    || serialize_transaction_unsigned(tx)
)
```

Bumping the domain tag ensures v1 and v2 signatures live in disjoint hash
spaces — no signature can be replayed across the boundary even if every
other byte happens to coincide.

### 5.3 Confidentiality

Confidential outputs (`ConfidentialTxOutput`, the v1 commitment scheme)
are unchanged in v2.

---

## 6. Nonce rules (replay protection)

`tx.nonce: u64` is a **consensus-enforced strict-next replay barrier**
keyed by the payer's pubkey hash. The rule was already implemented in
v1 ([`crates/axiom-node/src/validation.rs`](../crates/axiom-node/src/validation.rs)
lines 247–262); v2 inherits it unchanged and pins the behaviour with the
tests in
[`crates/axiom-node/tests/v2_nonce_replay_protection.rs`](../crates/axiom-node/tests/v2_nonce_replay_protection.rs).

### Rule

For every non-coinbase transaction:

```text
   tx.nonce  must equal  stored_nonce(payer) + 1
```

A node MUST reject any transaction that does not satisfy this equality.
Specifically:

- **duplicate** (`tx.nonce == stored_nonce`) → rejected.
- **lower** (`tx.nonce < stored_nonce + 1`) → rejected.
- **skipped** (`tx.nonce > stored_nonce + 1`) → rejected.

The error variant is `ValidationError::InvalidNonce { expected, actual }`
where `expected = stored_nonce + 1`.

### Payer attribution

The payer is the address whose key signed the transaction — concretely,
the holder of the **first** input's UTXO. v1 already enforces a
single-signer constraint at validation.rs:233–240: every input's pubkey
must hash to the same value as the first input's. This is what makes the
single per-payer nonce check sufficient — there is no way to mix inputs
from multiple keys and bypass any one address's nonce ledger.

### State

Per-address state lives in `axiom-storage::NonceTracker`, on the on-disk
LSM database. The stored value is the **last used nonce** for that
address — not "next expected", not "last used + 1". When a transaction
with `tx.nonce = N` is applied to a block, the apply path writes
exactly `N` into the tracker; the next valid transaction's nonce is
`N + 1`, which the wallet derives by reading the RPC value (= `N`) and
adding 1, and which the validator demands as `stored + 1`. Every
component agrees on the same arithmetic, and the on-wire `tx.nonce`
field equals the 1-indexed transaction number per address (1, 2, 3, …).

Storage is durable across restarts and reorg-safe: every non-coinbase
tx that lands in a block records a `NonceUndo { pubkey_hash,
prev_nonce }` so the storage layer can restore the pre-block value
when the block is rolled back. The reorg path is in
[`crates/axiom-node/src/reorg.rs`](../crates/axiom-node/src/reorg.rs).

> **History note (v2-dev only).** A pre-stage-6 version of
> `ChainState::apply_block` wrote `tx.nonce + 1` to the nonce tracker.
> Combined with the wallet's `rpc_value + 1` derivation and the
> validator's `stored + 1` requirement, that produced odd-only on-wire
> nonces (1, 3, 5, …). The closed loop was internally consistent — every
> sequential transaction was still accepted — but block explorers and
> per-account transaction-counters showed surprising values. The fix
> (one line in [`state.rs:215`](../crates/axiom-node/src/state.rs#L215))
> writes `tx.nonce` directly. Triage is preserved at
> [`crates/axiom-node/tests/v2_nonce_lifecycle_triage.rs`](../crates/axiom-node/tests/v2_nonce_lifecycle_triage.rs)
> as a regression test for the corrected behaviour.

### Replacement / pipelining: not in scope

Earlier drafts of this section described a `NONCE_WINDOW = 16`
permissive-window rule and a fee-uplift replacement policy. **Both are
removed.** The implemented rule is strict-next, no window, no
replacement. Mempool dedup follows from the validator's rule directly:
a duplicate-nonce transaction can never become valid against the same
chain state, so the mempool admits at most one pending transaction per
`(payer_address, nonce)` pair.

### Cross-network replay

Already prevented by the chain-id domain tag in §5.2 — a v2 signed
transaction cannot replay on v1, and vice versa. The strict-next rule
above defends against intra-network replay.

---

## 7. Key rotation

Implementation: [`crates/axiom-wallet/src/rotation_v2.rs`](../crates/axiom-wallet/src/rotation_v2.rs).
CLI: `axiom wallet rotate`.

A wallet can rotate its identity without burning the underlying funds:

1. The wallet generates a fresh ML-DSA-87 keypair `K_new`.
2. The wallet builds a `RotationRecord` signed by the old key:
   ```rust
   pub struct RotationRecord {
       pub from_address: Address,
       pub to_address: Address,
       pub predecessor_pubkey: PublicKey,      // K_old (the signer)
       pub successor_pubkey: PublicKey,        // K_new (announced)
       pub effective_height: u32,              // advisory; not consensus-enforced
       pub signature: Signature,               // ML-DSA-87(K_old, signing_hash)
   }
   ```

   The signing hash is `tagged_hash("axiom-rotation-v2", body)` where the
   body is length-prefixed in every region:

   ```text
       u32 LE from_addr_len   || from_address.pubkey_hash bytes
       u32 LE to_addr_len     || to_address.pubkey_hash bytes
       u32 LE predecessor_len || predecessor_pubkey bytes
       u32 LE successor_len   || successor_pubkey bytes
       u32 LE effective_height
   ```

   Length prefixes rule out boundary-collision attacks of the
   `("ab","cd") == ("a","bcd")` shape.

3. **The record stays local** to the wallet. Stage 7 does not put the
   record on chain — there is no new tx type, no `v2_extension`
   threading, and no consensus rule. The record is persisted alongside
   the keystore as a JSON `linkage` file.

4. UTXOs sent to `from_address` remain spendable by `K_old`
   indefinitely. The chain has no concept of "this address can no
   longer sign"; rotation is a wallet-side identity statement, not a
   UTXO-level invalidation.

5. Multiple rotations form a chain (`A → B → C → …`) tracked by
   `Linkage`. `Linkage::apply_record` verifies a candidate record
   against the current tip:

   - empty linkage → `from_address` is the wallet's seed identity;
   - non-empty → `from_address == linkage.last().to_address`;
   - `effective_height` strictly greater than the previous record's;
   - both pubkey hashes match their respective addresses;
   - ML-DSA-87 signature verifies against `predecessor_pubkey`.

   Records are appended only after every check passes.

6. The `Linkage::to_json_string` / `from_json_str` helpers persist the
   chain to a JSON file kept next to the keystore. Loading
   re-verifies every record on the way in, so a tampered file is
   refused even if the bit-flip lands on a hex-encoded signature byte.

CLI walkthrough (`axiom wallet rotate`):

  - Reads the existing keystore at the platform default path (override
    with `--wallet`).
  - Prompts for the old keystore password and unlocks it.
  - Generates a fresh ML-DSA-87 keypair.
  - Builds and verifies a `RotationRecord`.
  - Prompts for a new password, encrypts the new keystore, writes it
    to `<wallet>.rotated.<timestamp>.json` (override with `--out`).
  - Updates the linkage file at `<wallet>.linkage.json` (override with
    `--linkage`).
  - Prints both addresses and the file paths. The old keystore is
    preserved untouched.

---

## 8. Crypto roadmap

Code skeleton: [`crates/axiom-crypto/src/kem_v2.rs`](../crates/axiom-crypto/src/kem_v2.rs).

| Stage | Component | Status on `v2-dev` |
|---|---|---|
| 1 | Skeleton + spec (this document) | done |
| 2 | ML-KEM-768 wrapper (`generate_keypair`, `encapsulate`, `decapsulate` over RustCrypto `ml-kem` 0.2; round-trip + tamper + size + length-validation tests) | done |
| 3 | Hybrid handshake — transcript hash, HelloV2/HelloAckV2 wire format, hybrid (X25519+ML-KEM) key agreement, HKDF-SHA256 directional session keys, ML-DSA+Ed25519 dual identity proof; 10 round-trip / tamper / downgrade-binding tests | done |
| 4 | Encrypted transport — XChaCha20-Poly1305 framing with on-wire seq + AEAD; `EncryptedConnectionV2` over any `AsyncRead+AsyncWrite`; strict-monotonic replay rejection; 4-MB frame cap; 11 round-trip / tamper / replay / oversized / truncated / wrong-key tests | done |
| 5 | Hybrid node-identity (`axiom_guard::fingerprint_v2`) — `PeerId` = SHA-256-tagged hash of (ml_dsa_pk \|\| ed25519_pk) with length-prefix anti-collision; `compute_peer_id` and `verify_announced_peer_id`; 12 tests covering determinism, key substitution, single-bit sensitivity, length-prefix anti-collision, cross-session stability | done |
| 6 | Replay-rule enforcement — strict-next per-address nonce already enforced at validation.rs:247–262 with reorg-safe `NonceUndo` storage; 8 verification tests in `v2_nonce_replay_protection.rs` cover first-tx, duplicate, lower, skipped, independent-address, reorg-undo, and storage persistence; spec §6 corrected to remove `NONCE_WINDOW=16` window. End-to-end nonce off-by-one diagnosed (apply wrote `tx.nonce + 1`) and fixed in `f141b3f` so on-chain nonces are now consecutive | done |
| 7 | Wallet rotation — `axiom-wallet::rotation_v2` real impl: `build_rotation_record` (ML-DSA-87 over length-prefixed body, domain `axiom-rotation-v2`); `verify_rotation_record` (address↔key binding both ends, linkage-tip + effective-height checks, signature verify); `Linkage::apply_record` and JSON persistence with re-verification on load. `axiom wallet rotate` CLI command. 12 tests covering happy path, wrong-old-key, tampered signature/pubkey, A→B→C chain, height monotonicity, JSON round-trip, tamper-on-load rejection, and old-key-still-spends invariant | done |
| 8 | UPnP — `axiom-node::network::upnp` over RustCrypto-style `igd-next` 0.17 (aio_tokio): `try_map` / `try_unmap` / `spawn_renewal_task` / `fallback_instructions`; non-blocking startup attempt (timeout-bounded SSDP), best-effort lease renewal; `--no-upnp` CLI flag; new RPC endpoint `/network/external_address`; `axiom status` displays the external mapping in the [NETWORK] section. 6 tests covering address formatting (v4/v6), fallback message content, error formatting, local-IP detection panic-safety, and lease-renewal math. Failure paths are non-fatal and produce manual port-forward instructions on stderr | **done** |
| 9 | Integration tests + reference vectors | not started |
| 10 | v2 release branch off `v2-dev` | future |

Each stage will be a separate signed commit on `v2-dev` with its own design
note. None of them ship in a release until stage 10.

---

## 9. Out of scope for v2

The following items were considered and explicitly **not** included so the
v2 release stays achievable:

- **Hybrid signatures on transactions.** Adding Ed25519 alongside ML-DSA at
  consensus level changes the signature-verification surface for every node
  and every block ever produced. The benefit is marginal (the existing
  ML-DSA-87 already provides NIST Category 5 PQ security); the engineering
  and audit cost is large. v2 keeps transactions ML-DSA-87 only.
- **Stateless light-client proofs.** Future work, not a v2 deliverable.
- **Account abstraction / programmable transactions.** Out of scope.
- **Sharding, parallel execution, alt-VMs.** Out of scope.

---

## 10. Living document

This file is the source of truth for what v2 means. When a stage from §8
lands, its code commit references this section and updates the table.
When a stage's design changes, this file changes first.
