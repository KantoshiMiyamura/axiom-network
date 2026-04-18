# Protocol Specification

Copyright (c) 2026 Kantoshi Miyamura

## Transaction Structure

```
Transaction {
    version: u32,
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    locktime: u32,
}

TxInput {
    prev_tx_hash: [u8; 32],
    prev_output_index: u32,
    signature: [u8; 64],
    pubkey: [u8; 32],
}

TxOutput {
    value: u64,  // satoshis
    script_pubkey: Vec<u8>,
}
```

## Transaction Validation Rules

1. All inputs must reference existing unspent outputs
2. Sum of input values >= sum of output values
3. All signatures must be valid
4. No duplicate inputs within transaction
5. No negative output values
6. No zero output values (dust limit: 546 satoshis)
7. Transaction size <= 100 KB
8. Locktime must be <= current block height (if set)

## Transaction Serialization

Deterministic binary serialization:

```
version (4 bytes, little-endian)
input_count (varint)
for each input:
    prev_tx_hash (32 bytes)
    prev_output_index (4 bytes, little-endian)
    signature (64 bytes)
    pubkey (32 bytes)
output_count (varint)
for each output:
    value (8 bytes, little-endian)
    script_length (varint)
    script_pubkey (variable)
locktime (4 bytes, little-endian)
```

## Transaction ID

Transaction ID = SHA-256(SHA-256(serialized_transaction))

## Block Structure

```
Block {
    header: BlockHeader,
    transactions: Vec<Transaction>,
}

BlockHeader {
    version: u32,
    prev_block_hash: [u8; 32],
    merkle_root: [u8; 32],
    timestamp: u32,
    difficulty_target: u32,
    nonce: u32,
}
```

## Block Validation Rules

1. Block header hash < difficulty target (proof-of-work)
2. Merkle root matches transaction set
3. Timestamp > median of last 11 blocks
4. Timestamp < current time + 2 hours
5. All transactions valid
6. First transaction is coinbase
7. Coinbase value <= block reward + fees
8. Block size <= 1 MB
9. No duplicate transactions

## Block Serialization

```
version (4 bytes, little-endian)
prev_block_hash (32 bytes)
merkle_root (32 bytes)
timestamp (4 bytes, little-endian)
difficulty_target (4 bytes, little-endian)
nonce (4 bytes, little-endian)
transaction_count (varint)
for each transaction:
    (serialized transaction)
```

## Block ID

Block ID = SHA-256(SHA-256(serialized_block_header))

## Proof-of-Work

Target difficulty encoded as compact representation (similar to Bitcoin).

Valid block: SHA-256(SHA-256(block_header)) < target

## Difficulty Adjustment

LWMA-3 (Linearly Weighted Moving Average) retargeting:

- Adjustment: Every block (`LWMA_WINDOW = 60` block window)
- Target block time: 30 seconds (`TARGET_BLOCK_TIME = 30 s`)
- Each block's solvetime is weighted by its position in the window (recent blocks weighted more)
- Retarget formula: `new_target = base_target × (weighted_sum / k)` where `k = N(N+1)/2 × T`
- Clamp: ratio clamped to [0.25, 4.0] — no more than 4× change per window
- Max target: `0x1e00ffff` — target can never exceed this value
- Compact format: Bitcoin's nBits encoding (`(size_byte << 24) | 24_bit_mantissa`)
- Non-retarget blocks: `difficulty_target` is carried forward unchanged from parent
- Consensus rule: every block's `difficulty_target` field must exactly equal the
  retarget-computed value; any deviation causes block rejection

Implementation: `axiom_consensus::calculate_new_target` and
`axiom_node::ChainState::get_next_difficulty_target_from_parent`.

## Coinbase Transaction

First transaction in block.

```
CoinbaseTransaction {
    version: u32,
    inputs: [CoinbaseInput],
    outputs: Vec<TxOutput>,
    locktime: u32,
}

CoinbaseInput {
    prev_tx_hash: [0; 32],  // null hash
    prev_output_index: 0xFFFFFFFF,
    signature: arbitrary_data,  // block height + extra nonce
    pubkey: [0; 32],  // null pubkey
}
```

## Block Reward Schedule

- Initial reward: 50 AXM
- Halving interval: 210,000 blocks (~4 years)
- Total supply: 21,000,000 AXM
- Smallest unit: 1 satoshi = 0.00000001 AXM

## Address Format

Address = Base58Check(version_byte || pubkey_hash || checksum)

- version_byte: 0x00 (mainnet), 0x6F (testnet)
- pubkey_hash: RIPEMD-160(SHA-256(pubkey))
- checksum: First 4 bytes of SHA-256(SHA-256(version_byte || pubkey_hash))

## Script System

Minimal script system for locking outputs:

- OP_DUP: Duplicate top stack item
- OP_HASH160: RIPEMD-160(SHA-256(x))
- OP_EQUALVERIFY: Verify equality, fail if not equal
- OP_CHECKSIG: Verify signature

Standard pay-to-pubkey-hash script:
```
scriptPubKey: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
scriptSig: <signature> <pubkey>
```

## Signature Algorithm

- Curve: Ed25519
- Message: SHA-256(SHA-256(transaction_without_signatures))
- Signature: 64 bytes (R || s)
- Public key: 32 bytes (compressed point)

## Replay Protection

Transactions are unique by input set.
Each UTXO can only be spent once.
No explicit replay protection needed beyond UTXO uniqueness.

## Fork Choice Rule

Longest chain by cumulative proof-of-work.

In case of tie: First seen.

## Mempool Rules

- Maximum mempool size: 300 MB
- Minimum fee rate: 1 satoshi per byte
- Eviction policy: Lowest fee rate first
- No replace-by-fee
- No child-pays-for-parent

## Network Protocol

Protocol version: 1
Maximum message size: 10 MB

Message types:
- Version: Protocol version, network, best height
- VerAck: Handshake acknowledgment
- Ping/Pong: Keepalive
- GetTip: Request chain tip
- Tip: Chain tip response (best hash, best height)
- GetBlock: Request block by hash
- Block: Block data
- Tx: Transaction data

Message format:
- Header: [type: u8][length: u32]
- Payload: [serialized data]
- Serialization: bincode (deterministic)

Handshake flow:
1. Initiator sends Version
2. Responder validates version (protocol, network)
3. Responder sends VerAck
4. Initiator sends VerAck
5. Both peers enter Ready state

Transaction propagation:
- Received transactions validated before mempool admission
- Duplicate transactions rejected
- Invalid transactions rejected silently
- No rebroadcast to originating peer

Block propagation:
- Received blocks validated before application
- Duplicate blocks rejected
- Invalid blocks rejected silently
- Mempool updated after block acceptance

Sync primitives:
- GetTip/Tip: Discover remote chain state
- GetBlock/Block: Request specific blocks by hash
- Sequential block application required

Current limitations:
- No peer discovery
- No automatic synchronization
- No inv/getdata pattern
- No DoS protection

## Genesis Block

Network: dev (development)
Height: 0
Timestamp: 0
Difficulty: 0 (no mining)
Coinbase: 50 AXM to unspendable address (Hash256::zero())

Genesis hash is deterministic and immutable per network.
Genesis must be initialized before any other blocks.
