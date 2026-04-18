# Consensus Rules

Copyright (c) 2026 Kantoshi Miyamura

## Purpose

Define deterministic consensus rules for Axiom Network.

Every node must validate blocks identically to maintain consensus.

## Block Validation Rules

### 1. Block Structure

- Block must contain at least one transaction
- First transaction must be coinbase
- Only first transaction can be coinbase
- All transactions must have valid structure

### 2. Previous Hash Linkage

- Block's prev_block_hash must match current chain tip
- Genesis block has prev_block_hash = Hash256::zero()
- Blocks form an immutable chain

### 3. Merkle Root Correctness

- Merkle root must be computed from all transactions
- Computation: hash of concatenated transaction hashes
- Merkle root must match header value
- Any transaction modification invalidates merkle root

### 4. Transaction Ordering

- Coinbase must be first transaction
- Non-coinbase transactions follow
- Order within block is preserved

### 5. Coinbase Validation

- Coinbase must encode block height in nonce field
- Coinbase value must not exceed block reward
- Block reward follows halving schedule
- No inputs allowed in coinbase

### 6. Block Reward Calculation

```
Initial reward: 50 AXM (5,000,000,000 satoshis)
Halving interval: 210,000 blocks
Reward = initial_reward >> (height / halving_interval)
Maximum halvings: 64
After 64 halvings: reward = 0
```

### 7. No Duplicate Transactions

- Each transaction in block must be unique
- Uniqueness determined by transaction hash
- Duplicate transactions rejected

### 8. Block Size Limits

- Maximum block size: 1 MB (1,000,000 bytes)
- Includes header and all transactions
- Blocks exceeding limit rejected

### 9. Transaction Count Limits

- Maximum transactions per block: 10,000
- Includes coinbase
- Blocks exceeding limit rejected

### 10. Transaction Size Limits

- Maximum transaction size: 100 KB (100,000 bytes)
- Applies to each transaction individually
- Transactions exceeding limit rejected

### 11. Output Value Validation

- All output values must be valid Amount
- No overflow allowed
- Checked arithmetic enforced

## Transaction Validation Rules

### 1. Structure Validation

- Must have inputs (except coinbase)
- Must have outputs
- No dust outputs (< 546 satoshis)
- Valid serialization

### 2. Nonce Validation

- Nonce must equal current nonce for sender
- Nonces strictly increase
- Prevents replay attacks
- Nonce stored per public key hash

### 3. UTXO Validation

- All inputs must reference existing UTXOs
- UTXOs must be unspent
- Input values must be valid

### 4. Signature Validation

- All inputs must have valid signatures
- Signature verifies against input public key
- Message: double SHA-256 of transaction
- Ed25519 signature scheme

### 5. Value Validation

- Sum of inputs >= sum of outputs
- Difference is transaction fee
- No negative values
- Checked arithmetic

### 6. Fee Validation

- Fee rate >= minimum (1 satoshi/byte)
- Fee = input_value - output_value
- Fee rate = fee / transaction_size

## State Transition Rules

### 1. UTXO Updates

- Spent inputs removed from UTXO set
- New outputs added to UTXO set
- Updates are atomic
- No partial state

### 2. Nonce Updates

- Nonce incremented after transaction
- New nonce = old nonce + 1
- Stored persistently
- Per public key hash

### 3. Chain Metadata Updates

- Best block hash updated
- Best height updated
- Updates are atomic
- Consistent with UTXO state

### 4. Atomicity

- All state changes in single batch
- Either all succeed or all fail
- No partial block application
- Database transaction guarantees

## Chain Selection Rules

### Current Rule

Longest chain (highest block height).

### Tie Breaking

- If two chains have same height, first seen wins
- No reorganization for equal-height chains
- Deterministic within single node

### Future

- Cumulative difficulty (when PoW implemented)
- Heaviest chain wins
- Difficulty-based tie breaking

## Determinism Guarantees

### 1. Serialization

- All structures use deterministic serialization
- Bincode with fixed byte order
- No floating point
- No undefined behavior

### 2. Hash Functions

- SHA-256 (double hash for commitments)
- Deterministic output
- No randomness
- Consistent across platforms

### 3. Arithmetic

- All arithmetic is checked
- Overflow/underflow rejected
- No wrapping behavior
- Explicit error handling

### 4. Timestamps

- Timestamps not validated (development mode)
- Future: timestamp validation rules
- No consensus dependency on local time

## Replay Protection

### 1. Nonce-Based

- Each transaction has unique nonce
- Nonces strictly increase
- Cannot replay old transactions
- Per-account nonce tracking

### 2. UTXO-Based

- Each UTXO can only be spent once
- Spent UTXOs removed from set
- Cannot double-spend
- Explicit UTXO references

### 3. Block-Based

- Each block references previous block
- Cannot replay blocks
- Chain linkage prevents reordering
- Block hash uniqueness

## Validation Sequence

### Block Validation Order

1. Check block structure
2. Validate previous hash
3. Validate merkle root
4. Validate coinbase position
5. Validate coinbase reward
6. Validate coinbase height
7. Check duplicate transactions
8. Check block size
9. Check transaction count
10. Check transaction sizes
11. Validate output values

### Transaction Validation Order (Mempool)

1. Reject coinbase
2. Check inputs exist
3. Check outputs exist
4. Check dust outputs
5. Validate nonce
6. Validate UTXO existence
7. Validate input values
8. Validate output values
9. Validate fee rate
10. Validate signatures

### State Application Order

1. Validate block (consensus rules)
2. Store block
3. Store transactions
4. Remove spent UTXOs
5. Update nonces
6. Add new UTXOs
7. Update chain metadata
8. Commit atomically

## Rejection Behavior

### Invalid Block

- Block rejected immediately
- No state changes
- Error logged
- Peer not banned (development mode)

### Invalid Transaction

- Transaction rejected
- Not added to mempool
- Error logged
- No propagation

### Duplicate Block

- Silently ignored
- No error
- No state changes
- Seen tracking prevents reprocessing

### Duplicate Transaction

- Rejected from mempool
- Already confirmed: ignored
- Not propagated

## Current Limitations

- No proof-of-work validation (development mode)
- No timestamp validation
- No difficulty adjustment
- No reorganization support
- No fork choice beyond longest chain
- No peer banning for invalid blocks

## Future Enhancements

- Proof-of-work validation
- Difficulty adjustment algorithm
- Timestamp validation rules
- Chain reorganization support
- Cumulative difficulty tracking
- Peer reputation system
- DoS protection

