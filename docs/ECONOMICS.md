# Economics

Copyright (c) 2026 Kantoshi Miyamura

## Monetary Philosophy

Axiom Network implements a fixed-supply monetary system with predictable issuance.

The supply schedule is deterministic and cannot be changed without hard fork consensus.

## Supply Model

- Maximum supply: 21,000,000 AXM
- Initial block reward: 50 AXM
- Halving interval: 210,000 blocks (~4 years at 10 min/block)
- Final halving: Block 6,930,000 (~132 years)
- Smallest unit: 1 satoshi = 0.00000001 AXM

Supply schedule:

| Blocks | Reward | Period Supply | Cumulative Supply |
|--------|--------|---------------|-------------------|
| 0 - 209,999 | 50 AXM | 10,500,000 | 10,500,000 |
| 210,000 - 419,999 | 25 AXM | 5,250,000 | 15,750,000 |
| 420,000 - 629,999 | 12.5 AXM | 2,625,000 | 18,375,000 |
| 630,000 - 839,999 | 6.25 AXM | 1,312,500 | 19,687,500 |
| ... | ... | ... | ... |
| 6,930,000+ | 0 AXM | 0 | 21,000,000 |

## Issuance Mechanism

New AXM is issued only through block rewards (coinbase transactions).

No pre-mine.
No ICO.
No foundation allocation.
No developer fund.
No treasury.

## Fee Model

Transaction fees are voluntary but economically necessary.

Fee = Sum(inputs) - Sum(outputs)

Fees are collected by block producer (miner).

Minimum relay fee: 1 satoshi per byte (mempool policy, not consensus rule).

## Fee Market

Mempool is bounded (300 MB default).

When mempool is full, lowest fee-rate transactions are evicted.

Users compete for block space through fees.

No fee burning.
No fee redistribution.
No protocol-level fee rules beyond non-negativity.

## Anti-Spam Economics

Dust limit: 546 satoshis per output (mempool policy).

Rationale: Prevent UTXO set bloat with economically unspendable outputs.

Minimum transaction size: 1 input + 1 output = ~200 bytes.
Minimum relay fee: 200 satoshis.

Cost to spam network: Proportional to block space consumed.

## Security Budget

Network security is funded by:
1. Block rewards (decreasing over time)
2. Transaction fees (increasing over time)

Long-term security assumption: Fee market develops as block rewards diminish.

Security budget = Block reward + Transaction fees per block.

Target security budget: Sufficient to make 51% attack economically irrational.

## Economic Assumptions

1. Rational miners maximize revenue (block reward + fees)
2. Users pay fees to ensure transaction inclusion
3. Fee market clears through mempool competition
4. Long-term: Transaction volume grows to sustain security budget
5. No external subsidy required

## Inflation Schedule

| Year | Annual Inflation | Circulating Supply |
|------|------------------|-------------------|
| 1 | ~50% | ~2.6M AXM |
| 2 | ~25% | ~5.2M AXM |
| 4 | ~12.5% | ~10.5M AXM |
| 8 | ~6.25% | ~15.75M AXM |
| 12 | ~3.1% | ~18.375M AXM |
| 16 | ~1.5% | ~19.6875M AXM |
| 20+ | <1% | Approaching 21M |

Inflation rate decreases geometrically.

Terminal inflation: 0% (after all halvings complete).

## Monetary Policy Invariants

1. Total supply never exceeds 21,000,000 AXM
2. Block reward halves every 210,000 blocks
3. No inflation after block 6,930,000
4. No negative fees (consensus rule)
5. No money creation outside coinbase transactions

These invariants are enforced by consensus rules and cannot be violated without hard fork.

## Economic Security Model

Attack cost = Cost to acquire 51% of hash rate.

Defense: Honest miners earn block rewards + fees.

Attack incentive: Ability to double-spend or censor transactions.

Economic equilibrium: Attack cost > potential gain from attack.

Assumption: Majority of hash rate is economically rational and prefers long-term network value over short-term attack profit.

## Comparison to Fiat Systems

- No central bank
- No monetary policy discretion
- No quantitative easing
- No interest rate manipulation
- No bailouts
- No capital controls
- No inflation targeting

Monetary policy is algorithmic and deterministic.

## Comparison to Other Cryptocurrencies

- No pre-mine (unlike many altcoins)
- No ICO (unlike Ethereum)
- No foundation tax (unlike Zcash)
- No developer fund (unlike Bitcoin Cash)
- No treasury (unlike Decred)
- No staking rewards (unlike Ethereum 2.0)

Pure proof-of-work with miner-only rewards.
