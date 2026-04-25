// Copyright (c) 2026 Kantoshi Miyamura

//! Consensus invariants — the hard mathematical rules every node must agree on.
//!
//! This module is **pure**. It contains no I/O, no system-time reads, no RNG,
//! and no floating-point arithmetic. Every value equation is enforced via
//! `checked_*` on fixed-width integers (satoshi-denominated `Amount`, u64
//! primitives for supply totals). A violation is a hard reject — never a
//! log-only warning. The invariants below are the contract between wallet,
//! mempool, block validator, and the chain-state transition function.
//!
//! ## The four invariants
//!
//! 1. **Value conservation** (per-transaction):
//!    `inputs >= outputs + burn`, and `fee = inputs - outputs - burn` must be
//!    a non-negative integer. A transaction that tries to spend more than it
//!    brings in, or whose arithmetic would require a negative fee, is rejected.
//!
//! 2. **Fee non-negativity**: `fee >= 0`. Encoded in the `u64` return of
//!    [`check_value_conservation`] — the function cannot return a negative
//!    value because `checked_sub` fails first.
//!
//! 3. **Supply transition** (per-block): `new_supply = prev_supply - burn + reward`
//!    with full checked arithmetic. Overflow past `Amount::MAX` → reject.
//!    Underflow (burn > prev_supply) → reject.
//!
//! 4. **Coinbase bound** (per-block): `coinbase_out <= reward + total_fees`.
//!    Equivalent to "the miner cannot mint coins beyond the schedule plus
//!    what fees actually paid." Overclaim → reject.

use axiom_primitives::Amount;

/// A violated invariant. Every variant is a hard consensus reject — no
/// variant maps to a log-only path. Callers must propagate as error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvariantError {
    /// `outputs + burn` would exceed `inputs`. Transaction prints value.
    NegativeFee {
        inputs_sat: u64,
        outputs_sat: u64,
        burn_sat: u64,
    },
    /// `outputs + burn` overflowed u64 before comparison with inputs.
    OutputsPlusBurnOverflow { outputs_sat: u64, burn_sat: u64 },
    /// `prev_supply - burn` underflowed (you cannot burn more than exists).
    SupplyUnderflow { prev_sat: u64, burn_sat: u64 },
    /// `prev_supply - burn + reward` exceeded `Amount::MAX`.
    SupplyOverflow {
        prev_sat: u64,
        burn_sat: u64,
        reward_sat: u64,
    },
    /// Coinbase claimed more than `reward + fees` — mint of thin-air coins.
    CoinbaseOverclaim { claimed_sat: u64, allowed_sat: u64 },
    /// `reward + fees` overflowed u64 before comparison with coinbase claim.
    RewardPlusFeesOverflow { reward_sat: u64, fees_sat: u64 },
}

impl std::fmt::Display for InvariantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvariantError::NegativeFee {
                inputs_sat,
                outputs_sat,
                burn_sat,
            } => write!(
                f,
                "value conservation violated: inputs ({}) < outputs ({}) + burn ({})",
                inputs_sat, outputs_sat, burn_sat
            ),
            InvariantError::OutputsPlusBurnOverflow {
                outputs_sat,
                burn_sat,
            } => write!(
                f,
                "outputs ({}) + burn ({}) overflowed u64",
                outputs_sat, burn_sat
            ),
            InvariantError::SupplyUnderflow { prev_sat, burn_sat } => write!(
                f,
                "supply underflow: burn ({}) > prev_supply ({})",
                burn_sat, prev_sat
            ),
            InvariantError::SupplyOverflow {
                prev_sat,
                burn_sat,
                reward_sat,
            } => write!(
                f,
                "supply overflow: prev ({}) - burn ({}) + reward ({}) exceeds max",
                prev_sat, burn_sat, reward_sat
            ),
            InvariantError::CoinbaseOverclaim {
                claimed_sat,
                allowed_sat,
            } => write!(
                f,
                "coinbase overclaim: claimed {} > allowed {} (reward + fees)",
                claimed_sat, allowed_sat
            ),
            InvariantError::RewardPlusFeesOverflow {
                reward_sat,
                fees_sat,
            } => write!(
                f,
                "reward ({}) + fees ({}) overflowed u64",
                reward_sat, fees_sat
            ),
        }
    }
}

impl std::error::Error for InvariantError {}

impl From<InvariantError> for crate::Error {
    fn from(e: InvariantError) -> crate::Error {
        crate::Error::InvariantViolation(e.to_string())
    }
}

// ──────────────────────────────────────────────────────────────────────────
//  Invariant 1 + 2: value conservation and non-negative fee.
// ──────────────────────────────────────────────────────────────────────────

/// Enforce `inputs >= outputs + burn` and return `fee = inputs - outputs - burn`.
///
/// All three arguments are satoshi-denominated `Amount`s (so each is already
/// bounded by `Amount::MAX`). The sum `outputs + burn` is nonetheless computed
/// with `checked_add` on the underlying `u64` so that no sum step can silently
/// wrap, even if somebody constructs an `Amount` outside the normal factory.
///
/// The returned fee is a raw `u64` of satoshis (not an `Amount`) — fees
/// themselves are not required to fit under `Amount::MAX`, but as a sanity
/// check they cannot exceed `inputs`, which was constrained at construction.
pub fn check_value_conservation(
    inputs: Amount,
    outputs: Amount,
    burn: Amount,
) -> Result<u64, InvariantError> {
    let inputs_sat = inputs.as_sat();
    let outputs_sat = outputs.as_sat();
    let burn_sat = burn.as_sat();

    let out_plus_burn =
        outputs_sat
            .checked_add(burn_sat)
            .ok_or(InvariantError::OutputsPlusBurnOverflow {
                outputs_sat,
                burn_sat,
            })?;

    let fee = inputs_sat
        .checked_sub(out_plus_burn)
        .ok_or(InvariantError::NegativeFee {
            inputs_sat,
            outputs_sat,
            burn_sat,
        })?;

    Ok(fee)
}

// ──────────────────────────────────────────────────────────────────────────
//  Invariant 3: supply transition.
// ──────────────────────────────────────────────────────────────────────────

/// Enforce `new_supply = prev_supply - burn + reward` with full checked math.
///
/// Any of the following is a hard reject:
///   - `burn > prev_supply` (underflow)
///   - `prev_supply - burn + reward > Amount::MAX` (inflation past cap)
pub fn check_supply_transition(
    prev_supply: Amount,
    burn: Amount,
    reward: Amount,
) -> Result<Amount, InvariantError> {
    let prev_sat = prev_supply.as_sat();
    let burn_sat = burn.as_sat();
    let reward_sat = reward.as_sat();

    let after_burn = prev_sat
        .checked_sub(burn_sat)
        .ok_or(InvariantError::SupplyUnderflow { prev_sat, burn_sat })?;
    let after_reward =
        after_burn
            .checked_add(reward_sat)
            .ok_or(InvariantError::SupplyOverflow {
                prev_sat,
                burn_sat,
                reward_sat,
            })?;

    Amount::from_sat(after_reward).map_err(|_| InvariantError::SupplyOverflow {
        prev_sat,
        burn_sat,
        reward_sat,
    })
}

// ──────────────────────────────────────────────────────────────────────────
//  Invariant 4: coinbase value bound.
// ──────────────────────────────────────────────────────────────────────────

/// Enforce `coinbase_value <= reward + total_fees`.
///
/// This is the per-block money-supply invariant at the mining layer. If the
/// coinbase output sum exceeds the scheduled reward plus the fees that the
/// miner genuinely collected from validated txs, the block is rejected —
/// otherwise the miner would be minting coins outside the schedule.
pub fn check_coinbase_value(
    coinbase_value: Amount,
    reward: Amount,
    total_fees: u64,
) -> Result<(), InvariantError> {
    let claimed_sat = coinbase_value.as_sat();
    let reward_sat = reward.as_sat();

    let allowed_sat =
        reward_sat
            .checked_add(total_fees)
            .ok_or(InvariantError::RewardPlusFeesOverflow {
                reward_sat,
                fees_sat: total_fees,
            })?;

    if claimed_sat > allowed_sat {
        return Err(InvariantError::CoinbaseOverclaim {
            claimed_sat,
            allowed_sat,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn amt(s: u64) -> Amount {
        Amount::from_sat(s).unwrap()
    }

    // ── Invariant 1 + 2: value conservation ──

    #[test]
    fn value_conservation_exact() {
        // inputs == outputs + burn → fee == 0
        assert_eq!(
            check_value_conservation(amt(1_000), amt(900), amt(100)).unwrap(),
            0
        );
    }

    #[test]
    fn value_conservation_positive_fee() {
        assert_eq!(
            check_value_conservation(amt(1_000), amt(800), amt(100)).unwrap(),
            100
        );
    }

    #[test]
    fn value_conservation_rejects_overspend() {
        let err = check_value_conservation(amt(100), amt(99), amt(10)).unwrap_err();
        assert!(matches!(err, InvariantError::NegativeFee { .. }));
    }

    #[test]
    fn value_conservation_rejects_pure_overspend() {
        let err = check_value_conservation(amt(100), amt(200), amt(0)).unwrap_err();
        assert!(matches!(err, InvariantError::NegativeFee { .. }));
    }

    #[test]
    fn value_conservation_zero_everywhere_ok() {
        assert_eq!(
            check_value_conservation(Amount::ZERO, Amount::ZERO, Amount::ZERO).unwrap(),
            0
        );
    }

    // ── Invariant 3: supply transition ──

    #[test]
    fn supply_transition_reward_only() {
        let new = check_supply_transition(amt(1_000), Amount::ZERO, amt(50)).unwrap();
        assert_eq!(new.as_sat(), 1_050);
    }

    #[test]
    fn supply_transition_burn_only() {
        let new = check_supply_transition(amt(1_000), amt(100), Amount::ZERO).unwrap();
        assert_eq!(new.as_sat(), 900);
    }

    #[test]
    fn supply_transition_both() {
        let new = check_supply_transition(amt(1_000), amt(100), amt(50)).unwrap();
        assert_eq!(new.as_sat(), 950);
    }

    #[test]
    fn supply_transition_rejects_burn_exceeds_prev() {
        let err = check_supply_transition(amt(10), amt(11), amt(0)).unwrap_err();
        assert!(matches!(err, InvariantError::SupplyUnderflow { .. }));
    }

    #[test]
    fn supply_transition_rejects_overflow_past_max() {
        let err = check_supply_transition(Amount::MAX, Amount::ZERO, amt(1)).unwrap_err();
        assert!(matches!(err, InvariantError::SupplyOverflow { .. }));
    }

    // ── Invariant 4: coinbase bound ──

    #[test]
    fn coinbase_exact_reward_ok() {
        check_coinbase_value(amt(50), amt(50), 0).unwrap();
    }

    #[test]
    fn coinbase_reward_plus_fees_ok() {
        check_coinbase_value(amt(150), amt(100), 50).unwrap();
    }

    #[test]
    fn coinbase_underclaim_ok() {
        // Miner is allowed to claim less — no protocol requirement to maximize.
        check_coinbase_value(amt(10), amt(100), 50).unwrap();
    }

    #[test]
    fn coinbase_overclaim_rejected() {
        let err = check_coinbase_value(amt(151), amt(100), 50).unwrap_err();
        assert!(matches!(err, InvariantError::CoinbaseOverclaim { .. }));
    }

    #[test]
    fn coinbase_reward_plus_fees_overflow_rejected() {
        // u64::MAX fees + non-zero reward → arithmetic overflow → hard reject.
        let err = check_coinbase_value(amt(1), amt(1), u64::MAX).unwrap_err();
        assert!(matches!(err, InvariantError::RewardPlusFeesOverflow { .. }));
    }

    // ── Determinism property ──

    #[test]
    fn invariant_functions_are_deterministic() {
        // Pure functions: same inputs → same outputs, no time/rng drift.
        for _ in 0..16 {
            assert_eq!(
                check_value_conservation(amt(1_000), amt(800), amt(100)).unwrap(),
                100
            );
            assert_eq!(
                check_supply_transition(amt(5_000), amt(10), amt(50))
                    .unwrap()
                    .as_sat(),
                5_040
            );
            assert!(check_coinbase_value(amt(150), amt(100), 50).is_ok());
        }
    }
}
