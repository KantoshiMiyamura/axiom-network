// Copyright (c) 2026 Kantoshi Miyamura

use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// Satoshi-denominated amount. 1 AXM = 100,000,000 sat. Max supply 21M AXM.
/// All arithmetic is checked to prevent overflow/underflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Amount(u64);

impl Amount {
    pub const MAX: Amount = Amount(2_100_000_000_000_000);
    pub const ZERO: Amount = Amount(0);
    pub const SATOSHI: Amount = Amount(1);
    pub const AXM: Amount = Amount(100_000_000);
    pub const DUST_LIMIT: Amount = Amount(546);

    /// Create from satoshis. Returns an error if the amount exceeds max supply.
    pub fn from_sat(sat: u64) -> Result<Self> {
        if sat > Self::MAX.0 {
            return Err(Error::InvalidAmount(format!(
                "exceeds maximum supply: {}",
                sat
            )));
        }
        Ok(Amount(sat))
    }

    pub fn as_sat(&self) -> u64 {
        self.0
    }

    pub fn checked_add(&self, other: Amount) -> Result<Amount> {
        let result = self.0.checked_add(other.0).ok_or(Error::Overflow)?;
        Amount::from_sat(result)
    }

    pub fn checked_sub(&self, other: Amount) -> Result<Amount> {
        let result = self.0.checked_sub(other.0).ok_or(Error::Underflow)?;
        Ok(Amount(result))
    }

    pub fn checked_mul(&self, multiplier: u64) -> Result<Amount> {
        let result = self.0.checked_mul(multiplier).ok_or(Error::Overflow)?;
        Amount::from_sat(result)
    }

    pub fn is_dust(&self) -> bool {
        *self < Self::DUST_LIMIT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amount_constants() {
        assert_eq!(Amount::ZERO.as_sat(), 0);
        assert_eq!(Amount::SATOSHI.as_sat(), 1);
        assert_eq!(Amount::AXM.as_sat(), 100_000_000);
        assert_eq!(Amount::MAX.as_sat(), 2_100_000_000_000_000);
    }

    #[test]
    fn test_amount_from_sat() {
        assert!(Amount::from_sat(0).is_ok());
        assert!(Amount::from_sat(1000).is_ok());
        assert!(Amount::from_sat(Amount::MAX.as_sat()).is_ok());
        assert!(Amount::from_sat(Amount::MAX.as_sat() + 1).is_err());
    }

    #[test]
    fn test_checked_add() {
        let a = Amount::from_sat(100).unwrap();
        let b = Amount::from_sat(200).unwrap();
        assert_eq!(a.checked_add(b).unwrap().as_sat(), 300);

        let max = Amount::MAX;
        let one = Amount::SATOSHI;
        assert!(max.checked_add(one).is_err());
    }

    #[test]
    fn test_checked_sub() {
        let a = Amount::from_sat(200).unwrap();
        let b = Amount::from_sat(100).unwrap();
        assert_eq!(a.checked_sub(b).unwrap().as_sat(), 100);

        let zero = Amount::ZERO;
        let one = Amount::SATOSHI;
        assert!(zero.checked_sub(one).is_err());
    }

    #[test]
    fn test_checked_mul() {
        let a = Amount::from_sat(100).unwrap();
        assert_eq!(a.checked_mul(3).unwrap().as_sat(), 300);

        let large = Amount::from_sat(1_000_000_000_000_000).unwrap();
        assert!(large.checked_mul(3).is_err());
    }

    #[test]
    fn test_is_dust() {
        assert!(Amount::ZERO.is_dust());
        assert!(Amount::from_sat(545).unwrap().is_dust());
        assert!(!Amount::from_sat(546).unwrap().is_dust());
        assert!(!Amount::AXM.is_dust());
    }
}
