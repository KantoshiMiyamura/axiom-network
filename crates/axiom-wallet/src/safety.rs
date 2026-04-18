// Copyright (c) 2026 Kantoshi Miyamura

// Wallet precondition checks. All local, no network calls.

use crate::{Address, Result, WalletError};

/// Outputs below this amount are non-standard.
pub const MIN_DUST_SATOSHIS: u64 = 546;

/// Fees above 50% of the transfer amount are almost certainly mistakes.
pub const MAX_FEE_FRACTION_PERCENT: u64 = 50;

/// Minimum password length.
pub const MIN_PASSWORD_LEN: usize = 8;

/// Require at least 8 chars, one uppercase, one lowercase, one digit, one special character.
pub fn validate_password_strength(password: &str) -> Result<()> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(WalletError::WeakPassword(format!(
            "password must be at least {} characters",
            MIN_PASSWORD_LEN
        )));
    }
    if !password.chars().any(|c| c.is_uppercase()) {
        return Err(WalletError::WeakPassword(
            "password must contain at least one uppercase letter".into(),
        ));
    }
    if !password.chars().any(|c| c.is_lowercase()) {
        return Err(WalletError::WeakPassword(
            "password must contain at least one lowercase letter".into(),
        ));
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(WalletError::WeakPassword(
            "password must contain at least one digit".into(),
        ));
    }
    if !password.chars().any(|c| !c.is_alphanumeric()) {
        return Err(WalletError::WeakPassword(
            "password must contain at least one special character".into(),
        ));
    }
    Ok(())
}

/// Parse and checksum-validate an address string. Call before every outbound send.
pub fn validate_address(addr_str: &str) -> Result<Address> {
    Address::from_string(addr_str)
}

/// Reject amounts below the dust threshold.
pub fn validate_amount_not_dust(amount_sat: u64) -> Result<()> {
    if amount_sat < MIN_DUST_SATOSHIS {
        return Err(WalletError::DustAmount {
            amount: amount_sat,
            min: MIN_DUST_SATOSHIS,
        });
    }
    Ok(())
}

/// Reject fees that exceed MAX_FEE_FRACTION_PERCENT of the transfer amount.
/// Zero fees are allowed (valid on devnet).
pub fn validate_fee_reasonable(fee_sat: u64, amount_sat: u64) -> Result<()> {
    if fee_sat == 0 {
        return Ok(());
    }
    if amount_sat == 0 {
        return Err(WalletError::InvalidAmount("amount cannot be zero".into()));
    }
    let fee_pct = fee_sat.saturating_mul(100) / amount_sat;
    if fee_pct > MAX_FEE_FRACTION_PERCENT {
        return Err(WalletError::FeeTooHigh {
            fee: fee_sat,
            amount: amount_sat,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Password strength ─────────────────────────────────────────────────

    #[test]
    fn strong_password_accepted() {
        assert!(validate_password_strength("Axiom123!secure").is_ok());
    }

    #[test]
    fn too_short_rejected() {
        assert!(validate_password_strength("Ab1!").is_err());
    }

    #[test]
    fn no_uppercase_rejected() {
        assert!(validate_password_strength("axiom123!secure").is_err());
    }

    #[test]
    fn no_lowercase_rejected() {
        assert!(validate_password_strength("AXIOM123!SECURE").is_err());
    }

    #[test]
    fn no_digit_rejected() {
        assert!(validate_password_strength("Axiom!!!secure").is_err());
    }

    #[test]
    fn no_special_rejected() {
        assert!(validate_password_strength("Axiom123secure").is_err());
    }

    // ── Address validation ────────────────────────────────────────────────

    #[test]
    fn valid_address_accepted() {
        use crate::KeyPair;
        let kp = KeyPair::generate().unwrap();
        let addr = crate::Address::from_pubkey_hash(kp.public_key_hash());
        assert!(validate_address(&addr.to_string()).is_ok());
    }

    #[test]
    fn invalid_address_rejected() {
        assert!(validate_address("notanaddress").is_err());
    }

    // ── Dust threshold ────────────────────────────────────────────────────

    #[test]
    fn above_dust_accepted() {
        assert!(validate_amount_not_dust(MIN_DUST_SATOSHIS).is_ok());
        assert!(validate_amount_not_dust(10_000).is_ok());
    }

    #[test]
    fn below_dust_rejected() {
        assert!(matches!(
            validate_amount_not_dust(100).unwrap_err(),
            WalletError::DustAmount { .. }
        ));
    }

    // ── Fee sanity ────────────────────────────────────────────────────────

    #[test]
    fn reasonable_fee_accepted() {
        assert!(validate_fee_reasonable(100, 10_000).is_ok());
    }

    #[test]
    fn zero_fee_accepted() {
        assert!(validate_fee_reasonable(0, 10_000).is_ok());
    }

    #[test]
    fn excessive_fee_rejected() {
        assert!(matches!(
            validate_fee_reasonable(6_000, 10_000).unwrap_err(),
            WalletError::FeeTooHigh { .. }
        ));
    }
}
