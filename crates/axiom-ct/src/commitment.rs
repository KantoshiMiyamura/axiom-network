// Copyright (c) 2026 Kantoshi Miyamura

//! Pedersen commitments over the Ristretto255 group.
//!
//! A Pedersen commitment to value `v` with blinding factor `r` is:
//!
//! ```text
//! C = v·H + r·G
//! ```
//!
//! where `G` is the Ristretto basepoint and `H` is a second generator with no
//! known discrete-log relationship to `G` (a "nothing-up-my-sleeve" point
//! derived by hashing the string `"axiom-pedersen-H-v1"` to the curve).
//!
//! ## Properties
//!
//! - **Perfectly hiding** — an adversary with unbounded compute cannot learn `v`
//!   from `C` without knowing `r`.
//! - **Computationally binding** — finding two openings `(v,r)` and `(v',r')`
//!   for the same `C` is as hard as the discrete-log problem on Ristretto255.
//! - **Homomorphic** — `commit(v1,r1) + commit(v2,r2) == commit(v1+v2, r1+r2)`.
//!   This is the property that makes balance verification possible without
//!   revealing individual amounts.

use crate::error::{CtError, Result};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
// curve25519-dalek-ng uses digest 0.9; sha3 v0.9 implements that trait.
use sha3::Sha3_512;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Generators ──────────────────────────────────────────────────────────────

/// G — standard Ristretto basepoint.
pub fn generator_g() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT
}

/// H — second independent generator, derived deterministically.
///
/// Computed as `hash_to_ristretto("axiom-pedersen-H-v1")` using SHA3-512
/// (compatible with the digest v0.9 API used by curve25519-dalek-ng).
/// The derivation is public, so nobody can know `log_G(H)`.
pub fn generator_h() -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha3_512>(b"axiom-pedersen-H-v1")
}

// ── Blinding factor ──────────────────────────────────────────────────────────

/// A 32-byte blinding factor (random scalar in Z_r).
///
/// Zeroized on drop — the blinding factor is as sensitive as a private key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BlindingFactor(pub(crate) Scalar);

impl BlindingFactor {
    /// Generate a fresh random blinding factor.
    pub fn random() -> Self {
        let mut bytes = [0u8; 64];
        OsRng.fill_bytes(&mut bytes);
        BlindingFactor(Scalar::from_bytes_mod_order_wide(&bytes))
    }

    /// Construct from raw bytes (32-byte little-endian scalar).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        BlindingFactor(Scalar::from_bytes_mod_order(*bytes))
    }

    /// Export raw bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub(crate) fn inner(&self) -> &Scalar {
        &self.0
    }

    /// Negate this blinding factor: returns `-r` (mod the group order).
    pub fn negate(&self) -> BlindingFactor {
        BlindingFactor(-self.0)
    }

    /// Add two blinding factors: returns `self + other`.
    pub fn add(&self, other: &BlindingFactor) -> BlindingFactor {
        BlindingFactor(self.0 + other.0)
    }
}

impl std::fmt::Debug for BlindingFactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlindingFactor([redacted])")
    }
}

// ── Commitment ────────────────────────────────────────────────────────────────

/// A Pedersen commitment: `C = v·H + r·G`.
///
/// 32 bytes when compressed (Ristretto canonical encoding).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    /// Compressed Ristretto point.
    bytes: [u8; 32],
}

impl Commitment {
    /// Commit to `value` with blinding factor `r`.
    pub fn commit(value: u64, r: &BlindingFactor) -> Self {
        let v_scalar = Scalar::from(value);
        let point = v_scalar * generator_h() + r.inner() * generator_g();
        Commitment { bytes: point.compress().to_bytes() }
    }

    /// Decompress to a curve point for homomorphic operations.
    pub fn to_point(&self) -> Result<RistrettoPoint> {
        use curve25519_dalek::ristretto::CompressedRistretto;
        let compressed = CompressedRistretto::from_slice(&self.bytes);
        compressed.decompress().ok_or(CtError::DeserializationFailed)
    }

    /// Raw 32-byte encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// Construct from raw 32 bytes (no validation).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Commitment { bytes }
    }
}

/// Homomorphic addition: `C1 + C2 = commit(v1+v2, r1+r2)`.
impl std::ops::Add for &Commitment {
    type Output = Result<Commitment>;
    fn add(self, rhs: &Commitment) -> Result<Commitment> {
        let p1 = self.to_point()?;
        let p2 = rhs.to_point()?;
        Ok(Commitment { bytes: (p1 + p2).compress().to_bytes() })
    }
}

/// Homomorphic subtraction: `C1 - C2 = commit(v1-v2, r1-r2)`.
impl std::ops::Sub for &Commitment {
    type Output = Result<Commitment>;
    fn sub(self, rhs: &Commitment) -> Result<Commitment> {
        let p1 = self.to_point()?;
        let p2 = rhs.to_point()?;
        Ok(Commitment { bytes: (p1 - p2).compress().to_bytes() })
    }
}

/// Sum a slice of commitments.
pub fn sum_commitments(commitments: &[Commitment]) -> Result<Commitment> {
    if commitments.is_empty() {
        // Commitment to zero with zero blinding = H*0 + G*0 = identity
        use curve25519_dalek::traits::Identity;
        let zero = RistrettoPoint::identity();
        return Ok(Commitment { bytes: zero.compress().to_bytes() });
    }
    let mut acc = commitments[0].to_point()?;
    for c in &commitments[1..] {
        acc += c.to_point()?;
    }
    Ok(Commitment { bytes: acc.compress().to_bytes() })
}

/// Sum a slice of blinding factors: `r_1 + r_2 + … + r_n`.
///
/// Returns the zero scalar when `factors` is empty.
pub fn sum_blinding_factors(factors: &[BlindingFactor]) -> BlindingFactor {
    let mut acc = Scalar::zero();
    for f in factors {
        acc += f.inner();
    }
    BlindingFactor(acc)
}

/// Verify that `sum(inputs) == sum(outputs) + fee_commitment`.
///
/// This is the core balance check for a confidential transaction:
/// no satoshis are created or destroyed, just redistributed.
pub fn verify_balance(
    input_commitments: &[Commitment],
    output_commitments: &[Commitment],
    fee_commitment: &Commitment,
) -> Result<()> {
    let in_sum = sum_commitments(input_commitments)?;
    let out_sum = sum_commitments(output_commitments)?;

    let rhs_point = out_sum.to_point()? + fee_commitment.to_point()?;
    let rhs = Commitment { bytes: rhs_point.compress().to_bytes() };

    if in_sum == rhs {
        Ok(())
    } else {
        Err(CtError::BalanceCheckFailed)
    }
}
