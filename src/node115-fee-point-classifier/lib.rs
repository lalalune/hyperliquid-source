// SPDX-License-Identifier: MIT
// Independently authored from the reviewed node #115 numerical contract.
#![no_std]
#![forbid(unsafe_code)]

//! Conditional point classification for the node #115 fee calculation.
//!
//! This projects the first numerical branch in the selected kernel. It does
//! not reproduce the native ABI, diagnostics, overflow-hook effects, returned
//! winner/state, or outer traversal. Correspondence requires separately rounded
//! binary64 operations with round-to-nearest, ties-to-even, gradual underflow,
//! masked exceptions, and normal preserving returns from reached native hooks.
//! The component neither inspects nor changes the floating-point environment.

/// The largest quantity in the observed bounded construction.
pub const MAX_QUANTITY: u64 = 10_000_000;

/// The six exact scale encodings, in the order of the captured array.
pub const SCALE_BITS: [u64; 6] = [
    0x3ff0_0000_0000_0000,
    0x3fc9_9999_9999_999a,
    0x4018_0000_0000_0000,
    0x3fb9_9999_9999_999a,
    0x4000_0000_0000_0000,
    0x4044_0000_0000_0000,
];

/// Supplied values for one point; the five scalar fields accept all bit patterns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Point {
    pub quantity: u64,
    pub scale_bits: u64,
    pub t_bits: u64,
    pub d_bits: u64,
    pub q_bits: u64,
    pub m_bits: u64,
    pub h_bits: u64,
}

/// Chosen names for the first numerical condition, not native enum variants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Classification {
    FirstProductNegative,
    NetAndBaseNegative,
    SecondProductNegative,
    RoundedMagnitudeAtLeastQuantity,
    Pass,
}

impl Classification {
    /// Stable text used by the input-only validation driver.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FirstProductNegative => "FirstProductNegative",
            Self::NetAndBaseNegative => "NetAndBaseNegative",
            Self::SecondProductNegative => "SecondProductNegative",
            Self::RoundedMagnitudeAtLeastQuantity => "RoundedMagnitudeAtLeastQuantity",
            Self::Pass => "Pass",
        }
    }
}

/// Safe host-domain refusals. These are not reconstructed native errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainError {
    QuantityOutOfRange,
    UnsupportedScale,
}

// Each native conversion first maps all nonfinite inputs to zero. Rust's
// finite float-to-i64 cast then supplies toward-zero conversion with saturation.
// In particular, plain casting without this gate would mishandle infinities.
fn finite_trunc_sat(value: f64) -> i64 {
    if value.is_finite() { value as i64 } else { 0 }
}

/// Classify one supplied point under the module's explicit FP/native premises.
///
/// Quantity is checked before scale as a chosen host policy. Each rejection
/// returns before the next numerical stage. No callback supplies a numeric
/// answer: the native overflow continuations recompute saturation themselves.
pub fn classify(point: Point) -> Result<Classification, DomainError> {
    if !(1..=MAX_QUANTITY).contains(&point.quantity) {
        return Err(DomainError::QuantityOutOfRange);
    }
    if !SCALE_BITS.contains(&point.scale_bits) {
        return Err(DomainError::UnsupportedScale);
    }

    // Quantity conversion is exact in 1..=10,000,000. Conversions of A/E below
    // can round and must not be replaced by exact real-number multiplication.
    let quantity = point.quantity as f64;
    let scale = f64::from_bits(point.scale_bits);
    let t = f64::from_bits(point.t_bits);
    let d = f64::from_bits(point.d_bits);
    let q = f64::from_bits(point.q_bits);

    // A = T((((1 - d) * t) * scale) * I(quantity)); B = T(I(A) * q).
    // Keep each binary64 operation separate; no mul_add or reassociation.
    let one_minus_d = 1.0 - d;
    let first_product = one_minus_d * t;
    let scaled_first = first_product * scale;
    let a = finite_trunc_sat(scaled_first * quantity);
    let b = finite_trunc_sat((a as f64) * q);
    if b < 0 {
        return Ok(Classification::FirstProductNegative);
    }

    // D = T((m * scale) * I(quantity)); S = SatAdd(SatSub(A, B), D).
    let m = f64::from_bits(point.m_bits);
    let scaled_base = m * scale;
    let base = finite_trunc_sat(scaled_base * quantity);
    let difference = a.saturating_sub(b);
    let net = difference.saturating_add(base);
    if net < 0 {
        return Ok(Classification::NetAndBaseNegative);
    }

    // E = T((scale * h) * I(quantity)); F = T(q * I(E)).
    let h = f64::from_bits(point.h_bits);
    let scaled_second = scale * h;
    let e = finite_trunc_sat(scaled_second * quantity);
    let f = finite_trunc_sat(q * (e as f64));
    if f < 0 {
        return Ok(Classification::SecondProductNegative);
    }

    // Both summands are in 0..=i64::MAX, so this first sum cannot overflow u64.
    let positive_e = e.max(0) as u64;
    let v = (f as u64) + positive_e;
    // unsigned_abs also represents i64::MIN as 2^63 without signed overflow.
    // This primitive fact does not claim MIN reaches this stage in the kernel.
    let total = v.saturating_add(base.unsigned_abs());
    if total >= point.quantity {
        Ok(Classification::RoundedMagnitudeAtLeastQuantity)
    } else {
        Ok(Classification::Pass)
    }
}
