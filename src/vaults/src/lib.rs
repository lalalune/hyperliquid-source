//! Integrated node #115 vaults and sub-account library.
//!
//! Target binary: Linux x86-64 `hl-node` #115, SHA-256
//! `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
//!
//! Combines the bounded vault micro-crates with independently authored Rust
//! reconstructions of the binary-verified vault equity, deposit/move,
//! withdrawal admission, share-split settlement, and sub-account admission
//! routines.

#![forbid(unsafe_code)]

pub mod amount;
pub mod deposit;
pub mod distribute;
pub mod split;
pub mod sub_account;
pub mod withdraw;

pub use node115_vault_address as address;
pub use node115_vault_create_context as create_context;
pub use node115_vault_identity_guards as identity_guards;
pub use node115_vault_redistribution as redistribution;
pub use node115_vault_weight_update as weight_update;

/// Pinned SHA-256 digest of Linux x86-64 node #115 (`artifacts/node/115/hl-node`).
pub const TARGET_SHA256: &str =
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";

/// 20-byte account / vault address.
pub type Address = [u8; 20];

/// USDC fixed-point scale observed across node #115 vault routines (`0x450e80` / `0x4599a0`).
pub const USD_SCALE: f64 = 1_000_000.0;

/// Smallest accepted denominator / positive threshold (`0x459ba0`: `1e-15`).
pub const TINY_EPS: f64 = 1e-15;

/// Smallest negative numerator clamped to `+0.0` in `0x14ca350` (`0x458fa0`: `-1e-15`).
pub const NEG_TINY_EPS: f64 = -1e-15;

/// Node #115 checked ratio helper at VA `0x14ca350`.
///
/// Rejects non-finite inputs, negative numerators `<= -1e-15`, denominators
/// `< 1e-15`, and non-finite quotients. Numerators in `(-1e-15, 0.0)` are
/// clamped to `0.0` before division.
pub fn checked_ratio(mut numerator: f64, denominator: f64) -> Option<f64> {
    if !numerator.is_finite() || !denominator.is_finite() {
        return None;
    }
    if numerator < 0.0 && numerator > NEG_TINY_EPS {
        numerator = 0.0;
        if TINY_EPS > denominator {
            return None;
        }
    } else if 0.0 > numerator || TINY_EPS > denominator {
        return None;
    }
    let quotient = numerator / denominator;
    if quotient.is_finite() {
        Some(quotient)
    } else {
        None
    }
}

/// Saturating `f64 -> i64` truncation matching node #115's clamp constants
/// (`-9.223372036854776e18`, `9.223372036854776e18`, `9.223372036854775e18`).
#[inline]
pub fn sat_trunc_i64(x: f64) -> i64 {
    if x.is_nan() {
        0
    } else {
        x as i64
    }
}

/// Finite-clamped `f64 -> i64` truncation used by `leader_share` in `0x44ae810`,
/// where both `NaN` and `±infinity` map to `0` before truncation.
#[inline]
pub fn finite_clamp_i64(x: f64) -> i64 {
    if !x.is_finite() {
        0
    } else {
        x as i64
    }
}

/// Saturating signed addition that records whether saturation occurred.
#[inline]
pub fn sat_add_i64(a: i64, b: i64) -> (i64, bool) {
    match a.checked_add(b) {
        Some(v) => (v, false),
        None => (if b > 0 { i64::MAX } else { i64::MIN }, true),
    }
}

/// Saturating signed subtraction that records whether saturation occurred.
#[inline]
pub fn sat_sub_i64(a: i64, b: i64) -> (i64, bool) {
    match a.checked_sub(b) {
        Some(v) => (v, false),
        None => (if b < 0 { i64::MAX } else { i64::MIN }, true),
    }
}

/// Saturating unsigned addition that records whether saturation occurred.
#[inline]
pub fn sat_add_u64(a: u64, b: u64) -> (u64, bool) {
    match a.checked_add(b) {
        Some(v) => (v, false),
        None => (u64::MAX, true),
    }
}
