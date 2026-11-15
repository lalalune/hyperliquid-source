//! Quorum `0x595bc40` (slot `0x64e8780`): stake test, then a participation-count test against a fraction.

use std::collections::BTreeSet;

use crate::sigmap::Address;
use crate::stake::StakeSet;

/// The fraction used by the count stage, from the double at context `+0x88`. Infinities and NaNs (any
/// sign) give `1.0`; everything else is `min(0.7, max(0.0, x))` with the operand order of the SSE
/// instructions (`-0.0` stays `-0.0`, which compares equal to zero).
pub fn fraction(bits: u64) -> f64 {
    if bits & 0x7fff_ffff_ffff_ffff > 0x7fef_ffff_ffff_ffff {
        return 1.0;
    }
    let x = f64::from_bits(bits);
    let t = if 0.0 > x { 0.0 } else { x };
    if 0.7 < t { 0.7 } else { t }
}

/// `signers` are the keys the collector found; `fraction_bits` is context `+0x88`.
pub fn quorum(fraction_bits: u64, set: &StakeSet, signers: &BTreeSet<Address>) -> bool {
    let keys: Vec<Address> = signers.iter().copied().collect();
    if !set.stakes.stake_test(&keys) {
        return false;
    }
    let f = fraction(fraction_bits);
    if f == 0.0 {
        return true;
    }
    let count = keys.iter().filter(|k| set.validators.contains(*k)).count() as u64;
    (count as f64) > f * (set.validator_count as f64)
}
