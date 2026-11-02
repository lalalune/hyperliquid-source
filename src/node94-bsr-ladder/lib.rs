//! Safe numeric projection of node94 ELF VA [0x556e980, 0x556e9d8).
//! The argument meanings and the original calling interface remain unknown.
#![no_std]
#![forbid(unsafe_code)]

/// Evaluate the ordered unsigned min/max ladder on its defined BSR domain.
///
/// Inputs represent the low 32 bits of the four original argument registers.
/// `None` refuses to specify the target's architecturally undefined BSR-zero
/// cases: `second` is 0 or 1, or `third` is 0. It is a new safe API result,
/// not a return value observed in the original function, which has no guards.
/// The fourth argument is subtracted modulo 2^32 before unsigned comparisons.
pub fn ladder(value: u32, second: u32, third: u32, fourth: u32) -> Option<u32> {
    if second <= 1 || third == 0 {
        return None;
    }
    let upper = bit_index(second - 1).wrapping_sub(fourth);
    let lower = (bit_index(second) + 1).min(bit_index(third) + 2);
    let value = if value == 0 { 11 } else { value };
    Some(value.min(upper).max(lower).min(12).max(5))
}

fn bit_index(nonzero: u32) -> u32 {
    31 - nonzero.leading_zeros()
}
