//! Raw value reconstruction of node94 ELF VA [0x54b4390, 0x54b43d2).
#![no_std]
#![forbid(unsafe_code)]

/// Return the observed u32 value for any u64 input, without assigning meaning
/// to the input or the extracted two-bit field.
///
/// The wrapping doubled-minus-one operand is always odd, including for zero
/// and high-bit inputs. Thus its bit index is defined and lies in 0..=63.
/// The shift lies in 4..=60, and the final value lies in 1..=232.
pub fn raw_value(n: u64) -> u32 {
    let doubled = n.wrapping_mul(2).wrapping_sub(1);
    let rank = 63 - doubled.leading_zeros();
    let shift = rank.max(7) - 3;
    let mask = u64::MAX << shift;
    let field = ((n.wrapping_sub(1) & mask) >> shift) & 3;
    (field as u32)
        .wrapping_add(4 * rank.max(6))
        .wrapping_sub(23)
}
