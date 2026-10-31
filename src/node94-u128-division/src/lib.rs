//! A checked two-limb quotient interface for the node94 RE-004 data contract.
//!
//! This independent implementation uses binary long division with u64 limbs.
//! It does not invoke a u128 division primitive, reproduce the target's native
//! calling convention, or claim its optimized instruction paths or performance.
#![no_std]
#![forbid(unsafe_code)]

/// An unsigned value `low + 2^64 * high`; this is a new Rust representation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Words {
    pub low: u64,
    pub high: u64,
}

/// A checked input boundary: the native helper instead faults on a zero divisor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonZeroWords(Words);

impl NonZeroWords {
    pub const fn new(words: Words) -> Option<Self> {
        if words.low == 0 && words.high == 0 {
            None
        } else {
            Some(Self(words))
        }
    }
}

/// Return the unsigned floor quotient, using exactly 128 input-bit steps.
///
/// At step k the remainder represents the processed k-bit prefix modulo the
/// divisor. Before the last shift it has at most 127 bits, so the two-limb
/// left shift cannot discard a significant bit. The subtraction occurs only
/// when the shifted remainder is at least the divisor; low-limb borrow must
/// propagate into the high limb. This explanation is not a machine proof.
pub fn quotient(numerator: Words, denominator: NonZeroWords) -> Words {
    let divisor = denominator.0;
    let mut remainder = Words::default();
    let mut result = Words::default();
    for bit in (0..128).rev() {
        let incoming = if bit >= 64 {
            (numerator.high >> (bit - 64)) & 1
        } else {
            (numerator.low >> bit) & 1
        };
        remainder.high = (remainder.high << 1) | (remainder.low >> 63);
        remainder.low = (remainder.low << 1) | incoming;
        if remainder.high > divisor.high
            || (remainder.high == divisor.high && remainder.low >= divisor.low)
        {
            let (low, borrow) = remainder.low.overflowing_sub(divisor.low);
            remainder.low = low;
            remainder.high = remainder
                .high
                .wrapping_sub(divisor.high)
                .wrapping_sub(u64::from(borrow));
            if bit >= 64 {
                result.high |= 1 << (bit - 64);
            } else {
                result.low |= 1 << bit;
            }
        }
    }
    result
}

#[cfg(test)]
mod tests;
