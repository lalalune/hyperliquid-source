#![no_std]

//! The bounded unsigned remainder leaf observed at node #115 `0x63bfbc0`.
//!
//! This preserves the target's reciprocal-multiply quotient calculation while
//! exposing only its mathematical input and output, not the native pointer ABI.

const DIVISOR: u64 = 1_000_000_000;
const RECIPROCAL: u64 = 0x0044_b82f_a09b_5a53;

/// Returns the unsigned input modulo one billion.
///
/// The calculation mirrors the target's reciprocal multiplication: it shifts
/// the input by nine, multiplies by the observed reciprocal, extracts the
/// quotient from product bits 75 and above, then subtracts the quotient times
/// one billion. The target packet proves this quotient is exact for every
/// `u64` input.
#[must_use]
pub fn remainder(value: u64) -> u64 {
    let shifted = u128::from(value >> 9);
    let product = shifted * u128::from(RECIPROCAL);
    let quotient = (product >> 75) as u64;
    value - quotient * DIVISOR
}

#[cfg(test)]
mod tests {
    use super::remainder;

    #[test]
    fn handles_divisor_boundaries() {
        for value in [0, 1, 999_999_998, 999_999_999, 1_000_000_000, 1_000_000_001] {
            assert_eq!(remainder(value), value % 1_000_000_000);
        }
    }

    #[test]
    fn handles_the_u64_upper_boundary() {
        for value in [u64::MAX - 2, u64::MAX - 1, u64::MAX] {
            assert_eq!(remainder(value), value % 1_000_000_000);
        }
    }

    #[test]
    fn checks_values_around_quotient_boundaries() {
        let max_q = u64::MAX / 1_000_000_000;
        for q in [0, 1, 2, 3, 127, 128, 129, max_q - 1, max_q] {
            let base = q * 1_000_000_000;
            for delta in [0, 1, 999_999_999] {
                if let Some(value) = base.checked_add(delta) {
                    assert_eq!(remainder(value), value % 1_000_000_000);
                }
            }
        }
    }

    #[test]
    fn agrees_with_integer_remainder_for_deterministic_full_width_samples() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            assert_eq!(remainder(state), state % 1_000_000_000);
        }
    }
}
