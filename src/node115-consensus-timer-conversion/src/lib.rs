#![no_std]
//! The established seconds/nanoseconds conversion slice from node #115's
//! consensus timer constructor. This does not build the constructor's opaque
//! 0x70-byte payload or reproduce the native panic payload.

const NANOS_PER_SECOND: u128 = 1_000_000_000;
const FRACTION_MASK: u64 = (1 << 52) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeParts {
    pub seconds: u64,
    pub nanoseconds: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    NegativeInput,
    MagnitudeOutOfRange,
}

/// Convert a binary64 seconds value to integer seconds and nanoseconds.
///
/// Fractions round to nearest, ties to even. A rounded billion nanoseconds
/// carries into seconds. Negative values and values with exponent >= 0x43f
/// are rejected. The error variants identify the observed panic branch; they
/// do not reproduce its opaque native panic payload.
pub fn convert_seconds(value: f64) -> Result<TimeParts, Rejection> {
    let bits = value.to_bits();
    let negative = bits >> 63 != 0;
    let exponent = ((bits >> 52) & 0x7ff) as u32;
    let fraction = bits & FRACTION_MASK;
    let nan = exponent == 0x7ff && fraction != 0;
    let zero = exponent == 0 && fraction == 0;

    // The target's ordered comparison rejects every negative numeric value,
    // including -infinity, but an unordered NaN comparison continues.
    if negative && !nan && !zero {
        return Err(Rejection::NegativeInput);
    }
    if exponent >= 0x43f {
        return Err(Rejection::MagnitudeOutOfRange);
    }
    if exponent < 0x3e0 {
        return Ok(TimeParts {
            seconds: 0,
            nanoseconds: 0,
        });
    }

    let significand = (1u128 << 52) | u128::from(fraction);
    if exponent < 0x3ff {
        let shift = 1075 - exponent;
        let nanos = round_pow2(significand * NANOS_PER_SECOND, shift);
        return Ok(with_carry(0, nanos));
    }

    if exponent < 0x433 {
        let shift = 1075 - exponent;
        let seconds = significand >> shift;
        let fractional_bits = significand & ((1u128 << shift) - 1);
        let nanos = round_pow2(fractional_bits * NANOS_PER_SECOND, shift);
        return Ok(with_carry(seconds as u64, nanos));
    }

    let seconds = significand << (exponent - 0x433);
    Ok(TimeParts {
        seconds: seconds as u64,
        nanoseconds: 0,
    })
}

fn round_pow2(numerator: u128, shift: u32) -> u128 {
    debug_assert!(shift > 0 && shift < 128);
    let quotient = numerator >> shift;
    let remainder = numerator & ((1u128 << shift) - 1);
    let halfway = 1u128 << (shift - 1);
    quotient + u128::from(remainder > halfway || (remainder == halfway && quotient & 1 == 1))
}

fn with_carry(seconds: u64, nanoseconds: u128) -> TimeParts {
    if nanoseconds == NANOS_PER_SECOND {
        TimeParts {
            seconds: seconds + 1,
            nanoseconds: 0,
        }
    } else {
        TimeParts {
            seconds,
            nanoseconds: nanoseconds as u32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Rejection, TimeParts, convert_seconds, round_pow2};

    fn parts(seconds: u64, nanoseconds: u32) -> TimeParts {
        TimeParts {
            seconds,
            nanoseconds,
        }
    }

    #[test]
    fn rounds_binary_fraction_to_nearest_ties_even() {
        assert_eq!(round_pow2(4 * 16 + 7, 4), 4);
        assert_eq!(round_pow2(4 * 16 + 8, 4), 4);
        assert_eq!(round_pow2(5 * 16 + 8, 4), 6);
        assert_eq!(round_pow2(4 * 16 + 9, 4), 5);
    }

    #[test]
    fn matches_the_two_consensus_state_callsite_inputs() {
        assert_eq!(convert_seconds(0.3), Ok(parts(0, 300_000_000)));
        assert_eq!(
            convert_seconds(f64::from_bits(0x3fb9_9999_9999_9999)),
            Ok(parts(0, 100_000_000))
        );
    }

    #[test]
    fn covers_small_fraction_and_carry_boundaries() {
        assert_eq!(convert_seconds(2f64.powi(-31)), Ok(parts(0, 0)));
        assert_eq!(convert_seconds(1e-9), Ok(parts(0, 1)));
        assert_eq!(convert_seconds(0.999_999_999_6), Ok(parts(1, 0)));
        assert_eq!(convert_seconds(1.999_999_999_6), Ok(parts(2, 0)));
        assert_eq!(convert_seconds(1.0), Ok(parts(1, 0)));
    }

    #[test]
    fn covers_integer_regimes_and_u64_limit() {
        assert_eq!(convert_seconds(2f64.powi(52)), Ok(parts(1u64 << 52, 0)));
        assert_eq!(
            convert_seconds(f64::from_bits(0x43ef_ffff_ffff_ffff)),
            Ok(parts(u64::MAX - 2047, 0))
        );
        assert_eq!(
            convert_seconds(2f64.powi(64)),
            Err(Rejection::MagnitudeOutOfRange)
        );
    }

    #[test]
    fn distinguishes_negative_values_nan_and_signed_zero() {
        assert_eq!(convert_seconds(-0.0), Ok(parts(0, 0)));
        assert_eq!(
            convert_seconds(f64::from_bits(0x8000_0000_0000_0001)),
            Err(Rejection::NegativeInput)
        );
        assert_eq!(
            convert_seconds(f64::NEG_INFINITY),
            Err(Rejection::NegativeInput)
        );
        assert_eq!(
            convert_seconds(f64::NAN),
            Err(Rejection::MagnitudeOutOfRange)
        );
        assert_eq!(
            convert_seconds(f64::from_bits(0xfff8_0000_0000_0001)),
            Err(Rejection::MagnitudeOutOfRange)
        );
    }
}
