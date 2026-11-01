//! Supplied-sample values for node94 `0x3750610` and the absence projection
//! at `0x275eda0`. Native correspondence is conditional on the memory, helper
//! and Intel SSE premises in `RE-007-funding-rate-values-94/PROOF.md`.
//!
//! All arithmetic below uses integers: nearest-even binary64, gradual
//! underflow and the specified first-source NaN selection are independent of
//! the host floating environment. No scheduler, map or economic units are
//! reconstructed. This is newly authored MIT code, not recovered source text.

#![no_std]

const SIGN: u64 = 1 << 63;
const FRACTION: u64 = (1 << 52) - 1;
const INFINITY: u64 = 0x7ff0_0000_0000_0000;
const QUIET: u64 = 1 << 51;
const INDEFINITE: u64 = 0xfff8_0000_0000_0000;
const DEFAULT_INTEREST: u64 = 0x3f1a_36e2_eb1c_432d;
const ONE: u64 = 0x3ff0_0000_0000_0000;
const LIMIT: u64 = 0x3fd4_7ae1_47ae_147b;
const EIGHTH: u64 = 0x3fc0_0000_0000_0000;

fn nan(first: u64, second: u64) -> Option<u64> {
    if first & !SIGN > INFINITY {
        Some(first | QUIET)
    } else if second & !SIGN > INFINITY {
        Some(second | QUIET)
    } else {
        None
    }
}

fn parts(bits: u64) -> (u128, i32) {
    let exponent = ((bits >> 52) & 2047) as i32;
    if exponent == 0 {
        ((bits & FRACTION) as u128, -1074)
    } else {
        (((bits & FRACTION) | (1 << 52)) as u128, exponent - 1075)
    }
}

// The rounded integer is expressed in units of 2^quantum. Carry into the
// next binade and the largest-subnormal/minimum-normal boundary share this
// encoding path. Overflow at the nearest-even midpoint produces infinity.
fn encode(rounded: u128, quantum: i32, negative: bool) -> u64 {
    let sign = if negative { SIGN } else { 0 };
    if rounded == 0 {
        return sign;
    }
    let width = 128 - rounded.leading_zeros();
    let exponent = width as i32 - 1 + quantum;
    if exponent > 1023 {
        return sign | INFINITY;
    }
    if exponent < -1022 {
        return sign | rounded as u64;
    }
    let normalized = if width > 53 {
        rounded >> (width - 53)
    } else {
        rounded << (53 - width)
    };
    sign | (((exponent + 1023) as u64) << 52) | (normalized as u64 & FRACTION)
}

fn round_dyadic(magnitude: u128, power: i32, negative: bool) -> u64 {
    if magnitude == 0 {
        return if negative { SIGN } else { 0 };
    }
    let top = 127 - magnitude.leading_zeros() as i32 + power;
    let quantum = (top - 52).max(-1074);
    let shift = quantum - power;
    let rounded = if shift > 128 {
        0
    } else if shift == 128 {
        u128::from(magnitude > (1_u128 << 127))
    } else if shift > 0 {
        let quotient = magnitude >> shift;
        let remainder = magnitude & ((1_u128 << shift) - 1);
        let halfway = 1_u128 << (shift - 1);
        quotient + u128::from(remainder > halfway || (remainder == halfway && quotient & 1 != 0))
    } else {
        magnitude << -shift
    };
    encode(rounded, quantum, negative)
}

fn add(first: u64, second: u64) -> u64 {
    if let Some(result) = nan(first, second) {
        return result;
    }
    let a = first & !SIGN;
    let b = second & !SIGN;
    if a == INFINITY || b == INFINITY {
        return if a == INFINITY && b == INFINITY && (first ^ second) & SIGN != 0 {
            INDEFINITE
        } else if a == INFINITY {
            first
        } else {
            second
        };
    }
    if a == 0 && b == 0 {
        return first & second & SIGN;
    }
    if a == 0 {
        return second;
    }
    if b == 0 {
        return first;
    }
    let (mut am, ap) = parts(first);
    let (mut bm, bp) = parts(second);
    let gap = (ap - bp).unsigned_abs();
    if gap > 64 {
        // The smaller magnitude is strictly below half the smaller adjacent
        // spacing of the dominant operand, including powers of two.
        return if ap > bp { first } else { second };
    }
    let power = ap.min(bp);
    am <<= ap - power;
    bm <<= bp - power;
    if (first ^ second) & SIGN == 0 {
        round_dyadic(am + bm, power, first & SIGN != 0)
    } else if am > bm {
        round_dyadic(am - bm, power, first & SIGN != 0)
    } else if bm > am {
        round_dyadic(bm - am, power, second & SIGN != 0)
    } else {
        0
    }
}

fn subtract(first: u64, second: u64) -> u64 {
    // Intel SUB selects/quietens NaNs before the arithmetic sign inversion.
    if let Some(result) = nan(first, second) {
        result
    } else {
        add(first, second ^ SIGN)
    }
}

fn multiply(first: u64, second: u64) -> u64 {
    if let Some(result) = nan(first, second) {
        return result;
    }
    let a = first & !SIGN;
    let b = second & !SIGN;
    let negative = (first ^ second) & SIGN != 0;
    if a == INFINITY || b == INFINITY {
        return if a == 0 || b == 0 {
            INDEFINITE
        } else {
            (if negative { SIGN } else { 0 }) | INFINITY
        };
    }
    let (am, ap) = parts(first);
    let (bm, bp) = parts(second);
    round_dyadic(am * bm, ap + bp, negative)
}

// Only the nonzero, positive, correctly rounded sequence length is a
// denominator. The public operation never calls this with count == 0.
fn divide_by_count(sum: u64, count: u64) -> u64 {
    debug_assert!(count != 0);
    if let Some(result) = nan(sum, 0) {
        return result;
    }
    if sum & !SIGN == 0 || sum & !SIGN == INFINITY {
        return sum;
    }
    let length = round_dyadic(count as u128, 0, false);
    let (am, ap) = parts(sum);
    let (bm, bp) = parts(length);
    let mut ratio_top = bm.leading_zeros() as i32 - am.leading_zeros() as i32;
    if (ratio_top >= 0 && am < bm << ratio_top) || (ratio_top < 0 && am << -ratio_top < bm) {
        ratio_top -= 1;
    }
    let quantum = (ap - bp + ratio_top - 52).max(-1074);
    let shift = ap - bp - quantum;
    let negative = sum & SIGN != 0;
    let (numerator, denominator) = if shift >= 0 {
        // The selected quantum gives at most 106 numerator bits.
        (am << shift, bm)
    } else {
        let right = (-shift) as u32;
        if right >= 128 || (128 - bm.leading_zeros()) + right > 128 {
            return if negative { SIGN } else { 0 };
        }
        (am, bm << right)
    };
    let quotient = numerator / denominator;
    let remainder = numerator % denominator;
    let complement = denominator - remainder;
    let rounded = quotient
        + u128::from(remainder > complement || (remainder == complement && quotient & 1 != 0));
    encode(rounded, quantum, negative)
}

// Called with finite operands. Equal values (including opposite zero signs)
// choose the second operand, as the captured MINSD/MAXSD instructions do.
fn less(first: u64, second: u64) -> bool {
    if first & !SIGN == 0 && second & !SIGN == 0 {
        false
    } else if (first ^ second) & SIGN != 0 {
        first & SIGN != 0
    } else if first & SIGN == 0 {
        first < second
    } else {
        first > second
    }
}

fn minimum(first: u64, second: u64) -> u64 {
    if less(first, second) { first } else { second }
}

fn maximum(first: u64, second: u64) -> u64 {
    if less(second, first) { first } else { second }
}

/// Compute the admitted raw rate for one supplied sample sequence.
///
/// Missing or empty samples return `None`. Present NaNs, infinities and signed
/// zero are preserved as specified by the ordered Intel SSE value relation.
/// Optional parameters have the captured defaults. The borrowed slice supplies
/// ordinary valid storage; this function does not traverse native containers.
pub fn funding_rate_bits(
    samples: Option<&[u64]>,
    interest_bits: Option<u64>,
    multiplier_bits: Option<u64>,
    clamp_bits: u64,
) -> Option<u64> {
    let samples = samples?;
    if samples.is_empty() {
        return None;
    }
    let mut sum = SIGN;
    for &sample in samples {
        sum = add(sum, sample);
    }
    let mean = divide_by_count(sum, samples.len() as u64);
    let interest = interest_bits.unwrap_or(DEFAULT_INTEREST);
    let mut gap = subtract(interest, mean);
    if gap & !SIGN < INFINITY && clamp_bits & !SIGN < INFINITY {
        let low = minimum(clamp_bits, clamp_bits ^ SIGN);
        let high = maximum(clamp_bits ^ SIGN, clamp_bits);
        gap = minimum(high, maximum(low, gap));
    }
    let corrected = add(mean, gap);
    let mut product = multiply(corrected, multiplier_bits.unwrap_or(ONE));
    if product & !SIGN < INFINITY {
        product = minimum(LIMIT, maximum(LIMIT | SIGN, product));
    }
    Some(multiply(product, EIGHTH))
}

/// The caller substitutes positive zero only for absence; this does not write
/// any map, and every present raw bit pattern is returned unchanged.
pub fn insertion_bits(rate: Option<u64>) -> u64 {
    rate.unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_length_rounding_without_a_synthetic_slice() {
        assert_eq!(round_dyadic((1 << 53) + 1, 0, false), 0x4340_0000_0000_0000);
        assert_eq!(round_dyadic((1 << 53) + 3, 0, false), 0x4340_0000_0000_0002);
        assert_eq!(round_dyadic((1 << 60) - 1, 0, false), 0x43b0_0000_0000_0000);
        assert_eq!(divide_by_count(ONE, (1 << 53) + 1), 0x3ca0_0000_0000_0000);
    }

    #[test]
    fn exact_rounding_boundaries() {
        assert_eq!(round_dyadic(1, -1075, false), 0);
        assert_eq!(round_dyadic(3, -1075, false), 2);
        assert_eq!(
            round_dyadic((1 << 53) - 1, -1075, false),
            0x0010_0000_0000_0000
        );
        assert_eq!(round_dyadic((1 << 54) - 1, 970, false), INFINITY);
        assert_eq!(
            round_dyadic((1 << 54) - 2, 970, false),
            0x7fef_ffff_ffff_ffff
        );
        assert_eq!(divide_by_count(SIGN | 1, 2), SIGN);
        assert_eq!(divide_by_count(3, 2), 2);
    }

    #[test]
    fn alignment_cancellation_and_nan_sign() {
        assert_eq!(add(ONE, SIGN | 1), ONE);
        assert_eq!(add(ONE, 0xbca0_0000_0000_0000), 0x3fef_ffff_ffff_ffff);
        assert_eq!(add(ONE, ONE | SIGN), 0);
        assert_eq!(subtract(ONE, 0xfff0_0000_0000_0123), 0xfff8_0000_0000_0123);
        assert_eq!(multiply(INFINITY, 0), INDEFINITE);
    }
}
