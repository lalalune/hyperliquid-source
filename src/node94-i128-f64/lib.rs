//! Integer-only returned-bit reconstruction of node94 VA 0x565f4f0..0x565f598.
#![no_std]
#![forbid(unsafe_code)]

/// Convert a signed 128-bit value to binary64 bits with nearest-even rounding.
///
/// The complete target leaf uses integer instructions, so its returned bits do
/// not depend on MXCSR rounding mode. This value API does not recover its ABI.
pub const fn to_binary64_bits(value: i128) -> u64 {
    if value == 0 {
        return 0;
    }
    let sign = if value < 0 { 1_u64 << 63 } else { 0 };
    let magnitude = value.unsigned_abs();
    let exponent = 127 - magnitude.leading_zeros();
    let (significand, increment) = if exponent <= 52 {
        ((magnitude << (52 - exponent)) as u64, false)
    } else {
        let shift = exponent - 52;
        let retained = (magnitude >> shift) as u64;
        let discarded = magnitude & ((1_u128 << shift) - 1);
        let halfway = 1_u128 << (shift - 1);
        (
            retained,
            discarded > halfway || (discarded == halfway && retained & 1 != 0),
        )
    };
    // Including the implicit significand bit in this sum handles a rounding
    // carry into the next exponent without a special overflow branch.
    sign | (((exponent as u64 + 1022) << 52) + significand + increment as u64)
}

#[cfg(test)]
mod tests {
    use super::to_binary64_bits;

    #[test]
    fn extremes_and_exact_values() {
        assert_eq!(to_binary64_bits(0), 0);
        assert_eq!(to_binary64_bits(1), 0x3ff0_0000_0000_0000);
        assert_eq!(to_binary64_bits(-1), 0xbff0_0000_0000_0000);
        assert_eq!(to_binary64_bits(i128::MIN), 0xc7e0_0000_0000_0000);
        assert_eq!(to_binary64_bits(i128::MAX), 0x47e0_0000_0000_0000);
    }

    #[test]
    fn halfways_keep_even_and_carry() {
        let power = 1_i128 << 53;
        assert_eq!(to_binary64_bits(power + 1), 0x4340_0000_0000_0000);
        assert_eq!(to_binary64_bits(power + 3), 0x4340_0000_0000_0002);
        assert_eq!(to_binary64_bits(-(power + 3)), 0xc340_0000_0000_0002);
        assert_eq!(to_binary64_bits((1_i128 << 54) - 1), 0x4350_0000_0000_0000);
    }
}
