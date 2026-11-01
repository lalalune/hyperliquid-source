//! Scalar value reconstruction of two node94 binary64 leaves.
#![no_std]
#![forbid(unsafe_code)]

const SIGN: u64 = 1 << 63;

/// Truncate toward zero, preserving signed zero and every NaN payload bit.
/// Reconstructs ELF VA 0x565f490..0x565f4e5, independently of floating mode.
pub const fn trunc_bits(bits: u64) -> u64 {
    let exponent = (bits >> 52) & 2047;
    if exponent >= 1075 {
        return bits;
    }
    if exponent < 1023 {
        return bits & SIGN;
    }
    let unit = 1_u64 << (1075 - exponent);
    bits & !(unit - 1)
}

/// Return the low 64 output bits of ELF VA 0x565f6f0..0x565f784.
///
/// `daz` specifies the target MXCSR denormals-are-zero bit, not the host mode.
/// With DAZ clear, negative subnormals require the denormal exception masked
/// for normal return. With DAZ set, the target returns those input bits intact.
/// This models returned bits only; exception flags and upper XMM bits are omitted.
pub const fn floor_bits(bits: u64, daz: bool) -> u64 {
    let exponent = (bits >> 52) & 2047;
    if exponent >= 1075 {
        return bits;
    }
    if exponent < 1023 {
        if bits & SIGN == 0 {
            return 0;
        }
        if bits == SIGN || (daz && exponent == 0) {
            return bits;
        }
        return 0xbff0_0000_0000_0000;
    }
    let truncated = trunc_bits(bits);
    if bits & SIGN != 0 && truncated != bits {
        truncated + (1_u64 << (1075 - exponent))
    } else {
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::{floor_bits, trunc_bits};

    #[test]
    fn negative_subnormal_comparison_preserves_raw_bits_only_with_daz() {
        for bits in [0x8000_0000_0000_0001, 0x800f_ffff_ffff_ffff] {
            assert_eq!(trunc_bits(bits), 1 << 63);
            assert_eq!(floor_bits(bits, false), 0xbff0_0000_0000_0000);
            assert_eq!(floor_bits(bits, true), bits);
        }
    }

    #[test]
    fn signs_ties_and_exceptional_bits() {
        for (bits, trunc, floor) in [
            (0, 0, 0),
            (1 << 63, 1 << 63, 1 << 63),
            (
                0x3ff8_0000_0000_0000,
                0x3ff0_0000_0000_0000,
                0x3ff0_0000_0000_0000,
            ),
            (
                0xbff8_0000_0000_0000,
                0xbff0_0000_0000_0000,
                0xc000_0000_0000_0000,
            ),
            (
                0x7ff0_0000_0000_0001,
                0x7ff0_0000_0000_0001,
                0x7ff0_0000_0000_0001,
            ),
        ] {
            assert_eq!(trunc_bits(bits), trunc);
            assert_eq!(floor_bits(bits, false), floor);
            assert_eq!(floor_bits(bits, true), floor);
        }
    }
}
