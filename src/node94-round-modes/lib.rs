//! Returned-bit reconstruction of node94 ELF VA 0x565f410..0x565f481.
#![no_std]
#![forbid(unsafe_code)]

/// Target MXCSR.RC values, independent of the host's floating environment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RoundingMode {
    NearestEven = 0,
    TowardNegative = 1,
    TowardPositive = 2,
    TowardZero = 3,
}

/// Project the target's normal returned low 64 bits with SIMD exceptions masked.
///
/// The target adds a same-sign `(0.5 - 2^-54)` before truncating. Its return
/// depends on the addition's rounding mode, and it quiets signaling NaNs.
/// DAZ/FTZ do not change these returned bits. Flags/traps and upper XMM lanes
/// are outside this API; no host floating operation or state change occurs.
pub const fn round_bits(bits: u64, mode: RoundingMode) -> u64 {
    let sign = bits & (1 << 63);
    let exponent = (bits >> 52) & 2047;
    let fraction = bits & 0x000f_ffff_ffff_ffff;
    if exponent == 2047 {
        return if fraction == 0 {
            bits
        } else {
            bits | (1 << 51)
        };
    }
    let increase_magnitude = matches!(mode, RoundingMode::TowardNegative) && sign != 0
        || matches!(mode, RoundingMode::TowardPositive) && sign == 0;
    if exponent >= 1075 {
        return bits + increase_magnitude as u64;
    }
    let half_away = matches!(mode, RoundingMode::NearestEven) || increase_magnitude;
    if exponent < 1022 {
        return sign;
    }
    if exponent == 1022 {
        return sign
            | if fraction != 0 || half_away {
                0x3ff0_0000_0000_0000
            } else {
                0
            };
    }
    let unit = 1_u64 << (1075 - exponent);
    let remainder = bits & (unit - 1);
    let integer = bits & !(unit - 1);
    if remainder > unit / 2 || (remainder == unit / 2 && half_away) {
        integer + unit
    } else {
        integer
    }
}

#[cfg(test)]
mod tests {
    use super::{RoundingMode::*, round_bits};

    #[test]
    fn modes_change_halves_and_large_integer_successors() {
        let modes = [NearestEven, TowardNegative, TowardPositive, TowardZero];
        for (bits, expected) in [
            (
                0x3fe0_0000_0000_0000,
                [0x3ff0_0000_0000_0000, 0, 0x3ff0_0000_0000_0000, 0],
            ),
            (
                0xbfe0_0000_0000_0000,
                [
                    0xbff0_0000_0000_0000,
                    0xbff0_0000_0000_0000,
                    1 << 63,
                    1 << 63,
                ],
            ),
            (
                0x4330_0000_0000_0000,
                [
                    0x4330_0000_0000_0000,
                    0x4330_0000_0000_0000,
                    0x4330_0000_0000_0001,
                    0x4330_0000_0000_0000,
                ],
            ),
        ] {
            for (mode, want) in modes.into_iter().zip(expected) {
                assert_eq!(round_bits(bits, mode), want);
            }
        }
    }

    #[test]
    fn signed_zero_nan_payload_and_overflow() {
        assert_eq!(round_bits(1 << 63, TowardPositive), 1 << 63);
        assert_eq!(
            round_bits(0x7ff0_0000_0000_0001, TowardZero),
            0x7ff8_0000_0000_0001
        );
        assert_eq!(
            round_bits(0xfff8_0000_0000_0001, NearestEven),
            0xfff8_0000_0000_0001
        );
        assert_eq!(
            round_bits(0x7fef_ffff_ffff_ffff, TowardPositive),
            0x7ff0_0000_0000_0000
        );
        assert_eq!(
            round_bits(0x7fef_ffff_ffff_ffff, NearestEven),
            0x7fef_ffff_ffff_ffff
        );
    }
}
