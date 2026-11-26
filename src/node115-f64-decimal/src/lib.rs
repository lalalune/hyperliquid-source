//! The finite binary64-to-decimal branch used by native 0x43099f0.
//! This does not implement text parsing or the preceding decimal parser. It
//! projects native 0x5c43c60 with both caller flags set to one, using u128
//! arithmetic to represent the native three-u32 coefficient without overflow.

const MAX_COEFFICIENT: u128 = (1_u128 << 96) - 1;
const PRECISION_BOUNDARY: u128 = 1_u128 << 52;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decimal96 {
    pub coefficient: u128,
    pub scale: u32,
    pub negative: bool,
}
impl Decimal96 {
    /// Native decimal storage is flags, high32, low32, middle32, all little endian.
    pub fn words(self) -> [u32; 4] {
        [
            (self.scale << 16) | (u32::from(self.negative) << 31),
            (self.coefficient >> 64) as u32,
            self.coefficient as u32,
            (self.coefficient >> 32) as u32,
        ]
    }
}

/// Returns None for NaN, infinity, or a coefficient exceeding 96 bits at scale 0.
/// Signed zero is retained. Very small magnitudes can become signed scale-0 zero.
/// The rounding is the recovered decimal procedure, not exact rational rounding
/// to a chosen number of decimal places or a generic shortest-float formatter.
pub fn from_f64_bits(bits: u64) -> Option<Decimal96> {
    let negative = bits >> 63 != 0;
    let exponent_bits = ((bits >> 52) & 0x7ff) as i32;
    if exponent_bits == 0x7ff {
        return None;
    }
    let fraction = bits & ((1_u64 << 52) - 1);
    if exponent_bits == 0 && fraction == 0 {
        return Some(Decimal96 {
            coefficient: 0,
            scale: 0,
            negative,
        });
    }
    let (coefficient, binary_exponent) = if exponent_bits == 0 {
        (u128::from(fraction), -1074)
    } else {
        (u128::from(fraction | (1_u64 << 52)), exponent_bits - 1075)
    };
    from_binary_parts(coefficient, binary_exponent, negative)
}

/// Integer kernel for the native caller's `is64=true, round=true` mode.
/// Coefficients must fit 96 bits and exponents be within -1074..=1023.
/// These are host-interface bounds, not new native rejection rules. The binary64
/// entry point additionally handles nonfinite values and signed zero directly.
pub fn from_binary_parts(
    mut coefficient: u128,
    binary_exponent: i32,
    negative: bool,
) -> Option<Decimal96> {
    if coefficient > MAX_COEFFICIENT || !(-1074..=1023).contains(&binary_exponent) {
        return None;
    }
    let mut decimal_exponent = binary_exponent;
    if binary_exponent > 0 {
        for _ in 0..binary_exponent {
            if coefficient >= (1_u128 << 95) {
                coefficient /= 5;
            } else {
                coefficient *= 2;
                decimal_exponent -= 1;
            }
        }
    } else {
        for _ in binary_exponent..0 {
            if coefficient & 1 == 0 || coefficient * 5 > MAX_COEFFICIENT {
                coefficient >>= 1;
                decimal_exponent += 1;
            } else {
                coefficient *= 5;
            }
        }
    }
    while decimal_exponent > 0 {
        coefficient *= 10;
        if coefficient > MAX_COEFFICIENT {
            return None;
        }
        decimal_exponent -= 1;
    }
    while decimal_exponent < -28 {
        // Native exits as scale-0 zero before rounding once this division's
        // quotient is zero; an isolated remainder >=5 does not revive it.
        if coefficient < 10 {
            coefficient = 0;
            decimal_exponent = 0;
            break;
        }
        coefficient = round_divide_ten(coefficient);
        decimal_exponent += 1;
    }
    while decimal_exponent < 0 && coefficient >= PRECISION_BOUNDARY {
        coefficient = round_divide_ten(coefficient);
        decimal_exponent += 1;
    }
    while decimal_exponent < 0 && coefficient.is_multiple_of(10) {
        coefficient /= 10;
        decimal_exponent += 1;
    }
    Some(Decimal96 {
        coefficient,
        scale: (-decimal_exponent) as u32,
        negative,
    })
}
fn round_divide_ten(value: u128) -> u128 {
    value / 10 + u128::from(value % 10 >= 5)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nonfinite_and_signed_zero_are_distinct() {
        for bits in [
            f64::INFINITY.to_bits(),
            f64::NEG_INFINITY.to_bits(),
            0x7ff0000000000001,
            0xfff8000000000000,
        ] {
            assert_eq!(from_f64_bits(bits), None);
        }
        for negative in [false, true] {
            let zero = from_f64_bits(u64::from(negative) << 63).unwrap();
            assert_eq!(
                zero,
                Decimal96 {
                    coefficient: 0,
                    scale: 0,
                    negative
                }
            );
            assert_eq!(zero.words(), [u32::from(negative) << 31, 0, 0, 0]);
        }
    }
    #[test]
    fn exact_integer_and_decimal_boundaries() {
        for (value, coefficient, scale) in [
            (1.0, 1, 0),
            (0.5, 5, 1),
            (0.1, 1, 1),
            (1.25, 125, 2),
            (10.0, 10, 0),
        ] {
            for negative in [false, true] {
                let value: f64 = if negative { -value } else { value };
                assert_eq!(
                    from_f64_bits(value.to_bits()),
                    Some(Decimal96 {
                        coefficient,
                        scale,
                        negative
                    })
                );
            }
        }
        assert_eq!(
            from_f64_bits((2_f64.powi(96)).to_bits()),
            Some(Decimal96 {
                coefficient: (1_u128 << 96) - 6,
                scale: 0,
                negative: false
            })
        );
        assert_eq!(from_f64_bits((2_f64.powi(96)).to_bits() + 1), None);
        assert_eq!(from_f64_bits(f64::MAX.to_bits()), None);
        assert!(from_f64_bits((2_f64.powi(95)).to_bits()).is_some());
        assert_eq!(
            from_f64_bits(1),
            Some(Decimal96 {
                coefficient: 0,
                scale: 0,
                negative: false
            })
        );
    }
}
