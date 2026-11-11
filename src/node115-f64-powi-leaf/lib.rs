#![no_std]

//! Safe logical projection of the node #115 leaf at `0x63f0080`.
//!
//! The likely compiler-builtin identity is unconfirmed. This module records
//! only the value operation established by the target-bound static evidence.

/// Computes the target leaf's binary64 integer-power operation.
///
/// The exponent is interpreted by unsigned magnitude, the low bit selects an
/// initial `base` or `1.0`, later set bits multiply in successive squares, and
/// negative exponents reciprocate the final result. The multiply order is
/// intentionally explicit; this does not claim the source ABI or every
/// platform's `f64::powi` implementation.
pub fn powi_leaf(base: f64, exponent: i32) -> f64 {
    let mut magnitude = exponent.unsigned_abs();
    let mut factor = base;
    let mut result = if magnitude & 1 == 1 { base } else { 1.0 };
    magnitude >>= 1;

    while magnitude != 0 {
        factor *= factor;
        if magnitude & 1 == 1 {
            result *= factor;
        }
        magnitude >>= 1;
    }

    if exponent < 0 { 1.0 / result } else { result }
}

#[cfg(test)]
mod tests {
    use super::powi_leaf;

    fn independent_binary_power(base: f64, exponent: i32) -> f64 {
        let mut magnitude = exponent.unsigned_abs();
        let mut factor = base;
        let mut result = 1.0;
        while magnitude != 0 {
            if magnitude & 1 == 1 {
                result *= factor;
            }
            magnitude >>= 1;
            if magnitude != 0 {
                factor *= factor;
            }
        }
        if exponent < 0 { 1.0 / result } else { result }
    }

    #[test]
    fn matches_independent_binary_exponentiation_on_the_packet_grid() {
        let bases = [2.0, 0.5, -3.0, 1.5, 10.0, -1.0, 7.0];
        let exponents = [0, 1, 2, 3, 5, 8, 15, 31, -1, -2, -5, -8];
        for base in bases {
            for exponent in exponents {
                assert_eq!(
                    powi_leaf(base, exponent).to_bits(),
                    independent_binary_power(base, exponent).to_bits(),
                    "base={base} exponent={exponent}"
                );
            }
        }
    }

    #[test]
    fn zero_and_signed_exponents_preserve_the_observed_rule() {
        assert_eq!(powi_leaf(f64::NAN, 0).to_bits(), 1.0f64.to_bits());
        assert_eq!(powi_leaf(-0.0, 1).to_bits(), (-0.0f64).to_bits());
        assert_eq!(powi_leaf(-0.0, -3), f64::NEG_INFINITY);
        assert_eq!(powi_leaf(-0.0, -2), f64::INFINITY);
        assert_eq!(powi_leaf(-3.0, 4), 81.0);
        assert_eq!(powi_leaf(-3.0, -3), -1.0 / 27.0);
    }

    #[test]
    fn handles_the_full_i32_exponent_magnitude() {
        for base in [1.0, -1.0, 0.5, 2.0, 0.0, -0.0] {
            assert_eq!(
                powi_leaf(base, i32::MIN).to_bits(),
                independent_binary_power(base, i32::MIN).to_bits(),
                "base={base} exponent=i32::MIN"
            );
        }
    }
}
