#![no_std]

//! Logical projection of the two fraction conversions in the node #115
//! outcome-settlement routine at `0x3bf2be0`.
//!
//! The evidence packet records the target-bound instruction and dataflow proof.
//! This module does not model its lookup or token-tag prerequisites.

/// One independently scaled integer and its target-defined complement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScaleProjection {
    pub value: u64,
    pub complement: u64,
}

/// The coarse conversion rejects values whose truncated integer exceeds 1000.
/// This descriptive Rust error does not claim the original native error type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoarseOutOfRange;

/// Multiplies the original input by 1000, truncates with native u64
/// saturation, then returns the value and `1000 - value` when value is <=1000.
pub fn coarse_scale(input: f64) -> Result<ScaleProjection, CoarseOutOfRange> {
    let value = scaled_u64(input * 1_000.0);
    if value > 1_000 {
        return Err(CoarseOutOfRange);
    }
    Ok(ScaleProjection {
        value,
        complement: 1_000 - value,
    })
}

/// Independently multiplies the original input by 100,000,000, truncates with
/// native u64 saturation, then returns `max(0, 100000000 - value)`.
pub fn fine_scale(input: f64) -> ScaleProjection {
    let value = scaled_u64(input * 100_000_000.0);
    ScaleProjection {
        value,
        complement: 100_000_000u64.saturating_sub(value),
    }
}

fn scaled_u64(product: f64) -> u64 {
    if !product.is_finite() || product <= 0.0 {
        0
    } else if product >= 18_446_744_073_709_551_616.0 {
        u64::MAX
    } else {
        product as u64
    }
}

#[cfg(test)]
mod tests {
    use super::{CoarseOutOfRange, ScaleProjection, coarse_scale, fine_scale};

    #[test]
    fn matches_the_packet_binary64_examples() {
        let input_0009 = f64::from_bits(0x3f4d_7dbf_487f_cb92);
        let input_10005 = f64::from_bits(0x3ff0_020c_49ba_5e35);
        let input_1001 = f64::from_bits(0x3ff0_0418_9374_bc6a);

        assert_eq!(
            coarse_scale(input_0009),
            Ok(ScaleProjection {
                value: 0,
                complement: 1_000,
            })
        );
        assert_eq!(
            fine_scale(input_0009),
            ScaleProjection {
                value: 90_000,
                complement: 99_910_000,
            }
        );
        assert_eq!(
            coarse_scale(input_10005),
            Ok(ScaleProjection {
                value: 1_000,
                complement: 0,
            })
        );
        assert_eq!(
            fine_scale(input_10005),
            ScaleProjection {
                value: 100_050_000,
                complement: 0,
            }
        );
        assert_eq!(
            coarse_scale(input_1001),
            Ok(ScaleProjection {
                value: 1_000,
                complement: 0,
            })
        );
        assert_eq!(
            fine_scale(input_1001),
            ScaleProjection {
                value: 100_099_999,
                complement: 0,
            }
        );
    }

    #[test]
    fn coarse_path_accepts_exact_limit_and_rejects_above_it() {
        assert_eq!(
            coarse_scale(1.0),
            Ok(ScaleProjection {
                value: 1_000,
                complement: 0,
            })
        );
        assert_eq!(coarse_scale(1.002), Err(CoarseOutOfRange));
    }

    #[test]
    fn nonfinite_and_negative_products_become_zero() {
        for input in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.5, -0.0] {
            assert_eq!(
                coarse_scale(input),
                Ok(ScaleProjection {
                    value: 0,
                    complement: 1_000,
                })
            );
            assert_eq!(
                fine_scale(input),
                ScaleProjection {
                    value: 0,
                    complement: 100_000_000,
                }
            );
        }
    }

    #[test]
    fn fine_value_saturates_at_u64_max_and_complement_at_zero() {
        assert_eq!(
            fine_scale(1.0e17),
            ScaleProjection {
                value: u64::MAX,
                complement: 0,
            }
        );
    }
}
