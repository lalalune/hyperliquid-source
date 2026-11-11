#![no_std]
//! Logical register projection of node #115's finite-ratio leaf at `0x14ca350`.
#![forbid(unsafe_code)]

/// Raw binary64 encoding of the target's rounded `1e-15` threshold.
pub const EPSILON_BITS: u64 = 0x3cd2_03af_9ee7_5616;

const SIGN_BIT: u64 = 1 << 63;
const ABS_MASK: u64 = SIGN_BIT - 1;
const MAX_FINITE_BITS: u64 = 0x7fef_ffff_ffff_ffff;

/// The two relevant output registers of the selected leaf.
///
/// This is a logical projection, not the original function's source type or
/// ABI. `xmm0_bits` keeps exact zero signs and NaN payload bits when an early
/// nonfinite-input return preserves the incoming numerator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Projection {
    /// Observed integer return register: zero or one.
    pub rax: u64,
    /// Observed low 64 bits of XMM0 on return.
    pub xmm0_bits: u64,
}

const fn rejected(xmm0_bits: u64) -> Projection {
    Projection { rax: 0, xmm0_bits }
}

/// Projects the complete leaf for raw binary64 numerator and divisor bits.
///
/// The leaf first rejects nonfinite inputs while preserving the numerator in
/// XMM0. For finite inputs it clamps only numerators strictly inside
/// `(-epsilon, 0)` to positive zero, rejects values at or below `-epsilon`,
/// rejects divisors below epsilon, then divides and returns one exactly when
/// the quotient is finite. A rejected divisor returns the current numerator
/// bits; a nonfinite quotient remains in XMM0 with RAX zero.
///
/// The arithmetic projection assumes round-to-nearest/ties-to-even, masked
/// SSE exceptions, and DAZ/FTZ disabled, as required by the static evidence.
/// The target leaf does not establish or set that floating-point environment.
pub fn project_ratio(numerator_bits: u64, divisor_bits: u64) -> Projection {
    let numerator_abs = numerator_bits & ABS_MASK;
    let divisor_abs = divisor_bits & ABS_MASK;
    if numerator_abs > MAX_FINITE_BITS || divisor_abs > MAX_FINITE_BITS {
        return rejected(numerator_bits);
    }

    let mut numerator = f64::from_bits(numerator_bits);
    let divisor = f64::from_bits(divisor_bits);

    if numerator < 0.0 {
        let epsilon = f64::from_bits(EPSILON_BITS);
        if numerator <= -epsilon {
            return rejected(numerator_bits);
        }
        numerator = 0.0;
    }
    let current_numerator_bits = numerator.to_bits();

    if divisor < f64::from_bits(EPSILON_BITS) {
        return rejected(current_numerator_bits);
    }

    let quotient = numerator / divisor;
    Projection {
        rax: if quotient.is_finite() { 1 } else { 0 },
        xmm0_bits: quotient.to_bits(),
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::{project_ratio, Projection, EPSILON_BITS};

    #[test]
    fn all_frozen_target_vectors_match() {
        let mut count = 0;
        for line in include_str!("target-vectors.tsv").lines() {
            let mut fields = line.split('\t');
            let name = fields.next().expect("vector name");
            let numerator = fields.next().expect("numerator bits").parse().unwrap();
            let divisor = fields.next().expect("divisor bits").parse().unwrap();
            let rax = fields.next().expect("RAX").parse().unwrap();
            let xmm0_bits = fields.next().expect("XMM0 bits").parse().unwrap();
            assert!(fields.next().is_none(), "extra fields in {name}");
            assert_eq!(
                project_ratio(numerator, divisor),
                Projection { rax, xmm0_bits },
                "{name}"
            );
            count += 1;
        }
        assert_eq!(count, 28);
    }

    #[test]
    fn strict_negative_boundary_preserves_the_unclamped_value() {
        let negative_epsilon = (1 << 63) | EPSILON_BITS;
        let at_boundary = project_ratio(negative_epsilon, EPSILON_BITS);
        assert_eq!(
            at_boundary,
            Projection {
                rax: 0,
                xmm0_bits: negative_epsilon
            }
        );

        // The adjacent representable negative value closer to zero is inside
        // the strict clamp interval and becomes positive zero.
        let just_above_boundary = project_ratio(negative_epsilon - 1, EPSILON_BITS);
        assert_eq!(
            just_above_boundary,
            Projection {
                rax: 1,
                xmm0_bits: 0
            }
        );

        let just_below_boundary = project_ratio(negative_epsilon + 1, EPSILON_BITS);
        assert_eq!(
            just_below_boundary,
            Projection {
                rax: 0,
                xmm0_bits: negative_epsilon + 1
            }
        );
    }

    #[test]
    fn preserves_negative_zero_and_observed_xmm0_on_small_divisor() {
        let negative_zero = 1 << 63;
        assert_eq!(
            project_ratio(negative_zero, EPSILON_BITS),
            Projection {
                rax: 1,
                xmm0_bits: negative_zero
            }
        );

        let numerator = 1.0f64.to_bits();
        assert_eq!(
            project_ratio(numerator, EPSILON_BITS - 1),
            Projection {
                rax: 0,
                xmm0_bits: numerator
            }
        );
        assert_eq!(
            project_ratio(negative_epsilon_bits() - 1, EPSILON_BITS - 1),
            Projection {
                rax: 0,
                xmm0_bits: 0
            }
        );
    }

    #[test]
    fn nonfinite_input_and_quotient_preserve_the_observed_return_bits() {
        let numerator_nan = 0x7ff8_0000_0000_0042;
        assert_eq!(
            project_ratio(numerator_nan, EPSILON_BITS),
            Projection {
                rax: 0,
                xmm0_bits: numerator_nan
            }
        );

        let divisor_infinity = 0x7ff0_0000_0000_0000;
        assert_eq!(
            project_ratio(1.0f64.to_bits(), divisor_infinity),
            Projection {
                rax: 0,
                xmm0_bits: 1.0f64.to_bits()
            }
        );

        let overflow = project_ratio(f64::MAX.to_bits(), EPSILON_BITS);
        assert_eq!(overflow.rax, 0);
        assert_eq!(overflow.xmm0_bits, f64::INFINITY.to_bits());
    }

    fn negative_epsilon_bits() -> u64 {
        (1 << 63) | EPSILON_BITS
    }
}
