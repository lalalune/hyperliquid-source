//! Pure supplied-binary64 duration values qualified by RE-013 evidence.
//!
//! This preserves the captured converter's unusual large-input discontinuity.
//! It does not read a clock, change floating state, sleep or execute native code.
#![forbid(unsafe_code)]

const BILLION: u128 = 1_000_000_000;
const FIRST_SCALED_OVERFLOW: u64 = 0x7eb0_c6f7_a0b5_ed8d;

/// Canonical seconds and nanoseconds from the qualified value conversion.
///
/// Private fields ensure that nanoseconds is always less than one billion.
/// This is a new safe API, not the captured native layout or ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurationValue {
    seconds: u64,
    nanoseconds: u32,
}

impl DurationValue {
    /// The whole seconds component.
    pub const fn seconds(self) -> u64 {
        self.seconds
    }

    /// The remainder, always in `0..1_000_000_000`.
    pub const fn nanoseconds(self) -> u32 {
        self.nanoseconds
    }
}

/// Convert any raw binary64 encoding to the evidence-qualified duration pair.
///
/// Nonpositive and nonfinite inputs yield zero. Positive inputs below 2^64
/// round exact nanoseconds to nearest, ties to even. Larger finite inputs yield
/// the microsecond-derived maximum pair until their million-fold binary64
/// product overflows; those overflowing inputs yield zero again.
///
/// Only bounded integer arithmetic is used. Native correspondence is conditional
/// on the floating/loader/frame premises in the packet; this host API needs no
/// particular floating environment and makes no native execution claim.
pub fn convert_bits(bits: u64) -> DurationValue {
    let exponent = ((bits >> 52) & 0x7ff) as u32;
    let zero = DurationValue {
        seconds: 0,
        nanoseconds: 0,
    };
    if bits >> 63 != 0 || exponent == 0x7ff || exponent < 992 {
        return zero;
    }
    if exponent >= 1087 {
        if bits >= FIRST_SCALED_OVERFLOW {
            return zero;
        }
        return DurationValue {
            seconds: u64::MAX / 1_000_000,
            nanoseconds: ((u64::MAX % 1_000_000) * 1000) as u32,
        };
    }
    let significand = u128::from((bits & 0x000f_ffff_ffff_ffff) | (1_u64 << 52));
    let numerator = significand * BILLION;
    let total_nanoseconds = if exponent >= 1075 {
        numerator << (exponent - 1075)
    } else {
        let shift = 1075 - exponent;
        let quotient = numerator >> shift;
        let remainder = numerator & ((1_u128 << shift) - 1);
        let halfway = 1_u128 << (shift - 1);
        quotient + u128::from(remainder > halfway || (remainder == halfway && quotient & 1 == 1))
    };
    DurationValue {
        seconds: (total_nanoseconds / BILLION) as u64,
        nanoseconds: (total_nanoseconds % BILLION) as u32,
    }
}
