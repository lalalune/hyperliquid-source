#![no_std]

//! The five-significant-digit truncation leaf observed at node #115 `0x269d520`.
//!
//! This exposes only the mathematical input and output of the leaf, not its
//! native register ABI, source name, type or units.

/// Scale selection observed in the target: the first upper bound (exclusive)
/// that the input is below chooses the paired scale. Inputs of 10^19 and above
/// use 10^15.
const LADDER: [(u64, u64); 15] = [
    (100_000, 1),
    (1_000_000, 10),
    (10_000_000, 100),
    (100_000_000, 1_000),
    (1_000_000_000, 10_000),
    (10_000_000_000, 100_000),
    (100_000_000_000, 1_000_000),
    (1_000_000_000_000, 10_000_000),
    (10_000_000_000_000, 100_000_000),
    (100_000_000_000_000, 1_000_000_000),
    (1_000_000_000_000_000, 10_000_000_000),
    (10_000_000_000_000_000, 100_000_000_000),
    (100_000_000_000_000_000, 1_000_000_000_000),
    (1_000_000_000_000_000_000, 10_000_000_000_000),
    (10_000_000_000_000_000_000, 100_000_000_000_000),
];
const TOP_SCALE: u64 = 1_000_000_000_000_000;

/// Returns the scale `10^max(0, digits(value) - 5)` that the target selects.
#[must_use]
pub fn scale(value: u64) -> u64 {
    for (bound, scale) in LADDER {
        if value < bound {
            return scale;
        }
    }
    TOP_SCALE
}

/// Rounds `value` down to five significant decimal digits.
///
/// Values below 100,000 are returned unchanged. The target multiplies the
/// quotient back and returns `u64::MAX` on overflow, i.e. a saturating
/// multiply; saturation cannot occur because the product never exceeds the
/// input, but it is kept to mirror the observed instructions.
#[must_use]
pub fn truncate(value: u64) -> u64 {
    let scale = scale(value);
    (value / scale).saturating_mul(scale)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::{scale, truncate};
    use std::string::ToString;

    /// Independent definition: keep the first five decimal digits, zero the rest.
    fn reference(value: u64) -> u64 {
        let text = value.to_string();
        if text.len() <= 5 {
            return value;
        }
        let kept: u64 = text[..5].parse().unwrap();
        kept * 10u64.pow((text.len() - 5) as u32)
    }

    #[test]
    fn small_values_are_unchanged() {
        for value in [0, 1, 9, 10, 99_999] {
            assert_eq!(truncate(value), value);
        }
    }

    #[test]
    fn examples() {
        assert_eq!(truncate(100_000), 100_000);
        assert_eq!(truncate(123_456), 123_450);
        assert_eq!(truncate(999_999), 999_990);
        assert_eq!(truncate(1_234_567_890), 1_234_500_000);
        assert_eq!(truncate(u64::MAX), 18_446_000_000_000_000_000);
    }

    #[test]
    fn every_power_of_ten_boundary() {
        let mut power = 1u64;
        loop {
            for value in [power - 1, power, power + 1] {
                assert_eq!(truncate(value), reference(value), "{value}");
            }
            assert_eq!(
                scale(power),
                10u64.pow((power.to_string().len() as u32).saturating_sub(5))
            );
            match power.checked_mul(10) {
                Some(next) => power = next,
                None => break,
            }
        }
        for value in [u64::MAX - 1, u64::MAX] {
            assert_eq!(truncate(value), reference(value));
        }
    }

    #[test]
    fn result_never_exceeds_input_and_keeps_five_digits() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let value = state >> (state % 64);
            let out = truncate(value);
            assert_eq!(out, reference(value), "{value}");
            assert!(out <= value);
            assert!(value - out < scale(value));
        }
    }
}
