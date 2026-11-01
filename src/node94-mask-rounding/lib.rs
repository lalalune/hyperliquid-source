//! Returned-u64 contract of node94 ELF VA 0x555e610..0x555e65b.
#![no_std]
#![forbid(unsafe_code)]

const CUTOFF: u64 = 0xff00_ff00_ff00_feff;
const SENTINEL_BITS: u64 = 0xffff_ffff_ffff_ffb8;

/// Compute the captured leaf's raw return bits for every u64 input.
///
/// Inputs above the inclusive cutoff return the bits of signed -72. That value
/// is also produced by an admitted input, so it is not an exclusive error tag.
/// Admitted arithmetic never overflows or reaches the target's zero fallback.
pub const fn bound_value(input: u64) -> u64 {
    if input > CUTOFF {
        return SENTINEL_BITS;
    }
    let correction = if input < 0x20000 {
        (0x20000 - input) >> 11
    } else {
        0
    };
    input.wrapping_add(input >> 8).wrapping_add(correction)
}

#[cfg(test)]
mod tests {
    use super::bound_value;

    #[test]
    fn small_rounding_boundaries() {
        for (input, expected) in [
            (0, 64),
            (1, 64),
            (255, 318),
            (256, 320),
            (2048, 2119),
            (2049, 2119),
            (0x1ffff, 0x201fe),
            (0x20000, 0x20200),
        ] {
            assert_eq!(bound_value(input), expected);
        }
    }

    #[test]
    fn cutoff_is_inclusive_and_precedes_arithmetic() {
        assert_eq!(bound_value(0xff00_ff00_ff00_feff), u64::MAX - 2);
        for input in [
            0xff00_ff00_ff00_ff00,
            0xff00_ff00_ff00_ff01,
            0xff00_ff00_ff00_ff02,
            u64::MAX,
        ] {
            assert_eq!(bound_value(input), 0xffff_ffff_ffff_ffb8);
        }
    }

    #[test]
    fn admitted_value_can_equal_the_sentinel() {
        assert_eq!(bound_value(0xff00_ff00_ff00_feba), 0xffff_ffff_ffff_ffb8);
    }
}
