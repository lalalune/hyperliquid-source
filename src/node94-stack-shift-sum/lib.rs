//! Value reconstruction of node #94 [0x55c6c40, 0x55c6c77).
//!
//! Arguments are the three raw u32 words observed at entry RSP+8/+12/+16.
//! This Rust value API does not reproduce the captured stack ABI or faults.
#![no_std]
#![forbid(unsafe_code)]

/// Computes the raw u64 result for every u32 triple.
///
/// Only `flag == 1` activates the calculation. Both shift counts wrap modulo
/// 64 and the final addition wraps modulo 2^64. An active input can return zero.
pub const fn shift_sum(flag: u32, first: u32, second: u32) -> u64 {
    if flag != 1 {
        return 0;
    }
    let distance = first.saturating_sub(second);
    1_u64
        .wrapping_shl(distance)
        .wrapping_add(8_u64.wrapping_shl(first))
}

#[cfg(test)]
mod tests {
    use super::shift_sum;

    #[test]
    fn gate_and_unsigned_order() {
        assert_eq!(shift_sum(0, 5, 3), 0);
        assert_eq!(shift_sum(2, 5, 3), 0);
        assert_eq!(shift_sum(0x8000_0001, 5, 3), 0);
        assert_eq!(shift_sum(1, 5, 3), 260);
        assert_eq!(shift_sum(1, 3, 5), 65);
        assert_eq!(shift_sum(1, 1, 0x8000_0000), 17);
        assert_eq!(shift_sum(1, 0x8000_0001, 0), 18);
    }

    #[test]
    fn masked_counts_and_discarded_high_bits() {
        assert_eq!(shift_sum(1, 0, 0), 9);
        assert_eq!(shift_sum(1, 64, 0), 9);
        assert_eq!(shift_sum(1, 65, 65), 17);
        assert_eq!(shift_sum(1, 70, 0), 576);
        assert_eq!(shift_sum(1, 61, 61), 1);
        assert_eq!(shift_sum(1, u32::MAX, 0), 1_u64 << 63);
    }

    #[test]
    fn active_zero_requires_wrapping_sum() {
        assert_eq!(shift_sum(1, 124, 61), 0);
        assert_eq!(shift_sum(1, 124, 60), (1_u64 << 63) + 1);
        assert_eq!(shift_sum(1, 124, 62), 3_u64 << 62);
        assert_eq!(shift_sum(1, 60, 61), (1_u64 << 63) + 1);
    }
}
