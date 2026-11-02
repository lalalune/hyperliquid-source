#![no_std]
#![forbid(unsafe_code)]

/// Value returned by node #94's leaf at ELF VA 0x546af50 for raw RDI bits.
///
/// The complete u64 domain is accepted, including sums that wrap modulo 2^64.
/// The name describes the inferred compression library, not an original symbol.
pub const fn snappy_bound(input_len: u64) -> u64 {
    input_len.wrapping_add(input_len / 6).wrapping_add(32)
}

/// Value returned by node #94's leaf at ELF VA 0x546e280 for raw EDI bits.
///
/// Inputs above 0x7e000000 return zero, including every negative i32 bit pattern.
/// An admitted input returns a bound that fits in u32 without overflow.
pub const fn lz4_bound(input_bits: u32) -> u32 {
    if input_bits > 0x7e00_0000 {
        0
    } else {
        input_bits + input_bits / 255 + 16
    }
}

#[cfg(test)]
mod tests {
    use super::{lz4_bound, snappy_bound};

    #[test]
    fn empty_and_first_quotient_steps() {
        assert_eq!(snappy_bound(0), 32);
        assert_eq!(snappy_bound(5), 37);
        assert_eq!(snappy_bound(6), 39);
        assert_eq!(lz4_bound(0), 16);
        assert_eq!(lz4_bound(254), 270);
        assert_eq!(lz4_bound(255), 272);
    }

    #[test]
    fn u64_sum_wraps() {
        assert_eq!(snappy_bound(u64::MAX), 3_074_457_345_618_258_633);
        assert_eq!(snappy_bound(65_536), 76_490);
    }

    #[test]
    fn inclusive_unsigned_limit() {
        assert_eq!(lz4_bound(0x7e00_0000), 0x7e7e_7e8e);
        for bits in [0x7e00_0001, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
            assert_eq!(lz4_bound(bits), 0);
        }
    }
}
