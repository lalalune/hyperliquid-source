//! Node94 unwindless population-count helper and its u32 field caller.
#![no_std]
#![forbid(unsafe_code)]

/// Count set bits using the target's bounded lane reductions and u32 folds.
/// Reconstructs low returned bits at ELF VA 0x5660010..0x5660072.
pub const fn count_bits(word: u64) -> u32 {
    let pairs = word.wrapping_sub((word >> 1) & 0x5555_5555_5555_5555);
    let nibbles = (pairs & 0x3333_3333_3333_3333) + ((pairs >> 2) & 0x3333_3333_3333_3333);
    let bytes = (nibbles + (nibbles >> 4)) & 0x0f0f_0f0f_0f0f_0f0f;
    let halves = (bytes as u32).wrapping_add((bytes >> 32) as u32);
    let quarters = halves.wrapping_add(halves >> 16);
    quarters.wrapping_add(quarters >> 8) & 0x7f
}

/// Value projection of the u32 field loaded by caller 0x4f9eb90..0x4f9eba5.
/// The original load is little-endian at object offset 0x40; this API takes
/// that decoded field and does not expose the original pointer/stack ABI.
pub const fn count_field(field: u32) -> u32 {
    count_bits(field as u64)
}

#[cfg(test)]
mod tests {
    use super::{count_bits, count_field};

    #[test]
    fn full_count_needs_seven_bits() {
        assert_eq!(count_bits(0), 0);
        assert_eq!(count_bits(u64::MAX), 64);
        assert_eq!(count_bits(0xaaaa_aaaa_aaaa_aaaa), 32);
    }

    #[test]
    fn high_input_bits_and_zero_extended_field() {
        assert_eq!(count_bits(1_u64 << 63), 1);
        assert_eq!(count_bits(0xffff_0000_0000_0001), 17);
        assert_eq!(count_field(u32::MAX), 32);
        assert_eq!(count_field(0x8000_0000), 1);
    }
}
