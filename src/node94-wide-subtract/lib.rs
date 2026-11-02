#![no_std]
#![forbid(unsafe_code)]

/// Ordered byte-image refinement, including overlapping operand and output ranges.
pub mod image;

/// Numeric projection of node94 VA 0x32d8310..0x32d8361.
///
/// The little-endian words form unsigned 256-bit values. Return their wrapping
/// difference and whether the left value is smaller than the right value.
/// All eight words may use their complete u64 domain.
/// This safe value API does not reproduce the captured pointer ABI, mutation
/// and copy order, pointer aliasing, register return value or memory faults.
#[inline(never)]
pub fn subtract_words(left: [u64; 4], right: [u64; 4]) -> ([u64; 4], bool) {
    let mut output = [0; 4];
    let mut borrow = false;
    for index in 0..4 {
        let (temporary, first) = left[index].overflowing_sub(right[index]);
        let (difference, second) = temporary.overflowing_sub(u64::from(borrow));
        output[index] = difference;
        borrow = first || second;
    }
    (output, borrow)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::subtract_words;
    use std::vec::Vec;

    #[test]
    fn frozen_pre_rust_whole_integer_cases() {
        let mut count = 0;
        for row in include_str!("target-vectors.tsv").lines() {
            let fields: Vec<_> = row.split('\t').collect();
            assert_eq!(fields.len(), 14);
            let mut left = [0; 4];
            let mut right = [0; 4];
            let mut expected = [0; 4];
            for index in 0..4 {
                left[index] = u64::from_str_radix(fields[index + 1], 16).unwrap();
                right[index] = u64::from_str_radix(fields[index + 5], 16).unwrap();
                expected[index] = u64::from_str_radix(fields[index + 9], 16).unwrap();
            }
            let borrow = u64::from_str_radix(fields[13], 16).unwrap();
            assert!(borrow <= 1);
            assert_eq!(subtract_words(left, right), (expected, borrow == 1), "case {}", fields[0]);
            count += 1;
        }
        assert_eq!(count, 1352);
    }
}
