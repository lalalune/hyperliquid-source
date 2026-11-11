//! Selected successful node #115 bridge word-buffer flattening.
//! The digest algorithm and native allocator are separate boundaries.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::vec::Vec;

pub const INPUT_LEN: usize = 52;
pub const OUTPUT_LEN: usize = 64;
/// Native intermediate allocation is 64 word slots of 32 bytes, not 64 bytes.
pub const NATIVE_WORD_CAPACITY: usize = 64;
pub const NATIVE_WORD_ALLOCATION_BYTES: usize = NATIVE_WORD_CAPACITY * 32;

/// The selected output owns its bytes independently of the input. The native
/// flatten result's capacity and length both equal 64 on this normal path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Preimage {
    bytes: [u8; OUTPUT_LEN],
}
impl Preimage {
    pub fn as_digest_input(&self) -> &[u8; OUTPUT_LEN] {
        &self.bytes
    }
    pub fn into_bytes(self) -> [u8; OUTPUT_LEN] {
        self.bytes
    }
}

/// Copy the selected 20-byte view and 32-byte view into the observed two words,
/// then flatten those words in order. No native allocator equivalence is claimed.
pub fn build(input: &[u8; INPUT_LEN]) -> Preimage {
    let mut words = [[0u8; 32]; 2];
    words[0][12..].copy_from_slice(&input[..20]);
    words[1].copy_from_slice(&input[20..]);
    let bytes: Vec<u8> = words.into_iter().flatten().collect();
    let mut result = [0; OUTPUT_LEN];
    result.copy_from_slice(&bytes);
    Preimage { bytes: result }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_offsets_and_independent_storage() {
        let mut input = core::array::from_fn(|i| i as u8 + 1);
        let output = build(&input);
        input.fill(0);
        let bytes = output.as_digest_input();
        assert_eq!(&bytes[..12], &[0; 12]);
        assert_eq!(&bytes[12..32], &(1u8..=20).collect::<Vec<_>>());
        assert_eq!(&bytes[32..], &(21u8..=52).collect::<Vec<_>>());
    }
    #[test]
    fn boundary_bits_and_zero_input() {
        let mut input = [0; INPUT_LEN];
        assert_eq!(build(&input).into_bytes(), [0; OUTPUT_LEN]);
        for pos in 0..INPUT_LEN {
            input[pos] = 0x80;
            let out = build(&input).into_bytes();
            let expected = pos + 12;
            assert_eq!(out[expected], 0x80);
            assert_eq!(out.iter().filter(|x| **x != 0).count(), 1);
            input[pos] = 0;
        }
    }
    #[test]
    fn flatten_length_is_distinct_from_word_allocation() {
        assert_eq!(build(&[0xa5; INPUT_LEN]).as_digest_input().len(), 64);
        assert_eq!(NATIVE_WORD_CAPACITY, 64);
        assert_eq!(NATIVE_WORD_ALLOCATION_BYTES, 2048);
    }
}
