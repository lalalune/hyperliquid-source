#![no_std]

//! Encode and decode the four binary64 words carried by Node115 FeeRateMapSerde.
//! The fresh-reader decoder projects values and cursor/depth/error classes.
//! This is not the native ABI, allocation/unwind behavior or complete fee subsystem.

mod decoder;
pub use decoder::{
    decode_prefix, CacheState, ContainerKind, DecodeError, DecodeOutcome, Observation,
};

/// Encode four stored IEEE-754 binary64 words without floating-point arithmetic.
///
/// The array marker is followed by four float64 markers and big-endian words.
/// Signed zero, infinities and NaN payloads retain their original bits. Positional
/// words do not assert recovered semantic names or fee units.
pub fn encode_bits(words: [u64; 4]) -> [u8; 37] {
    let mut output = [0u8; 37];
    output[0] = 0x94;
    for (slot, word) in words.into_iter().enumerate() {
        let start = 1 + slot * 9;
        output[start] = 0xcb;
        output[start + 1..start + 9].copy_from_slice(&word.to_be_bytes());
    }
    output
}
