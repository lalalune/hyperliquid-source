#![no_std]

//! Encode the four binary64 bit patterns carried by Node115 FeeRateMapSerde.
//! This implements its observed MessagePack output, not the native serializer
//! ABI, allocation/error paths, decoder, fee units, or complete fee subsystem.

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
