//! Slice/value reconstruction of node #94 ELF VA `0x16488e0..0x1648946`.
//!
//! The static relation assumes a valid, nonwrapping mapped input interval.
//! This API uses the actual slice length, not the native raw length register:
//! it does not expose bit-63 masking, pointer wrap or the native calling ABI.
//! No source-level hash identity or cryptographic property is established.
#![no_std]
#![forbid(unsafe_code)]

/// Fold bytes from both ends using two independent unsigned product streams.
///
/// Argument order preserves the observed seed order: `seed_b` was in RDX,
/// `seed_a` in RCX, and `key` in R8. Buffers shorter than 16 bytes return
/// `seed_a ^ seed_b`. Longer inputs use `ceil(len / 32)` rounds, reading
/// 16 bytes from each end per round; the final reads may overlap. Every word
/// is little-endian, including unaligned words at the backward end.
///
/// This function allocates nothing and does not modify the input.
pub fn two_stream_mix(input: &[u8], seed_b: u64, seed_a: u64, key: u64) -> u64 {
    let word = |offset: usize| {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&input[offset..offset + 8]);
        u64::from_le_bytes(bytes)
    };
    let mut a = seed_a;
    let mut b = seed_b;
    let mut front = 0;
    let mut back = input.len();
    while front < back && back >= 16 {
        let product_a = u128::from(a ^ word(front + 8)) * u128::from(word(back - 8) ^ key);
        let product_b = u128::from(b ^ word(front)) * u128::from(word(back - 16) ^ key);
        a = product_a as u64 ^ (product_a >> 64) as u64;
        b = product_b as u64 ^ (product_b >> 64) as u64;
        front += 16;
        back -= 16;
    }
    a ^ b
}
