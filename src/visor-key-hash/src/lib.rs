#![no_std]
#![forbid(unsafe_code)]
//! Seeded whole-input arithmetic from the captured Visor, including one FF byte.
//!
//! This safe value API does not implement table membership, a seed generator,
//! native ABI or a cryptographic security guarantee. See the evidence packet
//! `research/work-items/RE-013-visor-key-hash-rust` for the native domain/proof.

fn round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[2] = v[2].wrapping_add(v[3]);
    v[1] = v[1].rotate_left(13) ^ v[0];
    v[3] = v[3].rotate_left(16) ^ v[2];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[1]);
    v[0] = v[0].wrapping_add(v[3]);
    v[1] = v[1].rotate_left(17) ^ v[2];
    v[3] = v[3].rotate_left(21) ^ v[0];
    v[2] = v[2].rotate_left(32);
}

fn compress(v: &mut [u64; 4], word: u64) {
    v[3] ^= word;
    round(v);
    v[0] ^= word;
}

/// Compute the complete 64-bit value for `input` followed by exactly one FF.
///
/// `seed` contains the two native little-endian seed qword values in order.
/// Every input byte is significant: empty, NUL, FF and invalid UTF-8 are allowed.
/// All word additions wrap. The function allocates nothing and has no streaming
/// interface. Native correspondence assumes the valid spans and ordinary
/// execution specified in the packet; it does not reproduce native faults.
pub fn hash_key(seed: [u64; 2], input: &[u8]) -> u64 {
    let seeds = [seed[0], seed[1]];
    let mut v = [
        seeds[0] ^ 0x736f_6d65_7073_6575,
        seeds[1] ^ 0x646f_7261_6e64_6f6d,
        seeds[0] ^ 0x6c79_6765_6e65_7261,
        seeds[1] ^ 0x7465_6462_7974_6573,
    ];
    let mut chunks = input.chunks_exact(8);
    for chunk in &mut chunks {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(chunk);
        compress(&mut v, u64::from_le_bytes(bytes));
    }
    let remainder = chunks.remainder();
    let mut tail = 0;
    for (index, byte) in remainder.iter().enumerate() {
        tail |= u64::from(*byte) << (8 * index);
    }
    tail |= 0xff_u64 << (8 * remainder.len());
    if remainder.len() == 7 {
        compress(&mut v, tail);
        tail = 0;
    }
    let length_byte = (input.len().wrapping_add(1) as u64) & 0xff;
    compress(&mut v, tail | (length_byte << 56));
    v[2] ^= 0xff;
    for _ in 0..3 {
        round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}
