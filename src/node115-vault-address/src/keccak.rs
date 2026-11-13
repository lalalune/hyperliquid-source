//! Incremental Keccak-256 as the node #115 digest call sites use it.
//!
//! The digest entry `0x38d2ef0` builds a zeroed 224-byte state record (200-byte lane buffer, absorb offset
//! zero, rate 0x88 = 136 stored at +0xd0, delimiter byte 0x01 at +0xd8), calls the update slot
//! (`0x64e0148 -> 0x5cda910`) once with the whole serialized buffer and the finalize slot
//! (`0x64e0150 -> 0x5cdad40`) for 32 bytes. `update` here XORs input into the buffer and permutes whenever
//! a block fills (so input ending exactly on a rate boundary has already been permuted); `finalize` XORs the
//! delimiter at the offset and 0x80 at rate-1, permutes and copies the front out. The permutation is the
//! existing `node115-sponge-permutation` crate; the bodies of `0x5cda910` / `0x5cdad40` were reconstructed in
//! Python by `evm-keccak-ripemd-hash-115`, and this is their Rust incremental form.

const RATE: usize = 136;
const DELIMITER: u8 = 0x01;

pub struct Keccak256 {
    buffer: [u8; 200],
    offset: usize,
}

impl Keccak256 {
    pub fn new() -> Self {
        Keccak256 { buffer: [0; 200], offset: 0 }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            let take = input.len().min(RATE - self.offset);
            for (byte, new) in self.buffer[self.offset..self.offset + take].iter_mut().zip(input) {
                *byte ^= new;
            }
            self.offset += take;
            input = &input[take..];
            if self.offset == RATE {
                permute_bytes(&mut self.buffer);
                self.offset = 0;
            }
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        self.buffer[self.offset] ^= DELIMITER;
        self.buffer[RATE - 1] ^= 0x80;
        permute_bytes(&mut self.buffer);
        let mut out = [0; 32];
        out.copy_from_slice(&self.buffer[..32]);
        out
    }
}

impl Default for Keccak256 {
    fn default() -> Self {
        Self::new()
    }
}

fn permute_bytes(buffer: &mut [u8; 200]) {
    let mut lanes = [0u64; 25];
    for (lane, chunk) in lanes.iter_mut().zip(buffer.chunks_exact(8)) {
        *lane = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    permutation::permute(&mut lanes);
    for (chunk, lane) in buffer.chunks_exact_mut(8).zip(&lanes) {
        chunk.copy_from_slice(&lane.to_le_bytes());
    }
}

pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(input);
    hasher.finalize()
}
