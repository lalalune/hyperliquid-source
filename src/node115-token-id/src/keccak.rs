//! Incremental Keccak-256 as the node #115 digest call sites use it.
//!
//! Observed state record (224 bytes, same layout as the `tiny-keccak` `Keccak` state): 200-byte
//! lane buffer, absorb offset at +0xc8, rate 0x88 (136) at +0xd0, delimiter byte 0x01 at +0xd8,
//! squeeze flag at +0xd9 (zero when freshly built, see `0x38d2dad..0x38d2db9`).
//! `absorb` mirrors `0x5cda910` (XOR into the buffer, permute whenever the block fills, so an
//! input that ends exactly on a rate boundary has already been permuted), `finalize` mirrors
//! `0x5cdad40` (XOR the delimiter at the offset and 0x80 at rate-1, permute, copy the front
//! out). The permutation itself is the existing `node115-sponge-permutation` crate.

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
