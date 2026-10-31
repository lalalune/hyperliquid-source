//! Pure integer contract observed in node #94's feed and alias producer.
//!
//! Evidence: `research/work-items/RE-001-short-string-alias-94/` at repository root.
//! Target SHA-256: 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
//! Independently authored from authenticated bytes; no inferred source is copied.
//! This crate neither recovers the constructor/cache nor exposes the target ABI.
//! It uses no allocation, unsafe code, dependencies, target execution or I/O.

#![forbid(unsafe_code)]

/// Logical streaming state, not the target's memory representation or public ABI.
#[derive(Clone, Copy)]
pub struct AliasFeed {
    words: [u64; 4],
    length: u64,
    tail: u64,
    tail_len: u8,
}

impl Default for AliasFeed {
    fn default() -> Self {
        Self::new()
    }
}

impl AliasFeed {
    /// Starts the four-word state observed at producer VA 0x13c60a0..0x13c60d7.
    pub const fn new() -> Self {
        Self {
            words: [
                0x736f6d6570736575,
                0x646f72616e646f6d,
                0x6c7967656e657261,
                0x7465646279746573,
            ],
            length: 0,
            tail: 0,
            tail_len: 0,
        }
    }

    /// Feeds arbitrary byte chunks, preserving a partial little-endian word.
    ///
    /// The byte counter wraps as in the target's 64-bit addition. No allocation
    /// is needed, and an empty write preserves the state.
    pub fn write(&mut self, mut bytes: &[u8]) {
        self.length = self.length.wrapping_add(bytes.len() as u64);
        while self.tail_len != 0 && !bytes.is_empty() {
            self.tail |= u64::from(bytes[0]) << (8 * self.tail_len);
            self.tail_len += 1;
            bytes = &bytes[1..];
            if self.tail_len == 8 {
                compress(&mut self.words, self.tail);
                self.tail = 0;
                self.tail_len = 0;
            }
        }
        let mut chunks = bytes.chunks_exact(8);
        for chunk in &mut chunks {
            let word = u64::from_le_bytes(chunk.try_into().expect("exact eight-byte chunk"));
            compress(&mut self.words, word);
        }
        for (i, &byte) in chunks.remainder().iter().enumerate() {
            self.tail |= u64::from(byte) << (8 * i);
            self.tail_len += 1;
        }
    }

    /// Returns the observed final hash without consuming or changing this state.
    ///
    /// Only the low byte of the total length occupies the final word's high byte.
    /// This is a reconstruction contract, not a cryptographic API or safety claim.
    pub fn finish(&self) -> u64 {
        let mut words = self.words;
        compress(&mut words, self.tail | ((self.length & 255) << 56));
        words[2] ^= 255;
        for _ in 0..3 {
            round(&mut words);
        }
        words.into_iter().fold(0, |a, b| a ^ b)
    }
}

fn round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13) ^ v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16) ^ v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21) ^ v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17) ^ v[2];
    v[2] = v[2].rotate_left(32);
}

fn compress(v: &mut [u64; 4], word: u64) {
    v[3] ^= word;
    round(v);
    v[0] ^= word;
}

/// Produces ten ASCII letters from the observed input/ff/u32-LE counter feeds.
///
/// The state after input is copied for each counter instead of re-reading the
/// input ten times. The returned array substitutes for the evaluated producer's
/// preallocated output only; no allocation, cache or constructor is implemented.
/// Short inputs are diagnostic producer inputs, not constructor route claims.
pub fn alias10(input: &[u8]) -> [u8; 10] {
    let mut prefix = AliasFeed::new();
    prefix.write(input);
    let mut result = [0; 10];
    for (counter, letter) in result.iter_mut().enumerate() {
        let mut state = prefix;
        state.write(&[0xff]);
        state.write(&(counter as u32).to_le_bytes());
        *letter = 65 + (state.finish() % 26) as u8;
    }
    result
}

#[cfg(test)]
mod tests;
