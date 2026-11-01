#![no_std]
#![forbid(unsafe_code)]
//! Constructed valid-string projection of node94's stateful hex-pair leaf.
//! The raw result bytes express observed write masks, not a nominal enum ABI.

enum Scan { Digit(u8), End, Invalid { scalar: u32, index: usize } }

/// Own safe state. Its layout is not an original native struct or ABI.
pub struct HexPairs<'a> {
    text: &'a str,
    cursor: usize,
    consumed: u64,
    halted: bool,
}

impl<'a> HexPairs<'a> {
    /// No prefix is removed. Input stays immutable for the iterator lifetime.
    pub fn new(text: &'a str) -> Self {
        Self { text, cursor: 0, consumed: 0, halted: false }
    }

    pub fn cursor(&self) -> usize { self.cursor }
    pub fn consumed(&self) -> u64 { self.consumed }
    /// Natural end can leave this false; odd/invalid input sets it true.
    pub fn halted(&self) -> bool { self.halted }

    fn scan(&mut self) -> Scan {
        while self.cursor < self.text.len() {
            let index = self.cursor;
            let byte = self.text.as_bytes()[index];
            self.cursor += 1;
            self.consumed += 1;
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'A'..=b'F' => byte - b'A' + 10,
                b'a'..=b'f' => byte - b'a' + 10,
                b'\t' | b'\n' | b'\r' | b' ' => continue,
                _ => {
                    // The active invariant admits only preceding ASCII, so
                    // index is a nonempty UTF-8 boundary. Decode the scalar
                    // from the original suffix, retaining the outer one-byte
                    // cursor advance. Later calls halt before using it.
                    let scalar = self.text[index..].chars().next()
                        .expect("active nonempty scalar boundary") as u32;
                    return Scan::Invalid { scalar, index };
                }
            };
            return Scan::Digit(digit);
        }
        Scan::End
    }

    fn invalid(&mut self, output: &mut [u8; 16], scalar: u32, index: usize) {
        self.halted = true;
        output[0..4].copy_from_slice(&0u32.to_le_bytes());
        output[4..8].copy_from_slice(&scalar.to_le_bytes());
        output[8..16].copy_from_slice(&(index as u64).to_le_bytes());
    }

    /// Write one complete observed result into the same supplied output.
    ///
    /// Tag0 writes scalar/index and all16 bytes; tag2 writes one byte at+4;
    /// tags1/3 write only the tag. All other bytes keep their previous values.
    /// Repeated odd/invalid calls return tag3 with cursor/count/halt preserved.
    /// Valid immutable input, separated roles and normal finite execution are
    /// required. Forged state, invalid UTF-8, panic/fault/unwind and physical
    /// access timing are outside this safe projection.
    pub fn next_into<'o>(&mut self, output: &'o mut [u8; 16]) -> &'o mut [u8; 16] {
        if self.halted {
            output[0..4].copy_from_slice(&3u32.to_le_bytes());
            return output;
        }
        match self.scan() {
            Scan::End => output[0..4].copy_from_slice(&3u32.to_le_bytes()),
            Scan::Invalid { scalar, index } => self.invalid(output, scalar, index),
            Scan::Digit(first) => match self.scan() {
                Scan::End => {
                    self.halted = false;
                    output[0..4].copy_from_slice(&1u32.to_le_bytes());
                }
                Scan::Invalid { scalar, index } => self.invalid(output, scalar, index),
                Scan::Digit(second) => {
                    output[0..4].copy_from_slice(&2u32.to_le_bytes());
                    output[4] = first * 16 + second;
                }
            },
        }
        output
    }
}
