//! Fresh fixed-twenty-byte table-hash math, not a generic hasher or address derivation.
#![no_std]
#![forbid(unsafe_code)]

struct State {
    a: u64,
    b: u64,
    c: u64,
    d: u64,
}

impl State {
    fn mix(&mut self) {
        self.a = self.a.wrapping_add(self.b);
        self.c = self.c.wrapping_add(self.d);
        self.b = self.b.rotate_left(13) ^ self.a;
        self.d = self.d.rotate_left(16) ^ self.c;
        self.a = self.a.rotate_left(32);
        self.c = self.c.wrapping_add(self.b);
        self.a = self.a.wrapping_add(self.d);
        self.b = self.b.rotate_left(17) ^ self.c;
        self.d = self.d.rotate_left(21) ^ self.a;
        self.c = self.c.rotate_left(32);
    }

    fn absorb(&mut self, word: u64) {
        self.d ^= word;
        self.mix();
        self.a ^= word;
    }
}

/// Compute the established fresh-writer hash for exactly twenty bytes.
///
/// Both seed words are explicit caller inputs. No runtime seeds, address state,
/// secret material or original hasher object is accessed. Incremental writes,
/// other lengths, original ABI and address derivation are not implemented.
pub fn table_hash20(seed: [u64; 2], message: &[u8; 20]) -> u64 {
    let mut state = State {
        a: seed[0] ^ 0x736f6d6570736575,
        b: seed[1] ^ 0x646f72616e646f6d,
        c: seed[0] ^ 0x6c7967656e657261,
        d: seed[1] ^ 0x7465646279746573,
    };
    for offset in [0, 8] {
        let word = u64::from_le_bytes(core::array::from_fn(|index| message[offset + index]));
        state.absorb(word);
    }
    let tail = u64::from(u32::from_le_bytes([
        message[16],
        message[17],
        message[18],
        message[19],
    ]));
    state.absorb((20_u64 << 56) | tail);
    state.c ^= 0xff;
    for _ in 0..3 {
        state.mix();
    }
    state.a ^ state.b ^ state.c ^ state.d
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::table_hash20;
    use std::vec::Vec;

    #[test]
    fn pre_rust_captured_arithmetic_smoke() {
        let mut count = 0;
        for line in include_str!("target-smoke.tsv").lines() {
            let fields: Vec<_> = line.split('\t').collect();
            let seed = [
                u64::from_str_radix(fields[0], 16).unwrap(),
                u64::from_str_radix(fields[1], 16).unwrap(),
            ];
            let bytes: Vec<u8> = (0..40)
                .step_by(2)
                .map(|at| u8::from_str_radix(&fields[2][at..at + 2], 16).unwrap())
                .collect();
            let message: [u8; 20] = bytes.try_into().unwrap();
            let expected = u64::from_str_radix(fields[3], 16).unwrap();
            assert_eq!(table_hash20(seed, &message), expected, "{line}");
            count += 1;
        }
        assert_eq!(count, 12);
    }
}
