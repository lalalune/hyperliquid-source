//! The hasher behind the digest builder `0x57e8d40` and the recovery wrapper `0x1536a90`: a Keccak sponge with
//! rate 136 bytes and delimiter byte `0x01` (Keccak-256, the original padding, not SHA3-256's `0x06`).
//!
//! Native shape (relations-digest.tsv KU1, KF1): a state of a 200 byte buffer, an offset, a rate and a
//! delimiter byte (`+0xc8`, `+0xd0`, `+0xd8`) with a mode byte at `+0xd9`; `update` `0x5cda910` XORs the input
//! into the buffer and runs the permutation `0x5cda380` whenever the offset reaches the rate; `finalize`
//! `0x5cdad40` XORs the delimiter in at the offset and `0x80` into the last byte of the rate, runs one
//! permutation and copies the first output bytes. The squeezing mode (`update` after `finalize`, output longer
//! than the rate) is not modelled: neither caller uses it.
//!
//! The permutation is the 24 round Keccak-f[1600] of FIPS 202. The sponge-permutation crate of this
//! repository (`node115-sponge-permutation`, RE-009) compared the original permutation instructions with an
//! independent Rust construction on 262 whole states; this file restates the same public algorithm without
//! depending on it (it has no manifest to depend on), and `tests/digest.rs` checks the two against each other.

pub const RATE: usize = 136;

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rotation offsets by lane index `x + 5 * y`.
const ROTATIONS: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// Keccak-f[1600] on 25 lanes in `x + 5 * y` order.
pub fn keccak_f(a: &mut [u64; 25]) {
    for rc in ROUND_CONSTANTS {
        let mut c = [0u64; 5];
        for (x, col) in c.iter_mut().enumerate() {
            *col = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left(ROTATIONS[x + 5 * y]);
            }
        }
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }
        a[0] ^= rc;
    }
}

fn permute_bytes(buffer: &mut [u8; 200]) {
    let mut lanes = [0u64; 25];
    for (i, lane) in lanes.iter_mut().enumerate() {
        *lane = u64::from_le_bytes(buffer[8 * i..8 * i + 8].try_into().unwrap());
    }
    keccak_f(&mut lanes);
    for (i, lane) in lanes.iter().enumerate() {
        buffer[8 * i..8 * i + 8].copy_from_slice(&lane.to_le_bytes());
    }
}

/// The hasher state: 200 byte buffer, offset, delimiter byte; the rate is [`RATE`].
#[derive(Clone)]
pub struct Hasher {
    buffer: [u8; 200],
    offset: usize,
    delimiter: u8,
}

impl Hasher {
    /// What both callers build: rate 136, delimiter `0x01`, offset 0 (Keccak-256).
    pub fn keccak256() -> Self {
        Self::with_delimiter(0x01)
    }

    /// Same sponge with another delimiter byte; `0x06` makes it SHA3-256 (used by the standard vectors).
    pub fn with_delimiter(delimiter: u8) -> Self {
        Hasher { buffer: [0; 200], offset: 0, delimiter }
    }

    /// `0x5cda910`: absorb `data`.
    pub fn update(&mut self, mut data: &[u8]) {
        let mut offset = self.offset;
        while data.len() >= RATE - offset {
            let room = RATE - offset;
            for (b, d) in self.buffer[offset..RATE].iter_mut().zip(&data[..room]) {
                *b ^= d;
            }
            permute_bytes(&mut self.buffer);
            data = &data[room..];
            offset = 0;
        }
        for (b, d) in self.buffer[offset..].iter_mut().zip(data) {
            *b ^= d;
        }
        self.offset = offset + data.len();
    }

    /// `0x5cdad40` with output length 32 (the only length either caller asks for).
    pub fn finalize(mut self) -> [u8; 32] {
        self.buffer[self.offset] ^= self.delimiter;
        self.buffer[RATE - 1] ^= 0x80;
        permute_bytes(&mut self.buffer);
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.buffer[..32]);
        out
    }
}

/// Keccak-256 of `data`.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Hasher::keccak256();
    h.update(data);
    h.finalize()
}
