#![no_std]
#![forbid(unsafe_code)]
//! Complete owned25lane numeric permutation; no sponge/padding/hash or native ABI.
// Mathematical construction: NIST FIPS202 sections3.2/3.3. Target data and
// original-instruction expectations were sealed before this Rust source.
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];
const RHO: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];
/// Mutates all25u64 lanes, laid out by x+5*y. This API is independently chosen.
pub fn permute(state: &mut [u64; 25]) {
    for &constant in &ROUND_CONSTANTS {
        let mut columns = [0; 5];
        for (x, column) in columns.iter_mut().enumerate() {
            *column = (0..5).fold(0, |sum, y| sum ^ state[x + 5 * y]);
        }
        let mut delta = [0; 5];
        for (x, value) in delta.iter_mut().enumerate() {
            *value = columns[(x + 4) % 5] ^ columns[(x + 1) % 5].rotate_left(1);
        }
        for (i, lane) in state.iter_mut().enumerate() {
            *lane ^= delta[i % 5];
        }
        let mut moved = [0; 25];
        for (y, row) in state.chunks_exact(5).enumerate() {
            for (x, &lane) in row.iter().enumerate() {
                moved[y + 5 * ((2 * x + 3 * y) % 5)] = lane.rotate_left(RHO[x + 5 * y]);
            }
        }
        for (y, row) in state.chunks_exact_mut(5).enumerate() {
            for (x, lane) in row.iter_mut().enumerate() {
                *lane =
                    moved[x + 5 * y] ^ ((!moved[(x + 1) % 5 + 5 * y]) & moved[(x + 2) % 5 + 5 * y]);
            }
        }
        state[0] ^= constant;
    }
}
