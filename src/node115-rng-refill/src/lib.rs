#![no_std]
#![forbid(unsafe_code)]
//! Conditional scalar composition of the node #115 four-block refill fallback.

/// Key words and the four tail words observed in the native input state.
/// The first two tail words are a little-endian 64-bit counter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct State {
    pub key: [u32; 8],
    pub tail: [u32; 4],
}

fn quarter(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

/// Return four consecutive 16-word blocks and advance the counter by four.
/// Correspondence is limited to the selected six-double-round fallback,
/// normal return and valid non-overlapping native input/output regions.
/// This does not obtain entropy or choose any CPU-dependent implementation.
pub fn refill(state: &mut State) -> [u32; 64] {
    const C: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
    let counter = u64::from(state.tail[0]) | (u64::from(state.tail[1]) << 32);
    let mut out = [0u32; 64];
    for block in 0..4 {
        let n = counter.wrapping_add(block as u64);
        let mut base = [0u32; 16];
        base[..4].copy_from_slice(&C);
        base[4..12].copy_from_slice(&state.key);
        base[12] = n as u32;
        base[13] = (n >> 32) as u32;
        base[14] = state.tail[2];
        base[15] = state.tail[3];
        let mut x = base;
        for _ in 0..6 {
            quarter(&mut x, 0, 4, 8, 12);
            quarter(&mut x, 1, 5, 9, 13);
            quarter(&mut x, 2, 6, 10, 14);
            quarter(&mut x, 3, 7, 11, 15);
            quarter(&mut x, 0, 5, 10, 15);
            quarter(&mut x, 1, 6, 11, 12);
            quarter(&mut x, 2, 7, 8, 13);
            quarter(&mut x, 3, 4, 9, 14);
        }
        for i in 0..16 {
            out[block * 16 + i] = x[i].wrapping_add(base[i]);
        }
    }
    let next = counter.wrapping_add(4);
    state.tail[0] = next as u32;
    state.tail[1] = (next >> 32) as u32;
    out
}
