//! Supplied-seed, fixed20-byte hash from the node94 fresh writer path.
//!
//! This owns only a numeric result. Seeds are synthetic caller-supplied words;
//! their runtime creation and a native hash-table object's validity are external.
//! Actual adapter: 0x399c7a0..0x399c8e5; writer: 0x3a00700..0x3a008d7.
//! Node94 SHA256: 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
//! The sibling RE-001 math is credited. Only ntail0/fresh20 transfers across the
//! writer's R8/R11 comparison difference; no generic incremental writer is modeled.

#![forbid(unsafe_code)]

// Native storage order: v0, v2, v1, v3. This is a private arithmetic array,
// not an assertion about the original Rust type or external calling convention.
fn sip_round(state: &mut [u64; 4]) {
    state[0] = state[0].wrapping_add(state[2]);
    state[1] = state[1].wrapping_add(state[3]);
    state[2] = state[2].rotate_left(13) ^ state[0];
    state[3] = state[3].rotate_left(16) ^ state[1];
    state[0] = state[0].rotate_left(32);
    state[1] = state[1].wrapping_add(state[2]);
    state[0] = state[0].wrapping_add(state[3]);
    state[2] = state[2].rotate_left(17) ^ state[1];
    state[3] = state[3].rotate_left(21) ^ state[0];
    state[1] = state[1].rotate_left(32);
}

fn absorb(state: &mut [u64; 4], word: u64) {
    state[3] ^= word;
    sip_round(state);
    state[0] ^= word;
}

/// Hash exactly20 raw bytes with two supplied u64 seed words.
///
/// The native adapter reads16 little-endian seed bytes and a stable20-byte
/// query, initializes a fresh state and absorbs no collection-length prefix.
/// Seed/query validity and separation from mutable native frames are premises
/// of that correspondence. Owned seed words and the immutable byte array are
/// new safe-API choices, not recovered pointer provenance or native Rust ABI.
/// No seed generator, generic Hasher interface, Once or table producer is here.
#[must_use]
pub fn table_hash20(seeds: [u64; 2], query: &[u8; 20]) -> u64 {
    let [k0, k1] = seeds;
    let mut state = [
        k0 ^ 0x736f_6d65_7073_6575,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x646f_7261_6e64_6f6d,
        k1 ^ 0x7465_6462_7974_6573,
    ];
    let first = u64::from_le_bytes([
        query[0], query[1], query[2], query[3], query[4], query[5], query[6], query[7],
    ]);
    let second = u64::from_le_bytes([
        query[8], query[9], query[10], query[11], query[12], query[13], query[14], query[15],
    ]);
    let tail = u64::from(u32::from_le_bytes([
        query[16], query[17], query[18], query[19],
    ]));
    let final_block = tail | (20u64 << 56);
    for word in [first, second, final_block] {
        absorb(&mut state, word);
    }
    state[1] ^= 0xff;
    for _ in 0..3 {
        sip_round(&mut state);
    }
    state[0] ^ state[1] ^ state[2] ^ state[3]
}
