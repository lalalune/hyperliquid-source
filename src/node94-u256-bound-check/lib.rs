//! Value projection of node94's complete u256 helper and fixed-bound wrapper.
//! Inputs are little-endian word snapshots; this is not the native pointer ABI.
#![no_std]
#![forbid(unsafe_code)]

/// Exact 32 bytes read at linked ELF VA 0x9186a0, in little-endian words.
pub const BOUND: [u64; 4] = [
    0xffff_ffff_0000_0001,
    0x53bd_a402_fffe_5bfe,
    0x3339_d808_09a1_d805,
    0x73ed_a753_299d_7d48,
];

/// Seven selected full-width data-register observations at the corresponding RET.
/// Flags, SIMD registers, preserved entry registers and control state are excluded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
}

/// Complete [0x565dd80, 0x565ddc5) value relation, for all word patterns.
/// Native correspondence requires stable readable 32-byte operand spans whose
/// values match these snapshots; aliases impose only snapshot consistency.
pub fn compare_nonzero(left: [u64; 4], right: [u64; 4]) -> Registers {
    let mut difference = [0u64; 4];
    let mut borrow = false;
    for i in 0..4 {
        let (word, first) = left[i].overflowing_sub(right[i]);
        let (word, second) = word.overflowing_sub(borrow as u64);
        difference[i] = word;
        borrow = first || second;
    }
    let nonzero = (left[0] | left[1] | left[2] | left[3]) != 0;
    Registers {
        rax: (nonzero && borrow) as u64,
        rdx: 1,
        rsi: 0u64.wrapping_sub(borrow as u64),
        r8: difference[0],
        r9: difference[1],
        r10: difference[2],
        r11: difference[3],
    }
}

/// Complete [0x5651e50, 0x5651eb8) wrapper plus its closed helper.
/// The target reloads all 32 input bytes after the helper; correspondence requires
/// the same stable input throughout and the exact read-only BOUND bytes.
pub fn compare_bound(left: [u64; 4]) -> Registers {
    let mut result = compare_nonzero(left, BOUND);
    let zero = (left[0] | left[1] | left[2] | left[3]) == 0;
    result.rdx = zero as u64;
    result.rax |= result.rdx;
    result
}
