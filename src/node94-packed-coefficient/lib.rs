//! Complete value projection of node #94 normalization [0x565ec20,0x565ecb2)
//! and its tail-loop [0x565ecc0,0x565ed4d). All value/count inputs are admitted.
//! The normalizer requires successful stable original reads. There are no
//! stores; the custom machine ABI, flags and return control are not recreated.
#![no_std]
#![forbid(unsafe_code)]

const BIAS: u64 = 0x7fff_ffff_7fff_ffff;
const LOW: u64 = 0x7fff_ffff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

fn stable_coefficient(value: u64, steps: u64) -> u64 {
    if steps >= 64 {
        BIAS
    } else {
        BIAS.wrapping_add(value.wrapping_sub(BIAS).wrapping_shl(steps as u32))
    }
}

/// Complete loop-entry projection. R9/R11 are supplied unchanged entry values.
/// The two packed coefficients wrap at 64 bits before final 32-bit extraction.
pub fn iterate(mut x: u64, mut y: u64, raw_count: u64, r9: u64, r11: u64) -> Registers {
    let mut remaining = if raw_count as u32 == 0 {
        1_u64 << 32
    } else {
        u64::from(raw_count as u32)
    };
    let mut u = 0x7fff_ffff_8000_0000_u64;
    let mut v = 0x8000_0000_7fff_ffff_u64;
    let mut last = [0; 4];
    // Every nonzero-x step decreases bit_length(x)+bit_length(y), initially <=128.
    while remaining != 0 && x != 0 {
        last = [x, y, u, v];
        if x & 1 != 0 {
            if x < y {
                core::mem::swap(&mut x, &mut y);
                core::mem::swap(&mut u, &mut v);
            }
            x -= y;
            u = u.wrapping_sub(v).wrapping_add(BIAS);
        }
        x >>= 1;
        v = v.wrapping_mul(2).wrapping_sub(BIAS);
        remaining -= 1;
    }
    if remaining != 0 {
        last = [0, y, u, stable_coefficient(v, remaining - 1)];
        v = stable_coefficient(v, remaining);
    }
    Registers {
        rax: last[0],
        rbx: last[1],
        rcx: (u >> 32).wrapping_sub(LOW),
        rdx: u64::from(u as u32).wrapping_sub(LOW),
        rbp: last[2],
        r8: x,
        r9,
        r10: y,
        r11,
        r12: u64::from(v as u32).wrapping_sub(LOW),
        r13: (v >> 32).wrapping_sub(LOW),
        r14: last[3],
        r15: LOW,
    }
}

fn shifted_high(high: u64, low: u64, shift: u32) -> u64 {
    if shift == 0 {
        high
    } else {
        (high << shift) | (low >> (64 - shift))
    }
}

/// Complete normalizer entry plus its unconditional tail to `iterate`.
/// Arrays are the two adjacent four-qword snapshots loaded through original RSI.
pub fn normalize_iterate(a: [u64; 4], b: [u64; 4], raw_count: u64) -> Registers {
    let mut rank = 3;
    while rank != 0 && (a[rank] | b[rank]) == 0 {
        rank -= 1;
    }
    let (high_a, high_b) = if rank == 0 {
        (a[0], b[0])
    } else {
        let shift = (a[rank] | b[rank]).leading_zeros() & 63;
        (
            shifted_high(a[rank], a[rank - 1], shift),
            shifted_high(b[rank], b[rank - 1], shift),
        )
    };
    let r9 = high_a & !LOW;
    let r11 = high_b & !LOW;
    let x = (a[0] & LOW) | r9;
    let y = (b[0] & LOW) | r11;
    iterate(x, y, raw_count, r9, r11)
}
