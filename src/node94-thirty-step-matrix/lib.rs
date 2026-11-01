#![no_std]
#![forbid(unsafe_code)]
//! Complete numeric projection of node94 [0x565f2e0, 0x565f390).
//!
//! Inputs are the entry bits of R8, R9 and RBP. All u64 triples are admitted.
//! The fixed 30-step transform is not assigned a caller algorithm or purpose.
//! Physical ABI, flags and unchanged RSI/stack values are outside this API.

const BIAS: i64 = (1_i64 << 31) - 1;

/// The fourteen written general-purpose registers at the original return.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

fn encoded(row: [i64; 2]) -> u64 {
    ((BIAS + row[0]) as u64) | (((BIAS + row[1]) as u64) << 32)
}

/// Reduce the pair for exactly thirty steps, preserving raw accumulator bits.
///
/// An odd first value selects a larger-minus-smaller step and possibly swaps
/// the rows. An even first value keeps the pair before halving the first.
/// Matrix coefficients are tracked independently as bounded signed integers;
/// only their required final register representations use biased packing.
pub fn reduce(mut first: u64, mut second: u64, mut accumulator: u64) -> Registers {
    let mut rows = [[1_i64, 0_i64], [0_i64, 1_i64]];
    let mut before_pair = [0_u64; 2];
    let mut before_rows = rows;
    let mut before_accumulator = accumulator;
    for _ in 0..30 {
        before_pair = [first, second];
        before_rows = rows;
        before_accumulator = accumulator;
        if first & 1 != 0 {
            if first < second {
                accumulator = accumulator.wrapping_add((first & second) >> 1);
                core::mem::swap(&mut first, &mut second);
                rows.swap(0, 1);
            }
            first -= second;
            rows[0][0] -= rows[1][0];
            rows[0][1] -= rows[1][1];
        }
        first >>= 1;
        rows[1][0] *= 2;
        rows[1][1] *= 2;
        accumulator = accumulator.wrapping_add(second.wrapping_add(2) >> 2);
    }
    Registers {
        rax: rows[0][0] as u64,
        rbx: rows[0][1] as u64,
        rcx: rows[1][1] as u64,
        rdx: rows[1][0] as u64,
        rbp: accumulator,
        rdi: 0,
        r8: first,
        r9: second,
        r10: before_pair[0],
        r11: before_pair[1],
        r12: encoded(before_rows[0]),
        r13: encoded(before_rows[1]),
        r14: before_accumulator,
        r15: BIAS as u64,
    }
}
