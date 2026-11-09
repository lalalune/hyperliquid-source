#![no_std]
#![forbid(unsafe_code)]

//! Raw four-word relation for node #115's two-span projection leaf.
//!
//! The original source type, owner, and caller domain remain unresolved.

/// Returns the four output words observed for the raw `(C, B, H, N)` inputs.
///
/// The values are `u64` words with modulo-2^64 arithmetic. This is a safe
/// value-level relation, not the captured function's output-pointer ABI.
pub fn project(c: u64, b: u64, h: u64, n: u64) -> [u64; 4] {
    if n == 0 {
        return [b; 4];
    }

    let a = if h >= c { h.wrapping_sub(c) } else { h };
    let remaining = c.wrapping_sub(a);
    let first_start = b.wrapping_add(a.wrapping_mul(80));

    if n > remaining {
        [
            first_start,
            b.wrapping_add(c.wrapping_mul(80)),
            b,
            b.wrapping_add(n.wrapping_sub(remaining).wrapping_mul(80)),
        ]
    } else {
        [
            first_start,
            b.wrapping_add(a.wrapping_add(n).wrapping_mul(80)),
            b,
            b,
        ]
    }
}
