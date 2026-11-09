#![no_std]
#![forbid(unsafe_code)]

//! Raw three-word relation for node #115's bounded-offset leaf.
//!
//! The input words are kept unnamed at the source-domain level because the
//! enclosing caller and original Rust type have not been identified.

/// Returns the raw `(RAX, RDX)` relation established for the #115 leaf.
///
/// This accepts three `u64` words, not the captured function's pointer ABI.
/// The first result word is `1` only when `length` is zero. The second word is
/// the minimum of the wrapped offset and `length - 1` for nonzero lengths.
pub fn bounded_offset(capacity: u64, head: u64, length: u64) -> (u64, u64) {
    if length == 0 {
        return (1, 0);
    }

    let addend = if head < capacity { 0 } else { capacity };
    let offset = capacity.wrapping_sub(head).wrapping_add(addend);
    (0, offset.min(length - 1))
}
