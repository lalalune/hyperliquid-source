//! Equality helper `0x4e08870` and its callee `0x4e550e0`.
//!
//! `0x4e08870(a, b)` compares the length words at `+0x18`, builds a nine word iterator state for each
//! collection and calls `0x4e550e0`, which walks both in step: every pair must agree on the 20 key
//! bytes and the 65 signature bytes, and both must run out together.

use crate::sigmap::{Address, SigMap, Signature};

/// `0x4e550e0`. Natively the first iterator is stopped by its remaining counter or empty slices, and
/// the second must then be exhausted as well; a second iterator that ends first gives false.
pub fn entries_equal<'a>(
    mut first: impl Iterator<Item = (&'a Address, &'a Signature)>,
    mut second: impl Iterator<Item = (&'a Address, &'a Signature)>,
) -> bool {
    loop {
        match (first.next(), second.next()) {
            (None, None) => return true,
            (Some((ka, sa)), Some((kb, sb))) if ka == kb && sa == sb => {}
            _ => return false,
        }
    }
}

/// `0x4e08870`.
pub fn sig_maps_equal(a: &SigMap, b: &SigMap) -> bool {
    a.len() == b.len() && entries_equal(a.entries().into_iter(), b.entries().into_iter())
}
