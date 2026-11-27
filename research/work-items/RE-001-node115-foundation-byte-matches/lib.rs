#![forbid(unsafe_code)]

//! Independently authored node #115 `foundation` (`base`) rlib business-logic
//! reconstruction compiled under:
//! `rustc 1.95.0 (59807616e 2026-04-14) --edition=2021 --crate-type=rlib -C opt-level=3 -C overflow-checks=yes`.
//!
//! Target: Linux x86-64 node #115
//! (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).

/// Exact reconstruction of `base/src/short_string.rs:52` (`0x15472b0..0x1547309`, 89 B):
/// recursive little-endian `u128` byte-packer with checked `* 256` multiplication.
#[inline(never)]
pub fn short_string_pack_rec(bytes: &[u8], idx: usize) -> u128 {
    if idx == bytes.len() {
        return 0;
    }
    u128::from(bytes[idx]) + short_string_pack_rec(bytes, idx + 1) * 256
}
