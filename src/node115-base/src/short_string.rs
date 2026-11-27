//! Short-string little-endian `u128` byte-packing grounded in node #115
//! `base/src/short_string.rs:52` (`0x15472b0..0x1547309`, 89 B).
//!
//! Verified to 100.00% relocation-qualified compiled-byte identity under
//! `rustc 1.95.0 --edition=2021 --crate-type=rlib -C opt-level=3 -C overflow-checks=yes`.

/// Maximum raw byte length that packs directly into a `u128` without overflow.
pub const MAX_INLINE_LEN: usize = 16;

/// Exact recursive `u128` byte-packer observed at `0x15472b0..0x1547309` (`base/src/short_string.rs:52`):
/// packs `bytes[idx..]` in little-endian order (`bytes[idx]` in the low byte) using checked `* 256`.
///
/// Panics with index-out-of-bounds if `idx > bytes.len()` (`short_string.rs:52:9`),
/// or multiplication overflow if `bytes[idx..]` has more than 16 bytes with a non-zero
/// high byte (`short_string.rs:52:28`).
#[inline(never)]
pub fn short_string_pack_rec(bytes: &[u8], idx: usize) -> u128 {
    if idx == bytes.len() {
        return 0;
    }
    u128::from(bytes[idx]) + short_string_pack_rec(bytes, idx + 1) * 256
}

/// Non-panicking checked helper wrapping [`short_string_pack_rec`] for inline strings (`<= 16` bytes).
pub fn try_pack_short_string(s: &str) -> Option<u128> {
    let bytes = s.as_bytes();
    if bytes.len() > MAX_INLINE_LEN {
        return None;
    }
    Some(short_string_pack_rec(bytes, 0))
}
