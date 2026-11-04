#![no_std]

/// A new logical byte projection, not the original tagged-object ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selector<'a> {
    Numeric(u64),
    CopySource(&'a [u8]),
}

/// The caller may copy CopySource bytes when composing an owned result.
/// This function reconstructs only normal-return byte/value policy, without
/// the native allocator, lifetime, context lookup or source-type assumptions.
pub fn project(input: &[u8]) -> Selector<'_> {
    let fallback = Selector::CopySource(input);
    if input.len() == 9 {
        let word = u64::from_le_bytes([input[0],input[1],input[2],input[3],input[4],input[5],input[6],input[7]]);
        if word == u64::from_le_bytes(*b"PURR/USD") && input[8] == b'C' {
            return Selector::Numeric(0);
        }
    }
    if input.len() < 2 || input.len() > 21 { return fallback; }
    let prefix = input[0];
    if prefix != b'#' && prefix != b'@' { return fallback; }
    let digits = &input[1..];
    if digits.len() > 1 && digits[0] == b'0' { return fallback; }
    let mut n = 0u64;
    for &byte in digits {
        let Some(digit) = byte.checked_sub(b'0') else { return fallback; };
        if digit > 9 { return fallback; }
        let Some(next) = n.checked_mul(10).and_then(|v| v.checked_add(digit as u64)) else { return fallback; };
        n = next;
    }
    if prefix == b'@' {
        if n == 0 || n >= 100_000_000 { return fallback; }
        Selector::Numeric(n)
    } else {
        Selector::Numeric(n.saturating_add(100_000_000))
    }
}

/// Synthetic validation layout: tag/value/borrow-pointer/borrow-length.
/// No original Rust enum layout, allocated pointer or FFI ABI is asserted.
/// # Safety
/// out names4 exclusive writable aligned u64s; bytes is a nonnull readable
/// initialized nonwrapping allocation of length bytes (len<=isize::MAX).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn node115_selector_probe(out: *mut u64, bytes: *const u8, length: usize) {
    let input = unsafe { core::slice::from_raw_parts(bytes,length) };
    let (tag,value,pointer,size) = match project(input) {
        Selector::Numeric(n) => (418, n, 0, 0),
        Selector::CopySource(b) => (104, 0, b.as_ptr() as usize as u64, b.len() as u64),
    };
    unsafe {
        out.add(0).write_volatile(tag);
        out.add(1).write_volatile(value);
        out.add(2).write_volatile(pointer);
        out.add(3).write_volatile(size);
    }
}
