#![no_std]

//! Node #115 BlockHandle wire codec, bounded to its observed byte behavior.
//!
//! A handle is two unsigned LEB128 values in order: offset, then size. The
//! decoder intentionally accepts the target's overlong forms and preserves
//! its per-varint cursor commit behavior on failure.

extern crate alloc;

pub const BAD_BLOCK_HANDLE: &str = "bad block handle";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockHandle {
    pub offset: u64,
    pub size: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputSlice<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> InputSlice<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    pub const fn position(&self) -> usize {
        self.cursor
    }

    pub fn remaining(&self) -> &'a [u8] {
        // The cursor is advanced only to an in-bounds position.
        match self.bytes.get(self.cursor..) {
            Some(rest) => rest,
            None => &[],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeStatus {
    pub code: u32,
    pub subcode: u32,
    pub severity: u32,
    pub message: Option<&'static str>,
}

impl DecodeStatus {
    const fn ok() -> Self {
        Self {
            code: 0,
            subcode: 0,
            severity: 0,
            message: None,
        }
    }

    const fn corruption() -> Self {
        Self {
            code: 2,
            subcode: 0,
            severity: 0,
            message: Some(BAD_BLOCK_HANDLE),
        }
    }

    pub const fn is_ok(self) -> bool {
        self.code == 0 && self.message.is_none()
    }
}

/// Encode one unsigned varint64 in the target's low-group-first form.
pub fn encode_varint64(mut value: u64, output: &mut alloc::vec::Vec<u8>) {
    while value > 0x7f {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

/// Encode the handle as `varint64(offset) || varint64(size)`.
pub fn encode(handle: BlockHandle) -> alloc::vec::Vec<u8> {
    let mut output = alloc::vec::Vec::with_capacity(20);
    encode_varint64(handle.offset, &mut output);
    encode_varint64(handle.size, &mut output);
    output
}

/// Decode one target-compatible varint from `bytes` starting at `position`.
///
/// Overlong forms are accepted. At bit shift 63, only the input byte's low bit
/// contributes to the u64; a continuation bit there advances the shift past
/// 63 and fails.
pub fn decode_varint64(bytes: &[u8], position: usize) -> Option<(u64, usize)> {
    let mut cursor = position;
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *bytes.get(cursor)?;
        cursor += 1;
        if byte & 0x80 != 0 {
            value |= ((byte & 0x7f) as u64).wrapping_shl(shift);
            shift += 7;
            if shift > 63 {
                return None;
            }
            if cursor >= bytes.len() {
                return None;
            }
        } else {
            value |= (byte as u64).wrapping_shl(shift);
            return Some((value, cursor));
        }
    }
}

/// Decode into `handle`, preserving the target's output and cursor state.
///
/// The handle is zeroed before parsing. A successful first varint is committed
/// to the input cursor before the second is attempted. A partial or invalid
/// varint does not advance the cursor for that varint.
pub fn decode_into(handle: &mut BlockHandle, input: &mut InputSlice<'_>) -> DecodeStatus {
    *handle = BlockHandle::default();

    let Some((offset, after_offset)) = decode_varint64(input.bytes, input.cursor) else {
        return DecodeStatus::corruption();
    };
    input.cursor = after_offset;

    let Some((size, after_size)) = decode_varint64(input.bytes, input.cursor) else {
        return DecodeStatus::corruption();
    };
    input.cursor = after_size;
    *handle = BlockHandle { offset, size };
    DecodeStatus::ok()
}
