//! The accepted byte language of the node 115 storage-value reader.
//!
//! See `RE-001-node115-storage-value-decode`. This is a standalone decoder for
//! supplied database-value bytes, not a database, RPC handler or key-prefix
//! implementation. Native allocated error objects and failure cursor positions
//! are intentionally represented by one local rejection type.
#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decoded {
    /// Four limbs, least-significant limb first, as in the selected native output.
    pub limbs: [u64; 4],
    /// Bytes consumed by the successful first value. Trailing bytes are permitted.
    pub consumed: usize,
}

/// A local rejection marker, not the native diagnostic error representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidValue;

/// Decode the accepted forms of a fresh storage-value deserializer.
///
/// MessagePack bin8/bin16/bin32 with exactly 32 payload bytes are accepted.
/// String headers with a 32-byte payload are accepted only when that payload
/// is invalid UTF-8: the selected native reader falls back to its byte visitor.
/// Valid UTF-8 strings and all other MessagePack kinds are rejected.
pub fn decode(input: &[u8]) -> Result<Decoded, InvalidValue> {
    let marker = *input.first().ok_or(InvalidValue)?;
    let (length_bytes, string) = match marker {
        0xc4 => (1, false),
        0xc5 => (2, false),
        0xc6 => (4, false),
        0xd9 => (1, true),
        0xda => (2, true),
        0xdb => (4, true),
        _ => return Err(InvalidValue),
    };
    let header = 1 + length_bytes;
    let encoded_length = input.get(1..header).ok_or(InvalidValue)?;
    let mut length = 0_u32;
    for &byte in encoded_length {
        length = (length << 8) | u32::from(byte);
    }
    if length != 32 {
        return Err(InvalidValue);
    }
    let consumed = header + 32;
    let payload = input.get(header..consumed).ok_or(InvalidValue)?;
    if string && core::str::from_utf8(payload).is_ok() {
        return Err(InvalidValue);
    }
    let mut limbs = [0; 4];
    for (index, bytes) in payload.chunks_exact(8).enumerate() {
        let mut word = [0; 8];
        word.copy_from_slice(bytes);
        limbs[3 - index] = u64::from_be_bytes(word);
    }
    Ok(Decoded { limbs, consumed })
}
