//! Independently authored reconstruction of the node #94 integer-varint core.
//!
//! The encode and size operations cover the observed u32/u64 paths. Decoding
//! is intentionally restricted to the evidence-backed u64 slice fast path.

#![forbid(unsafe_code)]

use core::fmt;

const U16_MARKER: u8 = 0xfb;
const U32_MARKER: u8 = 0xfc;
const U64_MARKER: u8 = 0xfd;
const U128_MARKER: u8 = 0xfe;
const FAST_PATH_MINIMUM_REMAINING: usize = 9;

/// Byte order used for the payload following a varint marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadOrder {
    /// Least-significant payload byte first.
    Little,
    /// Most-significant payload byte first.
    Big,
}

/// Successful result from the evidence-backed u64 slice fast path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedU64 {
    /// Decoded unsigned value.
    pub value: u64,
    /// Number of input bytes consumed by the selected arm.
    pub consumed: usize,
}

/// Outcomes for inputs outside the established u64 slice fast path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The target uses a separate reader slow path at this remaining length.
    FastPathUnavailable { remaining: usize },
    /// The target fast path reaches an error arm for this marker.
    RejectedMarker { marker: u8 },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FastPathUnavailable { remaining } => write!(
                formatter,
                "u64 slice fast path requires more than 8 bytes; {remaining} remain"
            ),
            Self::RejectedMarker { marker } => {
                write!(
                    formatter,
                    "node #94 u64 fast path rejects marker 0x{marker:02x}"
                )
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Returns the observed encoded length for a u32 value.
#[must_use]
pub const fn encoded_len_u32(value: u32) -> usize {
    if value < U16_MARKER as u32 {
        1
    } else if value <= u16::MAX as u32 {
        3
    } else {
        5
    }
}

/// Returns the observed encoded length for a u64 value.
#[must_use]
pub const fn encoded_len_u64(value: u64) -> usize {
    if value < U16_MARKER as u64 {
        1
    } else if value <= u16::MAX as u64 {
        3
    } else if value <= u32::MAX as u64 {
        5
    } else {
        9
    }
}

/// Appends the observed minimal u32 representation and returns its length.
pub fn encode_u32(value: u32, order: PayloadOrder, output: &mut Vec<u8>) -> usize {
    let encoded_len = encoded_len_u32(value);
    match encoded_len {
        1 => output.push(value as u8),
        3 => {
            output.push(U16_MARKER);
            append_u16(value as u16, order, output);
        }
        5 => {
            output.push(U32_MARKER);
            append_u32(value, order, output);
        }
        _ => unreachable!("u32 varint length is one of 1, 3 or 5"),
    }
    encoded_len
}

/// Appends the observed minimal u64 representation and returns its length.
pub fn encode_u64(value: u64, order: PayloadOrder, output: &mut Vec<u8>) -> usize {
    let encoded_len = encoded_len_u64(value);
    match encoded_len {
        1 => output.push(value as u8),
        3 => {
            output.push(U16_MARKER);
            append_u16(value as u16, order, output);
        }
        5 => {
            output.push(U32_MARKER);
            append_u32(value as u32, order, output);
        }
        9 => {
            output.push(U64_MARKER);
            append_u64(value, order, output);
        }
        _ => unreachable!("u64 varint length is one of 1, 3, 5 or 9"),
    }
    encoded_len
}

/// Decodes only the node #94 little-endian u64 slice fast path.
///
/// The target enters this path only when more than eight bytes remain. Shorter
/// inputs are returned as [`DecodeError::FastPathUnavailable`] without reading
/// their tag because the separate reader slow path is unresolved.
pub fn decode_u64_slice_fast(input: &[u8]) -> Result<DecodedU64, DecodeError> {
    if input.len() < FAST_PATH_MINIMUM_REMAINING {
        return Err(DecodeError::FastPathUnavailable {
            remaining: input.len(),
        });
    }

    let tag = input[0];
    let decoded = match tag {
        0..=0xfa => DecodedU64 {
            value: u64::from(tag),
            consumed: 1,
        },
        U16_MARKER => DecodedU64 {
            value: u64::from(u16::from_le_bytes([input[1], input[2]])),
            consumed: 3,
        },
        U32_MARKER => DecodedU64 {
            value: u64::from(u32::from_le_bytes([input[1], input[2], input[3], input[4]])),
            consumed: 5,
        },
        U64_MARKER => DecodedU64 {
            value: u64::from_le_bytes([
                input[1], input[2], input[3], input[4], input[5], input[6], input[7], input[8],
            ]),
            consumed: 9,
        },
        U128_MARKER | 0xff => return Err(DecodeError::RejectedMarker { marker: tag }),
    };

    Ok(decoded)
}

fn append_u16(value: u16, order: PayloadOrder, output: &mut Vec<u8>) {
    match order {
        PayloadOrder::Little => output.extend_from_slice(&value.to_le_bytes()),
        PayloadOrder::Big => output.extend_from_slice(&value.to_be_bytes()),
    }
}

fn append_u32(value: u32, order: PayloadOrder, output: &mut Vec<u8>) {
    match order {
        PayloadOrder::Little => output.extend_from_slice(&value.to_le_bytes()),
        PayloadOrder::Big => output.extend_from_slice(&value.to_be_bytes()),
    }
}

fn append_u64(value: u64, order: PayloadOrder, output: &mut Vec<u8>) {
    match order {
        PayloadOrder::Little => output.extend_from_slice(&value.to_le_bytes()),
        PayloadOrder::Big => output.extend_from_slice(&value.to_be_bytes()),
    }
}
