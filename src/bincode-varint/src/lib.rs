//! Independently authored reconstruction of the node #94 integer-varint core.
//!
//! The encode and size operations cover the observed u32/u64 paths. Decoding
//! includes the original u64 slice fast-path API and the separately qualified
//! u32/u64 Reader value/cursor relation and slice-wrapper charge/state relation.
//! Their error paths remain distinct.

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

/// Own research representation of the established Reader error payloads.
/// These Rust variants do not claim the original enum's memory layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReaderError {
    /// Additional payload bytes needed. The marker has already been consumed;
    /// an empty original input instead needs one byte and consumes nothing.
    UnexpectedEnd { needed: usize },
    /// Raw expected/found code bytes passed to the captured error builder.
    InvalidIntegerType { expected_code: u8, found_code: u8 },
}

/// Active errors of the observed little-endian slice wrappers.
/// This representation does not reproduce the captured enum's memory layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SliceError {
    /// The fixed-width charge would overflow or exceeds the configured limit.
    LimitExceeded,
    /// Active payload of an integer decoding error.
    Reader(ReaderError),
}

/// Own safe representation of the qualified slice-wrapper state.
///
/// Mode 1 enables a fixed charge of 4 or 8 before decoding; other raw modes
/// bypass charging. Charge overflow leaves the counter unchanged. Exceeding
/// the limit retains the increment. Neither rejection consumes input.
/// This is a research state constructor, not a recovered original constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SliceDecoder<'a> {
    input: &'a [u8],
    mode: u32,
    limit: u64,
    charge: u64,
}

impl<'a> SliceDecoder<'a> {
    /// Supply the observed raw state fields without inferring enum variants.
    #[must_use]
    pub const fn from_state(input: &'a [u8], mode: u32, limit: u64, charge: u64) -> Self {
        Self {
            input,
            mode,
            limit,
            charge,
        }
    }

    /// The complete unread input suffix, including any retained error marker.
    #[must_use]
    pub const fn remaining(&self) -> &'a [u8] {
        self.input
    }

    /// Current fixed-width charge; it is not a count of consumed wire bytes.
    #[must_use]
    pub const fn charge(&self) -> u64 {
        self.charge
    }

    /// Decode the qualified u32 wrapper relation, including failure state.
    pub fn read_u32(&mut self) -> Result<u32, SliceError> {
        self.read_wrapper(4, 2).map(|value| value as u32)
    }

    /// Decode the qualified u64 wrapper relation, including failure state.
    pub fn read_u64(&mut self) -> Result<u64, SliceError> {
        self.read_wrapper(8, 3)
    }

    fn claim(&mut self, width: u64) -> Result<(), SliceError> {
        if self.mode == 1 {
            let next = self
                .charge
                .checked_add(width)
                .ok_or(SliceError::LimitExceeded)?;
            self.charge = next;
            if next > self.limit {
                return Err(SliceError::LimitExceeded);
            }
        }
        Ok(())
    }

    fn read_wrapper(&mut self, width: u64, expected: u8) -> Result<u64, SliceError> {
        self.claim(width)?;
        self.read_value(width, expected)
    }

    fn read_value(&mut self, width: u64, expected: u8) -> Result<u64, SliceError> {
        if self.input.len() > width as usize {
            let found = match self.input[0] {
                U64_MARKER if width == 4 => Some(3),
                U128_MARKER => Some(4),
                0xff => Some(12),
                _ => None,
            };
            if let Some(found_code) = found {
                // Both fast wrappers use expected code 2 and retain the marker.
                return Err(SliceError::Reader(ReaderError::InvalidIntegerType {
                    expected_code: 2,
                    found_code,
                }));
            }
        }
        // For successful fast tags the existing Reader has the same value and
        // suffix relation. Only rejected fast tags need the distinction above.
        read_integer(&mut self.input, PayloadOrder::Little, expected).map_err(SliceError::Reader)
    }
}

/// Read the established u32 Reader path, advancing the slice on all outcomes.
/// An available marker is consumed even on failure; short payloads are retained.
/// This is not the original reader object's ABI or the u32 slice wrapper.
pub fn read_u32(input: &mut &[u8], order: PayloadOrder) -> Result<u32, ReaderError> {
    read_integer(input, order, 2).map(|value| value as u32)
}

/// Read the established u64 Reader path at any remaining length.
/// Unlike `decode_u64_slice_fast`, this exposes the Reader's raw error codes
/// and cursor effects. It does not select the original fast/slow slice wrapper.
pub fn read_u64(input: &mut &[u8], order: PayloadOrder) -> Result<u64, ReaderError> {
    read_integer(input, order, 3)
}

fn read_integer(
    input: &mut &[u8],
    order: PayloadOrder,
    expected_code: u8,
) -> Result<u64, ReaderError> {
    let Some((&tag, rest)) = input.split_first() else {
        return Err(ReaderError::UnexpectedEnd { needed: 1 });
    };
    *input = rest;
    let width = match tag {
        0..=250 => return Ok(u64::from(tag)),
        U16_MARKER => 2,
        U32_MARKER => 4,
        U64_MARKER if expected_code == 3 => 8,
        _ => {
            let found_code = match tag {
                U64_MARKER => 3,
                U128_MARKER => 4,
                _ => 12,
            };
            return Err(ReaderError::InvalidIntegerType {
                expected_code,
                found_code,
            });
        }
    };
    if input.len() < width {
        return Err(ReaderError::UnexpectedEnd {
            needed: width - input.len(),
        });
    }
    let payload = &input[..width];
    let value = match order {
        PayloadOrder::Little => payload
            .iter()
            .rev()
            .fold(0, |n, &byte| (n << 8) | u64::from(byte)),
        PayloadOrder::Big => payload
            .iter()
            .fold(0, |n, &byte| (n << 8) | u64::from(byte)),
    };
    *input = &input[width..];
    Ok(value)
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
/// their tag; the separately qualified Reader and wrapper APIs cover that domain.
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
