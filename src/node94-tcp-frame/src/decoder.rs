use core::fmt;

use crate::{FrameLimits, HEADER_LEN, Header, HeaderError, LengthError};

/// One decoded frame and the number of wire bytes it consumed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedFrame {
    /// Header exactly as received, including a noncanonical raw flag.
    pub header: Header,
    /// Raw payload, or the decoded LZ4 bytes when the flag is exactly one.
    pub payload: Vec<u8>,
    /// Five header bytes plus the declared payload length.
    pub consumed: usize,
}

/// Complete offline frame-decoding failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The five-byte header was incomplete.
    Header(HeaderError),
    /// A frame or LZ4 prefix failed its inclusive configured limit.
    Length(LengthError),
    /// The header was complete but fewer than the declared payload bytes followed.
    UnexpectedPayloadEof { declared: u32, actual: usize },
    /// The pinned LZ4 decoder rejected the compressed block.
    Lz4(Lz4DecodeError),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(error) => error.fmt(formatter),
            Self::Length(error) => error.fmt(formatter),
            Self::UnexpectedPayloadEof { declared, actual } => write!(
                formatter,
                "unexpected EOF while reading frame payload: declared {declared} bytes, got {actual}"
            ),
            Self::Lz4(error) => write!(formatter, "decompress_lz4 failure: {error}"),
        }
    }
}

impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Header(error) => Some(error),
            Self::Length(error) => Some(error),
            Self::Lz4(error) => Some(error),
            Self::UnexpectedPayloadEof { .. } => None,
        }
    }
}

impl From<HeaderError> for DecodeError {
    fn from(error: HeaderError) -> Self {
        Self::Header(error)
    }
}

impl From<LengthError> for DecodeError {
    fn from(error: LengthError) -> Self {
        Self::Length(error)
    }
}

/// The five verified `lz4_flex` 0.11.6 decompression error classes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Lz4DecodeError {
    /// A literal or match would exceed the prefixed output capacity.
    OutputTooSmall { expected: usize, actual: usize },
    /// A literal run extends beyond the compressed block.
    LiteralOutOfBounds,
    /// The decoder needed another input byte.
    ExpectedAnotherByte,
    /// A match used the forbidden zero offset.
    OffsetZero,
    /// A match offset points before the produced output.
    OffsetOutOfBounds,
    /// Defensive mapping for the dependency's non-exhaustive error enum.
    Unknown,
}

impl fmt::Display for Lz4DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputTooSmall { expected, actual } => write!(
                formatter,
                "provided output is too small: expected {expected}, actual {actual}"
            ),
            Self::LiteralOutOfBounds => {
                formatter.write_str("literal is out of bounds of the input")
            }
            Self::ExpectedAnotherByte => formatter.write_str("expected another byte, found none"),
            Self::OffsetZero => formatter.write_str("zero is not a valid match offset"),
            Self::OffsetOutOfBounds => {
                formatter.write_str("match offset is outside produced output")
            }
            Self::Unknown => formatter.write_str("unrecognized lz4_flex decompression error"),
        }
    }
}

impl std::error::Error for Lz4DecodeError {}

impl From<lz4_flex::block::DecompressError> for Lz4DecodeError {
    fn from(error: lz4_flex::block::DecompressError) -> Self {
        match error {
            lz4_flex::block::DecompressError::OutputTooSmall { expected, actual } => {
                Self::OutputTooSmall { expected, actual }
            }
            lz4_flex::block::DecompressError::LiteralOutOfBounds => Self::LiteralOutOfBounds,
            lz4_flex::block::DecompressError::ExpectedAnotherByte => Self::ExpectedAnotherByte,
            lz4_flex::block::DecompressError::OffsetZero => Self::OffsetZero,
            lz4_flex::block::DecompressError::OffsetOutOfBounds => Self::OffsetOutOfBounds,
            _ => Self::Unknown,
        }
    }
}

/// Decodes one complete frame prefix from `input` without performing I/O.
///
/// Trailing bytes are left untouched and reported through [`DecodedFrame::consumed`].
pub fn decode_frame(input: &[u8], limits: FrameLimits) -> Result<DecodedFrame, DecodeError> {
    let header = Header::decode(input)?;
    limits.admit(header)?;

    let payload_len = header.payload_len as usize;
    let available = input.len().saturating_sub(HEADER_LEN);
    if available < payload_len {
        return Err(DecodeError::UnexpectedPayloadEof {
            declared: header.payload_len,
            actual: available,
        });
    }

    let consumed = HEADER_LEN + payload_len;
    let wire_payload = &input[HEADER_LEN..consumed];
    let payload = if header.is_compressed() {
        decode_lz4_payload(wire_payload, header.payload_len, limits)?
    } else {
        wire_payload.to_vec()
    };

    Ok(DecodedFrame {
        header,
        payload,
        consumed,
    })
}

pub(crate) fn decode_lz4_payload(
    payload: &[u8],
    compressed_payload_len: u32,
    limits: FrameLimits,
) -> Result<Vec<u8>, DecodeError> {
    let (uncompressed_size, block) = lz4_flex::block::uncompressed_size(payload)
        .map_err(|error| DecodeError::Lz4(Lz4DecodeError::from(error)))?;
    let uncompressed_size_u32 = uncompressed_size as u32;
    limits.admit_uncompressed_size(compressed_payload_len, uncompressed_size_u32)?;
    lz4_flex::block::decompress(block, uncompressed_size)
        .map_err(|error| DecodeError::Lz4(Lz4DecodeError::from(error)))
}
