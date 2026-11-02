//! Asynchronous frame boundaries over caller-owned I/O.
//!
//! Reads first fill the five-byte header, apply the length limit, then fill
//! payload chunks of at most 4,000,000 bytes. Writes chunk the complete encoded
//! frame. Short reads/writes and `Pending` are handled by Tokio 1.44.2's exact
//! I/O operations. This layer does not flush, close, reconnect, or set deadlines.
//!
//! These operations are not cancellation safe: cancellation or an I/O error
//! can leave part of a frame consumed or sent. The caller must discard the
//! connection unless it independently knows how to restore its frame boundary.

use core::fmt;
use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    ChunkPlan, DecodeError, DecodedFrame, EncodeError, FrameLimits, HEADER_LEN, Header,
    encode_frame,
};

/// Errors from an I/O operation or the existing frame codec.
#[derive(Debug)]
pub enum StreamError {
    /// Transport error, including premature EOF and a zero-progress write.
    Io(io::Error),
    /// Length admission or compressed-payload decoding failed.
    Decode(DecodeError),
    /// Encoding failed before any bytes were written.
    Encode(EncodeError),
    /// The frame's consumed-byte count cannot fit this host's address space.
    /// This cannot occur for a u32-sized frame on the target's 64-bit platform.
    AddressSpace,
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::Decode(error) => error.fmt(f),
            Self::Encode(error) => error.fmt(f),
            Self::AddressSpace => f.write_str("frame length exceeds host address space"),
        }
    }
}

impl std::error::Error for StreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Decode(error) => Some(error),
            Self::Encode(error) => Some(error),
            Self::AddressSpace => None,
        }
    }
}

impl From<io::Error> for StreamError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<DecodeError> for StreamError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

impl From<EncodeError> for StreamError {
    fn from(error: EncodeError) -> Self {
        Self::Encode(error)
    }
}

/// Reads exactly one frame without consuming any bytes from the next frame.
///
/// EOF, even before the first header byte, is `StreamError::Io` with
/// `UnexpectedEof`. A rejected header does not consume its advertised payload.
/// Length admission happens before allocating or reading the payload. The same
/// limit is applied to an LZ4 size prefix before allocating decompressed output.
pub async fn read_frame<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
    limits: FrameLimits,
) -> Result<DecodedFrame, StreamError> {
    let mut header_bytes = [0; HEADER_LEN];
    reader.read_exact(&mut header_bytes).await?;
    let header = Header::decode(&header_bytes).map_err(DecodeError::from)?;
    limits.admit(header).map_err(DecodeError::from)?;
    let consumed = usize::try_from(u64::from(header.payload_len) + HEADER_LEN as u64)
        .map_err(|_| StreamError::AddressSpace)?;

    let mut payload = vec![0; header.payload_len as usize];
    for chunk in ChunkPlan::new(u64::from(header.payload_len)) {
        let start = chunk.offset as usize;
        let end = start + chunk.len as usize;
        reader.read_exact(&mut payload[start..end]).await?;
    }
    if header.is_compressed() {
        payload = crate::decoder::decode_lz4_payload(&payload, header.payload_len, limits)?;
    }
    Ok(DecodedFrame {
        header,
        payload,
        consumed,
    })
}

/// Encodes and writes one complete frame, without flushing the caller's I/O.
///
/// Chunk boundaries include the five header bytes, unlike the reader's payload
/// chunk boundaries. The stream field retains the existing codec's compression
/// policy; it is not assigned a peer or listener role by this API.
pub async fn write_frame<W: AsyncWrite + Unpin + ?Sized>(
    writer: &mut W,
    payload: &[u8],
    stream_field: u16,
) -> Result<(), StreamError> {
    let frame = encode_frame(payload, stream_field)?;
    for chunk in frame.chunks() {
        let start = chunk.offset as usize;
        let end = start + chunk.len as usize;
        writer.write_all(&frame.as_bytes()[start..end]).await?;
    }
    Ok(())
}
