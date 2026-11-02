//! Frame I/O with the qualified node #94 deadline boundaries.
//!
//! A caller selects whether the header is timed (40 seconds). Each payload
//! chunk has a fresh 20-second deadline. Writes use a fresh deadline for each
//! complete-frame chunk: 20 seconds by default, or the caller's override.
//! Tokio 1.44.2 polls I/O before checking expiration, including at a tie.
//!
//! An active Tokio time driver is required whenever a deadline is used.
//! Timeout and cancellation can consume/transmit part of a frame. Discard the
//! connection unless its frame boundary can independently be restored.

use core::fmt;
use std::future::Future;
use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::stream::StreamError;
use crate::{ChunkPlan, DecodeError, DecodedFrame, FrameLimits, HEADER_LEN, Header, encode_frame};

pub const HEADER_TIMEOUT: Duration = Duration::from_secs(40);
pub const CHUNK_TIMEOUT: Duration = Duration::from_secs(20);

/// The exact I/O boundary whose deadline expired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Header,
    Payload { offset: u64, len: u64 },
    Write { offset: u64, len: u64 },
}

/// A framing failure or deadline expiry, without claiming the target's error ABI.
#[derive(Debug)]
pub enum DeadlineError {
    Stream(StreamError),
    Elapsed { phase: Phase, limit: Duration },
}

impl From<StreamError> for DeadlineError {
    fn from(error: StreamError) -> Self {
        Self::Stream(error)
    }
}

impl fmt::Display for DeadlineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stream(error) => error.fmt(f),
            Self::Elapsed { phase, limit } => write!(f, "frame {phase:?} exceeded {limit:?}"),
        }
    }
}

impl std::error::Error for DeadlineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Stream(error) => Some(error),
            Self::Elapsed { .. } => None,
        }
    }
}

async fn within<T>(
    phase: Phase,
    limit: Duration,
    operation: impl Future<Output = io::Result<T>>,
) -> Result<T, DeadlineError> {
    tokio::time::timeout(limit, operation)
        .await
        .map_err(|_| DeadlineError::Elapsed { phase, limit })?
        .map_err(|error| DeadlineError::Stream(StreamError::Io(error)))
}

/// Reads one frame with optional header timing and a deadline per payload chunk.
///
/// `time_header` represents the observed caller flag. Disabling it does not
/// disable payload deadlines. No global default for that caller flag is claimed.
pub async fn read_frame<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
    limits: FrameLimits,
    time_header: bool,
) -> Result<DecodedFrame, DeadlineError> {
    let mut header_bytes = [0; HEADER_LEN];
    if time_header {
        within(
            Phase::Header,
            HEADER_TIMEOUT,
            reader.read_exact(&mut header_bytes),
        )
        .await?;
    } else {
        reader
            .read_exact(&mut header_bytes)
            .await
            .map_err(StreamError::from)?;
    }
    let header = Header::decode(&header_bytes)
        .map_err(DecodeError::from)
        .map_err(StreamError::from)?;
    limits
        .admit(header)
        .map_err(DecodeError::from)
        .map_err(StreamError::from)?;
    let consumed = usize::try_from(u64::from(header.payload_len) + HEADER_LEN as u64)
        .map_err(|_| StreamError::AddressSpace)?;
    let mut payload = vec![0; header.payload_len as usize];
    for chunk in ChunkPlan::new(u64::from(header.payload_len)) {
        let start = chunk.offset as usize;
        let end = start + chunk.len as usize;
        within(
            Phase::Payload {
                offset: chunk.offset,
                len: chunk.len,
            },
            CHUNK_TIMEOUT,
            reader.read_exact(&mut payload[start..end]),
        )
        .await?;
    }
    if header.is_compressed() {
        payload = crate::decoder::decode_lz4_payload(&payload, header.payload_len, limits)
            .map_err(StreamError::from)?;
    }
    Ok(DecodedFrame {
        header,
        payload,
        consumed,
    })
}

/// Writes one frame with a deadline per chunk, including its header bytes.
///
/// `None` selects the observed 20-second default; `Some` is an explicit caller
/// override. The target's observed 60-second override is covered by tests.
/// This API does not recover arbitrary f64-to-duration conversion or error ABI.
pub async fn write_frame<W: AsyncWrite + Unpin + ?Sized>(
    writer: &mut W,
    payload: &[u8],
    stream_field: u16,
    override_timeout: Option<Duration>,
) -> Result<(), DeadlineError> {
    let frame = encode_frame(payload, stream_field).map_err(StreamError::from)?;
    let limit = override_timeout.unwrap_or(CHUNK_TIMEOUT);
    for chunk in frame.chunks() {
        let start = chunk.offset as usize;
        let end = start + chunk.len as usize;
        within(
            Phase::Write {
                offset: chunk.offset,
                len: chunk.len,
            },
            limit,
            writer.write_all(&frame.as_bytes()[start..end]),
        )
        .await?;
    }
    Ok(())
}
