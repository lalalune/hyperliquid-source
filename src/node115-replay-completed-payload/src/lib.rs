//! Offline projection of the selected #115 completed reader-to-decoder handoff.
#![forbid(unsafe_code)]

pub use node115_client_block_success::{ReplayError, ReplayPayload};
pub use node115_lz4_decode::DecodeError as CompressionError;
pub use node115_tcp_stream_frame_lz4::FrameError;

use node115_client_block_success::{decode_replay_payload_prefix, replay_parent_projection};
use node115_lz4_decode::decode;
use node115_tcp_stream_frame_lz4::{Limits, read_frame};

/// Selected initial producer value for both decoded capacity and reader charge.
pub const REPLAY_LIMIT: u64 = 10_000_000;

/// Bytes from the completed read, with the reader's already selected mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletedPayload<'a> {
    Plain(&'a [u8]),
    SizePrefixedLz4(&'a [u8]),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedPrefix {
    pub result: Result<ReplayPayload, ReplayError>,
    /// The input span's length at the replay decoder, after any transform.
    pub decoder_input_len: usize,
    pub consumed: usize,
    pub charged: u64,
}

/// Outcome of comparing a completed replay Block with the startup pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayBlockCheck {
    DecodeFailed,
    Tx,
    Match { successor: u64 },
    Mismatch { observed: [u64; 2] },
}

impl DecodedPrefix {
    /// Use the caller-supplied startup pair in the observed comparison order.
    /// The successor is available only on the matching Block continuation.
    pub fn check_block_identity(&self, expected: [u64; 2]) -> ReplayBlockCheck {
        let payload = match &self.result {
            Ok(payload) => payload,
            Err(_) => return ReplayBlockCheck::DecodeFailed,
        };
        let ReplayPayload::Block { block, .. } = payload else {
            return ReplayBlockCheck::Tx;
        };
        let projection = replay_parent_projection(&block.header.parent);
        if projection.comparison_words == expected {
            ReplayBlockCheck::Match {
                successor: projection.successor,
            }
        } else {
            ReplayBlockCheck::Mismatch {
                observed: projection.comparison_words,
            }
        }
    }
}

/// Decode the completed payload using the selected initial producer's limit.
/// The result retains the consumed count on inner decoder errors. Compression
/// failure returns before starting the replay decoder.
pub fn decode_completed_payload(
    payload: CompletedPayload<'_>,
) -> Result<DecodedPrefix, CompressionError> {
    let decompressed;
    let input = match payload {
        CompletedPayload::Plain(bytes) => bytes,
        CompletedPayload::SizePrefixedLz4(bytes) => {
            decompressed = decode(bytes, REPLAY_LIMIT)?;
            &decompressed
        }
    };
    Ok(decode_plain_payload(input))
}

fn decode_plain_payload(input: &[u8]) -> DecodedPrefix {
    let decoded = decode_replay_payload_prefix(input, REPLAY_LIMIT);
    DecodedPrefix {
        result: decoded.result,
        decoder_input_len: input.len(),
        consumed: input.len() - decoded.remaining.len(),
        charged: decoded.charged,
    }
}

/// One complete frame from the saved replay byte stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramedReplay {
    pub was_compressed: bool,
    /// Bytes consumed from the original stream, including the frame header.
    pub frame_bytes_consumed: usize,
    /// Decoder outcome within the frame's selected plain or decoded payload.
    pub prefix: DecodedPrefix,
}

/// Read and decode one frame from offline capture bytes.
///
/// The slice advances by the framed reader's consumption. Clean end-of-input
/// returns `None`. The outer result describes the framing or decompression
/// stage. The inner prefix keeps the payload decoder's own consumption and
/// result, which can differ from the full frame's consumption.
pub fn decode_framed_replay(input: &mut &[u8]) -> Result<Option<FramedReplay>, FrameError> {
    let before = input.len();
    let limits = Limits {
        frame_payload: REPLAY_LIMIT,
        decoded_capacity: REPLAY_LIMIT,
    };
    Ok(read_frame(input, limits)?.map(|frame| FramedReplay {
        was_compressed: frame.was_compressed,
        frame_bytes_consumed: before - input.len(),
        prefix: decode_plain_payload(&frame.payload),
    }))
}
