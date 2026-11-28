//! Offline projection of the selected #115 completed reader-to-decoder handoff.
#![forbid(unsafe_code)]

pub use node115_client_block_success::{AdmittedTimestamp, ReplayError, ReplayPayload};
pub use node115_lz4_decode::DecodeError as CompressionError;

use node115_client_block_success::{decode_replay_payload_prefix, replay_parent_projection};
use node115_lz4_decode::decode;

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

/// Header values staged by the selected replay-to-replica converter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplicaHeaderValues {
    pub time: AdmittedTimestamp,
    pub proposer: [u8; 20],
    pub round: u64,
    pub parent_round: u64,
    /// Version and round from the selected parent certificate, in wire order.
    pub hardfork: [u64; 2],
}

impl DecodedPrefix {
    /// Project the header of an ordinary converted Block for archive comparison.
    /// `conversion_cutoff` is the third argument supplied by the replay worker.
    /// The caller selects the ordinary conversion path before using this result.
    pub fn project_replica_header(&self, conversion_cutoff: u64) -> Option<ReplicaHeaderValues> {
        let ReplayPayload::Block { block, .. } = self.result.as_ref().ok()? else {
            return None;
        };
        let parent = replay_parent_projection(&block.header.parent);
        Some(ReplicaHeaderValues {
            time: block.header.timestamp,
            proposer: block.header.address,
            round: parent.successor,
            parent_round: conversion_cutoff,
            hardfork: parent.comparison_words,
        })
    }

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
    let decoded = decode_replay_payload_prefix(input, REPLAY_LIMIT);
    Ok(DecodedPrefix {
        result: decoded.result,
        decoder_input_len: input.len(),
        consumed: input.len() - decoded.remaining.len(),
        charged: decoded.charged,
    })
}
