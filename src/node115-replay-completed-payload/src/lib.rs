//! Offline projection of the selected #115 completed reader-to-decoder handoff.
#![forbid(unsafe_code)]

pub use node115_client_block_success::{ReplayError, ReplayPayload};
pub use node115_lz4_decode::DecodeError as CompressionError;

use node115_client_block_success::{decode_replay_payload_prefix, replay_parent_projection};
use node115_lz4_decode::decode;
use std::cmp::Ordering;

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

/// Decoded local-state fields before the optional startup hardfork rewrite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalStartupState {
    pub height: u64,
    pub context_round: u64,
    pub hardfork_version: u64,
    pub hardfork_round: u64,
    pub scheduled_freeze_height: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaleFreezeHeight {
    pub target: u64,
    pub restored: u64,
}

impl DecodedPrefix {
    /// Compare with the state sampled by the selected local startup path.
    /// This models the word selection on normal continuation, without applying
    /// the rewrite's other state changes or running its helpers.
    pub fn check_local_startup(
        &self,
        state: LocalStartupState,
    ) -> Result<ReplayBlockCheck, StaleFreezeHeight> {
        let original = [state.hardfork_version, state.hardfork_round];
        let expected = match state.scheduled_freeze_height {
            None => original,
            Some(target) => match target.cmp(&state.height) {
                Ordering::Less => {
                    return Err(StaleFreezeHeight {
                        target,
                        restored: state.height,
                    });
                }
                Ordering::Equal => [
                    state.hardfork_version.saturating_add(1),
                    state.context_round,
                ],
                Ordering::Greater => original,
            },
        };
        Ok(self.check_block_identity(expected))
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
