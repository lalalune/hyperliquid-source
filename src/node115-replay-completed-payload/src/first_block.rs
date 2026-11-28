//! First Block selection in an offline, ordered replay fixture.

use node115_client_block_success::{Attachment, Block, replay_parent_projection};

use crate::{
    CompletedPayload, CompressionError, ReplayError, ReplayPayload, decode_completed_payload,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedBlock {
    /// Zero-based position in the supplied fixture, including preceding Tx items.
    pub position: usize,
    pub decoder_input_len: usize,
    pub decoder_consumed: usize,
    pub decoder_charged: u64,
    pub successor: u64,
    pub block: Box<Block>,
    pub attachments: Option<Vec<Attachment>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectionError {
    Compression {
        position: usize,
        error: CompressionError,
    },
    Decode {
        position: usize,
        consumed: usize,
        error: ReplayError,
    },
    StartupPair {
        position: usize,
        expected: [u64; 2],
        observed: [u64; 2],
    },
}

/// Select the first Block candidate from complete, already ordered payloads.
///
/// Opaque Tx items consume fixture positions without supplying a Block. A
/// decoding gap or mismatched first Block is reported at its position. The
/// caller supplies the observed startup pair and the ordering of the capture.
pub fn select_first_block(
    payloads: &[CompletedPayload<'_>],
    startup_pair: [u64; 2],
) -> Result<Option<SelectedBlock>, SelectionError> {
    for (position, payload) in payloads.iter().enumerate() {
        let decoded = decode_completed_payload(*payload)
            .map_err(|error| SelectionError::Compression { position, error })?;
        let payload = decoded.result.map_err(|error| SelectionError::Decode {
            position,
            consumed: decoded.consumed,
            error,
        })?;
        let ReplayPayload::Block { block, attachments } = payload else {
            continue;
        };
        let parent = replay_parent_projection(&block.header.parent);
        if parent.comparison_words != startup_pair {
            return Err(SelectionError::StartupPair {
                position,
                expected: startup_pair,
                observed: parent.comparison_words,
            });
        }
        return Ok(Some(SelectedBlock {
            position,
            decoder_input_len: decoded.decoder_input_len,
            decoder_consumed: decoded.consumed,
            decoder_charged: decoded.charged,
            successor: parent.successor,
            block,
            attachments,
        }));
    }
    Ok(None)
}
