//! Materialized fixture entry coordinates for the selected local startup path.

const COMPACT_STATE_BYTES: usize = 0x42c8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactLocalRestoreError {
    WrongSize { actual: usize },
    HeightMismatch { expected: u64, actual: u64 },
    FreezeTag(u32),
}

/// Original materialized state words before the local startup rewrite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactLocalRestoreInput {
    pub height: u64,
    pub context_round: u64,
    pub hardfork_version: u64,
    pub hardfork_round: u64,
    pub scheduled_freeze: Option<u64>,
}

impl CompactLocalRestoreInput {
    /// Read a caller-pinned #115 compact checkpoint at the requested height.
    ///
    /// For the ordinary freeze option the low tag dword is 0 or 1. The
    /// inactive payload and the four bytes above the tag are not semantic input.
    pub fn from_checkpoint(
        image: &[u8],
        expected_height: u64,
    ) -> Result<Self, CompactLocalRestoreError> {
        if image.len() != COMPACT_STATE_BYTES {
            return Err(CompactLocalRestoreError::WrongSize {
                actual: image.len(),
            });
        }
        let word = |offset: usize| u64::from_le_bytes(image[offset..][..8].try_into().unwrap());
        let height = word(0x28);
        if height != expected_height {
            return Err(CompactLocalRestoreError::HeightMismatch {
                expected: expected_height,
                actual: height,
            });
        }
        let tag = u32::from_le_bytes(image[0x10e8..0x10ec].try_into().unwrap());
        let scheduled_freeze = match tag {
            0 => None,
            1 => Some(word(0x10f0)),
            value => return Err(CompactLocalRestoreError::FreezeTag(value)),
        };
        Ok(Self {
            height,
            context_round: word(0x30),
            hardfork_version: word(0x18),
            hardfork_round: word(0x20),
            scheduled_freeze,
        })
    }
}
