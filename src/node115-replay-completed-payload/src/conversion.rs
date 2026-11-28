//! Offline model of the selected replay worker's ordinary conversion cursor.

/// The worker's two round values after restoring a checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConversionCursor {
    expected_identity: u64,
    cutoff: u64,
}

/// Values entering the selected record comparison and conversion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparedRecord {
    /// Selected identity from the worker's prepared first owner.
    pub identity: u64,
    /// Saturated successor from the selected parent projection.
    pub successor: u64,
    /// Input count of the prepared second owner, before any row filtering.
    pub attachment_count: u64,
}

/// Projection of the comparison, empty gate and selected normal continuation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConversionOutcome {
    IdentityMismatch { expected: u64, observed: u64 },
    EmptyRecordSkipped,
    Converted { parent_round: u64 },
}

impl ConversionCursor {
    pub fn from_restored_round(round: u64) -> Self {
        Self {
            expected_identity: round,
            cutoff: round,
        }
    }

    pub fn expected_identity(&self) -> u64 {
        self.expected_identity
    }

    pub fn cutoff(&self) -> u64 {
        self.cutoff
    }

    /// Evaluate a prepared record in an offline sequence of normal continuations.
    ///
    /// A mismatch leaves the cursor untouched. A matching record advances the
    /// identity even if the empty-input check skips it. When a record passes
    /// that check, the model assumes the selected continuation completes and
    /// provides the previous cutoff for the projected replica header.
    pub fn observe(&mut self, record: PreparedRecord) -> ConversionOutcome {
        if record.identity != self.expected_identity {
            return ConversionOutcome::IdentityMismatch {
                expected: self.expected_identity,
                observed: record.identity,
            };
        }
        self.expected_identity = record.successor;
        if record.attachment_count == 0 && record.successor < self.cutoff.saturating_add(10) {
            return ConversionOutcome::EmptyRecordSkipped;
        }
        let parent_round = self.cutoff;
        self.cutoff = record.successor;
        ConversionOutcome::Converted { parent_round }
    }
}
