//! Compare retained Block links from separately acquired offline observations.

/// Bytes in the selected retained Block link field.
pub type BlockFingerprint = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedRow {
    /// Incoming selected identity.
    pub identity: u64,
    /// Saturated successor of the selected native basis.
    pub successor: u64,
    /// Incoming observed link, if the offline input supplies it.
    pub observed_predecessor: Option<BlockFingerprint>,
    /// This row's same-kind native Block fingerprint, if supplied.
    pub block_fingerprint: Option<BlockFingerprint>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContinuityError {
    Identity {
        row: usize,
        expected: u64,
        observed: u64,
    },
    MissingBlockFingerprint {
        row: usize,
    },
    MissingObservedPredecessor {
        row: usize,
    },
    Predecessor {
        row: usize,
        expected: BlockFingerprint,
        observed: BlockFingerprint,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Continuity {
    pub checked_rows: usize,
    pub next_identity: u64,
    /// The last row's supplied fingerprint for a following comparison.
    pub next_predecessor: Option<BlockFingerprint>,
}

/// Compare the first expected identity and each following retained link.
///
/// The local batch starts without an expected predecessor. Later rows require
/// the immediately preceding row's supplied fingerprint, and the comparison
/// stops at the first mismatch or missing observation. Both byte arrays must
/// come from the same native Block-link kind.
pub fn check_continuity(
    seed_identity: u64,
    rows: &[RetainedRow],
) -> Result<Continuity, ContinuityError> {
    let mut next_identity = seed_identity;
    let mut next_predecessor = None;
    for (row, block) in rows.iter().enumerate() {
        if block.identity != next_identity {
            return Err(ContinuityError::Identity {
                row,
                expected: next_identity,
                observed: block.identity,
            });
        }
        if row != 0 {
            let expected = next_predecessor
                .ok_or(ContinuityError::MissingBlockFingerprint { row: row - 1 })?;
            let observed = block
                .observed_predecessor
                .ok_or(ContinuityError::MissingObservedPredecessor { row })?;
            if expected != observed {
                return Err(ContinuityError::Predecessor {
                    row,
                    expected,
                    observed,
                });
            }
        }
        next_identity = block.successor;
        next_predecessor = block.block_fingerprint;
    }
    Ok(Continuity {
        checked_rows: rows.len(),
        next_identity,
        next_predecessor,
    })
}
