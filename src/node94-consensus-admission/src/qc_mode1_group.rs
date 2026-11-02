//! Qualified mode-one reservation and accepted-marker group composition.
//!
//! This closes the mode1 non-FD/reservation domain of node94 `0x466bf60`,
//! using the independently recovered accepted-value kernel. Final state only:
//! no original decoder ABI, inactive error meaning or instruction-store trace.

use crate::qc_mode0_group::{read_mode0_group, Mode0GroupOutcome};

/// Chosen safe type; its Rust layout has no native enum/ABI meaning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode1GroupOutcome {
    /// Wrong full mode word, or unsupported marker after admitted reservation.
    /// Atomic refusal here is a chosen API rule, outside the native claim.
    OutsideDomain,
    Complete([u64; 4]),
    Incomplete { needed: u64 },
    /// Initial reservation denial. No need or inactive payload is assigned.
    BudgetDenied,
}

impl Mode1GroupOutcome {
    /// Observed active group tag/kind/optional need; no inactive error bytes.
    pub fn observed_error_fields(&self) -> Option<(u64, u8, Option<u64>)> {
        match self {
            Self::BudgetDenied => Some((1, 2, None)),
            Self::Incomplete { needed } => Some((1, 0, Some(*needed))),
            _ => None,
        }
    }

    /// Write the complete-success or pre-marker-denial 40-byte memory view.
    ///
    /// On initial denial only the tag qword and kind byte are written; all
    /// other 31 supplied bytes remain unchanged, without assigned payload
    /// meaning. Incomplete/OutsideDomain have no raw memory projection here:
    /// false leaves this safe API's buffer unchanged and is not native behavior.
    pub fn write_result_view(&self, group: &mut [u8; 40]) -> bool {
        match self {
            Self::Complete(words) => {
                group[..8].copy_from_slice(&0u64.to_le_bytes());
                for (index, word) in words.iter().enumerate() {
                    group[8 + index * 8..16 + index * 8].copy_from_slice(&word.to_le_bytes());
                }
                true
            }
            Self::BudgetDenied => {
                let (tag, kind, _) = self.observed_error_fields().unwrap();
                group[..8].copy_from_slice(&tag.to_le_bytes());
                group[8] = kind;
                true
            }
            _ => false,
        }
    }
}

/// Project a full-word-one group: initial budget denial or four accepted reads.
///
/// Overflow leaves charge unchanged. Otherwise an exceeded limit retains C+32.
/// Both denials precede marker qualification and leave the input unchanged.
/// On admitted accepted-marker success/short, each scalar-return charge is C+32;
/// the native reserve/refund composition reduces to that final-state value.
/// FE/FF after admission and other full mode words remain outside this API's
/// native claim. Mode construction, full QC reachability and store timing are
/// not established. The shared kernel's unsigned LE/cursor semantics are
/// separately credited; its mode-zero parameter is a safe-code implementation
/// choice, not a claim that the native mode word changes.
pub fn read_mode1_group(
    mode_word: u64,
    charge: &mut u64,
    limit: u64,
    input: &mut &[u8],
) -> Mode1GroupOutcome {
    if mode_word != 1 {
        return Mode1GroupOutcome::OutsideDomain;
    }
    let Some(reserved_charge) = charge.checked_add(32) else {
        return Mode1GroupOutcome::BudgetDenied;
    };
    if reserved_charge > limit {
        *charge = reserved_charge;
        return Mode1GroupOutcome::BudgetDenied;
    }
    let mut suffix = *input;
    let mut unused_charge = 0;
    let outcome = match read_mode0_group(0, &mut unused_charge, 0, &mut suffix) {
        Mode0GroupOutcome::Complete(words) => Mode1GroupOutcome::Complete(words),
        Mode0GroupOutcome::Incomplete { needed } => Mode1GroupOutcome::Incomplete { needed },
        Mode0GroupOutcome::OutsideDomain => return Mode1GroupOutcome::OutsideDomain,
    };
    *charge = reserved_charge;
    *input = suffix;
    outcome
}
