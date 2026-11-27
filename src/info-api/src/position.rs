//! `info_server/src/f_types/position.rs` integer prefix projection and
//! liquidation-price candidate scan for node #115.
//!
//! Combines the post-lookup integer prefix semantics from `src/node115-position-integer`
//! (`RE-012-position-integer-115`) with `node115-risk-candidate-scan` (`0x2f063f0`).

use std::num::NonZeroI64;

pub use node115_risk_candidate_scan::{scan as scan_risk_candidates, Row as RiskCandidateRow, Stop as RiskCandidateStop};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DivisionWidth {
    Narrow32,
    Wide64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryDivision {
    pub quotient: u64,
    pub remainder: u64,
    pub width: DivisionWidth,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PositionIntegerObservation {
    MarkOrProductBoundary,
    EntrySignBoundary,
    SubtractionBoundary,
    Normal {
        product_word: u64,
        pnl_word: u64,
        division: Option<EntryDivision>,
    },
}

/// Interpret raw mark/entry words after lookup for a nonzero position size.
/// Mirrors `src/node115-position-integer/lib.rs`.
#[must_use]
pub fn project_position_integers(
    size: NonZeroI64,
    mark_word: u64,
    entry_word: u64,
) -> PositionIntegerObservation {
    let size = size.get();
    let mark = mark_word as i64;
    if mark < 0 {
        return PositionIntegerObservation::MarkOrProductBoundary;
    }
    let Some(product) = size.checked_mul(mark) else {
        return PositionIntegerObservation::MarkOrProductBoundary;
    };
    let entry = entry_word as i64;
    if entry == 0 {
        return PositionIntegerObservation::Normal {
            product_word: product as u64,
            pnl_word: 0,
            division: None,
        };
    }
    if entry < 0 {
        return PositionIntegerObservation::EntrySignBoundary;
    }
    let signed_entry = if size > 0 { entry } else { -entry };
    let Some(pnl) = product.checked_sub(signed_entry) else {
        return PositionIntegerObservation::SubtractionBoundary;
    };
    let magnitude = size.unsigned_abs();
    let division = if entry_word < magnitude {
        None
    } else {
        Some(EntryDivision {
            quotient: entry_word / magnitude,
            remainder: entry_word % magnitude,
            width: if (entry_word | magnitude) <= u64::from(u32::MAX) {
                DivisionWidth::Narrow32
            } else {
                DivisionWidth::Wide64
            },
        })
    };
    PositionIntegerObservation::Normal {
        product_word: product as u64,
        pnl_word: pnl as u64,
        division,
    }
}
