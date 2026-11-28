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

/// Binary64 values before the position response's decimal-string formatter.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PositionValues {
    pub signed_size: f64,
    pub position_value: f64,
    pub unrealized_pnl: f64,
    pub entry_price: Option<f64>,
}

/// Boundaries outside the selected normally returning projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PositionValueBoundary {
    MarkOrProduct,
    EntrySign,
    Subtraction,
    AssetDecimals,
}

/// Project post-lookup perp position display values from raw fixed-point words.
/// A flat position has no row. Asset size decimals in this projection are 0..=6.
pub fn project_position_values(
    size: i64,
    mark_word: u64,
    entry_word: u64,
    size_decimals: u8,
) -> Result<Option<PositionValues>, PositionValueBoundary> {
    let Some(size) = NonZeroI64::new(size) else {
        return Ok(None);
    };
    let (product, pnl, division) = match project_position_integers(size, mark_word, entry_word) {
        PositionIntegerObservation::Normal {
            product_word,
            pnl_word,
            division,
        } => (product_word as i64, pnl_word as i64, division),
        PositionIntegerObservation::MarkOrProductBoundary => {
            return Err(PositionValueBoundary::MarkOrProduct)
        }
        PositionIntegerObservation::EntrySignBoundary => {
            return Err(PositionValueBoundary::EntrySign)
        }
        PositionIntegerObservation::SubtractionBoundary => {
            return Err(PositionValueBoundary::Subtraction)
        }
    };
    const SCALES: [f64; 7] = [1., 10., 100., 1_000., 10_000., 100_000., 1_000_000.];
    let decimals = usize::from(size_decimals);
    let size_scale = SCALES
        .get(decimals)
        .ok_or(PositionValueBoundary::AssetDecimals)?;
    let quote_scale = SCALES[6];
    Ok(Some(PositionValues {
        signed_size: size.get() as f64 / size_scale,
        position_value: product.unsigned_abs() as f64 / quote_scale,
        unrealized_pnl: pnl as f64 / quote_scale,
        entry_price: division.map(|d| d.quotient as f64 / SCALES[6 - decimals]),
    }))
}
