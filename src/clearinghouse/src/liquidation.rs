//! Binary-verified node #115 clearinghouse liquidation, backstop pro-rata allocation,
//! and ADL classification (`l1/src/clearinghouse/clearinghouse.rs:179:98`, `RE-007`).
//!
//! Target binary: Linux x86-64 `hl-node` #115, SHA-256
//! `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
//!
//! Static FDE provenance:
//! - `0x44dcf80..0x44dd1a4` (548 B): `Clearinghouse::backstop_liquidate_position_allocation`
//!   (`clearinghouse.rs:179:98`, `0x648bb28`; `impl_ntl.rs:70:1`, `0x648ba50`; `oracle.rs`, `0x648ba20`).
//! - `0x38b54b0` / `0x38b5300` / `0x448b800`: maintenance margin and exact 2/3 backstop threshold.
//! - `.rodata 0x444f1c`: `"Liquidator must use cross margin for asset "`.

use crate::margin_user_state::{
    position_margin_summary, MarginRequirement, MarginStateError, MarginTableStore,
    PositionMarginInput, PositionMarginSummary, HIP3_PERP_ASSET_STRIDE,
};

/// Exact #115 `.rodata` error prefix (`0x444f1c`) when a liquidator attempts isolated margin.
pub const ERR_LIQUIDATOR_MUST_USE_CROSS_MARGIN: &str =
    "Liquidator must use cross margin for asset ";

/// Per-position output of `0x44dcf80` (`backstop_liquidate_position_allocation`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackstopPositionAllocation {
    pub asset: usize,
    pub szi: i64,
    /// `allocated_margin.saturating_sub(ntli)`.
    pub liquidation_pnl: i64,
    /// Signed mark notional `mark_px * szi`.
    pub ntli: i64,
    /// Pro-rata equity allocated to this position (`finite_clamp_i64(account_value * |ntli| / total_abs_ntl)`).
    pub allocated_margin: i64,
    /// Mirrors `impl_ntl.rs:70:1` overflow alerts.
    pub saturated: bool,
}

/// Liquidation state classification derived from maintenance (`0x38b54b0`) and 2/3 backstop (`0x38b5300`) margins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiquidationAction {
    /// Account value >= maintenance margin: healthy.
    Healthy,
    /// `backstop_margin <= account_value < maintenance_margin`: eligible for book/market liquidation.
    MarketLiquidate { shortfall_to_maintenance: u64 },
    /// `0 <= account_value < backstop_margin`: eligible for backstop liquidator takeover.
    BackstopLiquidate { shortfall_to_backstop: u64 },
    /// `account_value < 0`: underwater bankruptcy; requires backstop/ADL deficit absorption.
    AdlDeficit { deficit_usd: u64 },
}

/// Exact #115 finite-clamped `f64 -> i64` truncation observed at `0x44dd05d..0x44dd0cb`
/// (`0x459808` = `-2^63`, `0x459360` = `2^63`, `0x458e50` = `i64::MAX as f64`, non-finite -> `0`).
#[inline]
fn finite_clamp_i64(x: f64) -> i64 {
    if !x.is_finite() {
        return 0;
    }
    let clamped = x.clamp(i64::MIN as f64, i64::MAX as f64);
    if clamped >= 9_223_372_036_854_774_784.0 {
        i64::MAX
    } else if clamped.is_nan() {
        0
    } else {
        clamped as i64
    }
}

/// Reconstructs `0x44dcf80` (`l1/src/clearinghouse/clearinghouse.rs:179:98`).
///
/// Allocates a cross-margin account's equity pro-rata to a single position during backstop liquidation
/// in proportion to `|mark_px * szi| / total_abs_ntl`, decrementing `remaining_account_value` in place.
pub fn backstop_liquidate_position_allocation(
    asset: usize,
    szi: i64,
    oracle_pxs: &[i64],
    total_abs_ntl: u64,
    account_value: i64,
    remaining_account_value: &mut i64,
) -> Result<Option<BackstopPositionAllocation>, MarginStateError> {
    let local_index = asset % HIP3_PERP_ASSET_STRIDE;
    let mark_px = *oracle_pxs
        .get(local_index)
        .ok_or(MarginStateError::OracleIndexOutOfBounds {
            local_index,
            len: oracle_pxs.len(),
        })?;
    if mark_px < 0 {
        return Err(MarginStateError::InvalidMarkOrNotionalOverflow);
    }
    let ntli = mark_px
        .checked_mul(szi)
        .ok_or(MarginStateError::InvalidMarkOrNotionalOverflow)?;
    if total_abs_ntl == 0 {
        return Ok(None);
    }

    let abs_ntl = ntli.unsigned_abs();
    let share = (abs_ntl as f64) / (total_abs_ntl as f64);
    let allocated_margin = finite_clamp_i64((account_value as f64) * share);

    let mut saturated = false;
    let liquidation_pnl = match allocated_margin.checked_sub(ntli) {
        Some(v) => v,
        None => {
            saturated = true;
            allocated_margin.saturating_sub(ntli)
        }
    };
    *remaining_account_value = match remaining_account_value.checked_sub(allocated_margin) {
        Some(v) => v,
        None => {
            saturated = true;
            remaining_account_value.saturating_sub(allocated_margin)
        }
    };

    Ok(Some(BackstopPositionAllocation {
        asset,
        szi,
        liquidation_pnl,
        ntli,
        allocated_margin,
        saturated,
    }))
}

/// Classify liquidation / backstop / ADL status for an account or isolated position against
/// exact #115 maintenance (`0x38b54b0`) and 2/3 backstop (`0x38b5300`) thresholds.
pub fn classify_liquidation(
    account_value: i64,
    maintenance_margin: u64,
    backstop_margin: u64,
) -> LiquidationAction {
    if account_value < 0 {
        return LiquidationAction::AdlDeficit {
            deficit_usd: account_value.unsigned_abs(),
        };
    }
    let equity = account_value as u64;
    if equity < backstop_margin {
        LiquidationAction::BackstopLiquidate {
            shortfall_to_backstop: backstop_margin - equity,
        }
    } else if equity < maintenance_margin {
        LiquidationAction::MarketLiquidate {
            shortfall_to_maintenance: maintenance_margin - equity,
        }
    } else {
        LiquidationAction::Healthy
    }
}

/// Evaluate liquidation status for a single position using `position_margin_summary` (`0x448b800`).
pub fn evaluate_isolated_position_liquidation(
    pos: &PositionMarginInput,
    mark_px: i64,
    max_leverage: u8,
    tables: &MarginTableStore,
) -> Result<LiquidationAction, MarginStateError> {
    let maint = position_margin_summary(
        pos,
        mark_px,
        MarginRequirement::Maintenance,
        max_leverage,
        tables,
    )?;
    let backstop = position_margin_summary(
        pos,
        mark_px,
        MarginRequirement::Backstop,
        max_leverage,
        tables,
    )?;
    match (maint, backstop) {
        (
            PositionMarginSummary::Isolated {
                account_value,
                margin_required: maint_req,
                ..
            },
            PositionMarginSummary::Isolated {
                margin_required: backstop_req,
                ..
            },
        ) => Ok(classify_liquidation(account_value, maint_req, backstop_req)),
        _ => Err(MarginStateError::ExpectedIsolatedPosition),
    }
}
