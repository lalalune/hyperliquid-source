//! Binary-verified clearinghouse position fold (`0x3bebd70`), isolated position
//! check (`0x447e810`), position ratio (`0x446b840`), margin test (`0x469b990`),
//! and asset decimal scaler (`risk-asset-decimal-scale-115`).
//!
//! Anchored to node #115 evidence packets:
//! - `research/work-items/risk-position-family-115` (12,535 cases, 0 mismatches)
//! - `research/work-items/risk-position-ratio-115` (16,024 cases, 0 mismatches)
//! - `research/work-items/risk-asset-decimal-scale-115`

/// Minimum `f64` ratio floor observed at `0x459b00` (`1e-8`) in `0x446b840`.
pub const RATIO_FLOOR: f64 = 1e-8;

/// Final floor threshold (`-100`) observed in `0x469b990`.
pub const MARGIN_TEST_FLOOR: i64 = -100;

/// Observed status/error tags in `0x447e810` and `0x469b990`.
pub const TAG_OK: u16 = 0x1a2;
pub const TAG_INVALID_FRACTION: u16 = 0x46;
pub const TAG_ARITH_OVERFLOW: u16 = 0xc4;
pub const TAG_UNSUPPORTED_ASSET_MODE: u16 = 0x14e;

/// Per-position risk fields matching the 64-byte record layout in `0x3bebd70`,
/// `0x447e810`, and `0x446b840`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PositionRiskRecord {
    /// `+0x00`: mode tag (`1` = isolated in `0x3bebd70`; bit 0 checked in `0x447e810`/`0x446b840`).
    pub tag: u32,
    /// `+0x04`: leverage / margin divisor (`u32`; `0` faults on divide in `0x3bebd70`).
    pub divisor: u32,
    /// `+0x08`: stored isolated balance / raw margin offset (`i64`).
    pub stored_balance: i64,
    /// `+0x10`: signed position size `v` (`i64`).
    pub signed_size: i64,
    /// `+0x30`: entry notional / basis `b` (`i64`, must be non-negative in `0x446b840`).
    pub entry_ntl: i64,
}

/// Fault / panic outcomes matching the exact checks of `0x3bebd70`, `0x447e810`, `0x446b840`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PositionRiskError {
    /// `asset_key % 10_000 >= oracle_rows.len()` (`oracle.rs:433:18`).
    OracleRowOutOfBounds { index: usize, len: usize },
    /// `asset_key / 10_000 != expected_dex` or `asset_key % 10_000 >= assets.len()` (`perp_meta.rs:163:38`).
    AssetOutOfBounds { asset_key: u64 },
    /// Oracle price `< 0` or `oracle_px * signed_size` overflowed `i64` (`position.rs:204:57`).
    InvalidPriceOrProductOverflow,
    /// Zero divisor (`u32 == 0`, hardware divide fault in `0x3bebd70`).
    ZeroDivisor,
    /// Quotient `>= 2^63` (`Result::unwrap()` panic in `0x3bebd70` / `0x447e810`).
    QuotientOutOfI64Range,
    /// Negative `entry_ntl` in `0x446b840`.
    NegativeEntryNotional,
}

/// Output of [`fold_account_positions`] (`0x3bebd70`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FoldResult {
    pub required_equity: i64,
    pub raw_accumulator: i64,
    pub saturations: usize,
}

fn sat_add(a: i64, b: i64, sats: &mut usize) -> i64 {
    match a.checked_add(b) {
        Some(v) => v,
        None => {
            *sats += 1;
            if b > 0 { i64::MAX } else { i64::MIN }
        }
    }
}

fn sat_sub(a: i64, b: i64, sats: &mut usize) -> i64 {
    match a.checked_sub(b) {
        Some(v) => v,
        None => {
            *sats += 1;
            if b < 0 { i64::MAX } else { i64::MIN }
        }
    }
}

/// Reconstructs node #115 account position fold `0x3bebd70` (`risk-position-family-115`).
pub fn fold_account_positions(
    initial_acc: i64,
    positions: &[(u64, PositionRiskRecord)],
    oracle_rows: &[i64],
) -> Result<FoldResult, PositionRiskError> {
    let mut acc = initial_acc;
    let mut saturations = 0usize;

    for &(asset_key, rec) in positions {
        let idx = (asset_key % 10_000) as usize;
        let &oracle_px = oracle_rows
            .get(idx)
            .ok_or(PositionRiskError::OracleRowOutOfBounds {
                index: idx,
                len: oracle_rows.len(),
            })?;
        if oracle_px < 0 {
            return Err(PositionRiskError::InvalidPriceOrProductOverflow);
        }
        let product = oracle_px
            .checked_mul(rec.signed_size)
            .ok_or(PositionRiskError::InvalidPriceOrProductOverflow)?;
        if rec.divisor == 0 {
            return Err(PositionRiskError::ZeroDivisor);
        }
        let quotient_u64 = product.unsigned_abs() / u64::from(rec.divisor);
        if quotient_u64 >= (1u64 << 63) {
            return Err(PositionRiskError::QuotientOutOfI64Range);
        }
        let quotient = quotient_u64 as i64;

        if rec.tag == 1 {
            let extra = sat_add(product, rec.stored_balance, &mut saturations);
            if extra < quotient {
                acc = sat_add(acc, extra, &mut saturations);
                acc = sat_sub(acc, quotient, &mut saturations);
            }
        } else {
            acc = sat_add(acc, product, &mut saturations);
            acc = sat_sub(acc, quotient, &mut saturations);
        }
    }

    let required_equity = if acc == i64::MIN {
        i64::MAX
    } else {
        (-acc).max(0)
    };

    Ok(FoldResult {
        required_equity,
        raw_accumulator: acc,
        saturations,
    })
}

/// Outcome of [`check_isolated_position`] (`0x447e810`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IsolatedCheckOutcome {
    /// No emit required (or rejected with non-emit status code `0x46`, `0x14e`, `0xc4`, `0x1a2`).
    Status(u16),
    /// Positive shortfall `diff > 0` triggers the emit slot `0x64e7b28` (`0x447d1d0`).
    EmitRequired { diff: i64 },
}

/// Reconstructs node #115 single-position isolated margin check `0x447e810`.
pub fn check_isolated_position(
    expected_dex: u64,
    asset_key: u64,
    fraction: f64,
    asset_modes: &[u8],
    oracle_rows: &[i64],
    position: Option<PositionRiskRecord>,
) -> Result<IsolatedCheckOutcome, PositionRiskError> {
    // Note: NaN passes both `!(0.5 > x)` and `!(x > 1.0)` in node #115 `0x447e810`!
    // Using `(0.5..=1.0).contains(&fraction)` would diverge on NaN.
    #[allow(clippy::manual_range_contains)]
    if 0.5 > fraction || fraction > 1.0 {
        return Ok(IsolatedCheckOutcome::Status(TAG_INVALID_FRACTION));
    }
    let dex = asset_key / 10_000;
    let idx = (asset_key % 10_000) as usize;
    if dex != expected_dex || idx >= asset_modes.len() {
        return Err(PositionRiskError::AssetOutOfBounds { asset_key });
    }
    if asset_modes[idx] != 2 {
        return Ok(IsolatedCheckOutcome::Status(TAG_UNSUPPORTED_ASSET_MODE));
    }
    let Some(rec) = position else {
        return Ok(IsolatedCheckOutcome::Status(TAG_OK));
    };
    let &oracle_px = oracle_rows
        .get(idx)
        .ok_or(PositionRiskError::OracleRowOutOfBounds {
            index: idx,
            len: oracle_rows.len(),
        })?;
    if oracle_px < 0 {
        return Err(PositionRiskError::InvalidPriceOrProductOverflow);
    }
    let product = oracle_px
        .checked_mul(rec.signed_size)
        .ok_or(PositionRiskError::InvalidPriceOrProductOverflow)?;
    if (rec.tag & 1) == 0 {
        return Ok(IsolatedCheckOutcome::Status(TAG_OK));
    }

    let mut sats = 0usize;
    let total = sat_add(product, rec.stored_balance, &mut sats);
    let abs_prod = product.unsigned_abs();
    if abs_prod >= (1u64 << 63) {
        return Err(PositionRiskError::QuotientOutOfI64Range);
    }
    let scaled = (abs_prod as f64) * (1.0 / fraction);
    let cast = if !scaled.is_finite() {
        0i64
    } else {
        scaled as i64
    };
    let Some(diff) = cast.checked_sub(total) else {
        return Ok(IsolatedCheckOutcome::Status(TAG_ARITH_OVERFLOW));
    };
    if diff <= 0 {
        Ok(IsolatedCheckOutcome::Status(TAG_OK))
    } else {
        Ok(IsolatedCheckOutcome::EmitRequired { diff })
    }
}

/// Reconstructs node #115 clearinghouse position ratio `0x446b840` (`risk-position-ratio-115`).
///
/// Returns `Ok(None)` when the position is absent, zero-sized, or fails the side test
/// (`(signed_size <= 0) ^ is_long`). Otherwise returns `Ok(Some(ratio1 * ratio2))`.
pub fn compute_position_ratio(
    asset_key: u64,
    is_long: bool,
    position: Option<PositionRiskRecord>,
    oracle_rows: &[i64],
    cross_figure: i64,
) -> Result<Option<f64>, PositionRiskError> {
    let Some(rec) = position else {
        return Ok(None);
    };
    let v = rec.signed_size;
    if v == 0 || !((v <= 0) ^ is_long) {
        return Ok(None);
    }
    let idx = (asset_key % 10_000) as usize;
    let &oracle_px = oracle_rows
        .get(idx)
        .ok_or(PositionRiskError::OracleRowOutOfBounds {
            index: idx,
            len: oracle_rows.len(),
        })?;
    if oracle_px < 0 {
        return Err(PositionRiskError::InvalidPriceOrProductOverflow);
    }
    let product = oracle_px
        .checked_mul(v)
        .ok_or(PositionRiskError::InvalidPriceOrProductOverflow)?;

    let mut sats = 0usize;
    let figure = if (rec.tag & 1) != 0 {
        sat_add(product, rec.stored_balance, &mut sats)
    } else {
        cross_figure
    };
    let ratio1 = if figure > 0 {
        ((product.unsigned_abs() as f64) / (figure as f64)).max(RATIO_FLOOR)
    } else {
        RATIO_FLOOR
    };

    let b = rec.entry_ntl;
    if b < 0 {
        return Err(PositionRiskError::NegativeEntryNotional);
    }
    let ratio2 = if b == 0 {
        RATIO_FLOOR
    } else {
        let signed_b = if is_long { b } else { -b };
        let diff = sat_sub(product, signed_b, &mut sats);
        ((diff.max(0) as f64) / (b as f64)).max(RATIO_FLOOR)
    };

    Ok(Some(ratio1 * ratio2))
}

/// Inputs to [`evaluate_margin_test`] (`0x469b990`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarginTestInput {
    pub route_a: i64,
    pub route_b: i64,
    pub account_acc: i64,
    pub eval_tag: u8,
    pub extra: i64,
    pub unit: i64,
    pub delta: i64,
    pub third: i64,
    pub second: i64,
}

/// Output byte of `0x469b990` (`0` = fail, `1` = pass, `2` = error/overflow/tag2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarginTestOutcome {
    Fail = 0,
    Pass = 1,
    Rejected = 2,
}

/// Reconstructs the margin-test arithmetic of node #115 `0x469b990`.
///
/// Returns `None` where the native code panics (`route_b < 0` or `unit < 0` /
/// `unit * third` overflow).
pub fn evaluate_margin_test(inp: MarginTestInput) -> Option<MarginTestOutcome> {
    if inp.route_b < 0 {
        return None;
    }
    let gap = inp.route_a.saturating_sub(inp.route_b);
    if inp.account_acc.checked_sub(gap.max(0)).is_none() {
        return Some(MarginTestOutcome::Rejected);
    }
    if inp.eval_tag == 2 {
        return Some(MarginTestOutcome::Rejected);
    }

    let mut rest = match inp
        .route_a
        .checked_sub(inp.account_acc)
        .and_then(|v| v.checked_add(inp.extra))
    {
        Some(v) => v,
        None => return Some(MarginTestOutcome::Rejected),
    };
    if inp.eval_tag == 0 {
        if inp.unit < 0 {
            return Some(MarginTestOutcome::Rejected);
        }
        let prod = match inp.unit.checked_mul(inp.delta) {
            Some(v) => v,
            None => return Some(MarginTestOutcome::Rejected),
        };
        rest = match rest.checked_add(prod) {
            Some(v) => v,
            None => return Some(MarginTestOutcome::Rejected),
        };
    }

    if inp.unit < 0 {
        return None;
    }
    let mut other = inp.unit.checked_mul(inp.third)?;
    if inp.eval_tag == 1 {
        other = other.saturating_add(inp.second);
    }

    let pass = ((inp.eval_tag ^ 1) != 0 || other >= MARGIN_TEST_FLOOR) && rest >= MARGIN_TEST_FLOOR;
    Some(if pass {
        MarginTestOutcome::Pass
    } else {
        MarginTestOutcome::Fail
    })
}

/// Reconstructs node #115's asset-decimal scale power `10^(high - low)`
/// (`risk-asset-decimal-scale-115`), returning `None` if `high < low` or `high - low > 19`.
pub fn asset_decimal_scale(high_decimals: u8, low_decimals: u8) -> Option<u64> {
    let diff = high_decimals.checked_sub(low_decimals)?;
    if diff > 19 {
        return None;
    }
    Some(10u64.pow(u32::from(diff)))
}
