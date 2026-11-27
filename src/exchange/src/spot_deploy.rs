//! Spot-deploy perp-to-spot charge path (`0x2c57090` / `0x55cbcc0` / `0x55cc610`)
//! and rate scaler (`0x44811d0`).
//!
//! Anchored to `research/work-items/exchange-spot-deploy-charge-115`
//! (42,000 byte-executed cases, 75/75 negative controls, 0 mismatches, `l1/src/exchange/impl_spot_deploy.rs`).

/// Counter threshold above which perp-to-spot conversion is refused (`0x68db8bac710cb`).
pub const SPOT_DEPLOY_COUNTER_LIMIT: u64 = 0x0006_8db8_bac7_10cb;

/// Exact 35-byte refusal text at `.rodata` in `0x2c57090`.
pub const ERR_TEXT_PERP_TO_SPOT: &str = "could not convert perp usdc to spot";

/// Passthrough threshold in rate scaler `0x44811d0` (`floor(2^64 / 100)`).
pub const RATE_SCALER_PASSTHROUGH: u64 = 0x028f_5c28_f5c2_8f5c;

/// Upper clamp in rate scaler `0x44811d0` (`floor(2^63 / 100)`).
pub const RATE_SCALER_CLAMP_MAX: i64 = 0x0147_ae14_7ae1_47ae;

/// Observed error tags in `0x2c57090`.
pub const TAG_OK: u16 = 0x1a2;
pub const TAG_SCALE_ERROR: u16 = 0xae;
pub const TAG_REFUSAL_TEXT: u16 = 0xee;

/// Reconstructs `0x44811d0`: rate scaler used by spot-deploy charge paths.
///
/// - Values `> RATE_SCALER_PASSTHROUGH` pass through unchanged.
/// - Otherwise interprets as `i64`, multiplies by `rate_f64`, maps non-finite to `0.0`,
///   saturating-truncates to `i64`, negates (returning `None` where `i64::MIN` panics),
///   clamps to `[0, RATE_SCALER_CLAMP_MAX]`.
pub fn scale_deploy_rate(value: u64, rate_f64: f64) -> Option<u64> {
    if value > RATE_SCALER_PASSTHROUGH {
        return Some(value);
    }
    let prod = (value as i64 as f64) * rate_f64;
    let clamped = if !prod.is_finite() { 0i64 } else { prod as i64 };
    let neg = clamped.checked_neg()?;
    let bounded = neg.clamp(0, RATE_SCALER_CLAMP_MAX);
    Some(bounded as u64)
}

/// Computes `ceil(fee / 100)` matching the exact divisibility-by-100 check in `0x2c57090`.
pub const fn ceil_div_100(fee: u64) -> u64 {
    (fee / 100) + if fee.is_multiple_of(100) { 0 } else { 1 }
}

/// Ledger row updated by `0x2c57090` after the fee helper succeeds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SpotDeployLedgerRow {
    pub marked: bool,
    pub charge: u64,
}

/// Outcome of [`evaluate_spot_deploy_charge`] (`0x2c57090`).
#[derive(Clone, Debug, PartialEq)]
pub enum SpotDeployChargeOutcome {
    Refused {
        tag: u16,
        message: &'static str,
    },
    ZeroChargeNoDebit,
    Charged {
        charge: u64,
        event_amount_usd: f64,
    },
}

/// Executes the core decision, `ceil(fee / 100)` rounding, ledger mark, and debit
/// trigger of node #115 `0x2c57090` (`impl_spot_deploy.rs`).
pub fn evaluate_spot_deploy_charge(
    counter: u64,
    fee: u64,
    ledger_row: &mut SpotDeployLedgerRow,
) -> SpotDeployChargeOutcome {
    if counter > SPOT_DEPLOY_COUNTER_LIMIT {
        return SpotDeployChargeOutcome::Refused {
            tag: TAG_REFUSAL_TEXT,
            message: ERR_TEXT_PERP_TO_SPOT,
        };
    }

    let charge = ceil_div_100(fee);
    // Ledger update: only writes (true, charge) when previously unmarked.
    if !ledger_row.marked {
        ledger_row.marked = true;
        ledger_row.charge = charge;
    }

    if charge == 0 {
        SpotDeployChargeOutcome::ZeroChargeNoDebit
    } else {
        SpotDeployChargeOutcome::Charged {
            charge,
            event_amount_usd: -(charge as f64) / 1_000_000.0,
        }
    }
}
