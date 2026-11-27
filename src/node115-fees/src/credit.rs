//! Fee x100 scaling (`l1/src/fees/compute.rs:45` at `0x46a6860`), fee credit distribution
//! (`0x3c1ae50`, `0x3c1a250`, `0x3c1a3f0` from `fees-credit-distribution-115`), and fee credit
//! caller mode/tally scaling (`0x3c10000` from `fees-credit-caller-115`).

use std::collections::BTreeMap;

use crate::UserAddress;
use node115_assets::qtys::{OverflowKind, OverflowSink};

/// Denominator for secondary split fraction rows (`100_000.0`, `#115` `.rodata` `0x459510`).
pub const SECONDARY_SPLIT_DENOM: f64 = 100_000.0;

/// Maximum accepted fraction for a secondary split row (`1.01`, `#115` `.rodata` `0x4590b8`).
pub const SECONDARY_SPLIT_MAX_FRAC: f64 = 1.01;

/// Exact `#115` upper clamp threshold `2^64 - 2048` (`0x458d58`) in `0x3c1ae50`.
pub const U64_FLOAT_CLAMP_THRESHOLD: f64 = 18_446_744_073_709_549_568.0;

/// Exact `#115` upper clamp threshold `2^63 - 1024` (`9223372036854774784.0`) in `0x3c10000`.
pub const I64_FLOAT_CLAMP_THRESHOLD: f64 = 9_223_372_036_854_774_784.0;

/// Exact `#115` `0x4489847` guard `i64::MAX / 50` (`0x28f5c28f5c28f5c`).
pub const FILL_FEE_INPUT_CAP: u64 = 0x028f_5c28_f5c2_8f5c;

/// Exact `#115` `0x4489858` clamp `i64::MAX / 100` (`0x147ae147ae147ae`) before x100 scaling.
pub const FILL_FEE_PRE_X100_CAP: i64 = 0x0147_ae14_7ae1_47ae;

/// Exact `#115` `0x44896f0` `.rodata` HIP-3 fee-scale constants (`0x4592b0`, `0x4593d0`, `0x4593e0`).
pub const HIP3_DEFAULT_SCALE_CAP: f64 = 1.0;
pub const HIP3_NON_GROWTH_RAW_SCALE: f64 = 5.0;
pub const HIP3_NON_GROWTH_FACTOR: f64 = 0.1;

/// Clamps an `f64` fee product using `#115` `0x448987e..0x4489912` rules:
/// non-finite -> `0`; clamp to `[-i64::MAX/100, +i64::MAX/100]`; negative -> `0`; then `/ 10_000`.
#[inline]
pub fn scale_fill_fee_component(notional: u64, scale: f64, fee_rate: f64) -> u64 {
    if (notional as i64) < 0 {
        return 0;
    }
    let scaled_f = (notional as f64) * scale;
    let scaled_i = if !scaled_f.is_finite() || scaled_f <= 0.0 {
        0_i64
    } else if scaled_f > I64_FLOAT_CLAMP_THRESHOLD {
        i64::MAX
    } else {
        scaled_f as i64
    };
    let scaled_u = scaled_i.max(0) as u64;
    let pre_div = if scaled_u > FILL_FEE_INPUT_CAP {
        scaled_u
    } else {
        let prod = (scaled_u as f64) * fee_rate;
        let clamped_i = if !prod.is_finite() {
            0_i64
        } else if prod > I64_FLOAT_CLAMP_THRESHOLD {
            i64::MAX
        } else if prod < -(i64::MAX as f64) {
            i64::MIN
        } else {
            prod as i64
        };
        let bounded = clamped_i.clamp(-FILL_FEE_PRE_X100_CAP, FILL_FEE_PRE_X100_CAP);
        bounded.max(0) as u64
    };
    pre_div / 10_000
}

/// Computes `(extra_credit, base_fee, deployer_fee)` matching `#115` `0x44896f0`
/// (`0x4489762..0x4489b25`) for a fill of `notional` at `fee_rate`.
pub fn compute_fill_fee_triple(
    notional: u64,
    fee_rate: f64,
    is_hip3: bool,
    growth_mode: bool,
    deployer_scale: Option<f64>,
) -> (u64, u64, u64) {
    let (scale_a, scale_b) = if !is_hip3 {
        (HIP3_DEFAULT_SCALE_CAP, 0.0)
    } else if growth_mode {
        let s = deployer_scale
            .unwrap_or(HIP3_DEFAULT_SCALE_CAP)
            .min(HIP3_DEFAULT_SCALE_CAP);
        (HIP3_DEFAULT_SCALE_CAP, s)
    } else {
        let s = HIP3_NON_GROWTH_RAW_SCALE.min(HIP3_DEFAULT_SCALE_CAP) * HIP3_NON_GROWTH_FACTOR;
        (HIP3_NON_GROWTH_FACTOR, s)
    };
    let extra = scale_fill_fee_component(notional, scale_a, fee_rate);
    let base = scale_fill_fee_component(notional, 1.0, fee_rate);
    let deployer = scale_fill_fee_component(notional, scale_b, fee_rate);
    (extra, base, deployer)
}

/// Runs the complete `#115` `0x44896f0 -> 0x3c1a3f0 -> 0x46a6860 -> 0x3c1ae50` fill fee
/// settlement pipeline into `ledger` (skipping cleanly when `side_kind == 2`).
pub fn settle_fill_fee(
    ledger: &mut FeeLedger,
    user: UserAddress,
    token_key: u64,
    side_kind: u64,
    extra_credit_amount: u64,
    rec: &FeeDistributionRecord,
    sink: &mut impl OverflowSink,
) -> Result<bool, FeeScaleError> {
    if side_kind == 2 {
        return Ok(false);
    }
    ledger.extra_credit(user, token_key, extra_credit_amount, sink);
    let scaled = rec.scale_x100()?;
    ledger.distribute(user, token_key, &scaled, sink);
    Ok(true)
}

/// Error returned by the checked `* 100` fee-record scaler (`0x46a6860`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeScaleError {
    GrossOverflow,
    RebateOverflow,
    PrimaryOverflow,
    SecondaryTotalOverflow,
    ProtocolOverflow,
}

/// One fraction split row (`numerator / 100_000.0` paid to `recipient`) in `0x3c1ae50`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecondarySplitRow {
    pub numerator: u64,
    pub recipient: UserAddress,
}

/// Structured equivalent of the 0x78-byte fee distribution record scaled by `0x46a6860`
/// and consumed by `0x3c1ae50`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeeDistributionRecord {
    pub primary: Option<(UserAddress, u64)>,
    pub secondary: Option<(Vec<SecondarySplitRow>, u64, UserAddress)>,
    pub gross: u64,
    pub rebate: u64,
    pub protocol: u64,
}

impl FeeDistributionRecord {
    /// Checked `* 100` scaling matching the exact evaluation order of `#115` `0x46a6860`
    /// (`fees/compute.rs:45`): `gross`, `rebate`, optional `primary`, optional `secondary_total`,
    /// then `protocol`.
    pub fn scale_x100(&self) -> Result<Self, FeeScaleError> {
        let gross = self
            .gross
            .checked_mul(100)
            .ok_or(FeeScaleError::GrossOverflow)?;
        let rebate = self
            .rebate
            .checked_mul(100)
            .ok_or(FeeScaleError::RebateOverflow)?;
        let primary = match self.primary {
            Some((addr, amt)) => Some((
                addr,
                amt.checked_mul(100)
                    .ok_or(FeeScaleError::PrimaryOverflow)?,
            )),
            None => None,
        };
        let secondary = match &self.secondary {
            Some((rows, total, dest)) => Some((
                rows.clone(),
                total
                    .checked_mul(100)
                    .ok_or(FeeScaleError::SecondaryTotalOverflow)?,
                *dest,
            )),
            None => None,
        };
        let protocol = self
            .protocol
            .checked_mul(100)
            .ok_or(FeeScaleError::ProtocolOverflow)?;
        Ok(Self {
            primary,
            secondary,
            gross,
            rebate,
            protocol,
        })
    }
}

/// Per-`(UserAddress, token_key)` 0x30-byte fee ledger cell observed in `0x3c1ae50`/`0x3c1a250`/`0x3c1a3f0`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeeCell {
    /// Offset `+0x00`: extra credit (`0x3c1a3f0`).
    pub extra_credit: u64,
    /// Offset `+0x08`: credited amount (`0x3c1a250` & primary recipient credit in `0x3c1ae50`).
    pub credit: u64,
    /// Offset `+0x18`: primary fee amount paid by user.
    pub primary_paid: u64,
    /// Offset `+0x20`: net fee (`(gross - rebate) - protocol`, saturating sub).
    pub net_fee: u64,
    /// Offset `+0x28`: protocol fee.
    pub protocol_fee: u64,
}

#[inline]
fn sat_add(a: u64, b: u64, sink: &mut impl OverflowSink) -> u64 {
    let (sum, carry) = a.overflowing_add(b);
    if carry {
        sink.report(OverflowKind::UnsignedAdd);
        u64::MAX
    } else {
        sum
    }
}

#[inline]
fn sat_sub(a: u64, b: u64, sink: &mut impl OverflowSink) -> u64 {
    let (diff, borrow) = a.overflowing_sub(b);
    if borrow {
        sink.report(OverflowKind::UnsignedSub);
        0
    } else {
        diff
    }
}

/// Exact `#115` `0x3c1ae50` `f64 -> u64` conversion for secondary split payouts:
/// non-finite or `<= 0.0` -> `0`; `> 2^64 - 2048` -> `u64::MAX`; else truncation to `u64`.
#[inline]
pub fn float_to_u64_node115(p: f64) -> u64 {
    if !p.is_finite() || p <= 0.0 {
        0
    } else if p > U64_FLOAT_CLAMP_THRESHOLD {
        u64::MAX
    } else {
        p as u64
    }
}

/// Fee ledger holding the primary cell map (`state + 0xb0`) and the secondary credit map
/// (`state + 0x138`) matching `fees-credit-distribution-115`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeeLedger {
    pub primary_cells: BTreeMap<(UserAddress, u64), FeeCell>,
    pub secondary_credits: BTreeMap<(UserAddress, u64), u64>,
}

impl FeeLedger {
    /// Exact `#115` `0x3c1a250` (`credit`): returns early on `amount == 0` without creating
    /// any cell; otherwise saturating-adds `amount` to `primary_cells[(user, key)].credit`
    /// (`+0x08`) and `secondary_credits[(user, key)]` (`+0x00`).
    pub fn credit(
        &mut self,
        user: UserAddress,
        key: u64,
        amount: u64,
        sink: &mut impl OverflowSink,
    ) {
        if amount == 0 {
            return;
        }
        let cell = self.primary_cells.entry((user, key)).or_default();
        cell.credit = sat_add(cell.credit, amount, sink);
        let second = self.secondary_credits.entry((user, key)).or_default();
        *second = sat_add(*second, amount, sink);
    }

    /// Exact `#115` `0x3c1a3f0` (`extra_credit`): always creates `(user, key)` even when
    /// `amount == 0`, then saturating-adds `amount` to `cell.extra_credit` (`+0x00`).
    pub fn extra_credit(
        &mut self,
        user: UserAddress,
        key: u64,
        amount: u64,
        sink: &mut impl OverflowSink,
    ) {
        let cell = self.primary_cells.entry((user, key)).or_default();
        cell.extra_credit = sat_add(cell.extra_credit, amount, sink);
    }

    /// Exact `#115` `0x3c1ae50` (`distribute`):
    /// 1. `user` cell `+0x28 += protocol`.
    /// 2. If `primary` is `Some((recipient, primary_amt))`:
    ///    - `t = sat_sub(sat_sub(gross, rebate), protocol)` (two separate borrow hooks!)
    ///    - `user` cell `+0x20 += t`, `+0x18 += primary_amt`
    ///    - `recipient` cell `+0x08 += primary_amt` (primary map only, no secondary map write).
    /// 3. If `secondary` is `Some((rows, total, remainder_dest))` and `total != 0`:
    ///    - `remaining = total`; for each row: `f = row.numerator as f64 / 100_000.0`;
    ///      skip if `!f.is_finite() || f > 1.01`; `p = float_to_u64_node115(f * total as f64)`;
    ///      skip if `p > remaining`; else `credit(row.recipient, key, p)` and `remaining -= p`.
    ///    - `credit(remainder_dest, key, remaining)` (no-op if `remaining == 0`).
    pub fn distribute(
        &mut self,
        user: UserAddress,
        key: u64,
        rec: &FeeDistributionRecord,
        sink: &mut impl OverflowSink,
    ) {
        {
            let cell = self.primary_cells.entry((user, key)).or_default();
            cell.protocol_fee = sat_add(cell.protocol_fee, rec.protocol, sink);
        }

        if let Some((recipient, primary_amount)) = rec.primary {
            let t1 = sat_sub(rec.gross, rec.rebate, sink);
            let t = sat_sub(t1, rec.protocol, sink);
            {
                let cell = self.primary_cells.entry((user, key)).or_default();
                cell.net_fee = sat_add(cell.net_fee, t, sink);
                cell.primary_paid = sat_add(cell.primary_paid, primary_amount, sink);
            }
            {
                let rcell = self.primary_cells.entry((recipient, key)).or_default();
                rcell.credit = sat_add(rcell.credit, primary_amount, sink);
            }
        }

        if let Some((rows, total, dest)) = &rec.secondary
            && *total != 0
        {
            let mut remaining = *total;
            let total_f = *total as f64;
            for row in rows {
                let f = (row.numerator as f64) / SECONDARY_SPLIT_DENOM;
                if !f.is_finite() || f > SECONDARY_SPLIT_MAX_FRAC {
                    continue;
                }
                let p = float_to_u64_node115(f * total_f);
                if p > remaining {
                    continue;
                }
                self.credit(row.recipient, key, p, sink);
                remaining -= p;
            }
            self.credit(*dest, key, remaining, sink);
        }
    }
}

/// Mode transformation observed in `#115` `fees-credit-caller-115` (`0x3c10000` step 2).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FeeCreditMode {
    /// Mode 0: identity.
    Identity,
    /// Mode 1: integer division by 5 (`mul 0xcccccccccccccccd; shr 2`).
    OneFifth,
    /// Mode 2+: multiply by `f64` factor with `#115` `0x3c10000` clamping.
    FloatFactor(f64),
}

impl FeeCreditMode {
    /// Apply mode scaling to a non-negative `u64` amount (`amount <= i64::MAX as u64`).
    pub fn apply(self, amount: u64) -> u64 {
        match self {
            Self::Identity => amount,
            Self::OneFifth => amount / 5,
            Self::FloatFactor(factor) => {
                let prod = (amount as f64) * factor;
                if !prod.is_finite() || prod <= 0.0 {
                    0
                } else if prod > I64_FLOAT_CLAMP_THRESHOLD {
                    i64::MAX as u64
                } else {
                    prod as u64
                }
            }
        }
    }
}

/// Computes the `(Q, X)` 10^6-scaled tally pair observed in `#115` `0x3c10000` step 3.
#[inline]
pub fn tally_millionths(amount: u64, mode: FeeCreditMode) -> (u64, u64) {
    let mode_amount = mode.apply(amount);
    (amount / 1_000_000, mode_amount / 1_000_000)
}
