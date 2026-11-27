//! Protocol net-fee solvency floor (`0x36a58d0`), fee-rate dust/cap bounds (`0x36a1c20`),
//! and volume-gated action thresholds (`0x2c2cb40`, `0x2c59480`) grounded in node #115.
//!
//! Binary evidence (`RE-004-node115-fee-solvency-and-vlm-gates`):
//! - `0x36a1c20..0x36a31ff` (5,599 B, `l1/src/fees/fees.rs`): validates `FeeSchedule`:
//!   - taker (`cross`/`spot_cross`) rates: `r == 0.0 || (0.0001 <= r <= 0.001)` (`0x459b50`, `0x459af0`),
//!   - maker (`add`/`spot_add`/MM) rates (via `0x36e1b90`): `|r| <= 0.001` and if `r > 0.0` then `r >= 0.0001`,
//!   - discounts/proportions in `[0.0, 1.0]` (`0x4592b0`), staking tier bounds `(<= 5.0, <= 0.5)` (`0x4593d0`, `0x459490`),
//!   - invokes `0x36a58d0` twice (`0x36a2e1c` & `0x36a2eba`, perp & spot) for net-fee solvency.
//! - `0x36a58d0..0x36a5d40` (1,136 B): computes:
//!   - `min_add = f64::min(vip_adds.last().unwrap_or(base_add), mm_adds.last().unwrap_or(base_add))`
//!   - `min_cross = vip_crosses.last().unwrap_or(base_cross)`
//!   - `after_stake = min_cross * (1.0 - max_staking_discount)`
//!   - `net_cross_referral = after_stake * (1.0 - referral_discount) * (1.0 - referrer_keep)`
//!   - `net_cross_trial = after_stake * (1.0 - trial_discount)`
//!   - checks `net_cross.mul_add(scale, min_add * scale) >= 5e-6` (`0x459388`) for BOTH paths
//!     across all 6 protocol fee scale multipliers `[1.0, 0.2, 6.0, 0.1, 2.0, 40.0]` at `.rodata 0x79d4d0`.
//! - `0x2c2cb40..0x2c2cf4a` (1,034 B): `ScheduleCancel` volume gate `raw_vlm >= 100_000_000`
//!   (`0x5f5e100`, `$1,000,000` at `/ 100.0`), max `5` days ahead, max `10` per UTC day (`cmp [rax], 9`).
//! - `0x2c59480..0x2c5995b` (1,243 B): combined user + subaccounts raw volume gate
//!   `>= 2_000_000_000` (`0x77359400`) via saturating `0x2a8ae60` fold (`qtys/impl_ntl.rs:682`).

use node115_assets::qtys::OverflowSink;

use crate::vlm::RawVlm;

/// Six protocol fee scale multipliers located at node #115 `.rodata` `0x79d4d0..0x79d500`.
pub const PROTOCOL_FEE_SCALES: [f64; 6] = [1.0, 0.2, 6.0, 0.1, 2.0, 40.0];

/// Minimum net protocol fee floor (`0.0005%` = `0.05 bps`) at node #115 `.rodata` `0x459388`.
pub const MIN_NET_PROTOCOL_FEE: f64 = 5e-6;

/// Minimum non-zero positive fee rate (`0.01%` = `1 bps`) at node #115 `.rodata` `0x459b50`.
pub const MIN_POSITIVE_FEE_RATE: f64 = 0.0001;

/// Maximum absolute fee rate (`0.1%` = `10 bps`) at node #115 `.rodata` `0x459af0`.
pub const MAX_FEE_RATE: f64 = 0.001;

/// `ScheduleCancel` minimum 14-day raw volume (`0x5f5e100` = `100_000_000`, `$1M` at `/ 100.0`, `0x2c2cb7e`).
pub const SCHEDULE_CANCEL_MIN_RAW_VLM: u64 = 100_000_000;

/// `ScheduleCancel` maximum lookahead in days (`mov edx, 5` at `0x2c2cc6d`).
pub const SCHEDULE_CANCEL_MAX_DAYS_AHEAD: u64 = 5;

/// `ScheduleCancel` maximum scheduled cancels per UTC day (`cmp [rax], 9` at `0x2c2ce90` -> 10 max).
pub const SCHEDULE_CANCEL_MAX_PER_DAY: u64 = 10;

/// Combined user + subaccounts cumulative raw volume gate (`0x77359400` = `2_000_000_000`, `0x2c5965d`).
pub const COMBINED_SUBACCOUNT_MIN_RAW_VLM: u64 = 2_000_000_000;

/// Exact `#115` `0x36a2ef3..0x36a2f56` taker rate validity predicate:
/// `0.0 <= rate <= 0.001`, and if `rate > 0.0` then `rate >= 0.0001`.
#[inline]
pub fn is_valid_taker_rate(rate: f64) -> bool {
    if !(0.0..=MAX_FEE_RATE).contains(&rate) {
        return false;
    }
    rate == 0.0 || rate >= MIN_POSITIVE_FEE_RATE
}

/// Exact `#115` `0x36a3026..0x36a3059` maker rate validity predicate:
/// `rate.abs() <= 0.001`, and if `rate > 0.0` then `rate >= 0.0001` (negative rebates allowed).
#[inline]
pub fn is_valid_maker_rate(rate: f64) -> bool {
    if !rate.is_finite() || rate.abs() > MAX_FEE_RATE {
        return false;
    }
    rate <= 0.0 || rate >= MIN_POSITIVE_FEE_RATE
}

/// Inputs to node #115 `0x36a58d0` (`FeeSchedule` protocol net-fee solvency check).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SolvencyCheckInputs<'a> {
    pub vip_adds: &'a [f64],
    pub mm_adds: &'a [f64],
    pub vip_crosses: &'a [f64],
    pub base_add: f64,
    pub base_cross: f64,
    pub max_staking_discount: f64,
    pub referral_discount: f64,
    pub trial_discount: f64,
    pub referrer_keep: f64,
}

/// Exact `#115` `0x36a58d0` net-fee solvency check across all 6 `PROTOCOL_FEE_SCALES`:
/// verifies that both the referral path (`(1 - stake) * (1 - referral) * (1 - keep)`) and the
/// trial path (`(1 - stake) * (1 - trial)`) keep `net_cross * scale + min_add * scale >= 5e-6`
/// for every `scale` in `[1.0, 0.2, 6.0, 0.1, 2.0, 40.0]`.
#[allow(clippy::neg_cmp_op_on_partial_ord)]
pub fn check_net_fee_solvency_0x36a58d0(inputs: SolvencyCheckInputs<'_>) -> bool {
    let last_vip_add = inputs.vip_adds.last().copied().unwrap_or(inputs.base_add);
    let last_mm_add = inputs.mm_adds.last().copied().unwrap_or(inputs.base_add);
    let min_add = last_vip_add.min(last_mm_add);
    let min_cross = inputs
        .vip_crosses
        .last()
        .copied()
        .unwrap_or(inputs.base_cross);

    let after_stake = min_cross * (1.0 - inputs.max_staking_discount);
    let net_cross_referral =
        after_stake * (1.0 - inputs.referral_discount) * (1.0 - inputs.referrer_keep);
    let net_cross_trial = after_stake * (1.0 - inputs.trial_discount);

    for &scale in &PROTOCOL_FEE_SCALES {
        let ref_net = if scale == 1.0 {
            net_cross_referral + min_add
        } else {
            net_cross_referral.mul_add(scale, min_add * scale)
        };
        if !(ref_net >= MIN_NET_PROTOCOL_FEE) {
            return false;
        }
        let trial_net = if scale == 1.0 {
            net_cross_trial + min_add
        } else {
            net_cross_trial.mul_add(scale, min_add * scale)
        };
        if !(trial_net >= MIN_NET_PROTOCOL_FEE) {
            return false;
        }
    }
    true
}

/// Volume gate check matching `#115` `0x2c2cb7e..0x2c2cba0` (`ScheduleCancel`):
/// returns `Ok(())` when `raw_vlm >= 100_000_000`, else `Err(raw_vlm as f64 / 100.0)`.
#[inline]
pub fn check_schedule_cancel_volume_gate(raw_vlm: RawVlm) -> Result<(), f64> {
    if raw_vlm.0 >= SCHEDULE_CANCEL_MIN_RAW_VLM {
        Ok(())
    } else {
        Err((raw_vlm.0 as f64) / 100.0)
    }
}

/// Combined user + subaccounts raw volume gate matching `#115` `0x2c595cb..0x2c59672`
/// (saturating fold with `qtys/impl_ntl.rs:682` overflow sink against `2_000_000_000`).
pub fn check_combined_subaccount_volume_gate(
    master_vlm: RawVlm,
    subaccount_vlms: &[RawVlm],
    sink: &mut impl OverflowSink,
) -> bool {
    let mut total = master_vlm;
    for &sub in subaccount_vlms {
        total = total.sat_add(sub, sink);
    }
    total.0 > COMBINED_SUBACCOUNT_MIN_RAW_VLM
}
