#![forbid(unsafe_code)]

//! Node #115 `CStaking` reward emission curve, periodic bucket guards, reserve-capped
//! staging, commission/pro-rata distribution, and asymmetric 0.99 staking decay.
//!
//! Anchored to Linux x86-64 node #115 (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`):
//! - `0x3c38360..0x3c3854e` (494 B): `reward_rate_per_step` (inverse-sqrt quadratic APR curve)
//! - `0x3c3f780..0x3c403f7` (3,191 B): periodic bucket dispatcher (`c_staking_stage_reward`,
//!   `c_staking_distribute_staged_rewards`, `decay_staking`)
//! - `0x422c320..0x422c95f` (1,599 B) + `0x3d66500..0x3d66a5d` (1,373 B): reserve-capped
//!   per-validator reward staging
//! - `0x422abf0..0x422c320` (5,936 B): commission (`0.0001` bps, `<= 1.01` guard) and
//!   pro-rata delegator distribution (`0.0 <= share <= 1.01` guard)
//! - `0x422a630..0x422abe5` (1,461 B): asymmetric `0.99` staking-tier decay

use std::collections::BTreeMap;

/// `.rodata 0x459058` (`0x417e187e00000000`): 365.25 days in seconds (`31,557,600.0`).
pub const SECONDS_PER_YEAR: f64 = 31_557_600.0;
/// `.rodata 0x459a60` (`0x408f400000000000`): milliseconds per second (`1,000.0`).
pub const MS_PER_SECOND: f64 = 1_000.0;
/// `.rodata 0x4596b0` (`0x3f8eb851eb851eb8`): inverse-sqrt emission floor & numerator (`0.015`).
pub const EMISSION_BASE_FACTOR: f64 = 0.015;
/// `.rodata 0x459420` (`0xbfe0000000000000`): quadratic damping coefficient (`-0.5`).
pub const EMISSION_QUADRATIC_COEFF: f64 = -0.5;
/// `.rodata 0x459b50` (`0x3f1a36e2eb1c432d`): basis-point scale (`1e-4 = 0.0001`).
pub const COMMISSION_BPS_SCALE: f64 = 0.0001;
/// `.rodata 0x4590b8` (`0x3ff028f5c28f5c29`): fraction sanity ceiling (`1.01`).
pub const REWARD_FRACTION_CEILING: f64 = 1.01;
/// `.rodata 0x459208` (`0x3fefae147ae147ae`): asymmetric upward convergence factor (`0.99`).
pub const STAKING_DECAY_FACTOR: f64 = 0.99;

/// Exact node #115 finite-checked `f64 -> u64` saturating conversion observed at
/// `0x3d66916..0x3d66992`, `0x422b11d..0x422b187`, `0x422b77a..0x422b7ef`, and `0x422a74c..0x422a800`.
///
/// Non-finite (`NaN`, `±inf`) and negative values map to `0`; values `>= u64::MAX as f64`
/// clamp to `u64::MAX`.
#[must_use]
pub fn clamp_f64_to_u64(v: f64) -> u64 {
    if !v.is_finite() || v <= 0.0 {
        return 0;
    }
    if v >= u64::MAX as f64 {
        return u64::MAX;
    }
    v as u64
}

/// Exact node #115 inverse-square-root quadratic staking emission rate per reward step
/// (`0x3c38360..0x3c3854e`).
///
/// - Returns `None` when the epoch snapshot has no validator stakes entry.
/// - Returns `Some(0.0)` when `rewards_enabled == false`, `reference_supply_wei == 0`, or
///   `total_staked_wei == 0` / inactive.
/// - Otherwise:
///   - `step_secs = (reward_period_ms as f64) / 1000.0`
///   - `steps_per_year = if step_secs == inf { 0.0 } else { let s = 31_557_600.0 / step_secs; if s == inf { 0.0 } else { s } }`
///   - `ratio = (total_staked_wei as f64) / (reference_supply_wei as f64)`
///   - `x = 0.015 / ratio.sqrt().max(0.015)`
///   - `annual_rate = x + (-0.5) * x * x`
///   - `step_rate = annual_rate / steps_per_year`
#[must_use]
pub fn reward_rate_per_step(
    has_epoch_stakes: bool,
    rewards_enabled: bool,
    total_staked_wei: u64,
    reference_supply_wei: u64,
    reward_period_ms: u64,
) -> Option<f64> {
    if !has_epoch_stakes {
        return None;
    }
    if !rewards_enabled || total_staked_wei == 0 || reference_supply_wei == 0 {
        return Some(0.0);
    }
    let step_secs = (reward_period_ms as f64) / MS_PER_SECOND;
    let raw_steps_per_year = if step_secs == f64::INFINITY {
        f64::INFINITY
    } else {
        SECONDS_PER_YEAR / step_secs
    };
    let steps_per_year = if raw_steps_per_year == f64::INFINITY {
        0.0
    } else {
        raw_steps_per_year
    };
    let ratio = (total_staked_wei as f64) / (reference_supply_wei as f64);
    let denom = ratio.sqrt().max(EMISSION_BASE_FACTOR);
    let x = EMISSION_BASE_FACTOR / denom;
    let annual_rate = x + EMISSION_QUADRATIC_COEFF * x * x;
    Some(annual_rate / steps_per_year)
}

/// Bucketed periodic timer state matching `CStaking` offsets `+0x2a8..+0x2d8` (`0x3c3f780`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StakingPeriodicBuckets {
    /// `[self + 0x2b8]`: stage-reward period in ms.
    pub stage_period_ms: u64,
    /// `[self + 0x2c0]`: last triggered stage-reward bucket (`time_ms / stage_period_ms`).
    pub last_stage_bucket: u64,
    /// `[self + 0x2c8]`: distribute-staged-rewards period in ms.
    pub distribute_period_ms: u64,
    /// `[self + 0x2d0]`: last triggered distribution bucket (`time_ms / distribute_period_ms`).
    pub last_distribute_bucket: u64,
    /// `[self + 0x2a8]`: staking-decay period in ms.
    pub decay_period_ms: u64,
    /// `[self + 0x2b0]`: last triggered decay bucket (`time_ms / decay_period_ms`).
    pub last_decay_bucket: u64,
}

/// Which of the 3 periodic tasks triggered on a `CStaking` tick (`0x3c3f780`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeriodicTriggerMask {
    pub stage_reward: bool,
    pub distribute_staged_rewards: bool,
    pub decay_staking: bool,
}

impl StakingPeriodicBuckets {
    /// Evaluates the 3 ordered bucket guards (`0x3c3f87d`, `0x3c3fa3e`, `0x3c402a2`) and
    /// advances each triggered bucket strictly when `time_ms / period_ms > last_bucket`.
    pub fn evaluate_tick(&mut self, time_ms: u64) -> PeriodicTriggerMask {
        let stage_reward = advance_bucket(time_ms, self.stage_period_ms, &mut self.last_stage_bucket);
        let distribute_staged_rewards = advance_bucket(
            time_ms,
            self.distribute_period_ms,
            &mut self.last_distribute_bucket,
        );
        let decay_staking = advance_bucket(time_ms, self.decay_period_ms, &mut self.last_decay_bucket);
        PeriodicTriggerMask {
            stage_reward,
            distribute_staged_rewards,
            decay_staking,
        }
    }
}

fn advance_bucket(time_ms: u64, period_ms: u64, last_bucket: &mut u64) -> bool {
    if period_ms == 0 {
        return false;
    }
    let bucket = time_ms / period_ms;
    if bucket > *last_bucket {
        *last_bucket = bucket;
        true
    } else {
        false
    }
}

/// Reserve-capped per-validator reward staging (`0x3d66500..0x3d66a5d`).
///
/// For each `(validator, stake_wei)` in ascending validator order:
/// - Computes `raw_reward = clamp_f64_to_u64((stake_wei as f64) * step_rate)`.
/// - If `raw_reward == 0`, does not touch the reserve or staged balance.
/// - Otherwise caps the transfer by the remaining `reserve_wei` (`actual = reserve - reserve.saturating_sub(raw_reward)`),
///   deducts `actual` from `reserve_wei`, and saturating-adds `actual` into `staged_rewards[validator]`.
///
/// Returns per-validator `(validator, requested_reward_wei)` records matching `0x3d66a19`.
pub fn stage_validator_rewards(
    validator_stakes: &BTreeMap<[u8; 20], u64>,
    step_rate: f64,
    reserve_wei: &mut u64,
    staged_rewards: &mut BTreeMap<[u8; 20], u64>,
) -> Vec<([u8; 20], u64)> {
    let mut staged_log = Vec::with_capacity(validator_stakes.len());
    for (&validator, &stake_wei) in validator_stakes {
        let requested = clamp_f64_to_u64((stake_wei as f64) * step_rate);
        if requested > 0 {
            let remaining = reserve_wei.saturating_sub(requested);
            let actual = *reserve_wei - remaining;
            *reserve_wei = remaining;
            let entry = staged_rewards.entry(validator).or_insert(0);
            *entry = entry.saturating_add(actual);
        }
        staged_log.push((validator, requested));
    }
    staged_log
}

/// Result of distributing one validator's staged reward pool (`0x422abf0..0x422c320`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorDistributionOutcome {
    pub validator_commission_wei: u64,
    pub delegator_pool_wei: u64,
    pub delegator_payouts: BTreeMap<[u8; 20], u64>,
}

/// Exact node #115 validator commission and pro-rata delegator reward split (`0x422abf0`).
///
/// - Commission fraction: `commission_frac = (commission_bps as f64) * 0.0001`.
///   Guarded at `0x422b0e0` by `commission_frac <= 1.01` (else `0`).
///   `commission_wei = clamp_f64_to_u64(commission_frac * (staged_reward_wei as f64))`.
/// - `delegator_pool = staged_reward_wei.saturating_sub(commission_wei)`.
///   `validator_commission_wei = staged_reward_wei - delegator_pool` (guaranteed `<= staged_reward_wei`).
/// - For each delegator `(user, stake_wei)` with `total_stake_wei > 0`:
///   `share = (stake_wei as f64) / (total_stake_wei as f64)`.
///   Guarded at `0x422b754..0x422b76b` by `0.0 <= share <= 1.01` (else `0`).
///   `payout = clamp_f64_to_u64(share * (delegator_pool as f64))`.
#[must_use]
pub fn distribute_validator_staged_reward(
    staged_reward_wei: u64,
    commission_bps: u64,
    delegator_stakes: &BTreeMap<[u8; 20], u64>,
) -> ValidatorDistributionOutcome {
    let commission_frac = (commission_bps as f64) * COMMISSION_BPS_SCALE;
    let raw_commission = if commission_frac <= REWARD_FRACTION_CEILING {
        clamp_f64_to_u64(commission_frac * (staged_reward_wei as f64))
    } else {
        0
    };
    let delegator_pool_wei = staged_reward_wei.saturating_sub(raw_commission);
    let validator_commission_wei = staged_reward_wei - delegator_pool_wei;

    let total_stake: u64 = delegator_stakes
        .values()
        .copied()
        .fold(0u64, u64::saturating_add);
    let mut delegator_payouts = BTreeMap::new();
    if total_stake > 0 && delegator_pool_wei > 0 {
        let total_f = total_stake as f64;
        let pool_f = delegator_pool_wei as f64;
        for (&user, &stake) in delegator_stakes {
            let share = (stake as f64) / total_f;
            let payout = if (0.0..=REWARD_FRACTION_CEILING).contains(&share) {
                clamp_f64_to_u64(share * pool_f)
            } else {
                0
            };
            if payout > 0 {
                delegator_payouts.insert(user, payout);
            }
        }
    }

    ValidatorDistributionOutcome {
        validator_commission_wei,
        delegator_pool_wei,
        delegator_payouts,
    }
}

/// Asymmetric `0.99` staking-tier decay entry (`0x422a7a0..0x422a804`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecayedStakeEntry {
    /// `(%rdx)`: decayed / effective stake updated in place.
    pub decayed_wei: u64,
    /// `0x8(%rdx)`: raw current stake.
    pub raw_wei: u64,
}

/// Applies one node #115 `decay_staking` step (`0x422a630..0x422abe5`) to a single entry:
/// - If `raw_wei < decayed_wei`: instant drop `decayed_wei = raw_wei` (`0x422a7ad jb`).
/// - If `raw_wei >= decayed_wei`: closes 99% of the upward gap (`delta = clamp_f64_to_u64(((raw - decayed) as f64) * 0.99)`),
///   keeping `decayed_wei` unchanged on `u64` addition overflow (`0x422a78e jb -> 0x422a801`).
pub fn apply_decay_staking_step(entry: &mut DecayedStakeEntry) {
    if entry.raw_wei < entry.decayed_wei {
        entry.decayed_wei = entry.raw_wei;
        return;
    }
    let diff = entry.raw_wei - entry.decayed_wei;
    let delta = clamp_f64_to_u64((diff as f64) * STAKING_DECAY_FACTOR);
    if let Some(updated) = entry.decayed_wei.checked_add(delta) {
        entry.decayed_wei = updated;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reward_rate_matches_inverse_sqrt_quadratic_curve_and_floor() {
        // Missing epoch stakes -> None
        assert_eq!(reward_rate_per_step(false, true, 100, 1000, 60_000), None);
        // Disabled or zero stake/supply -> Some(0.0)
        assert_eq!(reward_rate_per_step(true, false, 100, 1000, 60_000), Some(0.0));
        assert_eq!(reward_rate_per_step(true, true, 0, 1000, 60_000), Some(0.0));
        assert_eq!(reward_rate_per_step(true, true, 100, 0, 60_000), Some(0.0));

        // 36% staked (sqrt = 0.6 > 0.015), 1-minute step (60_000 ms = 60s):
        // x = 0.015 / 0.6 = 0.025; annual = 0.025 - 0.5 * 0.000625 = 0.0246875
        // steps_per_year = 31_557_600 / 60 = 525_960
        let r = reward_rate_per_step(true, true, 360_000, 1_000_000, 60_000).unwrap();
        let expected = (0.025 - 0.5 * 0.025 * 0.025) / (31_557_600.0 / 60.0);
        assert!((r - expected).abs() < 1e-18);

        // Floor clamp: ratio = 1e-6 -> sqrt = 0.001 < 0.015 -> denom = 0.015 -> x = 1.0 -> annual = 0.5
        let r_floor = reward_rate_per_step(true, true, 1, 1_000_000, 31_557_600_000).unwrap();
        assert!((r_floor - 0.5).abs() < 1e-15);
    }

    #[test]
    fn periodic_buckets_staging_commission_split_and_decay_work_end_to_end() {
        let mut buckets = StakingPeriodicBuckets {
            stage_period_ms: 60_000,
            last_stage_bucket: 0,
            distribute_period_ms: 86_400_000,
            last_distribute_bucket: 0,
            decay_period_ms: 3_600_000,
            last_decay_bucket: 0,
        };
        let m1 = buckets.evaluate_tick(60_000);
        assert_eq!(
            m1,
            PeriodicTriggerMask {
                stage_reward: true,
                distribute_staged_rewards: false,
                decay_staking: false,
            }
        );
        // Same bucket does not re-trigger
        assert!(!buckets.evaluate_tick(119_999).stage_reward);
        // 1 day later triggers all 3
        let m2 = buckets.evaluate_tick(86_400_000);
        assert!(m2.stage_reward && m2.distribute_staged_rewards && m2.decay_staking);

        // Reserve-capped staging
        let v1 = [1u8; 20];
        let v2 = [2u8; 20];
        let mut stakes = BTreeMap::new();
        stakes.insert(v1, 10_000);
        stakes.insert(v2, 10_000);
        let mut reserve = 150u64;
        let mut staged = BTreeMap::new();
        let log = stage_validator_rewards(&stakes, 0.01, &mut reserve, &mut staged);
        assert_eq!(log, vec![(v1, 100), (v2, 100)]);
        assert_eq!(reserve, 0);
        assert_eq!(staged[&v1], 100);
        assert_eq!(staged[&v2], 50); // capped by remaining reserve

        // Commission split (5% = 500 bps) + pro-rata delegators
        let mut dels = BTreeMap::new();
        dels.insert([0x10; 20], 3_000);
        dels.insert([0x20; 20], 7_000);
        let dist = distribute_validator_staged_reward(10_000, 500, &dels);
        assert_eq!(dist.validator_commission_wei, 500);
        assert_eq!(dist.delegator_pool_wei, 9_500);
        assert_eq!(dist.delegator_payouts[&[0x10; 20]], 2_850);
        assert_eq!(dist.delegator_payouts[&[0x20; 20]], 6_650);

        // Commission > 101% (e.g. 10_200 bps -> 1.02 > 1.01) zeroes commission per 0x422b0e0
        let dist_bad = distribute_validator_staged_reward(10_000, 10_200, &dels);
        assert_eq!(dist_bad.validator_commission_wei, 0);
        assert_eq!(dist_bad.delegator_pool_wei, 10_000);

        // Asymmetric 0.99 decay: upward ramps by 99% of gap, downward drops instantly
        let mut entry = DecayedStakeEntry {
            decayed_wei: 0,
            raw_wei: 10_000,
        };
        apply_decay_staking_step(&mut entry);
        assert_eq!(entry.decayed_wei, 9_900);
        apply_decay_staking_step(&mut entry);
        assert_eq!(entry.decayed_wei, 9_999);
        entry.raw_wei = 1_000;
        apply_decay_staking_step(&mut entry);
        assert_eq!(entry.decayed_wei, 1_000);
    }
}
