//! Node #115 `FeeTracker` referral, reward-claiming, fee-trial, and builder-cap
//! lifecycle (`l1/src/fees/fees.rs`).
//!
//! Grounded directly in Linux x86-64 node #115 `.text` FDEs:
//! - `0x3c17390..0x3c17590` (512 B): `active_referral_discount` (`$25M` RawVlm cutoff)
//! - `0x3c17590..0x3c17fb9` (2,601 B): `set_referrer` (`0xa2`/`0xa3`/`0xa5`/`0xa6`, bucket refresh `max(custom, 1000)`)
//! - `0x3c17fc0..0x3c18252` (658 B): `claim_rewards` (`$1.00` / `100_000_000` wei threshold, `0xaa`/`0xab`)
//! - `0x3c18390..0x3c18a7e` (1,774 B): `start_fee_trial` (`0x149..0x14d`, 90d cooldown `0x5a`, 14d duration `0x0e`)
//! - `0x3c1a510..0x3c1ae41` (2,353 B): `approve_builder_fee` (10-builder cap `0xa`, `0x13c`)

use std::collections::{BTreeMap, BTreeSet};

use crate::UserAddress;
use crate::tiers::{BaseFeeRates, BuilderFeeError, BuilderFeeRegistry, FeeSchedule};

/// Right-shifted cumulative `RawVlm` cutoff in `0x3c17560..0x3c1756b`:
/// `shr r13, 8; cmp r13, 0x9502f8; ja return_zero`.
/// Equivalently, `cum_raw_vlm < (0x9502f8 + 1) << 8 = 2_500_000_000` (`$25,000,000.00` in `$0.01` units).
pub const REFERRAL_DISCOUNT_VLM_CAP_SHIFTED: u64 = 0x0095_02f8;
pub const REFERRAL_DISCOUNT_VLM_CAP_RAW: u64 = (REFERRAL_DISCOUNT_VLM_CAP_SHIFTED + 1) << 8;

/// Right-shifted cumulative `RawVlm` cutoff in `0x3c15a11..0x3c15a21`:
/// `shr r15, 0xb; cmp r15, 0x2e90edc; ja return_zero`.
/// Equivalently, `cum_raw_vlm < (0x2e90edc + 1) << 11 = 100_000_000_000` (`$1,000,000,000.00` in `$0.01` units).
pub const REFERRER_REWARD_VLM_CAP_SHIFTED: u64 = 0x02e9_0edc;
pub const REFERRER_REWARD_VLM_CAP_RAW: u64 = (REFERRER_REWARD_VLM_CAP_SHIFTED + 1) << 11;

/// Minimum cumulative `RawVlm` required for non-admin referral code creation in `0x3c1961a`
/// (`cmp rbx, 0xf4240` = `1_000_000` = `$10,000.00` in `$0.01` units).
pub const REGISTER_REFERRER_MIN_VLM_RAW: u64 = 1_000_000;

/// Maximum referral code byte length enforced in `0x3c193fc` & `0x3c19636` (`cmp r12, 0x64` = `100`).
pub const MAX_REFERRAL_CODE_LEN: usize = 100;

/// Two zero-fee system addresses checked via SIMD `pcmpeqb` in `0x3c154ee`, `0x3c15bf1`, and `0x3c18267`
/// (`.rodata` `0x453b70` for `[0xff; 20]` and `0x4543c0`/`0x455bb0` for `[0xfe; 20]`).
pub const ZERO_FEE_SYSTEM_ADDRESSES: [UserAddress; 2] = [[0xff; 20], [0xfe; 20]];

/// Returns `true` when `user` is one of node #115's two zero-fee system addresses.
#[inline]
#[must_use]
pub const fn is_zero_fee_system_address(user: &UserAddress) -> bool {
    let mut all_ff = true;
    let mut all_fe = true;
    let mut i = 0;
    while i < 20 {
        if user[i] != 0xff {
            all_ff = false;
        }
        if user[i] != 0xfe {
            all_fe = false;
        }
        i += 1;
    }
    all_ff || all_fe
}

/// Default referrals per refresh bucket in `0x3c17ab9..0x3c17ac4` (`cmp rax, 0x3e9; mov ebx, 0x3e8; cmovae`).
pub const DEFAULT_REFERRALS_PER_BUCKET: u64 = 1_000;

/// Minimum USDC-equivalent reward threshold in `0x3c1811e` (`mov edi, 0x5f5e100` = `100_000_000` = `$1.00` in `1e-8` wei).
pub const CLAIM_REWARD_MIN_USDC_WEI: u64 = 100_000_000;

/// Cooldown after previous fee trial end date in `0x3c186bb` (`mov esi, 0x5a` = 90 days).
pub const FEE_TRIAL_COOLDOWN_DAYS: u32 = 90;

/// Duration of a newly started fee trial in `0x3c186d4` (`mov esi, 0xe` = 14 days).
pub const FEE_TRIAL_DURATION_DAYS: u32 = 14;

/// Maximum approved builders per user in `0x3c1a60b` (`cmp rax, 0xa` = 10).
pub const MAX_APPROVED_BUILDERS: usize = 10;

/// Exact `UserError` / `Result` `u16` discriminants from master jump table `0x7d8c1c` (`0x46ef710`).
pub const ERR_SELF_REFER: u16 = 0x00a2;
pub const ERR_REFERRER_ALREADY_SET: u16 = 0x00a3;
pub const ERR_REFERRAL_CODE_TOO_LONG: u16 = 0x00a4;
pub const ERR_NO_MORE_REFERRALS: u16 = 0x00a5;
pub const ERR_REFERRAL_CODE_NOT_REGISTERED: u16 = 0x00a6;
pub const ERR_REFERRAL_CODE_ALREADY_TAKEN: u16 = 0x00a7;
pub const ERR_REFERRER_CODE_ALREADY_REGISTERED: u16 = 0x00a8;
pub const ERR_REFERRAL_INSUFFICIENT_VOLUME: u16 = 0x00a9;
pub const ERR_NO_REWARDS_TO_CLAIM: u16 = 0x00aa;
pub const ERR_REWARD_TOO_SMALL: u16 = 0x00ab;
pub const ERR_TOO_MANY_BUILDERS: u16 = 0x013c;
pub const ERR_TRIAL_ALREADY_STARTED: u16 = 0x0149;
pub const ERR_TRIAL_RATE_NOT_FOUND: u16 = 0x014a;
pub const ERR_TRIAL_RATES_ALREADY_MET: u16 = 0x014b;
pub const ERR_TRIAL_ENDED_TOO_RECENTLY: u16 = 0x014c;
pub const ERR_TRIALS_DISABLED: u16 = 0x014d;
pub const OK_STATUS_WORD: u16 = 0x01a2;

/// Errors emitted by `FeeLifecycleTracker`, each mapped to its exact node #115 `u16` discriminant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeLifecycleError {
    CannotSelfRefer,
    ReferrerAlreadySet,
    ReferralCodeTooLong,
    NoMoreReferralsInBucket,
    ReferralCodeNotRegistered,
    ReferralCodeAlreadyTaken,
    ReferrerAlreadyRegisteredCode,
    InsufficientVolumeForReferralCode,
    NoRewardsToClaim,
    RewardTooSmallToClaim,
    TooManyBuildersApproved,
    BuilderFee(BuilderFeeError),
    FeeTrialAlreadyStarted,
    FeeTrialRateNotFound,
    FeeTrialRatesAlreadyMet,
    FeeTrialEndedTooRecently,
    FeeTrialsDisabled,
}

impl FeeLifecycleError {
    /// Returns the node #115 `UserError` discriminant (`0x7d8c1c`) when directly mapped.
    #[must_use]
    pub const fn status_word(self) -> Option<u16> {
        match self {
            Self::CannotSelfRefer => Some(ERR_SELF_REFER),
            Self::ReferrerAlreadySet => Some(ERR_REFERRER_ALREADY_SET),
            Self::ReferralCodeTooLong => Some(ERR_REFERRAL_CODE_TOO_LONG),
            Self::NoMoreReferralsInBucket => Some(ERR_NO_MORE_REFERRALS),
            Self::ReferralCodeNotRegistered => Some(ERR_REFERRAL_CODE_NOT_REGISTERED),
            Self::ReferralCodeAlreadyTaken => Some(ERR_REFERRAL_CODE_ALREADY_TAKEN),
            Self::ReferrerAlreadyRegisteredCode => Some(ERR_REFERRER_CODE_ALREADY_REGISTERED),
            Self::InsufficientVolumeForReferralCode => Some(ERR_REFERRAL_INSUFFICIENT_VOLUME),
            Self::NoRewardsToClaim => Some(ERR_NO_REWARDS_TO_CLAIM),
            Self::RewardTooSmallToClaim => Some(ERR_REWARD_TOO_SMALL),
            Self::TooManyBuildersApproved => Some(ERR_TOO_MANY_BUILDERS),
            Self::BuilderFee(_) => None,
            Self::FeeTrialAlreadyStarted => Some(ERR_TRIAL_ALREADY_STARTED),
            Self::FeeTrialRateNotFound => Some(ERR_TRIAL_RATE_NOT_FOUND),
            Self::FeeTrialRatesAlreadyMet => Some(ERR_TRIAL_RATES_ALREADY_MET),
            Self::FeeTrialEndedTooRecently => Some(ERR_TRIAL_ENDED_TOO_RECENTLY),
            Self::FeeTrialsDisabled => Some(ERR_TRIALS_DISABLED),
        }
    }
}

/// Snapshot returned by `FeeLifecycleTracker::user_fee_state` (`0x3c18260..0x3c18389`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct UserFeeStateSnapshot {
    pub rates: BaseFeeRates,
    pub fee_scale: f64,
    pub active_trial: Option<ActiveFeeTrial>,
}

/// Per-referrer bucket quota state (`0x3c17a8e..0x3c17aeb`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferrerBucketState {
    pub referrer: UserAddress,
    pub last_bucket: u64,
    pub remaining_in_bucket: u64,
    pub custom_bucket_limit: u64,
    pub referred_users: BTreeSet<UserAddress>,
}

/// Per-token referral volume and reward ledger entry (`0x38`-byte entry in `0x3c174f0` & `0x3c18104`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserRewardEntry {
    pub cum_raw_vlm: u64,
    pub unclaimed_rewards: u64,
    pub claimed_rewards: u64,
}

/// Active fee trial record stored on a user (`0x3c188b0..0x3c18a46`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ActiveFeeTrial {
    pub effective_rates: BaseFeeRates,
    pub requested_rates: BaseFeeRates,
    pub end_day: u32,
}

/// Per-user referral, reward, and trial state tracked by `FeeLifecycleTracker`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct UserFeeLifecycleState {
    pub referrer: Option<UserAddress>,
    pub token_states: BTreeMap<usize, UserRewardEntry>,
    pub active_trial: Option<ActiveFeeTrial>,
    pub last_trial_end_day: Option<u32>,
}

impl UserFeeLifecycleState {
    /// Saturating sum of `cum_raw_vlm` across all token reward entries (`0x3c159a0`, `0x3c174f0`, `0x3c195d0`).
    #[must_use]
    pub fn total_cum_raw_vlm(&self) -> u64 {
        let mut total: u64 = 0;
        for entry in self.token_states.values() {
            total = total.saturating_add(entry.cum_raw_vlm);
        }
        total
    }
}

/// Node #115 `FeeTracker` lifecycle coordinator for referrals, rewards, trials, and builder caps.
#[derive(Clone, Debug, PartialEq)]
pub struct FeeLifecycleTracker {
    pub schedule: FeeSchedule,
    pub referral_bucket_millis: u64,
    pub trials_disabled: bool,
    pub code_to_referrer: BTreeMap<String, ReferrerBucketState>,
    pub user_states: BTreeMap<UserAddress, UserFeeLifecycleState>,
}

impl FeeLifecycleTracker {
    /// Creates a new tracker with the given fee schedule and referral bucket window (in ms).
    #[must_use]
    pub fn new(schedule: FeeSchedule, referral_bucket_millis: u64) -> Self {
        Self {
            schedule,
            referral_bucket_millis: referral_bucket_millis.max(1),
            trials_disabled: false,
            code_to_referrer: BTreeMap::new(),
            user_states: BTreeMap::new(),
        }
    }

    /// Registers a referral code owned by `referrer`.
    pub fn register_referrer_code(
        &mut self,
        code: impl Into<String>,
        referrer: UserAddress,
        custom_bucket_limit: u64,
    ) {
        self.code_to_referrer.insert(
            code.into(),
            ReferrerBucketState {
                referrer,
                last_bucket: 0,
                remaining_in_bucket: custom_bucket_limit.max(DEFAULT_REFERRALS_PER_BUCKET),
                custom_bucket_limit,
                referred_users: BTreeSet::new(),
            },
        );
    }

    /// `FeeTracker::active_referral_discount` (`0x3c17390..0x3c17590`, 512 B).
    ///
    /// Returns `schedule.referral_discount` iff the user has a referrer set and their
    /// saturating sum of per-token `cum_raw_vlm` satisfies `(sum >> 8) <= 0x9502f8`
    /// (i.e., `sum < 2_500_000_000` = `$25,000,000.00`).
    #[must_use]
    pub fn active_referral_discount(&self, user: &UserAddress) -> f64 {
        let Some(state) = self.user_states.get(user) else {
            return 0.0;
        };
        if state.referrer.is_none() {
            return 0.0;
        }
        let mut total: u64 = 0;
        for entry in state.token_states.values() {
            total = total.saturating_add(entry.cum_raw_vlm);
        }
        if (total >> 8) > REFERRAL_DISCOUNT_VLM_CAP_SHIFTED {
            0.0
        } else {
            self.schedule.referral_discount
        }
    }

    /// `FeeTracker::set_referrer` (`0x3c17590..0x3c17fb9`, 2,601 B).
    ///
    /// Enforces code registration (`0xa6`), non-self-referral (`0xa2`), one-time binding
    /// (`0xa3`), and per-bucket refresh quota `max(custom_bucket_limit, 1000)` (`0xa5`).
    pub fn set_referrer(
        &mut self,
        user: UserAddress,
        code: &str,
        now_millis: u64,
    ) -> Result<(), FeeLifecycleError> {
        let Some(bucket_state) = self.code_to_referrer.get_mut(code) else {
            return Err(FeeLifecycleError::ReferralCodeNotRegistered);
        };
        if bucket_state.referrer == user {
            return Err(FeeLifecycleError::CannotSelfRefer);
        }
        if self
            .user_states
            .get(&user)
            .and_then(|s| s.referrer)
            .is_some()
        {
            return Err(FeeLifecycleError::ReferrerAlreadySet);
        }

        let cur_bucket = now_millis / self.referral_bucket_millis;
        if cur_bucket != bucket_state.last_bucket {
            bucket_state.last_bucket = cur_bucket;
            bucket_state.remaining_in_bucket = bucket_state
                .custom_bucket_limit
                .max(DEFAULT_REFERRALS_PER_BUCKET);
        }
        if bucket_state.remaining_in_bucket == 0 {
            return Err(FeeLifecycleError::NoMoreReferralsInBucket);
        }
        bucket_state.remaining_in_bucket -= 1;
        let referrer = bucket_state.referrer;
        bucket_state.referred_users.insert(user);

        let user_state = self.user_states.entry(user).or_default();
        user_state.referrer = Some(referrer);
        Ok(())
    }

    /// `FeeTracker::claim_rewards` (`0x3c17fc0..0x3c18252`, 658 B).
    ///
    /// For each token with `unclaimed_rewards > 0`, calls `min_claim_wei_for_token(token, 100_000_000)`
    /// (corresponding to `0x4217e60` converting `$1.00` = `0x5f5e100` USDC wei into token wei).
    /// Tokens meeting `unclaimed_rewards >= min_wei` are zeroed, saturating-added to
    /// `claimed_rewards`, and returned. If no token qualifies, returns `RewardTooSmallToClaim`
    /// (`0xab`) if any token had positive dust below `$1.00`, otherwise `NoRewardsToClaim` (`0xaa`).
    pub fn claim_rewards<F>(
        &mut self,
        user: &UserAddress,
        mut min_claim_wei_for_token: F,
    ) -> Result<Vec<(usize, u64)>, FeeLifecycleError>
    where
        F: FnMut(usize, u64) -> Option<u64>,
    {
        let Some(state) = self.user_states.get_mut(user) else {
            return Err(FeeLifecycleError::NoRewardsToClaim);
        };
        let mut claimed_out = Vec::new();
        let mut saw_positive_unclaimed = false;

        for (&token, entry) in &mut state.token_states {
            let unclaimed = entry.unclaimed_rewards;
            if unclaimed == 0 {
                continue;
            }
            saw_positive_unclaimed = true;
            let Some(min_wei) = min_claim_wei_for_token(token, CLAIM_REWARD_MIN_USDC_WEI) else {
                continue;
            };
            if unclaimed >= min_wei {
                entry.unclaimed_rewards = 0;
                entry.claimed_rewards = entry.claimed_rewards.saturating_add(unclaimed);
                claimed_out.push((token, unclaimed));
            }
        }

        if claimed_out.is_empty() {
            if saw_positive_unclaimed {
                Err(FeeLifecycleError::RewardTooSmallToClaim)
            } else {
                Err(FeeLifecycleError::NoRewardsToClaim)
            }
        } else {
            Ok(claimed_out)
        }
    }

    /// Checks whether `requested` matches an exact VIP tier (`0x3c1854d..0x3c18587`) or a
    /// `(vip.cross, mm.add, vip.spot_cross, mm.add)` combination (`0x3c1863b..0x3c1867d`).
    #[must_use]
    pub fn is_valid_trial_rate_tuple(&self, requested: BaseFeeRates) -> bool {
        let mut cross_pair_matched = false;
        for vip in &self.schedule.vip_tiers {
            if vip.cross == requested.perp_cross && vip.spot_cross == requested.spot_cross {
                cross_pair_matched = true;
                if vip.add == requested.perp_add && vip.spot_add == requested.spot_add {
                    return true;
                }
            }
        }
        if !cross_pair_matched {
            return false;
        }
        self.schedule
            .mm_tiers
            .iter()
            .any(|mm| mm.add == requested.perp_add && mm.add == requested.spot_add)
    }

    /// `FeeTracker::start_fee_trial` (`0x3c18390..0x3c18a7e`, 1,774 B).
    ///
    /// Exact gate order matching node #115:
    /// 1. `trials_disabled` -> `FeeTrialsDisabled` (`0x14d`)
    /// 2. active trial already present -> `FeeTrialAlreadyStarted` (`0x149`)
    /// 3. requested 4-rate tuple must exist in `vip_tiers` or `(vip.cross, mm.add)` -> `FeeTrialRateNotFound` (`0x14a`)
    /// 4. if `last_trial_end_day` is set and `last_trial_end_day + 90 > cur_day` -> `FeeTrialEndedTooRecently` (`0x14c`)
    /// 5. apply staking discount `(1 - stake_discount)` to strictly positive requested rates only (`0x3c18764..0x3c187ad`);
    ///    if `cur_rates` already beats or equals all 4 discounted trial rates -> `FeeTrialRatesAlreadyMet` (`0x14b`)
    /// 6. store `effective_rates = min(cur_rates, discounted_trial)` with `end_day = cur_day + 14` across `user` + `linked_users`.
    pub fn start_fee_trial(
        &mut self,
        user: UserAddress,
        requested: BaseFeeRates,
        cur_rates: BaseFeeRates,
        staked_bps: f64,
        cur_day: u32,
        linked_users: &[UserAddress],
    ) -> Result<ActiveFeeTrial, FeeLifecycleError> {
        let has_active_trial = self
            .user_states
            .get(&user)
            .and_then(|s| s.active_trial)
            .is_some();
        if self.trials_disabled {
            return Err(FeeLifecycleError::FeeTrialsDisabled);
        }
        if has_active_trial {
            return Err(FeeLifecycleError::FeeTrialAlreadyStarted);
        }
        if !self.is_valid_trial_rate_tuple(requested) {
            return Err(FeeLifecycleError::FeeTrialRateNotFound);
        }
        if let Some(last_end) = self
            .user_states
            .get(&user)
            .and_then(|s| s.last_trial_end_day)
            && last_end.saturating_add(FEE_TRIAL_COOLDOWN_DAYS) > cur_day
        {
            return Err(FeeLifecycleError::FeeTrialEndedTooRecently);
        }

        let mut stake_discount = 0.0_f64;
        for st in &self.schedule.stake_discount_tiers {
            if staked_bps >= st.bps_of_max_supply_staked {
                stake_discount = st.discount;
            }
        }
        let mult = 1.0 - stake_discount;
        let apply_pos = |r: f64| if r > 0.0 { r * mult } else { r };
        let trial_discounted = BaseFeeRates {
            perp_cross: apply_pos(requested.perp_cross),
            perp_add: apply_pos(requested.perp_add),
            spot_cross: apply_pos(requested.spot_cross),
            spot_add: apply_pos(requested.spot_add),
        };

        let improves_any = (cur_rates.perp_cross - trial_discounted.perp_cross).max(0.0) != 0.0
            || (cur_rates.perp_add - trial_discounted.perp_add).max(0.0) != 0.0
            || (cur_rates.spot_cross - trial_discounted.spot_cross).max(0.0) != 0.0
            || (cur_rates.spot_add - trial_discounted.spot_add).max(0.0) != 0.0;
        if !improves_any {
            return Err(FeeLifecycleError::FeeTrialRatesAlreadyMet);
        }

        let trial = ActiveFeeTrial {
            effective_rates: BaseFeeRates {
                perp_cross: cur_rates.perp_cross.min(trial_discounted.perp_cross),
                perp_add: cur_rates.perp_add.min(trial_discounted.perp_add),
                spot_cross: cur_rates.spot_cross.min(trial_discounted.spot_cross),
                spot_add: cur_rates.spot_add.min(trial_discounted.spot_add),
            },
            requested_rates: requested,
            end_day: cur_day.saturating_add(FEE_TRIAL_DURATION_DAYS),
        };

        for &target in core::iter::once(&user).chain(linked_users.iter()) {
            let entry = self.user_states.entry(target).or_default();
            entry.active_trial = Some(trial);
        }
        Ok(trial)
    }

    /// Expires a user's active trial when `cur_day >= trial.end_day`, recording `last_trial_end_day`.
    pub fn expire_trial_if_due(&mut self, user: &UserAddress, cur_day: u32) -> bool {
        let Some(state) = self.user_states.get_mut(user) else {
            return false;
        };
        if let Some(trial) = state.active_trial
            && cur_day >= trial.end_day
        {
            state.active_trial = None;
            state.last_trial_end_day = Some(trial.end_day);
            return true;
        }
        false
    }

    /// Evaluates `FeeTracker::active_staking_discount` (`0x3c154d0..0x3c15802`).
    /// Zero-fee system addresses (`[0xff; 20]`, `[0xfe; 20]`) are treated as `staked_bps = 0.0`.
    #[must_use]
    pub fn active_staking_discount(&self, user: &UserAddress, staked_bps: f64) -> f64 {
        let effective_bps = if is_zero_fee_system_address(user) {
            0.0
        } else {
            staked_bps
        };
        let mut discount = 0.0_f64;
        for tier in &self.schedule.stake_discount_tiers {
            if effective_bps >= tier.bps_of_max_supply_staked {
                discount = tier.discount;
            } else {
                break;
            }
        }
        discount
    }

    /// Evaluates `FeeTracker::referrer_reward_fraction` (`0x3c15810..0x3c15b93`).
    /// - Returns `0.0` once `referred_user`'s cumulative `RawVlm` satisfies
    ///   `(cum >> 11) > 0x2e90edc` (`cum >= 100_000_000_000`, `$1,000,000,000.00`).
    /// - On spot (`is_spot == true`), returns `self.schedule.referrer_keep`.
    /// - On perp (`is_spot == false`), returns
    ///   `max(0.0, user_fee_scale * (referrer_stake_discount - user_stake_discount))`.
    #[must_use]
    pub fn referrer_reward_fraction(
        &self,
        referrer: &UserAddress,
        referred_user: &UserAddress,
        referrer_staked_bps: f64,
        user_staked_bps: f64,
        user_fee_scale: f64,
        is_spot: bool,
    ) -> f64 {
        let cum_raw_vlm = self
            .user_states
            .get(referred_user)
            .map(UserFeeLifecycleState::total_cum_raw_vlm)
            .unwrap_or(0);
        if (cum_raw_vlm >> 11) > REFERRER_REWARD_VLM_CAP_SHIFTED {
            return 0.0;
        }
        if is_spot {
            return self.schedule.referrer_keep;
        }
        let ref_disc = self.active_staking_discount(referrer, referrer_staked_bps);
        if ref_disc <= 0.0 {
            return 0.0;
        }
        let user_disc = self.active_staking_discount(referred_user, user_staked_bps);
        (user_fee_scale * (ref_disc - user_disc)).max(0.0)
    }

    /// Evaluates `FeeTracker::user_fee_state` (`0x3c18260..0x3c18389`).
    /// - Zero-fee system addresses (`[0xff; 20]`, `[0xfe; 20]`) return zero rates and `fee_scale = 0.0`.
    /// - Unknown users return `self.schedule.rates` with `fee_scale = 1.0`.
    /// - Known users return their active trial effective rates (when present) or schedule base rates
    ///   with `fee_scale = 1.0`.
    #[must_use]
    pub fn user_fee_state(&self, user: &UserAddress) -> UserFeeStateSnapshot {
        if is_zero_fee_system_address(user) {
            return UserFeeStateSnapshot {
                rates: BaseFeeRates {
                    perp_cross: 0.0,
                    perp_add: 0.0,
                    spot_cross: 0.0,
                    spot_add: 0.0,
                },
                fee_scale: 0.0,
                active_trial: None,
            };
        }
        let active_trial = self.user_states.get(user).and_then(|s| s.active_trial);
        let rates = active_trial.map_or(self.schedule.rates, |t| t.effective_rates);
        UserFeeStateSnapshot {
            rates,
            fee_scale: 1.0,
            active_trial,
        }
    }

    /// Evaluates `FeeTracker::register_referrer` (`0x3c193d0..0x3c1a24b`).
    /// - For non-admin callers (`!is_admin`), requires cumulative `RawVlm >= 1_000_000`
    ///   (`$10,000.00` in `$0.01` units) -> `0xa9`.
    /// - Enforces `code.len() <= 100` (`0x64`) -> `0xa4`.
    /// - For non-admin callers, rejects users who already registered a code -> `0xa8`.
    /// - Rejects codes already registered by another user -> `0xa7`.
    pub fn create_referral_code(
        &mut self,
        user: UserAddress,
        code: &str,
        is_admin: bool,
    ) -> Result<(), FeeLifecycleError> {
        if !is_admin {
            let cum_raw_vlm = self
                .user_states
                .get(&user)
                .map(UserFeeLifecycleState::total_cum_raw_vlm)
                .unwrap_or(0);
            if cum_raw_vlm < REGISTER_REFERRER_MIN_VLM_RAW {
                return Err(FeeLifecycleError::InsufficientVolumeForReferralCode);
            }
        }
        if code.len() > MAX_REFERRAL_CODE_LEN {
            return Err(FeeLifecycleError::ReferralCodeTooLong);
        }
        if !is_admin && self.code_to_referrer.values().any(|b| b.referrer == user) {
            return Err(FeeLifecycleError::ReferrerAlreadyRegisteredCode);
        }
        if let Some(existing) = self.code_to_referrer.get(code)
            && existing.referrer != user
        {
            return Err(FeeLifecycleError::ReferralCodeAlreadyTaken);
        }
        self.register_referrer_code(code, user, 0);
        Ok(())
    }
}

/// Enforces node #115's 10-builder per-user approval cap (`0x3c1a510..0x3c1ae41`,
/// `cmp rax, 0xa` -> `0x13c`) on top of `BuilderFeeRegistry::approve`.
pub fn approve_builder_fee_capped(
    registry: &mut BuilderFeeRegistry,
    user: UserAddress,
    builder: UserAddress,
    max_fee_rate: f64,
) -> Result<(), FeeLifecycleError> {
    if max_fee_rate != 0.0
        && !registry.approvals.contains_key(&(user, builder))
        && registry
            .approvals
            .keys()
            .filter(|(u, _)| *u == user)
            .count()
            >= MAX_APPROVED_BUILDERS
    {
        return Err(FeeLifecycleError::TooManyBuildersApproved);
    }
    registry
        .approve(user, builder, max_fee_rate)
        .map_err(FeeLifecycleError::BuilderFee)
}
