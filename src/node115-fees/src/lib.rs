//! Integrated `fees` crate for Linux x86-64 node #115
//! (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
//!
//! Combines the verified `fees` micro-crates with binary-grounded implementations of
//! `l1/src/raw_vlm.rs`, `l1/src/scaled_vlm.rs`, `l1/src/fees/fees.rs`,
//! `l1/src/fees/compute.rs`, open-order cap thresholds (`0x5495210`/`0x5495680`),
//! and fee credit distribution & ledger updates (`0x3c1ae50`, `0x3c1a250`, `0x3c1a3f0`, `0x3c10000`).

#![forbid(unsafe_code)]

pub mod credit;
pub mod lifecycle;
pub mod schedule;
pub mod solvency;
pub mod tiers;
pub mod vlm;

/// Verified node #115 target binary SHA-256.
pub const TARGET_SHA256: &str =
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";

/// 20-byte user / vault / recipient address.
pub type UserAddress = [u8; 20];

// Re-export verified Cargo-packaged `fees` micro-crates.
pub use node115_fee_failure_selection as fee_failure_selection;
pub use node115_fee_history_reward as fee_history_reward;
pub use node115_fee_map_iteration as fee_map_iteration;
pub use node115_fee_point_classifier as fee_point_classifier;
pub use node115_fee_rate_map_codec as fee_rate_map_codec;
pub use node115_fee_schedule_compose as fee_schedule_compose;
pub use node115_fee_trial as fee_trial;

pub use credit::{
    FILL_FEE_INPUT_CAP, FILL_FEE_PRE_X100_CAP, FeeCell, FeeCreditMode, FeeDistributionRecord,
    FeeLedger, FeeScaleError, HIP3_DEFAULT_SCALE_CAP, HIP3_NON_GROWTH_FACTOR,
    HIP3_NON_GROWTH_RAW_SCALE, SecondarySplitRow, compute_fill_fee_triple,
    scale_fill_fee_component, settle_fill_fee,
};
pub use lifecycle::{
    ActiveFeeTrial, CLAIM_REWARD_MIN_USDC_WEI, DEFAULT_REFERRALS_PER_BUCKET,
    ERR_NO_MORE_REFERRALS, ERR_NO_REWARDS_TO_CLAIM, ERR_REFERRAL_CODE_ALREADY_TAKEN,
    ERR_REFERRAL_CODE_NOT_REGISTERED, ERR_REFERRAL_CODE_TOO_LONG,
    ERR_REFERRAL_INSUFFICIENT_VOLUME, ERR_REFERRER_ALREADY_SET,
    ERR_REFERRER_CODE_ALREADY_REGISTERED, ERR_REWARD_TOO_SMALL, ERR_SELF_REFER,
    ERR_TOO_MANY_BUILDERS, ERR_TRIAL_ALREADY_STARTED, ERR_TRIAL_ENDED_TOO_RECENTLY,
    ERR_TRIAL_RATE_NOT_FOUND, ERR_TRIAL_RATES_ALREADY_MET, ERR_TRIALS_DISABLED,
    FEE_TRIAL_COOLDOWN_DAYS, FEE_TRIAL_DURATION_DAYS, FeeLifecycleError, FeeLifecycleTracker,
    MAX_APPROVED_BUILDERS, MAX_REFERRAL_CODE_LEN, OK_STATUS_WORD,
    REFERRAL_DISCOUNT_VLM_CAP_RAW, REFERRAL_DISCOUNT_VLM_CAP_SHIFTED,
    REFERRER_REWARD_VLM_CAP_RAW, REFERRER_REWARD_VLM_CAP_SHIFTED, REGISTER_REFERRER_MIN_VLM_RAW,
    ReferrerBucketState, UserFeeLifecycleState, UserFeeStateSnapshot, UserRewardEntry,
    ZERO_FEE_SYSTEM_ADDRESSES, approve_builder_fee_capped, is_zero_fee_system_address,
};
pub use schedule::is_monotonically_non_increasing;
pub use solvency::{
    COMBINED_SUBACCOUNT_MIN_RAW_VLM, MAX_FEE_RATE, MIN_NET_PROTOCOL_FEE, MIN_POSITIVE_FEE_RATE,
    PROTOCOL_FEE_SCALES, SCHEDULE_CANCEL_MAX_DAYS_AHEAD, SCHEDULE_CANCEL_MAX_PER_DAY,
    SCHEDULE_CANCEL_MIN_RAW_VLM, SolvencyCheckInputs, check_combined_subaccount_volume_gate,
    check_net_fee_solvency_0x36a58d0, check_schedule_cancel_volume_gate, is_valid_maker_rate,
    is_valid_taker_rate,
};
pub use tiers::{
    BaseFeeRates, BuilderFeeError, BuilderFeeRegistry, FeeSchedule, MAX_PERP_BUILDER_FEE_RATE,
    MAX_SPOT_BUILDER_FEE_RATE, MmFeeTier, StakeDiscountTier, TradeFeeBreakdown, UserFeeRates,
    VipFeeTier,
};
pub use vlm::{
    BASE_OPEN_ORDER_CAP, MAX_BONUS_OPEN_ORDERS, OpenOrderDecision, OpenOrderDescriptor,
    PRIVILEGED_OPEN_ORDER_ADDRESSES, PRIVILEGED_OPEN_ORDER_CAP, RawVlm, ScaledVlm,
    UserVolumeTotals, VOLUME_PER_EXTRA_ORDER, check_open_order_cap, fold_user_volumes,
    fold_users_raw_volume, is_privileged_open_order_address, open_order_limit,
};
