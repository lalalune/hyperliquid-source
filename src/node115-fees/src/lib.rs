//! Integrated `fees` crate for Linux x86-64 node #115
//! (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
//!
//! Combines the verified `fees` micro-crates with binary-grounded implementations of
//! `l1/src/raw_vlm.rs`, `l1/src/scaled_vlm.rs`, `l1/src/fees/fees.rs`,
//! `l1/src/fees/compute.rs`, open-order cap thresholds (`0x5495210`/`0x5495680`),
//! and fee credit distribution & ledger updates (`0x3c1ae50`, `0x3c1a250`, `0x3c1a3f0`, `0x3c10000`).

#![forbid(unsafe_code)]

pub mod credit;
pub mod schedule;
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
    FeeCell, FeeCreditMode, FeeDistributionRecord, FeeLedger, FeeScaleError, SecondarySplitRow,
};
pub use schedule::is_monotonically_non_increasing;
pub use vlm::{
    BASE_OPEN_ORDER_CAP, MAX_BONUS_OPEN_ORDERS, OpenOrderDecision, OpenOrderDescriptor,
    PRIVILEGED_OPEN_ORDER_ADDRESSES, PRIVILEGED_OPEN_ORDER_CAP, RawVlm, ScaledVlm,
    UserVolumeTotals, VOLUME_PER_EXTRA_ORDER, check_open_order_cap, fold_user_volumes,
    fold_users_raw_volume, is_privileged_open_order_address, open_order_limit,
};
