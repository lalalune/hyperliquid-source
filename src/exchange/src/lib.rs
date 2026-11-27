//! Integrated node #115 exchange orchestration crate.
//!
//! Target binary: Linux x86-64 `hl-node` #115, SHA-256
//! `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

#![forbid(unsafe_code)]

pub mod bole_liquidation;
pub mod bole_reserve;
pub mod orchestrator;
pub mod spot_deploy;
pub mod stake_requirement;
pub mod token_scaling;

pub use action_dispatch;
pub use action_wire;
pub use clearinghouse;
pub use dex_registry;
pub use l1_shared;
pub use node115_assets as assets;
pub use node115_bole_record_bound as bole_record_bound;
pub use node115_bole_reserve_reply as bole_reserve_reply;
pub use node115_bole_user_reply as bole_user_reply;
pub use node115_fees as fees;
pub use node115_funding_premium as funding_premium;
pub use node115_funding_rate as funding_rate;
pub use node115_funding_read_reset as funding_read_reset;
pub use node115_funding_settlement_user as funding_settlement_user;
pub use node115_modify_window_admission as modify_window_admission;
pub use node115_orderbook as orderbook;
pub use vaults;

/// Pinned SHA-256 digest of Linux x86-64 node #115 (`artifacts/node/115/hl-node`).
pub const TARGET_SHA256: &str =
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";

/// 20-byte account address.
pub type Address = [u8; 20];
