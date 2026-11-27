//! Integrated node #115 clearinghouses and risk library.
//!
//! Target binary: Linux x86-64 `hl-node` #115, SHA-256
//! `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

#![forbid(unsafe_code)]

pub mod liquidation;
pub mod margin_user_state;
pub mod position_risk;
pub mod reference_oracle;
pub mod spot_clearinghouse;

pub use node115_borrow_lend_codec as borrow_lend_codec;
pub use node115_borrow_lend_content_assembly as borrow_lend_content_assembly;
pub use node115_clearinghouse_ntl_ratio as ntl_ratio;
pub use node115_leverage_aggregate as leverage_aggregate;
pub use node115_margin_flat_compose as margin_flat_compose;
pub use node115_margin_mode_codec as margin_mode_codec;
pub use node115_margin_mode_identifier as margin_mode_identifier;
pub use node115_margin_range as margin_range;
pub use node115_margin_tree_range as margin_tree_range;
pub use node115_notional_collector as notional_collector;
pub use node115_oracle_entry_lifecycle as oracle_entry_lifecycle;
pub use node115_oracle_named_admission as oracle_named_admission;
pub use node115_oracle_nested_keys as oracle_nested_keys;
pub use node115_oracle_outcome_kind as oracle_outcome_kind;
pub use node115_outcome_account_projection as outcome_account_projection;
pub use node115_outcome_fraction_scale as outcome_fraction_scale;
pub use node115_outcome_payload as outcome_payload;
pub use node115_outcome_record_msgpack as outcome_record_msgpack;
pub use node115_position_transition as position_transition;

/// Pinned SHA-256 digest of Linux x86-64 node #115 (`artifacts/node/115/hl-node`).
pub const TARGET_SHA256: &str =
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";

/// 20-byte account address.
pub type Address = [u8; 20];
