//! Integrated `orderbook` crate for Linux x86-64 node #115
//! (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
//!
//! Combines `node115-assets`, `node115-fees`, and all 19 verified Cargo-packaged
//! `RE-006` micro-crates with binary-grounded implementations of:
//! - order slab allocation/recycling and doubly-linked per-level FIFO queues (`RE-006-book-slab-link-115`),
//! - order peer links and parent-child detach compaction (`RE-006-book-peer-links-115`),
//! - price-time matching, TIF dispatch (`0x936ecc`), self-trade prevention (`0x5911dd0`),
//!   resting reduce-only validation, maker/taker margin clamping, and OID cancel/modify (`0x23ce3e0`),
//! - multi-asset `Books` container (`l1/src/books.rs`).

#![forbid(unsafe_code)]

pub mod books;
pub mod matching;
pub mod relations;
pub mod slab;

/// Verified node #115 target binary SHA-256.
pub const TARGET_SHA256: &str =
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";

// Re-export verified Cargo-packaged `orderbook` micro-crates.
pub use node115_level_change_record as level_change_record;
pub use node115_mid_market_order_builder as mid_market_order_builder;
pub use node115_mid_market_plan as mid_market_plan;
pub use node115_open_interest_cap as open_interest_cap;
pub use node115_order_band_gates as order_band_gates;
pub use node115_order_group_admission as order_group_admission;
pub use node115_order_ring_growth as order_ring_growth;
pub use node115_order_unlink_level as order_unlink_level;
pub use node115_post_broadcast_targets as post_broadcast_targets;
pub use node115_priority_three as priority_three;
pub use node115_schedule_cancel as schedule_cancel;
pub use node115_tif_name_codec as tif_name_codec;
pub use node115_twap_action_wire as twap_action_wire;
pub use node115_twap_advance as twap_advance;
pub use node115_twap_cancel_signing_input as twap_cancel_signing_input;
pub use node115_twap_finish as twap_finish;
pub use node115_twap_limit_price as twap_limit_price;
pub use node115_twap_quantity as twap_quantity;
pub use node115_twap_tag4_cleanup as twap_tag4_cleanup;

pub use books::Books;
pub use matching::{
    BAD_ALO_HEAD, Book, BookRiskOracle, CancelError, FillEvent, IOC_CANCEL_HEAD, InsertError,
    InsertOrderRequest, InsertOutcome, L2Level, MAX_ORDER_CAP, ModifyError, ModifyOrderRequest,
    OrderStatus, RestingCancelReason, UnboundedRiskOracle, cancel_oid_hash, would_cross,
};
pub use relations::{OrderRelations, detach_from_parent, link_peers};
pub use slab::{Level, OrderRecord, OrderSlab, SlabError, SlabIndex, UnlinkResult};
