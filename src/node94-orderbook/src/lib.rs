//! A standalone, evidence-bounded order-book lifecycle component for node #94.
//!
//! This crate implements only the transitions supported by the RE-006 packets:
//! slot allocation/reuse, signed price-level ordering, FIFO links, cancellation,
//! one selected resting-order match step, and relation cleanup. It is not a
//! complete exchange, matching loop, risk engine, or target-ABI replacement.

mod book;
pub mod first_left_insertion;
mod layout;
mod matching;
mod snapshot;
mod types;

pub use book::{Book, OrderView};
pub use layout::{TARGET_SHA256, TargetRelationLayout, TargetSlotLayout};
pub use matching::{
    Fill, MAX_SUPPORTED_NOTIONAL, MatchLimits, MatchOutcome, MatchReason, MatchStatus, TakerOrder,
    TargetFillMask,
};
pub use snapshot::{BookSnapshot, LevelSnapshot, SlotSnapshot, SlotStateSnapshot};
pub use types::{
    BookError, CancelReason, CancelRecord, InsertOrder, OrderId, RelationRequest, Side, SlotId,
    UserId,
};

#[cfg(test)]
mod tests;
