//! Independently authored, offline margin calculations established for node #94.
//!
//! This crate deliberately excludes live state, networking, order execution,
//! liquidation sizing, and balance transfers.

#![forbid(unsafe_code)]

mod candidate;
mod position;
mod requirements;
mod surplus;
mod tiers;
mod types;
pub mod row_selector;

pub use candidate::{
    CandidateAdmission, CandidateScope, CandidateSubject, LiquidationCandidate,
    TARGET_CANDIDATE_RECORD_BYTES, admit_cross_candidate, admit_isolated_candidate,
};
pub use position::{
    AccountingMode, MarginMode, PositionCalculationError, PositionInput, PositionMargin,
    calculate_position_margin,
};
pub use requirements::{
    RequirementError, initial_requirement, maintenance_requirement, select_tier,
};
pub use surplus::{
    CrossMarginContribution, CrossMarginSummary, LiquidationAssessment, LiquidationError,
    aggregate_cross_margin, assess_cross_liquidation, assess_isolated_liquidation,
};
pub use tiers::TierConstructionError;
pub use types::{
    LATER_TIER_LOWER_INCLUSIVE_MAX, MAX_DESCRIPTION_BYTES, MAX_LEVERAGE, MAX_TIERS, MarginTable,
    MarginTier, RawMarginTable, RawMarginTier, WIRE_NOTIONAL_EXCLUSIVE_MAX,
};
