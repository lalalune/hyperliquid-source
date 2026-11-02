//! Independently authored, offline margin calculations established for node #94.
//!
//! This crate deliberately excludes live state, networking, order execution,
//! liquidation sizing, and balance transfers.

#![forbid(unsafe_code)]

mod candidate;
mod leverage_increase;
mod position;
mod requirements;
mod surplus;
mod tiers;
mod tier_cap;
mod types;
pub mod row_selector;
pub mod hash20;

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
pub use tier_cap::position_leverage_cap;
pub use types::{
    LATER_TIER_LOWER_INCLUSIVE_MAX, MAX_DESCRIPTION_BYTES, MAX_LEVERAGE, MAX_TIERS, MarginTable,
    MarginTier, RawMarginTable, RawMarginTier, WIRE_NOTIONAL_EXCLUSIVE_MAX,
};

pub use leverage_increase::{
    CustomIncreaseDecision, CustomIncreaseDomainError, CustomLeverageIncrease,
    check_custom_leverage_increase,
};
