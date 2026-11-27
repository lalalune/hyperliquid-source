//! Cohesive node #115 staking & validator lifecycle library crate (`RE-008`).
//!
//! Joins the ten existing binary-backed #115 staking/validator/governance
//! micro-crates with independently authored `#![forbid(unsafe_code)]` Rust
//! reconstructions of:
//! - [`jailing`]: 3-arm validator jailing/unjailing state machine (`0x3c3c260`),
//!   stake-weighted median `jail_until`, protected-validator guard (`0x3c35a10`),
//!   300-second manual unjail cooldown, and expiry pruning (`0x3c35fe0`);
//! - [`snapshot`]: epoch validator snapshot lookup (`0x36c8430`), epoch stake
//!   quorum check (`0x36c7f70`), unique profile extraction (`0x36c7b30`), and
//!   bidirectional address/key queries (`0x36ca5b0` / `0x36ca700`);
//! - [`admission`]: 5-class action signer admission gate (`0x2bdb230` /
//!   `0x4d907c0` / `0x36c2030`) with exact 92-entry class table (`0x79dd60`)
//!   and other-chain listed addresses (`0x464946..0x464982`);
//! - [`delegation`]: delegation/undelegation lifecycle (`0x2c68bb0` / `0x3c34fd0` /
//!   `0x4221f40` / `0x4221510` / `0x42258d0` / `0x4225a30`), 4-chain lockup table
//!   (`0x4578a0`), 1-year self-delegation lock (`0x459058`), and epoch-min tracking;
//! - [`governance`]: staking proposal creation gate (`0x3c348b0`, slot `0x64e5bd0`).
//!
//! All semantics are bound to Linux x86-64 node #115
//! (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
#![forbid(unsafe_code)]

pub mod admission;
pub mod delegation;
pub mod governance;
pub mod jailing;
pub mod snapshot;

// Re-export all integrated node #115 staking, validator, and governance micro-crates.
pub use node115_governance_codec as governance_codec;
pub use node115_governance_vote_state as governance_vote_state;
pub use node115_link_staking_state as link_staking_state;
pub use node115_staking_error_text as error_text;
pub use node115_staking_projection as projection;
pub use node115_staking_weight_comparison as weight_comparison;
pub use node115_validator_epoch_ring as epoch_ring;
pub use node115_validator_snapshot_publication as snapshot_publication;
pub use node115_validator_unregister as validator_unregister;
pub use node115_vote_choice_weight as vote_choice_weight;

pub use admission::{
    ACTION_CLASS_TABLE, ACTION_CLASS_TABLE_BASE, AdmissionError, AdmissionOutcome,
    OTHER_CHAIN_LISTED_ADDRESSES, SignerClass, STATUS_OK, STATUS_REFUSED, STATUS_UNKNOWN_USER,
    STATUS_UNAUTHORIZED_VALIDATOR, UserResolver, action_class, admit_signer,
};
pub use delegation::{
    ActiveValidatorStake, DELEGATION_LOCKUP_SECS_BITS, DelegationError, DelegationMode,
    DelegationState, EpochMinStake, SELF_DELEGATION_LOCK_SECS_BITS, StakingChain,
    TAG_ACTION_OK, TAG_ADD_RESULT_ERROR, TAG_DELEGATE_ZERO_AMOUNT, TAG_DELEGATIONS_DISABLED,
    TAG_INSUFFICIENT_BALANCE_DELEGATE, TAG_INSUFFICIENT_BALANCE_UNDELEGATE, TAG_LOCKUP_ACTIVE,
    TAG_MISSING_EPOCH_STATE, TAG_NATIVE_TOKEN_MISSING, TAG_SELF_DELEGATION_INSUFFICIENT,
    TAG_UNKNOWN_VALIDATOR, UserDelegation, ValidatorDelegationInfo, add_secs_saturating,
};
pub use governance::{
    MAX_ACTIVE_PROPOSALS_PER_USER, PROPOSAL_DESC_MAX_LEN, PROPOSAL_DESC_MIN_LEN,
    PROPOSAL_DURATION_MAIN_LONG_BITS, PROPOSAL_DURATION_MAIN_SHORT_BITS,
    PROPOSAL_DURATION_TEST_LONG_BITS, PROPOSAL_DURATION_TEST_SHORT_BITS,
    PROPOSAL_MIN_DELEGATED_STAKE, PROPOSAL_TITLE_MAX_LEN, PROPOSAL_TITLE_MIN_LEN, ProposeError,
    TAG_INSUFFICIENT_DELEGATIONS_TO_PROPOSE, TAG_PROPOSAL_ALREADY_EXISTS, TAG_PROPOSAL_DESC_LEN,
    TAG_PROPOSAL_TITLE_LEN, TAG_TOO_MANY_ACTIVE_PROPOSALS, proposal_voting_duration_secs,
    validate_proposal_creation,
};
pub use jailing::{
    Address, JailingAction, JailingError, JailingState, JailingTime, MANUAL_UNJAIL_INTERVAL_SECS,
    STATUS_DISABLED, STATUS_JAILED_UNTIL, STATUS_MANUAL_UNJAIL_COOLDOWN,
    weighted_median_jail_until,
};
pub use snapshot::{
    EpochSnapshot, STATUS_MISSING_EPOCH, STATUS_NOT_VALIDATOR, SnapshotError, SnapshotStore,
    ValidatorEntry, ValidatorKey,
};
