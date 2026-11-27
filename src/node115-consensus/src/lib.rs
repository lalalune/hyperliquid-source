//! Cohesive node #115 consensus library crate (`RE-008`).
//!
//! Joins the existing binary-backed #115 consensus micro-crates with
//! independently authored Rust reconstructions of:
//! - [`round_progression`]: jailed-validator history lookup (`0x595c3a0`),
//!   TC high-QC selection (`0x5960010`), timeout quorum + 1/3 amplification
//!   (`0x2e112f0`), local timeout broadcast (`0x2e154e0`), and round
//!   advancement (`0x2e19920`);
//! - [`admission`]: signed block (`0x57e8970` / `0x2786870`) and timeout
//!   message (`0x2786a20`) admission front ends;
//! - [`block_rules`]: block validation rules (`0x59d6b80`, `signed.rs:194`);
//! - [`proposer`]: deterministic stake-weighted proposer selection (`0x595cb30`);
//! - [`tc_verify`]: timeout certificate verification (`0x5960390` + `0x564b510`);
//! - [`timeout_flow`]: first-timer polling selector (`0x2cdca20`) and
//!   saturating timeout counter (`0x2e098e0` arm `0x8000000000000006`);
//! - [`wire_codec`]: 5-variant bincode signing payload serializer (`0x5823db0`)
//!   and `try_propose` pre-proposal guards (`0x2e13ea0`).
//!
//! All semantics are bound to Linux x86-64 node #115
//! (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
//! Cryptographic curve operations, networking, and runtime timers stay behind
//! explicit trait/value boundaries.

pub mod admission;
pub mod block_rules;
pub mod proposer;
pub mod round_progression;
pub mod tc_verify;
pub mod timeout_flow;
pub mod wire_codec;

// Re-export integrated node #115 consensus micro-crates for downstream
// `node-runtime` and `storage-abci` callers.
pub use node115_certificate_caller as certificate_caller;
pub use node115_certificate_long_sort as certificate_long_sort;
pub use node115_consensus_batch_floor as batch_floor;
pub use node115_consensus_timer_conversion as timer_conversion;
pub use node115_execution_history_selection as execution_history_selection;
pub use node115_execution_order as execution_order;
pub use node115_nested_certificate_decision as nested_certificate;
pub use node115_stake_predicate as stake_predicate;
pub use node115_varint_buffer_writer as varint_writer;
pub use node115_vote_eligibility as vote_eligibility;

// Core consensus types & entrypoints surfaced directly at crate root.
pub use admission::{
    AdmissionPrimitives, BlockAdmissionError, BlockEnvelope, BlockRules, SignedBlockInput,
    SignedTimeoutInput, TimeoutAdmissionError, TimeoutDigestPayload, admit_signed_block,
    admit_signed_timeout, select_block_certificate_round,
};
pub use block_rules::{
    BlockJustification, BlockProposerProvider, BlockRuleError, ConsensusBlock, MAX_BLOCK_TX_HASHES,
    verify_block_rules,
};
pub use proposer::{
    PreparedWeights, ProposerError, ProposerScheduleHistory, ScheduleEvent, StakeRow,
    TAG_PROPOSER_EMPTY_SCHEDULE, TAG_PROPOSER_MISSING_HISTORY, TAG_PROPOSER_SELECTED,
    build_schedule, event_order, event_point_bits, history_query, history_warning_limit,
    prepare_weights, select_proposer,
};
pub use tc_verify::{
    TcSignatureEntry, TcVerifyError, VerifiableTimeoutCertificate, verify_timeout_certificate,
};
pub use wire_codec::{
    PeerMsgSigningPayload, SIGNING_TAG_BLOCK, SIGNING_TAG_PEER_MSG, SIGNING_TAG_STATUS,
    SIGNING_TAG_TIMEOUT, SIGNING_TAG_VOTE, TimeoutSigningPayload, TryProposeDecision,
    VoteSigningPayload, encode_block_signing_payload, evaluate_try_propose_guards,
    write_varint_u32, zigzag_encode_i64,
};
pub use nested_certificate::{
    Certificate, Context, Output as CertificateDecisionOutput, Rejection as CertificateRejection,
    StakeSetProvider, Verdict as CertificateVerdict, decide_nested, verify as verify_certificate,
};
pub use round_progression::{
    Address, AdvanceRoundReport, AdvanceTransitionKind, JailedHistory, JailedLookupError,
    JailedLookupOutcome, OutboundMessageKind, ProposerProvider, RoundMetricCode, RoundState,
    TimeoutCheckOutcome, TimeoutEntry, TimeoutQuorumChecker, advance_round,
    check_timeout_quorum_and_advance, jailed_validators_query_round, local_timeout_broadcast_plan,
    select_highest_qc_timeout, should_amplify_timeout,
};
pub use timeout_flow::{
    SelectorOutcome, TimerArm, TimerState, TimeoutCounterOutcome, poll_timer_arms,
    saturating_timeout_tick,
};
