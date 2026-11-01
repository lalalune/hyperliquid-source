//! Evidence-bounded reconstruction of node #94 consensus block admission.
//!
//! This crate reconstructs the stake-snapshot, QC, TC, ordered admission, and
//! registration behavior pinned by `RE-008-block-admission-94`.  Proposer
//! scheduling, other digest variants, and signature recovery remain outside the
//! recovered native contract. [`block_preimage`] provides a separately qualified
//! selector-0 value helper with explicit packed time. Callers supply authentication through
//! [`AdmissionAuthenticator`]; a bare boolean cannot cross that boundary.
//!
//! This is not a network service or a complete consensus implementation.

mod admission;
mod auth;
pub mod block_preimage;
mod error;
mod qc;
mod stake;
mod state;
mod tc;
mod types;

pub use admission::{verify_block, VerifiedBlock};
pub use auth::{AdmissionAuthenticator, AuthenticationError};
pub use error::{AdmissionError, FatalAdmissionError, VerificationFailure};
pub use qc::verify_qc;
pub use stake::{
    has_strict_two_thirds, Quorum, StakeHistory, StakeSnapshot, RECENT_ROUND_SPAN, STAKE_LAG_ROUNDS,
};
pub use state::{
    admit_and_register, admit_verified_block, register_admitted_block, AdmittedBlock,
    ConsensusState, ForwardChannel, ForwardDisposition, OutboundBlock, RegisteredBlock,
    RegistrationOutcome, TransactionRecord, OUTBOUND_BLOCK_TAG, UNKNOWN_TRANSACTION_TAG,
};
pub use tc::verify_tc;
pub use types::{
    BlockHash, EventTime, Hardfork, Qc, QcVote, Round, SignatureBytes, SignedBlock, Tc,
    TimeoutVote, TransactionHash, ValidatorAddress,
};
