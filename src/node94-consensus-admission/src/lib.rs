//! Evidence-bounded reconstruction of node #94 consensus block admission.
//!
//! This crate reconstructs the stake-snapshot, QC, TC, ordered admission, and
//! registration behavior pinned by `RE-008-block-admission-94`. QC-vote, timeout,
//! heartbeat and acknowledgement preimages are available through the digest
//! helpers and [`message_preimages`]. Proposer scheduling and signature recovery
//! remain outside the recovered contract. Admission delegates authentication
//! through [`AdmissionAuthenticator`]; a bare boolean cannot cross that boundary.
//! [`block_preimage`] additionally supplies selector 0 with explicit packed time.
//!
//! This is not a network service or a complete consensus implementation.

mod admission;
mod auth;
pub mod block_preimage;
mod digest;
mod client_batch;

pub mod client_transaction_join;
mod error;
pub mod message_preimages;
mod qc;
/// Independent qualified wire-field projection; no admission/authentication integration.
pub mod qc_recovery_byte;
pub mod qc_row_success;
/// Qualified mode-1, four-FD-word success projection; separate from admission.
pub mod qc_fd_group;
/// Qualified full-word-zero, accepted-marker group projection; separate from admission.
pub mod qc_mode0_group;
/// Qualified mode-one reservation/accepted-marker group projection.
pub mod qc_mode1_group;
mod stake;
mod state;
mod tc;
mod types;

pub use admission::{verify_block, VerifiedBlock};
pub use auth::{AdmissionAuthenticator, AuthenticationError};
pub use digest::{qc_vote_digest, qc_vote_preimage};
pub use client_batch::{
    verify_client_batch, ClientBatchAuthenticator, ClientBatchError, ClientBatchFailure,
    ClientBlock, ClientBlockBuffer, ClientBlockSink, ClientBlockTime, ClientBufferError,
    ClientBufferView, ClientCommitProof, ClientSpanError, ClientSpanField, ClientTransaction,
    TimedSignedBlock,
};
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
