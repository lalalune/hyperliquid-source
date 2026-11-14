//! Independent reconstruction of the node #115 nested certificate decision `0x595fd20` and of the flow
//! under it: verifier `0x595f880`, equality helper `0x4e08870` + `0x4e550e0`, signer collector
//! `0x4e00160`, per-signature check `0x57e8bd0`, quorum `0x595bc40` + `0x4d3e1a0`, the stake-set provider
//! `0x595e5c0` ([`history::StakeHistory`]), and, since round 4, the digest builder `0x57e8d40`
//! ([`digest`], [`keccak`]) and the recovery wrapper `0x1536a90` ([`recover`]).
//!
//! What stays outside the crate (all of it is stated, none of it is hidden behind one name):
//! * the curve routine under the recovery wrapper, three functions of a compiled-in secp256k1 library
//!   (`0x632b660`, `0x632b7b0`, `0x632b480` and what they call), injected as [`recover::Secp256k1`]; the tests
//!   supply stand-ins, so no real signature is verified here;
//! * the message variants of the serializer other than variant 1, and the squeezing modes of the hasher;
//! * the value-level model of the containers (history search, tree iterator, drops, allocation, native ABI),
//!   see the README.
//!
//! [`verifier::StakeSetProvider`] stays a trait so that a test can stand in for the state;
//! [`signer::SignaturePrimitives`] stays a trait so that a test can record what the check hands over;
//! [`primitives::NodePrimitives`] is the real digest and wrapper around an injected curve routine.
//!
//! No target code is executed. `research/work-items/RE-008-node115-nested-certificate-decision/` has the
//! instruction addresses behind every branch (`relations*.tsv`, checked by `verify_target.py`).

pub mod certificate;
pub mod collect;
pub mod decision;
pub mod digest;
pub mod equality;
pub mod history;
pub mod keccak;
pub mod primitives;
pub mod quorum;
pub mod recover;
pub mod signer;
pub mod sigmap;
pub mod stake;
pub mod verifier;

pub use certificate::{Certificate, Context};
pub use decision::{
    Output, TAG_BEHIND, TAG_CONTINUE, TAG_MISMATCH, TAG_OUT_OF_ORDER, TAG_UNEQUAL, VerifierResult, decide,
    decide_nested, empty_reference,
};
pub use verifier::{Rejection, StakeSetProvider, Verdict, verify};
