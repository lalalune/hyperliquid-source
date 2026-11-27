//! Integrated node #115 action router (`0x2bda7c0`) and action handler crates.
//!
//! Target binary: Linux x86-64 `hl-node` #115, SHA-256
//! `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

#![forbid(unsafe_code)]

pub mod router;

pub use action_wire;
pub use node115_action_admission_binding as admission_binding;
pub use node115_builder_approval as builder_approval;
pub use node115_claim_rewards as claim_rewards;
pub use node115_display_name_decision as display_name_decision;
pub use node115_display_name_state as display_name_state;
pub use node115_referral_code as referral_code;
pub use node115_set_referrer as set_referrer;

/// Pinned SHA-256 digest of Linux x86-64 node #115 (`artifacts/node/115/hl-node`).
pub const TARGET_SHA256: &str =
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";
