//! Integrated node #115 L1 shared state helpers.
//!
//! Target binary: Linux x86-64 `hl-node` #115, SHA-256
//! `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

#![forbid(unsafe_code)]

pub mod chain_ext;
pub mod decimal_scaler;
pub mod hyperliquidity;
pub mod nonce_set;
pub mod state_guards;
pub mod utils;

pub use node115_agent_erase_state as agent_erase;
pub use node115_daycount_date as daycount_date;

/// Pinned SHA-256 digest of Linux x86-64 node #115 (`artifacts/node/115/hl-node`).
pub const TARGET_SHA256: &str =
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";

/// 20-byte account address.
pub type Address = [u8; 20];
