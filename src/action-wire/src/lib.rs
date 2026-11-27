//! Integrated node #115 action wire codecs, EIP-712 signing digests, and error display.
//!
//! Target binary: Linux x86-64 `hl-node` #115, SHA-256
//! `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

#![forbid(unsafe_code)]

pub mod eip712;
pub mod error_display;
pub mod variants;

pub use l1_shared::nonce_set;
pub use node115_action_any_reader as any_reader;
pub use node115_action_enum_variant_matchers as enum_variant_matchers;
pub use node115_action_msgpack_identifier as msgpack_identifier;
pub use node115_signed_action_four_field as signed_action_four_field;
pub use node115_usd_class_transfer as usd_class_transfer;
pub use node115_vault_address::keccak256;

/// Pinned SHA-256 digest of Linux x86-64 node #115 (`artifacts/node/115/hl-node`).
pub const TARGET_SHA256: &str =
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";

/// 20-byte Ethereum / Hyperliquid address.
pub type Address = [u8; 20];
