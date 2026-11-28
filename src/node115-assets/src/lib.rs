//! Integrated `assets` crate for Linux x86-64 node #115
//! (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
//!
//! Combines the verified `RE-004` micro-crates with binary-grounded core types
//! for `l1/src/asset/pdi.rs`, `l1/src/perp_meta.rs`, `l1/src/spot_meta.rs`,
//! `l1/src/qtys/*`, and `l1/src/wire_qty.rs`.

#![forbid(unsafe_code)]

pub mod meta;
pub mod pdi;
pub mod qtys;
pub mod wire_qty;

/// Verified node #115 target binary SHA-256.
pub const TARGET_SHA256: &str =
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301";

// Re-export verified Cargo-packaged `assets` micro-crates.
pub use node115_decimal96_conversion as decimal96_conversion;
pub use node115_f64_decimal as f64_decimal;
pub use node115_f64_powi_leaf as f64_powi_leaf;
pub use node115_five_significant_digits as five_significant_digits;
pub use node115_price_list_retain as price_list_retain;
pub use node115_quantity_notification as quantity_notification;
pub use node115_quantity_preparation_adapter as quantity_preparation;
pub use node115_quantity_source as quantity_source;
pub use node115_signed_scalar as signed_scalar;
pub use node115_spot_price_band as spot_price_band;
pub use node115_spot_scalar_conversions as spot_scalar_conversions;
pub use node115_three_digit_decimal as three_digit_decimal;
pub use node115_u256_decimal_scale as u256_decimal_scale;

pub use meta::{
    BUILTIN_MARGIN_TABLE_LIMIT, DeployerFeeShareError, LEGACY_MAINNET_TOKEN_MAX, MAINNET_CHAIN_TAG,
    MAX_DEPLOYER_TRADING_FEE_SHARE_E5, MetaError, PerpAssetMeta, PerpMeta, PerpNameLookupError,
    SpotMeta, SpotPairMeta, SpotTokenMeta, is_builtin_margin_table_id, update_deployer_trading_fee_share,
};
pub use pdi::{PDI_STRIDE, Pdi, PerpAsset, Side, SpotAsset, Token};
pub use qtys::{
    MAX_PERP_SZ_DECIMALS, MAX_SPOT_SZ_DECIMALS, Ntl, Ntli, NoopOverflowSink, OverflowKind,
    OverflowSink, POW10_F64, Px, RecordingOverflowSink, Sz, Szi, Usdc, UsdcSigned, Wei,
    scale_nonneg_i64_by_f64_clamped,
};
