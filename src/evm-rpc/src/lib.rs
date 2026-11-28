#![forbid(unsafe_code)]
//! Node #115 `evm_rpc` component reconstruction.
//!
//! Target: Linux x86-64 node #115
//! (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).

pub mod fee_history;
mod fee_history_result;
pub mod forwarder;
pub mod limiter;
pub mod method_router;
pub mod store;

pub use fee_history::{
    compute_fee_history_range, select_weighted_rewards, validate_reward_percentiles,
    FeeHistoryError, FeeHistoryRange, RewardRow, BLOB_GAS_DIVISOR, MAX_FEE_HISTORY_BLOCKS,
    MAX_REWARD_PERCENTILES,
};
pub use fee_history_result::FeeHistoryResult;
pub use forwarder::{
    build_send_raw_tx_json_rpc, decode_raw_tx_hex, encode_raw_tx_hex, forward_url_for_selector,
    ForwardError, ForwardErrorKind, HexDecodeError, MAINNET_EVM_RPC_URL, TESTNET_EVM_RPC_URL,
};
pub use limiter::{
    validate_log_filter_limits, ExpensiveCallLimiter, LimiterSelector, PermitOutcome,
    EXPENSIVE_CALL_PERMIT_METRIC, LOG_FILTER_LIMIT_ERROR, MAX_FILTER_ITEMS, MAX_PERMIT_COUNT,
};
pub use method_router::{
    MethodRouter, RouterError, EVM_RPC_ALL_METHOD_COUNT, EVM_RPC_CORE_METHODS,
    EVM_RPC_EXTRA_METHODS, EVM_RPC_WRITE_FORWARD_METHOD, JSONRPC_CONTENT_TYPE,
    JSONRPC_INTERNAL_ERROR, JSONRPC_INVALID_PARAMS, JSONRPC_INVALID_REQUEST,
    JSONRPC_METHOD_NOT_FOUND, JSONRPC_PARSE_ERROR, JSONRPC_SERVER_ERROR,
};
pub use node115_block_number_text::{parse_number_text, NumberSelector, ParseError as BlockNumberParseError};
pub use node115_storage_key_builder::{
    build_storage_key, storage_key_suffix, ADDRESS_BYTES, SLOT_BYTES, STORAGE_KEY_SUFFIX_BYTES,
};
pub use store::{build_block_height_key, decode_block_height_suffix, SYSTEM_TXS_BY_BLOCK_TABLE};
