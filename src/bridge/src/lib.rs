#![forbid(unsafe_code)]
//! Node #115 `bridge` component reconstruction (`l1/src/bridge2.rs`,
//! `l1/src/bridge_request.rs`).
//!
//! Target: Linux x86-64 node #115
//! (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).

pub mod eth_event;
pub mod request;
pub mod state;

pub use eth_event::{EthEventId, VoteEthDepositAction};
pub use node115_bridge_event_name_decoder::Node115BridgeEvent;
pub use node115_bridge_preimage::{inner_digest as bridge_preimage_digest, preimage as bridge_preimage};
pub use node115_bridge_request_abi::{
    encode_request_withdrawal, DYNAMIC_OFFSET as REQUEST_WITHDRAWAL_DYNAMIC_OFFSET,
    ENCODED_LEN as REQUEST_WITHDRAWAL_ENCODED_LEN, REQUEST_LABEL as REQUEST_WITHDRAWAL_LABEL,
};
pub use node115_bridge_request_mutation::{
    apply as apply_bridge_request_mutation, FreshValue as BridgeRequestFreshValue,
    Key as BridgeRequestKey, Request as WithdrawalMutationRequest,
    State as WithdrawalMutationState, Stop as WithdrawalMutationStop,
};
pub use node115_bridge_word_flatten::{
    build as flatten_bridge_words, Preimage as FlattenedBridgePreimage,
};
pub use node115_token_id::{keccak256, Keccak256};
pub use request::{
    arb_chain_id_for, bridge2_contract_lookup_key, BridgeAgentPayload, BridgeRequest, BridgeRole,
    ARB_MAINNET_CHAIN_ID, ARB_SEPOLIA_CHAIN_ID, BRIDGE_AGENT_SOURCE,
};
pub use state::{BRIDGE2_SERIALIZED_FIELD_COUNT, BRIDGE2_SERIALIZED_NAMED_KEYS};
