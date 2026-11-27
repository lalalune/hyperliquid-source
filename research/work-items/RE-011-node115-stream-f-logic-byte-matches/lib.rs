#![forbid(unsafe_code)]
#![allow(dead_code, non_camel_case_types)]

//! Clean-room MIT reconstruction of Stream F (`bridge`, `evm`, `evm-rpc`)
//! first-party Serde field-dispatch functions (`FieldVisitor::visit_str` and
//! `FieldVisitor::visit_bytes`) targeting Linux x86-64 node #115
//! (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
//!
//! Zero external dependencies; live-compiled under:
//!   `rustc +1.95.0 --edition=2021 --crate-type=rlib -C opt-level=3 -C overflow-checks=yes -C codegen-units=1 --emit=obj`

use std::ptr::NonNull;

/// Sret `Result<Field, ErrTag0>` error layout where `Ok(Field)` has tag `0x00`
/// at offset 0 and the field discriminant byte at offset 1 (matches `serde_json`
/// / generic `Error` with `size > 16` B in node #115).
#[repr(C)]
pub struct ErrTag0(pub usize, pub usize, pub usize);

/// 1-byte-aligned 9-variant error layout mirroring `rmp_serde::decode::Error`
/// (`0..=8` error variants -> `Result<Field, ErrTag9>` niches `Ok(Field)` to
/// tag `0x09` at offset 0 and `Field` at offset 1, passed via sret).
pub enum ErrTag9 {
    V0([u8; 24]),
    V1,
    V2,
    V3,
    V4,
    V5,
    V6,
    V7,
    V8,
}

/// 8-byte non-null pointer error layout mirroring `serde_json::Error`
/// (`Result<Field, JsonErr>` -> 16 B sret with tag `0x00` = `Ok(Field at +1)`,
/// tag `0x01` = `Err(ptr at +8)`).
pub struct JsonErr(pub NonNull<u8>);

#[cold]
#[inline(never)]
fn stub_unknown_field(value: &str, expected: &'static [&'static str]) -> JsonErr {
    std::hint::black_box((value, expected));
    std::hint::black_box(JsonErr(NonNull::dangling()))
}

const ABI_GUARD_FIELDS: &[&str] = &["__abi_guard__"];

/// Secondary call site so LLVM IPSCCP preserves the `(field, expected)` ABI of
/// `stub_unknown_field` across the crate boundary (matching `serde::de::Error::unknown_field`).
pub fn abi_guard_unknown_field(value: &str) -> JsonErr {
    stub_unknown_field(value, ABI_GUARD_FIELDS)
}

// =========================================================================
// 1. bridge: Bridge2 (15 fields + __Ignore)
// =========================================================================

#[derive(Copy, Clone)]
pub enum Bridge2Field {
    EthIdToDepositVotes,
    FinishedDepositsData,
    Dvp,
    Dvpd,
    Dvs,
    Lfd,
    WithdrawalSignatures,
    WithdrawalFinalizedVotes,
    FinishedWithdrawalToTime,
    ValidatorSetSignatures,
    ValidatorSetFinalizedVotes,
    Bal,
    LastPrunedDepositBlockNumber,
    Oaw,
    R,
    Ignore,
}

#[inline(always)]
fn match_bridge2_str(value: &str) -> Bridge2Field {
    match value {
        "eth_id_to_deposit_votes" => Bridge2Field::EthIdToDepositVotes,
        "finished_deposits_data" => Bridge2Field::FinishedDepositsData,
        "dvp" => Bridge2Field::Dvp,
        "dvpd" => Bridge2Field::Dvpd,
        "dvs" => Bridge2Field::Dvs,
        "lfd" => Bridge2Field::Lfd,
        "withdrawal_signatures" => Bridge2Field::WithdrawalSignatures,
        "withdrawal_finalized_votes" => Bridge2Field::WithdrawalFinalizedVotes,
        "finished_withdrawal_to_time" => Bridge2Field::FinishedWithdrawalToTime,
        "validator_set_signatures" => Bridge2Field::ValidatorSetSignatures,
        "validator_set_finalized_votes" => Bridge2Field::ValidatorSetFinalizedVotes,
        "bal" => Bridge2Field::Bal,
        "last_pruned_deposit_block_number" => Bridge2Field::LastPrunedDepositBlockNumber,
        "oaw" => Bridge2Field::Oaw,
        "r" => Bridge2Field::R,
        _ => Bridge2Field::Ignore,
    }
}

pub fn bridge2_visit_str_tag0(value: &str) -> Result<Bridge2Field, ErrTag0> {
    Ok(match_bridge2_str(value))
}

pub fn bridge2_visit_str_tag9(value: &str) -> Result<Bridge2Field, ErrTag9> {
    Ok(match_bridge2_str(value))
}

pub fn bridge2_visit_bytes_tag9(value: &[u8]) -> Result<Bridge2Field, ErrTag9> {
    match value {
        b"eth_id_to_deposit_votes" => Ok(Bridge2Field::EthIdToDepositVotes),
        b"finished_deposits_data" => Ok(Bridge2Field::FinishedDepositsData),
        b"dvp" => Ok(Bridge2Field::Dvp),
        b"dvpd" => Ok(Bridge2Field::Dvpd),
        b"dvs" => Ok(Bridge2Field::Dvs),
        b"lfd" => Ok(Bridge2Field::Lfd),
        b"withdrawal_signatures" => Ok(Bridge2Field::WithdrawalSignatures),
        b"withdrawal_finalized_votes" => Ok(Bridge2Field::WithdrawalFinalizedVotes),
        b"finished_withdrawal_to_time" => Ok(Bridge2Field::FinishedWithdrawalToTime),
        b"validator_set_signatures" => Ok(Bridge2Field::ValidatorSetSignatures),
        b"validator_set_finalized_votes" => Ok(Bridge2Field::ValidatorSetFinalizedVotes),
        b"bal" => Ok(Bridge2Field::Bal),
        b"last_pruned_deposit_block_number" => Ok(Bridge2Field::LastPrunedDepositBlockNumber),
        b"oaw" => Ok(Bridge2Field::Oaw),
        b"r" => Ok(Bridge2Field::R),
        _ => Ok(Bridge2Field::Ignore),
    }
}

// =========================================================================
// 2. bridge: EthEventId (5 fields with 1-char rename + full alias + __Ignore)
// =========================================================================

#[derive(Copy, Clone)]
pub enum EthEventIdField {
    BlockNumber,
    TxIndex,
    EventType,
    EventIndex,
    TxHash,
    Ignore,
}

#[inline(always)]
fn match_eth_event_id_str(value: &str) -> EthEventIdField {
    match value {
        "b" => EthEventIdField::BlockNumber,
        "t" => EthEventIdField::TxIndex,
        "e" => EthEventIdField::EventType,
        "i" => EthEventIdField::EventIndex,
        "h" => EthEventIdField::TxHash,
        "block_number" => EthEventIdField::BlockNumber,
        "tx_index" => EthEventIdField::TxIndex,
        "event_type" => EthEventIdField::EventType,
        "event_index" => EthEventIdField::EventIndex,
        "tx_hash" => EthEventIdField::TxHash,
        _ => EthEventIdField::Ignore,
    }
}

pub fn eth_event_id_visit_str_tag0(value: &str) -> Result<EthEventIdField, ErrTag0> {
    Ok(match_eth_event_id_str(value))
}

pub fn eth_event_id_visit_str_tag9(value: &str) -> Result<EthEventIdField, ErrTag9> {
    Ok(match_eth_event_id_str(value))
}

// =========================================================================
// 3. evm: HyperEvm (15 fields + __Ignore)
// =========================================================================

#[derive(Copy, Clone)]
pub enum HyperEvmField {
    State2,
    LatestBlock2,
    SmallBlockContext,
    BigBlockContext,
    IsInitialized,
    L1ToEvmNativeTokenQueue,
    L1ToEvmErc20Queue,
    L1TransfersEnabled,
    DisabledCoreWriterActions,
    Put,
    Ul,
    Ub,
    Ft,
    Mrb,
    Dt,
    Ignore,
}

#[inline(always)]
fn match_hyperevm_str(value: &str) -> HyperEvmField {
    match value {
        "state2" => HyperEvmField::State2,
        "latest_block2" => HyperEvmField::LatestBlock2,
        "small_block_context" => HyperEvmField::SmallBlockContext,
        "big_block_context" => HyperEvmField::BigBlockContext,
        "is_initialized" => HyperEvmField::IsInitialized,
        "l1_to_evm_native_token_queue" => HyperEvmField::L1ToEvmNativeTokenQueue,
        "l1_to_evm_erc20_queue" => HyperEvmField::L1ToEvmErc20Queue,
        "l1_transfers_enabled" => HyperEvmField::L1TransfersEnabled,
        "disabled_core_writer_actions" => HyperEvmField::DisabledCoreWriterActions,
        "put" => HyperEvmField::Put,
        "ul" => HyperEvmField::Ul,
        "ub" => HyperEvmField::Ub,
        "ft" => HyperEvmField::Ft,
        "mrb" => HyperEvmField::Mrb,
        "dt" => HyperEvmField::Dt,
        _ => HyperEvmField::Ignore,
    }
}

pub fn hyperevm_visit_str_tag0(value: &str) -> Result<HyperEvmField, ErrTag0> {
    Ok(match_hyperevm_str(value))
}

pub fn hyperevm_visit_str_tag9(value: &str) -> Result<HyperEvmField, ErrTag9> {
    Ok(match_hyperevm_str(value))
}

pub fn hyperevm_visit_bytes_tag9(value: &[u8]) -> Result<HyperEvmField, ErrTag9> {
    match value {
        b"state2" => Ok(HyperEvmField::State2),
        b"latest_block2" => Ok(HyperEvmField::LatestBlock2),
        b"small_block_context" => Ok(HyperEvmField::SmallBlockContext),
        b"big_block_context" => Ok(HyperEvmField::BigBlockContext),
        b"is_initialized" => Ok(HyperEvmField::IsInitialized),
        b"l1_to_evm_native_token_queue" => Ok(HyperEvmField::L1ToEvmNativeTokenQueue),
        b"l1_to_evm_erc20_queue" => Ok(HyperEvmField::L1ToEvmErc20Queue),
        b"l1_transfers_enabled" => Ok(HyperEvmField::L1TransfersEnabled),
        b"disabled_core_writer_actions" => Ok(HyperEvmField::DisabledCoreWriterActions),
        b"put" => Ok(HyperEvmField::Put),
        b"ul" => Ok(HyperEvmField::Ul),
        b"ub" => Ok(HyperEvmField::Ub),
        b"ft" => Ok(HyperEvmField::Ft),
        b"mrb" => Ok(HyperEvmField::Mrb),
        b"dt" => Ok(HyperEvmField::Dt),
        _ => Ok(HyperEvmField::Ignore),
    }
}

// =========================================================================
// 4. evm-rpc: EthCallOverrides (4 fields with camelCase + snake_case alias)
// =========================================================================

#[derive(Copy, Clone)]
pub enum EthCallOverridesField {
    Request,
    BlockId,
    StateOverrides,
    BlockOverrides,
    Ignore,
}

#[inline(never)]
pub fn eth_call_ovr_tag0(value: &str) -> Result<EthCallOverridesField, ErrTag0> {
    match value {
        "request" => Ok(EthCallOverridesField::Request),
        "blockId" | "block_id" => Ok(EthCallOverridesField::BlockId),
        "stateOverrides" | "state_overrides" => Ok(EthCallOverridesField::StateOverrides),
        "blockOverrides" | "block_overrides" => Ok(EthCallOverridesField::BlockOverrides),
        _ => Ok(EthCallOverridesField::Ignore),
    }
}

// =========================================================================
// 5. evm-rpc: AccountOverride (6 fields + HyperEVM MovePrecompileToAddress)
// =========================================================================

#[derive(Copy, Clone)]
pub enum AccountOverrideField {
    Balance,
    Nonce,
    Code,
    State,
    StateDiff,
    MovePrecompileToAddress,
}

const ACCOUNT_OVERRIDE_FIELDS: &[&str] = &[
    "balance",
    "nonce",
    "code",
    "state",
    "stateDiff",
    "MovePrecompileToAddress",
    "movePrecompileToAddress",
];

pub fn account_override_visit_str(value: &str) -> Result<AccountOverrideField, JsonErr> {
    match value {
        "balance" => Ok(AccountOverrideField::Balance),
        "nonce" => Ok(AccountOverrideField::Nonce),
        "code" => Ok(AccountOverrideField::Code),
        "state" => Ok(AccountOverrideField::State),
        "stateDiff" => Ok(AccountOverrideField::StateDiff),
        "MovePrecompileToAddress" | "movePrecompileToAddress" => {
            Ok(AccountOverrideField::MovePrecompileToAddress)
        }
        _ => Err(stub_unknown_field(value, ACCOUNT_OVERRIDE_FIELDS)),
    }
}
