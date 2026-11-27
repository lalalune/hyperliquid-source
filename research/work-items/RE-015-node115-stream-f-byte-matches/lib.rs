#![forbid(unsafe_code)]
//! Independently authored Stream F node #115 first-party Rust functions for
//! compiled-byte identity verification with `rustc 1.95.0 (59807616e 2026-04-14)`
//! (`--edition=2021 --crate-type=rlib -C opt-level=3 -C overflow-checks=yes`).

use core::fmt;

/// ABI-shaped boxed error payload modeling `serde_json::Error` in node #115.
#[derive(Debug, PartialEq, Eq)]
pub struct JsonErr(pub Box<[usize; 2]>);

#[cold]
#[inline(never)]
fn json_unknown_variant(v: &str, expected: &'static [&'static str]) -> JsonErr {
    let p = core::hint::black_box((v.as_ptr(), v.len(), expected.as_ptr(), expected.len()));
    JsonErr(Box::new([(p.0 as usize) ^ p.1, (p.2 as usize) ^ p.3]))
}

/// Prevents LLVM from specializing the `expected` slice argument of `json_unknown_variant`.
pub fn retain_json_unknown_variant(v: &str) -> JsonErr {
    json_unknown_variant(v, &[])
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chain {
    Local = 0,
    Sandbox = 1,
    Testnet = 2,
    Mainnet = 3,
}

/// `constants`: `Chain::fmt` (`0x1778c60..0x1778cca`, 106 B).
#[inline(never)]
pub fn constants_chain_fmt_display(c: &Chain, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match c {
        Chain::Local => f.write_str("Local"),
        Chain::Sandbox => f.write_str("Sandbox"),
        Chain::Testnet => f.write_str("Testnet"),
        Chain::Mainnet => f.write_str("Mainnet"),
    }
}

/// `info-api`: `NodeInfoRequest` 55-variant JSON `visit_str` (`0x2744200..0x2744bfa`, 2,554 B).
#[inline(never)]
pub fn info_request_55_visit_str_json(v: &str) -> Result<u8, JsonErr> {
    const VARIANTS: &[&str] = &[
        "fileSnapshot", "webData2", "webData3", "meta", "spotMeta",
        "outcomeMeta", "outcomeDeployerLimits", "clearinghouseState",
        "spotClearinghouseState", "openOrders", "exchangeStatus",
        "frontendOpenOrders", "activeAssetData", "maxMarketOrderNtls",
        "vaultSummaries", "userVaultEquities", "leadingVaults", "extraAgents",
        "subAccounts", "subAccounts2", "userFees", "userRateLimit",
        "spotDeployState", "spotPairDeployAuctionStatus", "perpDeployAuctionStatus",
        "votes", "delegations", "delegatorSummary", "maxBuilderFee",
        "userToMultiSigSigners", "userRole", "perpsAtOpenInterestCap",
        "perpDexLimits", "validatorL1Votes", "marginTable", "perpDexs",
        "allPerpMetas", "userDexAbstraction", "perpDexStatus",
        "borrowLendUserState", "borrowLendReserveState", "allBorrowLendReserveStates",
        "userAbstraction", "perpAnnotation", "perpCategories",
        "perpConciseAnnotations", "tokenAnnotation", "tokenConciseAnnotations",
        "settledOutcome", "settledQuestion", "approvedBuilders",
        "gossipPriorityAuctionStatus", "outcomeTemplates", "aqav2InterestHistory",
        "userStarState",
    ];
    match v {
        "fileSnapshot" => Ok(0),
        "webData2" => Ok(1),
        "webData3" => Ok(2),
        "meta" => Ok(3),
        "spotMeta" => Ok(4),
        "outcomeMeta" => Ok(5),
        "outcomeDeployerLimits" => Ok(6),
        "clearinghouseState" => Ok(7),
        "spotClearinghouseState" => Ok(8),
        "openOrders" => Ok(9),
        "exchangeStatus" => Ok(10),
        "frontendOpenOrders" => Ok(11),
        "activeAssetData" => Ok(12),
        "maxMarketOrderNtls" => Ok(13),
        "vaultSummaries" => Ok(14),
        "userVaultEquities" => Ok(15),
        "leadingVaults" => Ok(16),
        "extraAgents" => Ok(17),
        "subAccounts" => Ok(18),
        "subAccounts2" => Ok(19),
        "userFees" => Ok(20),
        "userRateLimit" => Ok(21),
        "spotDeployState" => Ok(22),
        "spotPairDeployAuctionStatus" => Ok(23),
        "perpDeployAuctionStatus" => Ok(24),
        "votes" => Ok(25),
        "delegations" => Ok(26),
        "delegatorSummary" => Ok(27),
        "maxBuilderFee" => Ok(28),
        "userToMultiSigSigners" => Ok(29),
        "userRole" => Ok(30),
        "perpsAtOpenInterestCap" => Ok(31),
        "perpDexLimits" => Ok(32),
        "validatorL1Votes" => Ok(33),
        "marginTable" => Ok(34),
        "perpDexs" => Ok(35),
        "allPerpMetas" => Ok(36),
        "userDexAbstraction" => Ok(37),
        "perpDexStatus" => Ok(38),
        "borrowLendUserState" => Ok(39),
        "borrowLendReserveState" => Ok(40),
        "allBorrowLendReserveStates" => Ok(41),
        "userAbstraction" => Ok(42),
        "perpAnnotation" => Ok(43),
        "perpCategories" => Ok(44),
        "perpConciseAnnotations" => Ok(45),
        "tokenAnnotation" => Ok(46),
        "tokenConciseAnnotations" => Ok(47),
        "settledOutcome" => Ok(48),
        "settledQuestion" => Ok(49),
        "approvedBuilders" => Ok(50),
        "gossipPriorityAuctionStatus" => Ok(51),
        "outcomeTemplates" => Ok(52),
        "aqav2InterestHistory" => Ok(53),
        "userStarState" => Ok(54),
        _ => Err(json_unknown_variant(v, VARIANTS)),
    }
}

#[inline(never)]
pub fn bridge_expecting_struct_bridge2(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct Bridge2")
}

#[inline(never)]
pub fn bridge_expecting_struct_bridgevalidatorset(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct BridgeValidatorSet")
}

#[inline(never)]
pub fn bridge_expecting_struct_etheventid(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct EthEventId")
}

#[inline(never)]
pub fn bridge_expecting_struct_pendingwithdrawals(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct PendingWithdrawals")
}

#[inline(never)]
pub fn bridge_expecting_struct_totalwithdrawal(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct TotalWithdrawal")
}

#[inline(never)]
pub fn bridge_expecting_struct_voteethdepositaction(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct VoteEthDepositAction")
}

#[inline(never)]
pub fn bridge_expecting_struct_voteethfinalizedvalidatorsetupdateaction(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct VoteEthFinalizedValidatorSetUpdateAction")
}

#[inline(never)]
pub fn bridge_expecting_struct_voteethfinalizedwithdrawalaction(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct VoteEthFinalizedWithdrawalAction")
}

#[inline(never)]
pub fn bridge_expecting_tuple_struct_bridgeepoch(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("tuple struct BridgeEpoch")
}

#[inline(never)]
pub fn bridge_expecting_tuple_struct_bridgevalidator(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("tuple struct BridgeValidator")
}

#[inline(never)]
pub fn constants_expecting_enum_chain(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("enum Chain")
}

#[inline(never)]
pub fn constants_expecting_struct_staticconfig(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct StaticConfig")
}

#[inline(never)]
pub fn evm_expecting_enum_evmblockwire(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("enum EvmBlockWire")
}

#[inline(never)]
pub fn evm_expecting_enum_readprecompileresult(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("enum ReadPrecompileResult")
}

#[inline(never)]
pub fn evm_expecting_enum_txtypewire(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("enum TxTypeWire")
}

#[inline(never)]
pub fn evm_expecting_struct_blockbodywire(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct BlockBodyWire")
}

#[inline(never)]
pub fn evm_expecting_struct_evmstate(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct EvmState")
}

#[inline(never)]
pub fn evm_expecting_struct_evmtxlookup(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct EvmTxLookup")
}

#[inline(never)]
pub fn evm_expecting_struct_evmusermodifyaction(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct EvmUserModifyAction")
}

#[inline(never)]
pub fn evm_expecting_struct_hyperevm(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct HyperEvm")
}

#[inline(never)]
pub fn evm_expecting_struct_l1toevmerc20transfer(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct L1ToEvmErc20Transfer")
}

#[inline(never)]
pub fn evm_expecting_struct_l1toevmnativetokentransfer(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct L1ToEvmNativeTokenTransfer")
}

#[inline(never)]
pub fn evm_expecting_struct_readprecompileinput(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct ReadPrecompileInput")
}

#[inline(never)]
pub fn evm_expecting_struct_receiptwire(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct ReceiptWire")
}

#[inline(never)]
pub fn evm_expecting_struct_sealedblockwire(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct SealedBlockWire")
}

#[inline(never)]
pub fn evm_expecting_struct_sendtoevmdata(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct SendToEvmData")
}

#[inline(never)]
pub fn evm_expecting_struct_sendtoevmwithdataaction(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct SendToEvmWithDataAction")
}

#[inline(never)]
pub fn evm_expecting_struct_txeip1559wire(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct TxEip1559Wire")
}

#[inline(never)]
pub fn evm_expecting_struct_txeip2930wire(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct TxEip2930Wire")
}

#[inline(never)]
pub fn evm_expecting_struct_txeip4844wire(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct TxEip4844Wire")
}

#[inline(never)]
pub fn evm_expecting_struct_txeip7702wire(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct TxEip7702Wire")
}

#[inline(never)]
pub fn evm_expecting_struct_txlegacywire(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct TxLegacyWire")
}

#[inline(never)]
pub fn evm_expecting_struct_variant_readprecompileresult_ok(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant ReadPrecompileResult::Ok")
}

#[inline(never)]
pub fn evm_rpc_expecting_struct_evmrpcconfig(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct EvmRpcConfig")
}

#[inline(never)]
pub fn evm_rpc_expecting_struct_jsonrpcerror(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct JsonRpcError")
}

#[inline(never)]
pub fn evm_rpc_expecting_struct_jsonrpcresponse(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct JsonRpcResponse")
}

#[inline(never)]
pub fn evm_rpc_expecting_struct_paramsobject(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct ParamsObject")
}

#[inline(never)]
pub fn evm_rpc_expecting_struct_variant_jsonrpcresult_error(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant JsonRpcResult::Error")
}

#[inline(never)]
pub fn evm_rpc_expecting_struct_variant_jsonrpcresult_success(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant JsonRpcResult::Success")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_activeassetdata(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::ActiveAssetData")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_approvedbuilders(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::ApprovedBuilders")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_aqav2interesthistory(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::Aqav2InterestHistory")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_bolereservestate(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::BoleReserveState")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_boleuserstate(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::BoleUserState")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_clearinghousestate(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::ClearinghouseState")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_delegations(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::Delegations")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_delegatorsummary(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::DelegatorSummary")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_extraagents(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::ExtraAgents")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_filesnapshot(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::FileSnapshot")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_frontendopenorders(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::FrontendOpenOrders")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_leadingvaults(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::LeadingVaults")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_margintable(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::MarginTable")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_maxbuilderfee(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::MaxBuilderFee")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_meta(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::Meta")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_openorders(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::OpenOrders")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_outcomedeployerlimits(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::OutcomeDeployerLimits")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_perpannotation(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::PerpAnnotation")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_perpdexlimits(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::PerpDexLimits")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_perpdexstatus(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::PerpDexStatus")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_perpsatopeninterestcap(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::PerpsAtOpenInterestCap")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_settledoutcome(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::SettledOutcome")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_settledquestion(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::SettledQuestion")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_spotclearinghousestate(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::SpotClearinghouseState")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_spotdeploystate(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::SpotDeployState")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_spotmeta(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::SpotMeta")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_subaccounts(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::SubAccounts")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_subaccounts2(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::SubAccounts2")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_tokenannotation(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::TokenAnnotation")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_userabstraction(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::UserAbstraction")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_userdexabstraction(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::UserDexAbstraction")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_userfees(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::UserFees")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_userratelimit(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::UserRateLimit")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_userrole(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::UserRole")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_userstarstate(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::UserStarState")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_usertomultisigsigners(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::UserToMultiSigSigners")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_uservaultequities(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::UserVaultEquities")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_vaultsummaries(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::VaultSummaries")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_votes(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::Votes")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_webdata2(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::WebData2")
}

#[inline(never)]
pub fn info_api_expecting_struct_variant_nodeinforequest_webdata3(_self: &(), f: &mut &mut dyn fmt::Write) -> fmt::Result {
    f.write_str("struct variant NodeInfoRequest::WebData3")
}
