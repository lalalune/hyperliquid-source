#![forbid(unsafe_code)]
#![allow(dead_code)]
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(serde::Deserialize, Debug)]
enum EnumFam0 {
    #[serde(rename = "Alo")] V0,
    #[serde(rename = "Ioc")] V1,
    #[serde(rename = "Gtc")] V2,
    #[serde(rename = "FrontendMarket")] V3,
    #[serde(rename = "LiquidationMarket")] V4,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam0 {
    #[serde(rename = "Alo")] V0 { x: u8 },
    #[serde(rename = "Ioc")] V1 { x: u8 },
    #[serde(rename = "Gtc")] V2 { x: u8 },
    #[serde(rename = "FrontendMarket")] V3 { x: u8 },
    #[serde(rename = "LiquidationMarket")] V4 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam0 {
    A { v: EnumFam0 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam1 {
    #[serde(rename = "Cross")] V0,
    #[serde(rename = "Isolated")] V1,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam1 {
    #[serde(rename = "Cross")] V0 { x: u8 },
    #[serde(rename = "Isolated")] V1 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam1 {
    A { v: EnumFam1 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam2 {
    #[serde(rename = "Deposit")] V0,
    #[serde(rename = "InvalidatedWithdrawal")] V1,
    #[serde(rename = "RequestedWithdrawal")] V2,
    #[serde(rename = "FinalizedWithdrawal")] V3,
    #[serde(rename = "FinalizedValidatorSetUpdate")] V4,
    #[serde(rename = "RequestedValidatorSetUpdateEvent")] V5,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam2 {
    #[serde(rename = "Deposit")] V0 { x: u8 },
    #[serde(rename = "InvalidatedWithdrawal")] V1 { x: u8 },
    #[serde(rename = "RequestedWithdrawal")] V2 { x: u8 },
    #[serde(rename = "FinalizedWithdrawal")] V3 { x: u8 },
    #[serde(rename = "FinalizedValidatorSetUpdate")] V4 { x: u8 },
    #[serde(rename = "RequestedValidatorSetUpdateEvent")] V5 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam2 {
    A { v: EnumFam2 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam3 {
    #[serde(rename = "Evm")] V0,
    #[serde(rename = "Broadcaster")] V1,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam3 {
    #[serde(rename = "Evm")] V0 { x: u8 },
    #[serde(rename = "Broadcaster")] V1 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam3 {
    A { v: EnumFam3 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam4 {
    #[serde(rename = "Local")] V0,
    #[serde(rename = "Sandbox")] V1,
    #[serde(rename = "Testnet")] V2,
    #[serde(rename = "Mainnet")] V3,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam4 {
    #[serde(rename = "Local")] V0 { x: u8 },
    #[serde(rename = "Sandbox")] V1 { x: u8 },
    #[serde(rename = "Testnet")] V2 { x: u8 },
    #[serde(rename = "Mainnet")] V3 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam4 {
    A { v: EnumFam4 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam5 {
    #[serde(rename = "Main")] V0,
    #[serde(rename = "Hip3")] V1,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam5 {
    #[serde(rename = "Main")] V0 { x: u8 },
    #[serde(rename = "Hip3")] V1 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam5 {
    A { v: EnumFam5 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam6 {
    #[serde(rename = "Na")] V0,
    #[serde(rename = "UserDisabled")] V1,
    #[serde(rename = "ValidatorDisabled")] V2,
    #[serde(rename = "m")] V3,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam6 {
    #[serde(rename = "Na")] V0 { x: u8 },
    #[serde(rename = "UserDisabled")] V1 { x: u8 },
    #[serde(rename = "ValidatorDisabled")] V2 { x: u8 },
    #[serde(rename = "m")] V3 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam6 {
    A { v: EnumFam6 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam7 {
    #[serde(rename = "NoEvmDb")] V0,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam7 {
    #[serde(rename = "NoEvmDb")] V0 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam7 {
    A { v: EnumFam7 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam8 {
    #[serde(rename = "Oracle")] V0,
    #[serde(rename = "ReferenceOracle")] V1,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam8 {
    #[serde(rename = "Oracle")] V0 { x: u8 },
    #[serde(rename = "ReferenceOracle")] V1 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam8 {
    A { v: EnumFam8 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam9 {
    #[serde(rename = "Perp")] V0,
    #[serde(rename = "Spot")] V1,
    #[serde(rename = "Token")] V2,
    #[serde(rename = "Pdi")] V3,
    #[serde(rename = "ActivateDexAbstraction")] V4,
    #[serde(rename = "ActivateUnifiedAccount")] V5,
    #[serde(rename = "AllBoleTokens")] V6,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam9 {
    #[serde(rename = "Perp")] V0 { x: u8 },
    #[serde(rename = "Spot")] V1 { x: u8 },
    #[serde(rename = "Token")] V2 { x: u8 },
    #[serde(rename = "Pdi")] V3 { x: u8 },
    #[serde(rename = "ActivateDexAbstraction")] V4 { x: u8 },
    #[serde(rename = "ActivateUnifiedAccount")] V5 { x: u8 },
    #[serde(rename = "AllBoleTokens")] V6 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam9 {
    A { v: EnumFam9 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam10 {
    #[serde(rename = "Q")] V0,
    #[serde(rename = "N")] V1,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam10 {
    #[serde(rename = "Q")] V0 { x: u8 },
    #[serde(rename = "N")] V1 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam10 {
    A { v: EnumFam10 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam11 {
    #[serde(rename = "Requested")] V0,
    #[serde(rename = "TradingUser")] V1,
    #[serde(rename = "StakingUser")] V2,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam11 {
    #[serde(rename = "Requested")] V0 { x: u8 },
    #[serde(rename = "TradingUser")] V1 { x: u8 },
    #[serde(rename = "StakingUser")] V2 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam11 {
    A { v: EnumFam11 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam12 {
    #[serde(rename = "Reth115")] V0,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam12 {
    #[serde(rename = "Reth115")] V0 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam12 {
    A { v: EnumFam12 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam13 {
    #[serde(rename = "Spot")] V0,
    #[serde(rename = "Mark")] V1,
    #[serde(rename = "ExternalPerp")] V2,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam13 {
    #[serde(rename = "Spot")] V0 { x: u8 },
    #[serde(rename = "Mark")] V1 { x: u8 },
    #[serde(rename = "ExternalPerp")] V2 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam13 {
    A { v: EnumFam13 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam14 {
    #[serde(rename = "StandaloneOutcome")] V0,
    #[serde(rename = "Question")] V1,
    #[serde(rename = "QuestionOutcome")] V2,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam14 {
    #[serde(rename = "StandaloneOutcome")] V0 { x: u8 },
    #[serde(rename = "Question")] V1 { x: u8 },
    #[serde(rename = "QuestionOutcome")] V2 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam14 {
    A { v: EnumFam14 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam15 {
    #[serde(rename = "accelerated")] V0,
    #[serde(rename = "constitutional")] V1,
    #[serde(rename = "ecosystem")] V2,
    #[serde(rename = "electoral")] V3,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam15 {
    #[serde(rename = "accelerated")] V0 { x: u8 },
    #[serde(rename = "constitutional")] V1 { x: u8 },
    #[serde(rename = "ecosystem")] V2 { x: u8 },
    #[serde(rename = "electoral")] V3 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam15 {
    A { v: EnumFam15 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam16 {
    #[serde(rename = "borrow")] V0,
    #[serde(rename = "supply")] V1,
    #[serde(rename = "repay")] V2,
    #[serde(rename = "withdraw")] V3,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam16 {
    #[serde(rename = "borrow")] V0 { x: u8 },
    #[serde(rename = "supply")] V1 { x: u8 },
    #[serde(rename = "repay")] V2 { x: u8 },
    #[serde(rename = "withdraw")] V3 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam16 {
    A { v: EnumFam16 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam17 {
    #[serde(rename = "create")] V0,
    #[serde(rename = "firstStorageSlot")] V1,
    #[serde(rename = "customStorageSlot")] V2,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam17 {
    #[serde(rename = "create")] V0 { x: u8 },
    #[serde(rename = "firstStorageSlot")] V1 { x: u8 },
    #[serde(rename = "customStorageSlot")] V2 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam17 {
    A { v: EnumFam17 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam18 {
    #[serde(rename = "dateTime")] V0,
    #[serde(rename = "date")] V1,
    #[serde(rename = "string")] V2,
    #[serde(rename = "shortString")] V3,
    #[serde(rename = "hlPerp")] V4,
    #[serde(rename = "uInt")] V5,
    #[serde(rename = "uDecimal")] V6,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam18 {
    #[serde(rename = "dateTime")] V0 { x: u8 },
    #[serde(rename = "date")] V1 { x: u8 },
    #[serde(rename = "string")] V2 { x: u8 },
    #[serde(rename = "shortString")] V3 { x: u8 },
    #[serde(rename = "hlPerp")] V4 { x: u8 },
    #[serde(rename = "uInt")] V5 { x: u8 },
    #[serde(rename = "uDecimal")] V6 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam18 {
    A { v: EnumFam18 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam19 {
    #[serde(rename = "disabled")] V0,
    #[serde(rename = "reduceOnly")] V1,
    #[serde(rename = "enabled")] V2,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam19 {
    #[serde(rename = "disabled")] V0 { x: u8 },
    #[serde(rename = "reduceOnly")] V1 { x: u8 },
    #[serde(rename = "enabled")] V2 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam19 {
    A { v: EnumFam19 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam20 {
    #[serde(rename = "enabled")] V0,
    #[serde(rename = "disabled")] V1,
    #[serde(rename = "blocked")] V2,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam20 {
    #[serde(rename = "enabled")] V0 { x: u8 },
    #[serde(rename = "disabled")] V1 { x: u8 },
    #[serde(rename = "blocked")] V2 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam20 {
    A { v: EnumFam20 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam21 {
    #[serde(rename = "limit")] V0,
    #[serde(rename = "trigger")] V1,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam21 {
    #[serde(rename = "limit")] V0 { x: u8 },
    #[serde(rename = "trigger")] V1 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam21 {
    A { v: EnumFam21 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam22 {
    #[serde(rename = "modifyApproval")] V0,
    #[serde(rename = "modifyBackstopLiquidatorApproval")] V1,
    #[serde(rename = "setReduceOnly")] V2,
    #[serde(rename = "cancel")] V3,
    #[serde(rename = "cancelAll")] V4,
    #[serde(rename = "order")] V5,
    #[serde(rename = "sendAsset")] V6,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam22 {
    #[serde(rename = "modifyApproval")] V0 { x: u8 },
    #[serde(rename = "modifyBackstopLiquidatorApproval")] V1 { x: u8 },
    #[serde(rename = "setReduceOnly")] V2 { x: u8 },
    #[serde(rename = "cancel")] V3 { x: u8 },
    #[serde(rename = "cancelAll")] V4 { x: u8 },
    #[serde(rename = "order")] V5 { x: u8 },
    #[serde(rename = "sendAsset")] V6 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam22 {
    A { v: EnumFam22 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam23 {
    #[serde(rename = "modifyApproval")] V0,
    #[serde(rename = "modifyBackstopLiquidatorApproval")] V1,
    #[serde(rename = "setReduceOnly")] V2,
    #[serde(rename = "cancel")] V3,
    #[serde(rename = "cancelAll")] V4,
    #[serde(rename = "order")] V5,
    #[serde(rename = "sendAsset")] V6,
    #[serde(rename = "setOracle")] V7,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam23 {
    #[serde(rename = "modifyApproval")] V0 { x: u8 },
    #[serde(rename = "modifyBackstopLiquidatorApproval")] V1 { x: u8 },
    #[serde(rename = "setReduceOnly")] V2 { x: u8 },
    #[serde(rename = "cancel")] V3 { x: u8 },
    #[serde(rename = "cancelAll")] V4 { x: u8 },
    #[serde(rename = "order")] V5 { x: u8 },
    #[serde(rename = "sendAsset")] V6 { x: u8 },
    #[serde(rename = "setOracle")] V7 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam23 {
    A { v: EnumFam23 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam24 {
    #[serde(rename = "na")] V0,
    #[serde(rename = "normalTpsl")] V1,
    #[serde(rename = "positionTpsl")] V2,
    #[serde(rename = "p")] V3,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam24 {
    #[serde(rename = "na")] V0 { x: u8 },
    #[serde(rename = "normalTpsl")] V1 { x: u8 },
    #[serde(rename = "positionTpsl")] V2 { x: u8 },
    #[serde(rename = "p")] V3 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam24 {
    A { v: EnumFam24 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam25 {
    #[serde(rename = "noop")] V0,
    #[serde(rename = "approveAgent")] V1,
    #[serde(rename = "batchModify")] V2,
    #[serde(rename = "cancel")] V3,
    #[serde(rename = "cancelByCloid")] V4,
    #[serde(rename = "claimRewards")] V5,
    #[serde(rename = "createSubAccount")] V6,
    #[serde(rename = "createVault")] V7,
    #[serde(rename = "evmRawTx")] V8,
    #[serde(rename = "ForceIncreaseEpochAction")] V9,
    #[serde(rename = "liquidate")] V10,
    #[serde(rename = "linkStakingUser")] V11,
    #[serde(rename = "modify")] V12,
    #[serde(rename = "NetChildVaultPositionsAction")] V13,
    #[serde(rename = "order")] V14,
    #[serde(rename = "registerReferrer")] V15,
    #[serde(rename = "RegisterValidatorAction")] V16,
    #[serde(rename = "CValidatorAction")] V17,
    #[serde(rename = "scheduleCancel")] V18,
    #[serde(rename = "setDisplayName")] V19,
    #[serde(rename = "VoteGlobalAction")] V20,
    #[serde(rename = "validatorL1Vote")] V21,
    #[serde(rename = "validatorL1Stream")] V22,
    #[serde(rename = "validatorL1Status")] V23,
    #[serde(rename = "validatorL1UpdateReferenceOracle")] V24,
    #[serde(rename = "SetGlobalAction")] V25,
    #[serde(rename = "setReferrer")] V26,
    #[serde(rename = "spotDeploy")] V27,
    #[serde(rename = "spotUser")] V28,
    #[serde(rename = "spotSend")] V29,
    #[serde(rename = "SignValidatorSetUpdateAction")] V30,
    #[serde(rename = "subAccountModify")] V31,
    #[serde(rename = "subAccountTransfer")] V32,
    #[serde(rename = "subAccountSpotTransfer")] V33,
    #[serde(rename = "tokenDelegate")] V34,
    #[serde(rename = "twapCancel")] V35,
    #[serde(rename = "twapOrder")] V36,
    #[serde(rename = "updateIsolatedMargin")] V37,
    #[serde(rename = "topUpIsolatedOnlyMargin")] V38,
    #[serde(rename = "updateLeverage")] V39,
    #[serde(rename = "usdSend")] V40,
    #[serde(rename = "ValidatorSignWithdrawalAction")] V41,
    #[serde(rename = "vaultDistribute")] V42,
    #[serde(rename = "vaultModify")] V43,
    #[serde(rename = "vaultTransfer")] V44,
    #[serde(rename = "VoteEthDepositAction")] V45,
    #[serde(rename = "VoteEthFinalizedValidatorSetUpdateAction")] V46,
    #[serde(rename = "VoteEthFinalizedWithdrawalAction")] V47,
    #[serde(rename = "withdraw3")] V48,
    #[serde(rename = "govPropose")] V49,
    #[serde(rename = "govVote")] V50,
    #[serde(rename = "usdClassTransfer")] V51,
    #[serde(rename = "multiSig")] V52,
    #[serde(rename = "convertToMultiSigUser")] V53,
    #[serde(rename = "approveBuilderFee")] V54,
    #[serde(rename = "startFeeTrial")] V55,
    #[serde(rename = "SystemBoleAction")] V56,
    #[serde(rename = "SystemSpotSendAction")] V57,
    #[serde(rename = "deployerSendToEvmForFrozenUser")] V58,
    #[serde(rename = "SystemUsdClassTransferAction")] V59,
    #[serde(rename = "CSignerAction")] V60,
    #[serde(rename = "cWithdraw")] V61,
    #[serde(rename = "cDeposit")] V62,
    #[serde(rename = "cUserModify")] V63,
    #[serde(rename = "reassessFees")] V64,
    #[serde(rename = "evmUserModify")] V65,
    #[serde(rename = "reserveRequestWeight")] V66,
    #[serde(rename = "finalizeEvmContract")] V67,
    #[serde(rename = "perpDeploy")] V68,
    #[serde(rename = "sendAsset")] V69,
    #[serde(rename = "SystemApproveBuilderFeeAction")] V70,
    #[serde(rename = "SystemSendAssetAction")] V71,
    #[serde(rename = "agentEnableDexAbstraction")] V72,
    #[serde(rename = "userDexAbstraction")] V73,
    #[serde(rename = "borrowLend")] V74,
    #[serde(rename = "sendToEvmWithData")] V75,
    #[serde(rename = "userPortfolioMargin")] V76,
    #[serde(rename = "userSetAbstraction")] V77,
    #[serde(rename = "agentSetAbstraction")] V78,
    #[serde(rename = "userOutcome")] V79,
    #[serde(rename = "gossipPriorityBid")] V80,
    #[serde(rename = "agentSendAsset")] V81,
    #[serde(rename = "hip3LiquidatorTransfer")] V82,
    #[serde(rename = "l1ValidatorVoteBridgeDeposit")] V83,
    #[serde(rename = "authorizeAqav2Role")] V84,
    #[serde(rename = "stakingLinkDisableTradingUser")] V85,
    #[serde(rename = "voteL1Hash")] V86,
    #[serde(rename = "voteAbciDigest")] V87,
    #[serde(rename = "activateOutcomeDeployer")] V88,
    #[serde(rename = "trailingStop")] V89,
    #[serde(rename = "outcomeDeploy")] V90,
    #[serde(rename = "cDeposit2")] V91,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam25 {
    #[serde(rename = "noop")] V0 { x: u8 },
    #[serde(rename = "approveAgent")] V1 { x: u8 },
    #[serde(rename = "batchModify")] V2 { x: u8 },
    #[serde(rename = "cancel")] V3 { x: u8 },
    #[serde(rename = "cancelByCloid")] V4 { x: u8 },
    #[serde(rename = "claimRewards")] V5 { x: u8 },
    #[serde(rename = "createSubAccount")] V6 { x: u8 },
    #[serde(rename = "createVault")] V7 { x: u8 },
    #[serde(rename = "evmRawTx")] V8 { x: u8 },
    #[serde(rename = "ForceIncreaseEpochAction")] V9 { x: u8 },
    #[serde(rename = "liquidate")] V10 { x: u8 },
    #[serde(rename = "linkStakingUser")] V11 { x: u8 },
    #[serde(rename = "modify")] V12 { x: u8 },
    #[serde(rename = "NetChildVaultPositionsAction")] V13 { x: u8 },
    #[serde(rename = "order")] V14 { x: u8 },
    #[serde(rename = "registerReferrer")] V15 { x: u8 },
    #[serde(rename = "RegisterValidatorAction")] V16 { x: u8 },
    #[serde(rename = "CValidatorAction")] V17 { x: u8 },
    #[serde(rename = "scheduleCancel")] V18 { x: u8 },
    #[serde(rename = "setDisplayName")] V19 { x: u8 },
    #[serde(rename = "VoteGlobalAction")] V20 { x: u8 },
    #[serde(rename = "validatorL1Vote")] V21 { x: u8 },
    #[serde(rename = "validatorL1Stream")] V22 { x: u8 },
    #[serde(rename = "validatorL1Status")] V23 { x: u8 },
    #[serde(rename = "validatorL1UpdateReferenceOracle")] V24 { x: u8 },
    #[serde(rename = "SetGlobalAction")] V25 { x: u8 },
    #[serde(rename = "setReferrer")] V26 { x: u8 },
    #[serde(rename = "spotDeploy")] V27 { x: u8 },
    #[serde(rename = "spotUser")] V28 { x: u8 },
    #[serde(rename = "spotSend")] V29 { x: u8 },
    #[serde(rename = "SignValidatorSetUpdateAction")] V30 { x: u8 },
    #[serde(rename = "subAccountModify")] V31 { x: u8 },
    #[serde(rename = "subAccountTransfer")] V32 { x: u8 },
    #[serde(rename = "subAccountSpotTransfer")] V33 { x: u8 },
    #[serde(rename = "tokenDelegate")] V34 { x: u8 },
    #[serde(rename = "twapCancel")] V35 { x: u8 },
    #[serde(rename = "twapOrder")] V36 { x: u8 },
    #[serde(rename = "updateIsolatedMargin")] V37 { x: u8 },
    #[serde(rename = "topUpIsolatedOnlyMargin")] V38 { x: u8 },
    #[serde(rename = "updateLeverage")] V39 { x: u8 },
    #[serde(rename = "usdSend")] V40 { x: u8 },
    #[serde(rename = "ValidatorSignWithdrawalAction")] V41 { x: u8 },
    #[serde(rename = "vaultDistribute")] V42 { x: u8 },
    #[serde(rename = "vaultModify")] V43 { x: u8 },
    #[serde(rename = "vaultTransfer")] V44 { x: u8 },
    #[serde(rename = "VoteEthDepositAction")] V45 { x: u8 },
    #[serde(rename = "VoteEthFinalizedValidatorSetUpdateAction")] V46 { x: u8 },
    #[serde(rename = "VoteEthFinalizedWithdrawalAction")] V47 { x: u8 },
    #[serde(rename = "withdraw3")] V48 { x: u8 },
    #[serde(rename = "govPropose")] V49 { x: u8 },
    #[serde(rename = "govVote")] V50 { x: u8 },
    #[serde(rename = "usdClassTransfer")] V51 { x: u8 },
    #[serde(rename = "multiSig")] V52 { x: u8 },
    #[serde(rename = "convertToMultiSigUser")] V53 { x: u8 },
    #[serde(rename = "approveBuilderFee")] V54 { x: u8 },
    #[serde(rename = "startFeeTrial")] V55 { x: u8 },
    #[serde(rename = "SystemBoleAction")] V56 { x: u8 },
    #[serde(rename = "SystemSpotSendAction")] V57 { x: u8 },
    #[serde(rename = "deployerSendToEvmForFrozenUser")] V58 { x: u8 },
    #[serde(rename = "SystemUsdClassTransferAction")] V59 { x: u8 },
    #[serde(rename = "CSignerAction")] V60 { x: u8 },
    #[serde(rename = "cWithdraw")] V61 { x: u8 },
    #[serde(rename = "cDeposit")] V62 { x: u8 },
    #[serde(rename = "cUserModify")] V63 { x: u8 },
    #[serde(rename = "reassessFees")] V64 { x: u8 },
    #[serde(rename = "evmUserModify")] V65 { x: u8 },
    #[serde(rename = "reserveRequestWeight")] V66 { x: u8 },
    #[serde(rename = "finalizeEvmContract")] V67 { x: u8 },
    #[serde(rename = "perpDeploy")] V68 { x: u8 },
    #[serde(rename = "sendAsset")] V69 { x: u8 },
    #[serde(rename = "SystemApproveBuilderFeeAction")] V70 { x: u8 },
    #[serde(rename = "SystemSendAssetAction")] V71 { x: u8 },
    #[serde(rename = "agentEnableDexAbstraction")] V72 { x: u8 },
    #[serde(rename = "userDexAbstraction")] V73 { x: u8 },
    #[serde(rename = "borrowLend")] V74 { x: u8 },
    #[serde(rename = "sendToEvmWithData")] V75 { x: u8 },
    #[serde(rename = "userPortfolioMargin")] V76 { x: u8 },
    #[serde(rename = "userSetAbstraction")] V77 { x: u8 },
    #[serde(rename = "agentSetAbstraction")] V78 { x: u8 },
    #[serde(rename = "userOutcome")] V79 { x: u8 },
    #[serde(rename = "gossipPriorityBid")] V80 { x: u8 },
    #[serde(rename = "agentSendAsset")] V81 { x: u8 },
    #[serde(rename = "hip3LiquidatorTransfer")] V82 { x: u8 },
    #[serde(rename = "l1ValidatorVoteBridgeDeposit")] V83 { x: u8 },
    #[serde(rename = "authorizeAqav2Role")] V84 { x: u8 },
    #[serde(rename = "stakingLinkDisableTradingUser")] V85 { x: u8 },
    #[serde(rename = "voteL1Hash")] V86 { x: u8 },
    #[serde(rename = "voteAbciDigest")] V87 { x: u8 },
    #[serde(rename = "activateOutcomeDeployer")] V88 { x: u8 },
    #[serde(rename = "trailingStop")] V89 { x: u8 },
    #[serde(rename = "outcomeDeploy")] V90 { x: u8 },
    #[serde(rename = "cDeposit2")] V91 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam25 {
    A { v: EnumFam25 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam26 {
    #[serde(rename = "normal")] V0,
    #[serde(rename = "child")] V1,
    #[serde(rename = "parent")] V2,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam26 {
    #[serde(rename = "normal")] V0 { x: u8 },
    #[serde(rename = "child")] V1 { x: u8 },
    #[serde(rename = "parent")] V2 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam26 {
    A { v: EnumFam26 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam27 {
    #[serde(rename = "normal")] V0,
    #[serde(rename = "noCross")] V1,
    #[serde(rename = "strictIsolated")] V2,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam27 {
    #[serde(rename = "normal")] V0 { x: u8 },
    #[serde(rename = "noCross")] V1 { x: u8 },
    #[serde(rename = "strictIsolated")] V2 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam27 {
    A { v: EnumFam27 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam28 {
    #[serde(rename = "register")] V0,
    #[serde(rename = "changeProfile")] V1,
    #[serde(rename = "unregister")] V2,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam28 {
    #[serde(rename = "register")] V0 { x: u8 },
    #[serde(rename = "changeProfile")] V1 { x: u8 },
    #[serde(rename = "unregister")] V2 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam28 {
    A { v: EnumFam28 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam29 {
    #[serde(rename = "registerAndAssociateNamedOutcomeFromTemplate")] V0,
    #[serde(rename = "registerQuestionFromTemplate")] V1,
    #[serde(rename = "registerStandaloneOutcomeFromTemplate")] V2,
    #[serde(rename = "settleOutcome")] V3,
    #[serde(rename = "settleQuestion")] V4,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam29 {
    #[serde(rename = "registerAndAssociateNamedOutcomeFromTemplate")] V0 { x: u8 },
    #[serde(rename = "registerQuestionFromTemplate")] V1 { x: u8 },
    #[serde(rename = "registerStandaloneOutcomeFromTemplate")] V2 { x: u8 },
    #[serde(rename = "settleOutcome")] V3 { x: u8 },
    #[serde(rename = "settleQuestion")] V4 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam29 {
    A { v: EnumFam29 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam30 {
    #[serde(rename = "registerAsset")] V0,
    #[serde(rename = "registerAsset2")] V1,
    #[serde(rename = "setOracle")] V2,
    #[serde(rename = "haltTrading")] V3,
    #[serde(rename = "insertMarginTable")] V4,
    #[serde(rename = "setFeeRecipient")] V5,
    #[serde(rename = "setMarginTableIds")] V6,
    #[serde(rename = "setOpenInterestCaps")] V7,
    #[serde(rename = "setFundingMultipliers")] V8,
    #[serde(rename = "setFundingInterestRates")] V9,
    #[serde(rename = "setFundingClamps")] V10,
    #[serde(rename = "setSubDeployers")] V11,
    #[serde(rename = "setMarginModes")] V12,
    #[serde(rename = "setDeployerFees")] V13,
    #[serde(rename = "disableDex")] V14,
    #[serde(rename = "setPerpAnnotation")] V15,
    #[serde(rename = "migrateDexQuoteToken")] V16,
    #[serde(rename = "star")] V17,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam30 {
    #[serde(rename = "registerAsset")] V0 { x: u8 },
    #[serde(rename = "registerAsset2")] V1 { x: u8 },
    #[serde(rename = "setOracle")] V2 { x: u8 },
    #[serde(rename = "haltTrading")] V3 { x: u8 },
    #[serde(rename = "insertMarginTable")] V4 { x: u8 },
    #[serde(rename = "setFeeRecipient")] V5 { x: u8 },
    #[serde(rename = "setMarginTableIds")] V6 { x: u8 },
    #[serde(rename = "setOpenInterestCaps")] V7 { x: u8 },
    #[serde(rename = "setFundingMultipliers")] V8 { x: u8 },
    #[serde(rename = "setFundingInterestRates")] V9 { x: u8 },
    #[serde(rename = "setFundingClamps")] V10 { x: u8 },
    #[serde(rename = "setSubDeployers")] V11 { x: u8 },
    #[serde(rename = "setMarginModes")] V12 { x: u8 },
    #[serde(rename = "setDeployerFees")] V13 { x: u8 },
    #[serde(rename = "disableDex")] V14 { x: u8 },
    #[serde(rename = "setPerpAnnotation")] V15 { x: u8 },
    #[serde(rename = "migrateDexQuoteToken")] V16 { x: u8 },
    #[serde(rename = "star")] V17 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam30 {
    A { v: EnumFam30 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam31 {
    #[serde(rename = "registerToken")] V0,
    #[serde(rename = "registerToken2")] V1,
    #[serde(rename = "userGenesis")] V2,
    #[serde(rename = "genesis")] V3,
    #[serde(rename = "registerSpot")] V4,
    #[serde(rename = "registerHyperliquidity")] V5,
    #[serde(rename = "requestEvmContract")] V6,
    #[serde(rename = "setFullName")] V7,
    #[serde(rename = "setTokenAnnotation")] V8,
    #[serde(rename = "setDeployerTradingFeeShare")] V9,
    #[serde(rename = "setDeployerLabel")] V10,
    #[serde(rename = "enableFreezePrivilege")] V11,
    #[serde(rename = "freezeUser")] V12,
    #[serde(rename = "revokeFreezePrivilege")] V13,
    #[serde(rename = "enableQuoteToken")] V14,
    #[serde(rename = "disableQuoteToken")] V15,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam31 {
    #[serde(rename = "registerToken")] V0 { x: u8 },
    #[serde(rename = "registerToken2")] V1 { x: u8 },
    #[serde(rename = "userGenesis")] V2 { x: u8 },
    #[serde(rename = "genesis")] V3 { x: u8 },
    #[serde(rename = "registerSpot")] V4 { x: u8 },
    #[serde(rename = "registerHyperliquidity")] V5 { x: u8 },
    #[serde(rename = "requestEvmContract")] V6 { x: u8 },
    #[serde(rename = "setFullName")] V7 { x: u8 },
    #[serde(rename = "setTokenAnnotation")] V8 { x: u8 },
    #[serde(rename = "setDeployerTradingFeeShare")] V9 { x: u8 },
    #[serde(rename = "setDeployerLabel")] V10 { x: u8 },
    #[serde(rename = "enableFreezePrivilege")] V11 { x: u8 },
    #[serde(rename = "freezeUser")] V12 { x: u8 },
    #[serde(rename = "revokeFreezePrivilege")] V13 { x: u8 },
    #[serde(rename = "enableQuoteToken")] V14 { x: u8 },
    #[serde(rename = "disableQuoteToken")] V15 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam31 {
    A { v: EnumFam31 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam32 {
    #[serde(rename = "registerTokensAndStandaloneOutcome")] V0,
    #[serde(rename = "registerTokensAndQuestion")] V1,
    #[serde(rename = "settleOutcome")] V2,
    #[serde(rename = "settleQuestion2")] V3,
    #[serde(rename = "changeOutcomeDescription")] V4,
    #[serde(rename = "registerAndAssociateNamedOutcome")] V5,
    #[serde(rename = "changeQuestionDescription")] V6,
    #[serde(rename = "registerTemplate")] V7,
    #[serde(rename = "registerTemplateGroup")] V8,
    #[serde(rename = "registerStandaloneOutcomeFromTemplate")] V9,
    #[serde(rename = "registerQuestionFromTemplate")] V10,
    #[serde(rename = "registerAndAssociateNamedOutcomeFromTemplate")] V11,
    #[serde(rename = "setSubDeployers")] V12,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam32 {
    #[serde(rename = "registerTokensAndStandaloneOutcome")] V0 { x: u8 },
    #[serde(rename = "registerTokensAndQuestion")] V1 { x: u8 },
    #[serde(rename = "settleOutcome")] V2 { x: u8 },
    #[serde(rename = "settleQuestion2")] V3 { x: u8 },
    #[serde(rename = "changeOutcomeDescription")] V4 { x: u8 },
    #[serde(rename = "registerAndAssociateNamedOutcome")] V5 { x: u8 },
    #[serde(rename = "changeQuestionDescription")] V6 { x: u8 },
    #[serde(rename = "registerTemplate")] V7 { x: u8 },
    #[serde(rename = "registerTemplateGroup")] V8 { x: u8 },
    #[serde(rename = "registerStandaloneOutcomeFromTemplate")] V9 { x: u8 },
    #[serde(rename = "registerQuestionFromTemplate")] V10 { x: u8 },
    #[serde(rename = "registerAndAssociateNamedOutcomeFromTemplate")] V11 { x: u8 },
    #[serde(rename = "setSubDeployers")] V12 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam32 {
    A { v: EnumFam32 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam33 {
    #[serde(rename = "splitOutcome")] V0,
    #[serde(rename = "mergeOutcome")] V1,
    #[serde(rename = "mergeQuestion")] V2,
    #[serde(rename = "negateOutcome")] V3,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam33 {
    #[serde(rename = "splitOutcome")] V0 { x: u8 },
    #[serde(rename = "mergeOutcome")] V1 { x: u8 },
    #[serde(rename = "mergeQuestion")] V2 { x: u8 },
    #[serde(rename = "negateOutcome")] V3 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam33 {
    A { v: EnumFam33 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam34 {
    #[serde(rename = "standaloneOutcome")] V0,
    #[serde(rename = "question")] V1,
    #[serde(rename = "questionOutcome")] V2,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam34 {
    #[serde(rename = "standaloneOutcome")] V0 { x: u8 },
    #[serde(rename = "question")] V1 { x: u8 },
    #[serde(rename = "questionOutcome")] V2 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam34 {
    A { v: EnumFam34 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam35 {
    #[serde(rename = "technical")] V0,
    #[serde(rename = "treasury")] V1,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam35 {
    #[serde(rename = "technical")] V0 { x: u8 },
    #[serde(rename = "treasury")] V1 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam35 {
    A { v: EnumFam35 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam36 {
    #[serde(rename = "toggleSpotDusting")] V0,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam36 {
    #[serde(rename = "toggleSpotDusting")] V0 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam36 {
    A { v: EnumFam36 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam37 {
    #[serde(rename = "tp")] V0,
    #[serde(rename = "sl")] V1,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam37 {
    #[serde(rename = "tp")] V0 { x: u8 },
    #[serde(rename = "sl")] V1 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam37 {
    A { v: EnumFam37 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam38 {
    #[serde(rename = "unjailSelf")] V0,
    #[serde(rename = "jailSelf")] V1,
    #[serde(rename = "voteJail")] V2,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam38 {
    #[serde(rename = "unjailSelf")] V0 { x: u8 },
    #[serde(rename = "jailSelf")] V1 { x: u8 },
    #[serde(rename = "voteJail")] V2 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam38 {
    A { v: EnumFam38 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam39 {
    #[serde(rename = "usdtUsdcPx")] V0,
    #[serde(rename = "nativePx")] V1,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam39 {
    #[serde(rename = "usdtUsdcPx")] V0 { x: u8 },
    #[serde(rename = "nativePx")] V1 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam39 {
    A { v: EnumFam39 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam40 {
    #[serde(rename = "yes")] V0,
    #[serde(rename = "no")] V1,
    #[serde(rename = "abstain")] V2,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam40 {
    #[serde(rename = "yes")] V0 { x: u8 },
    #[serde(rename = "no")] V1 { x: u8 },
    #[serde(rename = "abstain")] V2 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam40 {
    A { v: EnumFam40 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam41 {
    #[serde(rename = "registerAsset")] V0,
    #[serde(rename = "setOracle")] V1,
    #[serde(rename = "insertMarginTable")] V2,
    #[serde(rename = "setFeeRecipient")] V3,
    #[serde(rename = "haltTrading")] V4,
    #[serde(rename = "setMarginTableIds")] V5,
    #[serde(rename = "setOpenInterestCaps")] V6,
    #[serde(rename = "setFundingMultipliers")] V7,
    #[serde(rename = "setMarginModes")] V8,
    #[serde(rename = "setDeployerFees")] V9,
    #[serde(rename = "setFeeScale")] V10,
    #[serde(rename = "setFundingInterestRates")] V11,
    #[serde(rename = "disableDex")] V12,
    #[serde(rename = "setPerpAnnotation")] V13,
    #[serde(rename = "migrateDexQuoteToken")] V14,
    #[serde(rename = "setFundingClamps")] V15,
    #[serde(rename = "hip3Star")] V16,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam41 {
    #[serde(rename = "registerAsset")] V0 { x: u8 },
    #[serde(rename = "setOracle")] V1 { x: u8 },
    #[serde(rename = "insertMarginTable")] V2 { x: u8 },
    #[serde(rename = "setFeeRecipient")] V3 { x: u8 },
    #[serde(rename = "haltTrading")] V4 { x: u8 },
    #[serde(rename = "setMarginTableIds")] V5 { x: u8 },
    #[serde(rename = "setOpenInterestCaps")] V6 { x: u8 },
    #[serde(rename = "setFundingMultipliers")] V7 { x: u8 },
    #[serde(rename = "setMarginModes")] V8 { x: u8 },
    #[serde(rename = "setDeployerFees")] V9 { x: u8 },
    #[serde(rename = "setFeeScale")] V10 { x: u8 },
    #[serde(rename = "setFundingInterestRates")] V11 { x: u8 },
    #[serde(rename = "disableDex")] V12 { x: u8 },
    #[serde(rename = "setPerpAnnotation")] V13 { x: u8 },
    #[serde(rename = "migrateDexQuoteToken")] V14 { x: u8 },
    #[serde(rename = "setFundingClamps")] V15 { x: u8 },
    #[serde(rename = "hip3Star")] V16 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam41 {
    A { v: EnumFam41 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam42 {
    #[serde(rename = "l")] V0,
    #[serde(rename = "limit")] V1,
    #[serde(rename = "m")] V2,
    #[serde(rename = "market")] V3,
    #[serde(rename = "T")] V4,
    #[serde(rename = "takeProfitMarket")] V5,
    #[serde(rename = "t")] V6,
    #[serde(rename = "takeProfitLimit")] V7,
    #[serde(rename = "S")] V8,
    #[serde(rename = "stopMarket")] V9,
    #[serde(rename = "s")] V10,
    #[serde(rename = "stopLimit")] V11,
    #[serde(rename = "closeForVaultWithdrawal")] V12,
    #[serde(rename = "v")] V13,
    #[serde(rename = "d")] V14,
    #[serde(rename = "spotDustConversion")] V15,
    #[serde(rename = "b")] V16,
    #[serde(rename = "borrowLendLiquidation")] V17,
    #[serde(rename = "twapSlice")] V18,
    #[serde(rename = "w")] V19,
    #[serde(rename = "trailingStopMarket")] V20,
    #[serde(rename = "z")] V21,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam42 {
    #[serde(rename = "l")] V0 { x: u8 },
    #[serde(rename = "limit")] V1 { x: u8 },
    #[serde(rename = "m")] V2 { x: u8 },
    #[serde(rename = "market")] V3 { x: u8 },
    #[serde(rename = "T")] V4 { x: u8 },
    #[serde(rename = "takeProfitMarket")] V5 { x: u8 },
    #[serde(rename = "t")] V6 { x: u8 },
    #[serde(rename = "takeProfitLimit")] V7 { x: u8 },
    #[serde(rename = "S")] V8 { x: u8 },
    #[serde(rename = "stopMarket")] V9 { x: u8 },
    #[serde(rename = "s")] V10 { x: u8 },
    #[serde(rename = "stopLimit")] V11 { x: u8 },
    #[serde(rename = "closeForVaultWithdrawal")] V12 { x: u8 },
    #[serde(rename = "v")] V13 { x: u8 },
    #[serde(rename = "d")] V14 { x: u8 },
    #[serde(rename = "spotDustConversion")] V15 { x: u8 },
    #[serde(rename = "b")] V16 { x: u8 },
    #[serde(rename = "borrowLendLiquidation")] V17 { x: u8 },
    #[serde(rename = "twapSlice")] V18 { x: u8 },
    #[serde(rename = "w")] V19 { x: u8 },
    #[serde(rename = "trailingStopMarket")] V20 { x: u8 },
    #[serde(rename = "z")] V21 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam42 {
    A { v: EnumFam42 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam43 {
    #[serde(rename = "Ec")] V0,
    #[serde(rename = "DummyTokyo")] V1,
    #[serde(rename = "DummyTokyo2")] V2,
    #[serde(rename = "GaOnchain")] V3,
    #[serde(rename = "GbOnchain")] V4,
    #[serde(rename = "NodeTestnet")] V5,
    #[serde(rename = "NodeTestnet2")] V6,
    #[serde(rename = "NodeTestnet3")] V7,
    #[serde(rename = "NodeTestnet4")] V8,
    #[serde(rename = "Ea")] V9,
    #[serde(rename = "Ea2")] V10,
    #[serde(rename = "Ea3")] V11,
    #[serde(rename = "EaMm")] V12,
    #[serde(rename = "EaTx")] V13,
    #[serde(rename = "HeavyTestnet")] V14,
    #[serde(rename = "HeavyMainnet")] V15,
    #[serde(rename = "Eb")] V16,
    #[serde(rename = "Ed")] V17,
    #[serde(rename = "Ee")] V18,
    #[serde(rename = "SoloTestnet")] V19,
    #[serde(rename = "SoloMainnet")] V20,
    #[serde(rename = "LockerTestnet")] V21,
    #[serde(rename = "LockerMainnet")] V22,
    #[serde(rename = "RpcTestnet")] V23,
    #[serde(rename = "RpcSandbox")] V24,
    #[serde(rename = "RpcMainnet")] V25,
    #[serde(rename = "RpcMainnet2")] V26,
    #[serde(rename = "Sa")] V27,
    #[serde(rename = "Sb")] V28,
    #[serde(rename = "Sc")] V29,
    #[serde(rename = "Sd")] V30,
    #[serde(rename = "WebSandbox")] V31,
    #[serde(rename = "SoloSandbox")] V32,
    #[serde(rename = "NvTestnet")] V33,
    #[serde(rename = "NvTestnet2")] V34,
    #[serde(rename = "NvMainnet")] V35,
    #[serde(rename = "NvMainnet2")] V36,
    #[serde(rename = "NvMainnet3")] V37,
    #[serde(rename = "JoinMainnet")] V38,
    #[serde(rename = "DummyNv")] V39,
    #[serde(rename = "FBinSpot")] V40,
    #[serde(rename = "FBinSpot2")] V41,
    #[serde(rename = "FBinSpot3")] V42,
    #[serde(rename = "FBinSpot4")] V43,
    #[serde(rename = "FBinSpot5")] V44,
    #[serde(rename = "FBinSpot6")] V45,
    #[serde(rename = "FBinSpot7")] V46,
    #[serde(rename = "FBinSpot8")] V47,
    #[serde(rename = "FBinPerp")] V48,
    #[serde(rename = "FBinPerp2")] V49,
    #[serde(rename = "FOkexSpot")] V50,
    #[serde(rename = "FOkexSpot2")] V51,
    #[serde(rename = "FOkexPerp")] V52,
    #[serde(rename = "FHuobiSpot")] V53,
    #[serde(rename = "FHuobiSpot2")] V54,
    #[serde(rename = "FHuobiSpot3")] V55,
    #[serde(rename = "FHuobiSpot4")] V56,
    #[serde(rename = "FHuobiPi")] V57,
    #[serde(rename = "FHuobiPerp")] V58,
    #[serde(rename = "FCobSpot")] V59,
    #[serde(rename = "FKraSpot")] V60,
    #[serde(rename = "FBybitSpot")] V61,
    #[serde(rename = "ScratchDummy")] V62,
    #[serde(rename = "ScratchCron")] V63,
    #[serde(rename = "OBinSpot")] V64,
    #[serde(rename = "FHlPerp")] V65,
    #[serde(rename = "GaHlPerp")] V66,
    #[serde(rename = "GaHlPerp2")] V67,
    #[serde(rename = "GaHlPerp3")] V68,
    #[serde(rename = "GbHlPerp")] V69,
    #[serde(rename = "GbHlPerp2")] V70,
    #[serde(rename = "GbHlPerp3")] V71,
    #[serde(rename = "GcHlPerp")] V72,
    #[serde(rename = "GcHlPerp2")] V73,
    #[serde(rename = "GdHlPerp")] V74,
    #[serde(rename = "GdHlPerp2")] V75,
    #[serde(rename = "GsHlPerp")] V76,
    #[serde(rename = "EaHlPerp")] V77,
    #[serde(rename = "EbHlPerp")] V78,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam43 {
    #[serde(rename = "Ec")] V0 { x: u8 },
    #[serde(rename = "DummyTokyo")] V1 { x: u8 },
    #[serde(rename = "DummyTokyo2")] V2 { x: u8 },
    #[serde(rename = "GaOnchain")] V3 { x: u8 },
    #[serde(rename = "GbOnchain")] V4 { x: u8 },
    #[serde(rename = "NodeTestnet")] V5 { x: u8 },
    #[serde(rename = "NodeTestnet2")] V6 { x: u8 },
    #[serde(rename = "NodeTestnet3")] V7 { x: u8 },
    #[serde(rename = "NodeTestnet4")] V8 { x: u8 },
    #[serde(rename = "Ea")] V9 { x: u8 },
    #[serde(rename = "Ea2")] V10 { x: u8 },
    #[serde(rename = "Ea3")] V11 { x: u8 },
    #[serde(rename = "EaMm")] V12 { x: u8 },
    #[serde(rename = "EaTx")] V13 { x: u8 },
    #[serde(rename = "HeavyTestnet")] V14 { x: u8 },
    #[serde(rename = "HeavyMainnet")] V15 { x: u8 },
    #[serde(rename = "Eb")] V16 { x: u8 },
    #[serde(rename = "Ed")] V17 { x: u8 },
    #[serde(rename = "Ee")] V18 { x: u8 },
    #[serde(rename = "SoloTestnet")] V19 { x: u8 },
    #[serde(rename = "SoloMainnet")] V20 { x: u8 },
    #[serde(rename = "LockerTestnet")] V21 { x: u8 },
    #[serde(rename = "LockerMainnet")] V22 { x: u8 },
    #[serde(rename = "RpcTestnet")] V23 { x: u8 },
    #[serde(rename = "RpcSandbox")] V24 { x: u8 },
    #[serde(rename = "RpcMainnet")] V25 { x: u8 },
    #[serde(rename = "RpcMainnet2")] V26 { x: u8 },
    #[serde(rename = "Sa")] V27 { x: u8 },
    #[serde(rename = "Sb")] V28 { x: u8 },
    #[serde(rename = "Sc")] V29 { x: u8 },
    #[serde(rename = "Sd")] V30 { x: u8 },
    #[serde(rename = "WebSandbox")] V31 { x: u8 },
    #[serde(rename = "SoloSandbox")] V32 { x: u8 },
    #[serde(rename = "NvTestnet")] V33 { x: u8 },
    #[serde(rename = "NvTestnet2")] V34 { x: u8 },
    #[serde(rename = "NvMainnet")] V35 { x: u8 },
    #[serde(rename = "NvMainnet2")] V36 { x: u8 },
    #[serde(rename = "NvMainnet3")] V37 { x: u8 },
    #[serde(rename = "JoinMainnet")] V38 { x: u8 },
    #[serde(rename = "DummyNv")] V39 { x: u8 },
    #[serde(rename = "FBinSpot")] V40 { x: u8 },
    #[serde(rename = "FBinSpot2")] V41 { x: u8 },
    #[serde(rename = "FBinSpot3")] V42 { x: u8 },
    #[serde(rename = "FBinSpot4")] V43 { x: u8 },
    #[serde(rename = "FBinSpot5")] V44 { x: u8 },
    #[serde(rename = "FBinSpot6")] V45 { x: u8 },
    #[serde(rename = "FBinSpot7")] V46 { x: u8 },
    #[serde(rename = "FBinSpot8")] V47 { x: u8 },
    #[serde(rename = "FBinPerp")] V48 { x: u8 },
    #[serde(rename = "FBinPerp2")] V49 { x: u8 },
    #[serde(rename = "FOkexSpot")] V50 { x: u8 },
    #[serde(rename = "FOkexSpot2")] V51 { x: u8 },
    #[serde(rename = "FOkexPerp")] V52 { x: u8 },
    #[serde(rename = "FHuobiSpot")] V53 { x: u8 },
    #[serde(rename = "FHuobiSpot2")] V54 { x: u8 },
    #[serde(rename = "FHuobiSpot3")] V55 { x: u8 },
    #[serde(rename = "FHuobiSpot4")] V56 { x: u8 },
    #[serde(rename = "FHuobiPi")] V57 { x: u8 },
    #[serde(rename = "FHuobiPerp")] V58 { x: u8 },
    #[serde(rename = "FCobSpot")] V59 { x: u8 },
    #[serde(rename = "FKraSpot")] V60 { x: u8 },
    #[serde(rename = "FBybitSpot")] V61 { x: u8 },
    #[serde(rename = "ScratchDummy")] V62 { x: u8 },
    #[serde(rename = "ScratchCron")] V63 { x: u8 },
    #[serde(rename = "OBinSpot")] V64 { x: u8 },
    #[serde(rename = "FHlPerp")] V65 { x: u8 },
    #[serde(rename = "GaHlPerp")] V66 { x: u8 },
    #[serde(rename = "GaHlPerp2")] V67 { x: u8 },
    #[serde(rename = "GaHlPerp3")] V68 { x: u8 },
    #[serde(rename = "GbHlPerp")] V69 { x: u8 },
    #[serde(rename = "GbHlPerp2")] V70 { x: u8 },
    #[serde(rename = "GbHlPerp3")] V71 { x: u8 },
    #[serde(rename = "GcHlPerp")] V72 { x: u8 },
    #[serde(rename = "GcHlPerp2")] V73 { x: u8 },
    #[serde(rename = "GdHlPerp")] V74 { x: u8 },
    #[serde(rename = "GdHlPerp2")] V75 { x: u8 },
    #[serde(rename = "GsHlPerp")] V76 { x: u8 },
    #[serde(rename = "EaHlPerp")] V77 { x: u8 },
    #[serde(rename = "EbHlPerp")] V78 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam43 {
    A { v: EnumFam43 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam44 {
    #[serde(rename = "d")] V0,
    #[serde(rename = "default")] V1,
    #[serde(rename = "dexAbstraction")] V2,
    #[serde(rename = "e")] V3,
    #[serde(rename = "disabled")] V4,
    #[serde(rename = "i")] V5,
    #[serde(rename = "z")] V6,
    #[serde(rename = "u")] V7,
    #[serde(rename = "unifiedAccount")] V8,
    #[serde(rename = "p")] V9,
    #[serde(rename = "portfolioMargin")] V10,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam44 {
    #[serde(rename = "d")] V0 { x: u8 },
    #[serde(rename = "default")] V1 { x: u8 },
    #[serde(rename = "dexAbstraction")] V2 { x: u8 },
    #[serde(rename = "e")] V3 { x: u8 },
    #[serde(rename = "disabled")] V4 { x: u8 },
    #[serde(rename = "i")] V5 { x: u8 },
    #[serde(rename = "z")] V6 { x: u8 },
    #[serde(rename = "u")] V7 { x: u8 },
    #[serde(rename = "unifiedAccount")] V8 { x: u8 },
    #[serde(rename = "p")] V9 { x: u8 },
    #[serde(rename = "portfolioMargin")] V10 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam44 {
    A { v: EnumFam44 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam45 {
    #[serde(rename = "C")] V0,
    #[serde(rename = "Cross")] V1,
    #[serde(rename = "I")] V2,
    #[serde(rename = "Isolated")] V3,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam45 {
    #[serde(rename = "C")] V0 { x: u8 },
    #[serde(rename = "Cross")] V1 { x: u8 },
    #[serde(rename = "I")] V2 { x: u8 },
    #[serde(rename = "Isolated")] V3 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam45 {
    A { v: EnumFam45 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam46 {
    #[serde(rename = "activate")] V0,
    #[serde(rename = "deactivate")] V1,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam46 {
    #[serde(rename = "activate")] V0 { x: u8 },
    #[serde(rename = "deactivate")] V1 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam46 {
    A { v: EnumFam46 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam47 {
    #[serde(rename = "proxy")] V0,
    #[serde(rename = "setOracle")] V1,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam47 {
    #[serde(rename = "proxy")] V0 { x: u8 },
    #[serde(rename = "setOracle")] V1 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam47 {
    A { v: EnumFam47 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam48 {
    #[serde(rename = "hex")] V0,
    #[serde(rename = "base58")] V1,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam48 {
    #[serde(rename = "hex")] V0 { x: u8 },
    #[serde(rename = "base58")] V1 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam48 {
    A { v: EnumFam48 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam49 {
    #[serde(rename = "Enabled")] V0,
    #[serde(rename = "Disabled")] V1,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam49 {
    #[serde(rename = "Enabled")] V0 { x: u8 },
    #[serde(rename = "Disabled")] V1 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam49 {
    A { v: EnumFam49 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam50 {
    #[serde(rename = "bridge-voter")] V0,
    #[serde(rename = "reference-oracle-publisher")] V1,
    #[serde(rename = "outcome-voter")] V2,
    #[serde(rename = "visor")] V3,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam50 {
    #[serde(rename = "bridge-voter")] V0 { x: u8 },
    #[serde(rename = "reference-oracle-publisher")] V1 { x: u8 },
    #[serde(rename = "outcome-voter")] V2 { x: u8 },
    #[serde(rename = "visor")] V3 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam50 {
    A { v: EnumFam50 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam51 {
    #[serde(rename = "NodeMetadata")] V0,
    #[serde(rename = "VisorMetadata")] V1,
    #[serde(rename = "HotfixMetadata")] V2,
    #[serde(rename = "NodeArtifact")] V3,
    #[serde(rename = "PublisherBinaryMetadata")] V4,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam51 {
    #[serde(rename = "NodeMetadata")] V0 { x: u8 },
    #[serde(rename = "VisorMetadata")] V1 { x: u8 },
    #[serde(rename = "HotfixMetadata")] V2 { x: u8 },
    #[serde(rename = "NodeArtifact")] V3 { x: u8 },
    #[serde(rename = "PublisherBinaryMetadata")] V4 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "k")]
enum WrapEnumFam51 {
    A { v: EnumFam51 },
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam0 {
    #[serde(rename = "abstraction")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam0 {
    #[serde(rename = "v")] V(StructFam0),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam0 {
    #[serde(flatten)] inner: StructFam0,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam1 {
    #[serde(rename = "asset")] f0: u8,
    #[serde(rename = "cloid")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam1 {
    #[serde(rename = "v")] V(StructFam1),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam1 {
    #[serde(flatten)] inner: StructFam1,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam2 {
    #[serde(rename = "asset")] f0: u8,
    #[serde(rename = "isBuy")] f1: u8,
    #[serde(rename = "ntli")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam2 {
    #[serde(rename = "v")] V(StructFam2),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam2 {
    #[serde(flatten)] inner: StructFam2,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam3 {
    #[serde(rename = "asset")] f0: u8,
    #[serde(rename = "isBuy")] f1: u8,
    #[serde(rename = "sz")] f2: u8,
    #[serde(rename = "reduceOnly")] f3: u8,
    #[serde(rename = "retracement")] f4: u8,
    #[serde(rename = "activationPx")] f5: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam3 {
    #[serde(rename = "v")] V(StructFam3),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam3 {
    #[serde(flatten)] inner: StructFam3,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam4 {
    #[serde(rename = "asset")] f0: u8,
    #[serde(rename = "isCross")] f1: u8,
    #[serde(rename = "leverage")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam4 {
    #[serde(rename = "v")] V(StructFam4),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam4 {
    #[serde(flatten)] inner: StructFam4,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam5 {
    #[serde(rename = "asset")] f0: u8,
    #[serde(rename = "leverage")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam5 {
    #[serde(rename = "v")] V(StructFam5),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam5 {
    #[serde(flatten)] inner: StructFam5,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam6 {
    #[serde(rename = "childVaultAddresses")] f0: u8,
    #[serde(rename = "assets")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam6 {
    #[serde(rename = "v")] V(StructFam6),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam6 {
    #[serde(flatten)] inner: StructFam6,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam7 {
    #[serde(rename = "coin")] f0: u8,
    #[serde(rename = "szDecimals")] f1: u8,
    #[serde(rename = "oraclePx")] f2: u8,
    #[serde(rename = "marginTableId")] f3: u8,
    #[serde(rename = "marginMode")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam7 {
    #[serde(rename = "v")] V(StructFam7),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam7 {
    #[serde(flatten)] inner: StructFam7,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam8 {
    #[serde(rename = "coin")] f0: u8,
    #[serde(rename = "szDecimals")] f1: u8,
    #[serde(rename = "oraclePx")] f2: u8,
    #[serde(rename = "marginTableId")] f3: u8,
    #[serde(rename = "onlyIsolated")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam8 {
    #[serde(rename = "v")] V(StructFam8),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam8 {
    #[serde(flatten)] inner: StructFam8,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam9 {
    #[serde(rename = "destination")] f0: u8,
    #[serde(rename = "fromSubAccount")] f1: u8,
    #[serde(rename = "sourceDexOrSpot")] f2: u8,
    #[serde(rename = "destinationDexOrSpot")] f3: u8,
    #[serde(rename = "token")] f4: u8,
    #[serde(rename = "wei")] f5: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam9 {
    #[serde(rename = "v")] V(StructFam9),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam9 {
    #[serde(flatten)] inner: StructFam9,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam10 {
    #[serde(rename = "destination")] f0: u8,
    #[serde(rename = "sourceDex")] f1: u8,
    #[serde(rename = "destinationDex")] f2: u8,
    #[serde(rename = "token")] f3: u8,
    #[serde(rename = "amount")] f4: u8,
    #[serde(rename = "fromSubAccount")] f5: u8,
    #[serde(rename = "nonce")] f6: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam10 {
    #[serde(rename = "v")] V(StructFam10),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam10 {
    #[serde(flatten)] inner: StructFam10,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam11 {
    #[serde(rename = "destination")] f0: u8,
    #[serde(rename = "token")] f1: u8,
    #[serde(rename = "wei")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam11 {
    #[serde(rename = "v")] V(StructFam11),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam11 {
    #[serde(flatten)] inner: StructFam11,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam12 {
    #[serde(rename = "dex")] f0: u8,
    #[serde(rename = "ntl")] f1: u8,
    #[serde(rename = "isDeposit")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam12 {
    #[serde(rename = "v")] V(StructFam12),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam12 {
    #[serde(flatten)] inner: StructFam12,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam13 {
    #[serde(rename = "displayName")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam13 {
    #[serde(rename = "v")] V(StructFam13),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam13 {
    #[serde(flatten)] inner: StructFam13,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam14 {
    #[serde(rename = "frozenUser")] f0: u8,
    #[serde(rename = "token")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam14 {
    #[serde(rename = "v")] V(StructFam14),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam14 {
    #[serde(flatten)] inner: StructFam14,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam15 {
    #[serde(rename = "height")] f0: u8,
    #[serde(rename = "abciDigest")] f1: u8,
    #[serde(rename = "signature")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam15 {
    #[serde(rename = "v")] V(StructFam15),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam15 {
    #[serde(flatten)] inner: StructFam15,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam16 {
    #[serde(rename = "height")] f0: u8,
    #[serde(rename = "l1Hash")] f1: u8,
    #[serde(rename = "signature")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam16 {
    #[serde(rename = "v")] V(StructFam16),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam16 {
    #[serde(flatten)] inner: StructFam16,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam17 {
    #[serde(rename = "maxFeeRate")] f0: u8,
    #[serde(rename = "builder")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam17 {
    #[serde(rename = "v")] V(StructFam17),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam17 {
    #[serde(flatten)] inner: StructFam17,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam18 {
    #[serde(rename = "modifies")] f0: u8,
    #[serde(rename = "a")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam18 {
    #[serde(rename = "v")] V(StructFam18),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam18 {
    #[serde(flatten)] inner: StructFam18,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam19 {
    #[serde(rename = "multiSigUser")] f0: u8,
    #[serde(rename = "outerSigner")] f1: u8,
    #[serde(rename = "action")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam19 {
    #[serde(rename = "v")] V(StructFam19),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam19 {
    #[serde(flatten)] inner: StructFam19,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam20 {
    #[serde(rename = "name")] f0: u8,
    #[serde(rename = "description")] f1: u8,
    #[serde(rename = "initialUsd")] f2: u8,
    #[serde(rename = "nonce")] f3: u8,
    #[serde(rename = "maxUsdcFee")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam20 {
    #[serde(rename = "v")] V(StructFam20),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam20 {
    #[serde(flatten)] inner: StructFam20,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam21 {
    #[serde(rename = "node_ip")] f0: u8,
    #[serde(rename = "name")] f1: u8,
    #[serde(rename = "description")] f2: u8,
    #[serde(rename = "unjailed")] f3: u8,
    #[serde(rename = "disable_delegations")] f4: u8,
    #[serde(rename = "commission_bps")] f5: u8,
    #[serde(rename = "signer")] f6: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam21 {
    #[serde(rename = "v")] V(StructFam21),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam21 {
    #[serde(flatten)] inner: StructFam21,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam22 {
    #[serde(rename = "ntl")] f0: u8,
    #[serde(rename = "toPerp")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam22 {
    #[serde(rename = "v")] V(StructFam22),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam22 {
    #[serde(flatten)] inner: StructFam22,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam23 {
    #[serde(rename = "oid")] f0: u8,
    #[serde(rename = "order")] f1: u8,
    #[serde(rename = "a")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam23 {
    #[serde(rename = "v")] V(StructFam23),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam23 {
    #[serde(flatten)] inner: StructFam23,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam24 {
    #[serde(rename = "operation")] f0: u8,
    #[serde(rename = "token")] f1: u8,
    #[serde(rename = "amount")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam24 {
    #[serde(rename = "v")] V(StructFam24),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam24 {
    #[serde(flatten)] inner: StructFam24,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam25 {
    #[serde(rename = "operation")] f0: u8,
    #[serde(rename = "token")] f1: u8,
    #[serde(rename = "wei")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam25 {
    #[serde(rename = "v")] V(StructFam25),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam25 {
    #[serde(flatten)] inner: StructFam25,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam26 {
    #[serde(rename = "optOut")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam26 {
    #[serde(rename = "v")] V(StructFam26),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam26 {
    #[serde(flatten)] inner: StructFam26,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam27 {
    #[serde(rename = "oraclePxs")] f0: u8,
    #[serde(rename = "externalPerpPxs")] f1: u8,
    #[serde(rename = "scalarUpdates")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam27 {
    #[serde(rename = "v")] V(StructFam27),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam27 {
    #[serde(flatten)] inner: StructFam27,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam28 {
    #[serde(rename = "orders")] f0: u8,
    #[serde(rename = "grouping")] f1: u8,
    #[serde(rename = "builder")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam28 {
    #[serde(rename = "v")] V(StructFam28),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam28 {
    #[serde(flatten)] inner: StructFam28,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam29 {
    #[serde(rename = "perpAddBaseRate")] f0: u8,
    #[serde(rename = "perpCrossBaseRate")] f1: u8,
    #[serde(rename = "spotAddBaseRate")] f2: u8,
    #[serde(rename = "spotCrossBaseRate")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam29 {
    #[serde(rename = "v")] V(StructFam29),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam29 {
    #[serde(flatten)] inner: StructFam29,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam30 {
    #[serde(rename = "pmdl")] f0: u8,
    #[serde(rename = "pmln")] f1: u8,
    #[serde(rename = "pmbm")] f2: u8,
    #[serde(rename = "ubgln")] f3: u8,
    #[serde(rename = "ubglm")] f4: u8,
    #[serde(rename = "ubuln")] f5: u8,
    #[serde(rename = "ubulm")] f6: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam30 {
    #[serde(rename = "v")] V(StructFam30),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam30 {
    #[serde(flatten)] inner: StructFam30,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam31 {
    #[serde(rename = "profile")] f0: u8,
    #[serde(rename = "unjailed")] f1: u8,
    #[serde(rename = "initial_wei")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam31 {
    #[serde(rename = "v")] V(StructFam31),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam31 {
    #[serde(flatten)] inner: StructFam31,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam32 {
    #[serde(rename = "pxs")] f0: u8,
    #[serde(rename = "externalPerpPxs")] f1: u8,
    #[serde(rename = "usdtUsdcPx")] f2: u8,
    #[serde(rename = "nativePx")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam32 {
    #[serde(rename = "v")] V(StructFam32),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam32 {
    #[serde(flatten)] inner: StructFam32,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam33 {
    #[serde(rename = "rates")] f0: u8,
    #[serde(rename = "tiers")] f1: u8,
    #[serde(rename = "referralDiscount")] f2: u8,
    #[serde(rename = "referrerKeep")] f3: u8,
    #[serde(rename = "destination")] f4: u8,
    #[serde(rename = "extraDestinationFractions")] f5: u8,
    #[serde(rename = "stakeDiscountTiers")] f6: u8,
    #[serde(rename = "weighSpotVolumeDouble")] f7: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam33 {
    #[serde(rename = "v")] V(StructFam33),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam33 {
    #[serde(flatten)] inner: StructFam33,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam34 {
    #[serde(rename = "riskFreeRate")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam34 {
    #[serde(rename = "v")] V(StructFam34),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam34 {
    #[serde(flatten)] inner: StructFam34,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam35 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "agentAddress")] f2: u8,
    #[serde(rename = "agentName")] f3: u8,
    #[serde(rename = "nonce")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam35 {
    #[serde(rename = "v")] V(StructFam35),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam35 {
    #[serde(flatten)] inner: StructFam35,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam36 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "amount")] f2: u8,
    #[serde(rename = "toPerp")] f3: u8,
    #[serde(rename = "nonce")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam36 {
    #[serde(rename = "v")] V(StructFam36),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam36 {
    #[serde(flatten)] inner: StructFam36,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam37 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "destination")] f2: u8,
    #[serde(rename = "amount")] f3: u8,
    #[serde(rename = "time")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam37 {
    #[serde(rename = "v")] V(StructFam37),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam37 {
    #[serde(flatten)] inner: StructFam37,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam38 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "destination")] f2: u8,
    #[serde(rename = "sourceDex")] f3: u8,
    #[serde(rename = "destinationDex")] f4: u8,
    #[serde(rename = "token")] f5: u8,
    #[serde(rename = "amount")] f6: u8,
    #[serde(rename = "fromSubAccount")] f7: u8,
    #[serde(rename = "nonce")] f8: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam38 {
    #[serde(rename = "v")] V(StructFam38),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam38 {
    #[serde(flatten)] inner: StructFam38,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam39 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "destination")] f2: u8,
    #[serde(rename = "token")] f3: u8,
    #[serde(rename = "amount")] f4: u8,
    #[serde(rename = "time")] f5: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam39 {
    #[serde(rename = "v")] V(StructFam39),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam39 {
    #[serde(flatten)] inner: StructFam39,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam40 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "extendLongTermStaking")] f2: u8,
    #[serde(rename = "nonce")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam40 {
    #[serde(rename = "v")] V(StructFam40),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam40 {
    #[serde(flatten)] inner: StructFam40,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam41 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "id")] f2: u8,
    #[serde(rename = "choice")] f3: u8,
    #[serde(rename = "nonce")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam41 {
    #[serde(rename = "v")] V(StructFam41),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam41 {
    #[serde(flatten)] inner: StructFam41,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam42 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "maxFeeRate")] f2: u8,
    #[serde(rename = "builder")] f3: u8,
    #[serde(rename = "nonce")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam42 {
    #[serde(rename = "v")] V(StructFam42),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam42 {
    #[serde(flatten)] inner: StructFam42,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam43 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "signers")] f2: u8,
    #[serde(rename = "nonce")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam43 {
    #[serde(rename = "v")] V(StructFam43),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam43 {
    #[serde(flatten)] inner: StructFam43,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam44 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "title")] f2: u8,
    #[serde(rename = "description")] f3: u8,
    #[serde(rename = "category")] f4: u8,
    #[serde(rename = "nonce")] f5: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam44 {
    #[serde(rename = "v")] V(StructFam44),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam44 {
    #[serde(flatten)] inner: StructFam44,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam45 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "token")] f2: u8,
    #[serde(rename = "amount")] f3: u8,
    #[serde(rename = "sourceDex")] f4: u8,
    #[serde(rename = "destinationRecipient")] f5: u8,
    #[serde(rename = "addressEncoding")] f6: u8,
    #[serde(rename = "destinationChainId")] f7: u8,
    #[serde(rename = "gasLimit")] f8: u8,
    #[serde(rename = "data")] f9: u8,
    #[serde(rename = "nonce")] f10: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam45 {
    #[serde(rename = "v")] V(StructFam45),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam45 {
    #[serde(flatten)] inner: StructFam45,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam46 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "tradingUser")] f2: u8,
    #[serde(rename = "nonce")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam46 {
    #[serde(rename = "v")] V(StructFam46),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam46 {
    #[serde(flatten)] inner: StructFam46,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam47 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "user")] f2: u8,
    #[serde(rename = "abstraction")] f3: u8,
    #[serde(rename = "nonce")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam47 {
    #[serde(rename = "v")] V(StructFam47),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam47 {
    #[serde(flatten)] inner: StructFam47,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam48 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "user")] f2: u8,
    #[serde(rename = "enabled")] f3: u8,
    #[serde(rename = "nonce")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam48 {
    #[serde(rename = "v")] V(StructFam48),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam48 {
    #[serde(flatten)] inner: StructFam48,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam49 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "user")] f2: u8,
    #[serde(rename = "isFinalize")] f3: u8,
    #[serde(rename = "nonce")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam49 {
    #[serde(rename = "v")] V(StructFam49),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam49 {
    #[serde(flatten)] inner: StructFam49,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam50 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "validator")] f2: u8,
    #[serde(rename = "wei")] f3: u8,
    #[serde(rename = "isUndelegate")] f4: u8,
    #[serde(rename = "nonce")] f5: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam50 {
    #[serde(rename = "v")] V(StructFam50),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam50 {
    #[serde(flatten)] inner: StructFam50,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam51 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "wei")] f2: u8,
    #[serde(rename = "nonce")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam51 {
    #[serde(rename = "v")] V(StructFam51),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam51 {
    #[serde(flatten)] inner: StructFam51,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam52 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "signatures")] f1: u8,
    #[serde(rename = "payload")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam52 {
    #[serde(rename = "v")] V(StructFam52),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam52 {
    #[serde(flatten)] inner: StructFam52,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam53 {
    #[serde(rename = "signer")] f0: u8,
    #[serde(rename = "jail_until")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam53 {
    #[serde(rename = "v")] V(StructFam53),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam53 {
    #[serde(flatten)] inner: StructFam53,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam54 {
    #[serde(rename = "slotId")] f0: u8,
    #[serde(rename = "ip")] f1: u8,
    #[serde(rename = "maxGas")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam54 {
    #[serde(rename = "v")] V(StructFam54),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam54 {
    #[serde(flatten)] inner: StructFam54,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam55 {
    #[serde(rename = "subAccountUser")] f0: u8,
    #[serde(rename = "isDeposit")] f1: u8,
    #[serde(rename = "token")] f2: u8,
    #[serde(rename = "amount")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam55 {
    #[serde(rename = "v")] V(StructFam55),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam55 {
    #[serde(flatten)] inner: StructFam55,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam56 {
    #[serde(rename = "subAccountUser")] f0: u8,
    #[serde(rename = "isDeposit")] f1: u8,
    #[serde(rename = "usd")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam56 {
    #[serde(rename = "v")] V(StructFam56),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam56 {
    #[serde(flatten)] inner: StructFam56,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam57 {
    #[serde(rename = "subAccountUser")] f0: u8,
    #[serde(rename = "name")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam57 {
    #[serde(rename = "v")] V(StructFam57),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam57 {
    #[serde(flatten)] inner: StructFam57,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam58 {
    #[serde(rename = "token")] f0: u8,
    #[serde(rename = "role")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam58 {
    #[serde(rename = "v")] V(StructFam58),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam58 {
    #[serde(flatten)] inner: StructFam58,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam59 {
    #[serde(rename = "token")] f0: u8,
    #[serde(rename = "technicalStaker")] f1: u8,
    #[serde(rename = "treasuryStaker")] f2: u8,
    #[serde(rename = "treasuryEvmAddress")] f3: u8,
    #[serde(rename = "evmRebalanceContract")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam59 {
    #[serde(rename = "v")] V(StructFam59),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam59 {
    #[serde(flatten)] inner: StructFam59,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam60 {
    #[serde(rename = "twap")] f0: u8,
    #[serde(rename = "details")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam60 {
    #[serde(rename = "v")] V(StructFam60),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam60 {
    #[serde(flatten)] inner: StructFam60,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam61 {
    #[serde(rename = "user")] f0: u8,
    #[serde(rename = "defaultLiquidator")] f1: u8,
    #[serde(rename = "request")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam61 {
    #[serde(rename = "v")] V(StructFam61),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam61 {
    #[serde(flatten)] inner: StructFam61,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam62 {
    #[serde(rename = "user")] f0: u8,
    #[serde(rename = "destination")] f1: u8,
    #[serde(rename = "nonce")] f2: u8,
    #[serde(rename = "usd")] f3: u8,
    #[serde(rename = "ethTxHash")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam62 {
    #[serde(rename = "v")] V(StructFam62),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam62 {
    #[serde(flatten)] inner: StructFam62,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam63 {
    #[serde(rename = "user")] f0: u8,
    #[serde(rename = "destination")] f1: u8,
    #[serde(rename = "usd")] f2: u8,
    #[serde(rename = "nonce")] f3: u8,
    #[serde(rename = "signature")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam63 {
    #[serde(rename = "v")] V(StructFam63),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam63 {
    #[serde(flatten)] inner: StructFam63,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam64 {
    #[serde(rename = "user")] f0: u8,
    #[serde(rename = "usd")] f1: u8,
    #[serde(rename = "ethId")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam64 {
    #[serde(rename = "v")] V(StructFam64),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam64 {
    #[serde(flatten)] inner: StructFam64,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam65 {
    #[serde(rename = "usingBigBlocks")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam65 {
    #[serde(rename = "v")] V(StructFam65),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam65 {
    #[serde(flatten)] inner: StructFam65,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam66 {
    #[serde(rename = "validator")] f0: u8,
    #[serde(rename = "signature")] f1: u8,
    #[serde(rename = "coldUser")] f2: u8,
    #[serde(rename = "coldUserSignature")] f3: u8,
    #[serde(rename = "nonce")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam66 {
    #[serde(rename = "v")] V(StructFam66),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam66 {
    #[serde(flatten)] inner: StructFam66,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam67 {
    #[serde(rename = "validatorSet")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam67 {
    #[serde(rename = "v")] V(StructFam67),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam67 {
    #[serde(flatten)] inner: StructFam67,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam68 {
    #[serde(rename = "validatorSet")] f0: u8,
    #[serde(rename = "signature")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam68 {
    #[serde(rename = "v")] V(StructFam68),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam68 {
    #[serde(flatten)] inner: StructFam68,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam69 {
    #[serde(rename = "validatorsAndSignatures")] f0: u8,
    #[serde(rename = "newActiveEpoch")] f1: u8,
    #[serde(rename = "nonce")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam69 {
    #[serde(rename = "v")] V(StructFam69),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam69 {
    #[serde(flatten)] inner: StructFam69,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam70 {
    #[serde(rename = "vaultAddress")] f0: u8,
    #[serde(rename = "allowDeposits")] f1: u8,
    #[serde(rename = "alwaysCloseOnWithdraw")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam70 {
    #[serde(rename = "v")] V(StructFam70),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam70 {
    #[serde(flatten)] inner: StructFam70,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam71 {
    #[serde(rename = "vaultAddress")] f0: u8,
    #[serde(rename = "isDeposit")] f1: u8,
    #[serde(rename = "usd")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam71 {
    #[serde(rename = "v")] V(StructFam71),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam71 {
    #[serde(flatten)] inner: StructFam71,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam72 {
    #[serde(rename = "vaultAddress")] f0: u8,
    #[serde(rename = "usd")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam72 {
    #[serde(rename = "v")] V(StructFam72),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam72 {
    #[serde(flatten)] inner: StructFam72,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam73 {
    #[serde(rename = "venueName")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam73 {
    #[serde(rename = "v")] V(StructFam73),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam73 {
    #[serde(flatten)] inner: StructFam73,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam74 {
    #[serde(rename = "weight")] f0: u8,
    #[serde(rename = "destination")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam74 {
    #[serde(rename = "v")] V(StructFam74),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam74 {
    #[serde(flatten)] inner: StructFam74,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam75 {
    #[serde(rename = "cancels")] f0: u8,
    #[serde(rename = "f")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam75 {
    #[serde(rename = "v")] V(StructFam75),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam75 {
    #[serde(flatten)] inner: StructFam75,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam76 {
    #[serde(rename = "a")] f0: u8,
    #[serde(rename = "asset")] f1: u8,
    #[serde(rename = "t")] f2: u8,
    #[serde(rename = "twapId")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam76 {
    #[serde(rename = "v")] V(StructFam76),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam76 {
    #[serde(flatten)] inner: StructFam76,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam77 {
    #[serde(rename = "a")] f0: u8,
    #[serde(rename = "asset")] f1: u8,
    #[serde(rename = "o")] f2: u8,
    #[serde(rename = "oid")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam77 {
    #[serde(rename = "v")] V(StructFam77),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam77 {
    #[serde(flatten)] inner: StructFam77,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam78 {
    #[serde(rename = "a")] f0: u8,
    #[serde(rename = "asset")] f1: u8,
    #[serde(rename = "b")] f2: u8,
    #[serde(rename = "isBuy")] f3: u8,
    #[serde(rename = "s")] f4: u8,
    #[serde(rename = "sz")] f5: u8,
    #[serde(rename = "r")] f6: u8,
    #[serde(rename = "reduceOnly")] f7: u8,
    #[serde(rename = "m")] f8: u8,
    #[serde(rename = "minutes")] f9: u8,
    #[serde(rename = "randomize")] f10: u8,
    #[serde(rename = "t")] f11: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam78 {
    #[serde(rename = "v")] V(StructFam78),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam78 {
    #[serde(flatten)] inner: StructFam78,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam79 {
    #[serde(rename = "a")] f0: u8,
    #[serde(rename = "asset")] f1: u8,
    #[serde(rename = "b")] f2: u8,
    #[serde(rename = "isBuy")] f3: u8,
    #[serde(rename = "limitPx")] f4: u8,
    #[serde(rename = "p")] f5: u8,
    #[serde(rename = "s")] f6: u8,
    #[serde(rename = "sz")] f7: u8,
    #[serde(rename = "r")] f8: u8,
    #[serde(rename = "reduceOnly")] f9: u8,
    #[serde(rename = "orderType")] f10: u8,
    #[serde(rename = "t")] f11: u8,
    #[serde(rename = "c")] f12: u8,
    #[serde(rename = "cloid")] f13: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam79 {
    #[serde(rename = "v")] V(StructFam79),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam79 {
    #[serde(flatten)] inner: StructFam79,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam80 {
    #[serde(rename = "c")] f0: u8,
    #[serde(rename = "core")] f1: u8,
    #[serde(rename = "t")] f2: u8,
    #[serde(rename = "trigger")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam80 {
    #[serde(rename = "v")] V(StructFam80),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam80 {
    #[serde(flatten)] inner: StructFam80,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam81 {
    #[serde(rename = "p")] f0: u8,
    #[serde(rename = "prev_key")] f1: u8,
    #[serde(rename = "n")] f2: u8,
    #[serde(rename = "next_key")] f3: u8,
    #[serde(rename = "i")] f4: u8,
    #[serde(rename = "is_position_tpsl")] f5: u8,
    #[serde(rename = "r")] f6: u8,
    #[serde(rename = "resting_sz")] f7: u8,
    #[serde(rename = "O")] f8: u8,
    #[serde(rename = "orig_sz")] f9: u8,
    #[serde(rename = "P")] f10: u8,
    #[serde(rename = "priority_rate")] f11: u8,
    #[serde(rename = "u")] f12: u8,
    #[serde(rename = "user")] f13: u8,
    #[serde(rename = "t")] f14: u8,
    #[serde(rename = "tif")] f15: u8,
    #[serde(rename = "c")] f16: u8,
    #[serde(rename = "core")] f17: u8,
    #[serde(rename = "o")] f18: u8,
    #[serde(rename = "oid")] f19: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam81 {
    #[serde(rename = "v")] V(StructFam81),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam81 {
    #[serde(flatten)] inner: StructFam81,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam82 {
    #[serde(rename = "halfs")] f0: u8,
    #[serde(rename = "oid_to_key")] f1: u8,
    #[serde(rename = "cloid_tracker")] f2: u8,
    #[serde(rename = "bod")] f3: u8,
    #[serde(rename = "asset")] f4: u8,
    #[serde(rename = "user_states")] f5: u8,
    #[serde(rename = "last_trade_px")] f6: u8,
    #[serde(rename = "total_sz")] f7: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam82 {
    #[serde(rename = "v")] V(StructFam82),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam82 {
    #[serde(flatten)] inner: StructFam82,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam83 {
    #[serde(rename = "order_sz")] f0: u8,
    #[serde(rename = "points")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam83 {
    #[serde(rename = "v")] V(StructFam83),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam83 {
    #[serde(flatten)] inner: StructFam83,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam84 {
    #[serde(rename = "outcome")] f0: u8,
    #[serde(rename = "description")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam84 {
    #[serde(rename = "v")] V(StructFam84),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam84 {
    #[serde(flatten)] inner: StructFam84,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam85 {
    #[serde(rename = "question")] f0: u8,
    #[serde(rename = "args")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam85 {
    #[serde(rename = "v")] V(StructFam85),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam85 {
    #[serde(flatten)] inner: StructFam85,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam86 {
    #[serde(rename = "question")] f0: u8,
    #[serde(rename = "description")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam86 {
    #[serde(rename = "v")] V(StructFam86),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam86 {
    #[serde(flatten)] inner: StructFam86,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam87 {
    #[serde(rename = "questionTemplateInstance")] f0: u8,
    #[serde(rename = "namedOutcomeTemplateInstances")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam87 {
    #[serde(rename = "v")] V(StructFam87),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam87 {
    #[serde(flatten)] inner: StructFam87,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam88 {
    #[serde(rename = "question")] f0: u8,
    #[serde(rename = "namedOutcomeTemplateInstance")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam88 {
    #[serde(rename = "v")] V(StructFam88),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam88 {
    #[serde(flatten)] inner: StructFam88,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam89 {
    #[serde(rename = "mti")] f0: u8,
    #[serde(rename = "mdo")] f1: u8,
    #[serde(rename = "mdod")] f2: u8,
    #[serde(rename = "mnd")] f3: u8,
    #[serde(rename = "mao")] f4: u8,
    #[serde(rename = "mnao")] f5: u8,
    #[serde(rename = "mnaq")] f6: u8,
    #[serde(rename = "den")] f7: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam89 {
    #[serde(rename = "v")] V(StructFam89),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam89 {
    #[serde(flatten)] inner: StructFam89,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam90 {
    #[serde(rename = "token")] f0: u8,
    #[serde(rename = "input")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam90 {
    #[serde(rename = "v")] V(StructFam90),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam90 {
    #[serde(flatten)] inner: StructFam90,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam91 {
    #[serde(rename = "id")] f0: u8,
    #[serde(rename = "role")] f1: u8,
    #[serde(rename = "nameAndDescription")] f2: u8,
    #[serde(rename = "keywordToHint")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam91 {
    #[serde(rename = "v")] V(StructFam91),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam91 {
    #[serde(flatten)] inner: StructFam91,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam92 {
    #[serde(rename = "outcome")] f0: u8,
    #[serde(rename = "settleFraction")] f1: u8,
    #[serde(rename = "details")] f2: u8,
    #[serde(rename = "nameAndDescription")] f3: u8,
    #[serde(rename = "sideNames")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam92 {
    #[serde(rename = "v")] V(StructFam92),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam92 {
    #[serde(flatten)] inner: StructFam92,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam93 {
    #[serde(rename = "question")] f0: u8,
    #[serde(rename = "outcomeSettlements")] f1: u8,
    #[serde(rename = "nameAndDescription")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam93 {
    #[serde(rename = "v")] V(StructFam93),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam93 {
    #[serde(flatten)] inner: StructFam93,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam94 {
    #[serde(rename = "questionTemplate")] f0: u8,
    #[serde(rename = "namedOutcomeTemplates")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam94 {
    #[serde(rename = "v")] V(StructFam94),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam94 {
    #[serde(flatten)] inner: StructFam94,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam95 {
    #[serde(rename = "id")] f0: u8,
    #[serde(rename = "keywordToValue")] f1: u8,
    #[serde(rename = "deployerFeeScale")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam95 {
    #[serde(rename = "v")] V(StructFam95),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam95 {
    #[serde(flatten)] inner: StructFam95,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam96 {
    #[serde(rename = "quoteToken")] f0: u8,
    #[serde(rename = "nameAndDescription")] f1: u8,
    #[serde(rename = "sideNames")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam96 {
    #[serde(rename = "v")] V(StructFam96),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam96 {
    #[serde(flatten)] inner: StructFam96,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam97 {
    #[serde(rename = "quoteToken")] f0: u8,
    #[serde(rename = "questionNameAndDescription")] f1: u8,
    #[serde(rename = "fallbackNameAndDescription")] f2: u8,
    #[serde(rename = "namedOutcomes")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam97 {
    #[serde(rename = "v")] V(StructFam97),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam97 {
    #[serde(flatten)] inner: StructFam97,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam98 {
    #[serde(rename = "id")] f0: u8,
    #[serde(rename = "keywordToValue")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam98 {
    #[serde(rename = "v")] V(StructFam98),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam98 {
    #[serde(flatten)] inner: StructFam98,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam99 {
    #[serde(rename = "outcome")] f0: u8,
    #[serde(rename = "amount")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam99 {
    #[serde(rename = "v")] V(StructFam99),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam99 {
    #[serde(flatten)] inner: StructFam99,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam100 {
    #[serde(rename = "question")] f0: u8,
    #[serde(rename = "amount")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam100 {
    #[serde(rename = "v")] V(StructFam100),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam100 {
    #[serde(flatten)] inner: StructFam100,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam101 {
    #[serde(rename = "question")] f0: u8,
    #[serde(rename = "outcome")] f1: u8,
    #[serde(rename = "amount")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam101 {
    #[serde(rename = "v")] V(StructFam101),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam101 {
    #[serde(flatten)] inner: StructFam101,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam102 {
    #[serde(rename = "maxGas")] f0: u8,
    #[serde(rename = "assetRequest")] f1: u8,
    #[serde(rename = "dex")] f2: u8,
    #[serde(rename = "schema")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam102 {
    #[serde(rename = "v")] V(StructFam102),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam102 {
    #[serde(flatten)] inner: StructFam102,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam103 {
    #[serde(rename = "dex")] f0: u8,
    #[serde(rename = "oraclePxs")] f1: u8,
    #[serde(rename = "markPxs")] f2: u8,
    #[serde(rename = "externalPerpPxs")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam103 {
    #[serde(rename = "v")] V(StructFam103),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam103 {
    #[serde(flatten)] inner: StructFam103,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam104 {
    #[serde(rename = "coin")] f0: u8,
    #[serde(rename = "isHalted")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam104 {
    #[serde(rename = "v")] V(StructFam104),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam104 {
    #[serde(flatten)] inner: StructFam104,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam105 {
    #[serde(rename = "dex")] f0: u8,
    #[serde(rename = "marginTable")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam105 {
    #[serde(rename = "v")] V(StructFam105),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam105 {
    #[serde(flatten)] inner: StructFam105,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam106 {
    #[serde(rename = "dex")] f0: u8,
    #[serde(rename = "feeRecipient")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam106 {
    #[serde(rename = "v")] V(StructFam106),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam106 {
    #[serde(flatten)] inner: StructFam106,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam107 {
    #[serde(rename = "dex")] f0: u8,
    #[serde(rename = "subDeployers")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam107 {
    #[serde(rename = "v")] V(StructFam107),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam107 {
    #[serde(flatten)] inner: StructFam107,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam108 {
    #[serde(rename = "coin")] f0: u8,
    #[serde(rename = "category")] f1: u8,
    #[serde(rename = "description")] f2: u8,
    #[serde(rename = "displayName")] f3: u8,
    #[serde(rename = "keywords")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam108 {
    #[serde(rename = "v")] V(StructFam108),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam108 {
    #[serde(flatten)] inner: StructFam108,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam109 {
    #[serde(rename = "dex")] f0: u8,
    #[serde(rename = "newDex")] f1: u8,
    #[serde(rename = "schema")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam109 {
    #[serde(rename = "v")] V(StructFam109),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam109 {
    #[serde(flatten)] inner: StructFam109,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam110 {
    #[serde(rename = "dex")] f0: u8,
    #[serde(rename = "operation")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam110 {
    #[serde(rename = "v")] V(StructFam110),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam110 {
    #[serde(flatten)] inner: StructFam110,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam111 {
    #[serde(rename = "limits")] f0: u8,
    #[serde(rename = "schema")] f1: u8,
    #[serde(rename = "state")] f2: u8,
    #[serde(rename = "hip3_backstop_liquidator_state")] f3: u8,
    #[serde(rename = "ss")] f4: u8,
    #[serde(rename = "df")] f5: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam111 {
    #[serde(rename = "v")] V(StructFam111),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam111 {
    #[serde(flatten)] inner: StructFam111,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam112 {
    #[serde(rename = "books")] f0: u8,
    #[serde(rename = "funding_tracker")] f1: u8,
    #[serde(rename = "twap_tracker")] f2: u8,
    #[serde(rename = "perp_to_annotation")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam112 {
    #[serde(rename = "v")] V(StructFam112),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam112 {
    #[serde(flatten)] inner: StructFam112,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam113 {
    #[serde(rename = "l")] f0: u8,
    #[serde(rename = "last_update_time")] f1: u8,
    #[serde(rename = "c")] f2: u8,
    #[serde(rename = "category")] f3: u8,
    #[serde(rename = "d")] f4: u8,
    #[serde(rename = "description")] f5: u8,
    #[serde(rename = "display_name")] f6: u8,
    #[serde(rename = "n")] f7: u8,
    #[serde(rename = "k")] f8: u8,
    #[serde(rename = "keywords")] f9: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam113 {
    #[serde(rename = "v")] V(StructFam113),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam113 {
    #[serde(flatten)] inner: StructFam113,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam114 {
    #[serde(rename = "destination")] f0: u8,
    #[serde(rename = "amount")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam114 {
    #[serde(rename = "v")] V(StructFam114),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam114 {
    #[serde(flatten)] inner: StructFam114,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam115 {
    #[serde(rename = "periodic_abci_states")] f0: u8,
    #[serde(rename = "periodic_abci_state_statuses")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam115 {
    #[serde(rename = "v")] V(StructFam115),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam115 {
    #[serde(flatten)] inner: StructFam115,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam116 {
    #[serde(rename = "spec")] f0: u8,
    #[serde(rename = "maxGas")] f1: u8,
    #[serde(rename = "fullName")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam116 {
    #[serde(rename = "v")] V(StructFam116),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam116 {
    #[serde(flatten)] inner: StructFam116,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam117 {
    #[serde(rename = "token")] f0: u8,
    #[serde(rename = "userAndWei")] f1: u8,
    #[serde(rename = "existingTokenAndWei")] f2: u8,
    #[serde(rename = "blacklistUsers")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam117 {
    #[serde(rename = "v")] V(StructFam117),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam117 {
    #[serde(flatten)] inner: StructFam117,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam118 {
    #[serde(rename = "token")] f0: u8,
    #[serde(rename = "maxSupply")] f1: u8,
    #[serde(rename = "noHyperliquidity")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam118 {
    #[serde(rename = "v")] V(StructFam118),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam118 {
    #[serde(flatten)] inner: StructFam118,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam119 {
    #[serde(rename = "spot")] f0: u8,
    #[serde(rename = "startPx")] f1: u8,
    #[serde(rename = "orderSz")] f2: u8,
    #[serde(rename = "nOrders")] f3: u8,
    #[serde(rename = "nSeededLevels")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam119 {
    #[serde(rename = "v")] V(StructFam119),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam119 {
    #[serde(flatten)] inner: StructFam119,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam120 {
    #[serde(rename = "token")] f0: u8,
    #[serde(rename = "address")] f1: u8,
    #[serde(rename = "evmExtraWeiDecimals")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam120 {
    #[serde(rename = "v")] V(StructFam120),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam120 {
    #[serde(flatten)] inner: StructFam120,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam121 {
    #[serde(rename = "token")] f0: u8,
    #[serde(rename = "fullName")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam121 {
    #[serde(rename = "v")] V(StructFam121),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam121 {
    #[serde(flatten)] inner: StructFam121,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam122 {
    #[serde(rename = "token")] f0: u8,
    #[serde(rename = "annotation")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam122 {
    #[serde(rename = "v")] V(StructFam122),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam122 {
    #[serde(flatten)] inner: StructFam122,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam123 {
    #[serde(rename = "token")] f0: u8,
    #[serde(rename = "share")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam123 {
    #[serde(rename = "v")] V(StructFam123),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam123 {
    #[serde(flatten)] inner: StructFam123,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam124 {
    #[serde(rename = "token")] f0: u8,
    #[serde(rename = "user")] f1: u8,
    #[serde(rename = "freeze")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam124 {
    #[serde(rename = "v")] V(StructFam124),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam124 {
    #[serde(flatten)] inner: StructFam124,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam125 {
    #[serde(rename = "deployer")] f0: u8,
    #[serde(rename = "spec")] f1: u8,
    #[serde(rename = "spots")] f2: u8,
    #[serde(rename = "deploy_time")] f3: u8,
    #[serde(rename = "deploy_gas_wei")] f4: u8,
    #[serde(rename = "deploy_gas_token")] f5: u8,
    #[serde(rename = "evm_contract")] f6: u8,
    #[serde(rename = "full_name")] f7: u8,
    #[serde(rename = "seeded_usdc")] f8: u8,
    #[serde(rename = "non_circulating_users")] f9: u8,
    #[serde(rename = "deployer_trading_fee_share")] f10: u8,
    #[serde(rename = "frozen_users")] f11: u8,
    #[serde(rename = "annotation")] f12: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam125 {
    #[serde(rename = "v")] V(StructFam125),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam125 {
    #[serde(flatten)] inner: StructFam125,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam126 {
    #[serde(rename = "address")] f0: u8,
    #[serde(rename = "evm_extra_wei_decimals")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam126 {
    #[serde(rename = "v")] V(StructFam126),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam126 {
    #[serde(flatten)] inner: StructFam126,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam127 {
    #[serde(rename = "tokens")] f0: u8,
    #[serde(rename = "deploy_time")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam127 {
    #[serde(rename = "v")] V(StructFam127),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam127 {
    #[serde(flatten)] inner: StructFam127,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam128 {
    #[serde(rename = "bucket_guard")] f0: u8,
    #[serde(rename = "start_gas_wei")] f1: u8,
    #[serde(rename = "end_gas_wei")] f2: u8,
    #[serde(rename = "token")] f3: u8,
    #[serde(rename = "initial_gas_to_last_auction_gas_ratio")] f4: u8,
    #[serde(rename = "min_gas")] f5: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam128 {
    #[serde(rename = "v")] V(StructFam128),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam128 {
    #[serde(flatten)] inner: StructFam128,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam129 {
    #[serde(rename = "szDecimals")] f0: u8,
    #[serde(rename = "name")] f1: u8,
    #[serde(rename = "marginTableId")] f2: u8,
    #[serde(rename = "marginMode")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam129 {
    #[serde(rename = "v")] V(StructFam129),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam129 {
    #[serde(flatten)] inner: StructFam129,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam130 {
    #[serde(rename = "asset_to_recent_oi")] f0: u8,
    #[serde(rename = "override_max_oi_per_second")] f1: u8,
    #[serde(rename = "reset_recent_oi_bucket_guard")] f2: u8,
    #[serde(rename = "assets_at_open_interest_cap")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam130 {
    #[serde(rename = "v")] V(StructFam130),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam130 {
    #[serde(flatten)] inner: StructFam130,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam131 {
    #[serde(rename = "meta")] f0: u8,
    #[serde(rename = "user_states")] f1: u8,
    #[serde(rename = "oracle")] f2: u8,
    #[serde(rename = "total_net_deposit")] f3: u8,
    #[serde(rename = "total_non_bridge_deposit")] f4: u8,
    #[serde(rename = "perform_auto_deleveraging")] f5: u8,
    #[serde(rename = "adl_shortfall_remaining")] f6: u8,
    #[serde(rename = "bridge2_withdraw_fee")] f7: u8,
    #[serde(rename = "daily_exchange_scaled_and_raw_vlms")] f8: u8,
    #[serde(rename = "halted_assets")] f9: u8,
    #[serde(rename = "override_max_signed_distances_from_oracle")] f10: u8,
    #[serde(rename = "max_withdraw_leverage")] f11: u8,
    #[serde(rename = "last_set_global_time")] f12: u8,
    #[serde(rename = "lnsgt")] f13: u8,
    #[serde(rename = "usdc_ntl_scale")] f14: u8,
    #[serde(rename = "isolated_external")] f15: u8,
    #[serde(rename = "isolated_oracle")] f16: u8,
    #[serde(rename = "moh")] f17: u8,
    #[serde(rename = "znfn")] f18: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam131 {
    #[serde(rename = "v")] V(StructFam131),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam131 {
    #[serde(flatten)] inner: StructFam131,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam132 {
    #[serde(rename = "l")] f0: u8,
    #[serde(rename = "leverage")] f1: u8,
    #[serde(rename = "raw_usd")] f2: u8,
    #[serde(rename = "u")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam132 {
    #[serde(rename = "v")] V(StructFam132),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam132 {
    #[serde(flatten)] inner: StructFam132,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam133 {
    #[serde(rename = "min_rate")] f0: u8,
    #[serde(rename = "max_rate")] f1: u8,
    #[serde(rename = "kink_rate")] f2: u8,
    #[serde(rename = "kink_utilization")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam133 {
    #[serde(rename = "v")] V(StructFam133),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam133 {
    #[serde(flatten)] inner: StructFam133,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam134 {
    #[serde(rename = "lower_bound")] f0: u8,
    #[serde(rename = "max_leverage")] f1: u8,
    #[serde(rename = "maintenance_deduction")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam134 {
    #[serde(rename = "v")] V(StructFam134),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam134 {
    #[serde(flatten)] inner: StructFam134,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam135 {
    #[serde(rename = "lowerBound")] f0: u8,
    #[serde(rename = "maxLeverage")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam135 {
    #[serde(rename = "v")] V(StructFam135),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam135 {
    #[serde(flatten)] inner: StructFam135,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam136 {
    #[serde(rename = "user")] f0: u8,
    #[serde(rename = "usd")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam136 {
    #[serde(rename = "v")] V(StructFam136),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam136 {
    #[serde(flatten)] inner: StructFam136,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam137 {
    #[serde(rename = "destination")] f0: u8,
    #[serde(rename = "usd")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam137 {
    #[serde(rename = "v")] V(StructFam137),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam137 {
    #[serde(flatten)] inner: StructFam137,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam138 {
    #[serde(rename = "wei")] f0: u8,
    #[serde(rename = "user")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam138 {
    #[serde(rename = "v")] V(StructFam138),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam138 {
    #[serde(flatten)] inner: StructFam138,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam139 {
    #[serde(rename = "user")] f0: u8,
    #[serde(rename = "wei")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam139 {
    #[serde(rename = "v")] V(StructFam139),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam139 {
    #[serde(flatten)] inner: StructFam139,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam140 {
    #[serde(rename = "user")] f0: u8,
    #[serde(rename = "action")] f1: u8,
    #[serde(rename = "id")] f2: u8,
    #[serde(rename = "is_frontend")] f3: u8,
    #[serde(rename = "expires_after")] f4: u8,
    #[serde(rename = "broadcaster")] f5: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam140 {
    #[serde(rename = "v")] V(StructFam140),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam140 {
    #[serde(flatten)] inner: StructFam140,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam141 {
    #[serde(rename = "n")] f0: u8,
    #[serde(rename = "name")] f1: u8,
    #[serde(rename = "s")] f2: u8,
    #[serde(rename = "sub_account_user")] f3: u8,
    #[serde(rename = "m")] f4: u8,
    #[serde(rename = "master")] f5: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam141 {
    #[serde(rename = "v")] V(StructFam141),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam141 {
    #[serde(flatten)] inner: StructFam141,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam142 {
    #[serde(rename = "n")] f0: u8,
    #[serde(rename = "name")] f1: u8,
    #[serde(rename = "v")] f2: u8,
    #[serde(rename = "validUntil")] f3: u8,
    #[serde(rename = "a")] f4: u8,
    #[serde(rename = "address")] f5: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam142 {
    #[serde(rename = "v")] V(StructFam142),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam142 {
    #[serde(flatten)] inner: StructFam142,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam143 {
    #[serde(rename = "variant")] f0: u8,
    #[serde(rename = "user")] f1: u8,
    #[serde(rename = "allowed")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam143 {
    #[serde(rename = "v")] V(StructFam143),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam143 {
    #[serde(flatten)] inner: StructFam143,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam144 {
    #[serde(rename = "au")] f0: u8,
    #[serde(rename = "authorizedUsers")] f1: u8,
    #[serde(rename = "authorized_users")] f2: u8,
    #[serde(rename = "threshold")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam144 {
    #[serde(rename = "v")] V(StructFam144),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam144 {
    #[serde(flatten)] inner: StructFam144,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam145 {
    #[serde(rename = "token")] f0: u8,
    #[serde(rename = "system_address")] f1: u8,
    #[serde(rename = "contract")] f2: u8,
    #[serde(rename = "wei")] f3: u8,
    #[serde(rename = "user")] f4: u8,
    #[serde(rename = "send_to_evm_data")] f5: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam145 {
    #[serde(rename = "v")] V(StructFam145),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam145 {
    #[serde(flatten)] inner: StructFam145,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam146 {
    #[serde(rename = "destination_recipient")] f0: u8,
    #[serde(rename = "destination_chain_id")] f1: u8,
    #[serde(rename = "gas_limit")] f2: u8,
    #[serde(rename = "nonce")] f3: u8,
    #[serde(rename = "data")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam146 {
    #[serde(rename = "v")] V(StructFam146),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam146 {
    #[serde(flatten)] inner: StructFam146,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam147 {
    #[serde(rename = "ntl_cutoff")] f0: u8,
    #[serde(rename = "rates")] f1: u8,
    #[serde(rename = "staking_keep_frac_for_referrer")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam147 {
    #[serde(rename = "v")] V(StructFam147),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam147 {
    #[serde(flatten)] inner: StructFam147,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam148 {
    #[serde(rename = "maker_fraction_cutoff")] f0: u8,
    #[serde(rename = "add")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam148 {
    #[serde(rename = "v")] V(StructFam148),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam148 {
    #[serde(flatten)] inner: StructFam148,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam149 {
    #[serde(rename = "boms")] f0: u8,
    #[serde(rename = "boms_staked")] f1: u8,
    #[serde(rename = "bps_of_max_supply_staked")] f2: u8,
    #[serde(rename = "discount")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam149 {
    #[serde(rename = "v")] V(StructFam149),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam149 {
    #[serde(flatten)] inner: StructFam149,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam150 {
    #[serde(rename = "referrerStates")] f0: u8,
    #[serde(rename = "l4Snapshots")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam150 {
    #[serde(rename = "v")] V(StructFam150),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam150 {
    #[serde(flatten)] inner: StructFam150,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam151 {
    #[serde(rename = "index")] f0: u8,
    #[serde(rename = "validatorIndex")] f1: u8,
    #[serde(rename = "address")] f2: u8,
    #[serde(rename = "amount")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam151 {
    #[serde(rename = "v")] V(StructFam151),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam151 {
    #[serde(flatten)] inner: StructFam151,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam152 {
    #[serde(rename = "until")] f0: u8,
    #[serde(rename = "required_matches")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam152 {
    #[serde(rename = "v")] V(StructFam152),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam152 {
    #[serde(flatten)] inner: StructFam152,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam153 {
    #[serde(rename = "code_location")] f0: u8,
    #[serde(rename = "last_seen_before")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam153 {
    #[serde(rename = "v")] V(StructFam153),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam153 {
    #[serde(flatten)] inner: StructFam153,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam154 {
    #[serde(rename = "last_bucket")] f0: u8,
    #[serde(rename = "bucket_millis")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam154 {
    #[serde(rename = "v")] V(StructFam154),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam154 {
    #[serde(flatten)] inner: StructFam154,
    _extra: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam155 {
    #[serde(rename = "hyperliquid_index")] f0: u8,
    #[serde(rename = "c")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum WrapStructFam155 {
    #[serde(rename = "v")] V(StructFam155),
}
#[derive(serde::Deserialize, Debug)]
struct FlatStructFam155 {
    #[serde(flatten)] inner: StructFam155,
    _extra: u8,
}
#[inline(never)]
fn drive_enums_0(s: &str, b: &[u8], v: &serde_json::Value) {
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam0>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam0>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam0>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam0>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam0>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam0>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam0>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam0>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam0>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam0>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam1>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam1>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam1>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam1>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam1>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam1>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam1>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam1>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam1>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam1>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam2>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam2>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam2>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam2>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam2>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam2>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam2>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam2>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam2>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam2>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam3>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam3>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam3>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam3>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam3>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam3>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam3>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam3>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam3>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam3>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam4>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam4>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam4>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam4>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam4>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam4>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam4>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam4>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam4>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam4>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam5>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam5>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam5>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam5>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam5>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam5>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam5>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam5>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam5>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam5>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam6>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam6>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam6>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam6>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam6>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam6>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam6>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam6>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam6>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam6>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam7>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam7>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam7>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam7>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam7>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam7>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam7>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam7>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam7>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam7>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam8>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam8>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam8>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam8>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam8>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam8>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam8>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam8>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam8>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam8>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam9>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam9>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam9>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam9>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam9>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam9>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam9>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam9>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam9>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam9>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam10>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam10>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam10>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam10>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam10>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam10>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam10>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam10>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam10>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam10>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam11>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam11>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam11>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam11>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam11>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam11>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam11>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam11>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam11>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam11>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam12>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam12>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam12>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam12>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam12>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam12>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam12>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam12>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam12>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam12>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam13>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam13>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam13>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam13>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam13>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam13>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam13>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam13>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam13>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam13>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam14>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam14>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam14>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam14>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam14>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam14>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam14>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam14>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam14>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam14>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam15>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam15>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam15>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam15>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam15>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam15>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam15>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam15>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam15>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam15>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam16>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam16>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam16>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam16>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam16>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam16>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam16>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam16>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam16>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam16>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam17>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam17>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam17>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam17>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam17>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam17>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam17>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam17>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam17>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam17>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam18>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam18>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam18>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam18>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam18>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam18>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam18>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam18>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam18>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam18>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam19>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam19>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam19>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam19>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam19>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam19>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam19>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam19>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam19>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam19>(&mut jd));
}
#[inline(never)]
fn drive_enums_20(s: &str, b: &[u8], v: &serde_json::Value) {
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam20>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam20>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam20>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam20>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam20>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam20>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam20>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam20>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam20>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam20>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam21>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam21>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam21>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam21>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam21>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam21>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam21>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam21>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam21>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam21>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam22>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam22>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam22>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam22>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam22>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam22>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam22>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam22>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam22>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam22>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam23>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam23>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam23>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam23>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam23>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam23>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam23>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam23>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam23>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam23>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam24>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam24>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam24>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam24>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam24>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam24>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam24>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam24>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam24>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam24>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam25>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam25>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam25>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam25>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam25>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam25>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam25>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam25>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam25>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam25>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam26>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam26>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam26>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam26>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam26>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam26>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam26>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam26>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam26>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam26>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam27>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam27>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam27>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam27>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam27>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam27>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam27>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam27>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam27>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam27>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam28>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam28>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam28>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam28>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam28>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam28>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam28>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam28>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam28>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam28>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam29>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam29>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam29>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam29>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam29>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam29>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam29>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam29>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam29>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam29>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam30>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam30>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam30>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam30>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam30>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam30>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam30>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam30>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam30>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam30>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam31>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam31>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam31>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam31>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam31>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam31>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam31>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam31>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam31>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam31>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam32>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam32>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam32>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam32>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam32>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam32>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam32>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam32>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam32>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam32>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam33>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam33>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam33>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam33>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam33>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam33>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam33>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam33>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam33>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam33>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam34>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam34>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam34>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam34>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam34>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam34>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam34>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam34>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam34>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam34>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam35>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam35>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam35>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam35>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam35>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam35>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam35>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam35>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam35>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam35>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam36>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam36>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam36>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam36>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam36>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam36>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam36>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam36>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam36>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam36>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam37>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam37>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam37>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam37>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam37>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam37>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam37>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam37>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam37>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam37>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam38>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam38>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam38>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam38>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam38>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam38>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam38>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam38>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam38>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam38>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam39>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam39>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam39>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam39>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam39>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam39>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam39>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam39>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam39>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam39>(&mut jd));
}
#[inline(never)]
fn drive_enums_40(s: &str, b: &[u8], v: &serde_json::Value) {
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam40>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam40>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam40>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam40>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam40>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam40>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam40>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam40>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam40>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam40>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam41>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam41>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam41>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam41>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam41>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam41>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam41>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam41>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam41>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam41>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam42>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam42>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam42>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam42>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam42>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam42>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam42>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam42>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam42>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam42>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam43>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam43>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam43>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam43>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam43>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam43>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam43>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam43>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam43>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam43>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam44>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam44>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam44>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam44>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam44>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam44>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam44>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam44>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam44>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam44>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam45>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam45>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam45>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam45>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam45>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam45>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam45>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam45>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam45>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam45>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam46>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam46>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam46>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam46>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam46>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam46>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam46>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam46>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam46>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam46>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam47>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam47>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam47>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam47>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam47>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam47>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam47>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam47>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam47>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam47>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam48>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam48>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam48>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam48>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam48>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam48>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam48>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam48>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam48>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam48>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam49>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam49>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam49>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam49>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam49>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam49>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam49>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam49>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam49>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam49>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam50>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam50>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam50>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam50>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam50>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam50>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam50>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam50>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam50>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam50>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam51>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam51>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam51>(b));
    let _ = core::hint::black_box(serde_json::from_value::<EnumFam51>(v.clone()));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam51>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam51>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<TagEnumFam51>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapEnumFam51>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapEnumFam51>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, EnumFam51>(&mut jd));
}
#[inline(never)]
fn drive_structs_0(s: &str, b: &[u8], v: &serde_json::Value) {
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam0>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam0>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam0>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam0>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam0>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam0>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam0>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam0>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam0>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam1>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam1>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam1>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam1>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam1>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam1>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam1>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam1>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam1>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam2>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam2>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam2>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam2>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam2>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam2>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam2>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam2>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam2>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam3>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam3>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam3>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam3>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam3>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam3>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam3>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam3>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam3>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam4>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam4>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam4>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam4>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam4>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam4>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam4>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam4>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam4>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam5>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam5>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam5>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam5>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam5>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam5>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam5>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam5>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam5>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam6>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam6>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam6>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam6>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam6>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam6>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam6>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam6>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam6>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam7>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam7>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam7>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam7>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam7>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam7>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam7>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam7>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam7>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam8>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam8>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam8>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam8>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam8>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam8>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam8>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam8>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam8>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam9>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam9>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam9>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam9>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam9>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam9>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam9>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam9>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam9>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam10>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam10>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam10>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam10>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam10>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam10>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam10>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam10>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam10>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam11>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam11>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam11>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam11>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam11>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam11>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam11>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam11>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam11>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam12>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam12>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam12>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam12>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam12>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam12>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam12>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam12>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam12>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam13>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam13>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam13>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam13>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam13>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam13>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam13>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam13>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam13>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam14>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam14>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam14>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam14>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam14>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam14>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam14>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam14>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam14>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam15>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam15>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam15>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam15>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam15>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam15>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam15>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam15>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam15>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam16>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam16>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam16>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam16>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam16>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam16>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam16>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam16>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam16>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam17>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam17>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam17>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam17>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam17>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam17>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam17>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam17>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam17>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam18>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam18>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam18>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam18>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam18>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam18>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam18>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam18>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam18>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam19>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam19>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam19>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam19>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam19>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam19>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam19>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam19>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam19>(&mut jd));
}
#[inline(never)]
fn drive_structs_20(s: &str, b: &[u8], v: &serde_json::Value) {
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam20>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam20>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam20>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam20>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam20>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam20>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam20>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam20>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam20>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam21>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam21>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam21>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam21>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam21>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam21>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam21>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam21>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam21>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam22>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam22>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam22>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam22>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam22>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam22>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam22>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam22>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam22>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam23>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam23>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam23>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam23>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam23>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam23>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam23>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam23>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam23>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam24>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam24>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam24>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam24>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam24>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam24>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam24>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam24>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam24>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam25>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam25>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam25>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam25>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam25>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam25>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam25>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam25>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam25>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam26>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam26>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam26>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam26>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam26>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam26>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam26>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam26>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam26>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam27>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam27>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam27>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam27>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam27>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam27>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam27>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam27>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam27>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam28>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam28>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam28>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam28>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam28>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam28>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam28>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam28>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam28>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam29>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam29>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam29>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam29>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam29>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam29>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam29>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam29>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam29>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam30>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam30>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam30>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam30>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam30>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam30>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam30>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam30>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam30>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam31>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam31>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam31>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam31>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam31>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam31>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam31>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam31>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam31>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam32>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam32>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam32>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam32>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam32>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam32>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam32>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam32>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam32>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam33>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam33>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam33>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam33>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam33>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam33>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam33>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam33>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam33>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam34>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam34>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam34>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam34>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam34>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam34>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam34>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam34>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam34>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam35>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam35>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam35>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam35>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam35>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam35>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam35>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam35>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam35>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam36>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam36>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam36>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam36>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam36>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam36>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam36>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam36>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam36>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam37>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam37>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam37>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam37>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam37>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam37>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam37>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam37>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam37>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam38>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam38>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam38>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam38>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam38>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam38>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam38>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam38>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam38>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam39>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam39>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam39>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam39>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam39>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam39>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam39>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam39>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam39>(&mut jd));
}
#[inline(never)]
fn drive_structs_40(s: &str, b: &[u8], v: &serde_json::Value) {
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam40>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam40>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam40>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam40>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam40>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam40>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam40>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam40>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam40>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam41>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam41>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam41>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam41>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam41>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam41>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam41>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam41>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam41>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam42>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam42>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam42>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam42>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam42>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam42>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam42>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam42>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam42>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam43>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam43>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam43>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam43>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam43>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam43>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam43>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam43>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam43>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam44>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam44>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam44>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam44>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam44>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam44>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam44>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam44>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam44>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam45>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam45>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam45>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam45>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam45>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam45>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam45>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam45>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam45>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam46>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam46>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam46>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam46>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam46>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam46>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam46>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam46>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam46>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam47>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam47>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam47>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam47>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam47>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam47>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam47>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam47>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam47>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam48>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam48>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam48>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam48>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam48>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam48>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam48>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam48>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam48>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam49>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam49>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam49>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam49>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam49>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam49>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam49>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam49>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam49>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam50>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam50>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam50>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam50>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam50>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam50>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam50>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam50>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam50>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam51>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam51>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam51>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam51>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam51>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam51>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam51>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam51>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam51>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam52>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam52>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam52>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam52>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam52>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam52>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam52>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam52>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam52>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam53>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam53>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam53>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam53>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam53>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam53>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam53>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam53>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam53>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam54>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam54>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam54>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam54>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam54>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam54>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam54>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam54>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam54>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam55>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam55>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam55>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam55>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam55>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam55>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam55>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam55>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam55>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam56>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam56>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam56>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam56>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam56>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam56>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam56>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam56>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam56>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam57>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam57>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam57>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam57>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam57>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam57>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam57>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam57>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam57>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam58>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam58>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam58>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam58>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam58>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam58>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam58>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam58>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam58>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam59>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam59>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam59>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam59>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam59>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam59>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam59>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam59>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam59>(&mut jd));
}
#[inline(never)]
fn drive_structs_60(s: &str, b: &[u8], v: &serde_json::Value) {
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam60>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam60>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam60>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam60>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam60>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam60>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam60>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam60>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam60>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam61>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam61>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam61>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam61>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam61>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam61>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam61>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam61>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam61>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam62>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam62>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam62>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam62>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam62>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam62>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam62>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam62>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam62>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam63>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam63>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam63>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam63>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam63>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam63>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam63>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam63>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam63>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam64>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam64>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam64>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam64>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam64>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam64>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam64>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam64>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam64>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam65>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam65>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam65>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam65>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam65>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam65>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam65>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam65>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam65>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam66>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam66>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam66>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam66>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam66>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam66>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam66>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam66>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam66>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam67>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam67>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam67>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam67>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam67>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam67>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam67>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam67>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam67>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam68>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam68>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam68>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam68>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam68>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam68>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam68>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam68>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam68>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam69>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam69>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam69>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam69>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam69>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam69>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam69>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam69>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam69>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam70>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam70>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam70>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam70>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam70>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam70>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam70>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam70>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam70>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam71>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam71>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam71>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam71>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam71>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam71>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam71>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam71>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam71>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam72>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam72>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam72>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam72>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam72>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam72>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam72>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam72>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam72>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam73>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam73>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam73>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam73>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam73>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam73>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam73>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam73>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam73>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam74>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam74>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam74>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam74>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam74>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam74>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam74>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam74>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam74>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam75>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam75>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam75>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam75>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam75>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam75>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam75>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam75>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam75>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam76>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam76>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam76>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam76>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam76>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam76>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam76>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam76>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam76>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam77>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam77>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam77>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam77>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam77>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam77>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam77>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam77>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam77>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam78>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam78>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam78>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam78>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam78>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam78>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam78>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam78>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam78>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam79>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam79>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam79>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam79>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam79>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam79>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam79>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam79>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam79>(&mut jd));
}
#[inline(never)]
fn drive_structs_80(s: &str, b: &[u8], v: &serde_json::Value) {
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam80>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam80>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam80>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam80>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam80>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam80>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam80>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam80>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam80>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam81>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam81>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam81>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam81>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam81>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam81>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam81>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam81>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam81>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam82>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam82>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam82>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam82>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam82>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam82>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam82>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam82>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam82>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam83>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam83>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam83>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam83>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam83>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam83>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam83>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam83>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam83>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam84>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam84>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam84>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam84>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam84>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam84>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam84>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam84>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam84>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam85>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam85>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam85>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam85>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam85>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam85>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam85>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam85>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam85>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam86>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam86>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam86>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam86>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam86>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam86>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam86>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam86>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam86>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam87>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam87>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam87>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam87>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam87>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam87>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam87>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam87>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam87>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam88>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam88>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam88>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam88>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam88>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam88>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam88>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam88>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam88>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam89>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam89>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam89>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam89>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam89>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam89>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam89>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam89>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam89>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam90>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam90>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam90>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam90>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam90>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam90>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam90>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam90>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam90>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam91>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam91>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam91>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam91>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam91>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam91>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam91>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam91>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam91>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam92>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam92>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam92>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam92>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam92>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam92>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam92>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam92>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam92>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam93>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam93>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam93>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam93>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam93>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam93>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam93>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam93>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam93>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam94>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam94>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam94>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam94>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam94>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam94>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam94>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam94>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam94>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam95>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam95>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam95>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam95>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam95>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam95>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam95>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam95>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam95>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam96>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam96>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam96>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam96>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam96>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam96>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam96>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam96>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam96>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam97>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam97>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam97>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam97>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam97>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam97>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam97>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam97>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam97>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam98>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam98>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam98>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam98>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam98>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam98>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam98>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam98>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam98>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam99>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam99>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam99>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam99>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam99>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam99>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam99>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam99>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam99>(&mut jd));
}
#[inline(never)]
fn drive_structs_100(s: &str, b: &[u8], v: &serde_json::Value) {
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam100>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam100>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam100>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam100>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam100>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam100>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam100>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam100>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam100>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam101>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam101>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam101>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam101>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam101>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam101>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam101>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam101>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam101>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam102>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam102>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam102>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam102>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam102>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam102>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam102>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam102>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam102>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam103>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam103>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam103>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam103>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam103>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam103>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam103>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam103>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam103>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam104>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam104>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam104>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam104>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam104>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam104>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam104>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam104>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam104>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam105>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam105>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam105>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam105>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam105>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam105>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam105>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam105>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam105>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam106>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam106>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam106>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam106>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam106>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam106>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam106>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam106>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam106>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam107>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam107>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam107>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam107>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam107>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam107>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam107>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam107>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam107>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam108>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam108>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam108>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam108>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam108>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam108>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam108>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam108>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam108>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam109>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam109>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam109>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam109>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam109>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam109>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam109>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam109>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam109>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam110>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam110>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam110>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam110>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam110>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam110>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam110>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam110>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam110>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam111>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam111>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam111>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam111>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam111>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam111>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam111>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam111>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam111>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam112>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam112>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam112>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam112>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam112>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam112>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam112>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam112>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam112>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam113>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam113>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam113>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam113>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam113>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam113>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam113>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam113>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam113>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam114>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam114>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam114>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam114>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam114>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam114>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam114>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam114>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam114>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam115>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam115>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam115>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam115>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam115>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam115>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam115>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam115>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam115>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam116>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam116>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam116>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam116>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam116>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam116>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam116>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam116>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam116>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam117>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam117>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam117>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam117>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam117>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam117>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam117>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam117>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam117>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam118>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam118>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam118>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam118>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam118>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam118>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam118>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam118>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam118>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam119>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam119>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam119>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam119>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam119>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam119>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam119>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam119>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam119>(&mut jd));
}
#[inline(never)]
fn drive_structs_120(s: &str, b: &[u8], v: &serde_json::Value) {
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam120>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam120>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam120>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam120>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam120>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam120>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam120>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam120>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam120>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam121>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam121>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam121>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam121>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam121>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam121>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam121>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam121>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam121>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam122>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam122>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam122>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam122>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam122>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam122>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam122>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam122>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam122>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam123>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam123>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam123>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam123>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam123>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam123>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam123>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam123>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam123>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam124>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam124>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam124>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam124>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam124>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam124>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam124>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam124>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam124>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam125>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam125>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam125>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam125>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam125>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam125>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam125>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam125>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam125>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam126>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam126>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam126>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam126>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam126>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam126>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam126>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam126>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam126>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam127>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam127>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam127>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam127>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam127>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam127>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam127>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam127>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam127>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam128>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam128>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam128>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam128>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam128>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam128>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam128>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam128>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam128>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam129>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam129>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam129>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam129>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam129>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam129>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam129>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam129>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam129>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam130>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam130>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam130>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam130>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam130>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam130>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam130>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam130>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam130>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam131>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam131>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam131>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam131>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam131>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam131>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam131>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam131>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam131>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam132>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam132>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam132>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam132>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam132>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam132>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam132>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam132>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam132>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam133>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam133>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam133>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam133>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam133>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam133>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam133>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam133>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam133>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam134>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam134>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam134>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam134>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam134>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam134>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam134>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam134>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam134>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam135>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam135>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam135>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam135>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam135>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam135>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam135>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam135>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam135>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam136>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam136>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam136>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam136>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam136>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam136>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam136>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam136>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam136>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam137>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam137>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam137>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam137>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam137>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam137>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam137>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam137>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam137>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam138>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam138>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam138>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam138>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam138>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam138>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam138>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam138>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam138>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam139>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam139>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam139>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam139>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam139>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam139>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam139>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam139>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam139>(&mut jd));
}
#[inline(never)]
fn drive_structs_140(s: &str, b: &[u8], v: &serde_json::Value) {
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam140>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam140>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam140>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam140>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam140>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam140>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam140>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam140>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam140>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam141>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam141>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam141>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam141>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam141>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam141>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam141>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam141>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam141>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam142>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam142>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam142>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam142>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam142>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam142>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam142>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam142>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam142>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam143>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam143>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam143>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam143>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam143>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam143>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam143>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam143>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam143>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam144>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam144>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam144>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam144>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam144>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam144>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam144>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam144>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam144>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam145>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam145>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam145>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam145>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam145>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam145>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam145>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam145>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam145>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam146>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam146>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam146>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam146>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam146>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam146>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam146>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam146>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam146>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam147>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam147>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam147>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam147>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam147>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam147>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam147>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam147>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam147>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam148>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam148>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam148>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam148>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam148>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam148>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam148>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam148>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam148>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam149>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam149>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam149>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam149>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam149>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam149>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam149>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam149>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam149>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam150>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam150>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam150>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam150>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam150>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam150>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam150>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam150>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam150>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam151>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam151>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam151>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam151>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam151>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam151>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam151>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam151>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam151>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam152>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam152>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam152>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam152>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam152>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam152>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam152>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam152>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam152>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam153>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam153>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam153>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam153>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam153>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam153>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam153>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam153>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam153>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam154>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam154>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam154>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam154>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam154>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam154>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam154>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam154>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam154>(&mut jd));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam155>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam155>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam155>(b));
    let _ = core::hint::black_box(serde_json::from_value::<StructFam155>(v.clone()));
    let _ = core::hint::black_box(serde_json::from_slice::<WrapStructFam155>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<WrapStructFam155>(b));
    let _ = core::hint::black_box(serde_json::from_slice::<FlatStructFam155>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<FlatStructFam155>(b));
    let mut jd = serde_json::Deserializer::from_slice(b);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, StructFam155>(&mut jd));
}
fn main() {
    let s = std::env::args().nth(1).unwrap_or_default();
    let b = s.as_bytes();
    let v = serde_json::from_slice::<serde_json::Value>(b).unwrap_or(serde_json::Value::Null);
    drive_enums_0(&s, b, &v);
    drive_enums_20(&s, b, &v);
    drive_enums_40(&s, b, &v);
    drive_structs_0(&s, b, &v);
    drive_structs_20(&s, b, &v);
    drive_structs_40(&s, b, &v);
    drive_structs_60(&s, b, &v);
    drive_structs_80(&s, b, &v);
    drive_structs_100(&s, b, &v);
    drive_structs_120(&s, b, &v);
    drive_structs_140(&s, b, &v);
}
