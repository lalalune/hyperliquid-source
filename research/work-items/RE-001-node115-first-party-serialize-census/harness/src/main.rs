#![forbid(unsafe_code)]
#![allow(dead_code, non_camel_case_types)]
use std::collections::BTreeMap;
use std::io::BufWriter;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam0 {
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
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam1 {
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
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam2 {
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
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam3 {
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
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam4 {
    #[serde(rename = "standaloneOutcome")] V0,
    #[serde(rename = "question")] V1,
    #[serde(rename = "questionOutcome")] V2,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam5 {
    #[serde(rename = "register")] V0,
    #[serde(rename = "changeProfile")] V1,
    #[serde(rename = "unregister")] V2,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam6 {
    #[serde(rename = "disabled")] V0,
    #[serde(rename = "reduceOnly")] V1,
    #[serde(rename = "enabled")] V2,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam7 {
    #[serde(rename = "usdtUsdcPx")] V0,
    #[serde(rename = "nativePx")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam8 {
    #[serde(rename = "technical")] V0,
    #[serde(rename = "treasury")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam9 {
    #[serde(rename = "registerAndAssociateNamedOutcomeFromTemplate")] V0,
    #[serde(rename = "registerQuestionFromTemplate")] V1,
    #[serde(rename = "registerStandaloneOutcomeFromTemplate")] V2,
    #[serde(rename = "settleOutcome")] V3,
    #[serde(rename = "settleQuestion")] V4,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam10 {
    #[serde(rename = "modifyApproval")] V0,
    #[serde(rename = "modifyBackstopLiquidatorApproval")] V1,
    #[serde(rename = "setReduceOnly")] V2,
    #[serde(rename = "cancel")] V3,
    #[serde(rename = "cancelAll")] V4,
    #[serde(rename = "order")] V5,
    #[serde(rename = "sendAsset")] V6,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam11 {
    #[serde(rename = "fileSnapshot")] V0,
    #[serde(rename = "webData2")] V1,
    #[serde(rename = "webData3")] V2,
    #[serde(rename = "meta")] V3,
    #[serde(rename = "spotMeta")] V4,
    #[serde(rename = "outcomeMeta")] V5,
    #[serde(rename = "outcomeDeployerLimits")] V6,
    #[serde(rename = "clearinghouseState")] V7,
    #[serde(rename = "spotClearinghouseState")] V8,
    #[serde(rename = "openOrders")] V9,
    #[serde(rename = "exchangeStatus")] V10,
    #[serde(rename = "frontendOpenOrders")] V11,
    #[serde(rename = "activeAssetData")] V12,
    #[serde(rename = "maxMarketOrderNtls")] V13,
    #[serde(rename = "vaultSummaries")] V14,
    #[serde(rename = "userVaultEquities")] V15,
    #[serde(rename = "leadingVaults")] V16,
    #[serde(rename = "extraAgents")] V17,
    #[serde(rename = "subAccounts")] V18,
    #[serde(rename = "subAccounts2")] V19,
    #[serde(rename = "userFees")] V20,
    #[serde(rename = "userRateLimit")] V21,
    #[serde(rename = "spotDeployState")] V22,
    #[serde(rename = "spotPairDeployAuctionStatus")] V23,
    #[serde(rename = "perpDeployAuctionStatus")] V24,
    #[serde(rename = "votes")] V25,
    #[serde(rename = "delegations")] V26,
    #[serde(rename = "delegatorSummary")] V27,
    #[serde(rename = "maxBuilderFee")] V28,
    #[serde(rename = "userToMultiSigSigners")] V29,
    #[serde(rename = "userRole")] V30,
    #[serde(rename = "perpsAtOpenInterestCap")] V31,
    #[serde(rename = "perpDexLimits")] V32,
    #[serde(rename = "validatorL1Votes")] V33,
    #[serde(rename = "marginTable")] V34,
    #[serde(rename = "perpDexs")] V35,
    #[serde(rename = "allPerpMetas")] V36,
    #[serde(rename = "userDexAbstraction")] V37,
    #[serde(rename = "perpDexStatus")] V38,
    #[serde(rename = "borrowLendUserState")] V39,
    #[serde(rename = "borrowLendReserveState")] V40,
    #[serde(rename = "allBorrowLendReserveStates")] V41,
    #[serde(rename = "userAbstraction")] V42,
    #[serde(rename = "perpAnnotation")] V43,
    #[serde(rename = "perpCategories")] V44,
    #[serde(rename = "perpConciseAnnotations")] V45,
    #[serde(rename = "tokenAnnotation")] V46,
    #[serde(rename = "tokenConciseAnnotations")] V47,
    #[serde(rename = "settledOutcome")] V48,
    #[serde(rename = "settledQuestion")] V49,
    #[serde(rename = "approvedBuilders")] V50,
    #[serde(rename = "gossipPriorityAuctionStatus")] V51,
    #[serde(rename = "outcomeTemplates")] V52,
    #[serde(rename = "aqav2InterestHistory")] V53,
    #[serde(rename = "userStarState")] V54,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam12 {
    #[serde(rename = "dateTime")] V0,
    #[serde(rename = "date")] V1,
    #[serde(rename = "string")] V2,
    #[serde(rename = "shortString")] V3,
    #[serde(rename = "hlPerp")] V4,
    #[serde(rename = "uInt")] V5,
    #[serde(rename = "uDecimal")] V6,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam13 {
    #[serde(rename = "splitOutcome")] V0,
    #[serde(rename = "mergeOutcome")] V1,
    #[serde(rename = "mergeQuestion")] V2,
    #[serde(rename = "negateOutcome")] V3,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam14 {
    #[serde(rename = "Requested")] V0,
    #[serde(rename = "TradingUser")] V1,
    #[serde(rename = "StakingUser")] V2,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam15 {
    #[serde(rename = "normal")] V0,
    #[serde(rename = "child")] V1,
    #[serde(rename = "parent")] V2,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam16 {
    #[serde(rename = "enabled")] V0,
    #[serde(rename = "disabled")] V1,
    #[serde(rename = "blocked")] V2,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam17 {
    #[serde(rename = "Oracle")] V0,
    #[serde(rename = "ReferenceOracle")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam18 {
    #[serde(rename = "Evm")] V0,
    #[serde(rename = "Broadcaster")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam19 {
    #[serde(rename = "na")] V0,
    #[serde(rename = "normalTpsl")] V1,
    #[serde(rename = "positionTpsl")] V2,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam20 {
    #[serde(rename = "normal")] V0,
    #[serde(rename = "noCross")] V1,
    #[serde(rename = "strictIsolated")] V2,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam21 {
    #[serde(rename = "create")] V0,
    #[serde(rename = "firstStorageSlot")] V1,
    #[serde(rename = "customStorageSlot")] V2,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam22 {
    #[serde(rename = "yes")] V0,
    #[serde(rename = "no")] V1,
    #[serde(rename = "abstain")] V2,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam23 {
    #[serde(rename = "unjailSelf")] V0,
    #[serde(rename = "jailSelf")] V1,
    #[serde(rename = "voteJail")] V2,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam24 {
    #[serde(rename = "limit")] V0,
    #[serde(rename = "trigger")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam25 {
    #[serde(rename = "Cross")] V0,
    #[serde(rename = "Isolated")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam26 {
    #[serde(rename = "Deposit")] V0,
    #[serde(rename = "InvalidatedWithdrawal")] V1,
    #[serde(rename = "RequestedWithdrawal")] V2,
    #[serde(rename = "FinalizedWithdrawal")] V3,
    #[serde(rename = "FinalizedValidatorSetUpdate")] V4,
    #[serde(rename = "RequestedValidatorSetUpdateEvent")] V5,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam27 {
    #[serde(rename = "modifyApproval")] V0,
    #[serde(rename = "modifyBackstopLiquidatorApproval")] V1,
    #[serde(rename = "setReduceOnly")] V2,
    #[serde(rename = "cancel")] V3,
    #[serde(rename = "cancelAll")] V4,
    #[serde(rename = "order")] V5,
    #[serde(rename = "sendAsset")] V6,
    #[serde(rename = "setOracle")] V7,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam28 {
    #[serde(rename = "Alo")] V0,
    #[serde(rename = "Ioc")] V1,
    #[serde(rename = "Gtc")] V2,
    #[serde(rename = "FrontendMarket")] V3,
    #[serde(rename = "LiquidationMarket")] V4,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam29 {
    #[serde(rename = "StandaloneOutcome")] V0,
    #[serde(rename = "Question")] V1,
    #[serde(rename = "QuestionOutcome")] V2,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam30 {
    #[serde(rename = "accelerated")] V0,
    #[serde(rename = "constitutional")] V1,
    #[serde(rename = "ecosystem")] V2,
    #[serde(rename = "electoral")] V3,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam31 {
    #[serde(rename = "Perp")] V0,
    #[serde(rename = "Spot")] V1,
    #[serde(rename = "Token")] V2,
    #[serde(rename = "Pdi")] V3,
    #[serde(rename = "ActivateDexAbstraction")] V4,
    #[serde(rename = "ActivateUnifiedAccount")] V5,
    #[serde(rename = "AllBoleTokens")] V6,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam32 {
    #[serde(rename = "Spot")] V0,
    #[serde(rename = "Mark")] V1,
    #[serde(rename = "ExternalPerp")] V2,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam33 {
    #[serde(rename = "borrow")] V0,
    #[serde(rename = "supply")] V1,
    #[serde(rename = "repay")] V2,
    #[serde(rename = "withdraw")] V3,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam34 {
    #[serde(rename = "Local")] V0,
    #[serde(rename = "Sandbox")] V1,
    #[serde(rename = "Testnet")] V2,
    #[serde(rename = "Mainnet")] V3,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam35 {
    #[serde(rename = "Main")] V0,
    #[serde(rename = "Hip3")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam36 {
    #[serde(rename = "Na")] V0,
    #[serde(rename = "UserDisabled")] V1,
    #[serde(rename = "ValidatorDisabled")] V2,
    #[serde(rename = "m")] V3,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam37 {
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
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam38 {
    #[serde(rename = "Bid")] V0,
    #[serde(rename = "Ask")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam39 {
    #[serde(rename = "Perp")] V0,
    #[serde(rename = "Spot")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam40 {
    #[serde(rename = "activated")] V0,
    #[serde(rename = "terminated")] V1,
    #[serde(rename = "finished")] V2,
    #[serde(rename = "error")] V3,
    #[serde(rename = "waitingForTrigger")] V4,
    #[serde(rename = "stopped")] V5,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam41 {
    #[serde(rename = "default")] V0,
    #[serde(rename = "disabled")] V1,
    #[serde(rename = "dexAbstraction")] V2,
    #[serde(rename = "portfolioMargin")] V3,
    #[serde(rename = "unifiedAccount")] V4,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam42 {
    #[serde(rename = "default")] V0,
    #[serde(rename = "disabled")] V1,
    #[serde(rename = "dexAbstraction")] V2,
    #[serde(rename = "unifiedAccount")] V3,
    #[serde(rename = "portfolioMargin")] V4,
    #[serde(rename = "s")] V5,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam43 {
    #[serde(rename = "referrerStates")] V0,
    #[serde(rename = "l4Snapshots")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam44 {
    #[serde(rename = "proxy")] V0,
    #[serde(rename = "setOracle")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam45 {
    #[serde(rename = "GdHlPerp2")] V0,
    #[serde(rename = "GsHlPerp")] V1,
    #[serde(rename = "EaHlPerp")] V2,
    #[serde(rename = "EbHlPerp")] V3,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam46 {
    #[serde(rename = "open")] V0,
    #[serde(rename = "filled")] V1,
    #[serde(rename = "canceled")] V2,
    #[serde(rename = "triggered")] V3,
    #[serde(rename = "rejected")] V4,
    #[serde(rename = "marginCanceled")] V5,
    #[serde(rename = "perpMaxPositionCanceled")] V6,
    #[serde(rename = "vaultWithdrawalCanceled")] V7,
    #[serde(rename = "openInterestCapCanceled")] V8,
    #[serde(rename = "selfTradeCanceled")] V9,
    #[serde(rename = "reduceOnlyCanceled")] V10,
    #[serde(rename = "siblingFilledCanceled")] V11,
    #[serde(rename = "delistedCanceled")] V12,
    #[serde(rename = "liquidatedCanceled")] V13,
    #[serde(rename = "outcomeSettledCanceled")] V14,
    #[serde(rename = "scheduledCancel")] V15,
    #[serde(rename = "internalCancel")] V16,
    #[serde(rename = "tickRejected")] V17,
    #[serde(rename = "minTradeNtlRejected")] V18,
    #[serde(rename = "perpMarginRejected")] V19,
    #[serde(rename = "perpMaxPositionRejected")] V20,
    #[serde(rename = "reduceOnlyRejected")] V21,
    #[serde(rename = "badAloPxRejected")] V22,
    #[serde(rename = "iocCancelRejected")] V23,
    #[serde(rename = "badTriggerPxRejected")] V24,
    #[serde(rename = "marketOrderNoLiquidityRejected")] V25,
    #[serde(rename = "positionIncreaseAtOpenInterestCapRejected")] V26,
    #[serde(rename = "positionFlipAtOpenInterestCapRejected")] V27,
    #[serde(rename = "tooAggressiveAtOpenInterestCapRejected")] V28,
    #[serde(rename = "openInterestIncreaseRejected")] V29,
    #[serde(rename = "insufficientSpotBalanceRejected")] V30,
    #[serde(rename = "oracleRejected")] V31,
    #[serde(rename = "outcomeSettledRejected")] V32,
    #[serde(rename = "hip3CrossMarginReduceOnly")] V33,
    #[serde(rename = "hip3CrossMarginDisabled")] V34,
    #[serde(rename = "haltedRejected")] V35,
    #[serde(rename = "tooManyOpenOrdersRejected")] V36,
    #[serde(rename = "invalidPriorityRejected")] V37,
    #[serde(rename = "priorityAloReduceOnlyRejected")] V38,
    #[serde(rename = "insufficientWeiCanceled")] V39,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam47 {
    #[serde(rename = "maker")] V0,
    #[serde(rename = "taker")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam48 {
    #[serde(rename = "Exchange")] V0,
    #[serde(rename = "Rpc")] V1,
    #[serde(rename = "EvmState")] V2,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam49 {
    #[serde(rename = "Validator")] V0,
    #[serde(rename = "NonValidator")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam50 {
    #[serde(rename = "CertifiedTwoChain")] V0,
    #[serde(rename = "CommitTx")] V1,
    #[serde(rename = "CommitBlock")] V2,
    #[serde(rename = "VoteTx")] V3,
    #[serde(rename = "VoteBlock")] V4,
    #[serde(rename = "Propose")] V5,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam51 {
    #[serde(rename = "fullLiquidatable")] V0,
    #[serde(rename = "partialLiquidatable")] V1,
    #[serde(rename = "atRisk")] V2,
    #[serde(rename = "healthy")] V3,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam52 {
    #[serde(rename = "allTime")] V0,
    #[serde(rename = "sinceOpen")] V1,
    #[serde(rename = "sinceChange")] V2,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam53 {
    #[serde(rename = "allTime")] V0,
    #[serde(rename = "sinceChange")] V1,
    #[serde(rename = "sinceOpen")] V2,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam54 {
    #[serde(rename = "hex")] V0,
    #[serde(rename = "base58")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam55 {
    #[serde(rename = "base58")] V0,
    #[serde(rename = "hex")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam56 {
    #[serde(rename = "Enabled")] V0,
    #[serde(rename = "Disabled")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam57 {
    #[serde(rename = "Disabled")] V0,
    #[serde(rename = "Enabled")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam58 {
    #[serde(rename = "market")] V0,
    #[serde(rename = "backstop")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam59 {
    #[serde(rename = "backstop")] V0,
    #[serde(rename = "market")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam60 {
    #[serde(rename = "Normal")] V0,
    #[serde(rename = "Fallback")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam61 {
    #[serde(rename = "Fallback")] V0,
    #[serde(rename = "Normal")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam62 {
    #[serde(rename = "active")] V0,
    #[serde(rename = "settled")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam63 {
    #[serde(rename = "settled")] V0,
    #[serde(rename = "active")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam64 {
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
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam65 {
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
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam66 {
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
    #[serde(rename = "setFundingInterestRates")] V10,
    #[serde(rename = "disableDex")] V11,
    #[serde(rename = "setPerpAnnotation")] V12,
    #[serde(rename = "migrateDexQuoteToken")] V13,
    #[serde(rename = "setFundingClamps")] V14,
    #[serde(rename = "hip3Star")] V15,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam67 {
    #[serde(rename = "missing")] V0,
    #[serde(rename = "user")] V1,
    #[serde(rename = "agent")] V2,
    #[serde(rename = "vault")] V3,
    #[serde(rename = "subAccount")] V4,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam68 {
    #[serde(rename = "bridge-voter")] V0,
    #[serde(rename = "reference-oracle-publisher")] V1,
    #[serde(rename = "outcome-voter")] V2,
    #[serde(rename = "visor")] V3,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam69 {
    #[serde(rename = "NodeMetadata")] V0,
    #[serde(rename = "VisorMetadata")] V1,
    #[serde(rename = "HotfixMetadata")] V2,
    #[serde(rename = "NodeArtifact")] V3,
    #[serde(rename = "PublisherBinaryMetadata")] V4,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam70 {
    #[serde(rename = "tp")] V0,
    #[serde(rename = "sl")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam71 {
    #[serde(rename = "sl")] V0,
    #[serde(rename = "tp")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam72 {
    #[serde(rename = "Ask")] V0,
    #[serde(rename = "Bid")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam73 {
    #[serde(rename = "Spot")] V0,
    #[serde(rename = "Perp")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam74 {
    #[serde(rename = "Isolated")] V0,
    #[serde(rename = "Cross")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam75 {
    #[serde(rename = "reduceOnly")] V0,
    #[serde(rename = "disabled")] V1,
    #[serde(rename = "enabled")] V2,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam76 {
    #[serde(rename = "enabled")] V0,
    #[serde(rename = "disabled")] V1,
    #[serde(rename = "reduceOnly")] V2,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam77 {
    #[serde(rename = "borrow")] V0,
    #[serde(rename = "supply")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam78 {
    #[serde(rename = "limit")] V0,
    #[serde(rename = "market")] V1,
    #[serde(rename = "takeProfitMarket")] V2,
    #[serde(rename = "takeProfitLimit")] V3,
    #[serde(rename = "stopMarket")] V4,
    #[serde(rename = "stopLimit")] V5,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam80 {
    #[serde(rename = "success")] V0,
    #[serde(rename = "error")] V1,
}
#[derive(serde::Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SerEnumFam81 {
    #[serde(rename = "na")] V0,
    #[serde(rename = "normalTpsl")] V1,
    #[serde(rename = "positionTpsl")] V2,
    #[serde(rename = "p")] V3,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam0 {
    #[serde(rename = "last_bucket")] f0: u64,
    #[serde(rename = "bucket_millis")] f1: u64,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam1 {
    #[serde(rename = "perpAddBaseRate")] f0: f64,
    #[serde(rename = "perpCrossBaseRate")] f1: f64,
    #[serde(rename = "spotAddBaseRate")] f2: f64,
    #[serde(rename = "spotCrossBaseRate")] f3: f64,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam2 {
    #[serde(rename = "total")] f0: u64,
    #[serde(rename = "hold")] f1: u64,
    #[serde(rename = "entry_ntl")] f2: u64,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam3 {
    #[serde(rename = "total")] f0: u64,
    #[serde(rename = "hold")] f1: u64,
    #[serde(rename = "entryNtl")] f2: u64,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam4 {
    #[serde(rename = "operation")] f0: String,
    #[serde(rename = "token")] f1: u64,
    #[serde(rename = "amount")] f2: Option<String>,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam5 {
    #[serde(rename = "dex")] f0: String,
    #[serde(rename = "ntl")] f1: u64,
    #[serde(rename = "isDeposit")] f2: bool,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam6 {
    #[serde(rename = "height")] f0: u64,
    #[serde(rename = "abciDigest")] f1: [u8; 32],
    #[serde(rename = "signature")] f2: String,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam7 {
    #[serde(rename = "height")] f0: u64,
    #[serde(rename = "l1Hash")] f1: [u8; 32],
    #[serde(rename = "signature")] f2: String,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam8 {
    #[serde(rename = "slotId")] f0: u64,
    #[serde(rename = "ip")] f1: String,
    #[serde(rename = "maxGas")] f2: u64,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam9 {
    #[serde(rename = "signatureChainId")] f0: String,
    #[serde(rename = "hyperliquidChain")] f1: String,
    #[serde(rename = "maxFeeRate")] f2: String,
    #[serde(rename = "builder")] f3: String,
    #[serde(rename = "nonce")] f4: u64,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam10 {
    #[serde(rename = "signatureChainId")] f0: String,
    #[serde(rename = "hyperliquidChain")] f1: String,
    #[serde(rename = "agentAddress")] f2: String,
    #[serde(rename = "agentName")] f3: Option<String>,
    #[serde(rename = "nonce")] f4: u64,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam11 {
    #[serde(rename = "signatureChainId")] f0: String,
    #[serde(rename = "hyperliquidChain")] f1: String,
    #[serde(rename = "validator")] f2: String,
    #[serde(rename = "wei")] f3: u64,
    #[serde(rename = "isUndelegate")] f4: bool,
    #[serde(rename = "nonce")] f5: u64,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam12 {
    #[serde(rename = "signatureChainId")] f0: String,
    #[serde(rename = "hyperliquidChain")] f1: String,
    #[serde(rename = "destination")] f2: String,
    #[serde(rename = "amount")] f3: String,
    #[serde(rename = "time")] f4: u64,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam13 {
    #[serde(rename = "signatureChainId")] f0: String,
    #[serde(rename = "hyperliquidChain")] f1: String,
    #[serde(rename = "destination")] f2: String,
    #[serde(rename = "token")] f3: String,
    #[serde(rename = "amount")] f4: String,
    #[serde(rename = "time")] f5: u64,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam14 {
    #[serde(rename = "signatureChainId")] f0: String,
    #[serde(rename = "hyperliquidChain")] f1: String,
    #[serde(rename = "destination")] f2: String,
    #[serde(rename = "amount")] f3: String,
    #[serde(rename = "time")] f4: u64,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam15 {
    #[serde(rename = "signatureChainId")] f0: String,
    #[serde(rename = "hyperliquidChain")] f1: String,
    #[serde(rename = "user")] f2: String,
    #[serde(rename = "abstraction")] f3: String,
    #[serde(rename = "nonce")] f4: u64,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam16 {
    #[serde(rename = "signatureChainId")] f0: String,
    #[serde(rename = "hyperliquidChain")] f1: String,
    #[serde(rename = "extendLongTermStaking")] f2: bool,
    #[serde(rename = "nonce")] f3: u64,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam17 {
    #[serde(rename = "bpsOfMaxSupply")] f0: u64,
    #[serde(rename = "discount")] f1: u64,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam18 {
    #[serde(rename = "makerFractionCutoff")] f0: u64,
    #[serde(rename = "add")] f1: u64,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam19 {
    #[serde(rename = "nDailyOutcomesRemaining")] f0: u64,
    #[serde(rename = "nActiveOutcomesRemaining")] f1: u64,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam20 {
    #[serde(rename = "isReduceOnly")] f0: bool,
    #[serde(rename = "isBackstopLiquidatorDepositAllowed")] f1: bool,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam21 {
    #[serde(rename = "basis")] f0: u64,
    #[serde(rename = "value")] f1: u64,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam22 {
    #[serde(rename = "user")] f0: String,
    #[serde(rename = "wei")] f1: u64,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam23 {
    #[serde(rename = "maxFeeRate")] f0: String,
    #[serde(rename = "builder")] f1: String,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam24 {
    #[serde(rename = "min_rate")] f0: f64,
    #[serde(rename = "max_rate")] f1: f64,
    #[serde(rename = "kink_rate")] f2: f64,
    #[serde(rename = "kink_utilization")] f3: f64,
}
#[derive(serde::Serialize, Debug, Default)]
struct SerStructFam25 {
    #[serde(rename = "allTime")] f0: u64,
    #[serde(rename = "sinceOpen")] f1: u64,
    #[serde(rename = "sinceChange")] f2: u64,
}

struct CollectStrTrigger(u64);
impl serde::Serialize for CollectStrTrigger {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("0x{:x}", self.0))
    }
}

#[inline(never)]
fn pin_ser<T: serde::Serialize, S: serde::Serializer>() {
    let f: fn(&T, S) -> Result<S::Ok, S::Error> = <T as serde::Serialize>::serialize::<S>;
    core::hint::black_box(f);
}

#[inline(never)]
fn exercise_collect_str(n: u64) {
    use serde_json::ser::PrettyFormatter;
    let c = CollectStrTrigger(n);
    pin_ser::<CollectStrTrigger, &mut serde_json::Serializer<&mut Vec<u8>>>();
    pin_ser::<CollectStrTrigger, &mut serde_json::Serializer<Vec<u8>>>();
    pin_ser::<CollectStrTrigger, &mut serde_json::Serializer<&mut Vec<u8>, PrettyFormatter<'_>>>();
    pin_ser::<CollectStrTrigger, &mut serde_json::Serializer<Vec<u8>, PrettyFormatter<'_>>>();
    pin_ser::<CollectStrTrigger, &mut serde_json::Serializer<&mut BufWriter<std::fs::File>>>();
    pin_ser::<CollectStrTrigger, &mut serde_json::Serializer<BufWriter<std::fs::File>>>();
    pin_ser::<CollectStrTrigger, &mut serde_json::Serializer<&mut std::fs::File>>();
    pin_ser::<CollectStrTrigger, &mut serde_json::Serializer<std::fs::File>>();
    pin_ser::<CollectStrTrigger, &mut serde_json::Serializer<&mut dyn std::io::Write>>();
    let _ = core::hint::black_box(serde_json::to_vec(&c));
    let _ = core::hint::black_box(serde_json::to_vec_pretty(&c));
}

#[inline(never)]
fn exercise_ser<T: serde::Serialize + Ord + Clone>(val: &T) {
    use rmp_serde::config::{BinaryConfig, DefaultConfig, HumanReadableConfig, StructMapConfig};
    use serde_json::ser::PrettyFormatter;
    pin_ser::<T, &mut serde_json::Serializer<&mut Vec<u8>>>();
    pin_ser::<T, &mut serde_json::Serializer<Vec<u8>>>();
    pin_ser::<T, &mut serde_json::Serializer<&mut Vec<u8>, PrettyFormatter<'_>>>();
    pin_ser::<T, &mut serde_json::Serializer<Vec<u8>, PrettyFormatter<'_>>>();
    pin_ser::<T, &mut serde_json::Serializer<&mut BufWriter<std::fs::File>>>();
    pin_ser::<T, &mut serde_json::Serializer<BufWriter<std::fs::File>>>();
    pin_ser::<T, &mut serde_json::Serializer<&mut std::fs::File>>();
    pin_ser::<T, &mut serde_json::Serializer<std::fs::File>>();
    pin_ser::<T, &mut serde_json::Serializer<&mut dyn std::io::Write>>();
    pin_ser::<T, serde_json::value::Serializer>();
    pin_ser::<T, &mut rmp_serde::Serializer<&mut Vec<u8>>>();
    pin_ser::<T, &mut rmp_serde::Serializer<Vec<u8>>>();
    pin_ser::<T, &mut rmp_serde::Serializer<&mut Vec<u8>, StructMapConfig<DefaultConfig>>>();
    pin_ser::<T, &mut rmp_serde::Serializer<Vec<u8>, StructMapConfig<DefaultConfig>>>();
    pin_ser::<T, &mut rmp_serde::Serializer<&mut Vec<u8>, HumanReadableConfig<DefaultConfig>>>();
    pin_ser::<T, &mut rmp_serde::Serializer<&mut Vec<u8>, HumanReadableConfig<StructMapConfig<DefaultConfig>>>>();
    pin_ser::<T, &mut rmp_serde::Serializer<&mut Vec<u8>, BinaryConfig<DefaultConfig>>>();
    pin_ser::<T, &mut rmp_serde::Serializer<&mut BufWriter<std::fs::File>>>();
    pin_ser::<T, &mut rmp_serde::Serializer<BufWriter<std::fs::File>>>();
    pin_ser::<T, &mut rmp_serde::Serializer<&mut BufWriter<std::fs::File>, StructMapConfig<DefaultConfig>>>();
    pin_ser::<T, &mut rmp_serde::Serializer<BufWriter<std::fs::File>, StructMapConfig<DefaultConfig>>>();
    pin_ser::<T, &mut rmp_serde::Serializer<&mut std::fs::File>>();
    let mut m = BTreeMap::new();
    m.insert(val.clone(), 1u8);
    let _ = core::hint::black_box(serde_json::to_vec(&m));
    let _ = core::hint::black_box(serde_json::to_vec_pretty(&m));
    let _ = core::hint::black_box(serde_json::to_value(&m));
    let _ = core::hint::black_box(rmp_serde::to_vec(&m));
    let _ = core::hint::black_box(rmp_serde::to_vec_named(&m));
}

#[inline(never)]
fn exercise_ser_struct<T: serde::Serialize>(val: &T) {
    use rmp_serde::config::{DefaultConfig, StructMapConfig};
    use serde_json::ser::PrettyFormatter;
    pin_ser::<T, &mut serde_json::Serializer<&mut Vec<u8>>>();
    pin_ser::<T, &mut serde_json::Serializer<Vec<u8>>>();
    pin_ser::<T, &mut serde_json::Serializer<&mut Vec<u8>, PrettyFormatter<'_>>>();
    pin_ser::<T, serde_json::value::Serializer>();
    pin_ser::<T, &mut rmp_serde::Serializer<&mut Vec<u8>>>();
    pin_ser::<T, &mut rmp_serde::Serializer<&mut Vec<u8>, StructMapConfig<DefaultConfig>>>();
    let _ = core::hint::black_box(serde_json::to_vec(val));
    let _ = core::hint::black_box(rmp_serde::to_vec(val));
    let _ = core::hint::black_box(rmp_serde::to_vec_named(val));
}

fn main() {
    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    if n == 0 { return; }
    exercise_collect_str(n as u64);
    let v = match n % 92 { 0 => SerEnumFam0::V0, 1 => SerEnumFam0::V1, 2 => SerEnumFam0::V2, 3 => SerEnumFam0::V3, 4 => SerEnumFam0::V4, 5 => SerEnumFam0::V5, 6 => SerEnumFam0::V6, 7 => SerEnumFam0::V7, 8 => SerEnumFam0::V8, 9 => SerEnumFam0::V9, 10 => SerEnumFam0::V10, 11 => SerEnumFam0::V11, 12 => SerEnumFam0::V12, 13 => SerEnumFam0::V13, 14 => SerEnumFam0::V14, 15 => SerEnumFam0::V15, 16 => SerEnumFam0::V16, 17 => SerEnumFam0::V17, 18 => SerEnumFam0::V18, 19 => SerEnumFam0::V19, 20 => SerEnumFam0::V20, 21 => SerEnumFam0::V21, 22 => SerEnumFam0::V22, 23 => SerEnumFam0::V23, 24 => SerEnumFam0::V24, 25 => SerEnumFam0::V25, 26 => SerEnumFam0::V26, 27 => SerEnumFam0::V27, 28 => SerEnumFam0::V28, 29 => SerEnumFam0::V29, 30 => SerEnumFam0::V30, 31 => SerEnumFam0::V31, 32 => SerEnumFam0::V32, 33 => SerEnumFam0::V33, 34 => SerEnumFam0::V34, 35 => SerEnumFam0::V35, 36 => SerEnumFam0::V36, 37 => SerEnumFam0::V37, 38 => SerEnumFam0::V38, 39 => SerEnumFam0::V39, 40 => SerEnumFam0::V40, 41 => SerEnumFam0::V41, 42 => SerEnumFam0::V42, 43 => SerEnumFam0::V43, 44 => SerEnumFam0::V44, 45 => SerEnumFam0::V45, 46 => SerEnumFam0::V46, 47 => SerEnumFam0::V47, 48 => SerEnumFam0::V48, 49 => SerEnumFam0::V49, 50 => SerEnumFam0::V50, 51 => SerEnumFam0::V51, 52 => SerEnumFam0::V52, 53 => SerEnumFam0::V53, 54 => SerEnumFam0::V54, 55 => SerEnumFam0::V55, 56 => SerEnumFam0::V56, 57 => SerEnumFam0::V57, 58 => SerEnumFam0::V58, 59 => SerEnumFam0::V59, 60 => SerEnumFam0::V60, 61 => SerEnumFam0::V61, 62 => SerEnumFam0::V62, 63 => SerEnumFam0::V63, 64 => SerEnumFam0::V64, 65 => SerEnumFam0::V65, 66 => SerEnumFam0::V66, 67 => SerEnumFam0::V67, 68 => SerEnumFam0::V68, 69 => SerEnumFam0::V69, 70 => SerEnumFam0::V70, 71 => SerEnumFam0::V71, 72 => SerEnumFam0::V72, 73 => SerEnumFam0::V73, 74 => SerEnumFam0::V74, 75 => SerEnumFam0::V75, 76 => SerEnumFam0::V76, 77 => SerEnumFam0::V77, 78 => SerEnumFam0::V78, 79 => SerEnumFam0::V79, 80 => SerEnumFam0::V80, 81 => SerEnumFam0::V81, 82 => SerEnumFam0::V82, 83 => SerEnumFam0::V83, 84 => SerEnumFam0::V84, 85 => SerEnumFam0::V85, 86 => SerEnumFam0::V86, 87 => SerEnumFam0::V87, 88 => SerEnumFam0::V88, 89 => SerEnumFam0::V89, 90 => SerEnumFam0::V90, 91 => SerEnumFam0::V91, _ => SerEnumFam0::V0 };
    exercise_ser(&v);
    let v = match n % 13 { 0 => SerEnumFam1::V0, 1 => SerEnumFam1::V1, 2 => SerEnumFam1::V2, 3 => SerEnumFam1::V3, 4 => SerEnumFam1::V4, 5 => SerEnumFam1::V5, 6 => SerEnumFam1::V6, 7 => SerEnumFam1::V7, 8 => SerEnumFam1::V8, 9 => SerEnumFam1::V9, 10 => SerEnumFam1::V10, 11 => SerEnumFam1::V11, 12 => SerEnumFam1::V12, _ => SerEnumFam1::V0 };
    exercise_ser(&v);
    let v = match n % 18 { 0 => SerEnumFam2::V0, 1 => SerEnumFam2::V1, 2 => SerEnumFam2::V2, 3 => SerEnumFam2::V3, 4 => SerEnumFam2::V4, 5 => SerEnumFam2::V5, 6 => SerEnumFam2::V6, 7 => SerEnumFam2::V7, 8 => SerEnumFam2::V8, 9 => SerEnumFam2::V9, 10 => SerEnumFam2::V10, 11 => SerEnumFam2::V11, 12 => SerEnumFam2::V12, 13 => SerEnumFam2::V13, 14 => SerEnumFam2::V14, 15 => SerEnumFam2::V15, 16 => SerEnumFam2::V16, 17 => SerEnumFam2::V17, _ => SerEnumFam2::V0 };
    exercise_ser(&v);
    let v = match n % 16 { 0 => SerEnumFam3::V0, 1 => SerEnumFam3::V1, 2 => SerEnumFam3::V2, 3 => SerEnumFam3::V3, 4 => SerEnumFam3::V4, 5 => SerEnumFam3::V5, 6 => SerEnumFam3::V6, 7 => SerEnumFam3::V7, 8 => SerEnumFam3::V8, 9 => SerEnumFam3::V9, 10 => SerEnumFam3::V10, 11 => SerEnumFam3::V11, 12 => SerEnumFam3::V12, 13 => SerEnumFam3::V13, 14 => SerEnumFam3::V14, 15 => SerEnumFam3::V15, _ => SerEnumFam3::V0 };
    exercise_ser(&v);
    let v = match n % 3 { 0 => SerEnumFam4::V0, 1 => SerEnumFam4::V1, 2 => SerEnumFam4::V2, _ => SerEnumFam4::V0 };
    exercise_ser(&v);
    let v = match n % 3 { 0 => SerEnumFam5::V0, 1 => SerEnumFam5::V1, 2 => SerEnumFam5::V2, _ => SerEnumFam5::V0 };
    exercise_ser(&v);
    let v = match n % 3 { 0 => SerEnumFam6::V0, 1 => SerEnumFam6::V1, 2 => SerEnumFam6::V2, _ => SerEnumFam6::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam7::V0, 1 => SerEnumFam7::V1, _ => SerEnumFam7::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam8::V0, 1 => SerEnumFam8::V1, _ => SerEnumFam8::V0 };
    exercise_ser(&v);
    let v = match n % 5 { 0 => SerEnumFam9::V0, 1 => SerEnumFam9::V1, 2 => SerEnumFam9::V2, 3 => SerEnumFam9::V3, 4 => SerEnumFam9::V4, _ => SerEnumFam9::V0 };
    exercise_ser(&v);
    let v = match n % 7 { 0 => SerEnumFam10::V0, 1 => SerEnumFam10::V1, 2 => SerEnumFam10::V2, 3 => SerEnumFam10::V3, 4 => SerEnumFam10::V4, 5 => SerEnumFam10::V5, 6 => SerEnumFam10::V6, _ => SerEnumFam10::V0 };
    exercise_ser(&v);
    let v = match n % 55 { 0 => SerEnumFam11::V0, 1 => SerEnumFam11::V1, 2 => SerEnumFam11::V2, 3 => SerEnumFam11::V3, 4 => SerEnumFam11::V4, 5 => SerEnumFam11::V5, 6 => SerEnumFam11::V6, 7 => SerEnumFam11::V7, 8 => SerEnumFam11::V8, 9 => SerEnumFam11::V9, 10 => SerEnumFam11::V10, 11 => SerEnumFam11::V11, 12 => SerEnumFam11::V12, 13 => SerEnumFam11::V13, 14 => SerEnumFam11::V14, 15 => SerEnumFam11::V15, 16 => SerEnumFam11::V16, 17 => SerEnumFam11::V17, 18 => SerEnumFam11::V18, 19 => SerEnumFam11::V19, 20 => SerEnumFam11::V20, 21 => SerEnumFam11::V21, 22 => SerEnumFam11::V22, 23 => SerEnumFam11::V23, 24 => SerEnumFam11::V24, 25 => SerEnumFam11::V25, 26 => SerEnumFam11::V26, 27 => SerEnumFam11::V27, 28 => SerEnumFam11::V28, 29 => SerEnumFam11::V29, 30 => SerEnumFam11::V30, 31 => SerEnumFam11::V31, 32 => SerEnumFam11::V32, 33 => SerEnumFam11::V33, 34 => SerEnumFam11::V34, 35 => SerEnumFam11::V35, 36 => SerEnumFam11::V36, 37 => SerEnumFam11::V37, 38 => SerEnumFam11::V38, 39 => SerEnumFam11::V39, 40 => SerEnumFam11::V40, 41 => SerEnumFam11::V41, 42 => SerEnumFam11::V42, 43 => SerEnumFam11::V43, 44 => SerEnumFam11::V44, 45 => SerEnumFam11::V45, 46 => SerEnumFam11::V46, 47 => SerEnumFam11::V47, 48 => SerEnumFam11::V48, 49 => SerEnumFam11::V49, 50 => SerEnumFam11::V50, 51 => SerEnumFam11::V51, 52 => SerEnumFam11::V52, 53 => SerEnumFam11::V53, 54 => SerEnumFam11::V54, _ => SerEnumFam11::V0 };
    exercise_ser(&v);
    let v = match n % 7 { 0 => SerEnumFam12::V0, 1 => SerEnumFam12::V1, 2 => SerEnumFam12::V2, 3 => SerEnumFam12::V3, 4 => SerEnumFam12::V4, 5 => SerEnumFam12::V5, 6 => SerEnumFam12::V6, _ => SerEnumFam12::V0 };
    exercise_ser(&v);
    let v = match n % 4 { 0 => SerEnumFam13::V0, 1 => SerEnumFam13::V1, 2 => SerEnumFam13::V2, 3 => SerEnumFam13::V3, _ => SerEnumFam13::V0 };
    exercise_ser(&v);
    let v = match n % 3 { 0 => SerEnumFam14::V0, 1 => SerEnumFam14::V1, 2 => SerEnumFam14::V2, _ => SerEnumFam14::V0 };
    exercise_ser(&v);
    let v = match n % 3 { 0 => SerEnumFam15::V0, 1 => SerEnumFam15::V1, 2 => SerEnumFam15::V2, _ => SerEnumFam15::V0 };
    exercise_ser(&v);
    let v = match n % 3 { 0 => SerEnumFam16::V0, 1 => SerEnumFam16::V1, 2 => SerEnumFam16::V2, _ => SerEnumFam16::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam17::V0, 1 => SerEnumFam17::V1, _ => SerEnumFam17::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam18::V0, 1 => SerEnumFam18::V1, _ => SerEnumFam18::V0 };
    exercise_ser(&v);
    let v = match n % 3 { 0 => SerEnumFam19::V0, 1 => SerEnumFam19::V1, 2 => SerEnumFam19::V2, _ => SerEnumFam19::V0 };
    exercise_ser(&v);
    let v = match n % 3 { 0 => SerEnumFam20::V0, 1 => SerEnumFam20::V1, 2 => SerEnumFam20::V2, _ => SerEnumFam20::V0 };
    exercise_ser(&v);
    let v = match n % 3 { 0 => SerEnumFam21::V0, 1 => SerEnumFam21::V1, 2 => SerEnumFam21::V2, _ => SerEnumFam21::V0 };
    exercise_ser(&v);
    let v = match n % 3 { 0 => SerEnumFam22::V0, 1 => SerEnumFam22::V1, 2 => SerEnumFam22::V2, _ => SerEnumFam22::V0 };
    exercise_ser(&v);
    let v = match n % 3 { 0 => SerEnumFam23::V0, 1 => SerEnumFam23::V1, 2 => SerEnumFam23::V2, _ => SerEnumFam23::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam24::V0, 1 => SerEnumFam24::V1, _ => SerEnumFam24::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam25::V0, 1 => SerEnumFam25::V1, _ => SerEnumFam25::V0 };
    exercise_ser(&v);
    let v = match n % 6 { 0 => SerEnumFam26::V0, 1 => SerEnumFam26::V1, 2 => SerEnumFam26::V2, 3 => SerEnumFam26::V3, 4 => SerEnumFam26::V4, 5 => SerEnumFam26::V5, _ => SerEnumFam26::V0 };
    exercise_ser(&v);
    let v = match n % 8 { 0 => SerEnumFam27::V0, 1 => SerEnumFam27::V1, 2 => SerEnumFam27::V2, 3 => SerEnumFam27::V3, 4 => SerEnumFam27::V4, 5 => SerEnumFam27::V5, 6 => SerEnumFam27::V6, 7 => SerEnumFam27::V7, _ => SerEnumFam27::V0 };
    exercise_ser(&v);
    let v = match n % 5 { 0 => SerEnumFam28::V0, 1 => SerEnumFam28::V1, 2 => SerEnumFam28::V2, 3 => SerEnumFam28::V3, 4 => SerEnumFam28::V4, _ => SerEnumFam28::V0 };
    exercise_ser(&v);
    let v = match n % 3 { 0 => SerEnumFam29::V0, 1 => SerEnumFam29::V1, 2 => SerEnumFam29::V2, _ => SerEnumFam29::V0 };
    exercise_ser(&v);
    let v = match n % 4 { 0 => SerEnumFam30::V0, 1 => SerEnumFam30::V1, 2 => SerEnumFam30::V2, 3 => SerEnumFam30::V3, _ => SerEnumFam30::V0 };
    exercise_ser(&v);
    let v = match n % 7 { 0 => SerEnumFam31::V0, 1 => SerEnumFam31::V1, 2 => SerEnumFam31::V2, 3 => SerEnumFam31::V3, 4 => SerEnumFam31::V4, 5 => SerEnumFam31::V5, 6 => SerEnumFam31::V6, _ => SerEnumFam31::V0 };
    exercise_ser(&v);
    let v = match n % 3 { 0 => SerEnumFam32::V0, 1 => SerEnumFam32::V1, 2 => SerEnumFam32::V2, _ => SerEnumFam32::V0 };
    exercise_ser(&v);
    let v = match n % 4 { 0 => SerEnumFam33::V0, 1 => SerEnumFam33::V1, 2 => SerEnumFam33::V2, 3 => SerEnumFam33::V3, _ => SerEnumFam33::V0 };
    exercise_ser(&v);
    let v = match n % 4 { 0 => SerEnumFam34::V0, 1 => SerEnumFam34::V1, 2 => SerEnumFam34::V2, 3 => SerEnumFam34::V3, _ => SerEnumFam34::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam35::V0, 1 => SerEnumFam35::V1, _ => SerEnumFam35::V0 };
    exercise_ser(&v);
    let v = match n % 4 { 0 => SerEnumFam36::V0, 1 => SerEnumFam36::V1, 2 => SerEnumFam36::V2, 3 => SerEnumFam36::V3, _ => SerEnumFam36::V0 };
    exercise_ser(&v);
    let v = match n % 79 { 0 => SerEnumFam37::V0, 1 => SerEnumFam37::V1, 2 => SerEnumFam37::V2, 3 => SerEnumFam37::V3, 4 => SerEnumFam37::V4, 5 => SerEnumFam37::V5, 6 => SerEnumFam37::V6, 7 => SerEnumFam37::V7, 8 => SerEnumFam37::V8, 9 => SerEnumFam37::V9, 10 => SerEnumFam37::V10, 11 => SerEnumFam37::V11, 12 => SerEnumFam37::V12, 13 => SerEnumFam37::V13, 14 => SerEnumFam37::V14, 15 => SerEnumFam37::V15, 16 => SerEnumFam37::V16, 17 => SerEnumFam37::V17, 18 => SerEnumFam37::V18, 19 => SerEnumFam37::V19, 20 => SerEnumFam37::V20, 21 => SerEnumFam37::V21, 22 => SerEnumFam37::V22, 23 => SerEnumFam37::V23, 24 => SerEnumFam37::V24, 25 => SerEnumFam37::V25, 26 => SerEnumFam37::V26, 27 => SerEnumFam37::V27, 28 => SerEnumFam37::V28, 29 => SerEnumFam37::V29, 30 => SerEnumFam37::V30, 31 => SerEnumFam37::V31, 32 => SerEnumFam37::V32, 33 => SerEnumFam37::V33, 34 => SerEnumFam37::V34, 35 => SerEnumFam37::V35, 36 => SerEnumFam37::V36, 37 => SerEnumFam37::V37, 38 => SerEnumFam37::V38, 39 => SerEnumFam37::V39, 40 => SerEnumFam37::V40, 41 => SerEnumFam37::V41, 42 => SerEnumFam37::V42, 43 => SerEnumFam37::V43, 44 => SerEnumFam37::V44, 45 => SerEnumFam37::V45, 46 => SerEnumFam37::V46, 47 => SerEnumFam37::V47, 48 => SerEnumFam37::V48, 49 => SerEnumFam37::V49, 50 => SerEnumFam37::V50, 51 => SerEnumFam37::V51, 52 => SerEnumFam37::V52, 53 => SerEnumFam37::V53, 54 => SerEnumFam37::V54, 55 => SerEnumFam37::V55, 56 => SerEnumFam37::V56, 57 => SerEnumFam37::V57, 58 => SerEnumFam37::V58, 59 => SerEnumFam37::V59, 60 => SerEnumFam37::V60, 61 => SerEnumFam37::V61, 62 => SerEnumFam37::V62, 63 => SerEnumFam37::V63, 64 => SerEnumFam37::V64, 65 => SerEnumFam37::V65, 66 => SerEnumFam37::V66, 67 => SerEnumFam37::V67, 68 => SerEnumFam37::V68, 69 => SerEnumFam37::V69, 70 => SerEnumFam37::V70, 71 => SerEnumFam37::V71, 72 => SerEnumFam37::V72, 73 => SerEnumFam37::V73, 74 => SerEnumFam37::V74, 75 => SerEnumFam37::V75, 76 => SerEnumFam37::V76, 77 => SerEnumFam37::V77, 78 => SerEnumFam37::V78, _ => SerEnumFam37::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam38::V0, 1 => SerEnumFam38::V1, _ => SerEnumFam38::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam39::V0, 1 => SerEnumFam39::V1, _ => SerEnumFam39::V0 };
    exercise_ser(&v);
    let v = match n % 6 { 0 => SerEnumFam40::V0, 1 => SerEnumFam40::V1, 2 => SerEnumFam40::V2, 3 => SerEnumFam40::V3, 4 => SerEnumFam40::V4, 5 => SerEnumFam40::V5, _ => SerEnumFam40::V0 };
    exercise_ser(&v);
    let v = match n % 5 { 0 => SerEnumFam41::V0, 1 => SerEnumFam41::V1, 2 => SerEnumFam41::V2, 3 => SerEnumFam41::V3, 4 => SerEnumFam41::V4, _ => SerEnumFam41::V0 };
    exercise_ser(&v);
    let v = match n % 6 { 0 => SerEnumFam42::V0, 1 => SerEnumFam42::V1, 2 => SerEnumFam42::V2, 3 => SerEnumFam42::V3, 4 => SerEnumFam42::V4, 5 => SerEnumFam42::V5, _ => SerEnumFam42::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam43::V0, 1 => SerEnumFam43::V1, _ => SerEnumFam43::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam44::V0, 1 => SerEnumFam44::V1, _ => SerEnumFam44::V0 };
    exercise_ser(&v);
    let v = match n % 4 { 0 => SerEnumFam45::V0, 1 => SerEnumFam45::V1, 2 => SerEnumFam45::V2, 3 => SerEnumFam45::V3, _ => SerEnumFam45::V0 };
    exercise_ser(&v);
    let v = match n % 40 { 0 => SerEnumFam46::V0, 1 => SerEnumFam46::V1, 2 => SerEnumFam46::V2, 3 => SerEnumFam46::V3, 4 => SerEnumFam46::V4, 5 => SerEnumFam46::V5, 6 => SerEnumFam46::V6, 7 => SerEnumFam46::V7, 8 => SerEnumFam46::V8, 9 => SerEnumFam46::V9, 10 => SerEnumFam46::V10, 11 => SerEnumFam46::V11, 12 => SerEnumFam46::V12, 13 => SerEnumFam46::V13, 14 => SerEnumFam46::V14, 15 => SerEnumFam46::V15, 16 => SerEnumFam46::V16, 17 => SerEnumFam46::V17, 18 => SerEnumFam46::V18, 19 => SerEnumFam46::V19, 20 => SerEnumFam46::V20, 21 => SerEnumFam46::V21, 22 => SerEnumFam46::V22, 23 => SerEnumFam46::V23, 24 => SerEnumFam46::V24, 25 => SerEnumFam46::V25, 26 => SerEnumFam46::V26, 27 => SerEnumFam46::V27, 28 => SerEnumFam46::V28, 29 => SerEnumFam46::V29, 30 => SerEnumFam46::V30, 31 => SerEnumFam46::V31, 32 => SerEnumFam46::V32, 33 => SerEnumFam46::V33, 34 => SerEnumFam46::V34, 35 => SerEnumFam46::V35, 36 => SerEnumFam46::V36, 37 => SerEnumFam46::V37, 38 => SerEnumFam46::V38, 39 => SerEnumFam46::V39, _ => SerEnumFam46::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam47::V0, 1 => SerEnumFam47::V1, _ => SerEnumFam47::V0 };
    exercise_ser(&v);
    let v = match n % 3 { 0 => SerEnumFam48::V0, 1 => SerEnumFam48::V1, 2 => SerEnumFam48::V2, _ => SerEnumFam48::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam49::V0, 1 => SerEnumFam49::V1, _ => SerEnumFam49::V0 };
    exercise_ser(&v);
    let v = match n % 6 { 0 => SerEnumFam50::V0, 1 => SerEnumFam50::V1, 2 => SerEnumFam50::V2, 3 => SerEnumFam50::V3, 4 => SerEnumFam50::V4, 5 => SerEnumFam50::V5, _ => SerEnumFam50::V0 };
    exercise_ser(&v);
    let v = match n % 4 { 0 => SerEnumFam51::V0, 1 => SerEnumFam51::V1, 2 => SerEnumFam51::V2, 3 => SerEnumFam51::V3, _ => SerEnumFam51::V0 };
    exercise_ser(&v);
    let v = match n % 3 { 0 => SerEnumFam52::V0, 1 => SerEnumFam52::V1, 2 => SerEnumFam52::V2, _ => SerEnumFam52::V0 };
    exercise_ser(&v);
    let v = match n % 3 { 0 => SerEnumFam53::V0, 1 => SerEnumFam53::V1, 2 => SerEnumFam53::V2, _ => SerEnumFam53::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam54::V0, 1 => SerEnumFam54::V1, _ => SerEnumFam54::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam55::V0, 1 => SerEnumFam55::V1, _ => SerEnumFam55::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam56::V0, 1 => SerEnumFam56::V1, _ => SerEnumFam56::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam57::V0, 1 => SerEnumFam57::V1, _ => SerEnumFam57::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam58::V0, 1 => SerEnumFam58::V1, _ => SerEnumFam58::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam59::V0, 1 => SerEnumFam59::V1, _ => SerEnumFam59::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam60::V0, 1 => SerEnumFam60::V1, _ => SerEnumFam60::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam61::V0, 1 => SerEnumFam61::V1, _ => SerEnumFam61::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam62::V0, 1 => SerEnumFam62::V1, _ => SerEnumFam62::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam63::V0, 1 => SerEnumFam63::V1, _ => SerEnumFam63::V0 };
    exercise_ser(&v);
    let v = match n % 16 { 0 => SerEnumFam64::V0, 1 => SerEnumFam64::V1, 2 => SerEnumFam64::V2, 3 => SerEnumFam64::V3, 4 => SerEnumFam64::V4, 5 => SerEnumFam64::V5, 6 => SerEnumFam64::V6, 7 => SerEnumFam64::V7, 8 => SerEnumFam64::V8, 9 => SerEnumFam64::V9, 10 => SerEnumFam64::V10, 11 => SerEnumFam64::V11, 12 => SerEnumFam64::V12, 13 => SerEnumFam64::V13, 14 => SerEnumFam64::V14, 15 => SerEnumFam64::V15, _ => SerEnumFam64::V0 };
    exercise_ser(&v);
    let v = match n % 17 { 0 => SerEnumFam65::V0, 1 => SerEnumFam65::V1, 2 => SerEnumFam65::V2, 3 => SerEnumFam65::V3, 4 => SerEnumFam65::V4, 5 => SerEnumFam65::V5, 6 => SerEnumFam65::V6, 7 => SerEnumFam65::V7, 8 => SerEnumFam65::V8, 9 => SerEnumFam65::V9, 10 => SerEnumFam65::V10, 11 => SerEnumFam65::V11, 12 => SerEnumFam65::V12, 13 => SerEnumFam65::V13, 14 => SerEnumFam65::V14, 15 => SerEnumFam65::V15, 16 => SerEnumFam65::V16, _ => SerEnumFam65::V0 };
    exercise_ser(&v);
    let v = match n % 16 { 0 => SerEnumFam66::V0, 1 => SerEnumFam66::V1, 2 => SerEnumFam66::V2, 3 => SerEnumFam66::V3, 4 => SerEnumFam66::V4, 5 => SerEnumFam66::V5, 6 => SerEnumFam66::V6, 7 => SerEnumFam66::V7, 8 => SerEnumFam66::V8, 9 => SerEnumFam66::V9, 10 => SerEnumFam66::V10, 11 => SerEnumFam66::V11, 12 => SerEnumFam66::V12, 13 => SerEnumFam66::V13, 14 => SerEnumFam66::V14, 15 => SerEnumFam66::V15, _ => SerEnumFam66::V0 };
    exercise_ser(&v);
    let v = match n % 5 { 0 => SerEnumFam67::V0, 1 => SerEnumFam67::V1, 2 => SerEnumFam67::V2, 3 => SerEnumFam67::V3, 4 => SerEnumFam67::V4, _ => SerEnumFam67::V0 };
    exercise_ser(&v);
    let v = match n % 4 { 0 => SerEnumFam68::V0, 1 => SerEnumFam68::V1, 2 => SerEnumFam68::V2, 3 => SerEnumFam68::V3, _ => SerEnumFam68::V0 };
    exercise_ser(&v);
    let v = match n % 5 { 0 => SerEnumFam69::V0, 1 => SerEnumFam69::V1, 2 => SerEnumFam69::V2, 3 => SerEnumFam69::V3, 4 => SerEnumFam69::V4, _ => SerEnumFam69::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam70::V0, 1 => SerEnumFam70::V1, _ => SerEnumFam70::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam71::V0, 1 => SerEnumFam71::V1, _ => SerEnumFam71::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam72::V0, 1 => SerEnumFam72::V1, _ => SerEnumFam72::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam73::V0, 1 => SerEnumFam73::V1, _ => SerEnumFam73::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam74::V0, 1 => SerEnumFam74::V1, _ => SerEnumFam74::V0 };
    exercise_ser(&v);
    let v = match n % 3 { 0 => SerEnumFam75::V0, 1 => SerEnumFam75::V1, 2 => SerEnumFam75::V2, _ => SerEnumFam75::V0 };
    exercise_ser(&v);
    let v = match n % 3 { 0 => SerEnumFam76::V0, 1 => SerEnumFam76::V1, 2 => SerEnumFam76::V2, _ => SerEnumFam76::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam77::V0, 1 => SerEnumFam77::V1, _ => SerEnumFam77::V0 };
    exercise_ser(&v);
    let v = match n % 6 { 0 => SerEnumFam78::V0, 1 => SerEnumFam78::V1, 2 => SerEnumFam78::V2, 3 => SerEnumFam78::V3, 4 => SerEnumFam78::V4, 5 => SerEnumFam78::V5, _ => SerEnumFam78::V0 };
    exercise_ser(&v);
    let v = match n % 2 { 0 => SerEnumFam80::V0, 1 => SerEnumFam80::V1, _ => SerEnumFam80::V0 };
    exercise_ser(&v);
    let v = match n % 4 { 0 => SerEnumFam81::V0, 1 => SerEnumFam81::V1, 2 => SerEnumFam81::V2, 3 => SerEnumFam81::V3, _ => SerEnumFam81::V0 };
    exercise_ser(&v);
    exercise_ser_struct(&SerStructFam0::default());
    exercise_ser_struct(&SerStructFam1::default());
    exercise_ser_struct(&SerStructFam2::default());
    exercise_ser_struct(&SerStructFam3::default());
    exercise_ser_struct(&SerStructFam4::default());
    exercise_ser_struct(&SerStructFam5::default());
    exercise_ser_struct(&SerStructFam6::default());
    exercise_ser_struct(&SerStructFam7::default());
    exercise_ser_struct(&SerStructFam8::default());
    exercise_ser_struct(&SerStructFam9::default());
    exercise_ser_struct(&SerStructFam10::default());
    exercise_ser_struct(&SerStructFam11::default());
    exercise_ser_struct(&SerStructFam12::default());
    exercise_ser_struct(&SerStructFam13::default());
    exercise_ser_struct(&SerStructFam14::default());
    exercise_ser_struct(&SerStructFam15::default());
    exercise_ser_struct(&SerStructFam16::default());
    exercise_ser_struct(&SerStructFam17::default());
    exercise_ser_struct(&SerStructFam18::default());
    exercise_ser_struct(&SerStructFam19::default());
    exercise_ser_struct(&SerStructFam20::default());
    exercise_ser_struct(&SerStructFam21::default());
    exercise_ser_struct(&SerStructFam22::default());
    exercise_ser_struct(&SerStructFam23::default());
    exercise_ser_struct(&SerStructFam24::default());
    exercise_ser_struct(&SerStructFam25::default());
}
