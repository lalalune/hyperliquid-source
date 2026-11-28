#![forbid(unsafe_code)]
#![allow(dead_code)]
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(serde::Deserialize, Debug)]
enum EnumFam0 {
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
enum TagEnumFam0 {
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
enum EnumFam1 {
    #[serde(rename = "D")] V0,
    #[serde(rename = "E")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam2 {
    #[serde(rename = "e")] V0,
    #[serde(rename = "n")] V1,
    #[serde(rename = "t")] V2,
    #[serde(rename = "m")] V3,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam3 {
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
enum TagEnumFam3 {
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
enum EnumFam4 {
    #[serde(rename = "a")] V0,
    #[serde(rename = "b")] V1,
    #[serde(rename = "c")] V2,
    #[serde(rename = "d")] V3,
    #[serde(rename = "e")] V4,
    #[serde(rename = "f")] V5,
    #[serde(rename = "g")] V6,
    #[serde(rename = "h")] V7,
    #[serde(rename = "j")] V8,
    #[serde(rename = "k")] V9,
    #[serde(rename = "l")] V10,
    #[serde(rename = "m")] V11,
    #[serde(rename = "n")] V12,
    #[serde(rename = "o")] V13,
    #[serde(rename = "p")] V14,
    #[serde(rename = "q")] V15,
    #[serde(rename = "r")] V16,
    #[serde(rename = "s")] V17,
    #[serde(rename = "t")] V18,
    #[serde(rename = "u")] V19,
    #[serde(rename = "v")] V20,
    #[serde(rename = "w")] V21,
    #[serde(rename = "x")] V22,
    #[serde(rename = "y")] V23,
    #[serde(rename = "z")] V24,
    #[serde(rename = "A")] V25,
    #[serde(rename = "B")] V26,
    #[serde(rename = "C")] V27,
    #[serde(rename = "D")] V28,
    #[serde(rename = "E")] V29,
    #[serde(rename = "F")] V30,
    #[serde(rename = "G")] V31,
    #[serde(rename = "H")] V32,
    #[serde(rename = "I")] V33,
    #[serde(rename = "J")] V34,
    #[serde(rename = "K")] V35,
    #[serde(rename = "L")] V36,
    #[serde(rename = "M")] V37,
    #[serde(rename = "N")] V38,
    #[serde(rename = "O")] V39,
    #[serde(rename = "P")] V40,
    #[serde(rename = "Q")] V41,
    #[serde(rename = "R")] V42,
    #[serde(rename = "S")] V43,
    #[serde(rename = "T")] V44,
    #[serde(rename = "W")] V45,
    #[serde(rename = "X")] V46,
    #[serde(rename = "Y")] V47,
    #[serde(rename = "Z")] V48,
    #[serde(rename = "aa")] V49,
    #[serde(rename = "bb")] V50,
    #[serde(rename = "cc")] V51,
    #[serde(rename = "dd")] V52,
    #[serde(rename = "ee")] V53,
    #[serde(rename = "ff")] V54,
    #[serde(rename = "gg")] V55,
    #[serde(rename = "hh")] V56,
    #[serde(rename = "ii")] V57,
    #[serde(rename = "jj")] V58,
    #[serde(rename = "kk")] V59,
    #[serde(rename = "mm")] V60,
    #[serde(rename = "nn")] V61,
    #[serde(rename = "oo")] V62,
    #[serde(rename = "pp")] V63,
    #[serde(rename = "qq")] V64,
    #[serde(rename = "rr")] V65,
    #[serde(rename = "ss")] V66,
    #[serde(rename = "tt")] V67,
    #[serde(rename = "uu")] V68,
    #[serde(rename = "vv")] V69,
    #[serde(rename = "ww")] V70,
    #[serde(rename = "xx")] V71,
    #[serde(rename = "yy")] V72,
    #[serde(rename = "zz")] V73,
    #[serde(rename = "AA")] V74,
    #[serde(rename = "BB")] V75,
    #[serde(rename = "CC")] V76,
    #[serde(rename = "DD")] V77,
    #[serde(rename = "EE")] V78,
    #[serde(rename = "FF")] V79,
    #[serde(rename = "HH")] V80,
    #[serde(rename = "II")] V81,
    #[serde(rename = "JJ")] V82,
    #[serde(rename = "KK")] V83,
    #[serde(rename = "LL")] V84,
    #[serde(rename = "OO")] V85,
    #[serde(rename = "PP")] V86,
    #[serde(rename = "QQ")] V87,
    #[serde(rename = "RR")] V88,
    #[serde(rename = "TT")] V89,
    #[serde(rename = "UU")] V90,
    #[serde(rename = "VV")] V91,
    #[serde(rename = "WW")] V92,
    #[serde(rename = "XX")] V93,
    #[serde(rename = "YY")] V94,
    #[serde(rename = "ZZ")] V95,
    #[serde(rename = "aaa")] V96,
    #[serde(rename = "bbb")] V97,
    #[serde(rename = "ccc")] V98,
    #[serde(rename = "fff")] V99,
    #[serde(rename = "ggg")] V100,
    #[serde(rename = "hhh")] V101,
    #[serde(rename = "iii")] V102,
    #[serde(rename = "jjj")] V103,
    #[serde(rename = "kkk")] V104,
    #[serde(rename = "lll")] V105,
    #[serde(rename = "mmm")] V106,
    #[serde(rename = "nnn")] V107,
    #[serde(rename = "ooo")] V108,
    #[serde(rename = "ppp")] V109,
    #[serde(rename = "qqq")] V110,
    #[serde(rename = "rrr")] V111,
    #[serde(rename = "sss")] V112,
    #[serde(rename = "ttt")] V113,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam4 {
    #[serde(rename = "a")] V0 { x: u8 },
    #[serde(rename = "b")] V1 { x: u8 },
    #[serde(rename = "c")] V2 { x: u8 },
    #[serde(rename = "d")] V3 { x: u8 },
    #[serde(rename = "e")] V4 { x: u8 },
    #[serde(rename = "f")] V5 { x: u8 },
    #[serde(rename = "g")] V6 { x: u8 },
    #[serde(rename = "h")] V7 { x: u8 },
    #[serde(rename = "j")] V8 { x: u8 },
    #[serde(rename = "k")] V9 { x: u8 },
    #[serde(rename = "l")] V10 { x: u8 },
    #[serde(rename = "m")] V11 { x: u8 },
    #[serde(rename = "n")] V12 { x: u8 },
    #[serde(rename = "o")] V13 { x: u8 },
    #[serde(rename = "p")] V14 { x: u8 },
    #[serde(rename = "q")] V15 { x: u8 },
    #[serde(rename = "r")] V16 { x: u8 },
    #[serde(rename = "s")] V17 { x: u8 },
    #[serde(rename = "t")] V18 { x: u8 },
    #[serde(rename = "u")] V19 { x: u8 },
    #[serde(rename = "v")] V20 { x: u8 },
    #[serde(rename = "w")] V21 { x: u8 },
    #[serde(rename = "x")] V22 { x: u8 },
    #[serde(rename = "y")] V23 { x: u8 },
    #[serde(rename = "z")] V24 { x: u8 },
    #[serde(rename = "A")] V25 { x: u8 },
    #[serde(rename = "B")] V26 { x: u8 },
    #[serde(rename = "C")] V27 { x: u8 },
    #[serde(rename = "D")] V28 { x: u8 },
    #[serde(rename = "E")] V29 { x: u8 },
    #[serde(rename = "F")] V30 { x: u8 },
    #[serde(rename = "G")] V31 { x: u8 },
    #[serde(rename = "H")] V32 { x: u8 },
    #[serde(rename = "I")] V33 { x: u8 },
    #[serde(rename = "J")] V34 { x: u8 },
    #[serde(rename = "K")] V35 { x: u8 },
    #[serde(rename = "L")] V36 { x: u8 },
    #[serde(rename = "M")] V37 { x: u8 },
    #[serde(rename = "N")] V38 { x: u8 },
    #[serde(rename = "O")] V39 { x: u8 },
    #[serde(rename = "P")] V40 { x: u8 },
    #[serde(rename = "Q")] V41 { x: u8 },
    #[serde(rename = "R")] V42 { x: u8 },
    #[serde(rename = "S")] V43 { x: u8 },
    #[serde(rename = "T")] V44 { x: u8 },
    #[serde(rename = "W")] V45 { x: u8 },
    #[serde(rename = "X")] V46 { x: u8 },
    #[serde(rename = "Y")] V47 { x: u8 },
    #[serde(rename = "Z")] V48 { x: u8 },
    #[serde(rename = "aa")] V49 { x: u8 },
    #[serde(rename = "bb")] V50 { x: u8 },
    #[serde(rename = "cc")] V51 { x: u8 },
    #[serde(rename = "dd")] V52 { x: u8 },
    #[serde(rename = "ee")] V53 { x: u8 },
    #[serde(rename = "ff")] V54 { x: u8 },
    #[serde(rename = "gg")] V55 { x: u8 },
    #[serde(rename = "hh")] V56 { x: u8 },
    #[serde(rename = "ii")] V57 { x: u8 },
    #[serde(rename = "jj")] V58 { x: u8 },
    #[serde(rename = "kk")] V59 { x: u8 },
    #[serde(rename = "mm")] V60 { x: u8 },
    #[serde(rename = "nn")] V61 { x: u8 },
    #[serde(rename = "oo")] V62 { x: u8 },
    #[serde(rename = "pp")] V63 { x: u8 },
    #[serde(rename = "qq")] V64 { x: u8 },
    #[serde(rename = "rr")] V65 { x: u8 },
    #[serde(rename = "ss")] V66 { x: u8 },
    #[serde(rename = "tt")] V67 { x: u8 },
    #[serde(rename = "uu")] V68 { x: u8 },
    #[serde(rename = "vv")] V69 { x: u8 },
    #[serde(rename = "ww")] V70 { x: u8 },
    #[serde(rename = "xx")] V71 { x: u8 },
    #[serde(rename = "yy")] V72 { x: u8 },
    #[serde(rename = "zz")] V73 { x: u8 },
    #[serde(rename = "AA")] V74 { x: u8 },
    #[serde(rename = "BB")] V75 { x: u8 },
    #[serde(rename = "CC")] V76 { x: u8 },
    #[serde(rename = "DD")] V77 { x: u8 },
    #[serde(rename = "EE")] V78 { x: u8 },
    #[serde(rename = "FF")] V79 { x: u8 },
    #[serde(rename = "HH")] V80 { x: u8 },
    #[serde(rename = "II")] V81 { x: u8 },
    #[serde(rename = "JJ")] V82 { x: u8 },
    #[serde(rename = "KK")] V83 { x: u8 },
    #[serde(rename = "LL")] V84 { x: u8 },
    #[serde(rename = "OO")] V85 { x: u8 },
    #[serde(rename = "PP")] V86 { x: u8 },
    #[serde(rename = "QQ")] V87 { x: u8 },
    #[serde(rename = "RR")] V88 { x: u8 },
    #[serde(rename = "TT")] V89 { x: u8 },
    #[serde(rename = "UU")] V90 { x: u8 },
    #[serde(rename = "VV")] V91 { x: u8 },
    #[serde(rename = "WW")] V92 { x: u8 },
    #[serde(rename = "XX")] V93 { x: u8 },
    #[serde(rename = "YY")] V94 { x: u8 },
    #[serde(rename = "ZZ")] V95 { x: u8 },
    #[serde(rename = "aaa")] V96 { x: u8 },
    #[serde(rename = "bbb")] V97 { x: u8 },
    #[serde(rename = "ccc")] V98 { x: u8 },
    #[serde(rename = "fff")] V99 { x: u8 },
    #[serde(rename = "ggg")] V100 { x: u8 },
    #[serde(rename = "hhh")] V101 { x: u8 },
    #[serde(rename = "iii")] V102 { x: u8 },
    #[serde(rename = "jjj")] V103 { x: u8 },
    #[serde(rename = "kkk")] V104 { x: u8 },
    #[serde(rename = "lll")] V105 { x: u8 },
    #[serde(rename = "mmm")] V106 { x: u8 },
    #[serde(rename = "nnn")] V107 { x: u8 },
    #[serde(rename = "ooo")] V108 { x: u8 },
    #[serde(rename = "ppp")] V109 { x: u8 },
    #[serde(rename = "qqq")] V110 { x: u8 },
    #[serde(rename = "rrr")] V111 { x: u8 },
    #[serde(rename = "sss")] V112 { x: u8 },
    #[serde(rename = "ttt")] V113 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam5 {
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
enum TagEnumFam5 {
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
enum EnumFam6 {
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
enum TagEnumFam6 {
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
enum EnumFam7 {
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
enum TagEnumFam7 {
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
enum EnumFam8 {
    #[serde(rename = "H")] V0,
    #[serde(rename = "R")] V1,
    #[serde(rename = "S")] V2,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam9 {
    #[serde(rename = "e")] V0,
    #[serde(rename = "x")] V1,
    #[serde(rename = "d")] V2,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam10 {
    #[serde(rename = "e")] V0,
    #[serde(rename = "a")] V1,
    #[serde(rename = "d")] V2,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam11 {
    #[serde(rename = "b")] V0,
    #[serde(rename = "c")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam12 {
    #[serde(rename = "G")] V0,
    #[serde(rename = "P")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam13 {
    #[serde(rename = "D")] V0,
    #[serde(rename = "U")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam14 {
    #[serde(rename = "standaloneOutcome")] V0,
    #[serde(rename = "question")] V1,
    #[serde(rename = "questionOutcome")] V2,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam15 {
    #[serde(rename = "register")] V0,
    #[serde(rename = "changeProfile")] V1,
    #[serde(rename = "unregister")] V2,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam16 {
    #[serde(rename = "normal")] V0,
    #[serde(rename = "noCross")] V1,
    #[serde(rename = "strictIsolated")] V2,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam17 {
    #[serde(rename = "disabled")] V0,
    #[serde(rename = "reduceOnly")] V1,
    #[serde(rename = "enabled")] V2,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam18 {
    #[serde(rename = "create")] V0,
    #[serde(rename = "firstStorageSlot")] V1,
    #[serde(rename = "customStorageSlot")] V2,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam19 {
    #[serde(rename = "yes")] V0,
    #[serde(rename = "no")] V1,
    #[serde(rename = "abstain")] V2,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam20 {
    #[serde(rename = "Ip")] V0,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam21 {
    #[serde(rename = "D")] V0,
    #[serde(rename = "Q")] V1,
    #[serde(rename = "C")] V2,
    #[serde(rename = "P")] V3,
    #[serde(rename = "G")] V4,
    #[serde(rename = "O")] V5,
    #[serde(rename = "E")] V6,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam22 {
    #[serde(rename = "usdtUsdcPx")] V0,
    #[serde(rename = "nativePx")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam23 {
    #[serde(rename = "technical")] V0,
    #[serde(rename = "treasury")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam24 {
    #[serde(rename = "d")] V0,
    #[serde(rename = "v")] V1,
    #[serde(rename = "l")] V2,
    #[serde(rename = "a")] V3,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam25 {
    #[serde(rename = "unjailSelf")] V0,
    #[serde(rename = "jailSelf")] V1,
    #[serde(rename = "voteJail")] V2,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam26 {
    #[serde(rename = "tp")] V0,
    #[serde(rename = "sl")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam27 {
    #[serde(rename = "proxy")] V0,
    #[serde(rename = "setOracle")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam28 {
    #[serde(rename = "activate")] V0,
    #[serde(rename = "deactivate")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam29 {
    #[serde(rename = "hex")] V0,
    #[serde(rename = "base58")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam30 {
    #[serde(rename = "limit")] V0,
    #[serde(rename = "trigger")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam31 {
    #[serde(rename = "Cross")] V0,
    #[serde(rename = "Isolated")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam32 {
    #[serde(rename = "pct")] V0,
    #[serde(rename = "px")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam33 {
    #[serde(rename = "registerAndAssociateNamedOutcomeFromTemplate")] V0,
    #[serde(rename = "registerQuestionFromTemplate")] V1,
    #[serde(rename = "registerStandaloneOutcomeFromTemplate")] V2,
    #[serde(rename = "settleOutcome")] V3,
    #[serde(rename = "settleQuestion")] V4,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam34 {
    #[serde(rename = "Deposit")] V0,
    #[serde(rename = "InvalidatedWithdrawal")] V1,
    #[serde(rename = "RequestedWithdrawal")] V2,
    #[serde(rename = "FinalizedWithdrawal")] V3,
    #[serde(rename = "FinalizedValidatorSetUpdate")] V4,
    #[serde(rename = "RequestedValidatorSetUpdateEvent")] V5,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam35 {
    #[serde(rename = "toggleSpotDusting")] V0,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam36 {
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
enum TagEnumFam36 {
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
enum EnumFam37 {
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
enum TagEnumFam37 {
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
enum EnumFam38 {
    #[serde(rename = "l")] V0,
    #[serde(rename = "L")] V1,
    #[serde(rename = "i")] V2,
    #[serde(rename = "d")] V3,
    #[serde(rename = "b")] V4,
    #[serde(rename = "o")] V5,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam39 {
    #[serde(rename = "modifyApproval")] V0,
    #[serde(rename = "modifyBackstopLiquidatorApproval")] V1,
    #[serde(rename = "setReduceOnly")] V2,
    #[serde(rename = "cancel")] V3,
    #[serde(rename = "cancelAll")] V4,
    #[serde(rename = "order")] V5,
    #[serde(rename = "sendAsset")] V6,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam40 {
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
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam40 {
    #[serde(rename = "fileSnapshot")] V0 { x: u8 },
    #[serde(rename = "webData2")] V1 { x: u8 },
    #[serde(rename = "webData3")] V2 { x: u8 },
    #[serde(rename = "meta")] V3 { x: u8 },
    #[serde(rename = "spotMeta")] V4 { x: u8 },
    #[serde(rename = "outcomeMeta")] V5 { x: u8 },
    #[serde(rename = "outcomeDeployerLimits")] V6 { x: u8 },
    #[serde(rename = "clearinghouseState")] V7 { x: u8 },
    #[serde(rename = "spotClearinghouseState")] V8 { x: u8 },
    #[serde(rename = "openOrders")] V9 { x: u8 },
    #[serde(rename = "exchangeStatus")] V10 { x: u8 },
    #[serde(rename = "frontendOpenOrders")] V11 { x: u8 },
    #[serde(rename = "activeAssetData")] V12 { x: u8 },
    #[serde(rename = "maxMarketOrderNtls")] V13 { x: u8 },
    #[serde(rename = "vaultSummaries")] V14 { x: u8 },
    #[serde(rename = "userVaultEquities")] V15 { x: u8 },
    #[serde(rename = "leadingVaults")] V16 { x: u8 },
    #[serde(rename = "extraAgents")] V17 { x: u8 },
    #[serde(rename = "subAccounts")] V18 { x: u8 },
    #[serde(rename = "subAccounts2")] V19 { x: u8 },
    #[serde(rename = "userFees")] V20 { x: u8 },
    #[serde(rename = "userRateLimit")] V21 { x: u8 },
    #[serde(rename = "spotDeployState")] V22 { x: u8 },
    #[serde(rename = "spotPairDeployAuctionStatus")] V23 { x: u8 },
    #[serde(rename = "perpDeployAuctionStatus")] V24 { x: u8 },
    #[serde(rename = "votes")] V25 { x: u8 },
    #[serde(rename = "delegations")] V26 { x: u8 },
    #[serde(rename = "delegatorSummary")] V27 { x: u8 },
    #[serde(rename = "maxBuilderFee")] V28 { x: u8 },
    #[serde(rename = "userToMultiSigSigners")] V29 { x: u8 },
    #[serde(rename = "userRole")] V30 { x: u8 },
    #[serde(rename = "perpsAtOpenInterestCap")] V31 { x: u8 },
    #[serde(rename = "perpDexLimits")] V32 { x: u8 },
    #[serde(rename = "validatorL1Votes")] V33 { x: u8 },
    #[serde(rename = "marginTable")] V34 { x: u8 },
    #[serde(rename = "perpDexs")] V35 { x: u8 },
    #[serde(rename = "allPerpMetas")] V36 { x: u8 },
    #[serde(rename = "userDexAbstraction")] V37 { x: u8 },
    #[serde(rename = "perpDexStatus")] V38 { x: u8 },
    #[serde(rename = "borrowLendUserState")] V39 { x: u8 },
    #[serde(rename = "borrowLendReserveState")] V40 { x: u8 },
    #[serde(rename = "allBorrowLendReserveStates")] V41 { x: u8 },
    #[serde(rename = "userAbstraction")] V42 { x: u8 },
    #[serde(rename = "perpAnnotation")] V43 { x: u8 },
    #[serde(rename = "perpCategories")] V44 { x: u8 },
    #[serde(rename = "perpConciseAnnotations")] V45 { x: u8 },
    #[serde(rename = "tokenAnnotation")] V46 { x: u8 },
    #[serde(rename = "tokenConciseAnnotations")] V47 { x: u8 },
    #[serde(rename = "settledOutcome")] V48 { x: u8 },
    #[serde(rename = "settledQuestion")] V49 { x: u8 },
    #[serde(rename = "approvedBuilders")] V50 { x: u8 },
    #[serde(rename = "gossipPriorityAuctionStatus")] V51 { x: u8 },
    #[serde(rename = "outcomeTemplates")] V52 { x: u8 },
    #[serde(rename = "aqav2InterestHistory")] V53 { x: u8 },
    #[serde(rename = "userStarState")] V54 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam41 {
    #[serde(rename = "e")] V0,
    #[serde(rename = "r")] V1,
    #[serde(rename = "b")] V2,
    #[serde(rename = "btp")] V3,
    #[serde(rename = "P")] V4,
    #[serde(rename = "Ps")] V5,
    #[serde(rename = "mu")] V6,
    #[serde(rename = "f")] V7,
    #[serde(rename = "t")] V8,
    #[serde(rename = "dp")] V9,
    #[serde(rename = "du")] V10,
    #[serde(rename = "pmv")] V11,
    #[serde(rename = "pma")] V12,
    #[serde(rename = "pmu")] V13,
    #[serde(rename = "rl")] V14,
    #[serde(rename = "mbs")] V15,
    #[serde(rename = "adl")] V16,
    #[serde(rename = "ri")] V17,
}
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum TagEnumFam41 {
    #[serde(rename = "e")] V0 { x: u8 },
    #[serde(rename = "r")] V1 { x: u8 },
    #[serde(rename = "b")] V2 { x: u8 },
    #[serde(rename = "btp")] V3 { x: u8 },
    #[serde(rename = "P")] V4 { x: u8 },
    #[serde(rename = "Ps")] V5 { x: u8 },
    #[serde(rename = "mu")] V6 { x: u8 },
    #[serde(rename = "f")] V7 { x: u8 },
    #[serde(rename = "t")] V8 { x: u8 },
    #[serde(rename = "dp")] V9 { x: u8 },
    #[serde(rename = "du")] V10 { x: u8 },
    #[serde(rename = "pmv")] V11 { x: u8 },
    #[serde(rename = "pma")] V12 { x: u8 },
    #[serde(rename = "pmu")] V13 { x: u8 },
    #[serde(rename = "rl")] V14 { x: u8 },
    #[serde(rename = "mbs")] V15 { x: u8 },
    #[serde(rename = "adl")] V16 { x: u8 },
    #[serde(rename = "ri")] V17 { x: u8 },
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam42 {
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
enum TagEnumFam42 {
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
enum EnumFam43 {
    #[serde(rename = "dateTime")] V0,
    #[serde(rename = "date")] V1,
    #[serde(rename = "string")] V2,
    #[serde(rename = "shortString")] V3,
    #[serde(rename = "hlPerp")] V4,
    #[serde(rename = "uInt")] V5,
    #[serde(rename = "uDecimal")] V6,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam44 {
    #[serde(rename = "splitOutcome")] V0,
    #[serde(rename = "mergeOutcome")] V1,
    #[serde(rename = "mergeQuestion")] V2,
    #[serde(rename = "negateOutcome")] V3,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam45 {
    #[serde(rename = "referrerStates")] V0,
    #[serde(rename = "l4Snapshots")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam46 {
    #[serde(rename = "Alo")] V0,
    #[serde(rename = "Ioc")] V1,
    #[serde(rename = "Gtc")] V2,
    #[serde(rename = "FrontendMarket")] V3,
    #[serde(rename = "LiquidationMarket")] V4,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam47 {
    #[serde(rename = "StandaloneOutcome")] V0,
    #[serde(rename = "Question")] V1,
    #[serde(rename = "QuestionOutcome")] V2,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam48 {
    #[serde(rename = "accelerated")] V0,
    #[serde(rename = "constitutional")] V1,
    #[serde(rename = "ecosystem")] V2,
    #[serde(rename = "electoral")] V3,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam49 {
    #[serde(rename = "Requested")] V0,
    #[serde(rename = "TradingUser")] V1,
    #[serde(rename = "StakingUser")] V2,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam50 {
    #[serde(rename = "Perp")] V0,
    #[serde(rename = "Spot")] V1,
    #[serde(rename = "Token")] V2,
    #[serde(rename = "Pdi")] V3,
    #[serde(rename = "ActivateDexAbstraction")] V4,
    #[serde(rename = "ActivateUnifiedAccount")] V5,
    #[serde(rename = "AllBoleTokens")] V6,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam51 {
    #[serde(rename = "normal")] V0,
    #[serde(rename = "child")] V1,
    #[serde(rename = "parent")] V2,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam52 {
    #[serde(rename = "enabled")] V0,
    #[serde(rename = "disabled")] V1,
    #[serde(rename = "blocked")] V2,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam53 {
    #[serde(rename = "C")] V0,
    #[serde(rename = "Cross")] V1,
    #[serde(rename = "I")] V2,
    #[serde(rename = "Isolated")] V3,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam54 {
    #[serde(rename = "Oracle")] V0,
    #[serde(rename = "ReferenceOracle")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam55 {
    #[serde(rename = "Spot")] V0,
    #[serde(rename = "Mark")] V1,
    #[serde(rename = "ExternalPerp")] V2,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam56 {
    #[serde(rename = "B")] V0,
    #[serde(rename = "Bid")] V1,
    #[serde(rename = "A")] V2,
    #[serde(rename = "Ask")] V3,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam57 {
    #[serde(rename = "Evm")] V0,
    #[serde(rename = "Broadcaster")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam58 {
    #[serde(rename = "borrow")] V0,
    #[serde(rename = "supply")] V1,
    #[serde(rename = "repay")] V2,
    #[serde(rename = "withdraw")] V3,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam59 {
    #[serde(rename = "na")] V0,
    #[serde(rename = "normalTpsl")] V1,
    #[serde(rename = "positionTpsl")] V2,
    #[serde(rename = "p")] V3,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam60 {
    #[serde(rename = "Enabled")] V0,
    #[serde(rename = "Disabled")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam61 {
    #[serde(rename = "Local")] V0,
    #[serde(rename = "Sandbox")] V1,
    #[serde(rename = "Testnet")] V2,
    #[serde(rename = "Mainnet")] V3,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam62 {
    #[serde(rename = "Pct")] V0,
    #[serde(rename = "Px")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam63 {
    #[serde(rename = "Reth115")] V0,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam64 {
    #[serde(rename = "NoEvmDb")] V0,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam65 {
    #[serde(rename = "Main")] V0,
    #[serde(rename = "Hip3")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam66 {
    #[serde(rename = "s")] V0,
    #[serde(rename = "p")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam67 {
    #[serde(rename = "Q")] V0,
    #[serde(rename = "N")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam68 {
    #[serde(rename = "s")] V0,
    #[serde(rename = "v")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam69 {
    #[serde(rename = "s")] V0,
    #[serde(rename = "t")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam70 {
    #[serde(rename = "v")] V0,
    #[serde(rename = "o")] V1,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam71 {
    #[serde(rename = "Na")] V0,
    #[serde(rename = "UserDisabled")] V1,
    #[serde(rename = "ValidatorDisabled")] V2,
    #[serde(rename = "m")] V3,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam72 {
    #[serde(rename = "Legacy")] V0,
    #[serde(rename = "Eip2930")] V1,
    #[serde(rename = "Eip1559")] V2,
    #[serde(rename = "Eip4844")] V3,
    #[serde(rename = "Eip7702")] V4,
}
#[derive(serde::Deserialize, Debug)]
enum EnumFam73 {
    #[serde(rename = "Ok")] V0,
    #[serde(rename = "OutOfGas")] V1,
    #[serde(rename = "Error")] V2,
    #[serde(rename = "UnexpectedError")] V3,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam0 {
    #[serde(rename = "a")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam1 {
    #[serde(rename = "g")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam2 {
    #[serde(rename = "b")] f0: u8,
    #[serde(rename = "f")] f1: u8,
    #[serde(rename = "s")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam3 {
    #[serde(rename = "profile")] f0: u8,
    #[serde(rename = "unjailed")] f1: u8,
    #[serde(rename = "initial_wei")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam4 {
    #[serde(rename = "oraclePxs")] f0: u8,
    #[serde(rename = "externalPerpPxs")] f1: u8,
    #[serde(rename = "scalarUpdates")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam5 {
    #[serde(rename = "cancels")] f0: u8,
    #[serde(rename = "f")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam6 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "signatures")] f1: u8,
    #[serde(rename = "payload")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam7 {
    #[serde(rename = "b")] f0: u8,
    #[serde(rename = "s")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam8 {
    #[serde(rename = "u")] f0: u8,
    #[serde(rename = "a")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam9 {
    #[serde(rename = "childVaultAddresses")] f0: u8,
    #[serde(rename = "assets")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam10 {
    #[serde(rename = "t")] f0: u8,
    #[serde(rename = "w")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam11 {
    #[serde(rename = "validatorsAndSignatures")] f0: u8,
    #[serde(rename = "newActiveEpoch")] f1: u8,
    #[serde(rename = "nonce")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam12 {
    #[serde(rename = "n")] f0: u8,
    #[serde(rename = "p")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam13 {
    #[serde(rename = "v")] f0: u8,
    #[serde(rename = "n")] f1: u8,
    #[serde(rename = "d")] f2: u8,
    #[serde(rename = "c")] f3: u8,
    #[serde(rename = "l")] f4: u8,
    #[serde(rename = "a")] f5: u8,
    #[serde(rename = "w")] f6: u8,
    #[serde(rename = "p")] f7: u8,
    #[serde(rename = "s")] f8: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam14 {
    #[serde(rename = "n")] f0: u8,
    #[serde(rename = "m")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam15 {
    #[serde(rename = "m")] f0: u8,
    #[serde(rename = "n")] f1: u8,
    #[serde(rename = "r")] f2: u8,
    #[serde(rename = "k")] f3: u8,
    #[serde(rename = "c")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam16 {
    #[serde(rename = "t")] f0: u8,
    #[serde(rename = "s")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam17 {
    #[serde(rename = "user")] f0: u8,
    #[serde(rename = "defaultLiquidator")] f1: u8,
    #[serde(rename = "request")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam18 {
    #[serde(rename = "multiSigUser")] f0: u8,
    #[serde(rename = "outerSigner")] f1: u8,
    #[serde(rename = "action")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam19 {
    #[serde(rename = "orders")] f0: u8,
    #[serde(rename = "grouping")] f1: u8,
    #[serde(rename = "builder")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam20 {
    #[serde(rename = "code")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam21 {
    #[serde(rename = "operation")] f0: u8,
    #[serde(rename = "token")] f1: u8,
    #[serde(rename = "amount")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam22 {
    #[serde(rename = "height")] f0: u8,
    #[serde(rename = "abciDigest")] f1: u8,
    #[serde(rename = "signature")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam23 {
    #[serde(rename = "dex")] f0: u8,
    #[serde(rename = "ntl")] f1: u8,
    #[serde(rename = "isDeposit")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam24 {
    #[serde(rename = "oid")] f0: u8,
    #[serde(rename = "order")] f1: u8,
    #[serde(rename = "a")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam25 {
    #[serde(rename = "height")] f0: u8,
    #[serde(rename = "l1Hash")] f1: u8,
    #[serde(rename = "signature")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam26 {
    #[serde(rename = "validatorSet")] f0: u8,
    #[serde(rename = "signature")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam27 {
    #[serde(rename = "slotId")] f0: u8,
    #[serde(rename = "ip")] f1: u8,
    #[serde(rename = "maxGas")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam28 {
    #[serde(rename = "twap")] f0: u8,
    #[serde(rename = "details")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam29 {
    #[serde(rename = "user")] f0: u8,
    #[serde(rename = "usd")] f1: u8,
    #[serde(rename = "ethId")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam30 {
    #[serde(rename = "d")] f0: u8,
    #[serde(rename = "s")] f1: u8,
    #[serde(rename = "i")] f2: u8,
    #[serde(rename = "m")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam31 {
    #[serde(rename = "subAccountUser")] f0: u8,
    #[serde(rename = "isDeposit")] f1: u8,
    #[serde(rename = "usd")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam32 {
    #[serde(rename = "vaultAddress")] f0: u8,
    #[serde(rename = "isDeposit")] f1: u8,
    #[serde(rename = "usd")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam33 {
    #[serde(rename = "asset")] f0: u8,
    #[serde(rename = "isCross")] f1: u8,
    #[serde(rename = "leverage")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam34 {
    #[serde(rename = "destination")] f0: u8,
    #[serde(rename = "token")] f1: u8,
    #[serde(rename = "wei")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam35 {
    #[serde(rename = "asset")] f0: u8,
    #[serde(rename = "isBuy")] f1: u8,
    #[serde(rename = "ntli")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam36 {
    #[serde(rename = "asset")] f0: u8,
    #[serde(rename = "leverage")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam37 {
    #[serde(rename = "usdtUsdcPx")] f0: u8,
    #[serde(rename = "nativePx")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam38 {
    #[serde(rename = "a")] f0: u8,
    #[serde(rename = "asset")] f1: u8,
    #[serde(rename = "t")] f2: u8,
    #[serde(rename = "twapId")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam39 {
    #[serde(rename = "vaultAddress")] f0: u8,
    #[serde(rename = "allowDeposits")] f1: u8,
    #[serde(rename = "alwaysCloseOnWithdraw")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam40 {
    #[serde(rename = "maxFeeRate")] f0: u8,
    #[serde(rename = "builder")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam41 {
    #[serde(rename = "v")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam42 {
    #[serde(rename = "weight")] f0: u8,
    #[serde(rename = "destination")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam43 {
    #[serde(rename = "operation")] f0: u8,
    #[serde(rename = "token")] f1: u8,
    #[serde(rename = "wei")] f2: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam44 {
    #[serde(rename = "asset")] f0: u8,
    #[serde(rename = "cloid")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam45 {
    #[serde(rename = "subAccountUser")] f0: u8,
    #[serde(rename = "name")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam46 {
    #[serde(rename = "vaultAddress")] f0: u8,
    #[serde(rename = "usd")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam47 {
    #[serde(rename = "signer")] f0: u8,
    #[serde(rename = "jail_until")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam48 {
    #[serde(rename = "modifies")] f0: u8,
    #[serde(rename = "a")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam49 {
    #[serde(rename = "ntl")] f0: u8,
    #[serde(rename = "toPerp")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam50 {
    #[serde(rename = "frozenUser")] f0: u8,
    #[serde(rename = "token")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam51 {
    #[serde(rename = "t")] f0: u8,
    #[serde(rename = "p")] f1: u8,
    #[serde(rename = "P")] f2: u8,
    #[serde(rename = "c")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam53 {
    #[serde(rename = "data")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam54 {
    #[serde(rename = "a")] f0: u8,
    #[serde(rename = "asset")] f1: u8,
    #[serde(rename = "o")] f2: u8,
    #[serde(rename = "oid")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam55 {
    #[serde(rename = "token")] f0: u8,
    #[serde(rename = "input")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam56 {
    #[serde(rename = "token")] f0: u8,
    #[serde(rename = "role")] f1: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam57 {
    #[serde(rename = "venueName")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam58 {
    #[serde(rename = "nonce")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam59 {
    #[serde(rename = "validatorSet")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam60 {
    #[serde(rename = "wei")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam61 {
    #[serde(rename = "action")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam62 {
    #[serde(rename = "displayName")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam63 {
    #[serde(rename = "riskFreeRate")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam64 {
    #[serde(rename = "name")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam65 {
    #[serde(rename = "optOut")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam66 {
    #[serde(rename = "abstraction")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam67 {
    #[serde(rename = "time")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam68 {
    #[serde(rename = "usingBigBlocks")] f0: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam69 {
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
#[serde(deny_unknown_fields)]
struct StructFam71 {
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
#[serde(deny_unknown_fields)]
struct StructFam72 {
    #[serde(rename = "node_ip")] f0: u8,
    #[serde(rename = "name")] f1: u8,
    #[serde(rename = "description")] f2: u8,
    #[serde(rename = "unjailed")] f3: u8,
    #[serde(rename = "disable_delegations")] f4: u8,
    #[serde(rename = "commission_bps")] f5: u8,
    #[serde(rename = "signer")] f6: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam73 {
    #[serde(rename = "token")] f0: u8,
    #[serde(rename = "technicalStaker")] f1: u8,
    #[serde(rename = "treasuryStaker")] f2: u8,
    #[serde(rename = "treasuryEvmAddress")] f3: u8,
    #[serde(rename = "evmRebalanceContract")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam74 {
    #[serde(rename = "destination")] f0: u8,
    #[serde(rename = "fromSubAccount")] f1: u8,
    #[serde(rename = "sourceDexOrSpot")] f2: u8,
    #[serde(rename = "destinationDexOrSpot")] f3: u8,
    #[serde(rename = "token")] f4: u8,
    #[serde(rename = "wei")] f5: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam75 {
    #[serde(rename = "destination")] f0: u8,
    #[serde(rename = "sourceDex")] f1: u8,
    #[serde(rename = "destinationDex")] f2: u8,
    #[serde(rename = "token")] f3: u8,
    #[serde(rename = "amount")] f4: u8,
    #[serde(rename = "fromSubAccount")] f5: u8,
    #[serde(rename = "nonce")] f6: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam76 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "validator")] f2: u8,
    #[serde(rename = "wei")] f3: u8,
    #[serde(rename = "isUndelegate")] f4: u8,
    #[serde(rename = "nonce")] f5: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam77 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "title")] f2: u8,
    #[serde(rename = "description")] f3: u8,
    #[serde(rename = "category")] f4: u8,
    #[serde(rename = "nonce")] f5: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam78 {
    #[serde(rename = "perpAddBaseRate")] f0: u8,
    #[serde(rename = "perpCrossBaseRate")] f1: u8,
    #[serde(rename = "spotAddBaseRate")] f2: u8,
    #[serde(rename = "spotCrossBaseRate")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam79 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "destination")] f2: u8,
    #[serde(rename = "token")] f3: u8,
    #[serde(rename = "amount")] f4: u8,
    #[serde(rename = "time")] f5: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam80 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "agentAddress")] f2: u8,
    #[serde(rename = "agentName")] f3: u8,
    #[serde(rename = "nonce")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam81 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "maxFeeRate")] f2: u8,
    #[serde(rename = "builder")] f3: u8,
    #[serde(rename = "nonce")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam82 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "extendLongTermStaking")] f2: u8,
    #[serde(rename = "nonce")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam83 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "destination")] f2: u8,
    #[serde(rename = "amount")] f3: u8,
    #[serde(rename = "time")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam84 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "user")] f2: u8,
    #[serde(rename = "abstraction")] f3: u8,
    #[serde(rename = "nonce")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam85 {
    #[serde(rename = "validator")] f0: u8,
    #[serde(rename = "signature")] f1: u8,
    #[serde(rename = "coldUser")] f2: u8,
    #[serde(rename = "coldUserSignature")] f3: u8,
    #[serde(rename = "nonce")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam86 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "user")] f2: u8,
    #[serde(rename = "isFinalize")] f3: u8,
    #[serde(rename = "nonce")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam87 {
    #[serde(rename = "asset")] f0: u8,
    #[serde(rename = "isBuy")] f1: u8,
    #[serde(rename = "sz")] f2: u8,
    #[serde(rename = "reduceOnly")] f3: u8,
    #[serde(rename = "retracement")] f4: u8,
    #[serde(rename = "activationPx")] f5: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam88 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "amount")] f2: u8,
    #[serde(rename = "toPerp")] f3: u8,
    #[serde(rename = "nonce")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam89 {
    #[serde(rename = "coin")] f0: u8,
    #[serde(rename = "szDecimals")] f1: u8,
    #[serde(rename = "oraclePx")] f2: u8,
    #[serde(rename = "marginTableId")] f3: u8,
    #[serde(rename = "onlyIsolated")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam90 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "user")] f2: u8,
    #[serde(rename = "enabled")] f3: u8,
    #[serde(rename = "nonce")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam91 {
    #[serde(rename = "coin")] f0: u8,
    #[serde(rename = "szDecimals")] f1: u8,
    #[serde(rename = "oraclePx")] f2: u8,
    #[serde(rename = "marginTableId")] f3: u8,
    #[serde(rename = "marginMode")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam92 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "id")] f2: u8,
    #[serde(rename = "choice")] f3: u8,
    #[serde(rename = "nonce")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam93 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "tradingUser")] f2: u8,
    #[serde(rename = "nonce")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam94 {
    #[serde(rename = "name")] f0: u8,
    #[serde(rename = "description")] f1: u8,
    #[serde(rename = "initialUsd")] f2: u8,
    #[serde(rename = "nonce")] f3: u8,
    #[serde(rename = "maxUsdcFee")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam95 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "signers")] f2: u8,
    #[serde(rename = "nonce")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam96 {
    #[serde(rename = "signatureChainId")] f0: u8,
    #[serde(rename = "hyperliquidChain")] f1: u8,
    #[serde(rename = "wei")] f2: u8,
    #[serde(rename = "nonce")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam97 {
    #[serde(rename = "user")] f0: u8,
    #[serde(rename = "destination")] f1: u8,
    #[serde(rename = "usd")] f2: u8,
    #[serde(rename = "nonce")] f3: u8,
    #[serde(rename = "signature")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam98 {
    #[serde(rename = "user")] f0: u8,
    #[serde(rename = "destination")] f1: u8,
    #[serde(rename = "nonce")] f2: u8,
    #[serde(rename = "usd")] f3: u8,
    #[serde(rename = "ethTxHash")] f4: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam99 {
    #[serde(rename = "pxs")] f0: u8,
    #[serde(rename = "externalPerpPxs")] f1: u8,
    #[serde(rename = "usdtUsdcPx")] f2: u8,
    #[serde(rename = "nativePx")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam100 {
    #[serde(rename = "subAccountUser")] f0: u8,
    #[serde(rename = "isDeposit")] f1: u8,
    #[serde(rename = "token")] f2: u8,
    #[serde(rename = "amount")] f3: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam101 {
    #[serde(rename = "pmdl")] f0: u8,
    #[serde(rename = "pmln")] f1: u8,
    #[serde(rename = "pmbm")] f2: u8,
    #[serde(rename = "ubgln")] f3: u8,
    #[serde(rename = "ubglm")] f4: u8,
    #[serde(rename = "ubuln")] f5: u8,
    #[serde(rename = "ubulm")] f6: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam102 {
    #[serde(rename = "t")] f0: u8,
    #[serde(rename = "l")] f1: u8,
    #[serde(rename = "y")] f2: u8,
    #[serde(rename = "b")] f3: u8,
    #[serde(rename = "s")] f4: u8,
    #[serde(rename = "ub")] f5: u8,
    #[serde(rename = "us")] f6: u8,
    #[serde(rename = "Mp")] f7: u8,
    #[serde(rename = "mp")] f8: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam103 {
    #[serde(rename = "d")] f0: u8,
    #[serde(rename = "D")] f1: u8,
    #[serde(rename = "r")] f2: u8,
    #[serde(rename = "w")] f3: u8,
    #[serde(rename = "e")] f4: u8,
    #[serde(rename = "b")] f5: u8,
    #[serde(rename = "m")] f6: u8,
    #[serde(rename = "a")] f7: u8,
    #[serde(rename = "A")] f8: u8,
}
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StructFam105 {
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
#[serde(deny_unknown_fields)]
struct StructFam106 {
    #[serde(rename = "balance")] f0: u8,
    #[serde(rename = "nonce")] f1: u8,
    #[serde(rename = "code")] f2: u8,
    #[serde(rename = "state")] f3: u8,
    #[serde(rename = "stateDiff")] f4: u8,
    #[serde(rename = "MovePrecompileToAddress")] f5: u8,
    #[serde(rename = "movePrecompileToAddress")] f6: u8,
}
fn main() {
    let s = std::env::args().nth(1).unwrap_or_default();
    let b = s.as_bytes();
    if s == "run" {
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam0>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam0>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam0>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam0>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam0>(&s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam1>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam1>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam1>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam2>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam2>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam2>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam3>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam3>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam3>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam3>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam3>(&s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam4>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam4>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam4>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam4>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam4>(&s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam5>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam5>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam5>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam5>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam5>(&s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam6>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam6>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam6>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam6>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam6>(&s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam7>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam7>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam7>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam7>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam7>(&s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam8>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam8>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam8>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam9>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam9>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam9>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam10>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam10>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam10>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam11>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam11>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam11>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam12>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam12>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam12>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam13>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam13>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam13>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam14>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam14>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam14>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam15>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam15>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam15>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam16>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam16>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam16>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam17>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam17>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam17>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam18>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam18>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam18>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam19>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam19>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam19>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam20>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam20>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam20>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam21>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam21>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam21>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam22>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam22>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam22>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam23>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam23>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam23>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam24>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam24>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam24>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam25>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam25>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam25>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam26>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam26>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam26>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam27>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam27>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam27>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam28>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam28>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam28>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam29>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam29>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam29>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam30>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam30>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam30>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam31>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam31>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam31>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam32>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam32>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam32>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam33>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam33>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam33>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam34>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam34>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam34>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam35>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam35>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam35>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam36>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam36>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam36>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam36>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam36>(&s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam37>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam37>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam37>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam37>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam37>(&s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam38>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam38>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam38>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam39>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam39>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam39>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam40>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam40>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam40>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam40>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam40>(&s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam41>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam41>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam41>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam41>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam41>(&s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam42>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam42>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam42>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<TagEnumFam42>(b));
    let _ = core::hint::black_box(serde_json::from_str::<TagEnumFam42>(&s));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam43>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam43>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam43>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam44>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam44>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam44>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam45>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam45>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam45>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam46>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam46>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam46>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam47>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam47>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam47>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam48>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam48>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam48>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam49>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam49>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam49>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam50>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam50>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam50>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam51>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam51>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam51>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam52>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam52>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam52>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam53>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam53>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam53>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam54>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam54>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam54>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam55>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam55>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam55>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam56>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam56>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam56>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam57>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam57>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam57>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam58>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam58>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam58>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam59>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam59>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam59>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam60>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam60>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam60>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam61>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam61>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam61>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam62>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam62>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam62>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam63>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam63>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam63>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam64>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam64>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam64>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam65>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam65>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam65>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam66>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam66>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam66>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam67>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam67>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam67>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam68>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam68>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam68>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam69>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam69>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam69>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam70>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam70>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam70>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam71>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam71>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam71>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam72>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam72>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam72>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<EnumFam73>(b));
    let _ = core::hint::black_box(serde_json::from_str::<EnumFam73>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<EnumFam73>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam0>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam0>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam0>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam1>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam1>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam1>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam2>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam2>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam2>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam3>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam3>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam3>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam4>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam4>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam4>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam5>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam5>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam5>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam6>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam6>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam6>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam7>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam7>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam7>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam8>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam8>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam8>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam9>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam9>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam9>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam10>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam10>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam10>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam11>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam11>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam11>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam12>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam12>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam12>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam13>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam13>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam13>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam14>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam14>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam14>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam15>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam15>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam15>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam16>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam16>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam16>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam17>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam17>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam17>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam18>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam18>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam18>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam19>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam19>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam19>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam20>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam20>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam20>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam21>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam21>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam21>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam22>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam22>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam22>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam23>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam23>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam23>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam24>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam24>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam24>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam25>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam25>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam25>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam26>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam26>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam26>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam27>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam27>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam27>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam28>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam28>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam28>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam29>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam29>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam29>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam30>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam30>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam30>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam31>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam31>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam31>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam32>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam32>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam32>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam33>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam33>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam33>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam34>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam34>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam34>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam35>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam35>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam35>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam36>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam36>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam36>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam37>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam37>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam37>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam38>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam38>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam38>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam39>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam39>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam39>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam40>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam40>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam40>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam41>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam41>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam41>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam42>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam42>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam42>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam43>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam43>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam43>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam44>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam44>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam44>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam45>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam45>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam45>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam46>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam46>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam46>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam47>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam47>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam47>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam48>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam48>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam48>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam49>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam49>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam49>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam50>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam50>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam50>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam51>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam51>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam51>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam53>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam53>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam53>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam54>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam54>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam54>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam55>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam55>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam55>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam56>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam56>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam56>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam57>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam57>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam57>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam58>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam58>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam58>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam59>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam59>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam59>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam60>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam60>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam60>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam61>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam61>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam61>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam62>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam62>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam62>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam63>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam63>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam63>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam64>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam64>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam64>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam65>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam65>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam65>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam66>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam66>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam66>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam67>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam67>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam67>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam68>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam68>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam68>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam69>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam69>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam69>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam71>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam71>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam71>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam72>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam72>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam72>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam73>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam73>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam73>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam74>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam74>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam74>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam75>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam75>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam75>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam76>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam76>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam76>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam77>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam77>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam77>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam78>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam78>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam78>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam79>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam79>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam79>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam80>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam80>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam80>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam81>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam81>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam81>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam82>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam82>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam82>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam83>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam83>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam83>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam84>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam84>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam84>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam85>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam85>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam85>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam86>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam86>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam86>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam87>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam87>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam87>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam88>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam88>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam88>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam89>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam89>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam89>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam90>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam90>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam90>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam91>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam91>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam91>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam92>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam92>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam92>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam93>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam93>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam93>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam94>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam94>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam94>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam95>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam95>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam95>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam96>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam96>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam96>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam97>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam97>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam97>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam98>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam98>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam98>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam99>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam99>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam99>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam100>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam100>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam100>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam101>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam101>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam101>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam102>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam102>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam102>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam103>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam103>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam103>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam105>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam105>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam105>(b));
    let _ = core::hint::black_box(rmp_serde::from_slice::<StructFam106>(b));
    let _ = core::hint::black_box(serde_json::from_str::<StructFam106>(&s));
    let _ = core::hint::black_box(serde_json::from_slice::<StructFam106>(b));
    }
}
