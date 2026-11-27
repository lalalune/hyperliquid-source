#![allow(clippy::too_many_lines)]
//! Wave 3 Hyperliquid first-party enum wire-name `visit_str` codecs.

use crate::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};

pub mod perp_deploy_v2 {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15, V16, V17 }
    pub static VARIANTS: &[&str] = &["registerAsset", "registerAsset2", "setOracle", "haltTrading", "insertMarginTable", "setFeeRecipient", "setMarginTableIds", "setOpenInterestCaps", "setFundingMultipliers", "setFundingInterestRates", "setFundingClamps", "setSubDeployers", "setMarginModes", "setDeployerFees", "disableDex", "setPerpAnnotation", "migrateDexQuoteToken", "star"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "registerAsset" => Ok(Variant::V0),
            "registerAsset2" => Ok(Variant::V1),
            "setOracle" => Ok(Variant::V2),
            "haltTrading" => Ok(Variant::V3),
            "insertMarginTable" => Ok(Variant::V4),
            "setFeeRecipient" => Ok(Variant::V5),
            "setMarginTableIds" => Ok(Variant::V6),
            "setOpenInterestCaps" => Ok(Variant::V7),
            "setFundingMultipliers" => Ok(Variant::V8),
            "setFundingInterestRates" => Ok(Variant::V9),
            "setFundingClamps" => Ok(Variant::V10),
            "setSubDeployers" => Ok(Variant::V11),
            "setMarginModes" => Ok(Variant::V12),
            "setDeployerFees" => Ok(Variant::V13),
            "disableDex" => Ok(Variant::V14),
            "setPerpAnnotation" => Ok(Variant::V15),
            "migrateDexQuoteToken" => Ok(Variant::V16),
            "star" => Ok(Variant::V17),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "registerAsset" => Ok(Variant::V0),
            "registerAsset2" => Ok(Variant::V1),
            "setOracle" => Ok(Variant::V2),
            "haltTrading" => Ok(Variant::V3),
            "insertMarginTable" => Ok(Variant::V4),
            "setFeeRecipient" => Ok(Variant::V5),
            "setMarginTableIds" => Ok(Variant::V6),
            "setOpenInterestCaps" => Ok(Variant::V7),
            "setFundingMultipliers" => Ok(Variant::V8),
            "setFundingInterestRates" => Ok(Variant::V9),
            "setFundingClamps" => Ok(Variant::V10),
            "setSubDeployers" => Ok(Variant::V11),
            "setMarginModes" => Ok(Variant::V12),
            "setDeployerFees" => Ok(Variant::V13),
            "disableDex" => Ok(Variant::V14),
            "setPerpAnnotation" => Ok(Variant::V15),
            "migrateDexQuoteToken" => Ok(Variant::V16),
            "star" => Ok(Variant::V17),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod outcome_deploy {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12 }
    pub static VARIANTS: &[&str] = &["registerTokensAndStandaloneOutcome", "registerTokensAndQuestion", "settleOutcome", "settleQuestion2", "changeOutcomeDescription", "registerAndAssociateNamedOutcome", "changeQuestionDescription", "registerTemplate", "registerTemplateGroup", "registerStandaloneOutcomeFromTemplate", "registerQuestionFromTemplate", "registerAndAssociateNamedOutcomeFromTemplate", "setSubDeployers"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "registerTokensAndStandaloneOutcome" => Ok(Variant::V0),
            "registerTokensAndQuestion" => Ok(Variant::V1),
            "settleOutcome" => Ok(Variant::V2),
            "settleQuestion2" => Ok(Variant::V3),
            "changeOutcomeDescription" => Ok(Variant::V4),
            "registerAndAssociateNamedOutcome" => Ok(Variant::V5),
            "changeQuestionDescription" => Ok(Variant::V6),
            "registerTemplate" => Ok(Variant::V7),
            "registerTemplateGroup" => Ok(Variant::V8),
            "registerStandaloneOutcomeFromTemplate" => Ok(Variant::V9),
            "registerQuestionFromTemplate" => Ok(Variant::V10),
            "registerAndAssociateNamedOutcomeFromTemplate" => Ok(Variant::V11),
            "setSubDeployers" => Ok(Variant::V12),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "registerTokensAndStandaloneOutcome" => Ok(Variant::V0),
            "registerTokensAndQuestion" => Ok(Variant::V1),
            "settleOutcome" => Ok(Variant::V2),
            "settleQuestion2" => Ok(Variant::V3),
            "changeOutcomeDescription" => Ok(Variant::V4),
            "registerAndAssociateNamedOutcome" => Ok(Variant::V5),
            "changeQuestionDescription" => Ok(Variant::V6),
            "registerTemplate" => Ok(Variant::V7),
            "registerTemplateGroup" => Ok(Variant::V8),
            "registerStandaloneOutcomeFromTemplate" => Ok(Variant::V9),
            "registerQuestionFromTemplate" => Ok(Variant::V10),
            "registerAndAssociateNamedOutcomeFromTemplate" => Ok(Variant::V11),
            "setSubDeployers" => Ok(Variant::V12),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod info_request {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15, V16, V17, V18, V19, V20, V21, V22, V23, V24, V25, V26, V27, V28, V29, V30, V31, V32, V33, V34, V35, V36, V37, V38, V39, V40, V41, V42, V43, V44, V45, V46, V47, V48, V49, V50, V51, V52, V53, V54 }
    pub static VARIANTS: &[&str] = &["fileSnapshot", "webData2", "webData3", "meta", "spotMeta", "outcomeMeta", "outcomeDeployerLimits", "clearinghouseState", "spotClearinghouseState", "openOrders", "exchangeStatus", "frontendOpenOrders", "activeAssetData", "maxMarketOrderNtls", "vaultSummaries", "userVaultEquities", "leadingVaults", "extraAgents", "subAccounts", "subAccounts2", "userFees", "userRateLimit", "spotDeployState", "spotPairDeployAuctionStatus", "perpDeployAuctionStatus", "votes", "delegations", "delegatorSummary", "maxBuilderFee", "userToMultiSigSigners", "userRole", "perpsAtOpenInterestCap", "perpDexLimits", "validatorL1Votes", "marginTable", "perpDexs", "allPerpMetas", "userDexAbstraction", "perpDexStatus", "borrowLendUserState", "borrowLendReserveState", "allBorrowLendReserveStates", "userAbstraction", "perpAnnotation", "perpCategories", "perpConciseAnnotations", "tokenAnnotation", "tokenConciseAnnotations", "settledOutcome", "settledQuestion", "approvedBuilders", "gossipPriorityAuctionStatus", "outcomeTemplates", "aqav2InterestHistory", "userStarState"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "fileSnapshot" => Ok(Variant::V0),
            "webData2" => Ok(Variant::V1),
            "webData3" => Ok(Variant::V2),
            "meta" => Ok(Variant::V3),
            "spotMeta" => Ok(Variant::V4),
            "outcomeMeta" => Ok(Variant::V5),
            "outcomeDeployerLimits" => Ok(Variant::V6),
            "clearinghouseState" => Ok(Variant::V7),
            "spotClearinghouseState" => Ok(Variant::V8),
            "openOrders" => Ok(Variant::V9),
            "exchangeStatus" => Ok(Variant::V10),
            "frontendOpenOrders" => Ok(Variant::V11),
            "activeAssetData" => Ok(Variant::V12),
            "maxMarketOrderNtls" => Ok(Variant::V13),
            "vaultSummaries" => Ok(Variant::V14),
            "userVaultEquities" => Ok(Variant::V15),
            "leadingVaults" => Ok(Variant::V16),
            "extraAgents" => Ok(Variant::V17),
            "subAccounts" => Ok(Variant::V18),
            "subAccounts2" => Ok(Variant::V19),
            "userFees" => Ok(Variant::V20),
            "userRateLimit" => Ok(Variant::V21),
            "spotDeployState" => Ok(Variant::V22),
            "spotPairDeployAuctionStatus" => Ok(Variant::V23),
            "perpDeployAuctionStatus" => Ok(Variant::V24),
            "votes" => Ok(Variant::V25),
            "delegations" => Ok(Variant::V26),
            "delegatorSummary" => Ok(Variant::V27),
            "maxBuilderFee" => Ok(Variant::V28),
            "userToMultiSigSigners" => Ok(Variant::V29),
            "userRole" => Ok(Variant::V30),
            "perpsAtOpenInterestCap" => Ok(Variant::V31),
            "perpDexLimits" => Ok(Variant::V32),
            "validatorL1Votes" => Ok(Variant::V33),
            "marginTable" => Ok(Variant::V34),
            "perpDexs" => Ok(Variant::V35),
            "allPerpMetas" => Ok(Variant::V36),
            "userDexAbstraction" => Ok(Variant::V37),
            "perpDexStatus" => Ok(Variant::V38),
            "borrowLendUserState" => Ok(Variant::V39),
            "borrowLendReserveState" => Ok(Variant::V40),
            "allBorrowLendReserveStates" => Ok(Variant::V41),
            "userAbstraction" => Ok(Variant::V42),
            "perpAnnotation" => Ok(Variant::V43),
            "perpCategories" => Ok(Variant::V44),
            "perpConciseAnnotations" => Ok(Variant::V45),
            "tokenAnnotation" => Ok(Variant::V46),
            "tokenConciseAnnotations" => Ok(Variant::V47),
            "settledOutcome" => Ok(Variant::V48),
            "settledQuestion" => Ok(Variant::V49),
            "approvedBuilders" => Ok(Variant::V50),
            "gossipPriorityAuctionStatus" => Ok(Variant::V51),
            "outcomeTemplates" => Ok(Variant::V52),
            "aqav2InterestHistory" => Ok(Variant::V53),
            "userStarState" => Ok(Variant::V54),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "fileSnapshot" => Ok(Variant::V0),
            "webData2" => Ok(Variant::V1),
            "webData3" => Ok(Variant::V2),
            "meta" => Ok(Variant::V3),
            "spotMeta" => Ok(Variant::V4),
            "outcomeMeta" => Ok(Variant::V5),
            "outcomeDeployerLimits" => Ok(Variant::V6),
            "clearinghouseState" => Ok(Variant::V7),
            "spotClearinghouseState" => Ok(Variant::V8),
            "openOrders" => Ok(Variant::V9),
            "exchangeStatus" => Ok(Variant::V10),
            "frontendOpenOrders" => Ok(Variant::V11),
            "activeAssetData" => Ok(Variant::V12),
            "maxMarketOrderNtls" => Ok(Variant::V13),
            "vaultSummaries" => Ok(Variant::V14),
            "userVaultEquities" => Ok(Variant::V15),
            "leadingVaults" => Ok(Variant::V16),
            "extraAgents" => Ok(Variant::V17),
            "subAccounts" => Ok(Variant::V18),
            "subAccounts2" => Ok(Variant::V19),
            "userFees" => Ok(Variant::V20),
            "userRateLimit" => Ok(Variant::V21),
            "spotDeployState" => Ok(Variant::V22),
            "spotPairDeployAuctionStatus" => Ok(Variant::V23),
            "perpDeployAuctionStatus" => Ok(Variant::V24),
            "votes" => Ok(Variant::V25),
            "delegations" => Ok(Variant::V26),
            "delegatorSummary" => Ok(Variant::V27),
            "maxBuilderFee" => Ok(Variant::V28),
            "userToMultiSigSigners" => Ok(Variant::V29),
            "userRole" => Ok(Variant::V30),
            "perpsAtOpenInterestCap" => Ok(Variant::V31),
            "perpDexLimits" => Ok(Variant::V32),
            "validatorL1Votes" => Ok(Variant::V33),
            "marginTable" => Ok(Variant::V34),
            "perpDexs" => Ok(Variant::V35),
            "allPerpMetas" => Ok(Variant::V36),
            "userDexAbstraction" => Ok(Variant::V37),
            "perpDexStatus" => Ok(Variant::V38),
            "borrowLendUserState" => Ok(Variant::V39),
            "borrowLendReserveState" => Ok(Variant::V40),
            "allBorrowLendReserveStates" => Ok(Variant::V41),
            "userAbstraction" => Ok(Variant::V42),
            "perpAnnotation" => Ok(Variant::V43),
            "perpCategories" => Ok(Variant::V44),
            "perpConciseAnnotations" => Ok(Variant::V45),
            "tokenAnnotation" => Ok(Variant::V46),
            "tokenConciseAnnotations" => Ok(Variant::V47),
            "settledOutcome" => Ok(Variant::V48),
            "settledQuestion" => Ok(Variant::V49),
            "approvedBuilders" => Ok(Variant::V50),
            "gossipPriorityAuctionStatus" => Ok(Variant::V51),
            "outcomeTemplates" => Ok(Variant::V52),
            "aqav2InterestHistory" => Ok(Variant::V53),
            "userStarState" => Ok(Variant::V54),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod spot_deploy {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15 }
    pub static VARIANTS: &[&str] = &["registerToken", "registerToken2", "userGenesis", "genesis", "registerSpot", "registerHyperliquidity", "requestEvmContract", "setFullName", "setTokenAnnotation", "setDeployerTradingFeeShare", "setDeployerLabel", "enableFreezePrivilege", "freezeUser", "revokeFreezePrivilege", "enableQuoteToken", "disableQuoteToken"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "registerToken" => Ok(Variant::V0),
            "registerToken2" => Ok(Variant::V1),
            "userGenesis" => Ok(Variant::V2),
            "genesis" => Ok(Variant::V3),
            "registerSpot" => Ok(Variant::V4),
            "registerHyperliquidity" => Ok(Variant::V5),
            "requestEvmContract" => Ok(Variant::V6),
            "setFullName" => Ok(Variant::V7),
            "setTokenAnnotation" => Ok(Variant::V8),
            "setDeployerTradingFeeShare" => Ok(Variant::V9),
            "setDeployerLabel" => Ok(Variant::V10),
            "enableFreezePrivilege" => Ok(Variant::V11),
            "freezeUser" => Ok(Variant::V12),
            "revokeFreezePrivilege" => Ok(Variant::V13),
            "enableQuoteToken" => Ok(Variant::V14),
            "disableQuoteToken" => Ok(Variant::V15),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "registerToken" => Ok(Variant::V0),
            "registerToken2" => Ok(Variant::V1),
            "userGenesis" => Ok(Variant::V2),
            "genesis" => Ok(Variant::V3),
            "registerSpot" => Ok(Variant::V4),
            "registerHyperliquidity" => Ok(Variant::V5),
            "requestEvmContract" => Ok(Variant::V6),
            "setFullName" => Ok(Variant::V7),
            "setTokenAnnotation" => Ok(Variant::V8),
            "setDeployerTradingFeeShare" => Ok(Variant::V9),
            "setDeployerLabel" => Ok(Variant::V10),
            "enableFreezePrivilege" => Ok(Variant::V11),
            "freezeUser" => Ok(Variant::V12),
            "revokeFreezePrivilege" => Ok(Variant::V13),
            "enableQuoteToken" => Ok(Variant::V14),
            "disableQuoteToken" => Ok(Variant::V15),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod agent_action {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4, V5, V6 }
    pub static VARIANTS: &[&str] = &["modifyApproval", "modifyBackstopLiquidatorApproval", "setReduceOnly", "cancel", "cancelAll", "order", "sendAsset"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "modifyApproval" => Ok(Variant::V0),
            "modifyBackstopLiquidatorApproval" => Ok(Variant::V1),
            "setReduceOnly" => Ok(Variant::V2),
            "cancel" => Ok(Variant::V3),
            "cancelAll" => Ok(Variant::V4),
            "order" => Ok(Variant::V5),
            "sendAsset" => Ok(Variant::V6),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "modifyApproval" => Ok(Variant::V0),
            "modifyBackstopLiquidatorApproval" => Ok(Variant::V1),
            "setReduceOnly" => Ok(Variant::V2),
            "cancel" => Ok(Variant::V3),
            "cancelAll" => Ok(Variant::V4),
            "order" => Ok(Variant::V5),
            "sendAsset" => Ok(Variant::V6),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod outcome_template {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4 }
    pub static VARIANTS: &[&str] = &["registerAndAssociateNamedOutcomeFromTemplate", "registerQuestionFromTemplate", "registerStandaloneOutcomeFromTemplate", "settleOutcome", "settleQuestion"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "registerAndAssociateNamedOutcomeFromTemplate" => Ok(Variant::V0),
            "registerQuestionFromTemplate" => Ok(Variant::V1),
            "registerStandaloneOutcomeFromTemplate" => Ok(Variant::V2),
            "settleOutcome" => Ok(Variant::V3),
            "settleQuestion" => Ok(Variant::V4),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "registerAndAssociateNamedOutcomeFromTemplate" => Ok(Variant::V0),
            "registerQuestionFromTemplate" => Ok(Variant::V1),
            "registerStandaloneOutcomeFromTemplate" => Ok(Variant::V2),
            "settleOutcome" => Ok(Variant::V3),
            "settleQuestion" => Ok(Variant::V4),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod outcome_field_type {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4, V5, V6 }
    pub static VARIANTS: &[&str] = &["dateTime", "date", "string", "shortString", "hlPerp", "uInt", "uDecimal"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "dateTime" => Ok(Variant::V0),
            "date" => Ok(Variant::V1),
            "string" => Ok(Variant::V2),
            "shortString" => Ok(Variant::V3),
            "hlPerp" => Ok(Variant::V4),
            "uInt" => Ok(Variant::V5),
            "uDecimal" => Ok(Variant::V6),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "dateTime" => Ok(Variant::V0),
            "date" => Ok(Variant::V1),
            "string" => Ok(Variant::V2),
            "shortString" => Ok(Variant::V3),
            "hlPerp" => Ok(Variant::V4),
            "uInt" => Ok(Variant::V5),
            "uDecimal" => Ok(Variant::V6),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod order_grouping {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3 }
    pub static VARIANTS: &[&str] = &["na", "normalTpsl", "positionTpsl", "p"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "na" => Ok(Variant::V0),
            "normalTpsl" => Ok(Variant::V1),
            "positionTpsl" => Ok(Variant::V2),
            "p" => Ok(Variant::V3),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "na" => Ok(Variant::V0),
            "normalTpsl" => Ok(Variant::V1),
            "positionTpsl" => Ok(Variant::V2),
            "p" => Ok(Variant::V3),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod outcome_entry_kind {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2 }
    pub static VARIANTS: &[&str] = &["standaloneOutcome", "question", "questionOutcome"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "standaloneOutcome" => Ok(Variant::V0),
            "question" => Ok(Variant::V1),
            "questionOutcome" => Ok(Variant::V2),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "standaloneOutcome" => Ok(Variant::V0),
            "question" => Ok(Variant::V1),
            "questionOutcome" => Ok(Variant::V2),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod staking_link_kind {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2 }
    pub static VARIANTS: &[&str] = &["Requested", "TradingUser", "StakingUser"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "Requested" => Ok(Variant::V0),
            "TradingUser" => Ok(Variant::V1),
            "StakingUser" => Ok(Variant::V2),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "Requested" => Ok(Variant::V0),
            "TradingUser" => Ok(Variant::V1),
            "StakingUser" => Ok(Variant::V2),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod c_validator_action {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2 }
    pub static VARIANTS: &[&str] = &["register", "changeProfile", "unregister"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "register" => Ok(Variant::V0),
            "changeProfile" => Ok(Variant::V1),
            "unregister" => Ok(Variant::V2),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "register" => Ok(Variant::V0),
            "changeProfile" => Ok(Variant::V1),
            "unregister" => Ok(Variant::V2),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod outcome_token_op {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3 }
    pub static VARIANTS: &[&str] = &["splitOutcome", "mergeOutcome", "mergeQuestion", "negateOutcome"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "splitOutcome" => Ok(Variant::V0),
            "mergeOutcome" => Ok(Variant::V1),
            "mergeQuestion" => Ok(Variant::V2),
            "negateOutcome" => Ok(Variant::V3),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "splitOutcome" => Ok(Variant::V0),
            "mergeOutcome" => Ok(Variant::V1),
            "mergeQuestion" => Ok(Variant::V2),
            "negateOutcome" => Ok(Variant::V3),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod asset_trading_mode {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2 }
    pub static VARIANTS: &[&str] = &["disabled", "reduceOnly", "enabled"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "disabled" => Ok(Variant::V0),
            "reduceOnly" => Ok(Variant::V1),
            "enabled" => Ok(Variant::V2),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "disabled" => Ok(Variant::V0),
            "reduceOnly" => Ok(Variant::V1),
            "enabled" => Ok(Variant::V2),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod vault_relationship {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2 }
    pub static VARIANTS: &[&str] = &["normal", "child", "parent"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "normal" => Ok(Variant::V0),
            "child" => Ok(Variant::V1),
            "parent" => Ok(Variant::V2),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "normal" => Ok(Variant::V0),
            "child" => Ok(Variant::V1),
            "parent" => Ok(Variant::V2),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod account_mode {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2 }
    pub static VARIANTS: &[&str] = &["enabled", "disabled", "blocked"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "enabled" => Ok(Variant::V0),
            "disabled" => Ok(Variant::V1),
            "blocked" => Ok(Variant::V2),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "enabled" => Ok(Variant::V0),
            "disabled" => Ok(Variant::V1),
            "blocked" => Ok(Variant::V2),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod oracle_source_kind {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1 }
    pub static VARIANTS: &[&str] = &["Oracle", "ReferenceOracle"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "Oracle" => Ok(Variant::V0),
            "ReferenceOracle" => Ok(Variant::V1),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "Oracle" => Ok(Variant::V0),
            "ReferenceOracle" => Ok(Variant::V1),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod node_stream_role {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1 }
    pub static VARIANTS: &[&str] = &["Evm", "Broadcaster"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "Evm" => Ok(Variant::V0),
            "Broadcaster" => Ok(Variant::V1),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "Evm" => Ok(Variant::V0),
            "Broadcaster" => Ok(Variant::V1),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod spot_px_kind {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1 }
    pub static VARIANTS: &[&str] = &["usdtUsdcPx", "nativePx"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "usdtUsdcPx" => Ok(Variant::V0),
            "nativePx" => Ok(Variant::V1),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "usdtUsdcPx" => Ok(Variant::V0),
            "nativePx" => Ok(Variant::V1),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod staker_role_kind {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1 }
    pub static VARIANTS: &[&str] = &["technical", "treasury"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "technical" => Ok(Variant::V0),
            "treasury" => Ok(Variant::V1),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "technical" => Ok(Variant::V0),
            "treasury" => Ok(Variant::V1),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod tpsl_kind {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1 }
    pub static VARIANTS: &[&str] = &["tp", "sl"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "tp" => Ok(Variant::V0),
            "sl" => Ok(Variant::V1),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "tp" => Ok(Variant::V0),
            "sl" => Ok(Variant::V1),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod quorum_status {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1 }
    pub static VARIANTS: &[&str] = &["Q", "N"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "Q" => Ok(Variant::V0),
            "N" => Ok(Variant::V1),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "Q" => Ok(Variant::V0),
            "N" => Ok(Variant::V1),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod indexed_artifact_content {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4 }
    pub static VARIANTS: &[&str] = &["NodeMetadata", "VisorMetadata", "HotfixMetadata", "NodeArtifact", "PublisherBinaryMetadata"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "NodeMetadata" => Ok(Variant::V0),
            "VisorMetadata" => Ok(Variant::V1),
            "HotfixMetadata" => Ok(Variant::V2),
            "NodeArtifact" => Ok(Variant::V3),
            "PublisherBinaryMetadata" => Ok(Variant::V4),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "NodeMetadata" => Ok(Variant::V0),
            "VisorMetadata" => Ok(Variant::V1),
            "HotfixMetadata" => Ok(Variant::V2),
            "NodeArtifact" => Ok(Variant::V3),
            "PublisherBinaryMetadata" => Ok(Variant::V4),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}
