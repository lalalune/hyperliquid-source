#![forbid(unsafe_code)]

//! Independently authored first-party node #115 functions for compiled-byte comparison
//! with `rustc 1.95.0 (59807616e 2026-04-14)` (`-C opt-level=3 -C overflow-checks=yes`).

use std::collections::VecDeque;

pub mod assets_wave3;
pub mod enums_wave3;
pub mod expecting_wave3;
pub mod fields_wave3;

/// ABI-shaped 9-variant error enum modeling the `rmp_serde::decode::Error` layout observed
/// in node #115 (`Ok(u8)` receives niche discriminant `0x09`).
#[derive(Debug, PartialEq, Eq)]
pub enum RmpErr {
    E0(u8, usize),
    E1(u8),
    E2(u8),
    E3(u8),
    E4(u8),
    E5(u8),
    E6(u8),
    E7(u8),
    E8(u8),
}

/// 32-byte ABI-shaped 9-variant error enum modeling the large-matcher `rmp_serde::decode::Error`
/// stack-spill layout observed in node #115 (`Ok(u8)` receives niche discriminant `0x09`).
#[derive(Debug, PartialEq, Eq)]
pub enum RmpErr32 {
    E0(u8, usize, usize, usize),
    E1(u8),
    E2(u8),
    E3(u8),
    E4(u8),
    E5(u8),
    E6(u8),
    E7(u8),
    E8(u8),
}

/// ABI-shaped boxed error payload modeling the `serde_json::Error` layout observed in node #115.
#[derive(Debug, PartialEq, Eq)]
pub struct JsonErr(pub Box<[usize; 2]>);

#[cold]
#[inline(never)]
pub(crate) fn rmp_unknown_variant(v: &str, expected: &'static [&'static str]) -> RmpErr {
    let p = core::hint::black_box((v.as_ptr(), v.len(), expected.as_ptr(), expected.len()));
    RmpErr::E0(p.0 as u8, p.1 ^ (p.2 as usize) ^ p.3)
}

#[cold]
#[inline(never)]
pub(crate) fn json_unknown_variant(v: &str, expected: &'static [&'static str]) -> JsonErr {
    let p = core::hint::black_box((v.as_ptr(), v.len(), expected.as_ptr(), expected.len()));
    JsonErr(Box::new([(p.0 as usize) ^ p.1, (p.2 as usize) ^ p.3]))
}

/// Keeps the cold error helpers externally reachable so argument registers are preserved.
#[cold]
#[inline(never)]
fn rmp32_unknown_variant(v: &str, expected: &'static [&'static str]) -> RmpErr32 {
    let p = core::hint::black_box((v.as_ptr(), v.len(), expected.as_ptr(), expected.len()));
    RmpErr32::E0(p.0 as u8, p.1, p.2 as usize, p.3)
}

/// Keeps the cold error helpers externally reachable so argument registers are preserved.
pub fn retain_cold_error_helpers(v: &str) -> (RmpErr, RmpErr32, JsonErr) {
    (
        rmp_unknown_variant(v, &[]),
        rmp32_unknown_variant(v, &[]),
        json_unknown_variant(v, &[]),
    )
}

// ---------------------------------------------------------------------------
// Leaf first-party helpers (raw-equal & relocation-qualified)
// ---------------------------------------------------------------------------

/// `l1-shared`: 20-byte slice equality (`0x5436860`, 86B, raw-equal; `l1/src/raw_signature_tracker.rs`).
#[inline(never)]
pub fn fp_slice20_equal(a: &[[u8; 20]], b: &[[u8; 20]]) -> bool {
    a == b
}

/// `fees`: adjacent descending binary64 window scan (`0x36e1b10`, 113B; `l1/src/fees/`).
#[inline(never)]
pub fn fp_fee_window_scan(w: &mut core::slice::Windows<'_, f64>) -> bool {
    w.any(|pair| pair[1] > pair[0])
}

/// `assets`: in-place 256-bit unsigned subtraction with final borrow (`0x2ccdd80`, `0x43be060`, `0x564c830`, 49B, raw-equal; `l1/src/qtys/impl_wei.rs`).
#[inline(never)]
pub fn fp_sub256_borrow(out: &mut ([u64; 4], bool), lhs: &mut [u64; 4], rhs: &[u64; 4]) {
    let mut borrow = false;
    let mut i = 0;
    while i < 4 {
        let (d, b) = lhs[i].borrowing_sub(rhs[i], borrow);
        lhs[i] = d;
        borrow = b;
        i += 1;
    }
    *out = (*lhs, borrow);
}

/// `foundation`: bounded ring offset via `VecDeque::binary_search_by` (`0x45514d0`, 83B, raw-equal).
#[inline(never)]
pub fn fp_bounded_offset(d: &VecDeque<u64>) -> Result<usize, usize> {
    d.binary_search_by(|_| core::cmp::Ordering::Equal)
}

/// `foundation`: two-span 80-byte-stride ring iterator construction (`0x152e360`, 114B, raw-equal).
#[inline(never)]
pub fn fp_two_span_projection(
    d: &VecDeque<[u8; 80]>,
) -> std::collections::vec_deque::Iter<'_, [u8; 80]> {
    d.iter()
}

// ---------------------------------------------------------------------------
// Hyperliquid first-party enum wire-name `visit_str` codecs
// ---------------------------------------------------------------------------

macro_rules! def_enum_visitors {
    ($mod_name:ident, $ename:ident, [ $( ($var:ident, $str:literal, $tag:expr) ),+ $(,)? ]) => {
        pub mod $mod_name {
            use super::*;

            #[repr(u8)]
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub enum $ename {
                $( $var = $tag, )+
            }

            pub static FIELDS: &[&str] = &[ $( $str, )+ ];

            #[inline(never)]
            pub fn visit_str_rmp(v: &str) -> Result<$ename, RmpErr> {
                match v {
                    $( $str => Ok($ename::$var), )+
                    _ => Err(rmp_unknown_variant(v, FIELDS)),
                }
            }

            #[inline(never)]
            pub fn visit_str_json(v: &str) -> Result<$ename, JsonErr> {
                match v {
                    $( $str => Ok($ename::$var), )+
                    _ => Err(json_unknown_variant(v, FIELDS)),
                }
            }
        }
    };
}

def_enum_visitors!(chain_name, ChainName, [
    (Local, "Local", 0),
    (Sandbox, "Sandbox", 1),
    (Testnet, "Testnet", 2),
    (Mainnet, "Mainnet", 3),
]);

def_enum_visitors!(spot_mark, SpotMarkKind, [
    (Spot, "Spot", 0),
    (Mark, "Mark", 1),
    (ExternalPerp, "ExternalPerp", 2),
]);

def_enum_visitors!(tif, Tif, [
    (Alo, "Alo", 0),
    (Ioc, "Ioc", 1),
    (Gtc, "Gtc", 2),
    (FrontendMarket, "FrontendMarket", 3),
    (LiquidationMarket, "LiquidationMarket", 4),
]);

def_enum_visitors!(outcome_kind, OutcomeKind, [
    (StandaloneOutcome, "StandaloneOutcome", 0),
    (Question, "Question", 1),
    (QuestionOutcome, "QuestionOutcome", 2),
]);

def_enum_visitors!(margin_mode, MarginMode, [
    (Normal, "normal", 0),
    (NoCross, "noCross", 1),
    (StrictIsolated, "strictIsolated", 2),
]);

def_enum_visitors!(borrow_lend_op, Operation, [
    (Borrow, "borrow", 0),
    (Supply, "supply", 1),
    (Repay, "repay", 2),
    (Withdraw, "withdraw", 3),
]);

def_enum_visitors!(borrow_lend_field, BorrowLendField, [
    (Operation, "operation", 0),
    (Token, "token", 1),
    (Amount, "amount", 2),
]);

def_enum_visitors!(bridge_event, BridgeEvent, [
    (Deposit, "Deposit", 0),
    (InvalidatedWithdrawal, "InvalidatedWithdrawal", 1),
    (RequestedWithdrawal, "RequestedWithdrawal", 2),
    (FinalizedWithdrawal, "FinalizedWithdrawal", 3),
    (FinalizedValidatorSetUpdate, "FinalizedValidatorSetUpdate", 4),
    (RequestedValidatorSetUpdateEvent, "RequestedValidatorSetUpdateEvent", 5),
]);

def_enum_visitors!(hip3_disabled, DisabledState, [
    (Na, "Na", 0),
    (UserDisabled, "UserDisabled", 1),
    (ValidatorDisabled, "ValidatorDisabled", 2),
    (M, "m", 3),
]);

def_enum_visitors!(evm_tx_type, EvmTxType, [
    (Legacy, "Legacy", 0),
    (Eip2930, "Eip2930", 1),
    (Eip1559, "Eip1559", 2),
    (Eip4844, "Eip4844", 3),
    (Eip7702, "Eip7702", 4),
]);

def_enum_visitors!(evm_precompile_outcome, ReadPrecompileOutcomeName, [
    (Ok, "Ok", 0),
    (OutOfGas, "OutOfGas", 1),
    (Error, "Error", 2),
    (UnexpectedError, "UnexpectedError", 3),
]);

def_enum_visitors!(abstraction_kind, AbstractionKind, [
    (Perp, "Perp", 0),
    (Spot, "Spot", 1),
    (Token, "Token", 2),
    (Pdi, "Pdi", 3),
    (ActivateDexAbstraction, "ActivateDexAbstraction", 4),
    (ActivateUnifiedAccount, "ActivateUnifiedAccount", 5),
    (AllBoleTokens, "AllBoleTokens", 6),
]);

def_enum_visitors!(vote_choice, VoteChoice, [
    (Yes, "yes", 0),
    (No, "no", 1),
    (Abstain, "abstain", 2),
]);

def_enum_visitors!(proposal_cat, ProposalCategory, [
    (Accelerated, "accelerated", 0),
    (Constitutional, "constitutional", 1),
    (Ecosystem, "ecosystem", 2),
    (Electoral, "electoral", 3),
]);


pub mod action92 {
    use super::*;

    #[repr(u8)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ActionVariant {
        V0 = 0, V1 = 1, V2 = 2, V3 = 3, V4 = 4, V5 = 5, V6 = 6, V7 = 7, V8 = 8, V9 = 9, V10 = 10, V11 = 11, V12 = 12, V13 = 13, V14 = 14, V15 = 15, V16 = 16, V17 = 17, V18 = 18, V19 = 19, V20 = 20, V21 = 21, V22 = 22, V23 = 23, V24 = 24, V25 = 25, V26 = 26, V27 = 27, V28 = 28, V29 = 29, V30 = 30, V31 = 31, V32 = 32, V33 = 33, V34 = 34, V35 = 35, V36 = 36, V37 = 37, V38 = 38, V39 = 39, V40 = 40, V41 = 41, V42 = 42, V43 = 43, V44 = 44, V45 = 45, V46 = 46, V47 = 47, V48 = 48, V49 = 49, V50 = 50, V51 = 51, V52 = 52, V53 = 53, V54 = 54, V55 = 55, V56 = 56, V57 = 57, V58 = 58, V59 = 59, V60 = 60, V61 = 61, V62 = 62, V63 = 63, V64 = 64, V65 = 65, V66 = 66, V67 = 67, V68 = 68, V69 = 69, V70 = 70, V71 = 71, V72 = 72, V73 = 73, V74 = 74, V75 = 75, V76 = 76, V77 = 77, V78 = 78, V79 = 79, V80 = 80, V81 = 81, V82 = 82, V83 = 83, V84 = 84, V85 = 85, V86 = 86, V87 = 87, V88 = 88, V89 = 89, V90 = 90, V91 = 91,
    }

    pub static FIELDS: &[&str] = &["noop", "approveAgent", "batchModify", "cancel", "cancelByCloid", "claimRewards", "createSubAccount", "createVault", "evmRawTx", "ForceIncreaseEpochAction", "liquidate", "linkStakingUser", "modify", "NetChildVaultPositionsAction", "order", "registerReferrer", "RegisterValidatorAction", "CValidatorAction", "scheduleCancel", "setDisplayName", "VoteGlobalAction", "validatorL1Vote", "validatorL1Stream", "validatorL1Status", "validatorL1UpdateReferenceOracle", "SetGlobalAction", "setReferrer", "spotDeploy", "spotUser", "spotSend", "SignValidatorSetUpdateAction", "subAccountModify", "subAccountTransfer", "subAccountSpotTransfer", "tokenDelegate", "twapCancel", "twapOrder", "updateIsolatedMargin", "topUpIsolatedOnlyMargin", "updateLeverage", "usdSend", "ValidatorSignWithdrawalAction", "vaultDistribute", "vaultModify", "vaultTransfer", "VoteEthDepositAction", "VoteEthFinalizedValidatorSetUpdateAction", "VoteEthFinalizedWithdrawalAction", "withdraw3", "govPropose", "govVote", "usdClassTransfer", "multiSig", "convertToMultiSigUser", "approveBuilderFee", "startFeeTrial", "SystemBoleAction", "SystemSpotSendAction", "deployerSendToEvmForFrozenUser", "SystemUsdClassTransferAction", "CSignerAction", "cWithdraw", "cDeposit", "cUserModify", "reassessFees", "evmUserModify", "reserveRequestWeight", "finalizeEvmContract", "perpDeploy", "sendAsset", "SystemApproveBuilderFeeAction", "SystemSendAssetAction", "agentEnableDexAbstraction", "userDexAbstraction", "borrowLend", "sendToEvmWithData", "userPortfolioMargin", "userSetAbstraction", "agentSetAbstraction", "userOutcome", "gossipPriorityBid", "agentSendAsset", "hip3LiquidatorTransfer", "l1ValidatorVoteBridgeDeposit", "authorizeAqav2Role", "stakingLinkDisableTradingUser", "voteL1Hash", "voteAbciDigest", "activateOutcomeDeployer", "trailingStop", "outcomeDeploy", "cDeposit2"];

    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<ActionVariant, RmpErr32> {
        match v {
            "noop" => Ok(ActionVariant::V0),
            "approveAgent" => Ok(ActionVariant::V1),
            "batchModify" => Ok(ActionVariant::V2),
            "cancel" => Ok(ActionVariant::V3),
            "cancelByCloid" => Ok(ActionVariant::V4),
            "claimRewards" => Ok(ActionVariant::V5),
            "createSubAccount" => Ok(ActionVariant::V6),
            "createVault" => Ok(ActionVariant::V7),
            "evmRawTx" => Ok(ActionVariant::V8),
            "ForceIncreaseEpochAction" => Ok(ActionVariant::V9),
            "liquidate" => Ok(ActionVariant::V10),
            "linkStakingUser" => Ok(ActionVariant::V11),
            "modify" => Ok(ActionVariant::V12),
            "NetChildVaultPositionsAction" => Ok(ActionVariant::V13),
            "order" => Ok(ActionVariant::V14),
            "registerReferrer" => Ok(ActionVariant::V15),
            "RegisterValidatorAction" => Ok(ActionVariant::V16),
            "CValidatorAction" => Ok(ActionVariant::V17),
            "scheduleCancel" => Ok(ActionVariant::V18),
            "setDisplayName" => Ok(ActionVariant::V19),
            "VoteGlobalAction" => Ok(ActionVariant::V20),
            "validatorL1Vote" => Ok(ActionVariant::V21),
            "validatorL1Stream" => Ok(ActionVariant::V22),
            "validatorL1Status" => Ok(ActionVariant::V23),
            "validatorL1UpdateReferenceOracle" => Ok(ActionVariant::V24),
            "SetGlobalAction" => Ok(ActionVariant::V25),
            "setReferrer" => Ok(ActionVariant::V26),
            "spotDeploy" => Ok(ActionVariant::V27),
            "spotUser" => Ok(ActionVariant::V28),
            "spotSend" => Ok(ActionVariant::V29),
            "SignValidatorSetUpdateAction" => Ok(ActionVariant::V30),
            "subAccountModify" => Ok(ActionVariant::V31),
            "subAccountTransfer" => Ok(ActionVariant::V32),
            "subAccountSpotTransfer" => Ok(ActionVariant::V33),
            "tokenDelegate" => Ok(ActionVariant::V34),
            "twapCancel" => Ok(ActionVariant::V35),
            "twapOrder" => Ok(ActionVariant::V36),
            "updateIsolatedMargin" => Ok(ActionVariant::V37),
            "topUpIsolatedOnlyMargin" => Ok(ActionVariant::V38),
            "updateLeverage" => Ok(ActionVariant::V39),
            "usdSend" => Ok(ActionVariant::V40),
            "ValidatorSignWithdrawalAction" => Ok(ActionVariant::V41),
            "vaultDistribute" => Ok(ActionVariant::V42),
            "vaultModify" => Ok(ActionVariant::V43),
            "vaultTransfer" => Ok(ActionVariant::V44),
            "VoteEthDepositAction" => Ok(ActionVariant::V45),
            "VoteEthFinalizedValidatorSetUpdateAction" => Ok(ActionVariant::V46),
            "VoteEthFinalizedWithdrawalAction" => Ok(ActionVariant::V47),
            "withdraw3" => Ok(ActionVariant::V48),
            "govPropose" => Ok(ActionVariant::V49),
            "govVote" => Ok(ActionVariant::V50),
            "usdClassTransfer" => Ok(ActionVariant::V51),
            "multiSig" => Ok(ActionVariant::V52),
            "convertToMultiSigUser" => Ok(ActionVariant::V53),
            "approveBuilderFee" => Ok(ActionVariant::V54),
            "startFeeTrial" => Ok(ActionVariant::V55),
            "SystemBoleAction" => Ok(ActionVariant::V56),
            "SystemSpotSendAction" => Ok(ActionVariant::V57),
            "deployerSendToEvmForFrozenUser" => Ok(ActionVariant::V58),
            "SystemUsdClassTransferAction" => Ok(ActionVariant::V59),
            "CSignerAction" => Ok(ActionVariant::V60),
            "cWithdraw" => Ok(ActionVariant::V61),
            "cDeposit" => Ok(ActionVariant::V62),
            "cUserModify" => Ok(ActionVariant::V63),
            "reassessFees" => Ok(ActionVariant::V64),
            "evmUserModify" => Ok(ActionVariant::V65),
            "reserveRequestWeight" => Ok(ActionVariant::V66),
            "finalizeEvmContract" => Ok(ActionVariant::V67),
            "perpDeploy" => Ok(ActionVariant::V68),
            "sendAsset" => Ok(ActionVariant::V69),
            "SystemApproveBuilderFeeAction" => Ok(ActionVariant::V70),
            "SystemSendAssetAction" => Ok(ActionVariant::V71),
            "agentEnableDexAbstraction" => Ok(ActionVariant::V72),
            "userDexAbstraction" => Ok(ActionVariant::V73),
            "borrowLend" => Ok(ActionVariant::V74),
            "sendToEvmWithData" => Ok(ActionVariant::V75),
            "userPortfolioMargin" => Ok(ActionVariant::V76),
            "userSetAbstraction" => Ok(ActionVariant::V77),
            "agentSetAbstraction" => Ok(ActionVariant::V78),
            "userOutcome" => Ok(ActionVariant::V79),
            "gossipPriorityBid" => Ok(ActionVariant::V80),
            "agentSendAsset" => Ok(ActionVariant::V81),
            "hip3LiquidatorTransfer" => Ok(ActionVariant::V82),
            "l1ValidatorVoteBridgeDeposit" => Ok(ActionVariant::V83),
            "authorizeAqav2Role" => Ok(ActionVariant::V84),
            "stakingLinkDisableTradingUser" => Ok(ActionVariant::V85),
            "voteL1Hash" => Ok(ActionVariant::V86),
            "voteAbciDigest" => Ok(ActionVariant::V87),
            "activateOutcomeDeployer" => Ok(ActionVariant::V88),
            "trailingStop" => Ok(ActionVariant::V89),
            "outcomeDeploy" => Ok(ActionVariant::V90),
            "cDeposit2" => Ok(ActionVariant::V91),
            _ => Err(rmp32_unknown_variant(v, FIELDS)),
        }
    }

    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<ActionVariant, JsonErr> {
        match v {
            "noop" => Ok(ActionVariant::V0),
            "approveAgent" => Ok(ActionVariant::V1),
            "batchModify" => Ok(ActionVariant::V2),
            "cancel" => Ok(ActionVariant::V3),
            "cancelByCloid" => Ok(ActionVariant::V4),
            "claimRewards" => Ok(ActionVariant::V5),
            "createSubAccount" => Ok(ActionVariant::V6),
            "createVault" => Ok(ActionVariant::V7),
            "evmRawTx" => Ok(ActionVariant::V8),
            "ForceIncreaseEpochAction" => Ok(ActionVariant::V9),
            "liquidate" => Ok(ActionVariant::V10),
            "linkStakingUser" => Ok(ActionVariant::V11),
            "modify" => Ok(ActionVariant::V12),
            "NetChildVaultPositionsAction" => Ok(ActionVariant::V13),
            "order" => Ok(ActionVariant::V14),
            "registerReferrer" => Ok(ActionVariant::V15),
            "RegisterValidatorAction" => Ok(ActionVariant::V16),
            "CValidatorAction" => Ok(ActionVariant::V17),
            "scheduleCancel" => Ok(ActionVariant::V18),
            "setDisplayName" => Ok(ActionVariant::V19),
            "VoteGlobalAction" => Ok(ActionVariant::V20),
            "validatorL1Vote" => Ok(ActionVariant::V21),
            "validatorL1Stream" => Ok(ActionVariant::V22),
            "validatorL1Status" => Ok(ActionVariant::V23),
            "validatorL1UpdateReferenceOracle" => Ok(ActionVariant::V24),
            "SetGlobalAction" => Ok(ActionVariant::V25),
            "setReferrer" => Ok(ActionVariant::V26),
            "spotDeploy" => Ok(ActionVariant::V27),
            "spotUser" => Ok(ActionVariant::V28),
            "spotSend" => Ok(ActionVariant::V29),
            "SignValidatorSetUpdateAction" => Ok(ActionVariant::V30),
            "subAccountModify" => Ok(ActionVariant::V31),
            "subAccountTransfer" => Ok(ActionVariant::V32),
            "subAccountSpotTransfer" => Ok(ActionVariant::V33),
            "tokenDelegate" => Ok(ActionVariant::V34),
            "twapCancel" => Ok(ActionVariant::V35),
            "twapOrder" => Ok(ActionVariant::V36),
            "updateIsolatedMargin" => Ok(ActionVariant::V37),
            "topUpIsolatedOnlyMargin" => Ok(ActionVariant::V38),
            "updateLeverage" => Ok(ActionVariant::V39),
            "usdSend" => Ok(ActionVariant::V40),
            "ValidatorSignWithdrawalAction" => Ok(ActionVariant::V41),
            "vaultDistribute" => Ok(ActionVariant::V42),
            "vaultModify" => Ok(ActionVariant::V43),
            "vaultTransfer" => Ok(ActionVariant::V44),
            "VoteEthDepositAction" => Ok(ActionVariant::V45),
            "VoteEthFinalizedValidatorSetUpdateAction" => Ok(ActionVariant::V46),
            "VoteEthFinalizedWithdrawalAction" => Ok(ActionVariant::V47),
            "withdraw3" => Ok(ActionVariant::V48),
            "govPropose" => Ok(ActionVariant::V49),
            "govVote" => Ok(ActionVariant::V50),
            "usdClassTransfer" => Ok(ActionVariant::V51),
            "multiSig" => Ok(ActionVariant::V52),
            "convertToMultiSigUser" => Ok(ActionVariant::V53),
            "approveBuilderFee" => Ok(ActionVariant::V54),
            "startFeeTrial" => Ok(ActionVariant::V55),
            "SystemBoleAction" => Ok(ActionVariant::V56),
            "SystemSpotSendAction" => Ok(ActionVariant::V57),
            "deployerSendToEvmForFrozenUser" => Ok(ActionVariant::V58),
            "SystemUsdClassTransferAction" => Ok(ActionVariant::V59),
            "CSignerAction" => Ok(ActionVariant::V60),
            "cWithdraw" => Ok(ActionVariant::V61),
            "cDeposit" => Ok(ActionVariant::V62),
            "cUserModify" => Ok(ActionVariant::V63),
            "reassessFees" => Ok(ActionVariant::V64),
            "evmUserModify" => Ok(ActionVariant::V65),
            "reserveRequestWeight" => Ok(ActionVariant::V66),
            "finalizeEvmContract" => Ok(ActionVariant::V67),
            "perpDeploy" => Ok(ActionVariant::V68),
            "sendAsset" => Ok(ActionVariant::V69),
            "SystemApproveBuilderFeeAction" => Ok(ActionVariant::V70),
            "SystemSendAssetAction" => Ok(ActionVariant::V71),
            "agentEnableDexAbstraction" => Ok(ActionVariant::V72),
            "userDexAbstraction" => Ok(ActionVariant::V73),
            "borrowLend" => Ok(ActionVariant::V74),
            "sendToEvmWithData" => Ok(ActionVariant::V75),
            "userPortfolioMargin" => Ok(ActionVariant::V76),
            "userSetAbstraction" => Ok(ActionVariant::V77),
            "agentSetAbstraction" => Ok(ActionVariant::V78),
            "userOutcome" => Ok(ActionVariant::V79),
            "gossipPriorityBid" => Ok(ActionVariant::V80),
            "agentSendAsset" => Ok(ActionVariant::V81),
            "hip3LiquidatorTransfer" => Ok(ActionVariant::V82),
            "l1ValidatorVoteBridgeDeposit" => Ok(ActionVariant::V83),
            "authorizeAqav2Role" => Ok(ActionVariant::V84),
            "stakingLinkDisableTradingUser" => Ok(ActionVariant::V85),
            "voteL1Hash" => Ok(ActionVariant::V86),
            "voteAbciDigest" => Ok(ActionVariant::V87),
            "activateOutcomeDeployer" => Ok(ActionVariant::V88),
            "trailingStop" => Ok(ActionVariant::V89),
            "outcomeDeploy" => Ok(ActionVariant::V90),
            "cDeposit2" => Ok(ActionVariant::V91),
            _ => Err(json_unknown_variant(v, FIELDS)),
        }
    }
}

pub mod env79 {
    use super::*;

    #[repr(u8)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum NodeEnv {
        V0 = 0, V1 = 1, V2 = 2, V3 = 3, V4 = 4, V5 = 5, V6 = 6, V7 = 7, V8 = 8, V9 = 9, V10 = 10, V11 = 11, V12 = 12, V13 = 13, V14 = 14, V15 = 15, V16 = 16, V17 = 17, V18 = 18, V19 = 19, V20 = 20, V21 = 21, V22 = 22, V23 = 23, V24 = 24, V25 = 25, V26 = 26, V27 = 27, V28 = 28, V29 = 29, V30 = 30, V31 = 31, V32 = 32, V33 = 33, V34 = 34, V35 = 35, V36 = 36, V37 = 37, V38 = 38, V39 = 39, V40 = 40, V41 = 41, V42 = 42, V43 = 43, V44 = 44, V45 = 45, V46 = 46, V47 = 47, V48 = 48, V49 = 49, V50 = 50, V51 = 51, V52 = 52, V53 = 53, V54 = 54, V55 = 55, V56 = 56, V57 = 57, V58 = 58, V59 = 59, V60 = 60, V61 = 61, V62 = 62, V63 = 63, V64 = 64, V65 = 65, V66 = 66, V67 = 67, V68 = 68, V69 = 69, V70 = 70, V71 = 71, V72 = 72, V73 = 73, V74 = 74, V75 = 75, V76 = 76, V77 = 77, V78 = 78,
    }

    pub static FIELDS: &[&str] = &["Ec", "DummyTokyo", "DummyTokyo2", "GaOnchain", "GbOnchain", "NodeTestnet", "NodeTestnet2", "NodeTestnet3", "NodeTestnet4", "Ea", "Ea2", "Ea3", "EaMm", "EaTx", "HeavyTestnet", "HeavyMainnet", "Eb", "Ed", "Ee", "SoloTestnet", "SoloMainnet", "LockerTestnet", "LockerMainnet", "RpcTestnet", "RpcSandbox", "RpcMainnet", "RpcMainnet2", "Sa", "Sb", "Sc", "Sd", "WebSandbox", "SoloSandbox", "NvTestnet", "NvTestnet2", "NvMainnet", "NvMainnet2", "NvMainnet3", "JoinMainnet", "DummyNv", "FBinSpot", "FBinSpot2", "FBinSpot3", "FBinSpot4", "FBinSpot5", "FBinSpot6", "FBinSpot7", "FBinSpot8", "FBinPerp", "FBinPerp2", "FOkexSpot", "FOkexSpot2", "FOkexPerp", "FHuobiSpot", "FHuobiSpot2", "FHuobiSpot3", "FHuobiSpot4", "FHuobiPi", "FHuobiPerp", "FCobSpot", "FKraSpot", "FBybitSpot", "ScratchDummy", "ScratchCron", "OBinSpot", "FHlPerp", "GaHlPerp", "GaHlPerp2", "GaHlPerp3", "GbHlPerp", "GbHlPerp2", "GbHlPerp3", "GcHlPerp", "GcHlPerp2", "GdHlPerp", "GdHlPerp2", "GsHlPerp", "EaHlPerp", "EbHlPerp"];

    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<NodeEnv, RmpErr32> {
        match v {
            "Ec" => Ok(NodeEnv::V0),
            "DummyTokyo" => Ok(NodeEnv::V1),
            "DummyTokyo2" => Ok(NodeEnv::V2),
            "GaOnchain" => Ok(NodeEnv::V3),
            "GbOnchain" => Ok(NodeEnv::V4),
            "NodeTestnet" => Ok(NodeEnv::V5),
            "NodeTestnet2" => Ok(NodeEnv::V6),
            "NodeTestnet3" => Ok(NodeEnv::V7),
            "NodeTestnet4" => Ok(NodeEnv::V8),
            "Ea" => Ok(NodeEnv::V9),
            "Ea2" => Ok(NodeEnv::V10),
            "Ea3" => Ok(NodeEnv::V11),
            "EaMm" => Ok(NodeEnv::V12),
            "EaTx" => Ok(NodeEnv::V13),
            "HeavyTestnet" => Ok(NodeEnv::V14),
            "HeavyMainnet" => Ok(NodeEnv::V15),
            "Eb" => Ok(NodeEnv::V16),
            "Ed" => Ok(NodeEnv::V17),
            "Ee" => Ok(NodeEnv::V18),
            "SoloTestnet" => Ok(NodeEnv::V19),
            "SoloMainnet" => Ok(NodeEnv::V20),
            "LockerTestnet" => Ok(NodeEnv::V21),
            "LockerMainnet" => Ok(NodeEnv::V22),
            "RpcTestnet" => Ok(NodeEnv::V23),
            "RpcSandbox" => Ok(NodeEnv::V24),
            "RpcMainnet" => Ok(NodeEnv::V25),
            "RpcMainnet2" => Ok(NodeEnv::V26),
            "Sa" => Ok(NodeEnv::V27),
            "Sb" => Ok(NodeEnv::V28),
            "Sc" => Ok(NodeEnv::V29),
            "Sd" => Ok(NodeEnv::V30),
            "WebSandbox" => Ok(NodeEnv::V31),
            "SoloSandbox" => Ok(NodeEnv::V32),
            "NvTestnet" => Ok(NodeEnv::V33),
            "NvTestnet2" => Ok(NodeEnv::V34),
            "NvMainnet" => Ok(NodeEnv::V35),
            "NvMainnet2" => Ok(NodeEnv::V36),
            "NvMainnet3" => Ok(NodeEnv::V37),
            "JoinMainnet" => Ok(NodeEnv::V38),
            "DummyNv" => Ok(NodeEnv::V39),
            "FBinSpot" => Ok(NodeEnv::V40),
            "FBinSpot2" => Ok(NodeEnv::V41),
            "FBinSpot3" => Ok(NodeEnv::V42),
            "FBinSpot4" => Ok(NodeEnv::V43),
            "FBinSpot5" => Ok(NodeEnv::V44),
            "FBinSpot6" => Ok(NodeEnv::V45),
            "FBinSpot7" => Ok(NodeEnv::V46),
            "FBinSpot8" => Ok(NodeEnv::V47),
            "FBinPerp" => Ok(NodeEnv::V48),
            "FBinPerp2" => Ok(NodeEnv::V49),
            "FOkexSpot" => Ok(NodeEnv::V50),
            "FOkexSpot2" => Ok(NodeEnv::V51),
            "FOkexPerp" => Ok(NodeEnv::V52),
            "FHuobiSpot" => Ok(NodeEnv::V53),
            "FHuobiSpot2" => Ok(NodeEnv::V54),
            "FHuobiSpot3" => Ok(NodeEnv::V55),
            "FHuobiSpot4" => Ok(NodeEnv::V56),
            "FHuobiPi" => Ok(NodeEnv::V57),
            "FHuobiPerp" => Ok(NodeEnv::V58),
            "FCobSpot" => Ok(NodeEnv::V59),
            "FKraSpot" => Ok(NodeEnv::V60),
            "FBybitSpot" => Ok(NodeEnv::V61),
            "ScratchDummy" => Ok(NodeEnv::V62),
            "ScratchCron" => Ok(NodeEnv::V63),
            "OBinSpot" => Ok(NodeEnv::V64),
            "FHlPerp" => Ok(NodeEnv::V65),
            "GaHlPerp" => Ok(NodeEnv::V66),
            "GaHlPerp2" => Ok(NodeEnv::V67),
            "GaHlPerp3" => Ok(NodeEnv::V68),
            "GbHlPerp" => Ok(NodeEnv::V69),
            "GbHlPerp2" => Ok(NodeEnv::V70),
            "GbHlPerp3" => Ok(NodeEnv::V71),
            "GcHlPerp" => Ok(NodeEnv::V72),
            "GcHlPerp2" => Ok(NodeEnv::V73),
            "GdHlPerp" => Ok(NodeEnv::V74),
            "GdHlPerp2" => Ok(NodeEnv::V75),
            "GsHlPerp" => Ok(NodeEnv::V76),
            "EaHlPerp" => Ok(NodeEnv::V77),
            "EbHlPerp" => Ok(NodeEnv::V78),
            _ => Err(rmp32_unknown_variant(v, FIELDS)),
        }
    }

    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<NodeEnv, JsonErr> {
        match v {
            "Ec" => Ok(NodeEnv::V0),
            "DummyTokyo" => Ok(NodeEnv::V1),
            "DummyTokyo2" => Ok(NodeEnv::V2),
            "GaOnchain" => Ok(NodeEnv::V3),
            "GbOnchain" => Ok(NodeEnv::V4),
            "NodeTestnet" => Ok(NodeEnv::V5),
            "NodeTestnet2" => Ok(NodeEnv::V6),
            "NodeTestnet3" => Ok(NodeEnv::V7),
            "NodeTestnet4" => Ok(NodeEnv::V8),
            "Ea" => Ok(NodeEnv::V9),
            "Ea2" => Ok(NodeEnv::V10),
            "Ea3" => Ok(NodeEnv::V11),
            "EaMm" => Ok(NodeEnv::V12),
            "EaTx" => Ok(NodeEnv::V13),
            "HeavyTestnet" => Ok(NodeEnv::V14),
            "HeavyMainnet" => Ok(NodeEnv::V15),
            "Eb" => Ok(NodeEnv::V16),
            "Ed" => Ok(NodeEnv::V17),
            "Ee" => Ok(NodeEnv::V18),
            "SoloTestnet" => Ok(NodeEnv::V19),
            "SoloMainnet" => Ok(NodeEnv::V20),
            "LockerTestnet" => Ok(NodeEnv::V21),
            "LockerMainnet" => Ok(NodeEnv::V22),
            "RpcTestnet" => Ok(NodeEnv::V23),
            "RpcSandbox" => Ok(NodeEnv::V24),
            "RpcMainnet" => Ok(NodeEnv::V25),
            "RpcMainnet2" => Ok(NodeEnv::V26),
            "Sa" => Ok(NodeEnv::V27),
            "Sb" => Ok(NodeEnv::V28),
            "Sc" => Ok(NodeEnv::V29),
            "Sd" => Ok(NodeEnv::V30),
            "WebSandbox" => Ok(NodeEnv::V31),
            "SoloSandbox" => Ok(NodeEnv::V32),
            "NvTestnet" => Ok(NodeEnv::V33),
            "NvTestnet2" => Ok(NodeEnv::V34),
            "NvMainnet" => Ok(NodeEnv::V35),
            "NvMainnet2" => Ok(NodeEnv::V36),
            "NvMainnet3" => Ok(NodeEnv::V37),
            "JoinMainnet" => Ok(NodeEnv::V38),
            "DummyNv" => Ok(NodeEnv::V39),
            "FBinSpot" => Ok(NodeEnv::V40),
            "FBinSpot2" => Ok(NodeEnv::V41),
            "FBinSpot3" => Ok(NodeEnv::V42),
            "FBinSpot4" => Ok(NodeEnv::V43),
            "FBinSpot5" => Ok(NodeEnv::V44),
            "FBinSpot6" => Ok(NodeEnv::V45),
            "FBinSpot7" => Ok(NodeEnv::V46),
            "FBinSpot8" => Ok(NodeEnv::V47),
            "FBinPerp" => Ok(NodeEnv::V48),
            "FBinPerp2" => Ok(NodeEnv::V49),
            "FOkexSpot" => Ok(NodeEnv::V50),
            "FOkexSpot2" => Ok(NodeEnv::V51),
            "FOkexPerp" => Ok(NodeEnv::V52),
            "FHuobiSpot" => Ok(NodeEnv::V53),
            "FHuobiSpot2" => Ok(NodeEnv::V54),
            "FHuobiSpot3" => Ok(NodeEnv::V55),
            "FHuobiSpot4" => Ok(NodeEnv::V56),
            "FHuobiPi" => Ok(NodeEnv::V57),
            "FHuobiPerp" => Ok(NodeEnv::V58),
            "FCobSpot" => Ok(NodeEnv::V59),
            "FKraSpot" => Ok(NodeEnv::V60),
            "FBybitSpot" => Ok(NodeEnv::V61),
            "ScratchDummy" => Ok(NodeEnv::V62),
            "ScratchCron" => Ok(NodeEnv::V63),
            "OBinSpot" => Ok(NodeEnv::V64),
            "FHlPerp" => Ok(NodeEnv::V65),
            "GaHlPerp" => Ok(NodeEnv::V66),
            "GaHlPerp2" => Ok(NodeEnv::V67),
            "GaHlPerp3" => Ok(NodeEnv::V68),
            "GbHlPerp" => Ok(NodeEnv::V69),
            "GbHlPerp2" => Ok(NodeEnv::V70),
            "GbHlPerp3" => Ok(NodeEnv::V71),
            "GcHlPerp" => Ok(NodeEnv::V72),
            "GcHlPerp2" => Ok(NodeEnv::V73),
            "GdHlPerp" => Ok(NodeEnv::V74),
            "GdHlPerp2" => Ok(NodeEnv::V75),
            "GsHlPerp" => Ok(NodeEnv::V76),
            "EaHlPerp" => Ok(NodeEnv::V77),
            "EbHlPerp" => Ok(NodeEnv::V78),
            _ => Err(json_unknown_variant(v, FIELDS)),
        }
    }
}

pub mod short114 {
    use super::*;

    #[repr(u8)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ShortActionTag {
        V0 = 0, V1 = 1, V2 = 2, V3 = 3, V4 = 4, V5 = 5, V6 = 6, V7 = 7, V8 = 8, V9 = 9, V10 = 10, V11 = 11, V12 = 12, V13 = 13, V14 = 14, V15 = 15, V16 = 16, V17 = 17, V18 = 18, V19 = 19, V20 = 20, V21 = 21, V22 = 22, V23 = 23, V24 = 24, V25 = 25, V26 = 26, V27 = 27, V28 = 28, V29 = 29, V30 = 30, V31 = 31, V32 = 32, V33 = 33, V34 = 34, V35 = 35, V36 = 36, V37 = 37, V38 = 38, V39 = 39, V40 = 40, V41 = 41, V42 = 42, V43 = 43, V44 = 44, V45 = 45, V46 = 46, V47 = 47, V48 = 48, V49 = 49, V50 = 50, V51 = 51, V52 = 52, V53 = 53, V54 = 54, V55 = 55, V56 = 56, V57 = 57, V58 = 58, V59 = 59, V60 = 60, V61 = 61, V62 = 62, V63 = 63, V64 = 64, V65 = 65, V66 = 66, V67 = 67, V68 = 68, V69 = 69, V70 = 70, V71 = 71, V72 = 72, V73 = 73, V74 = 74, V75 = 75, V76 = 76, V77 = 77, V78 = 78, V79 = 79, V80 = 80, V81 = 81, V82 = 82, V83 = 83, V84 = 84, V85 = 85, V86 = 86, V87 = 87, V88 = 88, V89 = 89, V90 = 90, V91 = 91, V92 = 92, V93 = 93, V94 = 94, V95 = 95, V96 = 96, V97 = 97, V98 = 98, V99 = 99, V100 = 100, V101 = 101, V102 = 102, V103 = 103, V104 = 104, V105 = 105, V106 = 106, V107 = 107, V108 = 108, V109 = 109, V110 = 110, V111 = 111, V112 = 112, V113 = 113,
    }

    pub static FIELDS: &[&str] = &["a", "b", "c", "d", "e", "f", "g", "h", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "W", "X", "Y", "Z", "aa", "bb", "cc", "dd", "ee", "ff", "gg", "hh", "ii", "jj", "kk", "mm", "nn", "oo", "pp", "qq", "rr", "ss", "tt", "uu", "vv", "ww", "xx", "yy", "zz", "AA", "BB", "CC", "DD", "EE", "FF", "HH", "II", "JJ", "KK", "LL", "OO", "PP", "QQ", "RR", "TT", "UU", "VV", "WW", "XX", "YY", "ZZ", "aaa", "bbb", "ccc", "fff", "ggg", "hhh", "iii", "jjj", "kkk", "lll", "mmm", "nnn", "ooo", "ppp", "qqq", "rrr", "sss", "ttt"];

    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<ShortActionTag, RmpErr32> {
        match v {
            "a" => Ok(ShortActionTag::V0),
            "b" => Ok(ShortActionTag::V1),
            "c" => Ok(ShortActionTag::V2),
            "d" => Ok(ShortActionTag::V3),
            "e" => Ok(ShortActionTag::V4),
            "f" => Ok(ShortActionTag::V5),
            "g" => Ok(ShortActionTag::V6),
            "h" => Ok(ShortActionTag::V7),
            "j" => Ok(ShortActionTag::V8),
            "k" => Ok(ShortActionTag::V9),
            "l" => Ok(ShortActionTag::V10),
            "m" => Ok(ShortActionTag::V11),
            "n" => Ok(ShortActionTag::V12),
            "o" => Ok(ShortActionTag::V13),
            "p" => Ok(ShortActionTag::V14),
            "q" => Ok(ShortActionTag::V15),
            "r" => Ok(ShortActionTag::V16),
            "s" => Ok(ShortActionTag::V17),
            "t" => Ok(ShortActionTag::V18),
            "u" => Ok(ShortActionTag::V19),
            "v" => Ok(ShortActionTag::V20),
            "w" => Ok(ShortActionTag::V21),
            "x" => Ok(ShortActionTag::V22),
            "y" => Ok(ShortActionTag::V23),
            "z" => Ok(ShortActionTag::V24),
            "A" => Ok(ShortActionTag::V25),
            "B" => Ok(ShortActionTag::V26),
            "C" => Ok(ShortActionTag::V27),
            "D" => Ok(ShortActionTag::V28),
            "E" => Ok(ShortActionTag::V29),
            "F" => Ok(ShortActionTag::V30),
            "G" => Ok(ShortActionTag::V31),
            "H" => Ok(ShortActionTag::V32),
            "I" => Ok(ShortActionTag::V33),
            "J" => Ok(ShortActionTag::V34),
            "K" => Ok(ShortActionTag::V35),
            "L" => Ok(ShortActionTag::V36),
            "M" => Ok(ShortActionTag::V37),
            "N" => Ok(ShortActionTag::V38),
            "O" => Ok(ShortActionTag::V39),
            "P" => Ok(ShortActionTag::V40),
            "Q" => Ok(ShortActionTag::V41),
            "R" => Ok(ShortActionTag::V42),
            "S" => Ok(ShortActionTag::V43),
            "T" => Ok(ShortActionTag::V44),
            "W" => Ok(ShortActionTag::V45),
            "X" => Ok(ShortActionTag::V46),
            "Y" => Ok(ShortActionTag::V47),
            "Z" => Ok(ShortActionTag::V48),
            "aa" => Ok(ShortActionTag::V49),
            "bb" => Ok(ShortActionTag::V50),
            "cc" => Ok(ShortActionTag::V51),
            "dd" => Ok(ShortActionTag::V52),
            "ee" => Ok(ShortActionTag::V53),
            "ff" => Ok(ShortActionTag::V54),
            "gg" => Ok(ShortActionTag::V55),
            "hh" => Ok(ShortActionTag::V56),
            "ii" => Ok(ShortActionTag::V57),
            "jj" => Ok(ShortActionTag::V58),
            "kk" => Ok(ShortActionTag::V59),
            "mm" => Ok(ShortActionTag::V60),
            "nn" => Ok(ShortActionTag::V61),
            "oo" => Ok(ShortActionTag::V62),
            "pp" => Ok(ShortActionTag::V63),
            "qq" => Ok(ShortActionTag::V64),
            "rr" => Ok(ShortActionTag::V65),
            "ss" => Ok(ShortActionTag::V66),
            "tt" => Ok(ShortActionTag::V67),
            "uu" => Ok(ShortActionTag::V68),
            "vv" => Ok(ShortActionTag::V69),
            "ww" => Ok(ShortActionTag::V70),
            "xx" => Ok(ShortActionTag::V71),
            "yy" => Ok(ShortActionTag::V72),
            "zz" => Ok(ShortActionTag::V73),
            "AA" => Ok(ShortActionTag::V74),
            "BB" => Ok(ShortActionTag::V75),
            "CC" => Ok(ShortActionTag::V76),
            "DD" => Ok(ShortActionTag::V77),
            "EE" => Ok(ShortActionTag::V78),
            "FF" => Ok(ShortActionTag::V79),
            "HH" => Ok(ShortActionTag::V80),
            "II" => Ok(ShortActionTag::V81),
            "JJ" => Ok(ShortActionTag::V82),
            "KK" => Ok(ShortActionTag::V83),
            "LL" => Ok(ShortActionTag::V84),
            "OO" => Ok(ShortActionTag::V85),
            "PP" => Ok(ShortActionTag::V86),
            "QQ" => Ok(ShortActionTag::V87),
            "RR" => Ok(ShortActionTag::V88),
            "TT" => Ok(ShortActionTag::V89),
            "UU" => Ok(ShortActionTag::V90),
            "VV" => Ok(ShortActionTag::V91),
            "WW" => Ok(ShortActionTag::V92),
            "XX" => Ok(ShortActionTag::V93),
            "YY" => Ok(ShortActionTag::V94),
            "ZZ" => Ok(ShortActionTag::V95),
            "aaa" => Ok(ShortActionTag::V96),
            "bbb" => Ok(ShortActionTag::V97),
            "ccc" => Ok(ShortActionTag::V98),
            "fff" => Ok(ShortActionTag::V99),
            "ggg" => Ok(ShortActionTag::V100),
            "hhh" => Ok(ShortActionTag::V101),
            "iii" => Ok(ShortActionTag::V102),
            "jjj" => Ok(ShortActionTag::V103),
            "kkk" => Ok(ShortActionTag::V104),
            "lll" => Ok(ShortActionTag::V105),
            "mmm" => Ok(ShortActionTag::V106),
            "nnn" => Ok(ShortActionTag::V107),
            "ooo" => Ok(ShortActionTag::V108),
            "ppp" => Ok(ShortActionTag::V109),
            "qqq" => Ok(ShortActionTag::V110),
            "rrr" => Ok(ShortActionTag::V111),
            "sss" => Ok(ShortActionTag::V112),
            "ttt" => Ok(ShortActionTag::V113),
            _ => Err(rmp32_unknown_variant(v, FIELDS)),
        }
    }

    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<ShortActionTag, JsonErr> {
        match v {
            "a" => Ok(ShortActionTag::V0),
            "b" => Ok(ShortActionTag::V1),
            "c" => Ok(ShortActionTag::V2),
            "d" => Ok(ShortActionTag::V3),
            "e" => Ok(ShortActionTag::V4),
            "f" => Ok(ShortActionTag::V5),
            "g" => Ok(ShortActionTag::V6),
            "h" => Ok(ShortActionTag::V7),
            "j" => Ok(ShortActionTag::V8),
            "k" => Ok(ShortActionTag::V9),
            "l" => Ok(ShortActionTag::V10),
            "m" => Ok(ShortActionTag::V11),
            "n" => Ok(ShortActionTag::V12),
            "o" => Ok(ShortActionTag::V13),
            "p" => Ok(ShortActionTag::V14),
            "q" => Ok(ShortActionTag::V15),
            "r" => Ok(ShortActionTag::V16),
            "s" => Ok(ShortActionTag::V17),
            "t" => Ok(ShortActionTag::V18),
            "u" => Ok(ShortActionTag::V19),
            "v" => Ok(ShortActionTag::V20),
            "w" => Ok(ShortActionTag::V21),
            "x" => Ok(ShortActionTag::V22),
            "y" => Ok(ShortActionTag::V23),
            "z" => Ok(ShortActionTag::V24),
            "A" => Ok(ShortActionTag::V25),
            "B" => Ok(ShortActionTag::V26),
            "C" => Ok(ShortActionTag::V27),
            "D" => Ok(ShortActionTag::V28),
            "E" => Ok(ShortActionTag::V29),
            "F" => Ok(ShortActionTag::V30),
            "G" => Ok(ShortActionTag::V31),
            "H" => Ok(ShortActionTag::V32),
            "I" => Ok(ShortActionTag::V33),
            "J" => Ok(ShortActionTag::V34),
            "K" => Ok(ShortActionTag::V35),
            "L" => Ok(ShortActionTag::V36),
            "M" => Ok(ShortActionTag::V37),
            "N" => Ok(ShortActionTag::V38),
            "O" => Ok(ShortActionTag::V39),
            "P" => Ok(ShortActionTag::V40),
            "Q" => Ok(ShortActionTag::V41),
            "R" => Ok(ShortActionTag::V42),
            "S" => Ok(ShortActionTag::V43),
            "T" => Ok(ShortActionTag::V44),
            "W" => Ok(ShortActionTag::V45),
            "X" => Ok(ShortActionTag::V46),
            "Y" => Ok(ShortActionTag::V47),
            "Z" => Ok(ShortActionTag::V48),
            "aa" => Ok(ShortActionTag::V49),
            "bb" => Ok(ShortActionTag::V50),
            "cc" => Ok(ShortActionTag::V51),
            "dd" => Ok(ShortActionTag::V52),
            "ee" => Ok(ShortActionTag::V53),
            "ff" => Ok(ShortActionTag::V54),
            "gg" => Ok(ShortActionTag::V55),
            "hh" => Ok(ShortActionTag::V56),
            "ii" => Ok(ShortActionTag::V57),
            "jj" => Ok(ShortActionTag::V58),
            "kk" => Ok(ShortActionTag::V59),
            "mm" => Ok(ShortActionTag::V60),
            "nn" => Ok(ShortActionTag::V61),
            "oo" => Ok(ShortActionTag::V62),
            "pp" => Ok(ShortActionTag::V63),
            "qq" => Ok(ShortActionTag::V64),
            "rr" => Ok(ShortActionTag::V65),
            "ss" => Ok(ShortActionTag::V66),
            "tt" => Ok(ShortActionTag::V67),
            "uu" => Ok(ShortActionTag::V68),
            "vv" => Ok(ShortActionTag::V69),
            "ww" => Ok(ShortActionTag::V70),
            "xx" => Ok(ShortActionTag::V71),
            "yy" => Ok(ShortActionTag::V72),
            "zz" => Ok(ShortActionTag::V73),
            "AA" => Ok(ShortActionTag::V74),
            "BB" => Ok(ShortActionTag::V75),
            "CC" => Ok(ShortActionTag::V76),
            "DD" => Ok(ShortActionTag::V77),
            "EE" => Ok(ShortActionTag::V78),
            "FF" => Ok(ShortActionTag::V79),
            "HH" => Ok(ShortActionTag::V80),
            "II" => Ok(ShortActionTag::V81),
            "JJ" => Ok(ShortActionTag::V82),
            "KK" => Ok(ShortActionTag::V83),
            "LL" => Ok(ShortActionTag::V84),
            "OO" => Ok(ShortActionTag::V85),
            "PP" => Ok(ShortActionTag::V86),
            "QQ" => Ok(ShortActionTag::V87),
            "RR" => Ok(ShortActionTag::V88),
            "TT" => Ok(ShortActionTag::V89),
            "UU" => Ok(ShortActionTag::V90),
            "VV" => Ok(ShortActionTag::V91),
            "WW" => Ok(ShortActionTag::V92),
            "XX" => Ok(ShortActionTag::V93),
            "YY" => Ok(ShortActionTag::V94),
            "ZZ" => Ok(ShortActionTag::V95),
            "aaa" => Ok(ShortActionTag::V96),
            "bbb" => Ok(ShortActionTag::V97),
            "ccc" => Ok(ShortActionTag::V98),
            "fff" => Ok(ShortActionTag::V99),
            "ggg" => Ok(ShortActionTag::V100),
            "hhh" => Ok(ShortActionTag::V101),
            "iii" => Ok(ShortActionTag::V102),
            "jjj" => Ok(ShortActionTag::V103),
            "kkk" => Ok(ShortActionTag::V104),
            "lll" => Ok(ShortActionTag::V105),
            "mmm" => Ok(ShortActionTag::V106),
            "nnn" => Ok(ShortActionTag::V107),
            "ooo" => Ok(ShortActionTag::V108),
            "ppp" => Ok(ShortActionTag::V109),
            "qqq" => Ok(ShortActionTag::V110),
            "rrr" => Ok(ShortActionTag::V111),
            "sss" => Ok(ShortActionTag::V112),
            "ttt" => Ok(ShortActionTag::V113),
            _ => Err(json_unknown_variant(v, FIELDS)),
        }
    }
}

pub mod perp16 {
    use super::*;

    #[repr(u8)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PerpDeployVariant {
        V0 = 0, V1 = 1, V2 = 2, V3 = 3, V4 = 4, V5 = 5, V6 = 6, V7 = 7, V8 = 8, V9 = 9, V10 = 10, V11 = 11, V12 = 12, V13 = 13, V14 = 14, V15 = 15,
    }

    pub static FIELDS: &[&str] = &["registerAsset", "setOracle", "insertMarginTable", "setFeeRecipient", "haltTrading", "setMarginTableIds", "setOpenInterestCaps", "setFundingMultipliers", "setMarginModes", "setDeployerFees", "setFeeScale", "setFundingInterestRates", "disableDex", "setPerpAnnotation", "migrateDexQuoteToken", "setFundingClamps", "hip3Star"];

    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<PerpDeployVariant, RmpErr32> {
        match v {
            "registerAsset" => Ok(PerpDeployVariant::V0),
            "setOracle" => Ok(PerpDeployVariant::V1),
            "insertMarginTable" => Ok(PerpDeployVariant::V2),
            "setFeeRecipient" => Ok(PerpDeployVariant::V3),
            "haltTrading" => Ok(PerpDeployVariant::V4),
            "setMarginTableIds" => Ok(PerpDeployVariant::V5),
            "setOpenInterestCaps" => Ok(PerpDeployVariant::V6),
            "setFundingMultipliers" => Ok(PerpDeployVariant::V7),
            "setMarginModes" => Ok(PerpDeployVariant::V8),
            "setDeployerFees" => Ok(PerpDeployVariant::V9),
            "setFeeScale" => Ok(PerpDeployVariant::V9),
            "setFundingInterestRates" => Ok(PerpDeployVariant::V10),
            "disableDex" => Ok(PerpDeployVariant::V11),
            "setPerpAnnotation" => Ok(PerpDeployVariant::V12),
            "migrateDexQuoteToken" => Ok(PerpDeployVariant::V13),
            "setFundingClamps" => Ok(PerpDeployVariant::V14),
            "hip3Star" => Ok(PerpDeployVariant::V15),
            _ => Err(rmp32_unknown_variant(v, FIELDS)),
        }
    }

    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<PerpDeployVariant, JsonErr> {
        match v {
            "registerAsset" => Ok(PerpDeployVariant::V0),
            "setOracle" => Ok(PerpDeployVariant::V1),
            "insertMarginTable" => Ok(PerpDeployVariant::V2),
            "setFeeRecipient" => Ok(PerpDeployVariant::V3),
            "haltTrading" => Ok(PerpDeployVariant::V4),
            "setMarginTableIds" => Ok(PerpDeployVariant::V5),
            "setOpenInterestCaps" => Ok(PerpDeployVariant::V6),
            "setFundingMultipliers" => Ok(PerpDeployVariant::V7),
            "setMarginModes" => Ok(PerpDeployVariant::V8),
            "setDeployerFees" => Ok(PerpDeployVariant::V9),
            "setFeeScale" => Ok(PerpDeployVariant::V9),
            "setFundingInterestRates" => Ok(PerpDeployVariant::V10),
            "disableDex" => Ok(PerpDeployVariant::V11),
            "setPerpAnnotation" => Ok(PerpDeployVariant::V12),
            "migrateDexQuoteToken" => Ok(PerpDeployVariant::V13),
            "setFundingClamps" => Ok(PerpDeployVariant::V14),
            "hip3Star" => Ok(PerpDeployVariant::V15),
            _ => Err(json_unknown_variant(v, FIELDS)),
        }
    }
}

pub mod hip3star {
    use super::*;

    #[repr(u8)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Hip3StarVariant {
        V0 = 0, V1 = 1, V2 = 2, V3 = 3, V4 = 4, V5 = 5, V6 = 6, V7 = 7,
    }

    pub static FIELDS: &[&str] = &["modifyApproval", "modifyBackstopLiquidatorApproval", "setReduceOnly", "cancel", "cancelAll", "order", "sendAsset", "setOracle"];

    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Hip3StarVariant, RmpErr> {
        match v {
            "modifyApproval" => Ok(Hip3StarVariant::V0),
            "modifyBackstopLiquidatorApproval" => Ok(Hip3StarVariant::V1),
            "setReduceOnly" => Ok(Hip3StarVariant::V2),
            "cancel" => Ok(Hip3StarVariant::V3),
            "cancelAll" => Ok(Hip3StarVariant::V4),
            "order" => Ok(Hip3StarVariant::V5),
            "sendAsset" => Ok(Hip3StarVariant::V6),
            "setOracle" => Ok(Hip3StarVariant::V7),
            _ => Err(rmp_unknown_variant(v, FIELDS)),
        }
    }

    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Hip3StarVariant, JsonErr> {
        match v {
            "modifyApproval" => Ok(Hip3StarVariant::V0),
            "modifyBackstopLiquidatorApproval" => Ok(Hip3StarVariant::V1),
            "setReduceOnly" => Ok(Hip3StarVariant::V2),
            "cancel" => Ok(Hip3StarVariant::V3),
            "cancelAll" => Ok(Hip3StarVariant::V4),
            "order" => Ok(Hip3StarVariant::V5),
            "sendAsset" => Ok(Hip3StarVariant::V6),
            "setOracle" => Ok(Hip3StarVariant::V7),
            _ => Err(json_unknown_variant(v, FIELDS)),
        }
    }
}

pub mod main_hip3 {
    use super::*;

    #[repr(u8)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum DexStateKind {
        V0 = 0, V1 = 1,
    }

    pub static FIELDS: &[&str] = &["Main", "Hip3"];

    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<DexStateKind, RmpErr32> {
        match v {
            "Main" => Ok(DexStateKind::V0),
            "Hip3" => Ok(DexStateKind::V1),
            _ => Err(rmp32_unknown_variant(v, FIELDS)),
        }
    }

    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<DexStateKind, JsonErr> {
        match v {
            "Main" => Ok(DexStateKind::V0),
            "Hip3" => Ok(DexStateKind::V1),
            _ => Err(json_unknown_variant(v, FIELDS)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_helpers_match_target_semantics() {
        assert!(fp_slice20_equal(&[], &[]));
        assert!(fp_slice20_equal(&[[7u8; 20]], &[[7u8; 20]]));
        assert!(!fp_slice20_equal(&[[7u8; 20]], &[[8u8; 20]]));
        assert!(!fp_slice20_equal(&[[7u8; 20]], &[]));

        let desc = [5.0_f64, 3.0, 3.0, 1.0];
        let mut w = desc.windows(2);
        assert!(!fp_fee_window_scan(&mut w));
        let asc = [5.0_f64, 3.0, 4.0, 1.0];
        let mut w2 = asc.windows(2);
        assert!(fp_fee_window_scan(&mut w2));

        let mut lhs = [0u64, 0, 0, 0];
        let rhs = [1u64, 0, 0, 0];
        let mut out = ([0u64; 4], false);
        fp_sub256_borrow(&mut out, &mut lhs, &rhs);
        assert_eq!(out, ([u64::MAX; 4], true));
        assert_eq!(lhs, [u64::MAX; 4]);

        let empty: VecDeque<u64> = VecDeque::new();
        assert_eq!(fp_bounded_offset(&empty), Err(0));
        let mut ring = VecDeque::from([10u64, 20, 30, 40]);
        assert!(fp_bounded_offset(&ring).is_ok());
        ring.pop_front();
        ring.push_back(50);
        assert!(fp_bounded_offset(&ring).is_ok());

        let d80: VecDeque<[u8; 80]> = VecDeque::from([[1u8; 80], [2u8; 80]]);
        assert_eq!(fp_two_span_projection(&d80).count(), 2);
    }

    #[test]
    fn enum_visitors_accept_exact_variants_and_reject_unknown() {
        assert_eq!(chain_name::visit_str_rmp("Mainnet"), Ok(chain_name::ChainName::Mainnet));
        assert_eq!(chain_name::visit_str_json("Testnet"), Ok(chain_name::ChainName::Testnet));
        assert!(chain_name::visit_str_rmp("mainnet").is_err());

        assert_eq!(spot_mark::visit_str_rmp("ExternalPerp"), Ok(spot_mark::SpotMarkKind::ExternalPerp));
        assert!(spot_mark::visit_str_rmp("spot").is_err());

        assert_eq!(tif::visit_str_rmp("FrontendMarket"), Ok(tif::Tif::FrontendMarket));
        assert_eq!(tif::visit_str_json("LiquidationMarket"), Ok(tif::Tif::LiquidationMarket));
        assert!(tif::visit_str_rmp("GTC").is_err());

        assert_eq!(outcome_kind::visit_str_rmp("StandaloneOutcome"), Ok(outcome_kind::OutcomeKind::StandaloneOutcome));
        assert!(outcome_kind::visit_str_rmp("Other").is_err());

        assert_eq!(margin_mode::visit_str_rmp("strictIsolated"), Ok(margin_mode::MarginMode::StrictIsolated));
        assert!(margin_mode::visit_str_rmp("Normal").is_err());

        assert_eq!(borrow_lend_op::visit_str_rmp("withdraw"), Ok(borrow_lend_op::Operation::Withdraw));
        assert_eq!(borrow_lend_op::visit_str_json("borrow"), Ok(borrow_lend_op::Operation::Borrow));
        assert_eq!(borrow_lend_field::visit_str_rmp("amount"), Ok(borrow_lend_field::BorrowLendField::Amount));

        assert_eq!(bridge_event::visit_str_rmp("RequestedValidatorSetUpdateEvent"), Ok(bridge_event::BridgeEvent::RequestedValidatorSetUpdateEvent));
        assert_eq!(bridge_event::visit_str_json("Deposit"), Ok(bridge_event::BridgeEvent::Deposit));

        assert_eq!(hip3_disabled::visit_str_rmp("ValidatorDisabled"), Ok(hip3_disabled::DisabledState::ValidatorDisabled));
        assert_eq!(hip3_disabled::visit_str_json("m"), Ok(hip3_disabled::DisabledState::M));

        assert_eq!(evm_tx_type::visit_str_rmp("Eip7702"), Ok(evm_tx_type::EvmTxType::Eip7702));
        assert_eq!(evm_tx_type::visit_str_json("Legacy"), Ok(evm_tx_type::EvmTxType::Legacy));

        assert_eq!(evm_precompile_outcome::visit_str_rmp("OutOfGas"), Ok(evm_precompile_outcome::ReadPrecompileOutcomeName::OutOfGas));

        assert_eq!(abstraction_kind::visit_str_rmp("ActivateUnifiedAccount"), Ok(abstraction_kind::AbstractionKind::ActivateUnifiedAccount));
        assert_eq!(abstraction_kind::visit_str_json("AllBoleTokens"), Ok(abstraction_kind::AbstractionKind::AllBoleTokens));

        assert_eq!(vote_choice::visit_str_rmp("abstain"), Ok(vote_choice::VoteChoice::Abstain));
        assert_eq!(proposal_cat::visit_str_rmp("constitutional"), Ok(proposal_cat::ProposalCategory::Constitutional));
        assert_eq!(proposal_cat::visit_str_json("accelerated"), Ok(proposal_cat::ProposalCategory::Accelerated));
    }

    #[test]
    fn wave2_dispatch_and_config_enum_visitors_accept_and_reject() {
        assert_eq!(action92::visit_str_rmp("noop"), Ok(action92::ActionVariant::V0));
        assert_eq!(action92::visit_str_rmp("cDeposit2"), Ok(action92::ActionVariant::V91));
        assert_eq!(action92::visit_str_json("order"), Ok(action92::ActionVariant::V14));
        assert!(action92::visit_str_rmp("unknownAction").is_err());

        assert_eq!(env79::visit_str_rmp("Ec"), Ok(env79::NodeEnv::V0));
        assert_eq!(env79::visit_str_json("EbHlPerp"), Ok(env79::NodeEnv::V78));
        assert!(env79::visit_str_rmp("UnknownEnv").is_err());

        assert_eq!(short114::visit_str_rmp("a"), Ok(short114::ShortActionTag::V0));
        assert_eq!(short114::visit_str_json("ttt"), Ok(short114::ShortActionTag::V113));
        assert!(short114::visit_str_rmp("zzzz").is_err());

        assert_eq!(perp16::visit_str_rmp("setDeployerFees"), Ok(perp16::PerpDeployVariant::V9));
        assert_eq!(perp16::visit_str_rmp("setFeeScale"), Ok(perp16::PerpDeployVariant::V9));
        assert_eq!(perp16::visit_str_json("hip3Star"), Ok(perp16::PerpDeployVariant::V15));
        assert!(perp16::visit_str_rmp("unknownPerp").is_err());

        assert_eq!(hip3star::visit_str_rmp("modifyApproval"), Ok(hip3star::Hip3StarVariant::V0));
        assert_eq!(hip3star::visit_str_json("setOracle"), Ok(hip3star::Hip3StarVariant::V7));
        assert!(hip3star::visit_str_rmp("bad").is_err());

        assert_eq!(main_hip3::visit_str_rmp("Main"), Ok(main_hip3::DexStateKind::V0));
        assert_eq!(main_hip3::visit_str_rmp("Hip3"), Ok(main_hip3::DexStateKind::V1));
        assert!(main_hip3::visit_str_rmp("main").is_err());
    }

    #[test]
    fn wave3_enums_fields_assets_and_expecting_work() {
        assert_eq!(
            enums_wave3::info_request::visit_str_json("clearinghouseState"),
            Ok(enums_wave3::info_request::Variant::V7)
        );
        assert!(enums_wave3::info_request::visit_str_json("unknownInfo").is_err());

        assert_eq!(
            enums_wave3::indexed_artifact_content::visit_str_json("NodeArtifact"),
            Ok(enums_wave3::indexed_artifact_content::Variant::V3)
        );
        assert_eq!(
            enums_wave3::quorum_status::visit_str_rmp("Q"),
            Ok(enums_wave3::quorum_status::Variant::V0)
        );
        assert_eq!(
            enums_wave3::c_validator_action::visit_str_rmp("unregister"),
            Ok(enums_wave3::c_validator_action::Variant::V2)
        );
        assert_eq!(
            enums_wave3::vault_relationship::visit_str_rmp("parent"),
            Ok(enums_wave3::vault_relationship::Variant::V2)
        );

        assert_eq!(
            fields_wave3::send_asset_cross_chain::visit_str_rmp("destinationChainId"),
            Ok(fields_wave3::send_asset_cross_chain::Variant::V7)
        );
        assert_eq!(
            fields_wave3::validator_change_profile::visit_str_rmp("commission_bps"),
            Ok(fields_wave3::validator_change_profile::Variant::V5)
        );
        assert!(fields_wave3::base_fee_rates::visit_str_rmp("bad").is_err());

        let spec = assets_wave3::TokenSpec {
            _pad: [0; 0x18],
            sz_decimals: 2,
            wei_decimals: 8,
        };
        assert_eq!(assets_wave3::assets_token_wei_per_sz(&spec), 1_000_000);

        let mut out = String::new();
        let mut w: &mut dyn core::fmt::Write = &mut out;
        expecting_wave3::exp_000_enum_abstractionreturn(&(), &mut w).unwrap();
        assert_eq!(out, "enum AbstractionReturn");
    }
}
