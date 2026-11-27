//! Complete 92-variant `Action` tag/index/wire-name crosswalk for node #115.
//!
//! Anchored to `research/work-items/action-wire-variant-dispatch-crosswalk-115/crosswalk.tsv`
//! (dispatcher `0x36c3180`, table `0x79b120`, 92 variants).

/// Base tag word for non-niche variants (`0x86` -> index 0).
pub const ACTION_TAG_BASE: u64 = 0x86;

/// Maximum valid tag word (`0xe1` -> index 91).
pub const ACTION_TAG_MAX: u64 = 0xe1;

/// Niche default index for any tag word `< 0x86` (`VoteGlobal`).
pub const VOTE_GLOBAL_NICHE_INDEX: usize = 20;

/// Metadata for one of the 92 node #115 `Action` variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActionVariantInfo {
    pub index: usize,
    /// Canonical tag word (`0x86 + index`; note index 20 `VoteGlobal` is selected by any tag `< 0x86`).
    pub canonical_tag: u64,
    pub variant_name: &'static str,
    pub wire_name: &'static str,
}

/// Complete 92-entry table in exact node #115 index order (`0..=91`).
pub const ACTION_VARIANTS: [ActionVariantInfo; 92] = [
    ActionVariantInfo { index: 0, canonical_tag: 0x86, variant_name: "Noop", wire_name: "noop" },
    ActionVariantInfo { index: 1, canonical_tag: 0x87, variant_name: "ApproveAgent3", wire_name: "approveAgent" },
    ActionVariantInfo { index: 2, canonical_tag: 0x88, variant_name: "BatchModify", wire_name: "batchModify" },
    ActionVariantInfo { index: 3, canonical_tag: 0x89, variant_name: "Cancel", wire_name: "cancel" },
    ActionVariantInfo { index: 4, canonical_tag: 0x8a, variant_name: "CancelByCloid", wire_name: "cancelByCloid" },
    ActionVariantInfo { index: 5, canonical_tag: 0x8b, variant_name: "ClaimRewards", wire_name: "claimRewards" },
    ActionVariantInfo { index: 6, canonical_tag: 0x8c, variant_name: "CreateSubAccount", wire_name: "createSubAccount" },
    ActionVariantInfo { index: 7, canonical_tag: 0x8d, variant_name: "CreateVault", wire_name: "createVault" },
    ActionVariantInfo { index: 8, canonical_tag: 0x8e, variant_name: "EvmRawTx", wire_name: "evmRawTx" },
    ActionVariantInfo { index: 9, canonical_tag: 0x8f, variant_name: "ForceIncreaseEpoch", wire_name: "ForceIncreaseEpochAction" },
    ActionVariantInfo { index: 10, canonical_tag: 0x90, variant_name: "Liquidate", wire_name: "liquidate" },
    ActionVariantInfo { index: 11, canonical_tag: 0x91, variant_name: "LinkStakingUser", wire_name: "linkStakingUser" },
    ActionVariantInfo { index: 12, canonical_tag: 0x92, variant_name: "Modify", wire_name: "modify" },
    ActionVariantInfo { index: 13, canonical_tag: 0x93, variant_name: "NetChildVaultPositions", wire_name: "NetChildVaultPositionsAction" },
    ActionVariantInfo { index: 14, canonical_tag: 0x94, variant_name: "Order", wire_name: "order" },
    ActionVariantInfo { index: 15, canonical_tag: 0x95, variant_name: "RegisterReferrer", wire_name: "registerReferrer" },
    ActionVariantInfo { index: 16, canonical_tag: 0x96, variant_name: "RegisterValidator", wire_name: "RegisterValidatorAction" },
    ActionVariantInfo { index: 17, canonical_tag: 0x97, variant_name: "CValidator", wire_name: "CValidatorAction" },
    ActionVariantInfo { index: 18, canonical_tag: 0x98, variant_name: "ScheduleCancel", wire_name: "scheduleCancel" },
    ActionVariantInfo { index: 19, canonical_tag: 0x99, variant_name: "SetDisplayName", wire_name: "setDisplayName" },
    ActionVariantInfo { index: 20, canonical_tag: 0x9a, variant_name: "VoteGlobal", wire_name: "VoteGlobalAction" },
    ActionVariantInfo { index: 21, canonical_tag: 0x9b, variant_name: "ValidatorL1Vote", wire_name: "validatorL1Vote" },
    ActionVariantInfo { index: 22, canonical_tag: 0x9c, variant_name: "ValidatorL1Stream", wire_name: "validatorL1Stream" },
    ActionVariantInfo { index: 23, canonical_tag: 0x9d, variant_name: "ValidatorL1Status", wire_name: "validatorL1Status" },
    ActionVariantInfo { index: 24, canonical_tag: 0x9e, variant_name: "ValidatorL1UpdateReferenceOracle", wire_name: "validatorL1UpdateReferenceOracle" },
    ActionVariantInfo { index: 25, canonical_tag: 0x9f, variant_name: "SetGlobal", wire_name: "SetGlobalAction" },
    ActionVariantInfo { index: 26, canonical_tag: 0xa0, variant_name: "SetReferrer", wire_name: "setReferrer" },
    ActionVariantInfo { index: 27, canonical_tag: 0xa1, variant_name: "SpotDeploy", wire_name: "spotDeploy" },
    ActionVariantInfo { index: 28, canonical_tag: 0xa2, variant_name: "SpotUser", wire_name: "spotUser" },
    ActionVariantInfo { index: 29, canonical_tag: 0xa3, variant_name: "SpotSend", wire_name: "spotSend" },
    ActionVariantInfo { index: 30, canonical_tag: 0xa4, variant_name: "SignValidatorSetUpdate", wire_name: "SignValidatorSetUpdateAction" },
    ActionVariantInfo { index: 31, canonical_tag: 0xa5, variant_name: "SubAccountModify", wire_name: "subAccountModify" },
    ActionVariantInfo { index: 32, canonical_tag: 0xa6, variant_name: "SubAccountTransfer", wire_name: "subAccountTransfer" },
    ActionVariantInfo { index: 33, canonical_tag: 0xa7, variant_name: "SubAccountSpotTransfer", wire_name: "subAccountSpotTransfer" },
    ActionVariantInfo { index: 34, canonical_tag: 0xa8, variant_name: "TokenDelegate", wire_name: "tokenDelegate" },
    ActionVariantInfo { index: 35, canonical_tag: 0xa9, variant_name: "TwapCancel", wire_name: "twapCancel" },
    ActionVariantInfo { index: 36, canonical_tag: 0xaa, variant_name: "TwapOrder", wire_name: "twapOrder" },
    ActionVariantInfo { index: 37, canonical_tag: 0xab, variant_name: "UpdateIsolatedMargin", wire_name: "updateIsolatedMargin" },
    ActionVariantInfo { index: 38, canonical_tag: 0xac, variant_name: "TopUpStrictIsolatedMargin", wire_name: "topUpIsolatedOnlyMargin" },
    ActionVariantInfo { index: 39, canonical_tag: 0xad, variant_name: "UpdateUserLeverage", wire_name: "updateLeverage" },
    ActionVariantInfo { index: 40, canonical_tag: 0xae, variant_name: "UsdSend", wire_name: "usdSend" },
    ActionVariantInfo { index: 41, canonical_tag: 0xaf, variant_name: "ValidatorSignWithdrawal", wire_name: "ValidatorSignWithdrawalAction" },
    ActionVariantInfo { index: 42, canonical_tag: 0xb0, variant_name: "VaultDistribute", wire_name: "vaultDistribute" },
    ActionVariantInfo { index: 43, canonical_tag: 0xb1, variant_name: "VaultModify", wire_name: "vaultModify" },
    ActionVariantInfo { index: 44, canonical_tag: 0xb2, variant_name: "VaultTransfer", wire_name: "vaultTransfer" },
    ActionVariantInfo { index: 45, canonical_tag: 0xb3, variant_name: "VoteEthDeposit", wire_name: "VoteEthDepositAction" },
    ActionVariantInfo { index: 46, canonical_tag: 0xb4, variant_name: "VoteEthFinalizedValidatorSetUpdate", wire_name: "VoteEthFinalizedValidatorSetUpdateAction" },
    ActionVariantInfo { index: 47, canonical_tag: 0xb5, variant_name: "VoteEthFinalizedWithdrawal", wire_name: "VoteEthFinalizedWithdrawalAction" },
    ActionVariantInfo { index: 48, canonical_tag: 0xb6, variant_name: "Withdraw3", wire_name: "withdraw3" },
    ActionVariantInfo { index: 49, canonical_tag: 0xb7, variant_name: "GovPropose", wire_name: "govPropose" },
    ActionVariantInfo { index: 50, canonical_tag: 0xb8, variant_name: "GovVote", wire_name: "govVote" },
    ActionVariantInfo { index: 51, canonical_tag: 0xb9, variant_name: "UsdClassTransfer", wire_name: "usdClassTransfer" },
    ActionVariantInfo { index: 52, canonical_tag: 0xba, variant_name: "MultiSig", wire_name: "multiSig" },
    ActionVariantInfo { index: 53, canonical_tag: 0xbb, variant_name: "ConvertToMultiSigUser", wire_name: "convertToMultiSigUser" },
    ActionVariantInfo { index: 54, canonical_tag: 0xbc, variant_name: "ApproveBuilderFee", wire_name: "approveBuilderFee" },
    ActionVariantInfo { index: 55, canonical_tag: 0xbd, variant_name: "StartFeeTrial", wire_name: "startFeeTrial" },
    ActionVariantInfo { index: 56, canonical_tag: 0xbe, variant_name: "SystemBole", wire_name: "SystemBoleAction" },
    ActionVariantInfo { index: 57, canonical_tag: 0xbf, variant_name: "SystemSpotSend", wire_name: "SystemSpotSendAction" },
    ActionVariantInfo { index: 58, canonical_tag: 0xc0, variant_name: "DeployerSendToEvmForFrozenUser", wire_name: "deployerSendToEvmForFrozenUser" },
    ActionVariantInfo { index: 59, canonical_tag: 0xc1, variant_name: "SystemUsdClassTransfer", wire_name: "SystemUsdClassTransferAction" },
    ActionVariantInfo { index: 60, canonical_tag: 0xc2, variant_name: "CSigner", wire_name: "CSignerAction" },
    ActionVariantInfo { index: 61, canonical_tag: 0xc3, variant_name: "CWithdraw", wire_name: "cWithdraw" },
    ActionVariantInfo { index: 62, canonical_tag: 0xc4, variant_name: "CDeposit", wire_name: "cDeposit" },
    ActionVariantInfo { index: 63, canonical_tag: 0xc5, variant_name: "CUserModify", wire_name: "cUserModify" },
    ActionVariantInfo { index: 64, canonical_tag: 0xc6, variant_name: "ReassessFees", wire_name: "reassessFees" },
    ActionVariantInfo { index: 65, canonical_tag: 0xc7, variant_name: "EvmUserModify", wire_name: "evmUserModify" },
    ActionVariantInfo { index: 66, canonical_tag: 0xc8, variant_name: "ReserveRequestWeight", wire_name: "reserveRequestWeight" },
    ActionVariantInfo { index: 67, canonical_tag: 0xc9, variant_name: "FinalizeEvmContract", wire_name: "finalizeEvmContract" },
    ActionVariantInfo { index: 68, canonical_tag: 0xca, variant_name: "Hip3Deploy", wire_name: "perpDeploy" },
    ActionVariantInfo { index: 69, canonical_tag: 0xcb, variant_name: "SendAsset", wire_name: "sendAsset" },
    ActionVariantInfo { index: 70, canonical_tag: 0xcc, variant_name: "SystemApproveBuilderFee", wire_name: "SystemApproveBuilderFeeAction" },
    ActionVariantInfo { index: 71, canonical_tag: 0xcd, variant_name: "SystemSendAsset", wire_name: "SystemSendAssetAction" },
    ActionVariantInfo { index: 72, canonical_tag: 0xce, variant_name: "AgentEnableDexAbstraction", wire_name: "agentEnableDexAbstraction" },
    ActionVariantInfo { index: 73, canonical_tag: 0xcf, variant_name: "UserDexAbstraction", wire_name: "userDexAbstraction" },
    ActionVariantInfo { index: 74, canonical_tag: 0xd0, variant_name: "Bole", wire_name: "borrowLend" },
    ActionVariantInfo { index: 75, canonical_tag: 0xd1, variant_name: "SendToEvmWithData", wire_name: "sendToEvmWithData" },
    ActionVariantInfo { index: 76, canonical_tag: 0xd2, variant_name: "UserPortfolioMargin", wire_name: "userPortfolioMargin" },
    ActionVariantInfo { index: 77, canonical_tag: 0xd3, variant_name: "UserSetAbstraction", wire_name: "userSetAbstraction" },
    ActionVariantInfo { index: 78, canonical_tag: 0xd4, variant_name: "AgentSetAbstraction", wire_name: "agentSetAbstraction" },
    ActionVariantInfo { index: 79, canonical_tag: 0xd5, variant_name: "UserOutcome", wire_name: "userOutcome" },
    ActionVariantInfo { index: 80, canonical_tag: 0xd6, variant_name: "GossipPriorityBid", wire_name: "gossipPriorityBid" },
    ActionVariantInfo { index: 81, canonical_tag: 0xd7, variant_name: "AgentSendAsset", wire_name: "agentSendAsset" },
    ActionVariantInfo { index: 82, canonical_tag: 0xd8, variant_name: "Hip3LiquidatorTransfer", wire_name: "hip3LiquidatorTransfer" },
    ActionVariantInfo { index: 83, canonical_tag: 0xd9, variant_name: "L1ValidatorVoteBridgeDeposit", wire_name: "l1ValidatorVoteBridgeDeposit" },
    ActionVariantInfo { index: 84, canonical_tag: 0xda, variant_name: "AuthorizeAqav2Role", wire_name: "authorizeAqav2Role" },
    ActionVariantInfo { index: 85, canonical_tag: 0xdb, variant_name: "StakingLinkDisableTradingUser", wire_name: "stakingLinkDisableTradingUser" },
    ActionVariantInfo { index: 86, canonical_tag: 0xdc, variant_name: "VoteL1Hash", wire_name: "voteL1Hash" },
    ActionVariantInfo { index: 87, canonical_tag: 0xdd, variant_name: "VoteAbciDigest", wire_name: "voteAbciDigest" },
    ActionVariantInfo { index: 88, canonical_tag: 0xde, variant_name: "ActivateOutcomeDeployer", wire_name: "activateOutcomeDeployer" },
    ActionVariantInfo { index: 89, canonical_tag: 0xdf, variant_name: "TrailingStopOrder", wire_name: "trailingStop" },
    ActionVariantInfo { index: 90, canonical_tag: 0xe0, variant_name: "OutcomeDeploy", wire_name: "outcomeDeploy" },
    ActionVariantInfo { index: 91, canonical_tag: 0xe1, variant_name: "CDeposit2", wire_name: "cDeposit2" },
];

/// Maps a raw node #115 `Action` tag word to its dispatch index `0..92`,
/// applying the exact `VoteGlobal` niche rule (`tag < 0x86 => 20`).
pub const fn tag_to_index(tag: u64) -> Option<usize> {
    if tag < ACTION_TAG_BASE {
        Some(VOTE_GLOBAL_NICHE_INDEX)
    } else if tag <= ACTION_TAG_MAX {
        Some((tag - ACTION_TAG_BASE) as usize)
    } else {
        None
    }
}

/// Resolves a raw tag word to its [`ActionVariantInfo`].
pub const fn variant_by_tag(tag: u64) -> Option<&'static ActionVariantInfo> {
    match tag_to_index(tag) {
        Some(idx) => Some(&ACTION_VARIANTS[idx]),
        None => None,
    }
}

/// Looks up an action variant by exact serde wire name.
pub fn variant_by_wire_name(wire_name: &str) -> Option<&'static ActionVariantInfo> {
    ACTION_VARIANTS.iter().find(|v| v.wire_name == wire_name)
}
