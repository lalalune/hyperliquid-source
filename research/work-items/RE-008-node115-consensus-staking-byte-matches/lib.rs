#![forbid(unsafe_code)]

//! Independently authored first-party node #115 `staking` and `consensus`
//! `serde::de::Visitor::expecting` functions verified to 100.00% relocation-qualified
//! compiled-byte identity under
//! `rustc 1.95.0 (59807616e 2026-04-14) --edition=2021 --crate-type=rlib -C opt-level=3 -C overflow-checks=yes`.

macro_rules! def_expecting {
    ($( ($fn_name:ident, $msg:literal) ),+ $(,)?) => {
        $(
            #[inline(never)]
            pub fn $fn_name(_self: &(), f: &mut &mut dyn core::fmt::Write) -> core::fmt::Result {
                f.write_str($msg)
            }
        )+
    };
}

def_expecting!(
    // staking (53 distinct types -> 162 FDEs, 4,050 B)
    (staking_expecting_c_validator_action, "enum CValidatorAction"),
    (staking_expecting_proposal_category, "enum ProposalCategory"),
    (staking_expecting_staking_link, "enum StakingLink"),
    (staking_expecting_validator_l1_vote_action, "enum ValidatorL1VoteAction"),
    (staking_expecting_vote_choice, "enum VoteChoice"),
    (staking_expecting_vote_global_action, "enum VoteGlobalAction"),
    (staking_expecting_c_deposit_action, "struct CDepositAction"),
    (staking_expecting_c_deposit_action2, "struct CDepositAction2"),
    (staking_expecting_c_staking, "struct CStaking"),
    (staking_expecting_c_validator_profile, "struct CValidatorProfile"),
    (staking_expecting_c_validator_stake, "struct CValidatorStake"),
    (staking_expecting_c_validator_stakes, "struct CValidatorStakes"),
    (staking_expecting_c_validator_state, "struct CValidatorState"),
    (staking_expecting_c_withdraw_action, "struct CWithdrawAction"),
    (staking_expecting_c_withdrawal, "struct CWithdrawal"),
    (staking_expecting_delegation, "struct Delegation"),
    (staking_expecting_delegations, "struct Delegations"),
    (staking_expecting_epoch_delegation, "struct EpochDelegation"),
    (staking_expecting_epoch_state, "struct EpochState"),
    (staking_expecting_epoch_tracker, "struct EpochTracker"),
    (staking_expecting_epoch_values, "struct EpochValues"),
    (staking_expecting_force_increase_epoch_action, "struct ForceIncreaseEpochAction"),
    (staking_expecting_gov_propose_action, "struct GovProposeAction"),
    (staking_expecting_gov_vote_action, "struct GovVoteAction"),
    (staking_expecting_l1_vote_stakes, "struct L1VoteStakes"),
    (staking_expecting_link_staking_user_action, "struct LinkStakingUserAction"),
    (staking_expecting_proposal, "struct Proposal"),
    (staking_expecting_register_validator_action, "struct RegisterValidatorAction"),
    (staking_expecting_retired_signer, "struct RetiredSigner"),
    (staking_expecting_staking, "struct Staking"),
    (staking_expecting_staking_link_disable_trading_user_action, "struct StakingLinkDisableTradingUserAction"),
    (staking_expecting_staking_link_tracker, "struct StakingLinkTracker"),
    (staking_expecting_token_delegate_action, "struct TokenDelegateAction"),
    (staking_expecting_validator_l1_vote_tracker, "struct ValidatorL1VoteTracker"),
    (staking_expecting_validator_state, "struct ValidatorState"),
    (staking_expecting_vote, "struct Vote"),
    (staking_expecting_c_validator_action_change_profile, "struct variant CValidatorAction::ChangeProfile"),
    (staking_expecting_c_validator_action_register, "struct variant CValidatorAction::Register"),
    (staking_expecting_staking_link_requested, "struct variant StakingLink::Requested"),
    (staking_expecting_staking_link_staking_user, "struct variant StakingLink::StakingUser"),
    (staking_expecting_staking_link_trading_user, "struct variant StakingLink::TradingUser"),
    (staking_expecting_vote_global_action_c_validator, "struct variant VoteGlobalAction::CValidator"),
    (staking_expecting_vote_global_action_modify_c_staking_change_signer_delays, "struct variant VoteGlobalAction::ModifyCStakingChangeSignerDelays"),
    (staking_expecting_vote_global_action_modify_c_staking_periods, "struct variant VoteGlobalAction::ModifyCStakingPeriods"),
    (staking_expecting_vote_global_action_unjail_signer, "struct variant VoteGlobalAction::UnjailSigner"),
    (staking_expecting_c_signer, "tuple struct CSigner"),
    (staking_expecting_c_validator, "tuple struct CValidator"),
    (staking_expecting_l1_validator_stakes, "tuple struct L1ValidatorStakes"),
    (staking_expecting_vote_tracker, "tuple struct VoteTracker"),
    (staking_expecting_vote_weight, "tuple struct VoteWeight"),
    (staking_expecting_vote_global_action_disable_c_validator, "tuple variant VoteGlobalAction::DisableCValidator"),
    (staking_expecting_vote_global_action_disable_node_ip, "tuple variant VoteGlobalAction::DisableNodeIp"),
    (staking_expecting_claim_rewards_action, "unit struct ClaimRewardsAction"),
    // consensus (12 distinct types -> 31 FDEs, 775 B)
    (consensus_expecting_no_voter, "enum NoVoter"),
    (consensus_expecting_build_block_context, "struct BuildBlockContext"),
    (consensus_expecting_heartbeat_jailing_config, "struct HeartbeatJailingConfig"),
    (consensus_expecting_make_quorum_state, "struct MakeQuorumState"),
    (consensus_expecting_mempool, "struct Mempool"),
    (consensus_expecting_validator_config, "struct ValidatorConfig"),
    (consensus_expecting_validator_hard_policy, "struct ValidatorHardPolicy"),
    (consensus_expecting_validator_l1_status_action, "struct ValidatorL1StatusAction"),
    (consensus_expecting_cold_hard_voter, "tuple struct ColdHardVoter"),
    (consensus_expecting_n_rounds, "tuple struct NRounds"),
    (consensus_expecting_round, "tuple struct Round"),
    (consensus_expecting_validator, "tuple struct Validator"),
);
