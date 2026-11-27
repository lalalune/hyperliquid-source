#!/usr/bin/env python3
"""Compile lib.rs with rustc 1.95.0 and verify 193 first-party staking/consensus FDE byte matches against node #115."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKET_DIR.parents[2]
BINARY_PATH = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"
FDE_TSV = REPO_ROOT / "work" / "index" / "node-115-fde.tsv"
BYTE_WINDOWS_JSON = REPO_ROOT / "research" / "byte-windows.json"
SOURCE_PATH = PACKET_DIR / "lib.rs"
RECORDS_PATH = PACKET_DIR / "records.json"

EXPECTED_BINARY_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
EXPECTED_BINARY_SIZE = 105_896_032

# (component, symbol_substring, start_va, end_va, label)
WINDOWS = [
    ("staking", "staking_expecting_c_validator_action", 0x292DE70, 0x292DE89, "staking CValidatorAction expecting (0x292de70)"),
    ("staking", "staking_expecting_c_validator_action", 0x44DC3B0, 0x44DC3C9, "staking CValidatorAction expecting (0x44dc3b0)"),
    ("staking", "staking_expecting_c_validator_action", 0x53D5A10, 0x53D5A29, "staking CValidatorAction expecting (0x53d5a10)"),
    ("staking", "staking_expecting_proposal_category", 0x24205B0, 0x24205C9, "staking ProposalCategory expecting (0x24205b0)"),
    ("staking", "staking_expecting_proposal_category", 0x3C4D830, 0x3C4D849, "staking ProposalCategory expecting (0x3c4d830)"),
    ("staking", "staking_expecting_proposal_category", 0x4D9C840, 0x4D9C859, "staking ProposalCategory expecting (0x4d9c840)"),
    ("staking", "staking_expecting_staking_link", 0x25EBD20, 0x25EBD39, "staking StakingLink expecting (0x25ebd20)"),
    ("staking", "staking_expecting_staking_link", 0x46DE070, 0x46DE089, "staking StakingLink expecting (0x46de070)"),
    ("staking", "staking_expecting_staking_link", 0x53D6590, 0x53D65A9, "staking StakingLink expecting (0x53d6590)"),
    ("staking", "staking_expecting_validator_l1_vote_action", 0x292D970, 0x292D989, "staking ValidatorL1VoteAction expecting (0x292d970)"),
    ("staking", "staking_expecting_validator_l1_vote_action", 0x46DDD70, 0x46DDD89, "staking ValidatorL1VoteAction expecting (0x46ddd70)"),
    ("staking", "staking_expecting_validator_l1_vote_action", 0x50D8F70, 0x50D8F89, "staking ValidatorL1VoteAction expecting (0x50d8f70)"),
    ("staking", "staking_expecting_vote_choice", 0x2420160, 0x2420179, "staking VoteChoice expecting (0x2420160)"),
    ("staking", "staking_expecting_vote_choice", 0x3C4D1F0, 0x3C4D209, "staking VoteChoice expecting (0x3c4d1f0)"),
    ("staking", "staking_expecting_vote_choice", 0x4D9C410, 0x4D9C429, "staking VoteChoice expecting (0x4d9c410)"),
    ("staking", "staking_expecting_vote_global_action", 0x292CE30, 0x292CE49, "staking VoteGlobalAction expecting (0x292ce30)"),
    ("staking", "staking_expecting_vote_global_action", 0x46DDB30, 0x46DDB49, "staking VoteGlobalAction expecting (0x46ddb30)"),
    ("staking", "staking_expecting_vote_global_action", 0x53D6370, 0x53D6389, "staking VoteGlobalAction expecting (0x53d6370)"),
    ("staking", "staking_expecting_c_deposit_action", 0x2420740, 0x2420759, "staking CDepositAction expecting (0x2420740)"),
    ("staking", "staking_expecting_c_deposit_action", 0x4451AF0, 0x4451B09, "staking CDepositAction expecting (0x4451af0)"),
    ("staking", "staking_expecting_c_deposit_action", 0x59423F0, 0x5942409, "staking CDepositAction expecting (0x59423f0)"),
    ("staking", "staking_expecting_c_deposit_action2", 0x29B06D0, 0x29B06E9, "staking CDepositAction2 expecting (0x29b06d0)"),
    ("staking", "staking_expecting_c_deposit_action2", 0x4683B90, 0x4683BA9, "staking CDepositAction2 expecting (0x4683b90)"),
    ("staking", "staking_expecting_c_deposit_action2", 0x53D60D0, 0x53D60E9, "staking CDepositAction2 expecting (0x53d60d0)"),
    ("staking", "staking_expecting_c_staking", 0x2C7D5B0, 0x2C7D5C9, "staking CStaking expecting (0x2c7d5b0)"),
    ("staking", "staking_expecting_c_staking", 0x3C4D8D0, 0x3C4D8E9, "staking CStaking expecting (0x3c4d8d0)"),
    ("staking", "staking_expecting_c_staking", 0x5616DF0, 0x5616E09, "staking CStaking expecting (0x5616df0)"),
    ("staking", "staking_expecting_c_validator_profile", 0x27732B0, 0x27732C9, "staking CValidatorProfile expecting (0x27732b0)"),
    ("staking", "staking_expecting_c_validator_profile", 0x4229890, 0x42298A9, "staking CValidatorProfile expecting (0x4229890)"),
    ("staking", "staking_expecting_c_validator_profile", 0x51AD800, 0x51AD819, "staking CValidatorProfile expecting (0x51ad800)"),
    ("staking", "staking_expecting_c_validator_stake", 0x2773610, 0x2773629, "staking CValidatorStake expecting (0x2773610)"),
    ("staking", "staking_expecting_c_validator_stake", 0x42294A0, 0x42294B9, "staking CValidatorStake expecting (0x42294a0)"),
    ("staking", "staking_expecting_c_validator_stake", 0x5942550, 0x5942569, "staking CValidatorStake expecting (0x5942550)"),
    ("staking", "staking_expecting_c_validator_stakes", 0x2773FB0, 0x2773FC9, "staking CValidatorStakes expecting (0x2773fb0)"),
    ("staking", "staking_expecting_c_validator_stakes", 0x4229730, 0x4229749, "staking CValidatorStakes expecting (0x4229730)"),
    ("staking", "staking_expecting_c_validator_stakes", 0x5942490, 0x59424A9, "staking CValidatorStakes expecting (0x5942490)"),
    ("staking", "staking_expecting_c_validator_state", 0x2C7D1D0, 0x2C7D1E9, "staking CValidatorState expecting (0x2c7d1d0)"),
    ("staking", "staking_expecting_c_validator_state", 0x3C4D0B0, 0x3C4D0C9, "staking CValidatorState expecting (0x3c4d0b0)"),
    ("staking", "staking_expecting_c_validator_state", 0x5616CD0, 0x5616CE9, "staking CValidatorState expecting (0x5616cd0)"),
    ("staking", "staking_expecting_c_withdraw_action", 0x2420940, 0x2420959, "staking CWithdrawAction expecting (0x2420940)"),
    ("staking", "staking_expecting_c_withdraw_action", 0x4452930, 0x4452949, "staking CWithdrawAction expecting (0x4452930)"),
    ("staking", "staking_expecting_c_withdraw_action", 0x53D6090, 0x53D60A9, "staking CWithdrawAction expecting (0x53d6090)"),
    ("staking", "staking_expecting_c_withdrawal", 0x2773BB0, 0x2773BC9, "staking CWithdrawal expecting (0x2773bb0)"),
    ("staking", "staking_expecting_c_withdrawal", 0x36CD4F0, 0x36CD509, "staking CWithdrawal expecting (0x36cd4f0)"),
    ("staking", "staking_expecting_c_withdrawal", 0x59422F0, 0x5942309, "staking CWithdrawal expecting (0x59422f0)"),
    ("staking", "staking_expecting_delegation", 0x2C7D2F0, 0x2C7D309, "staking Delegation expecting (0x2c7d2f0)"),
    ("staking", "staking_expecting_delegation", 0x4229810, 0x4229829, "staking Delegation expecting (0x4229810)"),
    ("staking", "staking_expecting_delegation", 0x5B09150, 0x5B09169, "staking Delegation expecting (0x5b09150)"),
    ("staking", "staking_expecting_delegations", 0x2C7D3F0, 0x2C7D409, "staking Delegations expecting (0x2c7d3f0)"),
    ("staking", "staking_expecting_delegations", 0x4229610, 0x4229629, "staking Delegations expecting (0x4229610)"),
    ("staking", "staking_expecting_delegations", 0x5B093D0, 0x5B093E9, "staking Delegations expecting (0x5b093d0)"),
    ("staking", "staking_expecting_epoch_delegation", 0x2C7D5D0, 0x2C7D5E9, "staking EpochDelegation expecting (0x2c7d5d0)"),
    ("staking", "staking_expecting_epoch_delegation", 0x4229400, 0x4229419, "staking EpochDelegation expecting (0x4229400)"),
    ("staking", "staking_expecting_epoch_delegation", 0x5B09310, 0x5B09329, "staking EpochDelegation expecting (0x5b09310)"),
    ("staking", "staking_expecting_epoch_state", 0x2773EF0, 0x2773F09, "staking EpochState expecting (0x2773ef0)"),
    ("staking", "staking_expecting_epoch_state", 0x36CD410, 0x36CD429, "staking EpochState expecting (0x36cd410)"),
    ("staking", "staking_expecting_epoch_state", 0x51ADB10, 0x51ADB29, "staking EpochState expecting (0x51adb10)"),
    ("staking", "staking_expecting_epoch_tracker", 0x2773E50, 0x2773E69, "staking EpochTracker expecting (0x2773e50)"),
    ("staking", "staking_expecting_epoch_tracker", 0x4229350, 0x4229369, "staking EpochTracker expecting (0x4229350)"),
    ("staking", "staking_expecting_epoch_tracker", 0x4D9C5B0, 0x4D9C5C9, "staking EpochTracker expecting (0x4d9c5b0)"),
    ("staking", "staking_expecting_epoch_values", 0x2773390, 0x27733A9, "staking EpochValues expecting (0x2773390)"),
    ("staking", "staking_expecting_epoch_values", 0x3C4D430, 0x3C4D449, "staking EpochValues expecting (0x3c4d430)"),
    ("staking", "staking_expecting_epoch_values", 0x5B092B0, 0x5B092C9, "staking EpochValues expecting (0x5b092b0)"),
    ("staking", "staking_expecting_force_increase_epoch_action", 0x2420060, 0x2420079, "staking ForceIncreaseEpochAction expecting (0x2420060)"),
    ("staking", "staking_expecting_force_increase_epoch_action", 0x41FEB90, 0x41FEBA9, "staking ForceIncreaseEpochAction expecting (0x41feb90)"),
    ("staking", "staking_expecting_force_increase_epoch_action", 0x53D6650, 0x53D6669, "staking ForceIncreaseEpochAction expecting (0x53d6650)"),
    ("staking", "staking_expecting_gov_propose_action", 0x2420650, 0x2420669, "staking GovProposeAction expecting (0x2420650)"),
    ("staking", "staking_expecting_gov_propose_action", 0x4453D30, 0x4453D49, "staking GovProposeAction expecting (0x4453d30)"),
    ("staking", "staking_expecting_gov_propose_action", 0x59423D0, 0x59423E9, "staking GovProposeAction expecting (0x59423d0)"),
    ("staking", "staking_expecting_gov_vote_action", 0x24207E0, 0x24207F9, "staking GovVoteAction expecting (0x24207e0)"),
    ("staking", "staking_expecting_gov_vote_action", 0x4450D40, 0x4450D59, "staking GovVoteAction expecting (0x4450d40)"),
    ("staking", "staking_expecting_gov_vote_action", 0x5942850, 0x5942869, "staking GovVoteAction expecting (0x5942850)"),
    ("staking", "staking_expecting_l1_vote_stakes", 0x2D4A1E0, 0x2D4A1F9, "staking L1VoteStakes expecting (0x2d4a1e0)"),
    ("staking", "staking_expecting_l1_vote_stakes", 0x42290E0, 0x42290F9, "staking L1VoteStakes expecting (0x42290e0)"),
    ("staking", "staking_expecting_l1_vote_stakes", 0x59422B0, 0x59422C9, "staking L1VoteStakes expecting (0x59422b0)"),
    ("staking", "staking_expecting_link_staking_user_action", 0x2D4A870, 0x2D4A889, "staking LinkStakingUserAction expecting (0x2d4a870)"),
    ("staking", "staking_expecting_link_staking_user_action", 0x445A010, 0x445A029, "staking LinkStakingUserAction expecting (0x445a010)"),
    ("staking", "staking_expecting_link_staking_user_action", 0x5942530, 0x5942549, "staking LinkStakingUserAction expecting (0x5942530)"),
    ("staking", "staking_expecting_proposal", 0x2420550, 0x2420569, "staking Proposal expecting (0x2420550)"),
    ("staking", "staking_expecting_proposal", 0x3C4D530, 0x3C4D549, "staking Proposal expecting (0x3c4d530)"),
    ("staking", "staking_expecting_proposal", 0x4D9C820, 0x4D9C839, "staking Proposal expecting (0x4d9c820)"),
    ("staking", "staking_expecting_register_validator_action", 0x2D4A730, 0x2D4A749, "staking RegisterValidatorAction expecting (0x2d4a730)"),
    ("staking", "staking_expecting_register_validator_action", 0x445E4A0, 0x445E4B9, "staking RegisterValidatorAction expecting (0x445e4a0)"),
    ("staking", "staking_expecting_register_validator_action", 0x5942270, 0x5942289, "staking RegisterValidatorAction expecting (0x5942270)"),
    ("staking", "staking_expecting_retired_signer", 0x2C7D510, 0x2C7D529, "staking RetiredSigner expecting (0x2c7d510)"),
    ("staking", "staking_expecting_retired_signer", 0x3C4D310, 0x3C4D329, "staking RetiredSigner expecting (0x3c4d310)"),
    ("staking", "staking_expecting_retired_signer", 0x5616970, 0x5616989, "staking RetiredSigner expecting (0x5616970)"),
    ("staking", "staking_expecting_staking", 0x2774050, 0x2774069, "staking Staking expecting (0x2774050)"),
    ("staking", "staking_expecting_staking", 0x36CD330, 0x36CD349, "staking Staking expecting (0x36cd330)"),
    ("staking", "staking_expecting_staking", 0x51AD600, 0x51AD619, "staking Staking expecting (0x51ad600)"),
    ("staking", "staking_expecting_staking_link_disable_trading_user_action", 0x2D4A180, 0x2D4A199, "staking StakingLinkDisableTradingUserAction expecting (0x2d4a180)"),
    ("staking", "staking_expecting_staking_link_disable_trading_user_action", 0x4466890, 0x44668A9, "staking StakingLinkDisableTradingUserAction expecting (0x4466890)"),
    ("staking", "staking_expecting_staking_link_disable_trading_user_action", 0x5941CD0, 0x5941CE9, "staking StakingLinkDisableTradingUserAction expecting (0x5941cd0)"),
    ("staking", "staking_expecting_staking_link_tracker", 0x25EB980, 0x25EB999, "staking StakingLinkTracker expecting (0x25eb980)"),
    ("staking", "staking_expecting_staking_link_tracker", 0x46DDD50, 0x46DDD69, "staking StakingLinkTracker expecting (0x46ddd50)"),
    ("staking", "staking_expecting_staking_link_tracker", 0x53D5870, 0x53D5889, "staking StakingLinkTracker expecting (0x53d5870)"),
    ("staking", "staking_expecting_token_delegate_action", 0x2420510, 0x2420529, "staking TokenDelegateAction expecting (0x2420510)"),
    ("staking", "staking_expecting_token_delegate_action", 0x4456350, 0x4456369, "staking TokenDelegateAction expecting (0x4456350)"),
    ("staking", "staking_expecting_token_delegate_action", 0x53D6850, 0x53D6869, "staking TokenDelegateAction expecting (0x53d6850)"),
    ("staking", "staking_expecting_validator_l1_vote_tracker", 0x27737B0, 0x27737C9, "staking ValidatorL1VoteTracker expecting (0x27737b0)"),
    ("staking", "staking_expecting_validator_l1_vote_tracker", 0x36CD170, 0x36CD189, "staking ValidatorL1VoteTracker expecting (0x36cd170)"),
    ("staking", "staking_expecting_validator_l1_vote_tracker", 0x51ADD90, 0x51ADDA9, "staking ValidatorL1VoteTracker expecting (0x51add90)"),
    ("staking", "staking_expecting_validator_state", 0x2773590, 0x27735A9, "staking ValidatorState expecting (0x2773590)"),
    ("staking", "staking_expecting_validator_state", 0x2C7CFB0, 0x2C7CFC9, "staking ValidatorState expecting (0x2c7cfb0)"),
    ("staking", "staking_expecting_validator_state", 0x36CD250, 0x36CD269, "staking ValidatorState expecting (0x36cd250)"),
    ("staking", "staking_expecting_validator_state", 0x4229710, 0x4229729, "staking ValidatorState expecting (0x4229710)"),
    ("staking", "staking_expecting_validator_state", 0x51AD3B0, 0x51AD3C9, "staking ValidatorState expecting (0x51ad3b0)"),
    ("staking", "staking_expecting_validator_state", 0x5B09530, 0x5B09549, "staking ValidatorState expecting (0x5b09530)"),
    ("staking", "staking_expecting_vote", 0x2420920, 0x2420939, "staking Vote expecting (0x2420920)"),
    ("staking", "staking_expecting_vote", 0x3C4D150, 0x3C4D169, "staking Vote expecting (0x3c4d150)"),
    ("staking", "staking_expecting_vote", 0x4D9C4B0, 0x4D9C4C9, "staking Vote expecting (0x4d9c4b0)"),
    ("staking", "staking_expecting_c_validator_action_change_profile", 0x292DB50, 0x292DB69, "staking CValidatorAction::ChangeProfile expecting (0x292db50)"),
    ("staking", "staking_expecting_c_validator_action_change_profile", 0x44DC8F0, 0x44DC909, "staking CValidatorAction::ChangeProfile expecting (0x44dc8f0)"),
    ("staking", "staking_expecting_c_validator_action_change_profile", 0x53D6170, 0x53D6189, "staking CValidatorAction::ChangeProfile expecting (0x53d6170)"),
    ("staking", "staking_expecting_c_validator_action_register", 0x292DB30, 0x292DB49, "staking CValidatorAction::Register expecting (0x292db30)"),
    ("staking", "staking_expecting_c_validator_action_register", 0x44DCBD0, 0x44DCBE9, "staking CValidatorAction::Register expecting (0x44dcbd0)"),
    ("staking", "staking_expecting_c_validator_action_register", 0x53D69F0, 0x53D6A09, "staking CValidatorAction::Register expecting (0x53d69f0)"),
    ("staking", "staking_expecting_staking_link_requested", 0x25EB6C0, 0x25EB6D9, "staking StakingLink::Requested expecting (0x25eb6c0)"),
    ("staking", "staking_expecting_staking_link_requested", 0x46DDC10, 0x46DDC29, "staking StakingLink::Requested expecting (0x46ddc10)"),
    ("staking", "staking_expecting_staking_link_requested", 0x53D69D0, 0x53D69E9, "staking StakingLink::Requested expecting (0x53d69d0)"),
    ("staking", "staking_expecting_staking_link_staking_user", 0x25EB5D0, 0x25EB5E9, "staking StakingLink::StakingUser expecting (0x25eb5d0)"),
    ("staking", "staking_expecting_staking_link_staking_user", 0x46DE3D0, 0x46DE3E9, "staking StakingLink::StakingUser expecting (0x46de3d0)"),
    ("staking", "staking_expecting_staking_link_staking_user", 0x53D6290, 0x53D62A9, "staking StakingLink::StakingUser expecting (0x53d6290)"),
    ("staking", "staking_expecting_staking_link_trading_user", 0x25EB860, 0x25EB879, "staking StakingLink::TradingUser expecting (0x25eb860)"),
    ("staking", "staking_expecting_staking_link_trading_user", 0x46DE0F0, 0x46DE109, "staking StakingLink::TradingUser expecting (0x46de0f0)"),
    ("staking", "staking_expecting_staking_link_trading_user", 0x53D65F0, 0x53D6609, "staking StakingLink::TradingUser expecting (0x53d65f0)"),
    ("staking", "staking_expecting_vote_global_action_c_validator", 0x292D790, 0x292D7A9, "staking VoteGlobalAction::CValidator expecting (0x292d790)"),
    ("staking", "staking_expecting_vote_global_action_c_validator", 0x46DD990, 0x46DD9A9, "staking VoteGlobalAction::CValidator expecting (0x46dd990)"),
    ("staking", "staking_expecting_vote_global_action_c_validator", 0x53D6870, 0x53D6889, "staking VoteGlobalAction::CValidator expecting (0x53d6870)"),
    ("staking", "staking_expecting_vote_global_action_modify_c_staking_change_signer_delays", 0x292DB10, 0x292DB29, "staking VoteGlobalAction::ModifyCStakingChangeSignerDelays expecting (0x292db10)"),
    ("staking", "staking_expecting_vote_global_action_modify_c_staking_change_signer_delays", 0x46DDB10, 0x46DDB29, "staking VoteGlobalAction::ModifyCStakingChangeSignerDelays expecting (0x46ddb10)"),
    ("staking", "staking_expecting_vote_global_action_modify_c_staking_change_signer_delays", 0x53D5BF0, 0x53D5C09, "staking VoteGlobalAction::ModifyCStakingChangeSignerDelays expecting (0x53d5bf0)"),
    ("staking", "staking_expecting_vote_global_action_modify_c_staking_periods", 0x292CDF0, 0x292CE09, "staking VoteGlobalAction::ModifyCStakingPeriods expecting (0x292cdf0)"),
    ("staking", "staking_expecting_vote_global_action_modify_c_staking_periods", 0x46DE410, 0x46DE429, "staking VoteGlobalAction::ModifyCStakingPeriods expecting (0x46de410)"),
    ("staking", "staking_expecting_vote_global_action_modify_c_staking_periods", 0x53D60F0, 0x53D6109, "staking VoteGlobalAction::ModifyCStakingPeriods expecting (0x53d60f0)"),
    ("staking", "staking_expecting_vote_global_action_unjail_signer", 0x292DC70, 0x292DC89, "staking VoteGlobalAction::UnjailSigner expecting (0x292dc70)"),
    ("staking", "staking_expecting_vote_global_action_unjail_signer", 0x46DDDF0, 0x46DDE09, "staking VoteGlobalAction::UnjailSigner expecting (0x46dddf0)"),
    ("staking", "staking_expecting_vote_global_action_unjail_signer", 0x53D5E50, 0x53D5E69, "staking VoteGlobalAction::UnjailSigner expecting (0x53d5e50)"),
    ("staking", "staking_expecting_c_signer", 0x2420820, 0x2420839, "staking CSigner expecting (0x2420820)"),
    ("staking", "staking_expecting_c_signer", 0x4229650, 0x4229669, "staking CSigner expecting (0x4229650)"),
    ("staking", "staking_expecting_c_signer", 0x53D5FF0, 0x53D6009, "staking CSigner expecting (0x53d5ff0)"),
    ("staking", "staking_expecting_c_validator", 0x24204B0, 0x24204C9, "staking CValidator expecting (0x24204b0)"),
    ("staking", "staking_expecting_c_validator", 0x4229870, 0x4229889, "staking CValidator expecting (0x4229870)"),
    ("staking", "staking_expecting_c_validator", 0x53D6830, 0x53D6849, "staking CValidator expecting (0x53d6830)"),
    ("staking", "staking_expecting_l1_validator_stakes", 0x2D4A770, 0x2D4A789, "staking L1ValidatorStakes expecting (0x2d4a770)"),
    ("staking", "staking_expecting_l1_validator_stakes", 0x4228F50, 0x4228F69, "staking L1ValidatorStakes expecting (0x4228f50)"),
    ("staking", "staking_expecting_l1_validator_stakes", 0x5941CB0, 0x5941CC9, "staking L1ValidatorStakes expecting (0x5941cb0)"),
    ("staking", "staking_expecting_vote_tracker", 0x26A1550, 0x26A1569, "staking VoteTracker expecting (0x26a1550)"),
    ("staking", "staking_expecting_vote_tracker", 0x3F146B0, 0x3F146C9, "staking VoteTracker expecting (0x3f146b0)"),
    ("staking", "staking_expecting_vote_tracker", 0x57D19D0, 0x57D19E9, "staking VoteTracker expecting (0x57d19d0)"),
    ("staking", "staking_expecting_vote_weight", 0x2420080, 0x2420099, "staking VoteWeight expecting (0x2420080)"),
    ("staking", "staking_expecting_vote_weight", 0x3C4D4F0, 0x3C4D509, "staking VoteWeight expecting (0x3c4d4f0)"),
    ("staking", "staking_expecting_vote_weight", 0x4D9C940, 0x4D9C959, "staking VoteWeight expecting (0x4d9c940)"),
    ("staking", "staking_expecting_vote_global_action_disable_c_validator", 0x292CB10, 0x292CB29, "staking VoteGlobalAction::DisableCValidator expecting (0x292cb10)"),
    ("staking", "staking_expecting_vote_global_action_disable_c_validator", 0x46DDC30, 0x46DDC49, "staking VoteGlobalAction::DisableCValidator expecting (0x46ddc30)"),
    ("staking", "staking_expecting_vote_global_action_disable_c_validator", 0x53D5DD0, 0x53D5DE9, "staking VoteGlobalAction::DisableCValidator expecting (0x53d5dd0)"),
    ("staking", "staking_expecting_vote_global_action_disable_node_ip", 0x292CC50, 0x292CC69, "staking VoteGlobalAction::DisableNodeIp expecting (0x292cc50)"),
    ("staking", "staking_expecting_vote_global_action_disable_node_ip", 0x46DDD30, 0x46DDD49, "staking VoteGlobalAction::DisableNodeIp expecting (0x46ddd30)"),
    ("staking", "staking_expecting_vote_global_action_disable_node_ip", 0x53D58D0, 0x53D58E9, "staking VoteGlobalAction::DisableNodeIp expecting (0x53d58d0)"),
    ("staking", "staking_expecting_claim_rewards_action", 0x26A18D0, 0x26A18E9, "staking ClaimRewardsAction expecting (0x26a18d0)"),
    ("staking", "staking_expecting_claim_rewards_action", 0x3F146D0, 0x3F146E9, "staking ClaimRewardsAction expecting (0x3f146d0)"),
    ("staking", "staking_expecting_claim_rewards_action", 0x4E39720, 0x4E39739, "staking ClaimRewardsAction expecting (0x4e39720)"),
    ("consensus", "consensus_expecting_no_voter", 0x2773C50, 0x2773C69, "consensus NoVoter expecting (0x2773c50)"),
    ("consensus", "consensus_expecting_no_voter", 0x42296D0, 0x42296E9, "consensus NoVoter expecting (0x42296d0)"),
    ("consensus", "consensus_expecting_no_voter", 0x5942150, 0x5942169, "consensus NoVoter expecting (0x5942150)"),
    ("consensus", "consensus_expecting_build_block_context", 0x29B0530, 0x29B0549, "consensus BuildBlockContext expecting (0x29b0530)"),
    ("consensus", "consensus_expecting_build_block_context", 0x43512C0, 0x43512D9, "consensus BuildBlockContext expecting (0x43512c0)"),
    ("consensus", "consensus_expecting_build_block_context", 0x5616930, 0x5616949, "consensus BuildBlockContext expecting (0x5616930)"),
    ("consensus", "consensus_expecting_heartbeat_jailing_config", 0x5A2F1B0, 0x5A2F1C9, "consensus HeartbeatJailingConfig expecting (0x5a2f1b0)"),
    ("consensus", "consensus_expecting_make_quorum_state", 0x2773810, 0x2773829, "consensus MakeQuorumState expecting (0x2773810)"),
    ("consensus", "consensus_expecting_make_quorum_state", 0x4229630, 0x4229649, "consensus MakeQuorumState expecting (0x4229630)"),
    ("consensus", "consensus_expecting_make_quorum_state", 0x5B09270, 0x5B09289, "consensus MakeQuorumState expecting (0x5b09270)"),
    ("consensus", "consensus_expecting_mempool", 0x2773B30, 0x2773B49, "consensus Mempool expecting (0x2773b30)"),
    ("consensus", "consensus_expecting_mempool", 0x4229500, 0x4229519, "consensus Mempool expecting (0x4229500)"),
    ("consensus", "consensus_expecting_mempool", 0x51AD920, 0x51AD939, "consensus Mempool expecting (0x51ad920)"),
    ("consensus", "consensus_expecting_validator_config", 0x2C7D450, 0x2C7D469, "consensus ValidatorConfig expecting (0x2c7d450)"),
    ("consensus", "consensus_expecting_validator_config", 0x59427B0, 0x59427C9, "consensus ValidatorConfig expecting (0x59427b0)"),
    ("consensus", "consensus_expecting_validator_hard_policy", 0x27740D0, 0x27740E9, "consensus ValidatorHardPolicy expecting (0x27740d0)"),
    ("consensus", "consensus_expecting_validator_hard_policy", 0x4229240, 0x4229259, "consensus ValidatorHardPolicy expecting (0x4229240)"),
    ("consensus", "consensus_expecting_validator_hard_policy", 0x5941CF0, 0x5941D09, "consensus ValidatorHardPolicy expecting (0x5941cf0)"),
    ("consensus", "consensus_expecting_validator_l1_status_action", 0x2C7D470, 0x2C7D489, "consensus ValidatorL1StatusAction expecting (0x2c7d470)"),
    ("consensus", "consensus_expecting_validator_l1_status_action", 0x3BDD8D0, 0x3BDD8E9, "consensus ValidatorL1StatusAction expecting (0x3bdd8d0)"),
    ("consensus", "consensus_expecting_validator_l1_status_action", 0x5942370, 0x5942389, "consensus ValidatorL1StatusAction expecting (0x5942370)"),
    ("consensus", "consensus_expecting_cold_hard_voter", 0x24207A0, 0x24207B9, "consensus ColdHardVoter expecting (0x24207a0)"),
    ("consensus", "consensus_expecting_cold_hard_voter", 0x4229950, 0x4229969, "consensus ColdHardVoter expecting (0x4229950)"),
    ("consensus", "consensus_expecting_cold_hard_voter", 0x53D6130, 0x53D6149, "consensus ColdHardVoter expecting (0x53d6130)"),
    ("consensus", "consensus_expecting_n_rounds", 0x2D4A750, 0x2D4A769, "consensus NRounds expecting (0x2d4a750)"),
    ("consensus", "consensus_expecting_n_rounds", 0x452A1C0, 0x452A1D9, "consensus NRounds expecting (0x452a1c0)"),
    ("consensus", "consensus_expecting_n_rounds", 0x53D64D0, 0x53D64E9, "consensus NRounds expecting (0x53d64d0)"),
    ("consensus", "consensus_expecting_round", 0x2D4A040, 0x2D4A059, "consensus Round expecting (0x2d4a040)"),
    ("consensus", "consensus_expecting_round", 0x452A0A0, 0x452A0B9, "consensus Round expecting (0x452a0a0)"),
    ("consensus", "consensus_expecting_round", 0x53D61B0, 0x53D61C9, "consensus Round expecting (0x53d61b0)"),
    ("consensus", "consensus_expecting_validator", 0x57D18D0, 0x57D18E9, "consensus Validator expecting (0x57d18d0)"),
]


def parse_elf_sections(blob: bytes) -> list[tuple[int, str, int, int, int, int, int, int]]:
    e_shoff = struct.unpack_from("<Q", blob, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", blob, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", blob, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", blob, 0x3E)[0]
    shstr_off = struct.unpack_from("<Q", blob, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    out = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type, _sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info = (
            struct.unpack_from("<IIQQQQII", blob, off)
        )
        end = blob.find(b"\0", shstr_off + sh_name)
        name = blob[shstr_off + sh_name : end].decode("latin1")
        out.append((i, name, sh_type, sh_addr, sh_offset, sh_size, sh_link, sh_info))
    return out


def load_fde_map() -> dict[int, int]:
    fdes: dict[int, int] = {}
    if not FDE_TSV.exists():
        return fdes
    with FDE_TSV.open("r", encoding="utf-8") as fh:
        fh.readline()
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                s = int(parts[0], 16) if parts[0].startswith("0x") else int(parts[0])
                e = int(parts[1], 16) if parts[1].startswith("0x") else int(parts[1])
                fdes[s] = e
    return fdes


def load_registered_windows() -> list[tuple[int, int, str, bool]]:
    if not BYTE_WINDOWS_JSON.exists():
        return []
    bw = json.loads(BYTE_WINDOWS_JSON.read_text(encoding="utf-8"))
    return [
        (int(w["start"]), int(w["end"]), str(w.get("id", "?")), "dependency" in w)
        for w in bw.get("windows", [])
    ]


def compile_object() -> tuple[bytes, str]:
    ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="re008-byte-match-") as tmpdir:
        obj_path = Path(tmpdir) / "consensus_staking_bytes.o"
        subprocess.run(
            [
                "rustc",
                "+1.95.0",
                "--edition=2021",
                "--crate-type=rlib",
                "--crate-name=consensus_staking_byte_matches",
                "-C",
                "opt-level=3",
                "-C",
                "overflow-checks=yes",
                "--emit=obj",
                "-o",
                str(obj_path),
                str(SOURCE_PATH),
            ],
            check=True,
        )
        return obj_path.read_bytes(), ver


def extract_compiled_symbols(obj: bytes) -> list[tuple[str, bytes, list[int]]]:
    secs = parse_elf_sections(obj)
    symtab = [s for s in secs if s[2] == 2][0]
    strtab = secs[symtab[6]]
    relas_by_sec: dict[int, list[int]] = {}
    for s in secs:
        if s[2] == 4:
            relas_by_sec[s[7]] = [
                struct.unpack_from("<Q", obj, o)[0]
                for o in range(s[4], s[4] + s[5], 24)
            ]
    out = []
    for o in range(symtab[4], symtab[4] + symtab[5], 24):
        st_name, _st_info, _st_other, st_shndx, st_value, st_size = struct.unpack_from(
            "<IBBHQQ", obj, o
        )
        if st_size == 0 or st_shndx >= len(secs):
            continue
        end = obj.find(b"\0", strtab[4] + st_name)
        name = obj[strtab[4] + st_name : end].decode("latin1")
        sec = secs[st_shndx]
        code = obj[sec[4] + st_value : sec[4] + st_value + st_size]
        rels = sorted(
            r_off - st_value
            for r_off in relas_by_sec.get(st_shndx, [])
            if st_value <= r_off < st_value + st_size
        )
        out.append((name, code, rels))
    return out


def match_symbol(
    syms: list[tuple[str, bytes, list[int]]], needle: str
) -> tuple[str, bytes, list[int]]:
    token = f"{len(needle)}{needle}17h"
    matches = [s for s in syms if token in s[0]]
    if len(matches) != 1:
        raise ValueError(
            f"expected 1 symbol matching {token!r}, found {len(matches)}: {[m[0] for m in matches]}"
        )
    return matches[0]


def build_records(hl_data: bytes) -> dict[str, object]:
    hl_secs = {s[1]: s for s in parse_elf_sections(hl_data)}
    t_addr, t_off = hl_secs[".text"][3], hl_secs[".text"][4]
    fde_map = load_fde_map()
    reg_windows = load_registered_windows()
    obj_bytes, rustc_version = compile_object()
    syms = extract_compiled_symbols(obj_bytes)

    rows = []
    seen_ranges: list[tuple[int, int]] = []
    for comp, sym_needle, start_va, end_va, label in WINDOWS:
        if fde_map and fde_map.get(start_va) != end_va:
            raise ValueError(
                f"FDE mismatch for {label}: index has {fde_map.get(start_va)}, expected 0x{end_va:x}"
            )
        for rs, re_, rid, is_dep in reg_windows:
            if start_va < re_ and rs < end_va:
                if is_dep or (start_va, end_va) != (rs, re_):
                    raise ValueError(f"Window {label} overlaps research/byte-windows.json entry {rid}")
        for ps, pe in seen_ranges:
            if start_va < pe and ps < end_va:
                raise ValueError(f"Internal overlap for {label} (0x{start_va:x}..0x{end_va:x})")
        seen_ranges.append((start_va, end_va))

        _sym_name, compiled, rels = match_symbol(syms, sym_needle)
        target = hl_data[t_off + (start_va - t_addr) : t_off + (end_va - t_addr)]
        if len(compiled) != len(target):
            raise ValueError(
                f"length mismatch for {label}: compiled={len(compiled)} target={len(target)}"
            )
        mask = bytearray(len(compiled))
        for r_off in rels:
            for k in range(4):
                if r_off + k < len(mask):
                    mask[r_off + k] = 1
        mismatches = [
            i for i in range(len(compiled)) if not mask[i] and compiled[i] != target[i]
        ]
        if mismatches:
            raise ValueError(f"non-relocation mismatches for {label}: {mismatches[:8]}")
        raw_equal = sum(1 for a, b in zip(compiled, target) if a == b)
        rows.append(
            {
                "component": comp,
                "label": label,
                "symbol_key": sym_needle,
                "start_va": f"0x{start_va:x}",
                "end_va": f"0x{end_va:x}",
                "size": len(target),
                "raw_equal_bytes": raw_equal,
                "relocation_offsets": rels,
                "relocation_qualified": True,
                "target_sha256": hashlib.sha256(target).hexdigest(),
                "compiled_sha256": hashlib.sha256(compiled).hexdigest(),
            }
        )

    return {
        "schema_version": 1,
        "work_item": "RE-008-node115-consensus-staking-byte-matches",
        "target_binary": {
            "path": "artifacts/node/115/hl-node",
            "size": len(hl_data),
            "sha256": hashlib.sha256(hl_data).hexdigest(),
        },
        "source_sha256": hashlib.sha256(SOURCE_PATH.read_bytes()).hexdigest(),
        "rustc_version": rustc_version,
        "summary": {
            "windows": len(rows),
            "total_bytes": sum(r["size"] for r in rows),
            "raw_equal_bytes": sum(r["raw_equal_bytes"] for r in rows),
            "staking_windows": sum(1 for r in rows if r["component"] == "staking"),
            "staking_bytes": sum(r["size"] for r in rows if r["component"] == "staking"),
            "consensus_windows": sum(1 for r in rows if r["component"] == "consensus"),
            "consensus_bytes": sum(r["size"] for r in rows if r["component"] == "consensus"),
        },
        "windows": rows,
    }


def verify_records(records: dict[str, object], hl_data: bytes, rebuild: bool = True) -> None:
    tb = records["target_binary"]
    if tb["sha256"] != EXPECTED_BINARY_SHA256 or tb["size"] != EXPECTED_BINARY_SIZE:
        raise ValueError("target_binary metadata mismatch")
    if hashlib.sha256(hl_data).hexdigest() != EXPECTED_BINARY_SHA256:
        raise ValueError("on-disk binary SHA-256 mismatch")
    if records["source_sha256"] != hashlib.sha256(SOURCE_PATH.read_bytes()).hexdigest():
        raise ValueError("source_sha256 mismatch")

    rows = records["windows"]
    if len(rows) != len(WINDOWS):
        raise ValueError(f"expected {len(WINDOWS)} windows, got {len(rows)}")
    seen = set()
    for r in rows:
        key = (r["start_va"], r["end_va"])
        if key in seen:
            raise ValueError(f"duplicate window {key}")
        seen.add(key)

    if rebuild:
        rebuilt = build_records(hl_data)
        if rebuilt["windows"] != records["windows"] or rebuilt["summary"] != records["summary"]:
            raise ValueError("rebuilt compiled-byte records diverge from committed records.json")
    else:
        hl_secs = {s[1]: s for s in parse_elf_sections(hl_data)}
        t_addr, t_off = hl_secs[".text"][3], hl_secs[".text"][4]
        for r in rows:
            s_va = int(r["start_va"], 16)
            e_va = int(r["end_va"], 16)
            target = hl_data[t_off + (s_va - t_addr) : t_off + (e_va - t_addr)]
            if len(target) != r["size"] or hashlib.sha256(target).hexdigest() != r["target_sha256"]:
                raise ValueError(f"target bytes mismatch for {r['label']}")
            if not r["relocation_qualified"]:
                raise ValueError(f"window not relocation-qualified: {r['label']}")


def run_negative_controls(records: dict[str, object], hl_data: bytes) -> int:
    mutations = []

    m1 = copy.deepcopy(records)
    m1["source_sha256"] = "0" * 64
    mutations.append(("corrupted_source_sha256", m1))

    m2 = copy.deepcopy(records)
    m2["windows"][0]["target_sha256"] = "f" * 64
    mutations.append(("corrupted_target_sha256", m2))

    m3 = copy.deepcopy(records)
    m3["windows"][0]["relocation_qualified"] = False
    mutations.append(("relocation_qualified_false", m3))

    m4 = copy.deepcopy(records)
    m4["windows"][1] = copy.deepcopy(m4["windows"][0])
    mutations.append(("duplicate_window", m4))

    for name, mutated in mutations:
        try:
            verify_records(mutated, hl_data, rebuild=False)
        except ValueError:
            continue
        raise AssertionError(f"negative control {name} was unexpectedly accepted")
    return len(mutations)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Compile and write records.json")
    parser.add_argument("--self-test", action="store_true", help="Run negative controls")
    args = parser.parse_args()

    hl_data = BINARY_PATH.read_bytes()
    if args.write:
        records = build_records(hl_data)
        RECORDS_PATH.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
        verify_records(records, hl_data, rebuild=False)
    else:
        records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        verify_records(records, hl_data, rebuild=True)

    neg = run_negative_controls(records, hl_data) if args.self_test else 0
    s = records["summary"]
    print(
        f"RE-008-node115-consensus-staking-byte-matches verified: "
        f"{s['windows']}/{s['windows']} relocation-qualified windows, "
        f"{s['total_bytes']} B ({s['raw_equal_bytes']} raw-equal), "
        f"staking={s['staking_windows']}w/{s['staking_bytes']}B, "
        f"consensus={s['consensus_windows']}w/{s['consensus_bytes']}B"
        + (f", {neg}/{neg} negative controls rejected." if args.self_test else ".")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
