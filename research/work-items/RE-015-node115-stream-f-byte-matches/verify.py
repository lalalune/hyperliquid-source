#!/usr/bin/env python3
"""Compile lib.rs with rustc 1.95.0 and verify 137 first-party Stream F FDE byte matches against node #115."""

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
SOURCE_PATH = PACKET_DIR / "lib.rs"
RECORDS_PATH = PACKET_DIR / "records.json"

sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "research" / "work-items" / "RE-002-node115-std-census"))
from byte_progress import compare  # noqa: E402
from census import object_functions  # noqa: E402
from elf_index import sections  # noqa: E402

EXPECTED_BINARY_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
EXPECTED_BINARY_SIZE = 105_896_032

# (component, symbol_substring, start_va, end_va, label, expecting_string_or_none)
WINDOWS = [
    ('info-api', 'info_request_55_visit_str_json', 0x2744200, 0x2744bfa, 'info-api NodeInfoRequest 55-variant JSON visit_str (0x2744200)', None),
    ('constants', 'constants_chain_fmt_display', 0x1778c60, 0x1778cca, 'constants Chain::fmt Display (0x1778c60)', None),
    ('evm-rpc', 'evm_rpc_expecting_struct_variant_jsonrpcresult_error', 0x174c6f0, 0x174c709, 'evm-rpc struct variant JsonRpcResult::Error expecting (0x174c6f0)', 'struct variant JsonRpcResult::Error'),
    ('evm-rpc', 'evm_rpc_expecting_struct_jsonrpcerror', 0x174c710, 0x174c729, 'evm-rpc struct JsonRpcError expecting (0x174c710)', 'struct JsonRpcError'),
    ('evm-rpc', 'evm_rpc_expecting_struct_variant_jsonrpcresult_success', 0x174c750, 0x174c769, 'evm-rpc struct variant JsonRpcResult::Success expecting (0x174c750)', 'struct variant JsonRpcResult::Success'),
    ('evm-rpc', 'evm_rpc_expecting_struct_jsonrpcresponse', 0x174c770, 0x174c789, 'evm-rpc struct JsonRpcResponse expecting (0x174c770)', 'struct JsonRpcResponse'),
    ('evm-rpc', 'evm_rpc_expecting_struct_paramsobject', 0x174c790, 0x174c7a9, 'evm-rpc struct ParamsObject expecting (0x174c790)', 'struct ParamsObject'),
    ('evm-rpc', 'evm_rpc_expecting_struct_evmrpcconfig', 0x17577c0, 0x17577d9, 'evm-rpc struct EvmRpcConfig expecting (0x17577c0)', 'struct EvmRpcConfig'),
    ('constants', 'constants_expecting_struct_staticconfig', 0x17785d0, 0x17785e9, 'constants struct StaticConfig expecting (0x17785d0)', 'struct StaticConfig'),
    ('evm', 'evm_expecting_struct_receiptwire', 0x22f56e0, 0x22f56f9, 'evm struct ReceiptWire expecting (0x22f56e0)', 'struct ReceiptWire'),
    ('evm', 'evm_expecting_struct_l1toevmnativetokentransfer', 0x22f5740, 0x22f5759, 'evm struct L1ToEvmNativeTokenTransfer expecting (0x22f5740)', 'struct L1ToEvmNativeTokenTransfer'),
    ('evm', 'evm_expecting_struct_txeip7702wire', 0x22f57c0, 0x22f57d9, 'evm struct TxEip7702Wire expecting (0x22f57c0)', 'struct TxEip7702Wire'),
    ('evm', 'evm_expecting_enum_evmblockwire', 0x22f5840, 0x22f5859, 'evm enum EvmBlockWire expecting (0x22f5840)', 'enum EvmBlockWire'),
    ('evm', 'evm_expecting_struct_txeip2930wire', 0x22f58a0, 0x22f58b9, 'evm struct TxEip2930Wire expecting (0x22f58a0)', 'struct TxEip2930Wire'),
    ('evm', 'evm_expecting_struct_sealedblockwire', 0x22f58e0, 0x22f58f9, 'evm struct SealedBlockWire expecting (0x22f58e0)', 'struct SealedBlockWire'),
    ('evm', 'evm_expecting_struct_blockbodywire', 0x22f5940, 0x22f5959, 'evm struct BlockBodyWire expecting (0x22f5940)', 'struct BlockBodyWire'),
    ('evm', 'evm_expecting_struct_txlegacywire', 0x22f5960, 0x22f5979, 'evm struct TxLegacyWire expecting (0x22f5960)', 'struct TxLegacyWire'),
    ('evm', 'evm_expecting_struct_txeip1559wire', 0x22f59a0, 0x22f59b9, 'evm struct TxEip1559Wire expecting (0x22f59a0)', 'struct TxEip1559Wire'),
    ('evm', 'evm_expecting_struct_l1toevmerc20transfer', 0x22f5a00, 0x22f5a19, 'evm struct L1ToEvmErc20Transfer expecting (0x22f5a00)', 'struct L1ToEvmErc20Transfer'),
    ('evm', 'evm_expecting_struct_sendtoevmdata', 0x22f5ac0, 0x22f5ad9, 'evm struct SendToEvmData expecting (0x22f5ac0)', 'struct SendToEvmData'),
    ('evm', 'evm_expecting_enum_txtypewire', 0x22f5b00, 0x22f5b19, 'evm enum TxTypeWire expecting (0x22f5b00)', 'enum TxTypeWire'),
    ('evm', 'evm_expecting_struct_txeip4844wire', 0x22f5c00, 0x22f5c19, 'evm struct TxEip4844Wire expecting (0x22f5c00)', 'struct TxEip4844Wire'),
    ('evm', 'evm_expecting_struct_evmtxlookup', 0x22f5c40, 0x22f5c59, 'evm struct EvmTxLookup expecting (0x22f5c40)', 'struct EvmTxLookup'),
    ('evm', 'evm_expecting_struct_sendtoevmwithdataaction', 0x24207c0, 0x24207d9, 'evm struct SendToEvmWithDataAction expecting (0x24207c0)', 'struct SendToEvmWithDataAction'),
    ('bridge', 'bridge_expecting_struct_bridgevalidatorset', 0x2420a20, 0x2420a39, 'bridge struct BridgeValidatorSet expecting (0x2420a20)', 'struct BridgeValidatorSet'),
    ('bridge', 'bridge_expecting_tuple_struct_bridgeepoch', 0x25eb4b0, 0x25eb4c9, 'bridge tuple struct BridgeEpoch expecting (0x25eb4b0)', 'tuple struct BridgeEpoch'),
    ('bridge', 'bridge_expecting_tuple_struct_bridgevalidator', 0x25eb4d0, 0x25eb4e9, 'bridge tuple struct BridgeValidator expecting (0x25eb4d0)', 'tuple struct BridgeValidator'),
    ('evm', 'evm_expecting_struct_readprecompileinput', 0x26a17c0, 0x26a17d9, 'evm struct ReadPrecompileInput expecting (0x26a17c0)', 'struct ReadPrecompileInput'),
    ('evm', 'evm_expecting_struct_variant_readprecompileresult_ok', 0x26a1950, 0x26a1969, 'evm struct variant ReadPrecompileResult::Ok expecting (0x26a1950)', 'struct variant ReadPrecompileResult::Ok'),
    ('evm', 'evm_expecting_enum_readprecompileresult', 0x26a1c20, 0x26a1c39, 'evm enum ReadPrecompileResult expecting (0x26a1c20)', 'enum ReadPrecompileResult'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_delegations', 0x2772fd0, 0x2772fe9, 'info-api struct variant NodeInfoRequest::Delegations expecting (0x2772fd0)', 'struct variant NodeInfoRequest::Delegations'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_spotdeploystate', 0x2773030, 0x2773049, 'info-api struct variant NodeInfoRequest::SpotDeployState expecting (0x2773030)', 'struct variant NodeInfoRequest::SpotDeployState'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_userdexabstraction', 0x2773090, 0x27730a9, 'info-api struct variant NodeInfoRequest::UserDexAbstraction expecting (0x2773090)', 'struct variant NodeInfoRequest::UserDexAbstraction'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_userrole', 0x2773190, 0x27731a9, 'info-api struct variant NodeInfoRequest::UserRole expecting (0x2773190)', 'struct variant NodeInfoRequest::UserRole'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_userratelimit', 0x27731d0, 0x27731e9, 'info-api struct variant NodeInfoRequest::UserRateLimit expecting (0x27731d0)', 'struct variant NodeInfoRequest::UserRateLimit'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_userfees', 0x2773230, 0x2773249, 'info-api struct variant NodeInfoRequest::UserFees expecting (0x2773230)', 'struct variant NodeInfoRequest::UserFees'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_uservaultequities', 0x2773270, 0x2773289, 'info-api struct variant NodeInfoRequest::UserVaultEquities expecting (0x2773270)', 'struct variant NodeInfoRequest::UserVaultEquities'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_usertomultisigsigners', 0x2773290, 0x27732a9, 'info-api struct variant NodeInfoRequest::UserToMultiSigSigners expecting (0x2773290)', 'struct variant NodeInfoRequest::UserToMultiSigSigners'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_subaccounts2', 0x27732d0, 0x27732e9, 'info-api struct variant NodeInfoRequest::SubAccounts2 expecting (0x27732d0)', 'struct variant NodeInfoRequest::SubAccounts2'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_subaccounts', 0x27732f0, 0x2773309, 'info-api struct variant NodeInfoRequest::SubAccounts expecting (0x27732f0)', 'struct variant NodeInfoRequest::SubAccounts'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_vaultsummaries', 0x2773310, 0x2773329, 'info-api struct variant NodeInfoRequest::VaultSummaries expecting (0x2773310)', 'struct variant NodeInfoRequest::VaultSummaries'),
    ('bridge', 'bridge_expecting_struct_pendingwithdrawals', 0x2773350, 0x2773369, 'bridge struct PendingWithdrawals expecting (0x2773350)', 'struct PendingWithdrawals'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_leadingvaults', 0x27733d0, 0x27733e9, 'info-api struct variant NodeInfoRequest::LeadingVaults expecting (0x27733d0)', 'struct variant NodeInfoRequest::LeadingVaults'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_settledoutcome', 0x2773410, 0x2773429, 'info-api struct variant NodeInfoRequest::SettledOutcome expecting (0x2773410)', 'struct variant NodeInfoRequest::SettledOutcome'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_perpsatopeninterestcap', 0x2773530, 0x2773549, 'info-api struct variant NodeInfoRequest::PerpsAtOpenInterestCap expecting (0x2773530)', 'struct variant NodeInfoRequest::PerpsAtOpenInterestCap'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_perpannotation', 0x2773570, 0x2773589, 'info-api struct variant NodeInfoRequest::PerpAnnotation expecting (0x2773570)', 'struct variant NodeInfoRequest::PerpAnnotation'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_filesnapshot', 0x27735f0, 0x2773609, 'info-api struct variant NodeInfoRequest::FileSnapshot expecting (0x27735f0)', 'struct variant NodeInfoRequest::FileSnapshot'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_bolereservestate', 0x2773690, 0x27736a9, 'info-api struct variant NodeInfoRequest::BoleReserveState expecting (0x2773690)', 'struct variant NodeInfoRequest::BoleReserveState'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_settledquestion', 0x27736f0, 0x2773709, 'info-api struct variant NodeInfoRequest::SettledQuestion expecting (0x27736f0)', 'struct variant NodeInfoRequest::SettledQuestion'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_webdata2', 0x2773770, 0x2773789, 'info-api struct variant NodeInfoRequest::WebData2 expecting (0x2773770)', 'struct variant NodeInfoRequest::WebData2'),
    ('evm', 'evm_expecting_struct_evmstate', 0x2773790, 0x27737a9, 'evm struct EvmState expecting (0x2773790)', 'struct EvmState'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_activeassetdata', 0x27737f0, 0x2773809, 'info-api struct variant NodeInfoRequest::ActiveAssetData expecting (0x27737f0)', 'struct variant NodeInfoRequest::ActiveAssetData'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_frontendopenorders', 0x2773830, 0x2773849, 'info-api struct variant NodeInfoRequest::FrontendOpenOrders expecting (0x2773830)', 'struct variant NodeInfoRequest::FrontendOpenOrders'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_clearinghousestate', 0x2773910, 0x2773929, 'info-api struct variant NodeInfoRequest::ClearinghouseState expecting (0x2773910)', 'struct variant NodeInfoRequest::ClearinghouseState'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_extraagents', 0x2773930, 0x2773949, 'info-api struct variant NodeInfoRequest::ExtraAgents expecting (0x2773930)', 'struct variant NodeInfoRequest::ExtraAgents'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_meta', 0x27739f0, 0x2773a09, 'info-api struct variant NodeInfoRequest::Meta expecting (0x27739f0)', 'struct variant NodeInfoRequest::Meta'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_approvedbuilders', 0x2773a30, 0x2773a49, 'info-api struct variant NodeInfoRequest::ApprovedBuilders expecting (0x2773a30)', 'struct variant NodeInfoRequest::ApprovedBuilders'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_webdata3', 0x2773a50, 0x2773a69, 'info-api struct variant NodeInfoRequest::WebData3 expecting (0x2773a50)', 'struct variant NodeInfoRequest::WebData3'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_perpdexlimits', 0x2773a70, 0x2773a89, 'info-api struct variant NodeInfoRequest::PerpDexLimits expecting (0x2773a70)', 'struct variant NodeInfoRequest::PerpDexLimits'),
    ('bridge', 'bridge_expecting_struct_totalwithdrawal', 0x2773ad0, 0x2773ae9, 'bridge struct TotalWithdrawal expecting (0x2773ad0)', 'struct TotalWithdrawal'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_boleuserstate', 0x2773b10, 0x2773b29, 'info-api struct variant NodeInfoRequest::BoleUserState expecting (0x2773b10)', 'struct variant NodeInfoRequest::BoleUserState'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_perpdexstatus', 0x2773bd0, 0x2773be9, 'info-api struct variant NodeInfoRequest::PerpDexStatus expecting (0x2773bd0)', 'struct variant NodeInfoRequest::PerpDexStatus'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_delegatorsummary', 0x2773c10, 0x2773c29, 'info-api struct variant NodeInfoRequest::DelegatorSummary expecting (0x2773c10)', 'struct variant NodeInfoRequest::DelegatorSummary'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_tokenannotation', 0x2773cf0, 0x2773d09, 'info-api struct variant NodeInfoRequest::TokenAnnotation expecting (0x2773cf0)', 'struct variant NodeInfoRequest::TokenAnnotation'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_aqav2interesthistory', 0x2773d70, 0x2773d89, 'info-api struct variant NodeInfoRequest::Aqav2InterestHistory expecting (0x2773d70)', 'struct variant NodeInfoRequest::Aqav2InterestHistory'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_margintable', 0x2773d90, 0x2773da9, 'info-api struct variant NodeInfoRequest::MarginTable expecting (0x2773d90)', 'struct variant NodeInfoRequest::MarginTable'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_maxbuilderfee', 0x2773e90, 0x2773ea9, 'info-api struct variant NodeInfoRequest::MaxBuilderFee expecting (0x2773e90)', 'struct variant NodeInfoRequest::MaxBuilderFee'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_userabstraction', 0x2773f10, 0x2773f29, 'info-api struct variant NodeInfoRequest::UserAbstraction expecting (0x2773f10)', 'struct variant NodeInfoRequest::UserAbstraction'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_votes', 0x2773f30, 0x2773f49, 'info-api struct variant NodeInfoRequest::Votes expecting (0x2773f30)', 'struct variant NodeInfoRequest::Votes'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_outcomedeployerlimits', 0x2773f50, 0x2773f69, 'info-api struct variant NodeInfoRequest::OutcomeDeployerLimits expecting (0x2773f50)', 'struct variant NodeInfoRequest::OutcomeDeployerLimits'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_spotclearinghousestate', 0x2773fd0, 0x2773fe9, 'info-api struct variant NodeInfoRequest::SpotClearinghouseState expecting (0x2773fd0)', 'struct variant NodeInfoRequest::SpotClearinghouseState'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_spotmeta', 0x2773ff0, 0x2774009, 'info-api struct variant NodeInfoRequest::SpotMeta expecting (0x2773ff0)', 'struct variant NodeInfoRequest::SpotMeta'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_openorders', 0x2774010, 0x2774029, 'info-api struct variant NodeInfoRequest::OpenOrders expecting (0x2774010)', 'struct variant NodeInfoRequest::OpenOrders'),
    ('info-api', 'info_api_expecting_struct_variant_nodeinforequest_userstarstate', 0x2774030, 0x2774049, 'info-api struct variant NodeInfoRequest::UserStarState expecting (0x2774030)', 'struct variant NodeInfoRequest::UserStarState'),
    ('bridge', 'bridge_expecting_struct_bridge2', 0x292c7b0, 0x292c7c9, 'bridge struct Bridge2 expecting (0x292c7b0)', 'struct Bridge2'),
    ('evm', 'evm_expecting_struct_evmusermodifyaction', 0x292ca70, 0x292ca89, 'evm struct EvmUserModifyAction expecting (0x292ca70)', 'struct EvmUserModifyAction'),
    ('bridge', 'bridge_expecting_struct_etheventid', 0x292d810, 0x292d829, 'bridge struct EthEventId expecting (0x292d810)', 'struct EthEventId'),
    ('bridge', 'bridge_expecting_struct_voteethfinalizedwithdrawalaction', 0x292d9f0, 0x292da09, 'bridge struct VoteEthFinalizedWithdrawalAction expecting (0x292d9f0)', 'struct VoteEthFinalizedWithdrawalAction'),
    ('bridge', 'bridge_expecting_struct_voteethdepositaction', 0x292dd50, 0x292dd69, 'bridge struct VoteEthDepositAction expecting (0x292dd50)', 'struct VoteEthDepositAction'),
    ('evm-rpc', 'evm_rpc_expecting_struct_paramsobject', 0x29b02f0, 0x29b0309, 'evm-rpc struct ParamsObject expecting (0x29b02f0)', 'struct ParamsObject'),
    ('evm', 'evm_expecting_struct_hyperevm', 0x29b0470, 0x29b0489, 'evm struct HyperEvm expecting (0x29b0470)', 'struct HyperEvm'),
    ('bridge', 'bridge_expecting_struct_voteethfinalizedvalidatorsetupdateaction', 0x29b06f0, 0x29b0709, 'bridge struct VoteEthFinalizedValidatorSetUpdateAction expecting (0x29b06f0)', 'struct VoteEthFinalizedValidatorSetUpdateAction'),
    ('bridge', 'bridge_expecting_struct_totalwithdrawal', 0x36cd0b0, 0x36cd0c9, 'bridge struct TotalWithdrawal expecting (0x36cd0b0)', 'struct TotalWithdrawal'),
    ('bridge', 'bridge_expecting_struct_bridgevalidatorset', 0x36cd0d0, 0x36cd0e9, 'bridge struct BridgeValidatorSet expecting (0x36cd0d0)', 'struct BridgeValidatorSet'),
    ('bridge', 'bridge_expecting_struct_pendingwithdrawals', 0x36cd230, 0x36cd249, 'bridge struct PendingWithdrawals expecting (0x36cd230)', 'struct PendingWithdrawals'),
    ('evm', 'evm_expecting_struct_l1toevmerc20transfer', 0x38db8c0, 0x38db8d9, 'evm struct L1ToEvmErc20Transfer expecting (0x38db8c0)', 'struct L1ToEvmErc20Transfer'),
    ('evm', 'evm_expecting_struct_l1toevmnativetokentransfer', 0x38dbd60, 0x38dbd79, 'evm struct L1ToEvmNativeTokenTransfer expecting (0x38dbd60)', 'struct L1ToEvmNativeTokenTransfer'),
    ('evm', 'evm_expecting_struct_hyperevm', 0x4351180, 0x4351199, 'evm struct HyperEvm expecting (0x4351180)', 'struct HyperEvm'),
    ('evm', 'evm_expecting_struct_evmstate', 0x4351420, 0x4351439, 'evm struct EvmState expecting (0x4351420)', 'struct EvmState'),
    ('evm', 'evm_expecting_struct_sendtoevmwithdataaction', 0x4461370, 0x4461389, 'evm struct SendToEvmWithDataAction expecting (0x4461370)', 'struct SendToEvmWithDataAction'),
    ('bridge', 'bridge_expecting_struct_voteethfinalizedwithdrawalaction', 0x44662d0, 0x44662e9, 'bridge struct VoteEthFinalizedWithdrawalAction expecting (0x44662d0)', 'struct VoteEthFinalizedWithdrawalAction'),
    ('bridge', 'bridge_expecting_struct_voteethfinalizedvalidatorsetupdateaction', 0x4468000, 0x4468019, 'bridge struct VoteEthFinalizedValidatorSetUpdateAction expecting (0x4468000)', 'struct VoteEthFinalizedValidatorSetUpdateAction'),
    ('evm', 'evm_expecting_struct_txlegacywire', 0x44dc370, 0x44dc389, 'evm struct TxLegacyWire expecting (0x44dc370)', 'struct TxLegacyWire'),
    ('evm', 'evm_expecting_struct_txeip2930wire', 0x44dc410, 0x44dc429, 'evm struct TxEip2930Wire expecting (0x44dc410)', 'struct TxEip2930Wire'),
    ('bridge', 'bridge_expecting_struct_bridge2', 0x44dc450, 0x44dc469, 'bridge struct Bridge2 expecting (0x44dc450)', 'struct Bridge2'),
    ('evm', 'evm_expecting_struct_txeip4844wire', 0x44dc4b0, 0x44dc4c9, 'evm struct TxEip4844Wire expecting (0x44dc4b0)', 'struct TxEip4844Wire'),
    ('evm', 'evm_expecting_struct_txeip7702wire', 0x44dc5d0, 0x44dc5e9, 'evm struct TxEip7702Wire expecting (0x44dc5d0)', 'struct TxEip7702Wire'),
    ('evm', 'evm_expecting_struct_blockbodywire', 0x44dc6b0, 0x44dc6c9, 'evm struct BlockBodyWire expecting (0x44dc6b0)', 'struct BlockBodyWire'),
    ('evm', 'evm_expecting_struct_sealedblockwire', 0x44dc770, 0x44dc789, 'evm struct SealedBlockWire expecting (0x44dc770)', 'struct SealedBlockWire'),
    ('bridge', 'bridge_expecting_struct_etheventid', 0x44dc890, 0x44dc8a9, 'bridge struct EthEventId expecting (0x44dc890)', 'struct EthEventId'),
    ('bridge', 'bridge_expecting_tuple_struct_bridgevalidator', 0x44dc930, 0x44dc949, 'bridge tuple struct BridgeValidator expecting (0x44dc930)', 'tuple struct BridgeValidator'),
    ('evm', 'evm_expecting_enum_evmblockwire', 0x44dc990, 0x44dc9a9, 'evm enum EvmBlockWire expecting (0x44dc990)', 'enum EvmBlockWire'),
    ('evm', 'evm_expecting_struct_txeip1559wire', 0x44dc9d0, 0x44dc9e9, 'evm struct TxEip1559Wire expecting (0x44dc9d0)', 'struct TxEip1559Wire'),
    ('bridge', 'bridge_expecting_tuple_struct_bridgeepoch', 0x44dca10, 0x44dca29, 'bridge tuple struct BridgeEpoch expecting (0x44dca10)', 'tuple struct BridgeEpoch'),
    ('evm', 'evm_expecting_struct_sendtoevmdata', 0x44dccb0, 0x44dccc9, 'evm struct SendToEvmData expecting (0x44dccb0)', 'struct SendToEvmData'),
    ('evm', 'evm_expecting_struct_evmusermodifyaction', 0x46929d0, 0x46929e9, 'evm struct EvmUserModifyAction expecting (0x46929d0)', 'struct EvmUserModifyAction'),
    ('bridge', 'bridge_expecting_struct_voteethdepositaction', 0x4692c80, 0x4692c99, 'bridge struct VoteEthDepositAction expecting (0x4692c80)', 'struct VoteEthDepositAction'),
    ('constants', 'constants_expecting_enum_chain', 0x46ddb50, 0x46ddb69, 'constants enum Chain expecting (0x46ddb50)', 'enum Chain'),
    ('evm', 'evm_expecting_struct_evmstate', 0x51ad940, 0x51ad959, 'evm struct EvmState expecting (0x51ad940)', 'struct EvmState'),
    ('bridge', 'bridge_expecting_struct_bridgevalidatorset', 0x51adc90, 0x51adca9, 'bridge struct BridgeValidatorSet expecting (0x51adc90)', 'struct BridgeValidatorSet'),
    ('bridge', 'bridge_expecting_tuple_struct_bridgevalidator', 0x53d5890, 0x53d58a9, 'bridge tuple struct BridgeValidator expecting (0x53d5890)', 'tuple struct BridgeValidator'),
    ('bridge', 'bridge_expecting_tuple_struct_bridgeepoch', 0x53d6350, 0x53d6369, 'bridge tuple struct BridgeEpoch expecting (0x53d6350)', 'tuple struct BridgeEpoch'),
    ('bridge', 'bridge_expecting_struct_voteethfinalizedwithdrawalaction', 0x53d6530, 0x53d6549, 'bridge struct VoteEthFinalizedWithdrawalAction expecting (0x53d6530)', 'struct VoteEthFinalizedWithdrawalAction'),
    ('evm', 'evm_expecting_struct_evmusermodifyaction', 0x53d6550, 0x53d6569, 'evm struct EvmUserModifyAction expecting (0x53d6550)', 'struct EvmUserModifyAction'),
    ('evm', 'evm_expecting_struct_hyperevm', 0x5616690, 0x56166a9, 'evm struct HyperEvm expecting (0x5616690)', 'struct HyperEvm'),
    ('constants', 'constants_expecting_enum_chain', 0x57d1bb0, 0x57d1bc9, 'constants enum Chain expecting (0x57d1bb0)', 'enum Chain'),
    ('bridge', 'bridge_expecting_struct_totalwithdrawal', 0x5941db0, 0x5941dc9, 'bridge struct TotalWithdrawal expecting (0x5941db0)', 'struct TotalWithdrawal'),
    ('evm', 'evm_expecting_struct_sendtoevmwithdataaction', 0x59421d0, 0x59421e9, 'evm struct SendToEvmWithDataAction expecting (0x59421d0)', 'struct SendToEvmWithDataAction'),
    ('bridge', 'bridge_expecting_struct_pendingwithdrawals', 0x59425b0, 0x59425c9, 'bridge struct PendingWithdrawals expecting (0x59425b0)', 'struct PendingWithdrawals'),
    ('bridge', 'bridge_expecting_struct_voteethdepositaction', 0x5942670, 0x5942689, 'bridge struct VoteEthDepositAction expecting (0x5942670)', 'struct VoteEthDepositAction'),
    ('bridge', 'bridge_expecting_struct_voteethfinalizedvalidatorsetupdateaction', 0x5942750, 0x5942769, 'bridge struct VoteEthFinalizedValidatorSetUpdateAction expecting (0x5942750)', 'struct VoteEthFinalizedValidatorSetUpdateAction'),
    ('evm', 'evm_expecting_struct_readprecompileinput', 0x5b08ed0, 0x5b08ee9, 'evm struct ReadPrecompileInput expecting (0x5b08ed0)', 'struct ReadPrecompileInput'),
    ('evm', 'evm_expecting_struct_evmtxlookup', 0x5b08f10, 0x5b08f29, 'evm struct EvmTxLookup expecting (0x5b08f10)', 'struct EvmTxLookup'),
    ('evm', 'evm_expecting_enum_evmblockwire', 0x5b08f50, 0x5b08f69, 'evm enum EvmBlockWire expecting (0x5b08f50)', 'enum EvmBlockWire'),
    ('evm', 'evm_expecting_struct_variant_readprecompileresult_ok', 0x5b09190, 0x5b091a9, 'evm struct variant ReadPrecompileResult::Ok expecting (0x5b09190)', 'struct variant ReadPrecompileResult::Ok'),
    ('evm', 'evm_expecting_struct_l1toevmerc20transfer', 0x5b092f0, 0x5b09309, 'evm struct L1ToEvmErc20Transfer expecting (0x5b092f0)', 'struct L1ToEvmErc20Transfer'),
    ('evm', 'evm_expecting_struct_txeip4844wire', 0x5b09410, 0x5b09429, 'evm struct TxEip4844Wire expecting (0x5b09410)', 'struct TxEip4844Wire'),
    ('evm', 'evm_expecting_struct_txeip1559wire', 0x5b09430, 0x5b09449, 'evm struct TxEip1559Wire expecting (0x5b09430)', 'struct TxEip1559Wire'),
    ('evm', 'evm_expecting_struct_sealedblockwire', 0x5b09470, 0x5b09489, 'evm struct SealedBlockWire expecting (0x5b09470)', 'struct SealedBlockWire'),
    ('bridge', 'bridge_expecting_struct_bridge2', 0x5b094b0, 0x5b094c9, 'bridge struct Bridge2 expecting (0x5b094b0)', 'struct Bridge2'),
    ('evm', 'evm_expecting_struct_l1toevmnativetokentransfer', 0x5b09510, 0x5b09529, 'evm struct L1ToEvmNativeTokenTransfer expecting (0x5b09510)', 'struct L1ToEvmNativeTokenTransfer'),
    ('evm', 'evm_expecting_struct_txeip7702wire', 0x5b09550, 0x5b09569, 'evm struct TxEip7702Wire expecting (0x5b09550)', 'struct TxEip7702Wire'),
    ('evm', 'evm_expecting_struct_receiptwire', 0x5b09610, 0x5b09629, 'evm struct ReceiptWire expecting (0x5b09610)', 'struct ReceiptWire'),
    ('evm', 'evm_expecting_struct_sendtoevmdata', 0x5b09690, 0x5b096a9, 'evm struct SendToEvmData expecting (0x5b09690)', 'struct SendToEvmData'),
    ('bridge', 'bridge_expecting_struct_etheventid', 0x5b09750, 0x5b09769, 'bridge struct EthEventId expecting (0x5b09750)', 'struct EthEventId'),
    ('evm', 'evm_expecting_struct_txlegacywire', 0x5b09790, 0x5b097a9, 'evm struct TxLegacyWire expecting (0x5b09790)', 'struct TxLegacyWire'),
    ('evm', 'evm_expecting_struct_blockbodywire', 0x5b097f0, 0x5b09809, 'evm struct BlockBodyWire expecting (0x5b097f0)', 'struct BlockBodyWire'),
    ('evm', 'evm_expecting_struct_txeip2930wire', 0x5b09870, 0x5b09889, 'evm struct TxEip2930Wire expecting (0x5b09870)', 'struct TxEip2930Wire'),
]


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


def compile_object() -> tuple[bytes, str]:
    ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    with tempfile.TemporaryDirectory() as td:
        obj = Path(td) / "stream_f_byte_matches.o"
        subprocess.run(
            [
                "rustc",
                "+1.95.0",
                "--edition=2021",
                "--crate-type=rlib",
                "--crate-name=node115_stream_f_byte_matches",
                "-C",
                "opt-level=3",
                "-C",
                "overflow-checks=yes",
                "--emit=obj",
                str(SOURCE_PATH),
                "-o",
                str(obj),
            ],
            check=True,
        )
        return obj.read_bytes(), ver


def build_records(data: bytes) -> dict:
    if len(data) != EXPECTED_BINARY_SIZE:
        raise AssertionError(f"size mismatch: {len(data)}")
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_BINARY_SHA256:
        raise AssertionError(f"sha256 mismatch: {sha}")

    secs = {s["name"]: s for s in sections(data)}
    def va_to_off(va: int) -> int:
        for s in secs.values():
            if s["address"] <= va < s["address"] + s["size"]:
                return s["offset"] + (va - s["address"])
        raise AssertionError(f"VA {hex(va)} not mapped")

    fdes = load_fde_map()
    obj_bytes, rustc_version = compile_object()
    compiled_funcs = list(object_functions(obj_bytes))

    def find_compiled(tok: str):
        for syms, c_bytes, rels in compiled_funcs:
            if any(tok in sym for sym in syms):
                rel_dicts = [
                    {"offset": r[0], "type": r[1], "addend": r[2], "width": 4}
                    for r in rels
                ]
                return c_bytes, rel_dicts
        raise AssertionError(f"compiled symbol not found for {tok}")

    rows = []
    by_comp: dict[str, dict[str, int]] = {}
    total_bytes = 0
    total_raw_equal = 0
    total_rel_qual = 0
    seen_starts = set()

    for comp, sym_tok, start_va, end_va, label, exp_str in WINDOWS:
        if start_va in seen_starts:
            raise AssertionError(f"duplicate start_va {hex(start_va)}")
        seen_starts.add(start_va)
        if fdes and fdes.get(start_va) != end_va:
            raise AssertionError(f"FDE mismatch at {hex(start_va)}: expected {hex(end_va)}, got {fdes.get(start_va)}")

        t_bytes = data[va_to_off(start_va) : va_to_off(end_va)]
        c_bytes, rels = find_compiled(sym_tok)
        if len(c_bytes) != len(t_bytes):
            raise AssertionError(f"length mismatch for {sym_tok} at {hex(start_va)}: {len(c_bytes)} vs {len(t_bytes)}")

        if exp_str is not None:
            # Verify RIP-relative .rodata string target in node #115
            disp = struct.unpack_from("<i", t_bytes, 14)[0]
            ln = struct.unpack_from("<I", t_bytes, 19)[0]
            str_va = start_va + 18 + disp
            got_str = data[va_to_off(str_va) : va_to_off(str_va) + ln].decode("ascii")
            if got_str != exp_str:
                raise AssertionError(f"expecting string mismatch at {hex(start_va)}: {got_str!r} != {exp_str!r}")

        cmp_res = compare(c_bytes, t_bytes, rels)
        if not cmp_res["relocation_qualified"] or cmp_res["non_relocation_difference_offsets"]:
            raise AssertionError(f"not relocation-qualified for {sym_tok} at {hex(start_va)}: {cmp_res}")

        sz = end_va - start_va
        total_bytes += sz
        total_raw_equal += cmp_res["raw_equal_bytes"]
        total_rel_qual += 1
        bucket = by_comp.setdefault(comp, {"windows": 0, "bytes": 0, "raw_equal_bytes": 0})
        bucket["windows"] += 1
        bucket["bytes"] += sz
        bucket["raw_equal_bytes"] += cmp_res["raw_equal_bytes"]

        rows.append(
            {
                "component": comp,
                "symbol": sym_tok,
                "start": hex(start_va),
                "end": hex(end_va),
                "bytes": sz,
                "label": label,
                "expecting_string": exp_str,
                "target_body_sha256": hashlib.sha256(t_bytes).hexdigest(),
                "compiled_body_sha256": hashlib.sha256(c_bytes).hexdigest(),
                "raw_equal_bytes": cmp_res["raw_equal_bytes"],
                "relocation_bytes": cmp_res["relocation_bytes"],
                "relocation_qualified": True,
                "relocations": rels,
            }
        )

    return {
        "work_item": "RE-015-node115-stream-f-byte-matches",
        "target_path": "artifacts/node/115/hl-node",
        "target_sha256": sha,
        "rustc_version": rustc_version,
        "rustc_flags": [
            "--edition=2021",
            "--crate-type=rlib",
            "-C",
            "opt-level=3",
            "-C",
            "overflow-checks=yes",
        ],
        "source_sha256": hashlib.sha256(SOURCE_PATH.read_bytes()).hexdigest(),
        "summary": {
            "windows": len(rows),
            "total_bytes": total_bytes,
            "raw_equal_bytes": total_raw_equal,
            "relocation_qualified_windows": total_rel_qual,
            "by_component": by_comp,
        },
        "windows": rows,
    }


def verify_records(records: dict, data: bytes, rebuild: bool = True) -> None:
    if records.get("target_sha256") != EXPECTED_BINARY_SHA256:
        raise AssertionError("target_sha256 mismatch in records")
    if len(data) != EXPECTED_BINARY_SIZE or hashlib.sha256(data).hexdigest() != EXPECTED_BINARY_SHA256:
        raise AssertionError("binary authentication failed")
    if rebuild:
        fresh = build_records(data)
        if fresh["windows"] != records["windows"]:
            raise AssertionError("rebuilt windows differ from committed records.json")
        if fresh["summary"] != records["summary"]:
            raise AssertionError("rebuilt summary differs from committed records.json")
    else:
        secs = {s["name"]: s for s in sections(data)}
        def va_to_off(va: int) -> int:
            for s in secs.values():
                if s["address"] <= va < s["address"] + s["size"]:
                    return s["offset"] + (va - s["address"])
            raise AssertionError(f"VA {hex(va)} not mapped")
        for row in records["windows"]:
            s = int(row["start"], 16)
            e = int(row["end"], 16)
            t_bytes = data[va_to_off(s) : va_to_off(e)]
            if hashlib.sha256(t_bytes).hexdigest() != row["target_body_sha256"]:
                raise AssertionError(f"body sha mismatch at {row['start']}")
            if row["expecting_string"] is not None:
                disp = struct.unpack_from("<i", t_bytes, 14)[0]
                ln = struct.unpack_from("<I", t_bytes, 19)[0]
                str_va = s + 18 + disp
                got = data[va_to_off(str_va) : va_to_off(str_va) + ln].decode("ascii")
                if got != row["expecting_string"]:
                    raise AssertionError(f"expecting string mismatch at {row['start']}")


def run_negative_controls(records: dict, data: bytes) -> int:
    rejected = 0

    # 1. Tampered target_sha256
    bad1 = copy.deepcopy(records)
    bad1["target_sha256"] = "0" * 64
    try:
        verify_records(bad1, data, rebuild=False)
    except AssertionError:
        rejected += 1

    # 2. Tampered target_body_sha256 on first window (0x2744200)
    bad2 = copy.deepcopy(records)
    bad2["windows"][0]["target_body_sha256"] = "f" * 64
    try:
        verify_records(bad2, data, rebuild=False)
    except AssertionError:
        rejected += 1

    # 3. Shifted end VA on second window (0x1778c60)
    bad3 = copy.deepcopy(records)
    bad3["windows"][1]["end"] = hex(int(bad3["windows"][1]["end"], 16) + 1)
    try:
        verify_records(bad3, data, rebuild=False)
    except AssertionError:
        rejected += 1

    # 4. Tampered expecting_string on an expecting window
    bad4 = copy.deepcopy(records)
    bad4["windows"][2]["expecting_string"] = "struct WrongName"
    try:
        verify_records(bad4, data, rebuild=False)
    except AssertionError:
        rejected += 1

    return rejected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--generate", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    data = BINARY_PATH.read_bytes()
    if args.generate:
        recs = build_records(data)
        RECORDS_PATH.write_text(json.dumps(recs, indent=2) + "\n", encoding="utf-8")
        s = recs["summary"]
        print(
            f"Generated {s['windows']} windows, {s['total_bytes']} B "
            f"({s['raw_equal_bytes']} raw-equal, {s['relocation_qualified_windows']}/{s['windows']} rel-qual)"
        )
        return 0

    recs = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
    verify_records(recs, data, rebuild=True)
    if args.self_test:
        rej = run_negative_controls(recs, data)
        if rej != 4:
            raise AssertionError(f"expected 4 rejected negative controls, got {rej}")
        s = recs["summary"]
        print(
            f"SELF-TEST OK: {s['windows']}/{s['windows']} relocation-qualified, "
            f"{s['total_bytes']} B ({s['raw_equal_bytes']} raw-equal), 4/4 negative controls rejected"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
