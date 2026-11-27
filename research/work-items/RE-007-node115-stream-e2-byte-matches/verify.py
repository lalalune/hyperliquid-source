#!/usr/bin/env python3
"""Compile lib.rs with rustc 1.95.0 and verify 219 first-party Stream E2 FDE byte matches against node #115."""

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

EXPECTED_BINARY_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECTED_BINARY_SIZE = 105896032

WINDOWS = [
    ('action-wire', 'action_wire_expecting_struct_usersetabstractionaction', 0x2420020, 0x2420039, 'action-wire struct UserSetAbstractionAction expecting (0x2420020)'),
    ('action-wire', 'action_wire_expecting_struct_usdsendaction', 0x24200e0, 0x24200f9, 'action-wire struct UsdSendAction expecting (0x24200e0)'),
    ('action-wire', 'action_wire_expecting_struct_converttomultisiguseraction', 0x24201e0, 0x24201f9, 'action-wire struct ConvertToMultiSigUserAction expecting (0x24201e0)'),
    ('action-wire', 'action_wire_expecting_struct_withdrawaction3', 0x2420260, 0x2420279, 'action-wire struct WithdrawAction3 expecting (0x2420260)'),
    ('action-wire', 'action_wire_expecting_struct_approvebuilderfeeaction', 0x24204f0, 0x2420509, 'action-wire struct ApproveBuilderFeeAction expecting (0x24204f0)'),
    ('action-wire', 'action_wire_expecting_struct_setdisplaynameaction', 0x2420720, 0x2420739, 'action-wire struct SetDisplayNameAction expecting (0x2420720)'),
    ('action-wire', 'action_wire_expecting_struct_spotsendaction', 0x2420760, 0x2420779, 'action-wire struct SpotSendAction expecting (0x2420760)'),
    ('action-wire', 'action_wire_expecting_struct_setreferreraction', 0x24208a0, 0x24208b9, 'action-wire struct SetReferrerAction expecting (0x24208a0)'),
    ('action-wire', 'action_wire_expecting_struct_usdclasstransferaction', 0x2420a00, 0x2420a19, 'action-wire struct UsdClassTransferAction expecting (0x2420a00)'),
    ('action-wire', 'action_wire_expecting_struct_sendassetaction', 0x2420b00, 0x2420b19, 'action-wire struct SendAssetAction expecting (0x2420b00)'),
    ('action-wire', 'action_wire_expecting_struct_cancelaction', 0x25eb550, 0x25eb569, 'action-wire struct CancelAction expecting (0x25eb550)'),
    ('action-wire', 'action_wire_expecting_struct_cancelbycloidaction', 0x25eb6a0, 0x25eb6b9, 'action-wire struct CancelByCloidAction expecting (0x25eb6a0)'),
    ('action-wire', 'action_wire_expecting_struct_updateisolatedmarginaction', 0x25ebaf0, 0x25ebb09, 'action-wire struct UpdateIsolatedMarginAction expecting (0x25ebaf0)'),
    ('action-wire', 'action_wire_expecting_struct_reserverequestweightaction', 0x292c8d0, 0x292c8e9, 'action-wire struct ReserveRequestWeightAction expecting (0x292c8d0)'),
    ('action-wire', 'action_wire_expecting_struct_schedulecancelaction', 0x292d1d0, 0x292d1e9, 'action-wire struct ScheduleCancelAction expecting (0x292d1d0)'),
    ('action-wire', 'action_wire_expecting_struct_twaporderaction', 0x292d230, 0x292d249, 'action-wire struct TwapOrderAction expecting (0x292d230)'),
    ('action-wire', 'action_wire_expecting_struct_modifyaction', 0x292d3d0, 0x292d3e9, 'action-wire struct ModifyAction expecting (0x292d3d0)'),
    ('action-wire', 'action_wire_expecting_struct_twapcancelaction', 0x29b0450, 0x29b0469, 'action-wire struct TwapCancelAction expecting (0x29b0450)'),
    ('action-wire', 'action_wire_expecting_struct_batchmodifyaction', 0x2d4a610, 0x2d4a629, 'action-wire struct BatchModifyAction expecting (0x2d4a610)'),
    ('action-wire', 'action_wire_expecting_struct_orderaction', 0x2d4a630, 0x2d4a649, 'action-wire struct OrderAction expecting (0x2d4a630)'),
    ('action-wire', 'action_wire_expecting_struct_orderaction', 0x3659730, 0x3659749, 'action-wire struct OrderAction expecting (0x3659730)'),
    ('action-wire', 'action_wire_expecting_struct_cancelaction', 0x3bd13a0, 0x3bd13b9, 'action-wire struct CancelAction expecting (0x3bd13a0)'),
    ('action-wire', 'action_wire_expecting_struct_modifyaction', 0x3bd13c0, 0x3bd13d9, 'action-wire struct ModifyAction expecting (0x3bd13c0)'),
    ('action-wire', 'action_wire_expecting_struct_twaporderaction', 0x3bd3880, 0x3bd3899, 'action-wire struct TwapOrderAction expecting (0x3bd3880)'),
    ('action-wire', 'action_wire_expecting_struct_reserverequestweightaction', 0x3bddbc0, 0x3bddbd9, 'action-wire struct ReserveRequestWeightAction expecting (0x3bddbc0)'),
    ('action-wire', 'action_wire_expecting_struct_updateisolatedmarginaction', 0x3bddbe0, 0x3bddbf9, 'action-wire struct UpdateIsolatedMarginAction expecting (0x3bddbe0)'),
    ('action-wire', 'action_wire_expecting_struct_batchmodifyaction', 0x41fe700, 0x41fe719, 'action-wire struct BatchModifyAction expecting (0x41fe700)'),
    ('action-wire', 'action_wire_expecting_struct_usdsendaction', 0x4450d60, 0x4450d79, 'action-wire struct UsdSendAction expecting (0x4450d60)'),
    ('action-wire', 'action_wire_expecting_struct_spotsendaction', 0x4451b10, 0x4451b29, 'action-wire struct SpotSendAction expecting (0x4451b10)'),
    ('action-wire', 'action_wire_expecting_struct_withdrawaction3', 0x4451b30, 0x4451b49, 'action-wire struct WithdrawAction3 expecting (0x4451b30)'),
    ('action-wire', 'action_wire_expecting_struct_sendassetaction', 0x4452950, 0x4452969, 'action-wire struct SendAssetAction expecting (0x4452950)'),
    ('action-wire', 'action_wire_expecting_struct_setreferreraction', 0x4454bc0, 0x4454bd9, 'action-wire struct SetReferrerAction expecting (0x4454bc0)'),
    ('action-wire', 'action_wire_expecting_struct_schedulecancelaction', 0x4458150, 0x4458169, 'action-wire struct ScheduleCancelAction expecting (0x4458150)'),
    ('action-wire', 'action_wire_expecting_struct_usdclasstransferaction', 0x445cea0, 0x445ceb9, 'action-wire struct UsdClassTransferAction expecting (0x445cea0)'),
    ('action-wire', 'action_wire_expecting_struct_approvebuilderfeeaction', 0x445f500, 0x445f519, 'action-wire struct ApproveBuilderFeeAction expecting (0x445f500)'),
    ('action-wire', 'action_wire_expecting_struct_usersetabstractionaction', 0x4461350, 0x4461369, 'action-wire struct UserSetAbstractionAction expecting (0x4461350)'),
    ('action-wire', 'action_wire_expecting_struct_converttomultisiguseraction', 0x4464a90, 0x4464aa9, 'action-wire struct ConvertToMultiSigUserAction expecting (0x4464a90)'),
    ('action-wire', 'action_wire_expecting_struct_twapcancelaction', 0x4684830, 0x4684849, 'action-wire struct TwapCancelAction expecting (0x4684830)'),
    ('action-wire', 'action_wire_expecting_struct_cancelbycloidaction', 0x46929b0, 0x46929c9, 'action-wire struct CancelByCloidAction expecting (0x46929b0)'),
    ('action-wire', 'action_wire_expecting_struct_setdisplaynameaction', 0x4692c40, 0x4692c59, 'action-wire struct SetDisplayNameAction expecting (0x4692c40)'),
    ('action-wire', 'action_wire_expecting_struct_cancelaction', 0x51ad4f0, 0x51ad509, 'action-wire struct CancelAction expecting (0x51ad4f0)'),
    ('action-wire', 'action_wire_expecting_struct_batchmodifyaction', 0x51ad7c0, 0x51ad7d9, 'action-wire struct BatchModifyAction expecting (0x51ad7c0)'),
    ('action-wire', 'action_wire_expecting_struct_cancelbycloidaction', 0x51adc30, 0x51adc49, 'action-wire struct CancelByCloidAction expecting (0x51adc30)'),
    ('action-wire', 'action_wire_expecting_struct_updateisolatedmarginaction', 0x51adcd0, 0x51adce9, 'action-wire struct UpdateIsolatedMarginAction expecting (0x51adcd0)'),
    ('action-wire', 'action_wire_expecting_struct_modifyaction', 0x51add10, 0x51add29, 'action-wire struct ModifyAction expecting (0x51add10)'),
    ('action-wire', 'action_wire_expecting_struct_setreferreraction', 0x53d5a30, 0x53d5a49, 'action-wire struct SetReferrerAction expecting (0x53d5a30)'),
    ('action-wire', 'action_wire_expecting_struct_schedulecancelaction', 0x53d5bd0, 0x53d5be9, 'action-wire struct ScheduleCancelAction expecting (0x53d5bd0)'),
    ('action-wire', 'action_wire_expecting_struct_twapcancelaction', 0x53d5c70, 0x53d5c89, 'action-wire struct TwapCancelAction expecting (0x53d5c70)'),
    ('action-wire', 'action_wire_expecting_struct_twaporderaction', 0x53d6470, 0x53d6489, 'action-wire struct TwapOrderAction expecting (0x53d6470)'),
    ('action-wire', 'action_wire_expecting_struct_setdisplaynameaction', 0x53d6570, 0x53d6589, 'action-wire struct SetDisplayNameAction expecting (0x53d6570)'),
    ('action-wire', 'action_wire_expecting_struct_usersetabstractionaction', 0x53d6a90, 0x53d6aa9, 'action-wire struct UserSetAbstractionAction expecting (0x53d6a90)'),
    ('action-wire', 'action_wire_expecting_struct_orderaction', 0x5941e10, 0x5941e29, 'action-wire struct OrderAction expecting (0x5941e10)'),
    ('action-wire', 'action_wire_expecting_struct_approvebuilderfeeaction', 0x5941e50, 0x5941e69, 'action-wire struct ApproveBuilderFeeAction expecting (0x5941e50)'),
    ('action-wire', 'action_wire_expecting_struct_usdclasstransferaction', 0x5941f90, 0x5941fa9, 'action-wire struct UsdClassTransferAction expecting (0x5941f90)'),
    ('action-wire', 'action_wire_expecting_struct_sendassetaction', 0x59420f0, 0x5942109, 'action-wire struct SendAssetAction expecting (0x59420f0)'),
    ('action-wire', 'action_wire_expecting_struct_usdsendaction', 0x5942310, 0x5942329, 'action-wire struct UsdSendAction expecting (0x5942310)'),
    ('action-wire', 'action_wire_expecting_struct_converttomultisiguseraction', 0x59423b0, 0x59423c9, 'action-wire struct ConvertToMultiSigUserAction expecting (0x59423b0)'),
    ('action-wire', 'action_wire_expecting_struct_withdrawaction3', 0x59425f0, 0x5942609, 'action-wire struct WithdrawAction3 expecting (0x59425f0)'),
    ('action-wire', 'action_wire_expecting_struct_spotsendaction', 0x5942690, 0x59426a9, 'action-wire struct SpotSendAction expecting (0x5942690)'),
    ('action-wire', 'action_wire_expecting_struct_reserverequestweightaction', 0x59426d0, 0x59426e9, 'action-wire struct ReserveRequestWeightAction expecting (0x59426d0)'),
    ('dex-registry', 'dex_registry_expecting_struct_hip3backstopliquidatorstate', 0x2773950, 0x2773969, 'dex-registry struct Hip3BackstopLiquidatorState expecting (0x2773950)'),
    ('dex-registry', 'dex_registry_expecting_struct_hip3schemainput', 0x292ced0, 0x292cee9, 'dex-registry struct Hip3SchemaInput expecting (0x292ced0)'),
    ('dex-registry', 'dex_registry_expecting_struct_perpdex', 0x292d7d0, 0x292d7e9, 'dex-registry struct PerpDex expecting (0x292d7d0)'),
    ('dex-registry', 'dex_registry_expecting_tuple_struct_perpdexs', 0x292d8f0, 0x292d909, 'dex-registry tuple struct PerpDexs expecting (0x292d8f0)'),
    ('dex-registry', 'dex_registry_expecting_struct_variant_mainorhip3_main', 0x2c7cc40, 0x2c7cc59, 'dex-registry struct variant MainOrHip3::Main expecting (0x2c7cc40)'),
    ('dex-registry', 'dex_registry_expecting_enum_mainorhip3', 0x2c7ce10, 0x2c7ce29, 'dex-registry enum MainOrHip3 expecting (0x2c7ce10)'),
    ('dex-registry', 'dex_registry_expecting_struct_hip3deployerfeestate', 0x2c7ce50, 0x2c7ce69, 'dex-registry struct Hip3DeployerFeeState expecting (0x2c7ce50)'),
    ('dex-registry', 'dex_registry_expecting_struct_hip3deployerfee', 0x2c7ced0, 0x2c7cee9, 'dex-registry struct Hip3DeployerFee expecting (0x2c7ced0)'),
    ('dex-registry', 'dex_registry_expecting_struct_hip3backstopliquidatorparams', 0x2c7cf90, 0x2c7cfa9, 'dex-registry struct Hip3BackstopLiquidatorParams expecting (0x2c7cf90)'),
    ('dex-registry', 'dex_registry_expecting_struct_hip3limits', 0x2c7cff0, 0x2c7d009, 'dex-registry struct Hip3Limits expecting (0x2c7cff0)'),
    ('dex-registry', 'dex_registry_expecting_struct_hip3state', 0x2c7d030, 0x2c7d049, 'dex-registry struct Hip3State expecting (0x2c7d030)'),
    ('dex-registry', 'dex_registry_expecting_struct_variant_mainorhip3_hip3', 0x2c7d0b0, 0x2c7d0c9, 'dex-registry struct variant MainOrHip3::Hip3 expecting (0x2c7d0b0)'),
    ('dex-registry', 'dex_registry_expecting_struct_hip3schemainput', 0x36647f0, 0x3664809, 'dex-registry struct Hip3SchemaInput expecting (0x36647f0)'),
    ('dex-registry', 'dex_registry_expecting_struct_perpdex', 0x4228f70, 0x4228f89, 'dex-registry struct PerpDex expecting (0x4228f70)'),
    ('dex-registry', 'dex_registry_expecting_tuple_struct_perpdexs', 0x4229060, 0x4229079, 'dex-registry tuple struct PerpDexs expecting (0x4229060)'),
    ('dex-registry', 'dex_registry_expecting_struct_hip3backstopliquidatorstate', 0x4351400, 0x4351419, 'dex-registry struct Hip3BackstopLiquidatorState expecting (0x4351400)'),
    ('dex-registry', 'dex_registry_expecting_struct_hip3state', 0x44dc230, 0x44dc249, 'dex-registry struct Hip3State expecting (0x44dc230)'),
    ('dex-registry', 'dex_registry_expecting_struct_hip3limits', 0x44dc2f0, 0x44dc309, 'dex-registry struct Hip3Limits expecting (0x44dc2f0)'),
    ('dex-registry', 'dex_registry_expecting_struct_variant_mainorhip3_main', 0x44dc330, 0x44dc349, 'dex-registry struct variant MainOrHip3::Main expecting (0x44dc330)'),
    ('dex-registry', 'dex_registry_expecting_struct_hip3deployerfeestate', 0x44dc550, 0x44dc569, 'dex-registry struct Hip3DeployerFeeState expecting (0x44dc550)'),
    ('dex-registry', 'dex_registry_expecting_struct_hip3backstopliquidatorparams', 0x44dc610, 0x44dc629, 'dex-registry struct Hip3BackstopLiquidatorParams expecting (0x44dc610)'),
    ('dex-registry', 'dex_registry_expecting_enum_mainorhip3', 0x44dc970, 0x44dc989, 'dex-registry enum MainOrHip3 expecting (0x44dc970)'),
    ('dex-registry', 'dex_registry_expecting_struct_variant_mainorhip3_hip3', 0x44dcc30, 0x44dcc49, 'dex-registry struct variant MainOrHip3::Hip3 expecting (0x44dcc30)'),
    ('dex-registry', 'dex_registry_expecting_struct_hip3deployerfee', 0x44dcd30, 0x44dcd49, 'dex-registry struct Hip3DeployerFee expecting (0x44dcd30)'),
    ('dex-registry', 'dex_registry_expecting_struct_hip3schemainput', 0x51adb70, 0x51adb89, 'dex-registry struct Hip3SchemaInput expecting (0x51adb70)'),
    ('dex-registry', 'dex_registry_expecting_struct_perpdex', 0x53d57f0, 0x53d5809, 'dex-registry struct PerpDex expecting (0x53d57f0)'),
    ('dex-registry', 'dex_registry_expecting_tuple_struct_perpdexs', 0x53d5e90, 0x53d5ea9, 'dex-registry tuple struct PerpDexs expecting (0x53d5e90)'),
    ('dex-registry', 'dex_registry_expecting_struct_hip3backstopliquidatorstate', 0x53d6050, 0x53d6069, 'dex-registry struct Hip3BackstopLiquidatorState expecting (0x53d6050)'),
    ('dex-registry', 'dex_registry_expecting_struct_hip3state', 0x5616710, 0x5616729, 'dex-registry struct Hip3State expecting (0x5616710)'),
    ('dex-registry', 'dex_registry_expecting_struct_hip3backstopliquidatorparams', 0x56167b0, 0x56167c9, 'dex-registry struct Hip3BackstopLiquidatorParams expecting (0x56167b0)'),
    ('dex-registry', 'dex_registry_expecting_struct_variant_mainorhip3_main', 0x56168b0, 0x56168c9, 'dex-registry struct variant MainOrHip3::Main expecting (0x56168b0)'),
    ('dex-registry', 'dex_registry_expecting_struct_hip3deployerfee', 0x56169b0, 0x56169c9, 'dex-registry struct Hip3DeployerFee expecting (0x56169b0)'),
    ('dex-registry', 'dex_registry_expecting_enum_mainorhip3', 0x5616a50, 0x5616a69, 'dex-registry enum MainOrHip3 expecting (0x5616a50)'),
    ('dex-registry', 'dex_registry_expecting_struct_hip3limits', 0x5616b10, 0x5616b29, 'dex-registry struct Hip3Limits expecting (0x5616b10)'),
    ('dex-registry', 'dex_registry_expecting_struct_hip3deployerfeestate', 0x5616bd0, 0x5616be9, 'dex-registry struct Hip3DeployerFeeState expecting (0x5616bd0)'),
    ('dex-registry', 'dex_registry_expecting_struct_variant_mainorhip3_hip3', 0x5616db0, 0x5616dc9, 'dex-registry struct variant MainOrHip3::Hip3 expecting (0x5616db0)'),
    ('exchange', 'exchange_expecting_struct_abstractioncounters', 0x2420450, 0x2420469, 'exchange struct AbstractionCounters expecting (0x2420450)'),
    ('exchange', 'exchange_expecting_enum_userabstraction', 0x2420610, 0x2420629, 'exchange enum UserAbstraction expecting (0x2420610)'),
    ('exchange', 'exchange_expecting_enum_abstractionreturn', 0x24209c0, 0x24209d9, 'exchange enum AbstractionReturn expecting (0x24209c0)'),
    ('exchange', 'exchange_expecting_tuple_struct_abstractionreturns', 0x2773a90, 0x2773aa9, 'exchange tuple struct AbstractionReturns expecting (0x2773a90)'),
    ('exchange', 'exchange_expecting_struct_exchange', 0x2c7d1f0, 0x2c7d209, 'exchange struct Exchange expecting (0x2c7d1f0)'),
    ('exchange', 'exchange_expecting_struct_exchangemisc', 0x2c7d350, 0x2c7d369, 'exchange struct ExchangeMisc expecting (0x2c7d350)'),
    ('exchange', 'exchange_expecting_struct_exchangecounters', 0x2c7d490, 0x2c7d4a9, 'exchange struct ExchangeCounters expecting (0x2c7d490)'),
    ('exchange', 'exchange_expecting_struct_exchangemisc', 0x3c4d030, 0x3c4d049, 'exchange struct ExchangeMisc expecting (0x3c4d030)'),
    ('exchange', 'exchange_expecting_struct_exchangecounters', 0x3c4d2d0, 0x3c4d2e9, 'exchange struct ExchangeCounters expecting (0x3c4d2d0)'),
    ('exchange', 'exchange_expecting_enum_abstractionreturn', 0x3c4d550, 0x3c4d569, 'exchange enum AbstractionReturn expecting (0x3c4d550)'),
    ('exchange', 'exchange_expecting_enum_userabstraction', 0x3c4d770, 0x3c4d789, 'exchange enum UserAbstraction expecting (0x3c4d770)'),
    ('exchange', 'exchange_expecting_struct_exchange', 0x3c4d850, 0x3c4d869, 'exchange struct Exchange expecting (0x3c4d850)'),
    ('exchange', 'exchange_expecting_struct_abstractioncounters', 0x3c4d870, 0x3c4d889, 'exchange struct AbstractionCounters expecting (0x3c4d870)'),
    ('exchange', 'exchange_expecting_tuple_struct_abstractionreturns', 0x44dc690, 0x44dc6a9, 'exchange tuple struct AbstractionReturns expecting (0x44dc690)'),
    ('exchange', 'exchange_expecting_struct_abstractioncounters', 0x4d9c020, 0x4d9c039, 'exchange struct AbstractionCounters expecting (0x4d9c020)'),
    ('exchange', 'exchange_expecting_enum_userabstraction', 0x4d9c210, 0x4d9c229, 'exchange enum UserAbstraction expecting (0x4d9c210)'),
    ('exchange', 'exchange_expecting_enum_abstractionreturn', 0x4d9c310, 0x4d9c329, 'exchange enum AbstractionReturn expecting (0x4d9c310)'),
    ('exchange', 'exchange_expecting_struct_exchangemisc', 0x56164b0, 0x56164c9, 'exchange struct ExchangeMisc expecting (0x56164b0)'),
    ('exchange', 'exchange_expecting_struct_exchange', 0x5616950, 0x5616969, 'exchange struct Exchange expecting (0x5616950)'),
    ('exchange', 'exchange_expecting_struct_exchangecounters', 0x5616d10, 0x5616d29, 'exchange struct ExchangeCounters expecting (0x5616d10)'),
    ('exchange', 'exchange_expecting_tuple_struct_abstractionreturns', 0x5b096d0, 0x5b096e9, 'exchange tuple struct AbstractionReturns expecting (0x5b096d0)'),
    ('l1-shared', 'l1_shared_expecting_tuple_struct_noncesetde', 0x292d210, 0x292d229, 'l1-shared tuple struct NonceSetDe expecting (0x292d210)'),
    ('l1-shared', 'l1_shared_expecting_tuple_struct_fpdecimal', 0x2c7d010, 0x2c7d029, 'l1-shared tuple struct FpDecimal expecting (0x2c7d010)'),
    ('l1-shared', 'l1_shared_expecting_struct_hyperliquidity', 0x2d4a550, 0x2d4a569, 'l1-shared struct Hyperliquidity expecting (0x2d4a550)'),
    ('l1-shared', 'l1_shared_expecting_struct_hyperliquidity', 0x38db740, 0x38db759, 'l1-shared struct Hyperliquidity expecting (0x38db740)'),
    ('l1-shared', 'l1_shared_expecting_tuple_struct_fpdecimal', 0x4229420, 0x4229439, 'l1-shared tuple struct FpDecimal expecting (0x4229420)'),
    ('l1-shared', 'l1_shared_expecting_tuple_struct_noncesetde', 0x4229930, 0x4229949, 'l1-shared tuple struct NonceSetDe expecting (0x4229930)'),
    ('l1-shared', 'l1_shared_expecting_struct_hyperliquidity', 0x51add50, 0x51add69, 'l1-shared struct Hyperliquidity expecting (0x51add50)'),
    ('l1-shared', 'l1_shared_expecting_tuple_struct_fpdecimal', 0x53d6250, 0x53d6269, 'l1-shared tuple struct FpDecimal expecting (0x53d6250)'),
    ('l1-shared', 'l1_shared_expecting_tuple_struct_noncesetde', 0x5b08df0, 0x5b08e09, 'l1-shared tuple struct NonceSetDe expecting (0x5b08df0)'),
    ('risk', 'risk_expecting_tuple_struct_oraclekindmap', 0x22f5ae0, 0x22f5af9, 'risk tuple struct OracleKindMap expecting (0x22f5ae0)'),
    ('risk', 'risk_expecting_enum_oraclekind', 0x22f5b60, 0x22f5b79, 'risk enum OracleKind expecting (0x22f5b60)'),
    ('risk', 'risk_expecting_struct_spotclearinghouse', 0x22f5ba0, 0x22f5bb9, 'risk struct SpotClearinghouse expecting (0x22f5ba0)'),
    ('risk', 'risk_expecting_struct_liquidationcounters', 0x2420040, 0x2420059, 'risk struct LiquidationCounters expecting (0x2420040)'),
    ('risk', 'risk_expecting_struct_positionmap', 0x2420180, 0x2420199, 'risk struct PositionMap expecting (0x2420180)'),
    ('risk', 'risk_expecting_struct_userstateserde', 0x2420530, 0x2420549, 'risk struct UserStateSerde expecting (0x2420530)'),
    ('risk', 'risk_expecting_struct_userstate', 0x2420ac0, 0x2420ad9, 'risk struct UserState expecting (0x2420ac0)'),
    ('risk', 'risk_expecting_tuple_struct_outcomedeployer', 0x24a7e50, 0x24a7e69, 'risk tuple struct OutcomeDeployer expecting (0x24a7e50)'),
    ('risk', 'risk_expecting_tuple_struct_boletoken', 0x25eb430, 0x25eb449, 'risk tuple struct BoleToken expecting (0x25eb430)'),
    ('risk', 'risk_expecting_enum_referenceoraclekey', 0x25eb510, 0x25eb529, 'risk enum ReferenceOracleKey expecting (0x25eb510)'),
    ('risk', 'risk_expecting_enum_leverage', 0x25eb590, 0x25eb5a9, 'risk enum Leverage expecting (0x25eb590)'),
    ('risk', 'risk_expecting_tuple_struct_rawleverage', 0x25ebab0, 0x25ebac9, 'risk tuple struct RawLeverage expecting (0x25ebab0)'),
    ('risk', 'risk_expecting_struct_clearinghouse', 0x2773db0, 0x2773dc9, 'risk struct Clearinghouse expecting (0x2773db0)'),
    ('risk', 'risk_expecting_struct_userstate', 0x2773ed0, 0x2773ee9, 'risk struct UserState expecting (0x2773ed0)'),
    ('risk', 'risk_expecting_struct_userstate', 0x292cd10, 0x292cd29, 'risk struct UserState expecting (0x292cd10)'),
    ('risk', 'risk_expecting_struct_userstate', 0x292d390, 0x292d3a9, 'risk struct UserState expecting (0x292d390)'),
    ('risk', 'risk_expecting_struct_userstate', 0x2c7cd20, 0x2c7cd39, 'risk struct UserState expecting (0x2c7cd20)'),
    ('risk', 'risk_expecting_struct_userstate', 0x2c7d0d0, 0x2c7d0e9, 'risk struct UserState expecting (0x2c7d0d0)'),
    ('risk', 'risk_expecting_enum_referenceoraclekey', 0x36cd030, 0x36cd049, 'risk enum ReferenceOracleKey expecting (0x36cd030)'),
    ('risk', 'risk_expecting_struct_userstate', 0x36cd4b0, 0x36cd4c9, 'risk struct UserState expecting (0x36cd4b0)'),
    ('risk', 'risk_expecting_struct_userstateserde', 0x38db6e0, 0x38db6f9, 'risk struct UserStateSerde expecting (0x38db6e0)'),
    ('risk', 'risk_expecting_struct_liquidationcounters', 0x3c4d110, 0x3c4d129, 'risk struct LiquidationCounters expecting (0x3c4d110)'),
    ('risk', 'risk_expecting_struct_userstate', 0x3c4d170, 0x3c4d189, 'risk struct UserState expecting (0x3c4d170)'),
    ('risk', 'risk_expecting_struct_spotclearinghouse', 0x3c4d2f0, 0x3c4d309, 'risk struct SpotClearinghouse expecting (0x3c4d2f0)'),
    ('risk', 'risk_expecting_tuple_struct_oraclekindmap', 0x3d527d0, 0x3d527e9, 'risk tuple struct OracleKindMap expecting (0x3d527d0)'),
    ('risk', 'risk_expecting_enum_oraclekind', 0x3d52920, 0x3d52939, 'risk enum OracleKind expecting (0x3d52920)'),
    ('risk', 'risk_expecting_tuple_struct_outcomedeployer', 0x42290c0, 0x42290d9, 'risk tuple struct OutcomeDeployer expecting (0x42290c0)'),
    ('risk', 'risk_expecting_enum_leverage', 0x4229220, 0x4229239, 'risk enum Leverage expecting (0x4229220)'),
    ('risk', 'risk_expecting_struct_userstate', 0x42294e0, 0x42294f9, 'risk struct UserState expecting (0x42294e0)'),
    ('risk', 'risk_expecting_tuple_struct_boletoken', 0x4229520, 0x4229539, 'risk tuple struct BoleToken expecting (0x4229520)'),
    ('risk', 'risk_expecting_tuple_struct_rawleverage', 0x42295f0, 0x4229609, 'risk tuple struct RawLeverage expecting (0x42295f0)'),
    ('risk', 'risk_expecting_struct_positionmap', 0x42298f0, 0x4229909, 'risk struct PositionMap expecting (0x42298f0)'),
    ('risk', 'risk_expecting_struct_clearinghouse', 0x44dc310, 0x44dc329, 'risk struct Clearinghouse expecting (0x44dc310)'),
    ('risk', 'risk_expecting_struct_userstate', 0x44dc950, 0x44dc969, 'risk struct UserState expecting (0x44dc950)'),
    ('risk', 'risk_expecting_struct_userstate', 0x4d9bec0, 0x4d9bed9, 'risk struct UserState expecting (0x4d9bec0)'),
    ('risk', 'risk_expecting_struct_liquidationcounters', 0x4d9bf00, 0x4d9bf19, 'risk struct LiquidationCounters expecting (0x4d9bf00)'),
    ('risk', 'risk_expecting_struct_userstate', 0x4d9c610, 0x4d9c629, 'risk struct UserState expecting (0x4d9c610)'),
    ('risk', 'risk_expecting_tuple_struct_boletoken', 0x4d9c8e0, 0x4d9c8f9, 'risk tuple struct BoleToken expecting (0x4d9c8e0)'),
    ('risk', 'risk_expecting_enum_referenceoraclekey', 0x50d9640, 0x50d9659, 'risk enum ReferenceOracleKey expecting (0x50d9640)'),
    ('risk', 'risk_expecting_struct_positionmap', 0x51ad6e0, 0x51ad6f9, 'risk struct PositionMap expecting (0x51ad6e0)'),
    ('risk', 'risk_expecting_tuple_struct_outcomedeployer', 0x53d5c10, 0x53d5c29, 'risk tuple struct OutcomeDeployer expecting (0x53d5c10)'),
    ('risk', 'risk_expecting_tuple_struct_oraclekindmap', 0x53d5f10, 0x53d5f29, 'risk tuple struct OracleKindMap expecting (0x53d5f10)'),
    ('risk', 'risk_expecting_enum_oraclekind', 0x53d6070, 0x53d6089, 'risk enum OracleKind expecting (0x53d6070)'),
    ('risk', 'risk_expecting_struct_userstate', 0x56167f0, 0x5616809, 'risk struct UserState expecting (0x56167f0)'),
    ('risk', 'risk_expecting_struct_userstate', 0x56168d0, 0x56168e9, 'risk struct UserState expecting (0x56168d0)'),
    ('risk', 'risk_expecting_struct_userstate', 0x5616990, 0x56169a9, 'risk struct UserState expecting (0x5616990)'),
    ('risk', 'risk_expecting_struct_userstateserde', 0x5942010, 0x5942029, 'risk struct UserStateSerde expecting (0x5942010)'),
    ('risk', 'risk_expecting_struct_clearinghouse', 0x5b09070, 0x5b09089, 'risk struct Clearinghouse expecting (0x5b09070)'),
    ('risk', 'risk_expecting_tuple_struct_rawleverage', 0x5b09210, 0x5b09229, 'risk tuple struct RawLeverage expecting (0x5b09210)'),
    ('risk', 'risk_expecting_struct_spotclearinghouse', 0x5b096b0, 0x5b096c9, 'risk struct SpotClearinghouse expecting (0x5b096b0)'),
    ('risk', 'risk_expecting_enum_leverage', 0x5b097d0, 0x5b097e9, 'risk enum Leverage expecting (0x5b097d0)'),
    ('vaults', 'vaults_expecting_struct_subaccounttransferaction', 0x24209e0, 0x24209f9, 'vaults struct SubAccountTransferAction expecting (0x24209e0)'),
    ('vaults', 'vaults_expecting_struct_relationships', 0x25eb8a0, 0x25eb8b9, 'vaults struct Relationships expecting (0x25eb8a0)'),
    ('vaults', 'vaults_expecting_struct_subaccounttracker', 0x2773170, 0x2773189, 'vaults struct SubAccountTracker expecting (0x2773170)'),
    ('vaults', 'vaults_expecting_struct_netchildvaultpositionsaction', 0x2773650, 0x2773669, 'vaults struct NetChildVaultPositionsAction expecting (0x2773650)'),
    ('vaults', 'vaults_expecting_struct_parentvaultstate', 0x2773850, 0x2773869, 'vaults struct ParentVaultState expecting (0x2773850)'),
    ('vaults', 'vaults_expecting_struct_subaccount', 0x2773af0, 0x2773b09, 'vaults struct SubAccount expecting (0x2773af0)'),
    ('vaults', 'vaults_expecting_struct_createvaultaction', 0x292c8f0, 0x292c909, 'vaults struct CreateVaultAction expecting (0x292c8f0)'),
    ('vaults', 'vaults_expecting_struct_subaccountspottransferaction', 0x292ca30, 0x292ca49, 'vaults struct SubAccountSpotTransferAction expecting (0x292ca30)'),
    ('vaults', 'vaults_expecting_struct_vault', 0x292cf30, 0x292cf49, 'vaults struct Vault expecting (0x292cf30)'),
    ('vaults', 'vaults_expecting_enum_vaultspotmode', 0x292cfd0, 0x292cfe9, 'vaults enum VaultSpotMode expecting (0x292cfd0)'),
    ('vaults', 'vaults_expecting_struct_vaultmodifyaction', 0x292d090, 0x292d0a9, 'vaults struct VaultModifyAction expecting (0x292d090)'),
    ('vaults', 'vaults_expecting_struct_vaulttransferaction', 0x292d910, 0x292d929, 'vaults struct VaultTransferAction expecting (0x292d910)'),
    ('vaults', 'vaults_expecting_struct_createsubaccountaction', 0x292db90, 0x292dba9, 'vaults struct CreateSubAccountAction expecting (0x292db90)'),
    ('vaults', 'vaults_expecting_struct_vaultdistributeaction', 0x292dd90, 0x292dda9, 'vaults struct VaultDistributeAction expecting (0x292dd90)'),
    ('vaults', 'vaults_expecting_struct_parentvaultstate', 0x36cced0, 0x36ccee9, 'vaults struct ParentVaultState expecting (0x36cced0)'),
    ('vaults', 'vaults_expecting_struct_subaccounttracker', 0x36ccf50, 0x36ccf69, 'vaults struct SubAccountTracker expecting (0x36ccf50)'),
    ('vaults', 'vaults_expecting_struct_subaccount', 0x36cd310, 0x36cd329, 'vaults struct SubAccount expecting (0x36cd310)'),
    ('vaults', 'vaults_expecting_struct_vaultmodifyaction', 0x4454be0, 0x4454bf9, 'vaults struct VaultModifyAction expecting (0x4454be0)'),
    ('vaults', 'vaults_expecting_struct_vaulttransferaction', 0x4456370, 0x4456389, 'vaults struct VaultTransferAction expecting (0x4456370)'),
    ('vaults', 'vaults_expecting_struct_vaultdistributeaction', 0x4459ff0, 0x445a009, 'vaults struct VaultDistributeAction expecting (0x4459ff0)'),
    ('vaults', 'vaults_expecting_struct_vault', 0x44dc830, 0x44dc849, 'vaults struct Vault expecting (0x44dc830)'),
    ('vaults', 'vaults_expecting_struct_relationships', 0x44dca90, 0x44dcaa9, 'vaults struct Relationships expecting (0x44dca90)'),
    ('vaults', 'vaults_expecting_enum_vaultspotmode', 0x44dcb70, 0x44dcb89, 'vaults enum VaultSpotMode expecting (0x44dcb70)'),
    ('vaults', 'vaults_expecting_struct_createvaultaction', 0x468cdf0, 0x468ce09, 'vaults struct CreateVaultAction expecting (0x468cdf0)'),
    ('vaults', 'vaults_expecting_struct_createsubaccountaction', 0x46955f0, 0x4695609, 'vaults struct CreateSubAccountAction expecting (0x46955f0)'),
    ('vaults', 'vaults_expecting_struct_subaccounttransferaction', 0x4695d40, 0x4695d59, 'vaults struct SubAccountTransferAction expecting (0x4695d40)'),
    ('vaults', 'vaults_expecting_struct_netchildvaultpositionsaction', 0x46976f0, 0x4697709, 'vaults struct NetChildVaultPositionsAction expecting (0x46976f0)'),
    ('vaults', 'vaults_expecting_struct_subaccountspottransferaction', 0x4697710, 0x4697729, 'vaults struct SubAccountSpotTransferAction expecting (0x4697710)'),
    ('vaults', 'vaults_expecting_struct_subaccount', 0x4d9bf60, 0x4d9bf79, 'vaults struct SubAccount expecting (0x4d9bf60)'),
    ('vaults', 'vaults_expecting_enum_vaultspotmode', 0x4d9c4f0, 0x4d9c509, 'vaults enum VaultSpotMode expecting (0x4d9c4f0)'),
    ('vaults', 'vaults_expecting_struct_subaccounttracker', 0x4d9c590, 0x4d9c5a9, 'vaults struct SubAccountTracker expecting (0x4d9c590)'),
    ('vaults', 'vaults_expecting_struct_vault', 0x4d9c670, 0x4d9c689, 'vaults struct Vault expecting (0x4d9c670)'),
    ('vaults', 'vaults_expecting_struct_relationships', 0x51adb90, 0x51adba9, 'vaults struct Relationships expecting (0x51adb90)'),
    ('vaults', 'vaults_expecting_struct_subaccounttransferaction', 0x53d59b0, 0x53d59c9, 'vaults struct SubAccountTransferAction expecting (0x53d59b0)'),
    ('vaults', 'vaults_expecting_struct_subaccountspottransferaction', 0x53d5e30, 0x53d5e49, 'vaults struct SubAccountSpotTransferAction expecting (0x53d5e30)'),
    ('vaults', 'vaults_expecting_struct_vaultdistributeaction', 0x53d5f90, 0x53d5fa9, 'vaults struct VaultDistributeAction expecting (0x53d5f90)'),
    ('vaults', 'vaults_expecting_struct_vaultmodifyaction', 0x53d61d0, 0x53d61e9, 'vaults struct VaultModifyAction expecting (0x53d61d0)'),
    ('vaults', 'vaults_expecting_struct_vaulttransferaction', 0x53d66b0, 0x53d66c9, 'vaults struct VaultTransferAction expecting (0x53d66b0)'),
    ('vaults', 'vaults_expecting_struct_createvaultaction', 0x53d6770, 0x53d6789, 'vaults struct CreateVaultAction expecting (0x53d6770)'),
    ('vaults', 'vaults_expecting_struct_createsubaccountaction', 0x53d67f0, 0x53d6809, 'vaults struct CreateSubAccountAction expecting (0x53d67f0)'),
    ('vaults', 'vaults_expecting_struct_netchildvaultpositionsaction', 0x53d6930, 0x53d6949, 'vaults struct NetChildVaultPositionsAction expecting (0x53d6930)'),
    ('vaults', 'vaults_expecting_struct_parentvaultstate', 0x5b08f90, 0x5b08fa9, 'vaults struct ParentVaultState expecting (0x5b08f90)'),
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
    rustc_ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    with tempfile.TemporaryDirectory() as td:
        obj_path = Path(td) / "stream_e2_byte_matches.o"
        subprocess.check_call(
            [
                "rustc",
                "+1.95.0",
                "--edition=2021",
                "--crate-type=rlib",
                "--crate-name=node115_stream_e2_byte_matches",
                "-C",
                "opt-level=3",
                "-C",
                "overflow-checks=yes",
                "--emit=obj",
                "-o",
                str(obj_path),
                str(SOURCE_PATH),
            ]
        )
        return obj_path.read_bytes(), rustc_ver


def extract_compiled_funcs(obj_bytes: bytes) -> dict[str, tuple[bytes, list[int]]]:
    secs = parse_elf_sections(obj_bytes)
    rel_by_sec: dict[int, list[int]] = {}
    for _i, _name, st, _addr, soff, ssz, _link, sinfo in secs:
        if st == 4:
            offs = []
            for j in range(0, ssz, 24):
                r_off = struct.unpack_from("<Q", obj_bytes, soff + j)[0]
                offs.append(r_off)
            rel_by_sec[sinfo] = offs
    funcs: dict[str, tuple[bytes, list[int]]] = {}
    for i, name, st, _addr, soff, ssz, _link, _sinfo in secs:
        if st == 1 and name.startswith(".text."):
            funcs[name] = (obj_bytes[soff : soff + ssz], rel_by_sec.get(i, []))
    return funcs


def build_records(binary_bytes: bytes, obj_bytes: bytes, rustc_ver: str) -> dict:
    secs = {name: (sa, so, sz) for _i, name, _st, sa, so, sz, _l, _in in parse_elf_sections(binary_bytes)}
    text_sa, text_so, _text_sz = secs[".text"]
    fdes = load_fde_map()
    compiled = extract_compiled_funcs(obj_bytes)

    by_comp: dict[str, dict[str, int]] = {}
    rows = []
    total_bytes = 0
    total_raw_equal = 0
    for comp, sym, start_va, end_va, label in WINDOWS:
        if fdes.get(start_va) != end_va:
            raise AssertionError(f"FDE mismatch for {hex(start_va)}: expected {hex(end_va)}, got {fdes.get(start_va)}")
        matches = [k for k in compiled if f"{len(sym)}{sym}" in k]
        if len(matches) != 1:
            raise AssertionError(f"Expected 1 compiled section for {sym}, got {matches}")
        got_bytes, rel_offs = compiled[matches[0]]
        size = end_va - start_va
        if len(got_bytes) != size:
            raise AssertionError(f"Size mismatch for {sym}: compiled {len(got_bytes)} vs target {size}")
        off = text_so + (start_va - text_sa)
        want_bytes = binary_bytes[off : off + size]
        mask = bytearray([1] * size)
        for roff in rel_offs:
            for b in range(roff, min(roff + 4, size)):
                mask[b] = 0
        mismatches = [idx for idx, (a, b, m) in enumerate(zip(got_bytes, want_bytes, mask)) if m and a != b]
        if mismatches:
            raise AssertionError(f"Non-relocation mismatch in {sym} @ {hex(start_va)}: {mismatches}")
        raw_eq = sum(1 for a, b in zip(got_bytes, want_bytes) if a == b)
        total_bytes += size
        total_raw_equal += raw_eq
        by_comp.setdefault(comp, {"windows": 0, "bytes": 0, "raw_equal": 0})
        by_comp[comp]["windows"] += 1
        by_comp[comp]["bytes"] += size
        by_comp[comp]["raw_equal"] += raw_eq
        rows.append(
            {
                "component": comp,
                "symbol": sym,
                "start_va": hex(start_va),
                "end_va": hex(end_va),
                "size": size,
                "raw_equal": raw_eq,
                "relocations": rel_offs,
                "target_sha256": hashlib.sha256(want_bytes).hexdigest(),
                "label": label,
            }
        )
    return {
        "work_item": "RE-007-node115-stream-e2-byte-matches",
        "target_release": "node-115",
        "target_path": "artifacts/node/115/hl-node",
        "target_sha256": hashlib.sha256(binary_bytes).hexdigest(),
        "target_size": len(binary_bytes),
        "rustc_version": rustc_ver,
        "summary": {
            "total_windows": len(rows),
            "total_bytes": total_bytes,
            "total_raw_equal": total_raw_equal,
            "by_component": by_comp,
        },
        "windows": rows,
    }


def verify_records(records: dict, binary_bytes: bytes, obj_bytes: bytes, rustc_ver: str) -> None:
    if records["target_sha256"] != EXPECTED_BINARY_SHA256:
        raise AssertionError("target_sha256 mismatch")
    if records["target_size"] != EXPECTED_BINARY_SIZE:
        raise AssertionError("target_size mismatch")
    rebuilt = build_records(binary_bytes, obj_bytes, rustc_ver)
    if records["windows"] != rebuilt["windows"] or records["summary"] != rebuilt["summary"]:
        raise AssertionError("rebuilt windows/summary mismatch against records.json")


def run_negative_controls(records: dict, binary_bytes: bytes, obj_bytes: bytes, rustc_ver: str) -> int:
    caught = 0
    # 1. Corrupt target_sha256
    r1 = copy.deepcopy(records)
    r1["target_sha256"] = "0" * 64
    try:
        verify_records(r1, binary_bytes, obj_bytes, rustc_ver)
        raise RuntimeError("failed to reject bad target_sha256")
    except AssertionError:
        caught += 1
    # 2. Corrupt window target_sha256
    r2 = copy.deepcopy(records)
    r2["windows"][0]["target_sha256"] = "f" * 64
    try:
        verify_records(r2, binary_bytes, obj_bytes, rustc_ver)
        raise RuntimeError("failed to reject bad window hash")
    except AssertionError:
        caught += 1
    # 3. Corrupt window size
    r3 = copy.deepcopy(records)
    r3["windows"][-1]["size"] += 1
    try:
        verify_records(r3, binary_bytes, obj_bytes, rustc_ver)
        raise RuntimeError("failed to reject bad window size")
    except AssertionError:
        caught += 1
    # 4. Corrupt binary byte at first window opcode (non-reloc offset 0)
    secs = {name: (sa, so, sz) for _i, name, _st, sa, so, sz, _l, _in in parse_elf_sections(binary_bytes)}
    text_sa, text_so, _ = secs[".text"]
    va0 = int(records["windows"][0]["start_va"], 16)
    mut_bin = bytearray(binary_bytes)
    mut_bin[text_so + (va0 - text_sa)] ^= 0xFF
    try:
        build_records(bytes(mut_bin), obj_bytes, rustc_ver)
        raise RuntimeError("failed to reject mutated target opcode")
    except AssertionError:
        caught += 1
    return caught


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--generate", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    binary_bytes = BINARY_PATH.read_bytes()
    if hashlib.sha256(binary_bytes).hexdigest() != EXPECTED_BINARY_SHA256:
        raise SystemExit("Pinned node #115 binary SHA-256 mismatch")
    obj_bytes, rustc_ver = compile_object()
    if args.generate:
        recs = build_records(binary_bytes, obj_bytes, rustc_ver)
        RECORDS_PATH.write_text(json.dumps(recs, indent=2) + "\n", encoding="utf-8")
        print(f"Generated {RECORDS_PATH}: {recs['summary']}")
    else:
        recs = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        verify_records(recs, binary_bytes, obj_bytes, rustc_ver)
        print(f"Verified {recs['summary']}")
    if args.self_test:
        caught = run_negative_controls(recs, binary_bytes, obj_bytes, rustc_ver)
        print(f"Negative controls rejected: {caught}/4")


if __name__ == "__main__":
    main()
