#!/usr/bin/env python3
"""Recover selected node-115 CALL-family and alternate-host evidence offline.

The program reads ELF bytes only; it does not invoke a disassembler or execute
captured instructions.  Addresses are linked ELF virtual addresses.  Ranges
described by FDEs are unwind extents, not a complete function census.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections, unwind_index  # noqa: E402
from fde_extents import eh_frame_records, uleb  # noqa: E402

TARGET = ROOT / "artifacts/node/115/hl-node"
TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
LEGACY_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

# Seven newly selected handler bodies.  The ordinary f1 handler is already
# owned elsewhere and is deliberately not selected or compared here.
FUNCTIONS = (
    ("alternate_interpreter", 0x22d9070, 0x22d949c),
    ("ordinary_delegate", 0x2999b00, 0x2999e6b),
    ("ordinary_static", 0x2999e70, 0x299a1c1),
    ("ordinary_callcode", 0x299a1d0, 0x299a579),
    ("alternate_delegate", 0x299a580, 0x299a8eb),
    ("alternate_call", 0x299a8f0, 0x299ac93),
    ("alternate_callcode", 0x299aca0, 0x299b049),
    ("alternate_static", 0x299b400, 0x299b751),
    ("alternate_account_loader", 0x5463980, 0x5463f8a),
    ("alternate_host", 0x546c330, 0x546cba0),
    ("alternate_code_prepare", 0x54793e0, 0x5479634),
    ("alternate_temporary_drop", 0x563e0e0, 0x563e100),
)

# These are reviewed instruction-shaped windows, not an x86 decoder.
# The hexadecimal strings are checked against the authenticated input.
PINS = (
    ("loop_arguments", 0x22d9081, "4d89cc4d89c54989d74989f64889bc248000000048894c2410"),
    ("loop_fetch_charge_call", 0x22d90c7, "4180bf49010000010f85eb010000498b87180100000fb61848ffc049898718010000498b44dd00410fb70c5c49298f880100000f82800100004c89ff4c89f6ffd0"),
    ("loop_dispatch_tail", 0x22d9110, "80c36080fb050f82850100004180bf49010000000f8576ffffff"),
    ("loop_charge_status", 0x22d9280, "b0204180bf10010000380f8580feffff"),
    ("loop_stop_status", 0x22d92c0, "41c6874901000001410fb6871001000041c68710010000383c380f8416010000"),
    ("loop_copy_action", 0x22d92e0, "498b8f0801000048894c2470410f1087f80000000f2944246066410f1087b800000066410f108fc800000066410f1097d800000066410f109fe8000000660f295c2450660f29542440660f294c2430660f2944242088442478"),
    ("loop_output_tag", 0x22d9357, "488b4c2470488b842480000000488948500fb64c2478884858"),
    ("loop_output_payload", 0x22d9388, "0f284424600f1140400f284424200f284c24300f285424400f285c24500f1158300f1150200f1148100f1100"),
    ("delegate_revision", 0x2999b1e, "80bfa901000000"),
    ("delegate_stack_check", 0x2999b2e, "488b4f30b02c4883f902"),
    ("delegate_stack_load", 0x2999b61, "4883c1fe4889cf48c1e705488b1c384c8b7438084c8b7c381048894e30"),
    ("delegate_endian", 0x2999ba0, "490fcf490fce480fcb49c1ef20"),
    ("delegate_key_host", 0x2999bd5, "44897c24204c8974242448895c242c"),
    ("delegate_key_frame", 0x2999cdf, "4489bc24b00000004c89b424b400000048899c24bc000000"),
    ("delegate_value_tag", 0x2999cfc, "48c744242001000000"),
    ("delegate_scheme", 0x2999d05, "c68424ee00000002"),
    ("delegate_action", 0x2999d83, "49c78424b80000000100000049899c24c000000041c684241001000000b004"),
    ("static_revision", 0x2999e8e, "80bfa901000003"),
    ("static_stack_load", 0x2999ed1, "4883c1fe4889cf48c1e705488b1c384c8b7438084c8b7c381048894e30"),
    ("static_endian", 0x2999f10, "490fcf490fce480fcb49c1ef20"),
    ("static_key_host", 0x2999f45, "44897c24204c8974242448895c242c"),
    ("static_key_frame", 0x299a028, "4489bc24b00000004c89b424b400000048899c24bc000000"),
    ("static_zero_value", 0x299a045, "0f57c00f294424200f2944243048c744244000000000"),
    ("static_scheme", 0x299a05b, "c68424ee00000003c68424ec00000001"),
    ("callcode_stack", 0x299a1ee, "488b4f30b02c4883f902"),
    ("callcode_consume", 0x299a23d, "4883c1fd"),
    ("callcode_endian", 0x299a2a3, "490fcd490fcf490fce49c1ed20"),
    ("callcode_key_host", 0x299a2db, "44896c24604c897c24644c8974246c"),
    ("callcode_key_frame", 0x299a3ee, "4489ac24f00000004c89bc24f40000004c89b424fc000000"),
    ("callcode_scheme", 0x299a40e, "48c744246000000000c684242e01000001"),
    ("alternate_call_static_gate", 0x299a99f, "b0274484a6a8010000"),
    ("alternate_call_endian", 0x299a9d0, "490fcd490fcf490fce49c1ed20"),
    ("alternate_call_key_host", 0x299a9f9, "44896c24304c897c24344c8974243c"),
    ("alternate_call_key_frame", 0x299ab0b, "4489ac24c00000004c89bc24c40000004c89b424cc000000"),
    ("alternate_call_scheme", 0x299ab28, "48c744243000000000c68424fe00000000"),
    ("host_value_charge", 0x546c35c, "488b87500200004c8bba880100004c2b78780f824007000089cd4c89ba88010000"),
    ("host_revision_gate", 0x546c38d, "0fb69aa901000080fb070f93c0"),
    ("host_first_guard", 0x546c388, "48895424400fb69aa901000080fb070f93c0488b9750020000488b8a80000000488b9290000000488954243848894c24184939cf0f92c120c1488db770020000440fb6af9603000048897c2408488d9798030000440fb6c1"),
    ("host_primary_mode", 0x546c3c8, "440fb6af96030000"),
    ("host_first_loader", 0x546c3e8, "488974243048895424284c89d1ff15eda80701"),
    ("host_primary_classification", 0x546c42f, "498d46284180fd027670f3410f6f4648f3410f6f4e58660f740dd35bfefa660f74059b73fefa660fdbc1660fd7c881f9ffff00007420f3410f6f4648f3410f6f4e58660febc8660fefc0660f76c10f50c883f10f7531f30f6f00f30f6f4810660febc8660fefc0660f76c10f50c883f10f751449837e6800eb14410fb68e8c000000f6c108750431c9eb06f6c1040f94c1"),
    ("host_first_cost_selector", 0x546c4c0, "31d241f6c40141bd000000004c0f456c241880fb0748c78424180100000000000048898424200100004488a42478010000888c24790100004c0f42ea"),
    ("host_value_restore_from_object", 0x546c505, "f049ff064189ec7f28e913060000"),
    ("host_value_restore_from_default", 0x546c513, "4c8b355ea70701418b460885c04189ec0f8594050000"),
    ("host_extra_cost_selector", 0x546c57b, "807c242400743580bc247901000000742b80fb030f93c14489e2f6d284ca0f85f4000000488b4c2408488b8950020000488b8988000000e9de000000"),
    ("host_add_cost_checked", 0x546c693, "31c94c01e90f825a04000031db"),
    ("host_adjustment_select", 0x546c69e, "31db4584e47421488b54240880ba65020000007413488b542408488b9250020000488b9a58010000"),
    ("host_code_tag", 0x546c5cd, "80787c010f8593020000488b50404883fa160f86e9040000488b4038"),
    ("host_code_pointer", 0x546c5e9, "8b4813898c24100100000f104003"),
    ("host_second_cost_checks", 0x546c5ff, "4c036c24380f82060500004d39fd775f488b4424184c01e80f82fc0400004531c048894424184939c7410f92c0"),
    ("host_secondary_mode", 0x546c62c, "488b442408440fb6b896030000"),
    ("host_secondary_classification", 0x546c720, "498d46284180ff027670f3410f6f4648f3410f6f4e58660f740de258fefa660f7405aa70fefa660fdbc1660fd7c881f9ffff00007420f3410f6f4648f3410f6f4e58660febc8660fefc0660f76c10f50c883f10f7531f30f6f00f30f6f4810660febc8660fefc0660f76c10f50c883f10f751449837e6800eb14410fb68e8c000000f6c108750431c9eb06f6c1040f94c1"),
    ("host_second_cost_select", 0x546c7d3, "f6c3014c0f456c2418"),
    ("host_other_adjustment_zero", 0x546c893, "488b84246801000031db4885c0740f"),
    ("host_first_charge", 0x546c8e9, "4c8b4c2440498b89880100004c29f94c8b4424480f828a01000049898988010000"),
    ("host_accounting_deficit", 0x546c90a, "498b91900100004889d04829d873584889d84829d04829c10f8265010000498b8198010000488d140348c1fa3f48be00000000000000804831d64801d8480f40c6498989880100004989819801000031c049898190010000"),
    ("host_accounting_enough", 0x546c971, "498b9198010000488d341348c1fe3f48bf00000000000000804831f74801da480f40d74989919801000049898190010000"),
    ("host_divisor_and_wide_div", 0x546c9ac, "488b442408488b8050020000488b70704885f60f843c0100004889c84809f048c1e82074354889c831d248f7f6"),
    ("host_null_adjustment_zero", 0x546c9db, "31db4d85f60f85d4feffff"),
    ("host_narrow_div_and_cap", 0x546ca06, "89c831d2f7f64889ca4829c24939d04c0f43c2"),
    ("host_forward_cap", 0x546ca0c, "4889ca4829c24939d04c0f43c24c29c1726f49898988010000"),
    ("host_stipend", 0x546ca2a, "488b442408488b80500200004c0380c000000048c7c0ffffffff4c0f42c0"),
    ("host_result_fields", 0x546ca48, "4885db0f28842480010000660f6f8c2490010000488b442410f30f7f48200f1140104c89304989c64c8940080f954030"),
    ("host_error_late", 0x546ca8d, "488b442410c60020c6403002"),
    ("host_error_drop", 0x546ca99, "f049ff0e750e488dbc2498000000ff15fb840701"),
    ("host_error_value", 0x546cab4, "41c60620e942ffffff"),
    ("host_unwind_second", 0x546cb6f, "4889c3488b0424f048ff0875094889e7ff1523840701488dbc2418010000e84e151d004889dfe8b63ef800"),
    ("account_lookup", 0x54639a2, "4881c6c8000000488d7c24404889cae8fa3ea9ff"),
    ("account_policy", 0x5463a01, "4c89e6ff15ce6c08014180f6014108c60f84ac040000"),
    ("account_refresh_policy", 0x5463e28, "498d7f484c89e6ff15a36808014180f601894424084108c64180fe01757d"),
    ("account_epoch", 0x5463b45, "8b45f8413b87200100000f85d3020000f645fc100f85c9020000"),
    ("account_journal", 0x5463ce2, "498b4720496bce58c6040800410f1004240f11440801418b5424108954081149ffc64d897728"),
    ("account_insert", 0x5463d70, "41883c1641887c361080e1010fb6c14929451048f7da4189ec4869eaa8000000488b4424384989842e58ffffff"),
    ("account_refresh", 0x5463e46, "418b87200100000fb64dfc89ca80e2ef8855fc8945f8f6c140740c4c89efe8e7f9feff8065fcbf4c89efff156a680801"),
    ("account_refresh_journal", 0x5463e76, "8065fc7f4d8b77284d3b7718750a498d7f18ff15622e08018b7424084080f601498b4720496bce58c6040800f3410f6f0424f30f7f440801418b5424108954081149ffc64d897728"),
    ("account_result", 0x5463df7, "418b542410895334410f1004240f1143244c892b488943084c897b10488b44241848894318894b2040887338"),
    ("code_cache_gate", 0x54793f0, "48837f70000f85ca010000"),
    ("code_compare", 0x5479417, "660f740d018cfdfa660f7405c9a3fdfa660fdbc1660fd7c03dffff00000f8425010000"),
    ("code_replace", 0x54795ab, "488b034885c0740ff048ff0875094889dfff15e6b906014c8933"),
    ("temporary_drop", 0x563e0e0, "48833f007419488b47504885c07410f048ff08750a4883c750ff25a96eea00c3"),
)

# Each masked four-byte field is an explicitly checked rel32 operand.  They
# are within-target PC-relative differences, not ELF relocation masks or a
# rebuilt-source byte comparison.  Exactly the host-slot target differs.
PAIRS = (
    ("delegate", 0x2999b00, 0x299a580,
     (0x8b, 0xfd, 0x223, 0x242, 0x2d2, 0x2f7, 0x30d, 0x322, 0x34c, 0x359, 0x361, 0x367), 0xfd),
    ("static", 0x2999e70, 0x299b400,
     (0x8b, 0xfd, 0x209, 0x228, 0x2b8, 0x2dd, 0x2f3, 0x308, 0x332, 0x33f, 0x347, 0x34d), 0xfd),
    ("callcode", 0x299a1d0, 0x299aca0,
     (0xbe, 0x136, 0x265, 0x284, 0x314, 0x339, 0x34b, 0x360, 0x38a, 0x397, 0x39f, 0x3a5), 0x136),
)

# Small call-boundary excerpts from the previously mapped alternate driver.
# This driver is a dependency, not one of the selected FDEs in this packet.
BOUNDARIES = (
    ("driver_table_copy", 0x2962fd5, "488d3534e2ad03488dbc24f00f0000ba00080000ff1519c5b703"),
    ("driver_heap_copy", 0x2963069, "4989c548895c2438488db424f00f0000ba620800004889c7488b1d80c4b703ffd3"),
    ("driver_table_save", 0x2963284, "4c89ac2460140000"),
    ("driver_loop_call", 0x296472d, "4c8b8424601400004c8ba4247814000049c1e4094c03a424881400004d8d8800080000488dbc24b0090000488db424f00f00004c89e2488d8c2498140000e8004997ff"),
    ("driver_output_gate", 0x2964770, "80bc24080a0000000f84cb000000"),
    ("driver_action_load", 0x2964849, "488bac24b00900004c8bbc24b8090000"),
    ("driver_action_save", 0x29648bd, "4889ac24380200004c89bc2440020000"),
)

# label, opcode, entry, frame-copy LEA, first value operation, scheme store,
# projected-key stores, action publication.  These coordinates are within the
# selected FDEs, not a general instruction decoder.
FRAME_MODES = (
    ("ordinary_delegate", 0xf4, 0x2999b00, 0x2999d33, 0x2999cfc, 0x2999d05, 0x2999cdf, 0x2999d83),
    ("alternate_delegate", 0xf4, 0x299a580, 0x299a7b3, 0x299a77c, 0x299a785, 0x299a75f, 0x299a803),
    ("ordinary_static", 0xfa, 0x2999e70, 0x299a089, 0x299a045, 0x299a05b, 0x299a028, 0x299a0d9),
    ("alternate_static", 0xfa, 0x299b400, 0x299b619, 0x299b5d5, 0x299b5eb, 0x299b5b8, 0x299b669),
    ("ordinary_callcode", 0xf2, 0x299a1d0, 0x299a445, 0x299a40e, 0x299a417, 0x299a3ee, 0x299a495),
    ("alternate_callcode", 0xf2, 0x299aca0, 0x299af15, 0x299aede, 0x299aee7, 0x299aebe, 0x299af65),
    ("alternate_call", 0xf1, 0x299a8f0, 0x299ab5f, 0x299ab28, 0x299ab31, 0x299ab0b, 0x299abaf),
)

INDIRECT = (
    ("ordinary_delegate_host", 0x2999bfb, 0x64e6e00),
    ("ordinary_static_host", 0x2999f6b, 0x64e6e00),
    ("ordinary_callcode_host", 0x299a304, 0x64e6e00),
    ("alternate_delegate_host", 0x299a67b, 0x64e6e08),
    ("alternate_call_host", 0x299aa26, 0x64e6e08),
    ("alternate_callcode_host", 0x299add4, 0x64e6e08),
    ("alternate_static_host", 0x299b4fb, 0x64e6e08),
    ("host_first_account", 0x546c3f5, 0x64e6ce8),
    ("host_second_account", 0x546c653, 0x64e6ce8),
    ("account_missing_policy", 0x5463a04, 0x64ea6d8),
    ("account_refresh_policy", 0x5463e2f, 0x64ea6d8),
    ("temporary_drop", 0x563e0f9, 0x64e4fa8),
)

# The same gates are decoded for both members of each paired handler.  The
# comparison observes only their selected unwind extents and operand masks.
HANDLER_GATES = (
    ("ordinary_delegate", 0x2999b32, 0x2999b8a, 0x2999d2a, 0x2999b1e, None),
    ("alternate_delegate", 0x299a5b2, 0x299a60a, 0x299a7aa, 0x299a59e, None),
    ("ordinary_static", 0x2999ea2, 0x2999efa, 0x299a080, 0x2999e8e, None),
    ("alternate_static", 0x299b432, 0x299b48a, 0x299b610, 0x299b41e, None),
    ("ordinary_callcode", 0x299a1f2, 0x299a28d, 0x299a43c, None, None),
    ("alternate_callcode", 0x299acc2, 0x299ad5d, 0x299af0c, None, None),
    ("alternate_call", 0x299a911, 0x299a9ba, 0x299ab56, None, 0x299a99f),
)

# Selected direct transfers; a condition's label describes the observation,
# not an assertion that the branch is reachable for arbitrary runtime state.
EDGES = (
    ("loop_not_running", 0x22d90cf, "jcc", 0x22d92c0),
    ("loop_base_gas_underflow", 0x22d90fa, "jcc", 0x22d9280),
    ("loop_handler_status", 0x22d910a, "jcc", 0x22d9282),
    ("loop_special_opcode", 0x22d9116, "jcc", 0x22d92a1),
    ("loop_continue", 0x22d9124, "jcc", 0x22d90a0),
    ("loop_existing_status", 0x22d928a, "jcc", 0x22d9110),
    ("loop_no_action", 0x22d92da, "jcc", 0x22d93f6),
    ("delegate_revision_zero", 0x2999b25, "jcc", 0x2999dfd),
    ("delegate_stack_short", 0x2999b38, "jcc", 0x2999da2),
    ("delegate_range", 0x2999b8a, "call", 0x29998f0),
    ("delegate_range_ok", 0x2999b94, "jcc", 0x2999ba0),
    ("delegate_allocation_null", 0x2999d2a, "jcc", 0x2999e01),
    ("delegate_action_empty", 0x2999d5a, "jcc", 0x2999d83),
    ("static_revision_low", 0x2999e95, "jcc", 0x299a153),
    ("static_stack_short", 0x2999ea8, "jcc", 0x299a0f8),
    ("static_range", 0x2999efa, "call", 0x29998f0),
    ("static_allocation_null", 0x299a080, "jcc", 0x299a157),
    ("callcode_stack_short", 0x299a1f8, "jcc", 0x299a4b4),
    ("callcode_range", 0x299a28d, "call", 0x29998f0),
    ("callcode_allocation_null", 0x299a43c, "jcc", 0x299a50f),
    ("alternate_call_stack_short", 0x299a917, "jcc", 0x299abce),
    ("alternate_call_static_value", 0x299a9a8, "jcc", 0x299abce),
    ("alternate_call_range", 0x299a9ba, "call", 0x29998f0),
    ("alternate_call_host_ok", 0x299aa36, "jcc", 0x299aa45),
    ("alternate_call_allocation_null", 0x299ab56, "jcc", 0x299ac29),
    ("host_no_value_charge", 0x546c35a, "jcc", 0x546c37f),
    ("host_value_charge_underflow", 0x546c36e, "jcc", 0x546cab4),
    ("host_loader_nonerror", 0x546c408, "jcc", 0x546c412),
    ("host_first_code_prepare", 0x546c42a, "call", 0x54793e0),
    ("primary_classification_low_mode", 0x546c437, "jcc", 0x546c4a9),
    ("primary_classification_literal", 0x546c463, "jcc", 0x546c485),
    ("primary_classification_nonzero_hash", 0x546c483, "jcc", 0x546c4b6),
    ("primary_classification_nonzero_value", 0x546c4a0, "jcc", 0x546c4b6),
    ("primary_classification_flag", 0x546c4b4, "jcc", 0x546c4ba),
    ("host_no_code_object", 0x546c5c7, "jcc", 0x546c86a),
    ("host_other_code_kind", 0x546c5d1, "jcc", 0x546c86a),
    ("host_code_too_short", 0x546c5df, "jcc", 0x546cace),
    ("host_second_cost_overflow", 0x546c604, "jcc", 0x546cb10),
    ("host_second_cost_unfunded", 0x546c60d, "jcc", 0x546c66e),
    ("host_second_total_overflow", 0x546c617, "jcc", 0x546cb19),
    ("host_secondary_loader_ok", 0x546c664, "jcc", 0x546c708),
    ("host_second_code_prepare", 0x546c71b, "call", 0x54793e0),
    ("host_extra_no_handler_mode", 0x546c580, "jcc", 0x546c5b7),
    ("host_extra_not_classified", 0x546c58a, "jcc", 0x546c5b7),
    ("host_extra_zero_at_revision", 0x546c599, "jcc", 0x546c693),
    ("host_extra_cost_overflow", 0x546c698, "jcc", 0x546caf8),
    ("host_no_value_adjustment", 0x546c6a3, "jcc", 0x546c6c6),
    ("host_adjustment_disabled", 0x546c6b1, "jcc", 0x546c6c6),
    ("host_null_temporary", 0x546c88d, "jcc", 0x546c9db),
    ("host_skip_old_reference", 0x546c8a0, "jcc", 0x546c8b1),
    ("host_null_path_charge", 0x546c9e0, "jcc", 0x546c8ba),
    ("host_unwind_temporary", 0x546cb8d, "call", 0x563e0e0),
    ("host_unwind_resume", 0x546cb95, "call", 0x63f0a50),
    ("secondary_classification_low_mode", 0x546c728, "jcc", 0x546c79a),
    ("secondary_classification_literal", 0x546c754, "jcc", 0x546c776),
    ("secondary_classification_nonzero_hash", 0x546c774, "jcc", 0x546c7a7),
    ("secondary_classification_nonzero_value", 0x546c791, "jcc", 0x546c7a7),
    ("secondary_classification_flag", 0x546c7a5, "jcc", 0x546c7ab),
    ("host_access_charge_underflow", 0x546c8fd, "jcc", 0x546ca8d),
    ("host_accounting_without_deficit", 0x546c917, "jcc", 0x546c971),
    ("host_additional_charge_underflow", 0x546c922, "jcc", 0x546ca8d),
    ("host_divisor_zero", 0x546c9bf, "jcc", 0x546cb01),
    ("host_forward_underflow", 0x546ca1c, "jcc", 0x546ca8d),
    ("account_map_entry", 0x54639b1, "call", 0x4ef78b0),
    ("account_cached_hit", 0x54639be, "jcc", 0x5463b39),
    ("account_policy_reject", 0x5463a11, "jcc", 0x5463ec3),
    ("account_backend", 0x5463a29, "call", 0x54419e0),
    ("account_epoch_changed", 0x5463b4f, "jcc", 0x5463e28),
    ("account_flag_refresh", 0x5463b59, "jcc", 0x5463e28),
    ("account_missing_journal", 0x5463b2e, "jcc", 0x5463cce),
    ("account_refresh_reject", 0x5463e44, "jcc", 0x5463ec3),
    ("account_skip_flag_cleanup", 0x5463e5f, "jcc", 0x5463e6d),
    ("code_already_present", 0x54793f5, "jcc", 0x54795c5),
    ("code_default_digest", 0x5479434, "jcc", 0x547955f),
    ("code_map_entry", 0x5479472, "call", 0x4ef7e50),
    ("code_cached_value", 0x547947f, "jcc", 0x547958d),
    ("code_last_reference", 0x54795b7, "jcc", 0x54795c2),
)


def authenticate(data, expected=TARGET_SHA):
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        raise ValueError("input SHA-256 mismatch")
    return digest


def mapping(secs, va, length, *, executable=False):
    if not isinstance(va, int) or not isinstance(length, int) or va < 0 or length <= 0:
        raise ValueError("invalid address or length")
    matches = [s for s in secs if s["type"] != 8 and s["size"] and
               (not executable or s["flags"] & 4) and s["address"] <= va and
               va + length <= s["address"] + s["size"]]
    if len(matches) != 1:
        raise ValueError("address is not in one file-backed section")
    s = matches[0]
    return s, s["offset"] + va - s["address"]


def read_va(data, secs, va, length, *, executable=False):
    section, off = mapping(secs, va, length, executable=executable)
    if off < 0 or off + length > len(data):
        raise ValueError("file-backed read exceeds input")
    return data[off:off + length], section, off


def relative_relocations(data, secs, wanted):
    matches = [s for s in secs if s["name"] == ".rela.dyn" and s["type"] == 4]
    if len(matches) != 1 or matches[0]["size"] % 24:
        raise ValueError("invalid relative relocation section")
    sec = matches[0]
    result = {}
    for off in range(sec["offset"], sec["offset"] + sec["size"], 24):
        slot, info, addend = struct.unpack_from("<QQq", data, off)
        if slot not in wanted:
            continue
        if slot in result or info != 8:
            raise ValueError("duplicate or non-relative relocation")
        result[slot] = {"slot_va": slot, "file_offset": off,
                        "info": info, "addend": addend}
    if set(result) != set(wanted):
        raise ValueError("missing relative relocation")
    return result


def symbol_relocation(data, secs, slot):
    """Read one ELF64 GLOB_DAT relocation and its dynamic-symbol name."""
    wanted = {}
    for name, section_type in ((".rela.dyn", 4), (".dynsym", 11), (".dynstr", 3)):
        matches = [s for s in secs if s["name"] == name and s["type"] == section_type]
        if len(matches) != 1:
            raise ValueError("missing or ambiguous dynamic section")
        sec = matches[0]
        if sec["offset"] < 0 or sec["offset"] + sec["size"] > len(data):
            raise ValueError("dynamic section exceeds input")
        wanted[name] = sec
    rela, sym, strings = (wanted[x] for x in (".rela.dyn", ".dynsym", ".dynstr"))
    if rela["size"] % 24 or sym["size"] % 24:
        raise ValueError("malformed dynamic records")
    hits = []
    for off in range(rela["offset"], rela["offset"] + rela["size"], 24):
        target, info, addend = struct.unpack_from("<QQq", data, off)
        if target == slot:
            hits.append((off, info, addend))
    if len(hits) != 1:
        raise ValueError("missing or duplicate symbol relocation")
    off, info, addend = hits[0]
    index, kind = info >> 32, info & 0xffffffff
    if kind != 6 or not index or index >= sym["size"] // 24:
        raise ValueError("unexpected dynamic symbol relocation")
    sym_off = sym["offset"] + index * 24
    name_index, symbol_info, other, shndx, value, symbol_size = struct.unpack_from("<IBBHQQ", data, sym_off)
    if name_index >= strings["size"]:
        raise ValueError("symbol name outside dynamic string table")
    name_off = strings["offset"] + name_index
    end = data.find(b"\0", name_off, strings["offset"] + strings["size"])
    if end < 0:
        raise ValueError("unterminated dynamic symbol name")
    try:
        name = bytes(data[name_off:end]).decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("non-ASCII symbol name") from exc
    slot_bytes, _, slot_off = read_va(data, secs, slot, 8)
    return {"slot_va": hex(slot), "slot_file_offset": hex(slot_off), "slot_bytes": bytes(slot_bytes).hex(),
            "rela_file_offset": hex(off), "rela_bytes": bytes(data[off:off + 24]).hex(),
            "relocation_type": kind, "addend": addend, "symbol_index": index,
            "symbol_file_offset": hex(sym_off), "symbol_bytes": bytes(data[sym_off:sym_off + 24]).hex(),
            "symbol_info": symbol_info, "symbol_other": other, "symbol_section_index": shndx,
            "symbol_value": hex(value), "symbol_size": symbol_size,
            "name_file_offset": hex(name_off), "name": name}


def assert_pins(data, secs, pins=PINS):
    result = []
    for label, va, expected in pins:
        raw, sec, off = read_va(data, secs, va, len(bytes.fromhex(expected)), executable=True)
        if raw.hex() != expected:
            raise ValueError("instruction window changed: " + label)
        result.append((label, hex(va), hex(off), sec["name"], raw.hex()))
    return result


def check_boundaries(data, secs):
    rows = assert_pins(data, secs, BOUNDARIES)
    lea, _, _ = read_va(data, secs, 0x2962fd5, 7, executable=True)
    if lea[:3] != b"\x48\x8d\x35" or 0x2962fd5 + 7 + struct.unpack_from("<i", lea, 3)[0] != 0x6441210:
        raise ValueError("driver table source changed")
    copy_call, _, _ = read_va(data, secs, 0x2962fe9, 6, executable=True)
    copy_load, _, _ = read_va(data, secs, 0x2963081, 7, executable=True)
    if (copy_call[:2] != b"\xff\x15" or
            0x2962fe9 + 6 + struct.unpack_from("<i", copy_call, 2)[0] != 0x64df508 or
            copy_load[:3] != b"\x48\x8b\x1d" or
            0x2963081 + 7 + struct.unpack_from("<i", copy_load, 3)[0] != 0x64df508):
        raise ValueError("driver copy slots changed")
    for va, target in ((0x296476b, 0x22d9070),):
        if decode_edge(data, secs, va, "call")[3] != target:
            raise ValueError("driver boundary target changed")
    if decode_edge(data, secs, 0x2964778, "jcc")[3] != 0x2964849:
        raise ValueError("driver action branch changed")
    return rows


def indirect_rows(data, secs, relas):
    rows = []
    for label, va, expected_slot in INDIRECT:
        raw, _, off = read_va(data, secs, va, 6, executable=True)
        if raw[:2] not in (b"\xff\x15", b"\xff\x25"):
            raise ValueError("unsupported indirect transfer: " + label)
        slot = va + 6 + struct.unpack_from("<i", raw, 2)[0]
        if slot != expected_slot or slot not in relas:
            raise ValueError("indirect transfer slot changed: " + label)
        rows.append((label, hex(va), hex(off), raw.hex(), hex(slot),
                     hex(relas[slot]["file_offset"]), hex(relas[slot]["addend"])))
    return rows


def frame_rows(data, secs):
    action_bytes = bytes.fromhex("49c78424b80000000100000049899c24c000000041c684241001000000b004")
    static_value = bytes.fromhex("0f57c00f294424200f2944243048c744244000000000")
    rows = []
    for label, opcode, entry, copy_va, tag_va, scheme_va, key_va, action_va in FRAME_MODES:
        copy, _, _ = read_va(data, secs, copy_va, 10, executable=True)
        if copy[:4] != b"\x48\x8d\x74\x24" or copy[5] != 0xba:
            raise ValueError("frame copy pattern changed: " + label)
        base, size = copy[4], struct.unpack_from("<I", copy, 6)[0]
        if size != 0xd0:
            raise ValueError("frame size changed: " + label)
        scheme, _, _ = read_va(data, secs, scheme_va, 8, executable=True)
        if scheme[:3] != b"\xc6\x84\x24":
            raise ValueError("scheme store changed: " + label)
        scheme_offset, scheme_value = struct.unpack_from("<I", scheme, 3)[0] - base, scheme[7]
        if (scheme_offset, scheme_value) != (0xce, {0xf1: 0, 0xf2: 1, 0xf4: 2, 0xfa: 3}[opcode]):
            raise ValueError("scheme offset or value changed: " + label)
        if opcode == 0xfa:
            tag, _, _ = read_va(data, secs, tag_va, len(static_value), executable=True)
            if tag != static_value or base != 0x20:
                raise ValueError("static zero frame changed")
            value_tag = 0
        else:
            tag, _, _ = read_va(data, secs, tag_va, 9, executable=True)
            if tag[:4] != b"\x48\xc7\x44\x24" or tag[4] != base:
                raise ValueError("value tag store changed: " + label)
            value_tag = struct.unpack_from("<I", tag, 5)[0]
            if value_tag != (1 if opcode == 0xf4 else 0):
                raise ValueError("value tag changed: " + label)
        key, _, _ = read_va(data, secs, key_va, 24, executable=True)
        expected_key = (bytes.fromhex("4489bc24b00000004c89b424b400000048899c24bc000000")
                        if opcode in (0xf4, 0xfa) else
                        bytes.fromhex("4489ac24f00000004c89bc24f40000004c89b424fc000000")
                        if opcode == 0xf2 else
                        bytes.fromhex("4489ac24c00000004c89bc24c40000004c89b424cc000000"))
        if key != expected_key or tuple(struct.unpack_from("<I", key, p)[0] - base for p in (4, 12, 20)) != (0x90, 0x94, 0x9c):
            raise ValueError("frame key stores changed: " + label)
        action, _, _ = read_va(data, secs, action_va, len(action_bytes), executable=True)
        if action != action_bytes:
            raise ValueError("action publication changed: " + label)
        sites = [va for name, va, _ in INDIRECT if name == label + "_host"]
        if len(sites) != 1:
            raise ValueError("missing handler host site: " + label)
        host_va = sites[0]
        if opcode == 0xf1:
            host_args, _, _ = read_va(data, secs, host_va - 9, 9, executable=True)
            if host_args != bytes.fromhex("41b8010000004989d9"):
                raise ValueError("CALL host mode changed")
            host_mode = 1
        else:
            host_args, _, _ = read_va(data, secs, host_va - 3, 3, executable=True)
            if host_args != bytes.fromhex("4531c0"):
                raise ValueError("non-CALL host mode changed: " + label)
            host_mode = 0
        rows.append((label, hex(opcode), hex(entry), hex(copy_va), hex(base), size,
                     hex(tag_va), tag.hex(), value_tag, hex(scheme_va), scheme.hex(),
                     hex(scheme_offset), scheme_value, hex(key_va), key.hex(),
                     hex(action_va), action.hex(), hex(host_va), host_args.hex(), host_mode))
    return rows


def handler_gate_rows(data, secs):
    extents = {label: (start, end) for label, start, end in FUNCTIONS}
    rows = []
    for label, stack_va, range_va, allocation_va, revision_va, static_va in HANDLER_GATES:
        start, end = extents[label]
        status, _, _ = read_va(data, secs, stack_va, 6, executable=True)
        if status[:2] != b"\xb0\x2c" or status[2:5] != b"\x48\x83\xf9":
            raise ValueError("stack gate changed: " + label)
        branch, _, _, short_target = decode_edge(data, secs, stack_va + 6, "jcc")
        if branch[:2] == b"\x0f\x82":
            minimum = status[5]
        elif branch[:2] == b"\x0f\x86":
            minimum = status[5] + 1
        else:
            raise ValueError("unsupported stack predicate: " + label)
        if not start <= short_target < end:
            raise ValueError("stack failure outside handler: " + label)
        call, _, _, range_target = decode_edge(data, secs, range_va, "call")
        if range_target != 0x29998f0:
            raise ValueError("range helper changed: " + label)
        alloc, _, _, alloc_target = decode_edge(data, secs, allocation_va, "jcc")
        if alloc[:2] != b"\x0f\x84" or not start <= alloc_target < end:
            raise ValueError("allocation branch changed: " + label)
        revision_test = revision_target = revision_bytes = ""
        if revision_va is not None:
            cmp_raw, _, _ = read_va(data, secs, revision_va, 7, executable=True)
            if cmp_raw[:6] != bytes.fromhex("80bfa9010000"):
                raise ValueError("revision comparison changed: " + label)
            jump, _, _, destination = decode_edge(data, secs, revision_va + 7, "jcc")
            if jump[:2] not in (b"\x0f\x84", b"\x0f\x86") or not start <= destination < end:
                raise ValueError("revision branch changed: " + label)
            ret, _, _ = read_va(data, secs, destination, 2, executable=True)
            if ret != b"\xb0\x2b":
                raise ValueError("revision status changed: " + label)
            revision_test = ("eq" if jump[1] == 0x84 else "unsigned_le") + ":" + str(cmp_raw[6])
            revision_target = hex(destination)
            revision_bytes = (cmp_raw + jump + ret).hex()
        static_target = static_bytes = ""
        if static_va is not None:
            raw, _, _ = read_va(data, secs, static_va, 9, executable=True)
            if raw != bytes.fromhex("b0274484a6a8010000"):
                raise ValueError("static-value gate changed")
            jump, _, _, destination = decode_edge(data, secs, static_va + 9, "jcc")
            if jump[:2] != b"\x0f\x85" or not start <= destination < end:
                raise ValueError("static-value branch changed")
            static_target, static_bytes = hex(destination), (raw + jump).hex()
        rows.append((label, hex(stack_va), status.hex(), branch.hex(), minimum, "0x2c", hex(short_target),
                     hex(range_va), call.hex(), hex(range_target), hex(allocation_va), alloc.hex(),
                     hex(alloc_target), hex(revision_va) if revision_va is not None else "",
                     revision_test, revision_target, revision_bytes,
                     hex(static_va) if static_va is not None else "", static_target, static_bytes))
    return rows


def classification_pair(data, secs):
    """Compare two selected classifier windows inside the same host body."""
    first_va, second_va, size = 0x546c42f, 0x546c720, 0x91
    first, _, first_off = read_va(data, secs, first_va, size, executable=True)
    second, _, second_off = read_va(data, secs, second_va, size, executable=True)
    if (first[6], second[6]) != (0xfd, 0xff):
        raise ValueError("classification mode registers changed")
    fields = []
    masks = {6}
    for pos, opcode, expected in ((0x1a, bytes.fromhex("660f740d"), 0x452020),
                                  (0x22, bytes.fromhex("660f7405"), 0x4537f0)):
        if first[pos - 4:pos] != opcode or second[pos - 4:pos] != opcode:
            raise ValueError("classification literal reference changed")
        targets = [base + pos + 4 + struct.unpack_from("<i", body, pos)[0]
                   for base, body in ((first_va, first), (second_va, second))]
        if targets != [expected, expected]:
            raise ValueError("classification literal target changed")
        masks.update(range(pos, pos + 4))
        fields.append({"operand_offset": hex(pos), "target_va": hex(expected),
                       "first_operand": first[pos:pos + 4].hex(),
                       "second_operand": second[pos:pos + 4].hex()})
    if any(a != b for i, (a, b) in enumerate(zip(first, second)) if i not in masks):
        raise ValueError("classification windows differ outside checked fields")
    return {"first_va": hex(first_va), "first_file_offset": hex(first_off),
            "second_va": hex(second_va), "second_file_offset": hex(second_off), "size_each": size,
            "raw_different_byte_positions": sum(a != b for a, b in zip(first, second)),
            "masked_byte_positions": sorted(masks), "mode_register_byte_offset": 6,
            "references": fields, "unmasked_bytes_equal": True,
            "normalization": "One checked mode-register byte and two checked RIP-relative operands; within this target only."}


def decode_edge(data, secs, va, kind):
    raw, sec, off = read_va(data, secs, va, 2, executable=True)
    if kind == "call" and raw[0] == 0xe8:
        size, pos, fmt = 5, 1, "<i"
    elif kind == "jcc" and 0x70 <= raw[0] <= 0x7f:
        size, pos, fmt = 2, 1, "<b"
    elif kind == "jcc" and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        size, pos, fmt = 6, 2, "<i"
    else:
        raise ValueError("unexpected transfer opcode")
    raw, sec, off = read_va(data, secs, va, size, executable=True)
    return raw, sec, off, va + size + struct.unpack_from(fmt, raw, pos)[0]


def edge_rows(data, secs):
    rows = []
    for label, va, kind, expected in EDGES:
        raw, sec, off, target = decode_edge(data, secs, va, kind)
        if target != expected:
            raise ValueError("transfer target changed: " + label)
        rows.append((label, kind, hex(va), hex(off), sec["name"], raw.hex(), hex(target)))
    return rows


def selected_fdes(data, secs):
    cies, fdes = eh_frame_records(data, secs)
    selected = {}
    wanted = {start: (label, end) for label, start, end in FUNCTIONS}
    for fde in fdes:
        if fde["start"] not in wanted:
            continue
        label, end = wanted[fde["start"]]
        if fde["start"] in selected or fde["end"] != end:
            raise ValueError("duplicate or changed selected FDE")
        selected[fde["start"]] = dict(fde, label=label)
    if set(selected) != set(wanted):
        raise ValueError("selected FDE missing")
    del fdes
    _, rows = unwind_index(data)
    selected_rows = [r for r in rows if r["start"] in wanted]
    indexed = {r["start"]: r["fde"] for r in selected_rows}
    del rows
    if len(selected_rows) != len(wanted) or len(indexed) != len(wanted) or any(indexed[a] != selected[a]["fde"] for a in wanted):
        raise ValueError("selected FDE is not uniquely indexed")
    result = []
    for label, start, end in FUNCTIONS:
        fde = selected[start]
        raw, sec, off = read_va(data, secs, start, end - start, executable=True)
        records = {}
        for name, va in (("fde", fde["fde"]), ("cie", fde["cie"])):
            first, _, _ = read_va(data, secs, va, 4)
            length = struct.unpack("<I", first)[0]
            rec, _, _ = read_va(data, secs, va, 4 + length)
            records[name + "_bytes"] = rec.hex()
        if fde["cie"] not in cies:
            raise ValueError("missing selected CIE")
        result.append({"label": label, "start_va": hex(start), "end_va_exclusive": hex(end),
                       "file_offset": hex(off), "section": sec["name"], "size": len(raw),
                       "sha256": hashlib.sha256(raw).hexdigest(), "body_bytes": raw.hex(),
                       "fde_va": hex(fde["fde"]), "cie_va": hex(fde["cie"]),
                       "lsda_va": hex(fde["lsda"]) if fde["lsda"] is not None else None,
                       **records})
    return result, selected


def decode_lsda(data, secs, fde):
    """Decode only the observed omitted-LPStart, ULEB call-site format."""
    va = fde["lsda"]
    if va is None:
        return None, []
    sec, offset = mapping(secs, va, 1)
    if sec["name"] != ".gcc_except_table":
        raise ValueError("LSDA outside exception section")
    limit = sec["offset"] + sec["size"]
    pos = offset
    if pos + 2 > limit or data[pos] != 0xff or data[pos + 1] not in (0xff, 0x9b):
        raise ValueError("unsupported LSDA header")
    type_encoding = data[pos + 1]
    pos += 2
    if type_encoding != 0xff:
        _, pos = uleb(data, pos, limit)
    if pos >= limit or data[pos] != 1:
        raise ValueError("unsupported LSDA call-site encoding")
    pos += 1
    length, pos = uleb(data, pos, limit)
    end = pos + length
    if end > limit:
        raise ValueError("LSDA call-site table crosses section")
    header = {"lsda_va": hex(va), "file_offset": hex(offset),
              "header_bytes": data[offset:pos].hex(), "callsite_bytes": length}
    rows = []
    while pos < end:
        begin = pos
        start, pos = uleb(data, pos, end)
        size, pos = uleb(data, pos, end)
        landing, pos = uleb(data, pos, end)
        action, pos = uleb(data, pos, end)
        if start + size > fde["end"] - fde["start"] or (landing and landing >= fde["end"] - fde["start"]):
            raise ValueError("LSDA call-site outside selected FDE")
        rows.append((fde["label"], hex(va), hex(begin), hex(fde["start"] + start),
                     hex(fde["start"] + start + size),
                     hex(fde["start"] + landing) if landing else "", action,
                     data[begin:pos].hex()))
    if pos != end:
        raise ValueError("malformed LSDA table")
    return header, rows


def relative_operand(body, base, pos):
    if pos >= 2 and body[pos - 2:pos] == b"\xff\x15":
        kind = "rip_indirect_call"
    elif pos >= 1 and body[pos - 1] == 0xe8:
        kind = "direct_call"
    else:
        raise ValueError("masked operand has unsupported opcode")
    if pos + 4 > len(body):
        raise ValueError("truncated relative operand")
    return kind, base + pos + 4 + struct.unpack_from("<i", body, pos)[0]


def compare_pair(data, secs, kind, left_va, right_va, offsets, host_offset, ends):
    left, _, _ = read_va(data, secs, left_va, ends[left_va] - left_va, executable=True)
    right, _, _ = read_va(data, secs, right_va, ends[right_va] - right_va, executable=True)
    if len(left) != len(right) or len(set(offsets)) != len(offsets):
        raise ValueError("invalid paired body size or masks")
    mask = set()
    operands = []
    for pos in offsets:
        if set(range(pos, pos + 4)) & mask:
            raise ValueError("overlapping operand masks")
        mask.update(range(pos, pos + 4))
        a_kind, a_target = relative_operand(left, left_va, pos)
        b_kind, b_target = relative_operand(right, right_va, pos)
        if a_kind != b_kind:
            raise ValueError("relative operand kinds differ")
        if pos == host_offset:
            if a_kind != "rip_indirect_call" or (a_target, b_target) != (0x64e6e00, 0x64e6e08):
                raise ValueError("host slot mapping differs")
        elif a_target != b_target:
            raise ValueError("non-host paired target differs")
        operands.append({"operand_offset": hex(pos), "kind": a_kind,
                         "ordinary_target_va": hex(a_target), "alternate_target_va": hex(b_target),
                         "ordinary_operand": left[pos:pos + 4].hex(),
                         "alternate_operand": right[pos:pos + 4].hex()})
    if any(a != b for i, (a, b) in enumerate(zip(left, right)) if i not in mask):
        raise ValueError("non-operand bytes in pair differ")
    return {"variant": kind, "ordinary_start_va": hex(left_va), "alternate_start_va": hex(right_va),
            "byte_count_each": len(left), "raw_different_byte_positions": sum(a != b for a, b in zip(left, right)),
            "masked_byte_positions": len(mask), "all_unmasked_bytes_equal": True,
            "normalization": "Only the listed checked four-byte PC-relative operands are masked; this is a within-target comparison, not a source build.",
            "operands": operands}


def project_key(value):
    if type(value) is not int or not 0 <= value < 1 << 256:
        raise ValueError("stack word is not an unsigned 256-bit integer")
    return (value & ((1 << 160) - 1)).to_bytes(20, "big")


def base_charge(remaining, price):
    """Model only the loop's fixed-width base charge and carry branch."""
    if type(remaining) is not int or not 0 <= remaining < 1 << 64:
        raise ValueError("remaining gas outside unsigned 64-bit domain")
    if type(price) is not int or not 0 <= price < 1 << 16:
        raise ValueError("price outside unsigned 16-bit domain")
    return ((remaining - price) & ((1 << 64) - 1), remaining >= price)


def account_classification(mode, code_hash, word, counter, flags, empty_hash):
    """Synthetic model of the two pinned classification windows only."""
    if type(mode) is not int or not 0 <= mode <= 255 or type(flags) is not int or not 0 <= flags <= 255:
        raise ValueError("mode or flags outside byte domain")
    if type(counter) is not int or not 0 <= counter < 1 << 64:
        raise ValueError("counter outside unsigned 64-bit domain")
    if any(type(x) is not bytes or len(x) != 32 for x in (code_hash, word, empty_hash)):
        raise ValueError("classification fields must be 32-byte values")
    if mode <= 2:
        return bool(flags & 0x08) and not bool(flags & 0x04)
    return code_hash in (bytes(32), empty_hash) and word == bytes(32) and counter == 0


def loader_policy(guard, membership):
    """Boolean-domain model; assumes the external policy returns a Boolean."""
    if type(guard) is not bool or type(membership) is not bool:
        raise ValueError("policy inputs must be Boolean")
    if guard and not membership:
        return ("reject", False, False, None)
    return ("accept", not membership, True, int(not membership))


def primary_cost(revision, remaining, loader_tag, call_mode, classified, has_value, cold, additional):
    """Selected primary component; excludes optional secondary-account cost."""
    limit = (1 << 64) - 1
    if (type(revision) is not int or not 0 <= revision <= 255 or
            type(loader_tag) is not int or not 0 <= loader_tag <= 255):
        raise ValueError("revision or loader tag outside byte domain")
    if any(type(n) is not int or not 0 <= n <= limit for n in (remaining, cold, additional)):
        raise ValueError("cost outside unsigned 64-bit domain")
    if any(type(x) is not bool for x in (call_mode, classified, has_value)):
        raise ValueError("selectors must be Boolean")
    guard = revision >= 7 and remaining < cold
    if loader_tag == 2:
        return (guard, "loader_error", None)
    first = cold if revision >= 7 and loader_tag & 1 else 0
    extra = additional if call_mode and classified and (revision < 3 or has_value) else 0
    if first + extra > limit:
        return (guard, "addition_overflow", None)
    return (guard, "ok", first + extra)


def secondary_cost(first_cost, extension, cold, remaining, loader_tag):
    """Selected secondary-key branch after its kind/length predicates pass."""
    limit = (1 << 64) - 1
    if any(type(n) is not int or not 0 <= n <= limit for n in (first_cost, extension, cold, remaining)):
        raise ValueError("cost outside unsigned 64-bit domain")
    if type(loader_tag) is not int or not 0 <= loader_tag <= 255:
        raise ValueError("loader tag outside byte domain")
    partial = first_cost + extension
    if partial > limit:
        return ("extension_overflow", None, None)
    if partial > remaining:
        return ("unfunded_before_lookup", None, None)
    with_cold = partial + cold
    if with_cold > limit:
        return ("guard_overflow", None, None)
    guard = remaining < with_cold
    if loader_tag == 2:
        return ("loader_error", guard, None)
    return ("ok", guard, with_cold if loader_tag & 1 else partial)


def primary_adjustment(has_value, context_flag, coefficient):
    """Model the pinned CALL-mode, classified-account adjustment branch."""
    if type(has_value) is not bool:
        raise ValueError("value selector must be Boolean")
    if type(context_flag) is not int or not 0 <= context_flag <= 255:
        raise ValueError("context flag outside byte domain")
    if type(coefficient) is not int or not 0 <= coefficient < 1 << 64:
        raise ValueError("coefficient outside unsigned 64-bit domain")
    return coefficient if has_value and context_flag != 0 else 0


def accounting_adjustment(gas, available, accumulator, adjustment):
    """Model the selected unsigned deficit and signed-saturating update."""
    limit = (1 << 64) - 1
    if any(type(n) is not int or not 0 <= n <= limit for n in (gas, available, adjustment)):
        raise ValueError("accounting input outside unsigned 64-bit domain")
    if type(accumulator) is not int or not -(1 << 63) <= accumulator < 1 << 63:
        raise ValueError("accumulator outside signed 64-bit domain")
    if available < adjustment:
        deficit = adjustment - available
        if gas < deficit:
            return ("underflow", gas, available, accumulator)
        gas -= deficit
        available = 0
    else:
        available -= adjustment
    signed_adjustment = adjustment if adjustment < 1 << 63 else adjustment - (1 << 64)
    accumulator = min((1 << 63) - 1, max(-(1 << 63), accumulator + signed_adjustment))
    return ("ok", gas, available, accumulator)


def synthetic_gas(remaining, value_cost, access_cost, requested, divisor, stipend, has_value, revision):
    """Restricted normal arm: no secondary adjustment and successful helpers."""
    limit = (1 << 64) - 1
    numbers = (remaining, value_cost, access_cost, requested, divisor, stipend)
    if any(type(x) is not int or not 0 <= x <= limit for x in numbers):
        raise ValueError("gas input outside unsigned 64-bit domain")
    if type(has_value) is not bool or type(revision) is not int or not 0 <= revision <= 255:
        raise ValueError("invalid selector")
    if has_value:
        if remaining < value_cost:
            return ("value_underflow", remaining, None)
        remaining -= value_cost
    if remaining < access_cost:
        return ("access_underflow", remaining, None)
    remaining -= access_cost
    if revision > 1:
        if divisor == 0:
            return ("divisor_error", remaining, None)
        requested = min(requested, remaining - remaining // divisor)
    if requested > remaining:
        return ("forward_underflow", remaining, None)
    remaining -= requested
    child = min(limit, requested + (stipend if has_value else 0))
    return ("ok", remaining, child)


def check_legacy(data):
    authenticate(data, LEGACY_SHA)
    secs = sections(data)
    key, _, key_off = read_va(data, secs, 0x574f0c0, 20)
    if key != bytes(19) + b"\x09":
        raise ValueError("legacy key mismatch")
    slots = relative_relocations(data, secs, {0x574f0b0, 0x5776f28})
    if slots[0x574f0b0]["addend"] != 0x4e9d2a0 or slots[0x5776f28]["addend"] != 0x4e9a8a0:
        raise ValueError("legacy callback relocation mismatch")
    call, _, call_off = read_va(data, secs, 0x4e9d3bd, 6, executable=True)
    if call[:2] != b"\xff\x15" or 0x4e9d3bd + 6 + struct.unpack_from("<i", call, 2)[0] != 0x5776f28:
        raise ValueError("legacy wrapper call mismatch")
    return {"sha256": LEGACY_SHA, "key_va": hex(0x574f0c0), "key_file_offset": hex(key_off),
            "key_bytes": key.hex(), "adapter_slot_va": hex(0x574f0b0),
            "adapter_rela_file_offset": hex(slots[0x574f0b0]["file_offset"]),
            "adapter_va": hex(slots[0x574f0b0]["addend"]),
            "wrapper_call_va": hex(0x4e9d3bd), "wrapper_call_file_offset": hex(call_off),
            "wrapper_call_bytes": call.hex(), "compressor_slot_va": hex(0x5776f28),
            "compressor_rela_file_offset": hex(slots[0x5776f28]["file_offset"]),
            "compressor_va": hex(slots[0x5776f28]["addend"])}


def tsv(header, rows):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
    writer.writerow(header)
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def json_bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def analyze(data):
    authenticate(data)
    secs = sections(data)
    pins = assert_pins(data, secs)
    edges = edge_rows(data, secs)
    boundaries = check_boundaries(data, secs)
    frames = frame_rows(data, secs)
    gates = handler_gate_rows(data, secs)
    functions, selected = selected_fdes(data, secs)
    ends = {start: end for _, start, end in FUNCTIONS}
    pair_results = [compare_pair(data, secs, *pair, ends) for pair in PAIRS]
    classification = classification_pair(data, secs)

    table_specs = (("ordinary", 0x6441f00, 0xf2, 0x299a1d0),
                   ("ordinary", 0x6441f00, 0xf4, 0x2999b00),
                   ("ordinary", 0x6441f00, 0xfa, 0x2999e70),
                   ("alternate", 0x6441210, 0xf1, 0x299a8f0),
                   ("alternate", 0x6441210, 0xf2, 0x299aca0),
                   ("alternate", 0x6441210, 0xf4, 0x299a580),
                   ("alternate", 0x6441210, 0xfa, 0x299b400))
    slots = {base + 8 * opcode for _, base, opcode, _ in table_specs}
    slots.update({0x64e6e00, 0x64e6e08, 0x64e6ce8, 0x64ea6d8,
                  0x64c0748, 0x6493010, 0x64e4fa8})
    relas = relative_relocations(data, secs, slots)
    memcpy = symbol_relocation(data, secs, 0x64df508)
    if memcpy["name"] != "memcpy" or memcpy["symbol_section_index"] != 0 or memcpy["addend"] != 0:
        raise ValueError("driver copy symbol changed")
    tables = []
    for family, base, opcode, target in table_specs:
        slot = base + 8 * opcode
        if relas[slot]["addend"] != target:
            raise ValueError("opcode table relocation changed")
        raw, _, off = read_va(data, secs, slot, 8)
        tables.append((family, hex(base), hex(opcode), hex(slot), hex(off), raw.hex(),
                       hex(relas[slot]["file_offset"]), hex(relas[slot]["info"]), hex(target)))
    expected_targets = {0x64e6e00: 0x4335cf0, 0x64e6e08: 0x546c330,
                        0x64e6ce8: 0x5463980, 0x64ea6d8: 0x5bdf8e0,
                        0x64c0748: 0x5c165b0, 0x6493010: 0x5c16650,
                        0x64e4fa8: 0x5bde820}
    for slot, addend in expected_targets.items():
        if relas[slot]["addend"] != addend:
            raise ValueError("selected relocation addend changed")
    indirect = indirect_rows(data, secs, relas)
    relocation_rows = [(hex(slot), hex(relas[slot]["file_offset"]), hex(relas[slot]["info"]),
                        hex(relas[slot]["addend"])) for slot in sorted(relas)]

    normal_key, normal_sec, normal_off = read_va(data, secs, 0x64c0750, 20)
    scaled_key, scaled_sec, scaled_off = read_va(data, secs, 0x6492ff8, 20)
    divisor_bytes, _, divisor_off = read_va(data, secs, 0x6493018, 8)
    if normal_key != bytes(19) + b"\x09" or scaled_key != normal_key or struct.unpack("<Q", divisor_bytes)[0] != 10:
        raise ValueError("address-09 source records changed")
    constants = {"target_sha256": TARGET_SHA,
                 "address09_ordinary": {"va": hex(0x64c0750), "file_offset": hex(normal_off),
                                         "section": normal_sec["name"], "bytes": normal_key.hex()},
                 "address09_scaled": {"va": hex(0x6492ff8), "file_offset": hex(scaled_off),
                                       "section": scaled_sec["name"], "bytes": scaled_key.hex(),
                                       "divisor_va": hex(0x6493018), "divisor_file_offset": hex(divisor_off),
                                       "divisor": struct.unpack("<Q", divisor_bytes)[0]}}
    first, _, first_off = read_va(data, secs, 0x4537f0, 16)
    second, _, second_off = read_va(data, secs, 0x452020, 16)
    constants["code_comparison_literal"] = {"first_va": hex(0x4537f0), "first_file_offset": hex(first_off),
                                             "second_va": hex(0x452020), "second_file_offset": hex(second_off),
                                             "bytes": (first + second).hex()}
    empty_hash = first + second
    if empty_hash != bytes.fromhex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"):
        raise ValueError("classification literal changed")

    exception_headers, exceptions = [], []
    for label, start, _ in FUNCTIONS:
        header, rows = decode_lsda(data, secs, selected[start])
        if header is not None:
            exception_headers.append(dict(label=label, **header))
            exceptions.extend(rows)

    # The pinned stack loads, swaps and stores support this lane projection;
    # it is a static model, not an executed transaction.
    lane_rows = [(variant, i, 19 - i, 0x90 + i, i)
                 for variant in ("delegate", "static", "callcode", "alternate_call") for i in range(20)]
    target_cases = [(f"{value:064x}", project_key(value).hex(), int(project_key(value) == normal_key))
                    for value in (0, 8, 9, 10, (1 << 160) | 9, (1 << 256) - 1)]
    zero, one = bytes(32), bytes(31) + b"\x01"
    classification_cases = []
    for mode, hash_field, word, counter, flags in ((2, one, one, 1, 0x08),
                                                   (2, zero, zero, 0, 0x0c),
                                                   (2, zero, zero, 0, 0x00),
                                                   (3, empty_hash, zero, 0, 0x00),
                                                   (3, zero, zero, 0, 0x00),
                                                   (3, one, zero, 0, 0x00),
                                                   (3, empty_hash, one, 0, 0x00),
                                                   (3, empty_hash, zero, 1, 0x00),
                                                   (255, zero, zero, 0, 0xff)):
        classification_cases.append((mode, hash_field.hex(), word.hex(), counter, hex(flags),
                                     int(account_classification(mode, hash_field, word, counter, flags, empty_hash))))
    policy_cases = [(int(guard), int(member), *loader_policy(guard, member))
                    for guard in (False, True) for member in (False, True)]
    primary_cases = []
    for case in ((6, 999, 1, False, False, False, 1000, 25000),
                 (7, 999, 1, False, False, False, 1000, 25000),
                 (7, 1000, 0, False, False, False, 1000, 25000),
                 (2, 50000, 1, True, True, False, 1000, 25000),
                 (3, 50000, 1, True, True, False, 1000, 25000),
                 (7, 50000, 1, True, True, True, 1000, 25000),
                 (7, 50000, 1, False, True, True, 1000, 25000),
                 (7, 0, 2, True, True, True, 1000, 25000),
                 (7, 0, 1, True, True, True, (1 << 64) - 1, 1)):
        guard, outcome, cost = primary_cost(*case)
        primary_cases.append((*case, int(guard), outcome, "" if cost is None else cost))
    secondary_cases = []
    for case in ((100, 25, 50, 124, 0),
                 (100, 25, 50, 125, 0),
                 (100, 25, 50, 174, 1),
                 (100, 25, 50, 175, 1),
                 (100, 25, 50, 175, 2),
                 ((1 << 64) - 1, 1, 0, (1 << 64) - 1, 0),
                 ((1 << 64) - 2, 0, 2, (1 << 64) - 1, 0)):
        outcome, guard, cost = secondary_cost(*case)
        secondary_cases.append((*case, outcome, "" if guard is None else int(guard), "" if cost is None else cost))
    accounting_cases = []
    for case in ((4, 3, 0, 8), (5, 3, 0, 8), (5, 8, 0, 8),
                 (0, 1, (1 << 63) - 1, 1),
                 (0, (1 << 64) - 1, -(1 << 63), (1 << 64) - 1)):
        accounting_cases.append((*case, *accounting_adjustment(*case)))
    adjustment_cases = [(int(has_value), flag, coefficient, primary_adjustment(has_value, flag, coefficient))
                        for has_value, flag, coefficient in ((False, 0, 77), (False, 1, 77),
                                                             (True, 0, 77), (True, 1, 77),
                                                             (True, 255, 77), (True, 1, (1 << 64) - 1))]
    gas_cases = []
    for case in ((8999, 9000, 100, 20000, 64, 2300, True, 13),
                 (9000, 9000, 100, 20000, 64, 2300, True, 13),
                 (9100, 9000, 100, 20000, 64, 2300, True, 13),
                 (100000, 9000, 100, 50000, 64, 2300, True, 13),
                 (100000, 9000, 100, 99999, 64, 2300, False, 13),
                 (100, 0, 0, 101, 64, 0, False, 1),
                 (100, 0, 0, 100, 0, 0, False, 13)):
        outcome, parent, child = synthetic_gas(*case)
        gas_cases.append((*case, outcome, parent, "" if child is None else child))
    loop_cases = []
    for remaining, price in ((0, 0), (0, 1), (1, 1), (9, 10), (10, 9), ((1 << 64) - 1, (1 << 16) - 1)):
        stored, call_handler = base_charge(remaining, price)
        loop_cases.append((remaining, price, stored, int(call_handler)))

    summary = {"target_sha256": TARGET_SHA, "selected_fdes": len(functions),
               "selected_fde_bytes": sum(item["size"] for item in functions),
               "selected_opcode_slots": len(tables), "paired_body_comparisons": len(pair_results),
               "fixed_byte_windows": len(pins), "selected_direct_transfers": len(edges),
               "prior_boundary_windows": len(boundaries), "frame_mode_rows": len(frames),
               "handler_gate_rows": len(gates),
               "indirect_relocated_transfers": len(indirect),
               "selected_symbol_relocations": 1,
               "selected_relative_relocations": len(relocation_rows),
               "selected_lsdas": len(exception_headers), "selected_lsda_call_sites": len(exceptions),
               "projected_key_lanes": len(lane_rows), "synthetic_gas_cases": len(gas_cases),
               "synthetic_base_charge_cases": len(loop_cases), "synthetic_target_cases": len(target_cases),
               "classification_window_pairs": 1, "synthetic_classification_cases": len(classification_cases),
               "synthetic_loader_policy_cases": len(policy_cases), "synthetic_primary_cost_cases": len(primary_cases),
               "synthetic_secondary_cost_cases": len(secondary_cases),
               "synthetic_accounting_cases": len(accounting_cases),
               "synthetic_adjustment_selection_cases": len(adjustment_cases),
               "limitations": "Static selected evidence only; no target execution, complete CFG, live provider selection, component gate, or source-build equivalence."}
    return {
        "functions.json": json_bytes(functions),
        "paired-bodies.json": json_bytes(pair_results),
        "classification-pair.json": json_bytes(classification),
        "constants.json": json_bytes(constants),
        "dynamic-symbol.json": json_bytes(memcpy),
        "exception-headers.json": json_bytes(exception_headers),
        "summary.json": json_bytes(summary),
        "windows.tsv": tsv(("label", "va", "file_offset", "section", "bytes"), pins),
        "prior-boundaries.tsv": tsv(("label", "va", "file_offset", "section", "bytes"), boundaries),
        "edges.tsv": tsv(("label", "kind", "va", "file_offset", "section", "bytes", "target_va"), edges),
        "indirect.tsv": tsv(("label", "instruction_va", "file_offset", "bytes", "slot_va", "rela_file_offset", "addend_va"), indirect),
        "frame-modes.tsv": tsv(("handler", "opcode", "entry_va", "copy_va", "frame_base_stack_offset", "copy_size", "value_store_va", "value_store_bytes", "value_tag", "scheme_store_va", "scheme_store_bytes", "scheme_frame_offset", "scheme", "key_store_va", "key_store_bytes", "action_store_va", "action_store_bytes", "host_call_va", "host_mode_argument_bytes", "host_mode_argument"), frames),
        "handler-gates.tsv": tsv(("handler", "stack_status_va", "stack_test_bytes", "stack_branch_bytes", "minimum_stack_words", "stack_status", "short_target_va", "range_call_va", "range_call_bytes", "range_target_va", "allocation_branch_va", "allocation_branch_bytes", "allocation_target_va", "revision_test_va", "revision_failure_predicate", "revision_target_va", "revision_bytes", "static_value_test_va", "static_value_target_va", "static_value_bytes"), gates),
        "relocations.tsv": tsv(("slot_va", "rela_file_offset", "info", "addend_va"), relocation_rows),
        "opcode-table.tsv": tsv(("table", "table_va", "opcode", "slot_va", "slot_file_offset", "slot_bytes", "rela_file_offset", "rela_info", "target_va"), tables),
        "exceptions.tsv": tsv(("function", "lsda_va", "record_file_offset", "start_va", "end_va_exclusive", "landing_va", "action_index", "raw_bytes"), exceptions),
        "key-lanes.tsv": tsv(("variant", "output_byte", "stack_word_le_byte", "frame_byte_offset", "host_key_byte_offset"), lane_rows),
        "target-cases.tsv": tsv(("stack_word_hex", "projected_key_hex", "matches_ordinary_and_scaled_09"), target_cases),
        "classification-cases.tsv": tsv(("mode", "hash_field_hex", "word_hex", "counter", "flags", "classification"), classification_cases),
        "loader-policy-cases.tsv": tsv(("guard", "membership", "outcome", "append_on_miss", "append_on_refresh", "returned_flag"), policy_cases),
        "primary-cost-cases.tsv": tsv(("revision", "remaining", "loader_tag", "call_mode", "classified", "has_value", "cold", "additional", "loader_guard", "outcome", "primary_cost"), primary_cases),
        "secondary-cost-cases.tsv": tsv(("first_cost", "extension", "cold", "remaining", "loader_tag", "outcome", "loader_guard", "access_cost"), secondary_cases),
        "accounting-cases.tsv": tsv(("gas", "available", "accumulator", "adjustment", "outcome", "gas_after", "available_after", "accumulator_after"), accounting_cases),
        "adjustment-cases.tsv": tsv(("has_value", "context_flag", "coefficient", "adjustment"), adjustment_cases),
        "gas-cases.tsv": tsv(("remaining", "value_cost", "access_cost", "requested", "divisor", "stipend", "has_value", "revision", "outcome", "parent_after", "child"), gas_cases),
        "base-charge-cases.tsv": tsv(("remaining", "price", "stored_value", "reaches_call_from_charge"), loop_cases),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--legacy", type=Path, help="optional separately authenticated historical node")
    args = parser.parse_args(argv)
    data = TARGET.read_bytes()
    result = analyze(data)
    legacy = check_legacy(args.legacy.read_bytes()) if args.legacy is not None else None
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in result.items():
        (args.out / name).write_bytes(content)
    print("generated", len(result), "evidence files")
    if legacy is not None:
        print("legacy:", json.dumps(legacy, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as exc:
        print("re21_call_host115:", exc, file=sys.stderr)
        raise SystemExit(1)
