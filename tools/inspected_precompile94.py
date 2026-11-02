"""Extract the selected node #94 inspected-precompile path, without execution.

The instruction predicates below are fixed, reviewed byte shapes, not a general
x86 decoder. All addresses are linked ELF virtual addresses before load bias.
Only the shared ELF and unwind readers and Python's standard library are used.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import struct
from pathlib import Path

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts/node/94/hl-node"
TARGET_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

# These are selected starts, not a census. Endpoints come from the FDEs.
FUNCTIONS = (
    (0x3287AD0, "consuming callback adapter and frame release"),
    (0x32CE340, "revision-12 execution callback constructor"),
    (0x34389A0, "materialized registry to independent address set"),
    (0x34D6480, "borrowed address-set clone"),
    (0x3577310, "owned registry keys to address-set insertion"),
    (0x36E3590, "reserve and extend context address set"),
    (0x379C1D0, "insert one twenty-byte address into context set"),
    (0x37DC350, "inspected adapter setup and execution handoff"),
    (0x37E1590, "inspection-hook and provider installation"),
    (0x37F3A00, "consuming inspection-callback adapter and ownership release"),
    (0x37F3CA0, "consuming inspection-hook adapter"),
    (0x37F4B90, "owned call-frame destructor"),
    (0x37FD850, "revision byte to handler construction"),
    (0x37FFA30, "call-frame snapshot and wrapped callback"),
    (0x3BE3E90, "consume address-set iterator into context set"),
)

# Relocation slots are validated as symbol-free R_X86_64_RELATIVE records.
# Values are independently resolved from .rela.dyn; expected targets fail closed.
DESCRIPTORS = (
    ("hook", 0x56F3AD8, ((0x18, 0x37F3CA0), (0x20, 0x37E1590), (0x28, 0x37E1590))),
    ("private_provider", 0x56DF878, ((0x18, 0x32A1D10), (0x20, 0x3268CE0), (0x28, 0x3268CE0))),
    ("inspection_callback", 0x570A7B0, ((0x18, 0x37F3A00), (0x20, 0x37FFA30), (0x28, 0x37FFA30))),
    ("revision12_inner_callback", 0x56E7120, ((0x18, 0x329AB80), (0x20, 0x3290BF0), (0x28, 0x3287AD0))),
)

# Start and length were reviewed against instruction boundaries. The expected
# bytes below are read from the authenticated target, not binutils output.
PINS = (
    ('request_revision', 0x37ddff9, '488b542418488b82480100000fb78a55010000440fb6ba58010000'),
    ('request_ctor', 0x37de289, '410fb6f7488dbc2440060000e8b6f50100'),
    ('hook_install', 0x37de2df, 'bf08000000ff15eefcf8014885c00f84da1e00004989c54c89304889c74889dee88c320000'),
    ('hook_list', 0x37de30c, '4c3bb424f818000075094889dfff15a974f901488b8424001900004c89f148c1e1044c892c08488d159f57f101488954080849ffc64c89b42408190000'),
    ('provider_gate', 0x37de5b9, '80bc24a02a0000050f858c040000488b8424c03e0000488b8c24c83e0000488b511048ffca4883e2f0488d34104883c610488dbc2438030000ff5128'),
    ('set_extract_call', 0x37de5f5, '488dbc24e0170000488db42438030000e896a3c5ff'),
    ('set_extend_call', 0x37de76c, '4c898424b02a0000488db424a02a0000e80f4ef0ff'),
    ('map_publication', 0x37de8bd, '488b8424c02a000049894720660f6f8424a02a00000f288c24b02a0000410f114f10f3410f7f07'),
    ('frame_gate', 0x37de9a8, '488bb424383e000080be94020000010f851c0500004881c6580100004889f74889deff15b85bf9014885c00f84091f0000'),
    ('execution_call', 0x37de9d9, '488b8c24803f00004c8b8424883f0000498b501048ffca4883e2f0488d34114883c610488dbc24a02a0000488d9424603d00004889c141ff5028'),
    ('execution_result', 0x37dea3b, '4883f8040f8583060000660f6f8424e0170000e947060000'),
    ('revision_switch', 0x37fd86c, '4080fe130f876a030000400fb6c6488d0dffcfd9fc486304814801c8ffe0'),
    ('revision_case12', 0x37fd88a, '488dbc24a0010000488d35e7deef01ba00080000ff153c07f70148c78424980100000000000048c704240000000048c74424080800000048c744241000000000488d7c2418e89c73dbff488d7c2448e86277abff488dbc2488000000e8d5d2abff488dbc24e8000000e8480aadffc683981100000ce9a4060000'),
    ('handler_callbacks_copy', 0x37fe06f, '4881c3e8000000488db424e8000000bab00000004889df41ffd6'),
    ('callback_selected_pair', 0x32ce5f3, '488b4c241048894b20488d0d1d8b410248894b28'),
    ('installer_entry', 0x37e1590, '554157415641554154534881ece80000004889f34889bc24e00000004c8dbe980100004883be98010000000f8456070000'),
    ('installer_opcode_loop', 0x37e15d0, '4e8ba42b980100004e8bb42ba00100004ac7842b9801000001000000488d05bd22f1014a89842ba0010000bf10000000ff15d2c9f8014885c00f842f0700004c89204c8970084a89842b980100004a89ac2ba00100004983c5104981fd00100000759d'),
    ('installer_five_loop', 0x37e163b, '41b5a06690418d45014180fda40fb6e8b8a40000000f44e849833f007461410fb6ddc1e3044d8b241f4d8b741f0849c7041f01000000488d059822f1014989441f08bf10000000ff1550c9f8014885c00f84980600004c01fb4c89204c897008488903488d059b22f101488943084180fda474154189ed4080fda57288eb0a4c89ffe81ec3c3ffeb95'),
    ('old_callback_capture', 0x37e1897, '488b44240848ff000f84a3050000488b8b08010000f048ff010f8e920500004c8da30801000048c74424200100000048c7442428010000004889442430410f1004240f11442438bf28000000ff15efc6f8014885c00f848b0400004989c7488b442440498947200f104424200f104c2430410f114f10410f1107498b0424f048ff0875094c89e7ff15643df9014c89bb08010000488d057e8ef20148898310010000'),
    ('provider_capture', 0x37e1c98, '0fb6839811000048c74424200100000048c744242801000000888424d0000000bfb8000000ff1515c3f8014885c00f846c0100004989c7488d742420bab80000004889c7ff15fec2f801'),
    ('provider_publish', 0x37e1ce2, '488b4348f048ff08750a488d7b48ff155238f9014c897b48488d0577dbef01488943504881c4e80000005b415c415d415e415f5dc3'),
    ('provider_unwind_publish', 0x37e1e4a, '4989c54c897b48488d0520daef01488943504c89efe8ace2e701'),
    ('replay_adapter', 0x37f3ca0, '50488b07488904244889e7e8e0d8feff58c3'),
    ('snapshot_guard', 0x37ffa30, '554157415641554154534881ecb80000004889cb488b2e48837d10000f858d0100004989d74989f44989fe48c74510ffffffffbfa0000000ff156ae5f6014885c00f8477010000'),
    ('snapshot_clone', 0x37ffa7a, '4c897c2408488b4328488b5330488d7340488b4b38488d7c2438ff10488b43588b4b70898c24800000000f1043600f294424708b8b84000000898c24940000000f1043740f118424840000008b8b98000000898c24a80000000f1083880000000f11842498000000488b4b2048894c24300f10030f104b100f294c24200f294424100fb68b9e0000000fb7939c0000000f1043480f114424584889442468888c24ae00000066899424ac000000488d742410baa00000004c89efff15a6e4f601'),
    ('snapshot_append_delegate', 0x37ffb3a, '4c8b7d284c3b7d18750a488d7d18ff15525cf701488b45204e892cf849ffc74c897d2848ff4510498b4424084d8b442410498b481048ffc94883e1f0488d34084883c610488d7c2410488b5424084889d941ff5028'),
    ('snapshot_output', 0x37ffb8f, '0f10442460410f1146500f10442450410f1146400f104424100f104c24200f105424300f105c2440410f115e30410f115620410f114e10410f11064c89f04881c4b80000005b415c415d415e415f5dc3'),
    ('snapshot_failure', 0x37ffbdf, '488d3d52aef001ff153402f701eb10bf08000000bea0000000ff1522e4f6010f0b'),
    ('snapshot_unwind', 0x37ffc00, '4989c64c89efe8854fffffeb22ff1515e5f6014989c6bea00000004c89ef31d2ff15eae3f60148ff4510eb0c4989c648ff4510eb034989c64889dfe8504fffff4c89f7e8c804e601ff15dae4f601'),
    ('delegate_adapter', 0x3287ad0, '415653504889cb4989fe4889d64889cae83b680200488b4328488b7330488d7b40488b5338ff5020bea00000004889df31d2ff1508654e024c89f04883c4085b415ec34989c6bea00000004889df31d2ff15ea644e024c89f7e8e2853d024989c64889dfe8e7b001004c89f7e8cf853d02ff15e1654e02'),
    ('frame_destroy', 0x37f4b90, '415653504889fb488b4728488b77304883c740488b5338ff5020bea00000004889df31d24883c4085b415eff254f94f7014989c6bea00000004889df31d2ff153c94f7014c89f7e834b5e601'),
    ('set_extract_tag', 0x34389ae, '4889fb4c8b3e4d85ff0f84e8000000'),
    ('set_extract_owned', 0x3438a41, '660f6f442460660fd7c0f7d04b8d0c2748ffc14c896c2430488d54243048895424384c897c24404983c7104c897c244848894c24506689442458488d7c2440488d542438e886e81300488b442420488943200f2804240f284c24100f114b100f1103'),
    ('set_extract_borrowed', 0x3438aa5, '488b76084c8b76484883c6284889dfe8c7d909004c897320'),
    ('set_extract_reserve', 0x3438acf, '4989f64889d5e876fe20fe4889ea4c89f6e935ffffff488d5424204889e74989f6b901000000ff1595ac33024c89f6e93effffff'),
    ('set_clone_sizes', 0x34d648b, '4c8b66084d85e47452498d442401b91400000048f7e1702a4883c00f4883e0f0498d5c24114989c74901df0f92c148baf0ffffffffffff7f4939d70f97c208ca7436488d3d92a3dafc488d15cdf51a02be39000000ff15b27b29020f1005f34521020f1147100f1005d84521020f11074889f8e996000000'),
    ('set_key_copy_hash', 0x35774aa, '8d45fff30fbccd21e889c5488b4424206689681848f7d9488d044948c1e004488b4c2430488b19418b4c06e0894c2410410f104406d00f290424488b05f56e1f024c8b08488b4008488b4c240c48334424084c31c948f7e14889c14989d0488b5424044c31ca488b43204833042448f7e24931d04931c84c31c04883f01449f7e148837b10007431'),
    ('set_extend', 0x36e3590, '415653504889f34989fe488b4638488d700148d1ee48837f1800480f44f0483b771077124889df4c89f64883c4085b415ee9ca085000498d56204c89f7b901000000ff15b8010902ebda4989c64889dfe86b58dfff4c89f7e823cbf701'),
    ('set_iterate', 0x3be3e90, '554157415641554154534883ec78f30f6f070f104f100f1057200f105f300f295c24300f295424200f294c2410660f7f04244c8b7c24384d85ff0f84940000004889f30fb76c24304c8b6c24184c8b6424204c8d742440660f1f8400000000006685ed752a66662e0f1f84000000000066410f6f0424660fd7e84981c5c0feffff4983c41081fdffff000074e3f7d58d45fff30fbccd21e889c548f7d9488d048949ffcf418b4c85fc894c2470f3410f6f4485ec660f7f442460894c2450660f7f4424404889df4c89f6e87182bbff4d85ff758c488b04244885c07429488b7424084885f6741ff3480fbcc831d24839f00f47d1488b7c24104883f8110f43d1ff157aa0b8014883c4785b415c415d415e415f5dc34889c366896c24304c896c24184c896424204c897c24384889e7e88c4e8fff4889dfe844c1a701'),
    ('set_insert_hash', 0x379c1d0, '55415741565350488b050222fd014c8b08488b4008488b4e0c483346084c31c948f7e14889c14989d0488b5604488b47204833064c31ca48f7e24931d04931c84c31c04883f01449f7e14831c248837f10000f844a010000'),
    ('set_insert_probe', 0x379c228, '488b0f4c8b4f084989d049c1e83966410f6ec0660f60c0f20f70c000660f70c0444c8d59ec4531f6660f76c931db4c21caf30f6f1411660f6fda660f74d866440fd7fb4585ff7460f3410fbcc74801d04c21c848f7d8488d0480f30f6f1ef3410f6f2483660f74e3660f6e5e1066410f6e6c8310660f74eb660fdbec660fd7edb00181fdffff00000f84b1000000418d47ff664421f84189c775ad666666662e0f1f8400000000004983fe017413660fd7c285c0741ff3440fbcd04901d24d21ca660f74d1660fd7c285c0751b41be01000000eb034531f64801da4883c2104883c310e946ffffff'),
    ('set_insert_publish', 0x379c310, '420fb6041184c00f89830000002401498d52f04c21ca468804114488441110f30f6f47100fb6c0660f6ec8660fc60d3c71a6fc02660ffbc1f30f7f471049f7da4b8d04928b5610895481fcf30f6f06f30f7f4481ec31c04883c4085b415e415f5dc3'),
    ('set_insert_reserve', 0x379c372, '488d47204989f6be010000004889fb4989d74889c2b901000000ff15fe73fd014c89fa4889df4c89f6e988feffff660f6f01660fd7c0f3440fbcd0420fb60411e966ffffff'),
)

PINS += (
    ('context_set_destination', 0x37de60a, '488dbc24e03d0000488b8c24e0170000488b9424e8170000660f6f01488b8424f81700004885d20f84e7000000488d34924c8d0cb5230000004983e1f04a8d340a4883c6114989c84d29c841b910000000'),
    ('context_set_iterator_and_call', 0x37de71e, '4531c94c8d511066440fd7d841f7d34801ca48ffc248898c24b82a00004c899424c02a000048899424c82a00006644899c24d02a000048898424d82a00004c898c24a02a00004889b424a82a00004c898424b02a0000488db424a02a0000e80f4ef0ff'),
    ('installer_opcode_loop_start', 0x37e15c1, '4531ed488d2d1523f1010f1f440000'),
    ('context_stack_base', 0x37de39c, '488dbc24603d0000bab00000004c89feffd5'),
    ('handler_stack_base', 0x37de420, '488dbc24783e0000ba981100004c89e6ffd5'),
    ('post_registry_tag_gate', 0x37de92a, '80bc24a02a0000050f851b010000'),
    ('pre_frame_underflow_gate', 0x37de938, '488b8424383e0000488b9838020000482b5c24180f8214200000'),
    ('pre_frame_tag_gate', 0x37de988, '0fb68424a02a00003c050f85f7040000'),
    ('underflow_failure', 0x37e0966, '488d3dab35f101ff15ddd7f801eb43'),
    ('pre_provider_other_tag', 0x37dea53, 'f30f6f8424a02a00000f108c24b02a00000f118c2458060000f30f7f8424480600004c89a42440060000'),
    ('pre_frame_other_tag', 0x37dee8f, '8b8c24a12a00008b9424a42a00008994244c060000898c2449060000488b8c24a82a0000f30f6f8424b02a0000f30f7f8424580600008884244806000048898c2450060000e99cfbffff'),
    ('builder_null_frame_failure', 0x37e08e2, '488d3d4736f101ff1581dbf801e9c4000000'),
    ('installer_empty_table_alternate', 0x37e1d17, '488d7424204c89ffe81cbec3ffe90af9ffff'),
    ('consuming_snapshot_normal', 0x37f3a00, '415653504889f34989fee821c00000488b0348ff0875094889dfff156824f801488b4308f048ff08750d4883c3084889dfff15511cf8014c89f04883c4085b415ec3'),
    ('consuming_snapshot_unwind', 0x37f3a42, '4989c6488b4308f048ff0875204883c3084889dfff152c1cf801eb11ff15c4a6f7014989c64889dfe8a13200004c89f7e899c6e601ff15aba6f701'),
    ('callback_result_read', 0x37dea13, '488b8424a02a00004c8bac24a82a0000488b9c24b02a00000f108424b82a00000f298424e01700004883f8040f8583060000'),
    ('callback_result_four_package', 0x37df09a, 'f30f7f8424580600004c89ac244806000048899c24500600004c89a424400600004c8bac24d0000000e9b5f9ffff'),
    ('result_sentinel', 0x37de91a, '49bc0200000000000080'),
    ('result_callbacks', 0x37dea7d, '488b8424403f00004c8bb424483f0000498b4e1048ffc94883e1f0488d1c084883c3104889ac24a02a00004c8dbc24a82a0000488db42440060000ba900000004c89ffff151af5f801488dbc24e01700004889de4889ea4c89f941ff5628488b8424503f0000488b8c24583f0000488b511048ffca4883e2f0488d3c104883c710488db424603d0000ff5128'),
    ('result_sentinel_return_path', 0x37debbf, '4c39e675708bb424400100008bbc244301000089bc243b01000089b424380100008bb424380100008bbc243b01000041897d0c4189750941886d084989451049894d18498955204d896500c78424d000000000000000488dbc24603d0000e84e620100488dbc2408020000e861fdc1ffe946020000'),
    ('builder_epilogue', 0x37dee7a, '4c89e84881c4185000005b415c415d415e415f5dc3'),
)

# Each site is a reviewed instruction start. Targets are checked independently
# after the signed displacement is decoded from the image.
EDGES = (
    ("builder_revision_constructor", 0x37DE295, 0x37FD850),
    ("builder_hook_allocation_failure", 0x37DE2ED, 0x37E01CD),
    ("builder_hook_install", 0x37DE2FF, 0x37E1590),
    ("builder_provider_gate_failure", 0x37DE5C1, 0x37DEA53),
    ("builder_copy_registry_addresses", 0x37DE605, 0x34389A0),
    ("builder_extend_context_addresses", 0x37DE77C, 0x36E3590),
    ("builder_post_registry_other_tag", 0x37DE932, 0x37DEA53),
    ("builder_pre_frame_subtract_underflow", 0x37DE94C, 0x37E0966),
    ("builder_pre_frame_other_tag", 0x37DE992, 0x37DEE8F),
    ("builder_underflow_failure_slot", 0x37E096D, 0x576E150),
    ("builder_frame_variant_bypass", 0x37DE9B7, 0x37DEED9),
    ("builder_frame_constructor_slot", 0x37DE9CA, 0x5774588),
    ("builder_null_frame", 0x37DE9D3, 0x37E08E2),
    ("builder_callback_result_other", 0x37DEA3F, 0x37DF0C8),
    ("builder_callback_result_four", 0x37DEA4E, 0x37DF09A),
    ("builder_callback_four_common_handler", 0x37DF0C3, 0x37DEA7D),
    ("builder_result_copy_slot", 0x37DEAC0, 0x576DFE0),
    ("builder_post_callback_result_other", 0x37DEBC2, 0x37DEC34),
    ("builder_result_cleanup_context", 0x37DEC1D, 0x37F4E70),
    ("builder_result_cleanup_auxiliary", 0x37DEC2A, 0x33FE990),
    ("builder_result_return", 0x37DEC2F, 0x37DEE7A),
    ("revision_default", 0x37FD870, 0x37FDBE0),
    ("revision12_group_1", 0x37FD8CF, 0x35B4C70),
    ("revision12_group_2", 0x37FD8D9, 0x32B5040),
    ("revision12_group_3", 0x37FD8E6, 0x32BABC0),
    ("revision12_group_4", 0x37FD8F3, 0x32CE340),
    ("callback_first_null", 0x32CE362, 0x32CE6B0),
    ("installer_empty_table", 0x37E15BB, 0x37E1D17),
    ("installer_empty_table_helper", 0x37E1D1F, 0x341DB40),
    ("installer_empty_table_resume", 0x37E1D24, 0x37E1633),
    ("installer_opcode_allocation_null", 0x37E1609, 0x37E1D3E),
    ("installer_opcode_loop", 0x37E1631, 0x37E15D0),
    ("installer_last_extra_opcode", 0x37E16AD, 0x37E16C4),
    ("installer_callback_allocation_null", 0x37E18EC, 0x37E1D7D),
    ("installer_provider_allocation_null", 0x37E1CC6, 0x37E1E38),
    ("installer_old_provider_drop_slot", 0x37E1CF0, 0x5775548),
    ("installer_unwind_resume", 0x37E1E5F, 0x5660110),
    ("replay_installer", 0x37F3CAB, 0x37E1590),
    ("consuming_snapshot_call", 0x37F3A0A, 0x37FFA30),
    ("consuming_first_count_nonzero", 0x37F3A15, 0x37F3A20),
    ("consuming_first_drop_slot", 0x37F3A1A, 0x5775E88),
    ("consuming_second_count_nonzero", 0x37F3A28, 0x37F3A37),
    ("consuming_second_drop_slot", 0x37F3A31, 0x5775688),
    ("consuming_unwind_count_nonzero", 0x37F3A4D, 0x37F3A6F),
    ("consuming_unwind_cleanup", 0x37F3A6A, 0x37F6D10),
    ("consuming_unwind_resume", 0x37F3A72, 0x5660110),
    ("snapshot_busy", 0x37FFA4C, 0x37FFBDF),
    ("snapshot_allocate_slot", 0x37FFA68, 0x576DFD8),
    ("snapshot_allocation_null", 0x37FFA71, 0x37FFBEE),
    ("snapshot_copy_slot", 0x37FFB34, 0x576DFE0),
    ("snapshot_capacity_available", 0x37FFB42, 0x37FFB4E),
    ("snapshot_grow_slot", 0x37FFB48, 0x57757A0),
    ("snapshot_busy_terminal", 0x37FFBEC, 0x37FFBFE),
    ("snapshot_allocation_error_slot", 0x37FFBF8, 0x576E020),
    ("snapshot_grow_unwind_drop", 0x37FFC06, 0x37F4B90),
    ("snapshot_cleanup_drop", 0x37FFC3B, 0x37F4B90),
    ("delegate_existing_call_boundary", 0x3287AE0, 0x32AE320),
    ("address_set_borrowed", 0x34389B7, 0x3438AA5),
    ("address_set_seed_initialization", 0x3438A14, 0x3438ACF),
    ("address_set_reserve", 0x3438A3B, 0x3438AE5),
    ("address_set_owned_copy", 0x3438A85, 0x3577310),
    ("address_set_borrowed_clone", 0x3438AB4, 0x34D6480),
    ("address_set_seed_helper", 0x3438AD5, 0x1648950),
    ("context_set_reserve", 0x36E35B2, 0x36E35C6),
    ("context_set_extend", 0x36E35C1, 0x3BE3E90),
    ("context_set_reserve_slot", 0x36E35D2, 0x5773790),
    ("context_set_empty_iterator", 0x3BE3ECA, 0x3BE3F64),
    ("context_set_insert", 0x3BE3F5A, 0x379C1D0),
    ("set_empty_growth_budget", 0x379C222, 0x379C372),
    ("set_existing_key", 0x379C2B0, 0x379C367),
    ("set_empty_control", 0x379C2F3, 0x379C310),
)

# Also bind these call slots. The addresses name linked ELF VAs, not host pointers.
SLOTS = {
    0x576DFD8: 0x54C06B0,
    0x576E020: 0x1345E2A,
    0x576E3E0: 0x5788348,
    0x5773790: 0x4E95B80,
    0x5774020: 0x37DC350,
    0x5774588: 0x4E91CB0,
    0x5775548: 0x34390F0,
    0x57757A0: 0x32D5780,
    0x5775688: 0x34390F0,
    0x5775E88: 0x3B7EE30,
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def checked_digest(data, expected=TARGET_SHA256):
    digest = hashlib.sha256(data).hexdigest()
    require(digest == expected, "target SHA-256 mismatch")
    return digest


def file_offset(secs, file_length, va, size):
    """Map one complete, allocated, file-backed section interval, never NOBITS."""
    require(isinstance(va, int) and isinstance(size, int) and va >= 0 and size > 0,
            "invalid virtual address or length")
    require(va + size <= 1 << 64, "virtual address overflow")
    matches = [s for s in secs if s["type"] != 8 and s["flags"] & 2
               and s["address"] <= va and va + size <= s["address"] + s["size"]]
    require(len(matches) == 1, "unmapped, crossing, NOBITS or ambiguous interval")
    section = matches[0]
    offset = section["offset"] + va - section["address"]
    require(offset >= 0 and offset + size <= file_length, "interval outside file")
    return offset


class Image:
    def __init__(self, data):
        checked_digest(data)
        self.data = data
        self.secs = sections(data)
        self._relas = None

    def offset(self, va, size=1):
        return file_offset(self.secs, len(self.data), va, size)

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def u64(self, va):
        return struct.unpack("<Q", self.read(va, 8))[0]

    def s32(self, va):
        return struct.unpack("<i", self.read(va, 4))[0]

    def relative_relocations(self):
        if self._relas is None:
            candidates = [s for s in self.secs if s["name"] == ".rela.dyn" and s["type"] == 4]
            require(len(candidates) == 1, "missing or ambiguous .rela.dyn")
            sec = candidates[0]
            require(sec["size"] % 24 == 0, "truncated RELA table")
            rows = {}
            for off in range(sec["offset"], sec["offset"] + sec["size"], 24):
                raw = self.data[off:off + 24]
                slot, info, addend = struct.unpack("<QQq", raw)
                if slot in rows:
                    raise ValueError("duplicate relocation slot")
                rows[slot] = (info, addend, off, raw)
            self._relas = rows
        return self._relas


def checked_relative(record, slot, expected_target=None):
    require(record is not None, "missing relocation")
    info, addend, off, raw = record
    require(len(raw) == 24, "truncated relocation")
    rslot, rinfo, raddend = struct.unpack("<QQq", raw)
    require((rslot, rinfo, raddend) == (slot, info, addend), "inconsistent relocation")
    require(info == 8, "expected symbol-free R_X86_64_RELATIVE")
    if expected_target is not None:
        require(addend == expected_target, "relocation addend mismatch")
    return {"slot": slot, "info": info, "addend": addend, "file_offset": off, "raw": raw.hex()}


def relative(image, slot, expected_target=None):
    row = checked_relative(image.relative_relocations().get(slot), slot, expected_target)
    # The loader writes this slot; the linked file itself holds a zero word.
    require(image.u64(slot) == 0, "unexpected pre-relocation slot contents")
    return row


def checked_global(record, slot):
    """Validate one symbol-bearing x86-64 GLOB_DAT RELA record."""
    require(record is not None, "missing symbolic relocation")
    info, addend, off, raw = record
    require(len(raw) == 24, "truncated symbolic relocation")
    require(struct.unpack("<QQq", raw) == (slot, info, addend), "inconsistent symbolic relocation")
    symbol = info >> 32
    require(info & 0xFFFFFFFF == 6 and symbol > 0 and addend == 0, "unexpected symbolic relocation")
    return {"slot": slot, "info": info, "addend": addend, "file_offset": off,
            "raw": raw.hex(), "symbol_index": symbol}


def dynamic_import(image, slot, expected_name):
    """Resolve one fixed dynamic symbol using section coordinates from elf_index."""
    row = checked_global(image.relative_relocations().get(slot), slot)
    require(image.u64(slot) == 0, "unexpected pre-relocation symbolic slot contents")
    symbols = [s for s in image.secs if s["name"] == ".dynsym" and s["type"] == 11]
    strings = [s for s in image.secs if s["name"] == ".dynstr" and s["type"] == 3]
    require(len(symbols) == len(strings) == 1, "missing or ambiguous dynamic-symbol section")
    sym, names = symbols[0], strings[0]
    entry_offset = 24 * row["symbol_index"]
    require(entry_offset + 24 <= sym["size"], "dynamic symbol index outside section")
    symbol_va = sym["address"] + entry_offset
    raw = image.read(symbol_va, 24)
    name_offset, info, other, section, value, size = struct.unpack("<IBBHQQ", raw)
    require(name_offset < names["size"], "dynamic symbol name outside section")
    table = image.read(names["address"], names["size"])
    end = table.find(b"\0", name_offset)
    require(end >= 0, "unterminated dynamic symbol name")
    name = table[name_offset:end]
    require(name == expected_name.encode("ascii") and info == 0x12 and other == 0
            and section == 0 and value == 0 and size == 0, "unexpected dynamic symbol")
    return {**row, "name": name.decode("ascii"), "name_va": names["address"] + name_offset,
            "name_file_offset": image.offset(names["address"] + name_offset, len(name) + 1),
            "name_raw": (name + b"\0").hex(), "symbol_va": symbol_va,
            "symbol_file_offset": image.offset(symbol_va, 24), "symbol_raw": raw.hex()}


def checked_bytes(image, va, expected):
    expected = bytes.fromhex(expected) if isinstance(expected, str) else expected
    require(len(expected) > 0 and image.read(va, len(expected)) == expected,
            "reviewed instruction-byte predicate failed")
    return expected


def decode_control(image, va):
    head = image.read(va, 2)
    op = head[0]
    if op in (0xE8, 0xE9):
        length, disp_at, kind = 5, 1, "call" if op == 0xE8 else "jump"
        raw = image.read(va, length)
        displacement = struct.unpack_from("<i", raw, disp_at)[0]
    elif op == 0x0F and 0x80 <= head[1] <= 0x8F:
        length, disp_at, kind = 6, 2, "conditional"
        raw = image.read(va, length)
        displacement = struct.unpack_from("<i", raw, disp_at)[0]
    elif 0x70 <= op <= 0x7F or op == 0xEB:
        length, kind = 2, "jump" if op == 0xEB else "conditional"
        raw = image.read(va, length)
        displacement = struct.unpack_from("<b", raw, 1)[0]
    elif op == 0xFF and head[1] in (0x15, 0x25):
        length, kind = 6, "indirect_slot_call" if head[1] == 0x15 else "indirect_slot_jump"
        raw = image.read(va, length)
        displacement = struct.unpack_from("<i", raw, 2)[0]
    else:
        raise ValueError("unsupported selected control-transfer shape")
    target = va + length + displacement
    require(0 <= target < 1 << 64, "control target overflow")
    return {"site": va, "kind": kind, "bytes": raw.hex(), "target": target}


def checked_control(image, va, expected_target):
    row = decode_control(image, va)
    require(row["target"] == expected_target, "selected control target mismatch")
    return row


def decode_rip_lea(image, va):
    raw = image.read(va, 7)
    require(raw[:2] == b"\x48\x8d" and raw[2] in (0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D),
            "unsupported RIP-relative LEA")
    return va + 7 + struct.unpack_from("<i", raw, 3)[0]


def unwind_records(image):
    secs, table = unwind_index(image.data)
    require(secs == image.secs, "ELF section parser disagreement")
    cies, fdes = eh_frame_records(image.data, secs)
    by_start = {}
    for fde in fdes:
        by_start.setdefault(fde["start"], []).append(fde)
    by_index = {}
    for row in table:
        by_index.setdefault(row["start"], []).append(row)
    selected = []
    for start, role in FUNCTIONS:
        require(len(by_start.get(start, [])) == 1, "missing or duplicate selected FDE")
        require(len(by_index.get(start, [])) == 1, "missing or duplicate unwind index")
        fde = by_start[start][0]
        index = by_index[start][0]
        require(index["fde"] == fde["fde"], "unwind index/FDE mismatch")
        require(fde["end"] > start, "empty FDE")
        body = image.read(start, fde["end"] - start)
        section = next(s for s in image.secs if s["name"] == index["section"])
        require(section["type"] != 8 and section["flags"] & 4
                and start >= section["address"] and fde["end"] <= section["address"] + section["size"],
                "selected FDE outside executable file-backed section")
        require(fde["cie"] in cies, "missing CIE")
        selected.append({**fde, "role": role, "size": len(body), "index": index["index"],
                         "file_offset": image.offset(start, len(body)),
                         "sha256": hashlib.sha256(body).hexdigest(), "bytes": body.hex()})
    return selected


def frame_record(image, va):
    length = struct.unpack("<I", image.read(va, 4))[0]
    require(length not in (0, 0xFFFFFFFF) and length >= 4, "unsupported unwind record")
    return image.read(va, 4 + length).hex()


def decode_lsda(data, pos, end, code_start, code_end):
    """Decode only the LSDA call-site encodings observed for selected FDEs.

    This does not decode type tables, actions or personality semantics.
    The general CIE/FDE/LEB parsing remains in the shared repository reader.
    """
    require(0 <= pos < end <= len(data), "LSDA outside data")
    beginning = pos
    require(pos + 2 <= end, "truncated LSDA header")
    lpstart, ttype = data[pos], data[pos + 1]
    pos += 2
    require(lpstart == 0xFF and ttype in (0xFF, 0x9B), "unsupported LSDA header")
    type_pointer = None
    if ttype != 0xFF:
        type_delta, pos = uleb(data, pos, end)
        type_pointer = pos + type_delta
        require(type_pointer <= end, "LSDA type table outside section")
    require(pos < end and data[pos] == 1, "unsupported LSDA call-site encoding")
    pos += 1
    table_length, pos = uleb(data, pos, end)
    table_start = pos
    table_end = pos + table_length
    require(table_end <= end, "LSDA call-site table outside section")
    require(type_pointer is None or type_pointer >= table_end, "LSDA type table overlaps call sites")
    rows = []
    while pos < table_end:
        record_start = pos
        start, pos = uleb(data, pos, table_end)
        length, pos = uleb(data, pos, table_end)
        landing, pos = uleb(data, pos, table_end)
        action, pos = uleb(data, pos, table_end)
        first, last = code_start + start, code_start + start + length
        landing_va = code_start + landing if landing else None
        require(code_start <= first <= last <= code_end, "LSDA interval outside FDE")
        require(landing_va is None or code_start <= landing_va < code_end,
                "LSDA landing outside FDE")
        rows.append({"start": first, "end": last, "landing": landing_va, "action": action,
                     "raw": data[record_start:pos].hex()})
    require(pos == table_end, "truncated LSDA record")
    return rows, {"lpstart_encoding": lpstart, "ttype_encoding": ttype,
                  "callsite_encoding": 1, "header": data[beginning:table_start].hex(),
                  "callsite_bytes": data[table_start:table_end].hex(),
                  "type_table_offset": type_pointer - beginning if type_pointer is not None else None}


def collect_exceptions(image, fdes):
    exception_sections = [s for s in image.secs if s["name"] == ".gcc_except_table"
                          and s["type"] != 8]
    require(len(exception_sections) == 1, "missing exception table")
    sec = exception_sections[0]
    rows, headers = [], []
    for fde in fdes:
        if fde["lsda"] is None:
            continue
        va = fde["lsda"]
        require(sec["address"] <= va < sec["address"] + sec["size"], "LSDA outside exception table")
        offset = sec["offset"] + va - sec["address"]
        entries, header = decode_lsda(image.data, offset, sec["offset"] + sec["size"],
                                      fde["start"], fde["end"])
        for entry in entries:
            rows.append({"function": fde["start"], **entry})
        headers.append({"function": fde["start"], "lsda": va,
                        "file_offset": offset, **header})
    return rows, headers


def revision_cases(image, owner):
    head = image.read(0x37FD86C, 4)
    require(head[:3] == bytes.fromhex("4080fe"), "revision comparison shape changed")
    last_index = head[3]
    default = checked_control(image, 0x37FD870, 0x37FDBE0)["target"]
    table = decode_rip_lea(image, 0x37FD87A)
    require(table == 0x59A880, "unexpected revision-table address")
    targets = [table + image.s32(table + 4 * n) for n in range(last_index + 1)]
    unique_targets = sorted(set(targets + [default]))
    require(len(unique_targets) == 15, "unexpected revision-case count")
    require(all(owner["start"] <= t < owner["end"] for t in unique_targets),
            "revision target outside selected FDE")
    case_data = {}
    shapes = (
        bytes.fromhex("488d7c2418e8"),
        bytes.fromhex("488d7c2448e8"),
        bytes.fromhex("488dbc2488000000e8"),
        bytes.fromhex("488dbc24e8000000e8"),
    )
    for target in unique_targets:
        # Search only a 120-byte window at each selected case target.
        span = image.read(target, 0x78)
        calls = []
        for shape in shapes:
            require(span.count(shape) == 1, "missing or ambiguous case-call shape")
            position = span.index(shape)
            call_site = target + position + len(shape) - 1
            calls.append(decode_control(image, call_site)["target"])
        store = bytes.fromhex("c68398110000")
        require(span.count(store) == 1, "missing or ambiguous canonical-byte store")
        p = span.index(store)
        canonical = span[p + len(store)]
        case_data[target] = {"canonical": canonical, "calls": calls,
                             "canonical_store": target + p}
    require(case_data[targets[12]]["canonical"] == 12
            and case_data[targets[12]]["calls"][3] == 0x32CE340,
            "revision-12 callback binding changed")
    rows = []
    for raw in range(256):
        target = targets[raw] if raw <= last_index else default
        case = case_data[target]
        rows.append({"requested": raw, "target": target, **case})
    return rows, {"table": table, "table_file_offset": image.offset(table, 4 * len(targets)),
                  "table_hex": image.read(table, 4 * len(targets)).hex(),
                  "last_table_index": last_index, "default": default,
                  "unique_destinations": len(unique_targets)}


def find_shapes(data, shape):
    cursor = 0
    while True:
        cursor = data.find(shape, cursor)
        if cursor < 0:
            return
        yield cursor
        cursor += 1


def callback_records(image, owner):
    # The LEA and following store form is intentionally narrow: only LEA into
    # rax/rcx followed immediately by a store to [rbx+disp8/disp32].
    data = image.read(owner["start"], owner["size"])
    callbacks = []
    for i in range(len(data) - 14):
        if data[i:i + 2] != b"\x48\x8d" or data[i + 2] not in (0x05, 0x0D):
            continue
        if data[i + 7:i + 9] != b"\x48\x89":
            continue
        modrm = data[i + 9]
        reg = data[i + 2]
        if (reg, modrm) not in ((0x05, 0x43), (0x05, 0x83), (0x0D, 0x4B), (0x0D, 0x8B)):
            continue
        disp_size = 1 if modrm in (0x43, 0x4B) else 4
        offset = int.from_bytes(data[i + 10:i + 10 + disp_size], "little", signed=False)
        if offset not in range(8, 0xA9, 0x10):
            continue
        site = owner["start"] + i
        desc = site + 7 + struct.unpack_from("<i", data, i + 3)[0]
        callbacks.append({"lea": site, "output_vtable_offset": offset,
                          "output_data_offset": offset - 8, "descriptor": desc,
                          "method": relative(image, desc + 0x28)["addend"],
                          "bytes": data[i:i + 10 + disp_size].hex()})
    callbacks.sort(key=lambda x: x["output_vtable_offset"])
    require(len(callbacks) == 11 and [r["output_vtable_offset"] for r in callbacks]
            == list(range(8, 0xA9, 0x10)), "callback-pair output mismatch")
    require(callbacks[2]["descriptor"] == 0x56E7120 and callbacks[2]["method"] == 0x3287AD0,
            "selected callback descriptor mismatch")

    # Exact allocator/check pattern, explicitly limited to the constructor FDE.
    prefix = bytes.fromhex("bf10000000ff15")
    checks = []
    for i in find_shapes(data, prefix):
        if i + 20 > len(data) or data[i + 11:i + 16] != bytes.fromhex("4885c00f84"):
            continue
        site = owner["start"] + i
        slot = decode_control(image, site + 5)["target"]
        branch = decode_control(image, site + 14)
        require(owner["start"] <= branch["target"] < owner["end"], "allocation branch outside FDE")
        checks.append({"allocation": site, "requested_size": data[i + 1],
                       "slot": slot, "branch": site + 14, "null_target": branch["target"],
                       "bytes": data[i:i + 20].hex()})
    require(len(checks) == 11, "unexpected callback allocation-check count")
    return callbacks, checks


def installed_wrappers(image, owner):
    # The normal path ends at the return before the failure/landing tails.
    start, end = 0x37E16C4, 0x37E1D17
    require(owner["start"] <= start < end <= owner["end"], "wrapper scan outside FDE")
    data = image.read(start, end - start)
    result = []
    for i in find_shapes(data, bytes.fromhex("488d05")):
        if i + 14 > len(data) or data[i + 7:i + 10] != bytes.fromhex("488983"):
            continue
        site = start + i
        descriptor = site + 7 + struct.unpack_from("<i", data, i + 3)[0]
        if not 0x570A780 <= descriptor <= 0x570A8A0:
            continue
        off = struct.unpack_from("<I", data, i + 10)[0]
        result.append({"lea": site, "descriptor": descriptor,
                       "handler_data_offset": off - 8, "handler_vtable_offset": off,
                       "method": relative(image, descriptor + 0x28)["addend"],
                       "bytes": data[i:i + 14].hex()})
    require(len(result) == 7, "unexpected installed-wrapper count")
    selected = [r for r in result if r["handler_vtable_offset"] == 0x110]
    require(len(selected) == 1 and selected[0]["descriptor"] == 0x570A7B0
            and selected[0]["method"] == 0x37FFA30, "wrapped callback binding mismatch")
    return result


def immediate32(image, site, prefix):
    raw = image.read(site, len(prefix) + 4)
    require(raw.startswith(prefix), "unexpected displacement/immediate shape")
    return struct.unpack_from("<I", raw, len(prefix))[0]


def immediate8(image, site, prefix):
    raw = image.read(site, len(prefix) + 1)
    require(raw.startswith(prefix), "unexpected byte-displacement shape")
    return raw[-1]


def collect_layout(image, callbacks, wrappers):
    handler_stack = immediate32(image, 0x37DE420, bytes.fromhex("488dbc24"))
    context_stack = immediate32(image, 0x37DE39C, bytes.fromhex("488dbc24"))
    factory_data = immediate32(image, 0x37DE5C7, bytes.fromhex("488b8424")) - handler_stack
    factory_vtable = immediate32(image, 0x37DE5CF, bytes.fromhex("488b8c24")) - handler_stack
    callback_data = immediate32(image, 0x37DE9D9, bytes.fromhex("488b8c24")) - handler_stack
    callback_vtable = immediate32(image, 0x37DE9E1, bytes.fromhex("4c8b8424")) - handler_stack
    result_data = immediate32(image, 0x37DEA7D, bytes.fromhex("488b8424")) - handler_stack
    result_vtable = immediate32(image, 0x37DEA85, bytes.fromhex("4c8bb424")) - handler_stack
    post_data = immediate32(image, 0x37DEADB, bytes.fromhex("488b8424")) - handler_stack
    post_vtable = immediate32(image, 0x37DEAE3, bytes.fromhex("488b8c24")) - handler_stack
    context_map = immediate32(image, 0x37DE7B7, bytes.fromhex("4c8dbc24")) - context_stack
    context_set = immediate32(image, 0x37DE60A, bytes.fromhex("488dbc24")) - context_stack
    callback_group = immediate32(image, 0x37FE06F, bytes.fromhex("4881c3"))
    selected = callbacks[2]
    wrapped = next(r for r in wrappers if r["handler_vtable_offset"] == callback_vtable)
    require(factory_data == 0x48 and factory_vtable == 0x50
            and callback_data == callback_group + selected["output_data_offset"]
            and callback_vtable == callback_group + selected["output_vtable_offset"]
            and callback_data == wrapped["handler_data_offset"] and context_map == 0xE8
            and context_set == 0x80 and (result_data, result_vtable) == (0xC8, 0xD0)
            and (post_data, post_vtable) == (0xD8, 0xE0),
            "cross-function handler/context offsets do not compose")

    source_first = immediate8(image, 0x37FFAA4, bytes.fromhex("0f1043"))
    source_last = immediate8(image, 0x37FFA9A, bytes.fromhex("8b4b"))
    staged_first = immediate8(image, 0x37FFAA8, bytes.fromhex("0f294424"))
    staged_last = immediate32(image, 0x37FFA9D, bytes.fromhex("898c24"))
    staged_base = immediate8(image, 0x37FFB27, bytes.fromhex("488d7424"))
    copy_length = immediate32(image, 0x37FFB2C, bytes.fromhex("ba"))
    allocation_size = immediate32(image, 0x37FFA63, bytes.fromhex("bf"))
    require(source_first == staged_first - staged_base == 0x60
            and source_last == staged_last - staged_base == source_first + 16
            and copy_length == allocation_size == 0xA0, "snapshot field-copy mismatch")
    checked_bytes(image, 0x37FFB88, bytes.fromhex("4889d941ff5028"))
    opcode_base = immediate32(image, 0x37E15AC, bytes.fromhex("4c8dbe"))
    opcode_stride = immediate8(image, 0x37E1626, bytes.fromhex("4983c5"))
    opcode_span = immediate32(image, 0x37E162A, bytes.fromhex("4981fd"))
    first_extra = immediate8(image, 0x37E163B, bytes.fromhex("41b5"))
    last_extra = immediate8(image, 0x37E1644, bytes.fromhex("4180fd"))
    require(opcode_stride > 0 and opcode_span % opcode_stride == 0
            and first_extra <= last_extra, "invalid installer loop bounds")
    require(relative(image, 0x5774588, 0x4E91CB0)["addend"] == 0x4E91CB0,
            "external frame-builder relocation changed")
    return {
        "builder": {
            "context_stack_offset": context_stack, "handler_stack_offset": handler_stack,
            "handler_factory_data_offset": factory_data, "handler_factory_vtable_offset": factory_vtable,
            "handler_callback_data_offset": callback_data, "handler_callback_vtable_offset": callback_vtable,
            "handler_result_data_offset": result_data, "handler_result_vtable_offset": result_vtable,
            "handler_post_data_offset": post_data, "handler_post_vtable_offset": post_vtable,
            "context_registry_offset": context_map, "context_address_set_offset": context_set,
            "handler_callback_group_offset": callback_group,
            "frame_variant_offset": immediate32(image, 0x37DE9B0, bytes.fromhex("80be")),
            "frame_constructor_argument_adjustment": immediate32(image, 0x37DE9BD, bytes.fromhex("4881c6")),
        },
        "installer": {
            "opcode_array_offset": opcode_base, "opcode_stride": opcode_stride,
            "opcode_span": opcode_span, "opcode_pair_count": opcode_span // opcode_stride,
            "extra_opcode_first": first_extra, "extra_opcode_last": last_extra,
            "extra_opcode_count": last_extra - first_extra + 1,
        },
        "snapshot": {
            "frame_bytes": copy_length, "address_source_offset": source_first,
            "address_last_word_offset": source_last, "address_length": source_last - source_first + 4,
            "temporary_stack_base": staged_base, "temporary_address_offset": staged_first,
            "temporary_last_word_offset": staged_last,
            "guard_offset": immediate8(image, 0x37FFA47, bytes.fromhex("48837d")),
            "vector_capacity_offset": immediate8(image, 0x37FFB3E, bytes.fromhex("4c3b7d")),
            "vector_pointer_offset": immediate8(image, 0x37FFB4E, bytes.fromhex("488b45")),
            "vector_length_offset": immediate8(image, 0x37FFB3A, bytes.fromhex("4c8b7d")),
            "delegate_vtable_offset": immediate8(image, 0x37FFB66, bytes.fromhex("4d8b4424")),
        },
        "address_set": {
            "iterator_remaining_offset": immediate8(image, 0x36E359A, bytes.fromhex("488b46")),
            "set_growth_offset": immediate8(image, 0x36E35AE, bytes.fromhex("483b77")),
            "set_count_offset": immediate8(image, 0x36E35A5, bytes.fromhex("48837f")),
            "key_width": immediate8(image, 0x379C213, bytes.fromhex("4883f0")),
        },
        "limitations": "Field and dataflow composition assumes the selected normal-return path, "
                       "ordinary allocator/copy behavior and nonaliasing across dynamic callbacks.",
    }


def tsv(columns, rows):
    output = io.StringIO(newline="")
    writer = csv.writer(output, delimiter="\t", lineterminator="\n")
    writer.writerow(columns)
    writer.writerows(rows)
    return output.getvalue().encode("ascii")


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def hx(value):
    return "" if value is None else hex(value)


def collect(image):
    fdes = unwind_records(image)
    owners = {x["start"]: x for x in fdes}
    windows = []
    for name, va, expected in PINS:
        raw = checked_bytes(image, va, expected)
        containing = [f for f in fdes if f["start"] <= va and va + len(raw) <= f["end"]]
        require(len(containing) == 1, "semantic window outside or across selected FDE")
        windows.append({"name": name, "function": containing[0]["start"], "va": va,
                        "file_offset": image.offset(va, len(raw)), "bytes": raw.hex()})

    transfers = []
    for name, va, target in EDGES:
        row = checked_control(image, va, target)
        containing = [f for f in fdes if f["start"] <= va < f["end"]]
        require(len(containing) == 1, "control transfer outside selected FDE")
        transfers.append({"name": name, "function": containing[0]["start"], **row})

    relocation_rows = {}
    for slot, target in SLOTS.items():
        relocation_rows[slot] = relative(image, slot, target)
    descriptor_rows = []
    for name, base, methods in DESCRIPTORS:
        size, alignment = image.u64(base + 8), image.u64(base + 16)
        require(alignment > 0 and alignment & (alignment - 1) == 0, "invalid vtable alignment")
        for offset, target in methods:
            row = relative(image, base + offset, target)
            relocation_rows[row["slot"]] = row
            descriptor_rows.append({"name": name, "descriptor": base, "payload_size": size,
                                    "payload_alignment": alignment, "method_offset": offset,
                                    "slot": row["slot"], "target": row["addend"]})

    revisions, revision_meta = revision_cases(image, owners[0x37FD850])
    callbacks, allocations = callback_records(image, owners[0x32CE340])
    wrappers = installed_wrappers(image, owners[0x37E1590])
    for entry in callbacks:
        relocation_rows[entry["descriptor"] + 0x28] = relative(image, entry["descriptor"] + 0x28)
    for entry in wrappers:
        relocation_rows[entry["descriptor"] + 0x28] = relative(image, entry["descriptor"] + 0x28)
    layout = collect_layout(image, callbacks, wrappers)
    symbol_imports = [dynamic_import(image, 0x576DFE0, "memcpy")]
    exceptions, exception_headers = collect_exceptions(image, fdes)

    # Actual records, not the next unwind-index start, define each selected span.
    unwind = []
    for f in fdes:
        unwind.append({"start": f["start"], "end": f["end"], "fde": f["fde"],
                       "fde_raw": frame_record(image, f["fde"]), "cie": f["cie"],
                       "cie_raw": frame_record(image, f["cie"]), "lsda": f["lsda"]})
    counts = {
        "selected_fde_count": len(fdes), "selected_fde_bytes": sum(f["size"] for f in fdes),
        "semantic_windows": len(windows), "selected_control_transfers": len(transfers),
        "revision_inputs": len(revisions), "revision_case_destinations": revision_meta["unique_destinations"],
        "callback_pairs": len(callbacks), "callback_allocation_checks": len(allocations),
        "installed_wrappers": len(wrappers), "selected_relocations": len(relocation_rows),
        "selected_symbolic_relocations": len(symbol_imports),
        "lsda_functions": len(exception_headers), "lsda_callsite_records": len(exceptions),
        "lsda_records_with_landing": sum(r["landing"] is not None for r in exceptions),
    }
    files = {
        "functions.tsv": tsv(
            ["start_va", "end_va", "bytes", "file_offset", "fde_va", "cie_va", "lsda_va", "sha256", "role"],
            [[hx(f["start"]), hx(f["end"]), f["size"], hx(f["file_offset"]), hx(f["fde"]),
              hx(f["cie"]), hx(f["lsda"]), f["sha256"], f["role"]] for f in fdes]),
        "function-bytes.json": json_bytes({
            "target_sha256": TARGET_SHA256,
            "functions": [{"start": hx(f["start"]), "end": hx(f["end"]), "sha256": f["sha256"],
                           "bytes": f["bytes"]} for f in fdes]}),
        "unwind-records.json": json_bytes(unwind),
        "semantic-windows.tsv": tsv(
            ["name", "function_va", "start_va", "file_offset", "bytes"],
            [[w["name"], hx(w["function"]), hx(w["va"]), hx(w["file_offset"]), w["bytes"]] for w in windows]),
        "control-edges.tsv": tsv(
            ["name", "function_va", "site_va", "kind", "instruction_bytes", "target_or_slot_va"],
            [[r["name"], hx(r["function"]), hx(r["site"]), r["kind"], r["bytes"], hx(r["target"])]
             for r in transfers]),
        "revision-cases.tsv": tsv(
            ["requested_byte", "case_va", "canonical_byte", "canonical_store_va",
             "group1_va", "group2_va", "group3_va", "group4_va"],
            [[r["requested"], hx(r["target"]), r["canonical"], hx(r["canonical_store"])]
             + [hx(x) for x in r["calls"]] for r in revisions]),
        "revision-table.json": json_bytes(revision_meta),
        "callback-pairs.tsv": tsv(
            ["lea_va", "output_data_offset", "output_vtable_offset", "descriptor_va", "method_plus_28_va", "bytes"],
            [[hx(r["lea"]), hx(r["output_data_offset"]), hx(r["output_vtable_offset"]),
              hx(r["descriptor"]), hx(r["method"]), r["bytes"]] for r in callbacks]),
        "callback-allocation-failures.tsv": tsv(
            ["allocation_va", "requested_bytes", "slot_va", "null_branch_va", "null_target_va", "bytes"],
            [[hx(r["allocation"]), r["requested_size"], hx(r["slot"]), hx(r["branch"]),
              hx(r["null_target"]), r["bytes"]] for r in allocations]),
        "installed-wrappers.tsv": tsv(
            ["lea_va", "handler_data_offset", "handler_vtable_offset", "descriptor_va", "method_plus_28_va", "bytes"],
            [[hx(r["lea"]), hx(r["handler_data_offset"]), hx(r["handler_vtable_offset"]),
              hx(r["descriptor"]), hx(r["method"]), r["bytes"]] for r in wrappers]),
        "descriptors.tsv": tsv(
            ["name", "descriptor_va", "payload_size", "alignment", "method_offset", "slot_va", "target_va"],
            [[r["name"], hx(r["descriptor"]), r["payload_size"], r["payload_alignment"],
              hx(r["method_offset"]), hx(r["slot"]), hx(r["target"])] for r in descriptor_rows]),
        "relocations.tsv": tsv(
            ["slot_va", "r_info", "addend_va", "file_offset", "raw_rela"],
            [[hx(r["slot"]), hx(r["info"]), hx(r["addend"]), hx(r["file_offset"]), r["raw"]]
             for _, r in sorted(relocation_rows.items())]),
        "dynamic-imports.tsv": tsv(
            ["name", "slot_va", "r_info", "addend", "rela_file_offset", "raw_rela",
             "symbol_index", "symbol_va", "symbol_file_offset", "raw_symbol",
             "name_va", "name_file_offset", "raw_name"],
            [[entry["name"], hx(entry["slot"]), hx(entry["info"]),
              entry["addend"], hx(entry["file_offset"]), entry["raw"],
              entry["symbol_index"], hx(entry["symbol_va"]), hx(entry["symbol_file_offset"]),
              entry["symbol_raw"], hx(entry["name_va"]), hx(entry["name_file_offset"]),
              entry["name_raw"]] for entry in symbol_imports]),
        "exception-sites.tsv": tsv(
            ["function_va", "start_va", "end_va", "landing_va", "action_index", "raw"],
            [[hx(r["function"]), hx(r["start"]), hx(r["end"]), hx(r["landing"]), r["action"], r["raw"]]
             for r in exceptions]),
        "exception-headers.json": json_bytes(exception_headers),
        "layout.json": json_bytes(layout),
        "summary.json": json_bytes({"target_sha256": TARGET_SHA256, "counts": counts,
                                    "limitations": "Static selected FDEs and fixed byte shapes only; "
                                                   "no execution, full CFG, component coverage or equivalence."}),
    }
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    image = Image(TARGET.read_bytes())
    files = collect(image)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(files.items()):
        (args.out / name).write_bytes(content)


if __name__ == "__main__":
    main()
