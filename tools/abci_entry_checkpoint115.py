#!/usr/bin/env python3
"""Trace the selected #115 process-entry and checkpoint-result connection."""

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
HISTORICAL_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# These are selected instruction-aligned byte patterns, not a disassembler or
# a claim that every branch in the surrounding functions has been recovered.
WINDOWS = [
    ('process_entry', 'context', 0x1419300, 'f30f1efa31ed4989d15e4889e24883e4f050544531c031c9488d3dd1658d01ff1533610c05f4'),
    ('main_bridge', 'context', 0x2cef8f0, '504889f14863d7488d05728afeff48890424488d353f1275034889e74531c0ff151b737f0359c3'),
    ('runtime_arg_save', 'context', 0x5c99984, '4589c549c7c0e0fbffff644d8b084d85c97526488b05b266860066904883f8ff0f84ca0400004c8d4801f04c0fb10d9966860075e7644d8908488955b048894da848897da0488975984c890d14668600'),
    ('runtime_dispatch', 'context', 0x5c99e03, '488b45b0488905f2618600488b45a8488905ef618600488b7da0488b4598ff50284863d88b05634f860085c0754d'),
    ('runtime_return', 'context', 0x5c99e31, 'ff15916184004889c131c0f0480fb10d3362860075154889d84881c4d80000005b415c415d415e415f5dc3'),
    ('runtime_failure_landing', 'context', 0x5c99f54, '4889c7ff152b5f84004c8b252c5f8400f049ff0c244989c66448ff0c25a0fbffff4989d764c60425a8fbffff00488b024885c074054c89f7ffd0498b7708bb650000004885f60f8487feffff498b4710f3480fbcc831d24839f00f47d14883f8110f43d14c89f7ff15df548400e961feffff'),
    ('runtime_thread_fail', 'context', 0x5c999a0, '4883f8ff0f84ca040000'),
    ('runtime_mode_fail', 'context', 0x5c99b28, '4180fd030f87f2030000'),
    ('main_shim', 'new', 0x292c5c0, '50488b3fe8a7f5340031c059c3'),
    ('alternative_shim', 'new', 0x292e230, '50488b3fe837d9340031c059c3'),
    ('function_thunk', 'new', 0x2c7bb70, '50ffd758c3'),
    ('main_callback', 'context', 0x2cd8370, '4881ec0010000048c70424000000004881ec0010000048c70424000000004881ec480c0000c684242202000000488d7c2408e8e992e0ff4881c4482c0000c3'),
    ('parent_poll_select', 'context', 0x2ae18cb, '4883bc24e00000000148895c24100f852b020000'),
    ('parent_poll_call', 'context', 0x2ae1edb, '488dbc2480000000488db424682e0000e840c51f0089c580fb02741648c7c1d0eeffff640fb6414883f801744883f802751b4080fd027450'),
    ('poll_gate', 'context', 0x2cde48d, '84c00f84710200004d8b2e410fb6851a020000488d0de1da92fd486304814801c8ffe0'),
    ('poll_initial_state', 'context', 0x2cde4b0, '0f57c0410f11850502000049c7851202000000000000'),
    ('poll_command_table', 'context', 0x2cde64b, '498d85c0000000488b004889c14883e902ba0c000000480f43d14d8da5a8000000488d0d4dd992fd486314914801caffe2'),
    ('poll_two_construct', 'context', 0x2cde6c2, '498b8de800000049898d4002000041c68548020000024188859002000041c68591020000004d8db5200200004c89f74889dee8077efdff84c07410b002b104e91e180000'),
    ('poll_one_construct', 'context', 0x2cdf559, '498b8de800000049898d4002000041c68548020000014188859002000041c68591020000004d8da5200200004c89e74889dee8706ffdff84c07409b002b103e987090000'),
    ('parent_loader_parent', 'context', 0x2cb7761, '488dbc24300700004c89f6488b542408e86a44000083bc243007000002750941c60703e994080000'),
    ('loader_middle_call', 'context', 0x2cbc063, '48896c24204889eae8005be8ff48bd0000000000000080488d450148398424a80600007507b003e96c1a0000'),
    ('loader_middle_boundary', 'context', 0x2b41f20, '488dbc2430040000488d742470ff15f5579a034889c548894340'),
    ('loader_location_boundary', 'context', 0x3c12899, '4889e24c89ef4c89f1ff15806d8d024989d44883f8010f8438010000'),
    ('loader_location', 'context', 0x3c13520, '41574156534883ec504989ce4889d3488d1572328602e8d5ae61004883f8017546'),
    ('parent_mode_save', 'context', 0x2cb758f, '0fb68b200b00000fb6ab210b0000c6831f2a0000014c89a42488000000c6831e2a0000014c8bb3e80a0000488b83f00a000048894424600fb683000b0000888b192a0000'),
    ('checkpoint_arg', 'context', 0x2cb7959, '0fb6b3192a0000488dbc2478020000488d942418010000ff15c2fa8203'),
    ('checkpoint_entry', 'context', 0x5a6dd30, '554157415641554154534881ece80000004989d489f54989ff'),
    ('checkpoint_gates', 'context', 0x5a6de21, '4080fd020f84000200004c89b424d80000004c89ac24e0000000488d7c2450ff150a32a70048b8000000000000008048394424500f84c2010000'),
    ('checkpoint_sentinel_rejoin', 'context', 0x5a6e01d, '8b05b521a80085c00f8584000000'),
    ('checkpoint_flag_height', 'context', 0x5a6e02b, '31c04080fd020f95c0498b0c244c8b4928890424488d0db2ccecfa41b80c0000004c89ff4c89f64c89eaff1515dfa700'),
    ('builder_args', 'context', 0x595ac30, '554157415641554154534881ec080100004c894c24584989fe4889b424d800000048899424e000000048898c24e80000004c898424f0000000'),
    ('builder_flag_load', 'context', 0x595ae9d, '0fb68424400100000f10442448'),
    ('builder_flag_height', 'context', 0x595aee3, '0f10842490000000410f1106488b4c245849894e6841884670'),
    ('stage_register_copy', 'context', 0x2cb7cd2, '488b8424e802000048898424200d00000f108424d80200000f298424100d0000'),
    ('stack_copy_a', 'context', 0x2cb7e6c, '488db424380700004c8dbc2410320000bab80600004c89ffffd5'),
    ('stack_copy_b', 'context', 0x2cb7ffe, '488dbc2440270000baf00700004c89feffd5'),
    ('parent_pending_gate', 'context', 0x2cb8010, 'c683182a0000014983fc02751cb0044c8b7c2420488b4c24508801b003418807b001b104e99b370000'),
    ('stack_copy_c', 'context', 0x2cb8039, '488dbc24501f0000488db42440270000baf0070000ff15b4748203'),
    ('parent_store', 'context', 0x2cb806f, '488dbba0010000488db424501f0000bab8060000ffd5'),
    ('callback_copy', 'context', 0x2cb97aa, '488db3980100004c89bc2440270000c683e20a000000c683dc0a000000c683da0a000000488dbc2430070000bac0060000ff15275d8203'),
    ('callback_allocate', 'context', 0x2cb984d, 'bf18070000ff15285c82034885c00f84870500004989c6488db42430070000ba180700004889c7ff158e5c8203488d3da05795fd488d0d18d97803be190000004c89f2ff15ba7e8203'),
    ('callback_adapter', 'context', 0x2a92960, '4156534883ec584889fb8bb7100700000f1087c00600000f108fd00600000f294c24400f29442430488b870007000048894424200f1087e00600000f108ff00600000f294c24100f2904244c8b8708070000488d5424304889e1ff151048a5034889dfe878c00100'),
    ('worker_entry', 'context', 0x5a6e1e0, '554157415641554154534881ec580d00004c89c54989cd4889942460010000897424584889fb4c89842430020000'),
    ('worker_sink_save', 'context', 0x5a6e273, '488d4340488984249003000048895c2428488d838005000048898424a0030000'),
    ('worker_receive_gate', 'context', 0x5a6e318, '488dbc2468040000488bb42460010000e8c38a040083bc2468040000010f854c1d0000'),
    ('worker_block_call', 'context', 0x5a6e9ad, '498b9fa00600004c8d7310488d0558c7ecfa48898424b801000048c78424c00100001900000048c78424b0010000000000004881c3400100004c89b424b00200004c89ac24b80200004889ef4889de488d94249002000031c94c8d05d3a1a4004d89e5e8ab384aff'),
    ('worker_sink_call', 'context', 0x5a6f979, '488bbc24a0030000488bb42420010000488d942490020000e81aadeeff'),
    ('sink_bucket', 'context', 0x595a6c1, '31c0483b47180f809f04000048899424b0000000488d5f184883fe014883d6ff48b94b598638d6c56d344889f048f7e148c1ea0b4c69f2102700004c3b77680f8621040000'),
    ('sink_roll_gate', 'context', 0x595a7a5, '4d89756841807d70000f850c030000'),
    ('sink_directory_predicate', 'context', 0x595a83e, '4c89ff4c89e6ff15de60b80084c00f846e020000488dbc24c00000004c89fe4c89e2ff156a61b80083bc24c0000000017512488bbc24c8000000488b07ff10e93e020000'),
    ('directory_adapter_entry', 'context', 0x15021d0, '534883ec704889fb488974246048895424684889e7ff1585e7fd040fb6442408488b3c243c020f848f00000048897c240888442410488d44246048890424488d7c24204889e6e8e5380b00'),
    ('directory_adapter_transfer', 'context', 0x150221b, '488b442420488b4c24284889c24885c07405488b542430400f95c6400fb6f6488974241848c744242000000000488944242848894c2430488974243848c744244000000000488944244848894c24504889542458488d7b08488d742418e863370b0031c04889034889d84883c4705bc3'),
    ('directory_adapter_error', 'context', 0x150228b, 'e8f0a6fcff48894308b801000000ebe4'),
    ('row32_collect', 'new', 0x15b5b00, '41574156534883ec404889fb488b461048894424300f10060f29442420488d7c2408488d742420e8d49df8ff4c8b7424184d85f6743a4c8b7c24104983fe017566488b44240849c1e6054d01fe4c897c24204c897c242848894424304c89742438488d7424204889dfe87241f8ffeb2a48c7030000000048c7431000000000488b7424084885f67411488b7c241048c1e60531d2ff150699f2044889d84883c4405b415e415fc3'),
    ('row32_sort', 'new', 0x15b5ba7, '4983fe15731a488d4c2407ba010000004c89ff4c89f6e85e13f1ffe97affffff488d5424074c89ff4c89f6ff1588b2f204e964ffffff4889c3488d7c2408e8c69f00004889dfe85eaee304'),
    ('row24_collect', 'new', 0x15b59e0, '41574156534883ec704889fb488b464048894424600f10060f104e100f1056200f105e300f295c24500f295424400f294c24300f29442420488d7c2408488d742420e819b0f8ff4c8b7424184d85f6743b4c8b7c24104983fe01756b488b4424084b8d0c76498d0ccf4c897c24204c897c2428488944243048894c2438488d7424204889dfe87643f8ffeb2e48c7030000000048c7431000000000488b4424084885c07415488b7c241048c1e003488d344031d2ff15069af2044889d84883c4705b415e415fc3'),
    ('row24_sort', 'new', 0x15b5aa7, '4983fe15731a488d4c2407ba010000004c89ff4c89f6e87e12f1ffe975ffffff488d5424074c89ff4c89f6ff1580b3f204e95fffffff4889c3488d7c2408e8d69700004889dfe85eafe304'),
    ('sink_common_roll', 'context', 0x595aac0, '488b8424a000000048898424d00000000f108424900000000f298424c0000000488d7c2408488db424c0000000ff152d55b8004889dfe8056bffff'),
    ('sink_emit', 'context', 0x595ab27, '4c8d7c24084c89ffff155b5eb8004889df4c89fe488b9424b0000000e8388478ff4889dfe8008eb6fb4889c7e82893bdfb4885c0740f4889442408488d7c2408e894a1b6fb'),
    ('engine_state_guard', 'context', 0x5a06687, '498b8f500400004c8b89581c00004c8b91601c00004983f90175134c8b41284d39c20f82911400000f84d5130000'),
    ('engine_begin_call', 'context', 0x5a06790, '488dbc2468020000488d942418020000498d9f500400004889de4c89e9e89ed7a7ff'),
    ('engine_end_call', 'context', 0x5a077d9, '488d7c24204c89fee83a0f0000'),
    ('begin_counter', 'context', 0x5483fd3, '498b752848ffc648c7c2ffffffff480f45d64989552849c7450000000000'),
    ('root_selector', 'context', 0x5a08731, '4989f64889fb488bb6500400004c8b7e2848b8917efb3a70ce88d2490fafc748c1c80448b9cc10c7bab88d06004839c8722283be581c00000175344c39be601c00000f824a060000400f94c541833e02740beb2340b50141833e02751a48b80000000000000080488903e91106000031ed41833e0274e683be581c00000175134c39be601c00000f821e060000410f94c5eb034531ed4d8da65004000048b8000000000000008048898424a80000004084ed7536488b8e384500004c89f84809c848c1e82074134c89f831d248f7f14885d20f85a8030000eb104489f831d2f7f14885d20f8596030000498d9630030000498d4e20488dbc2430010000e88d50a8ff498dbe00040000488d9424300100004c89fee856b7ffff4084ed0f845e030000'),
]

# Only these previously unclaimed FDEs are selected as new bodies. Existing
# loader, state, block and sink functions are represented by context windows.
NEW_FUNCTIONS = [
    ('descriptor_method', 0x292c5c0),
    ('descriptor_alternate', 0x292e230),
    ('function_pointer_thunk', 0x2c7bb70),
    ('row32_pipeline', 0x15b5b00),
    ('row24_pipeline', 0x15b59e0),
]

# rel32/rel8 targets and RIP-relative targets are decoded from the pinned
# bytes; expected values are fail-closed checks, not a whole-binary scan.
EDGES = [
    ('entry_main_address', 0x1419318, 'lea', 0x2cef8f0),
    ('entry_libc_slot', 0x141931f, 'slot', 0x64df458),
    ('bridge_callback', 0x2cef8f7, 'lea', 0x2cd8370),
    ('bridge_descriptor', 0x2cef902, 'lea', 0x6440b48),
    ('bridge_runtime_slot', 0x2cef90f, 'slot', 0x64e6c30),
    ('shim_thunk', 0x292c5c4, 'call', 0x2c7bb70),
    ('alternative_thunk', 0x292e234, 'call', 0x2c7bb70),
    ('callback_parent', 0x2cd83a2, 'call', 0x2ae1690),
    ('parent_other_poll', 0x2ae18d9, 'branch', 0x2ae1b0a),
    ('parent_poll_b', 0x2ae1eeb, 'call', 0x2cde430),
    ('poll_gate_zero', 0x2cde48f, 'branch', 0x2cde706),
    ('poll_state_table', 0x2cde4a0, 'lea', 0x60bf88),
    ('poll_command_table', 0x2cde66c, 'lea', 0x60bfc0),
    ('mode_two_parent', 0x2cde6f4, 'call', 0x2cb6500),
    ('mode_one_parent', 0x2cdf58b, 'call', 0x2cb6500),
    ('existing_parent_call', 0x2cb7771, 'call', 0x2cbbbe0),
    ('existing_middle_call', 0x2cbc06b, 'call', 0x2b41b70),
    ('existing_loader_slot', 0x2b41f2d, 'slot', 0x64e7728),
    ('existing_location_slot', 0x3c128a2, 'slot', 0x64e9628),
    ('location_reference', 0x3c1352f, 'lea', 0x64767a8),
    ('checkpoint_existing_slot', 0x2cb7970, 'slot', 0x64e7438),
    ('mode_two_skip', 0x5a6de25, 'branch', 0x5a6e02b),
    ('configuration_sentinel_skip', 0x5a6de55, 'branch', 0x5a6e01d),
    ('sentinel_logging_alternate', 0x5a6e025, 'branch', 0x5a6e0af),
    ('record_builder_slot', 0x5a6e055, 'slot', 0x64ebf70),
    ('parent_nonpending', 0x2cb801b, 'branch', 0x2cb8039),
    ('callback_worker_slot', 0x2a929ba, 'slot', 0x64e71d0),
    ('worker_receive_other', 0x5a6e335, 'branch', 0x5a70087),
    ('worker_block_boundary', 0x5a6ea10, 'call', 0x4f122c0),
    ('engine_past_guard', 0x5a066a9, 'branch', 0x5a07b40),
    ('engine_equal_guard', 0x5a066af, 'branch', 0x5a07a8a),
    ('engine_begin_boundary', 0x5a067ad, 'call', 0x5483f50),
    ('engine_end_boundary', 0x5a077e1, 'call', 0x5a08720),
    ('worker_result_sink', 0x5a6f991, 'call', 0x595a6b0),
    ('sink_disabled', 0x595a6c7, 'branch', 0x595ab6c),
    ('sink_no_new_bucket', 0x595a700, 'branch', 0x595ab27),
    ('sink_flag_nonzero', 0x595a7ae, 'branch', 0x595aac0),
    ('sink_directory_predicate', 0x595a844, 'slot', 0x64e0928),
    ('sink_predicate_zero', 0x595a84c, 'branch', 0x595aac0),
    ('sink_directory_adapter', 0x595a860, 'slot', 0x64e09d0),
    ('sink_directory_success', 0x595a86e, 'branch', 0x595a882),
    ('directory_error_tag', 0x15021f6, 'branch', 0x150228b),
    ('collect_rows32', 0x1502216, 'call', 0x15b5b00),
    ('collect_rows24', 0x1502278, 'call', 0x15b59e0),
    ('row32_collector', 0x15b5b27, 'call', 0x153f900),
    ('row32_processor', 0x15b5b69, 'call', 0x1539ce0),
    ('row32_unwind_cleanup', 0x15b5be5, 'call', 0x15bfbb0),
    ('row32_unwind_resume', 0x15b5bed, 'call', 0x63f0a50),
    ('row24_collector', 0x15b5a22, 'call', 0x1540a40),
    ('row24_processor', 0x15b5a65, 'call', 0x1539de0),
    ('row24_unwind_cleanup', 0x15b5ae5, 'call', 0x15bf2c0),
    ('row24_unwind_resume', 0x15b5aed, 'call', 0x63f0a50),
    ('directory_error_convert', 0x150228b, 'call', 0x14cc980),
    ('row32_empty', 0x15b5b34, 'branch', 0x15b5b70),
    ('row32_not_single', 0x15b5b3f, 'branch', 0x15b5ba7),
    ('row32_large', 0x15b5bab, 'branch', 0x15b5bc7),
    ('row32_small_sort', 0x15b5bbd, 'call', 0x14c6f20),
    ('row32_large_sort', 0x15b5bd2, 'slot', 0x64e0e60),
    ('row24_empty', 0x15b5a2f, 'branch', 0x15b5a6c),
    ('row24_not_single', 0x15b5a3a, 'branch', 0x15b5aa7),
    ('row24_large', 0x15b5aab, 'branch', 0x15b5ac7),
    ('row24_small_sort', 0x15b5abd, 'call', 0x14c6d40),
    ('row24_large_sort', 0x15b5ad2, 'slot', 0x64e0e58),
    ('sink_record_encoder', 0x595ab43, 'call', 0x50e2f80),
    ('runtime_exhausted_counter', 0x5c999a4, 'branch', 0x5c99e74),
    ('runtime_invalid_mode', 0x5c99b2c, 'branch', 0x5c99f24),
]

# Each field is a displacement/immediate inside one of WINDOWS. Fixed opcodes
# and operand bytes are authenticated before these values are interpreted.
FIELDS = [
    ('parent_mode_source', 0x2cb758f, 3, 4),
    ('parent_mode_saved', 0x2cb75cd, 2, 4),
    ('checkpoint_mode_argument', 0x2cb7959, 3, 4),
    ('parent_result_stack', 0x2cb7960, 4, 4),
    ('builder_frame_size', 0x595ac3a, 3, 4),
    ('builder_stack_argument', 0x595ae9d, 4, 4),
    ('builder_height_offset', 0x595aef4, 3, 1),
    ('builder_flag_offset', 0x595aef8, 3, 1),
    ('initial_height_offset', 0x5a6e038, 3, 1),
    ('mode_compare', 0x5a6e02d, 3, 1),
    ('height_lane_source', 0x2cb7ce2, 4, 4),
    ('height_lane_destination', 0x2cb7cea, 4, 4),
    ('flag_word_source', 0x2cb7cd2, 4, 4),
    ('flag_word_destination', 0x2cb7cda, 4, 4),
    ('copy_a_source', 0x2cb7e6c, 4, 4),
    ('copy_a_destination', 0x2cb7e74, 4, 4),
    ('copy_a_length', 0x2cb7e7c, 1, 4),
    ('copy_b_destination', 0x2cb7ffe, 4, 4),
    ('copy_b_length', 0x2cb8006, 1, 4),
    ('copy_c_destination', 0x2cb8039, 4, 4),
    ('copy_c_source', 0x2cb8041, 4, 4),
    ('copy_c_length', 0x2cb8049, 1, 4),
    ('parent_destination', 0x2cb806f, 3, 4),
    ('parent_source', 0x2cb8076, 4, 4),
    ('parent_copy_length', 0x2cb807e, 1, 4),
    ('callback_parent_source', 0x2cb97aa, 3, 4),
    ('callback_stack_destination', 0x2cb97ce, 4, 4),
    ('callback_parent_length', 0x2cb97d6, 1, 4),
    ('allocation_size', 0x2cb984d, 1, 4),
    ('allocation_stack_source', 0x2cb9864, 4, 4),
    ('allocation_copy_length', 0x2cb986c, 1, 4),
    ('worker_sink_offset', 0x5a6e284, 3, 4),
    ('sink_marker_offset', 0x595a6fc, 3, 1),
    ('sink_marker_store_offset', 0x595a7a5, 3, 1),
    ('sink_flag_offset', 0x595a7a9, 3, 1),
    ('sink_multiplier', 0x595a6e1, 2, 8),
    ('sink_shift', 0x595a6f1, 3, 1),
    ('sink_period', 0x595a6f5, 3, 4),
    ('runtime_method_offset', 0x5c99e21, 2, 1),
    ('worker_mode_two', 0x2cde6d0, 7, 1),
    ('worker_mode_one', 0x2cdf567, 7, 1),
    ('row32_count_cutoff', 0x15b5ba7, 3, 1),
    ('row24_count_cutoff', 0x15b5aa7, 3, 1),
    ('row32_stride_shift', 0x15b5b46, 3, 1),
    ('begin_counter_offset', 0x5483fd3, 3, 1),
]

RELOCATIONS = [
    ('libc_start_import', 0x64df458, 6, 1, 0),
    ('bridge_runtime', 0x64e6c30, 8, 0, 0x5c99970),
    ('descriptor_alternate_method', 0x6440b60, 8, 0, 0x292e230),
    ('descriptor_method', 0x6440b70, 8, 0, 0x292c5c0),
    ('source_location_path', 0x64767a8, 8, 0, 0x443168),
    ('existing_loader', 0x64e7728, 8, 0, 0x3c12800),
    ('existing_location_wrapper', 0x64e9628, 8, 0, 0x3c13520),
    ('checkpoint_boundary', 0x64e7438, 8, 0, 0x5a6dd30),
    ('record_builder_boundary', 0x64ebf70, 8, 0, 0x595ac30),
    ('callback_descriptor_entry', 0x64471b8, 8, 0, 0x2a92960),
    ('row32_large_helper', 0x64e0e60, 8, 0, 0x152d4b0),
    ('row24_large_helper', 0x64e0e58, 8, 0, 0x152d390),
    ('directory_open_helper', 0x64e0970, 8, 0, 0x5c9ca30),
    ('directory_predicate', 0x64e0928, 8, 0, 0x1500a60),
    ('directory_adapter', 0x64e09d0, 8, 0, 0x15021d0),
    ('callback_worker_boundary', 0x64e71d0, 8, 0, 0x5a6e1e0),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def authenticate(data, expected=TARGET_SHA256):
    actual = digest(data)
    require(actual == expected, 'binary SHA-256 mismatch')
    return actual


def named_section(secs, name):
    matches = [s for s in secs if s['name'] == name]
    require(len(matches) == 1 and matches[0]['type'] != 8, 'missing, duplicate, or fileless section: ' + name)
    return matches[0]


def file_offset(data, secs, va, size, executable=False):
    require(isinstance(va, int) and isinstance(size, int) and va >= 0 and size > 0, 'invalid address or size')
    matches = [s for s in secs if s['type'] != 8 and s['size'] and
               (not executable or s['flags'] & 4) and
               s['address'] <= va and va + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'address is not uniquely file-backed')
    off = matches[0]['offset'] + va - matches[0]['address']
    require(off >= 0 and off + size <= len(data), 'mapped bytes exceed file')
    return off


def read_va(data, secs, va, size, executable=False):
    off = file_offset(data, secs, va, size, executable)
    return data[off:off + size]


def verify_windows(data, secs, specs=WINDOWS):
    seen, rows = set(), []
    for name, scope, va, expected in specs:
        require(name not in seen, 'duplicate window label')
        seen.add(name)
        pattern = bytes.fromhex(expected)
        actual = read_va(data, secs, va, len(pattern), executable=True)
        require(actual == pattern, 'instruction pattern mismatch: ' + name)
        rows.append({'label': name, 'scope': scope, 'start_va': hex(va),
                     'end_va_exclusive': hex(va + len(actual)),
                     'file_offset': hex(file_offset(data, secs, va, len(actual), True)),
                     'raw_hex': actual.hex(), 'sha256': digest(actual)})
    return rows


def read_relocations(data, secs, expected=RELOCATIONS):
    section = named_section(secs, '.rela.dyn')
    require(section['size'] % 24 == 0, 'invalid relocation table length')
    wanted = {slot: (name, typ, sym, addend) for name, slot, typ, sym, addend in expected}
    require(len(wanted) == len(expected), 'duplicate requested relocation')
    found = {}
    for off in range(section['offset'], section['offset'] + section['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot not in wanted:
            continue
        require(slot not in found, 'duplicate relocation for selected slot')
        name, typ, sym, value = wanted[slot]
        file_offset(data, secs, slot, 8)
        require((info & 0xffffffff, info >> 32, addend) == (typ, sym, value),
                'selected relocation mismatch: ' + name)
        found[slot] = {'label': name, 'scope': 'context', 'slot_va': hex(slot), 'record_file_offset': hex(off),
                       'type': info & 0xffffffff, 'symbol_index': info >> 32, 'addend': hex(addend),
                       'raw_hex': data[off:off + 24].hex()}
    require(len(found) == len(wanted), 'missing selected relocation')
    return [found[slot] for slot in sorted(found)]


def dynamic_symbol(data, secs, index):
    sym = named_section(secs, '.dynsym')
    strings = named_section(secs, '.dynstr')
    require(sym['size'] % 24 == 0 and 0 <= index < sym['size'] // 24, 'invalid dynamic symbol index')
    off = sym['offset'] + index * 24
    nameoff = struct.unpack_from('<I', data, off)[0]
    require(nameoff < strings['size'], 'invalid dynamic symbol string offset')
    begin = strings['offset'] + nameoff
    end = data.find(b'\0', begin, strings['offset'] + strings['size'])
    require(end >= 0, 'unterminated dynamic symbol name')
    return data[begin:end].decode('ascii')


def decode_edge(data, secs, va, kind):
    if kind == 'call':
        raw = read_va(data, secs, va, 5, True)
        require(raw[0] == 0xe8, 'not a rel32 call')
    elif kind == 'slot':
        raw = read_va(data, secs, va, 6, True)
        require(raw[:2] == b'\xff\x15', 'not a RIP-relative indirect call')
    elif kind == 'lea':
        raw = read_va(data, secs, va, 7, True)
        require(raw[0] & 0xf0 == 0x40 and raw[1] == 0x8d and raw[2] & 0xc7 == 5,
                'not a RIP-relative address calculation')
    elif kind == 'branch':
        first = read_va(data, secs, va, 2, True)
        if first[0] == 0x0f and 0x80 <= first[1] <= 0x8f:
            raw = read_va(data, secs, va, 6, True)
        else:
            require(0x70 <= first[0] <= 0x7f, 'unsupported branch')
            raw = first
            return raw, va + 2 + struct.unpack('<b', raw[1:])[0]
    else:
        raise ValueError('unsupported edge kind')
    return raw, va + len(raw) + struct.unpack('<i', raw[-4:])[0]


def extract_edges(data, secs, specs=EDGES):
    rows = []
    for label, va, kind, expected in specs:
        raw, target = decode_edge(data, secs, va, kind)
        require(target == expected, 'selected transfer mismatch: ' + label)
        scopes = {scope for _, scope, start, pattern in WINDOWS if start <= va and va + len(raw) <= start + len(bytes.fromhex(pattern))}
        require(len(scopes) == 1, 'transfer is not covered by one pinned scope')
        rows.append({'label': label, 'scope': scopes.pop(), 'kind': kind, 'site_va': hex(va),
                     'file_offset': hex(file_offset(data, secs, va, len(raw), True)),
                     'raw_hex': raw.hex(), 'target_va': hex(target)})
    return rows


def extract_fields(data, secs, windows=WINDOWS, fields=FIELDS):
    spans = [(va, va + len(bytes.fromhex(raw))) for _, _, va, raw in windows]
    values, rows = {}, []
    for label, site, offset, width in fields:
        require(label not in values and width in (1, 2, 4, 8), 'invalid field specification')
        require(any(lo <= site and site + offset + width <= hi for lo, hi in spans),
                'field is not inside a pinned window: ' + label)
        b = read_va(data, secs, site + offset, width, True)
        value = int.from_bytes(b, 'little')
        values[label] = value
        rows.append({'label': label, 'instruction_va': hex(site), 'operand_va': hex(site + offset),
                     'file_offset': hex(file_offset(data, secs, site + offset, width, True)),
                     'raw_hex': b.hex(), 'value': hex(value)})
    return values, rows


def selected_fdes(data, secs, table, fdes):
    result = []
    for label, start in NEW_FUNCTIONS:
        hits = [f for f in fdes if f['start'] == start]
        require(len(hits) == 1 and hits[0]['end'] > start, 'missing or duplicate selected FDE')
        f = hits[0]
        overlaps = [x for x in fdes if x['start'] < f['end'] and x['end'] > start]
        require(len(overlaps) == 1 and overlaps[0]['fde'] == f['fde'], 'selected FDE overlaps')
        matching = [r for r in table if r['start'] == start]
        require(len(matching) == 1 and matching[0]['fde'] == f['fde'], 'unwind header/FDE mismatch')
        body = read_va(data, secs, start, f['end'] - start, True)
        result.append({'label': label, 'start_va': hex(start), 'end_va_exclusive': hex(f['end']),
                       'fde_va': hex(f['fde']), 'cie_va': hex(f['cie']),
                       'lsda_va': hex(f['lsda']) if f['lsda'] is not None else '-',
                       'index': matching[0]['index'], 'file_offset': hex(file_offset(data, secs, start, len(body), True)),
                       'size': len(body), 'sha256': digest(body), 'body_hex': body.hex()})
    return result


def lsda_rows(data, secs, fde):
    require(fde['lsda'] is not None, 'selected runtime has no LSDA')
    sec = named_section(secs, '.gcc_except_table')
    va = fde['lsda']
    require(sec['address'] <= va < sec['address'] + sec['size'], 'LSDA outside section')
    pos = file_offset(data, secs, va, 2)
    limit = sec['offset'] + sec['size']
    require(data[pos] == 0xff and data[pos + 1] in (0x9b, 0xff), 'unsupported LSDA header')
    typ = data[pos + 1]
    pos += 2
    type_base = limit
    if typ == 0x9b:
        delta, pos = uleb(data, pos, limit)
        type_base = pos + delta
    require(type_base <= limit and pos < limit and data[pos] == 1, 'unsupported LSDA encoding')
    length, pos = uleb(data, pos + 1, limit)
    stop = pos + length
    require(stop <= min(limit, type_base), 'truncated LSDA table')
    rows = []
    while pos < stop:
        first = pos
        start, pos = uleb(data, pos, stop)
        size, pos = uleb(data, pos, stop)
        landing, pos = uleb(data, pos, stop)
        action, pos = uleb(data, pos, stop)
        require(start + size <= fde['end'] - fde['start'], 'LSDA call range outside FDE')
        require(not landing or landing < fde['end'] - fde['start'], 'LSDA landing outside FDE')
        rows.append({'entry_file_offset': hex(first), 'start_va': hex(fde['start'] + start),
                     'end_va_exclusive': hex(fde['start'] + start + size),
                     'landing_va': hex(fde['start'] + landing) if landing else '-',
                     'action': action, 'raw_hex': data[first:pos].hex()})
    require(pos == stop, 'misaligned LSDA rows')
    return rows


def dispatch_tables(data, secs):
    rows = []
    _, state_base = decode_edge(data, secs, 0x2cde4a0, 'lea')
    _, command_base = decode_edge(data, secs, 0x2cde66c, 'lea')
    fallback = read_va(data, secs, 0x2cde65c, 5, True)
    require(fallback[0] == 0xba and command_base >= state_base and (command_base - state_base) % 4 == 0,
            'dispatch table shape changed')
    state_count = (command_base - state_base) // 4
    command_count = struct.unpack_from('<I', fallback, 1)[0] + 1
    require(state_count == 14 and command_count == 13, 'selected dispatch table bounds changed')
    for label, base, count in [('poll_state', state_base, state_count), ('poll_command', command_base, command_count)]:
        raw = read_va(data, secs, base, 4 * count)
        for index in range(count):
            delta = struct.unpack_from('<i', raw, 4 * index)[0]
            target = base + delta
            file_offset(data, secs, target, 1, True)
            rows.append({'table': label, 'table_va': hex(base), 'index': index,
                         'entry_file_offset': hex(file_offset(data, secs, base + 4 * index, 4)),
                         'raw_hex': raw[4 * index:4 * index + 4].hex(), 'target_va': hex(target)})
    expected = {(r['table'], r['index']): r['target_va'] for r in rows}
    for k, v in {('poll_state', 0): '0x2cde4b0', ('poll_state', 3): '0x2cdf57e',
                 ('poll_state', 4): '0x2cde6e7', ('poll_command', 0): '0x2cde67c',
                 ('poll_command', 1): '0x2cdf519'}.items():
        require(expected[k] == v, 'selected dispatch table entry mismatch')
    return rows


def map_copy(position, source, destination, length, width):
    require(width > 0 and source <= position and position + width <= source + length,
            'tracked field falls outside copy')
    return destination + position - source


def projection(values):
    v = values
    height = v['parent_result_stack'] + v['builder_height_offset']
    flag = v['parent_result_stack'] + v['builder_flag_offset']
    height = map_copy(height, v['height_lane_source'], v['height_lane_destination'], 16, 8)
    flag = map_copy(flag, v['flag_word_source'], v['flag_word_destination'], 8, 1)
    rows = [{'stage': 'staged_record', 'height': hex(height), 'flag': hex(flag)}]
    stages = [
        ('stack_copy_a', v['copy_a_source'], v['copy_a_destination'], v['copy_a_length']),
        ('stack_copy_b', v['copy_a_destination'], v['copy_b_destination'], v['copy_b_length']),
        ('stack_copy_c', v['copy_c_source'], v['copy_c_destination'], v['copy_c_length']),
        ('parent_field', v['parent_source'], v['parent_destination'], v['parent_copy_length']),
        ('callback_stack', v['callback_parent_source'], v['callback_stack_destination'], v['callback_parent_length']),
        ('callback_allocation', v['allocation_stack_source'], 0, v['allocation_copy_length']),
    ]
    require(v['copy_b_destination'] == v['copy_c_source'] and
            v['copy_c_destination'] == v['parent_source'] and
            v['callback_stack_destination'] == v['allocation_stack_source'] and
            v['allocation_size'] == v['allocation_copy_length'], 'copy stages do not join')
    for label, source, destination, length in stages:
        height = map_copy(height, source, destination, length, 8)
        flag = map_copy(flag, source, destination, length, 1)
        rows.append({'stage': label, 'source': hex(source), 'destination': hex(destination),
                     'length': hex(length), 'height': hex(height), 'flag': hex(flag)})
    require(height == v['worker_sink_offset'] + v['sink_marker_offset'] and
            height == v['worker_sink_offset'] + v['sink_marker_store_offset'] and
            flag == v['worker_sink_offset'] + v['sink_flag_offset'], 'callback-to-sink offsets do not join')
    require(v['parent_mode_saved'] == v['checkpoint_mode_argument'], 'saved mode byte does not join')
    require(v['builder_stack_argument'] == v['builder_frame_size'] + 6 * 8 + 8,
            'builder stack argument does not join')
    require(v['mode_compare'] == 2 and (v['worker_mode_one'], v['worker_mode_two']) == (1, 2),
            'selected mode constants changed')
    return rows


def bucket_formula(n, multiplier, shift, period):
    require(0 <= n < 1 << 64, 'value outside unsigned 64-bit range')
    prior = n - 1 if n else 0
    return ((prior * multiplier) >> (64 + shift)) * period


def verify_location(data, secs, relocs):
    loc = 0x64767a8
    record = read_va(data, secs, loc, 24)
    length, line, column = struct.unpack_from('<QII', record, 8)
    pointer = next(int(r['addend'], 16) for r in relocs if r['label'] == 'source_location_path')
    path = read_va(data, secs, pointer, length)
    require(path == b'l1/src/abci/state.rs' and (line, column) == (123, 37), 'Location record mismatch')
    return {'record_va': hex(loc), 'record_file_offset': hex(file_offset(data, secs, loc, 24)),
            'record_raw_hex': record.hex(), 'path_va': hex(pointer), 'path_length': length,
            'path': path.decode('ascii'), 'line': line, 'column': column}


def check_historical(path):
    data = path.read_bytes()
    authenticate(data, HISTORICAL_SHA256)
    secs = sections(data)
    section = named_section(secs, '.rela.dyn')
    found = {}
    for off in range(section['offset'], section['offset'] + section['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot in (0x56dfbf8, 0x57755a8):
            require(slot not in found and info == 8, 'historical relocation mismatch')
            found[slot] = addend
    require(found == {0x56dfbf8: 0x1dd8eb, 0x57755a8: 0x3273810}, 'historical anchor mismatch')
    length, line, column = struct.unpack('<QII', read_va(data, secs, 0x56dfbf8 + 8, 16))
    name = read_va(data, secs, found[0x56dfbf8], length)
    require(length == 49 and name.endswith(b'l1/src/abci/state.rs') and (line, column) == (107, 37),
            'historical Location mismatch')
    require(read_va(data, secs, 0x3273856, 7, True) == bytes.fromhex('488d0d9bc34602'),
            'historical Location reference mismatch')
    require(read_va(data, secs, 0x3273871, 4, True) == bytes.fromhex('4983fd02'),
            'historical comparison mismatch')
    _, target = decode_edge(data, secs, 0x3272785, 'slot')
    require(target == 0x57755a8, 'historical caller mismatch')
    return {'sha256': digest(data), 'location_va': hex(0x56dfbf8), 'line': line, 'column': column,
            'caller_va': hex(0x3272785), 'wrapper_va': hex(found[0x57755a8]), 'comparison': 2}


def as_tsv(rows):
    require(bool(rows), 'no rows to render')
    columns = list(rows[0])
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=columns, delimiter='\t', lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def as_json(value):
    return json.dumps(value, indent=2, sort_keys=True) + '\n'


def generate(data):
    actual = authenticate(data)
    secs, table = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    windows = verify_windows(data, secs)
    relocs = read_relocations(data, secs)
    require(dynamic_symbol(data, secs, 1) == '__libc_start_main', 'entry import mismatch')
    edges = extract_edges(data, secs)
    fields, field_rows = extract_fields(data, secs)
    proj = projection(fields)
    funcs = selected_fdes(data, secs, table, fdes)
    fde = next(f for f in fdes if f['start'] == 0x5c99970)
    exception = [dict(row, scope='context') for row in lsda_rows(data, secs, fde)]
    covering = [r for r in exception if int(r['start_va'], 16) <= 0x5c99e21 < int(r['end_va_exclusive'], 16)]
    require(len(covering) == 1 and covering[0]['landing_va'] == '0x5c99f54', 'runtime call LSDA mismatch')
    tables = dispatch_tables(data, secs)
    location = verify_location(data, secs, relocs)
    require(struct.unpack_from('<Q', data, 24)[0] == 0x1419300, 'ELF entry mismatch')
    descriptor = read_va(data, secs, 0x6440b48, fields['runtime_method_offset'] + 8)
    require(struct.unpack_from('<QQ', descriptor, 8) == (8, 8), 'descriptor size/alignment mismatch')
    require(fields['runtime_method_offset'] == 0x28, 'descriptor method offset mismatch')
    require(fields['sink_multiplier'] == 0x346dc5d63886594b and fields['sink_shift'] == 11 and
            fields['sink_period'] == 10000, 'bucket arithmetic operands changed')
    require(fields['begin_counter_offset'] == fields['initial_height_offset'], 'selected state word offsets differ')
    files = {
        'functions.tsv': as_tsv(funcs),
        'windows.tsv': as_tsv(windows),
        'transfers.tsv': as_tsv(edges),
        'fields.tsv': as_tsv(field_rows),
        'relocations.tsv': as_tsv(relocs),
        'dispatch.tsv': as_tsv(tables),
        'projection.json': as_json(proj),
        'exception.tsv': as_tsv(exception),
        'location.json': as_json(location),
    }
    summary = {'binary_sha256': actual, 'elf_entry_va': hex(struct.unpack_from('<Q', data, 24)[0]),
               'coordinate_system': 'linked ELF virtual address before load bias',
               'descriptor_va': hex(decode_edge(data, secs, 0x2cef902, 'lea')[1]), 'descriptor_raw_hex': descriptor.hex(),
               'entry_dynamic_symbol': dynamic_symbol(data, secs, 1),
               'bucket_operands': {'multiplier': hex(fields['sink_multiplier']),
                                   'shift': fields['sink_shift'], 'period': fields['sink_period']},
               'counts': {'new_fdes': len(funcs), 'windows': len(windows), 'transfers': len(edges),
                          'fields': len(field_rows), 'relocations': len(relocs), 'dispatch_entries': len(tables),
                          'projection_stages': len(proj), 'runtime_lsda_rows': len(exception)},
               'limitations': 'Selected static patterns and conditional joins only; FDEs are not a complete function census.'}
    files['summary.json'] = as_json(summary)
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--historical', type=Path, help='optional separately authenticated historical capture')
    args = parser.parse_args(argv)
    data = TARGET.read_bytes()
    authenticate(data)
    if args.historical is not None:
        historical = check_historical(args.historical)
        print('historical anchor verified:', json.dumps(historical, sort_keys=True))
    files = generate(data)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, body in files.items():
        (args.out / name).write_text(body, encoding='utf-8', newline='')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, struct.error) as error:
        print('abci_entry_checkpoint115:', str(error), file=sys.stderr)
        raise SystemExit(1)
