#!/usr/bin/env python3
"""Collect a digest-bound, static node-115 fee-history adapter trace.

All records are read from ELF file bytes. No target execution or external tool
is used. Captured code windows are evidence only; they are never executed.
"""
import argparse
import bisect
import hashlib
import json
import math
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

FUNCTIONS = [
    ('registration', 0x2d024e0),
    ('callback_factory', 0x2d032b0),
    ('outer_future', 0x2d0bee0),
    ('parameter_iterator', 0x2d10a60),
    ('error_object', 0x25cd880),
    ('history_future', 0x2a1fd20),
    ('block_number_resolver', 0x2a21c70),
    ('block_number_state_read', 0x2a3eb60),
    ('typed_context_lookup', 0x2a06530),
    ('block_range_future', 0x2a0acc0),
    ('task_constructor', 0x2b3daa0),
    ('task_poll_gateway', 0x2e4a980),
    ('task_failure_formatter', 0x29b0880),
    ('task_runner', 0x2b230d0),
    ('task_join_poll', 0x2b16880),
    ('task_result_transfer', 0x2b316b0),
    ('task_ready_helper', 0x5cdb250),
    ('range_iterator', 0x2698000),
    ('range_key_builder', 0x26990d0),
    ('range_prefix_copy', 0x2697f20),
    ('range_key_concat', 0x231fef0),
    ('range_value_decoder', 0x26985d0),
    ('range_value_projection', 0x231bc30),
    ('response_bridge', 0x22d7a70),
    ('response_envelope', 0x260b360),
    ('error_serializer', 0x260cb30),
    ('history_fields', 0x22e0850),
    ('reward_field', 0x2338940),
]

# (label, source, expected direct destination). Call instruction addresses are
# manually selected instruction boundaries, independently reviewed with objdump.
CALLS = [
    ('missing_argument_error', 0x2d0c201, 0x25cd880),
    ('second_parameter_parser', 0x2d0c227, 0x2d10a60),
    ('iterator_error_object', 0x2d10cee, 0x25cd880),
    ('resolve_block_number', 0x2a1fed0, 0x2a21c70),
    ('typed_context_lookup', 0x2a201c9, 0x2a06530),
    ('block_range_poll', 0x2a20457, 0x2a0acc0),
    ('construct_block_task', 0x2a0afd5, 0x2b3daa0),
    ('poll_block_task', 0x2a0affa, 0x2e4a980),
    ('format_task_failure', 0x2a0b07b, 0x29b0880),
    ('response_bridge', 0x2d0cb3e, 0x22d7a70),
    ('response_envelope', 0x22d7c2a, 0x260b360),
    ('history_fields', 0x260b512, 0x22e0850),
    ('reward_field', 0x22e0ac0, 0x2338940),
    ('task_run_range_iterator', 0x2b23327, 0x2698000),
    ('task_result_transfer', 0x2b2359d, 0x2b316b0),
    ('lower_bound_key', 0x2698086, 0x26990d0),
    ('upper_bound_key', 0x269809c, 0x26990d0),
    ('range_prefix_copy', 0x26980a9, 0x2697f20),
    ('key_prefix_copy', 0x26990e4, 0x2697f20),
    ('key_segments_concat', 0x269913a, 0x231fef0),
    ('decode_range_value', 0x2698337, 0x26985d0),
    ('project_range_values', 0x26984c4, 0x231bc30),
    ('block_number_uninstrumented', 0x2a21d2d, 0x2a3eb60),
    ('block_number_instrumented', 0x2a22463, 0x2a3eb60),
    ('serialize_error', 0x260b497, 0x260cb30),
]

# These are selected sites, not a disassembly-based census. All branch targets
# must remain inside the same decoded FDE.
BRANCHES = [
    ('outer_object_input', 0x2d0c051, 'jne'),
    ('outer_empty_array', 0x2d0c11b, 'je'),
    ('missing_argument_allocation', 0x2d0c19f, 'je'),
    ('second_argument_error', 0x2d0c231, 'jne'),
    ('optional_argument_not_absence_sentinel', 0x2d0c340, 'jne'),
    ('first_argument_result', 0x2d0c419, 'jne'),
    ('outer_inner_not_pending', 0x2d0c7fc, 'jne'),
    ('outer_error_variant', 0x2d0c932, 'je'),
    ('response_serializer_zero', 0x22d7c32, 'je'),
    ('result_serialization_failure', 0x260b51a, 'jne'),
    ('history_empty_base_fee', 0x22e08ce, 'je'),
    ('history_empty_blob_base_fee', 0x22e0a02, 'je'),
    ('history_empty_blob_ratio', 0x22e0a42, 'je'),
    ('history_no_reward', 0x22e0aab, 'jo'),
    ('zero_count', 0x2a1fe6b, 'je'),
    ('option_present', 0x2a1fe85, 'jne'),
    ('block_count_at_most_cap', 0x2a1fe8f, 'jbe'),
    ('selector_five', 0x2a1fea4, 'je'),
    ('selector_four', 0x2a1fea9, 'jne'),
    ('resolution_result', 0x2a1fee9, 'jne'),
    ('newest_increment', 0x2a1ff00, 'jne'),
    ('percentile_length', 0x2a20057, 'jbe'),
    ('percentile_loop_done', 0x2a20094, 'jb'),
    ('percentile_previous_above_limit', 0x2a200a3, 'ja'),
    ('percentile_pair_order', 0x2a200b0, 'jbe'),
    ('range_count_clamp', 0x2a200cb, 'jae'),
    ('range_order', 0x2a201aa, 'jb'),
    ('context_lookup_result', 0x2a201e3, 'jne'),
    ('range_poll_result', 0x2a20468, 'jne'),
    ('range_result_tag', 0x2a205a1, 'jne'),
    ('range_length_mismatch', 0x2a205df, 'jne'),
    ('range_empty', 0x2a205e8, 'je'),
    ('history_loop_end', 0x2a20b1c, 'je'),
    ('history_optional_reward', 0x2a20d20, 'je'),
    ('registry_null', 0x2a06554, 'je'),
    ('registry_empty', 0x2a0655f, 'je'),
    ('registry_match', 0x2a065cf, 'je'),
    ('registry_probe_empty', 0x2a065e8, 'jne'),
    ('registry_type_mismatch', 0x2a06627, 'jne'),
    ('reader_overflow', 0x2a0ad34, 'jne'),
    ('reader_poll_not_pending', 0x2a0b008, 'jne'),
    ('reader_status', 0x2a0b05e, 'jne'),
    ('reader_count_mismatch', 0x2a0b0f3, 'jne'),
    ('task_not_ready', 0x2b16899, 'je'),
    ('task_unexpected_output', 0x2b168d0, 'jne'),
    ('scan_reversed_bounds', 0x2698024, 'ja'),
    ('scan_iterator_null', 0x26980f0, 'je'),
    ('scan_direction', 0x2698120, 'je'),
    ('scan_invalid_iterator', 0x26981c7, 'je'),
    ('scan_null_key', 0x2698233, 'je'),
    ('scan_short_key', 0x2698247, 'jb'),
    ('scan_prefix_differs', 0x2698263, 'jne'),
    ('scan_null_value', 0x26982e4, 'je'),
    ('scan_suffix_size', 0x26982fb, 'jne'),
    ('scan_value_result', 0x2698348, 'jne'),
    ('scan_limit', 0x2698409, 'jb'),
    ('value_decoder_result', 0x2698622, 'jne'),
    ('prefix_allocation_failed', 0x2697f47, 'je'),
    ('key_allocation_failed', 0x26990f7, 'je'),
    ('block_number_fast_path', 0x2a3ec30, 'jne'),
    ('block_number_sentinel', 0x2a3ecb5, 'je'),
    ('block_number_optional_metric', 0x2a3ed43, 'je'),
    ('block_number_unlock', 0x2a3ee23, 'je'),
    ('block_number_duration_check', 0x2a3ef41, 'jbe'),
    ('envelope_selects_result', 0x260b489, 'jne'),
    ('error_serialize_failed', 0x260cbad, 'jne'),
    ('error_omits_data', 0x260ccef, 'je'),
    ('reward_source_empty', 0x2a20e19, 'je'),
    ('reward_multiple_rows', 0x2a20e85, 'jae'),
    ('reward_no_rows', 0x2a20e8e, 'je'),
    ('reward_no_percentiles', 0x2a20f2a, 'je'),
    ('reward_has_rows', 0x2a20f39, 'jae'),
    ('reward_threshold_met', 0x2a21073, 'jae'),
    ('reward_last_row', 0x2a21078, 'jae'),
    ('reward_cumulative_no_overflow', 0x2a21085, 'jae'),
    ('reward_index_out_of_bounds', 0x2a21098, 'jae'),
    ('reward_sort_large', 0x2a21204, 'jae'),
    ('concat_no_segments', 0x231ff01, 'je'),
    ('concat_length_overflow', 0x231ff25, 'jb'),
    ('concat_allocation_success', 0x231ffa8, 'jne'),
    ('concat_all_segments_copied', 0x2320025, 'je'),
    ('concat_segment_exceeds_capacity', 0x2320040, 'ja'),
]

TABLES = [
    ('outer', 0x2d0befe, 4, 0x2d0bee0),
    ('outer_nested', 0x2d0bfab, 4, 0x2d0bee0),
    ('history', 0x2a1fd46, 4, 0x2a1fd20),
    ('history_nested', 0x2a1fdf6, 4, 0x2a1fd20),
    ('history_range', 0x2a2001d, 4, 0x2a1fd20),
    ('reader', 0x2a0acdb, 4, 0x2a0acc0),
    ('reader_nested', 0x2a0ada2, 4, 0x2a0acc0),
    ('reader_task', 0x2a0adde, 4, 0x2a0acc0),
    ('error_codes', 0x25cd8be, 4, 0x25cd880),
    ('wire_error_codes', 0x260cc18, 8, 0x260cb30),
]

# Each relocation below establishes a particular descriptor/future slot, not
# dynamic reachability or the behavior of unselected trait-object instances.
RELATIONS = [
    ('descriptor_callback_a', 0x6450778, 0x2d032b0),
    ('descriptor_callback_b', 0x6450780, 0x2d032b0),
    ('outer_poll', 0x6450a60, 0x2d0bee0),
    ('history_poll', 0x64455a8, 0x2a1fd20),
    ('task_run', 0x64494c0, 0x2b230d0),
    ('task_join_poll', 0x64494d8, 0x2b16880),
]

# RIP-relative indirect calls with a pinned RELA slot. These records identify
# the selected first-level target; they do not resolve subsequent vtable calls.
INDIRECT_CALLS = [
    ('task_ready', 0x2b16891, 0x64dfe80, 0x5cdb250),
    ('iterator_create', 0x26980cc, 0x64e5bb8, 0x5d34520),
    ('seek_upper', 0x2698140, 0x64e5ba8, 0x5d34890),
    ('seek_lower', 0x2698181, 0x64e5bb0, 0x5d34840),
    ('iterator_valid', 0x26981bf, 0x64e20a8, 0x5d34810),
    ('iterator_key', 0x269822a, 0x64e20b0, 0x5d34900),
    ('iterator_value', 0x26982db, 0x64e20b8, 0x5d34920),
    ('iterator_reverse_step', 0x26981f3, 0x64e50d0, 0x5d348f0),
    ('iterator_forward_step', 0x269842e, 0x64e50e0, 0x5d348e0),
    ('iterator_destroy', 0x2698462, 0x64e50a8, 0x5d347e0),
]

# These are selected imported functions, not a catalogue of dynamic symbols.
EXTERNAL_CALLS = [
    ('concat_copy', 0x232000d, 0x64df508, 'memcpy'),
    ('prefix_equality', 0x269825b, 0x64df9f8, 'bcmp'),
    ('range_bound_compare', 0x2698289, 0x64dfb50, 'memcmp'),
]

# label, LEA site, exact pointed-to bytes, immediate-length site, immediate form
LITERALS = [
    ('block_count', 0x2d0cce1, b'block_count', 0x2d0ccf7, 'esi'),
    ('block_count_type', 0x2d0cce8, b'U64', 0x2d0ccfc, 'ecx'),
    ('newest_block', 0x2d0cd80, b'newest_block', 0x2d0cd96, 'esi'),
    ('newest_block_type', 0x2d0cd87, b'BlockNumberOrTag', 0x2d0cd9b, 'ecx'),
    ('reward_percentiles', 0x2d0ce0a, b'reward_percentiles', 0x2d0ce20, 'esi'),
    ('reward_percentiles_type', 0x2d0ce11, b'Option < Vec < f64 > >', 0x2d0ce25, 'ecx'),
    ('baseFeePerGas', 0x22e08d5, b'baseFeePerGas', 0x22e08e6, 'edx'),
    ('gasUsedRatio', 0x22e0904, b'gasUsedRatio', 0x22e0910, 'edx'),
    ('baseFeePerBlobGas', 0x22e0a18, b'baseFeePerBlobGas', 0x22e0a29, 'edx'),
    ('blobGasUsedRatio', 0x22e0a53, b'blobGasUsedRatio', 0x22e0a5f, 'edx'),
    ('oldestBlock', 0x22e0a82, b'oldestBlock', 0x22e0a93, 'edx'),
    ('reward', 0x2338948, b'reward', 0x233894f, 'edx'),
    ('invalid_params', 0x2d0c1e0, b'Invalid params', 0x2d0c1f7, 'ecx'),
    ('is_present', 0x2a2182e, b'is present', 0x2a2183c, 'esi'),
    ('jsonrpc', 0x260b3a2, b'jsonrpc', 0x260b3a9, 'ecx'),
    ('id', 0x260b41b, b'id', 0x260b422, 'ecx'),
    ('result', 0x260b4d1, b'result', 0x260b4d8, 'ecx'),
    ('error', 0x260cb79, b'error', 0x260cb80, 'ecx'),
    ('code', 0x260cbdb, b'code', 0x260cbe2, 'ecx'),
    ('message', 0x260cc9a, b'message', 0x260cca1, 'ecx'),
    ('data', 0x260cd0e, b'data', 0x260cd15, 'ecx'),
]

FORK_PREFIXES = [
    b'z_forks/bincode-fork/',
    b'z_forks/hyper-fork/',
    b'z_forks/hyper-tls-fork/',
    b'z_forks/reth-chainspec/',
    b'z_forks/reth-ethereum-forks/',
    b'z_forks/reth-rpc-eth-types/',
    b'z_forks/reth-rpc-server-types/',
    b'z_forks/revm-precompile/',
    b'z_vendor/alloy-consensus/',
    b'z_vendor/alloy-eip2930/',
    b'z_vendor/alloy-eip7702/',
    b'z_vendor/alloy-eips/',
    b'z_vendor/alloy-evm/',
    b'z_vendor/alloy-primitives/',
    b'z_vendor/alloy-rlp/',
    b'z_vendor/alloy-rpc-types-eth/',
    b'z_vendor/alloy-sol-types/',
    b'z_vendor/alloy-trie/',
    b'z_vendor/jsonrpsee-core/',
    b'z_vendor/jsonrpsee-types/',
    b'z_vendor/revm-bytecode/',
    b'z_vendor/revm-context/',
    b'z_vendor/revm-context-interface/',
    b'z_vendor/revm-handler/',
    b'z_vendor/revm-inspector/',
    b'z_vendor/revm-interpreter/',
    b'z_vendor/revm-state/',
    b'z_vendor/rocksdb/',
    b'z_vendor/serde_json/',
]

WINDOWS = [
    ('task_failure_cleanup', 0x29b0890, '488d05b973afff48894424084889742410488b05d80fb3034889442418488d3df1fba7fd4889e6e8b41e05004989c6498b5f084885db743b4d8b7f10498b074885c074054889dfffd0498b77084885f67421498b4710f3480fbcc831d24839f00f47d14883f8110f43d14889dfff159debb203'),
    ('register_refcount', 0x2d024ed, '4c8b2ef049ff45000f8e9f000000'),
    ('register_descriptor', 0x2d02543, '4889442410488d0509e27403488944241848c7442408010000004c8d4424084889df4c89e64c89fa4c89f1ff1524fc7d03'),
    ('register_failures', 0x2d02585, '488d5c2418bf08000000be18000000ff15f6ce7d030f0b4989c6f049ff4d0075094889dfff1509497e034c89f7e899e46e03'),
    ('callback_capture', 0x2d032b8, '488b07f048ff007e7f488b4a1048894c24100f10020f29042448894424304c894c24380f10060f11442418488b461048894424284c89442440c684248800000000'),
    ('callback_allocate_return', 0x2d032f1, 'c684248800000000bf90000000ff157cc17d034885c074274889e6ba900000004889c74889c3ff15ebc17d03488d1524d774034889d84881c4900000005bc3'),
    ('outer_dispatch', 0x2d0bef7, '0fb68688000000488d0dc33c90fd486304814801c84889bc2428010000ffe0'),
    ('outer_object_prefix', 0x2d0c040, '4d85ed0f84bd000000488b6b50807d007b0f85b80000004889ac24d00100004c89ac24d80100000f57c00f118424e00100004889ac24f00100004c89ac24f8010000488d7c2470488db424d0010000e8dc8c06ff488b6c2460837c2470060f85a1030000'),
    ('outer_empty_array', 0x2d0c106, '4839c57474488b6b504983fd02752c66817d005b5d7462'),
    ('missing_param', 0x2d0c191, 'bf0e000000ff15e4327d034885c00f842b0d000048b96520706172616d734889480648b94e6f206d6f72652048890848c78424d00100000e00000048898424d801000048c78424e00100000e000000488d15baa590fd488dbc24300100004c8d8424d0010000b90e000000bea680ffffe87a168cff'),
    ('first_parameter', 0x2d0c37b, '4983fd01740a807d01c00f8cac0b000049ffcd48ffc548c78424d00100000000000048c78424d80100000100000048c78424e0010000000000004889ac24e80100004c89ac24f00100000f57c00f118424f80100004889ac24080200004c89ac241002000066c7842418020000008048c784242002000000000000c684242802000000488d7c2420488db424d0010000e8d00406ff488b4424204883f8020f857b010000488bb424d00100004885f6'),
    ('second_parameter', 0x2d0c215, '4c8bbc2438010000488d7c2420488d742408e834480000837c2420030f85150b00000f104424280f29842400010000'),
    ('third_parameter', 0x2d0c295, '4983fd01740a807d01c00f8c750c000049ffcd48ffc548c78424d00100000000000048c78424d80100000100000048c78424e0010000000000004889ac24e80100004c89ac24f00100000f57c00f118424f80100004889ac24080200004c89ac241002000066c7842418020000008048c784242002000000000000c684242802000000488d7c2420488db424d0010000e836f505ff4c8b74242048b90100000000000080488d41014939c6'),
    ('parameter_transfer', 0x2d0c73a, '488b4b604883c110488d5368c683810000000048898c24f80100004c89bc24080200000f288424000100000f298424d00100004c89ac24e001000048897424604889b424e801000048898424f00100004889942400020000c68424c004000000bff8020000ff15db2c7d03'),
    ('future_allocation', 0x2d0c79a, 'bff8020000ff15db2c7d034885c00f84890500004989c6488db424d0010000baf80200004889c7ff15412d7d034c897370488d05be8d730348894378488dbc24d00100004c89f64889eaff5018'),
    ('future_pending', 0x2d0c7e7, '4c8bbc24d001000048b801000000000000804939c7751b41c6042403488b84242801000048c70002000000b103e9cc030000'),
    ('future_completion', 0x2d0c92c, '4989d54939c774430f288424900500000f288c24a00500000f289424b00500000f289c24c00500000f299c24c00100000f299424b00100000f298c24a00100000f298424900100004d89fd'),
    ('response_formatter_call', 0x2d0cb02, '488b432848898424a00100000f1043180f29842490010000488b4b40488dbc24d0010000488db42490010000488d9424d805000048899c2420010000e82daf5cff'),
    ('outer_return', 0x2d0cbae, '488b8424280100004889184c8978080f284424600f1340104c8960184c896820488b4c24184889482840886830b101488b9c2420010000888b8800000048'),
    ('block_count_error', 0x2d0cce1, '488d3d7bb290fd488d157fb290fd4c8d8424d0010000be0b000000b9030000004531c9ff15a6547d03'),
    ('newest_block_error', 0x2d0cd80, '488d3dd0b190fd488d15823874fd4c8d8424d0010000be0c000000b9100000004531c9ff1507547d03'),
    ('percentiles_error', 0x2d0ce0a, '488d3d1eb190fd488d1529b190fd4c8d8424d0010000be12000000b91600000041b901000000ff157a537d03'),
    ('error_dispatch', 0x25cd8a9, '418d855b7f000083f8034c897424080f87eb000000488d0d671d02fe486304814801c8ffe0'),
    ('error_invalid_params_arm', 0x25cd953, '41be050000004885db786be983000000'),
    ('error_value', 0x25cda17, '31c04983fd014883d001458974243045897c243449895c241849896c242049895c2428498904244d896c2408488b4424084989442410'),
    ('inner_dispatch', 0x2a1fd3f, '0fb686f0020000488d0dc316befd486304814801c84889742408ffe0'),
    ('inner_arguments', 0x2a1fd5b, '498b7528498b453849894540498b4d00498b6d086641c785f10200000000498b551048899424d0010000498b551848899424f00100004d8b7530498d5d4849894d4849896d50410f104510410f114558498b552049895568498975704d89757849898580000000498d95e802000048899424a001000041c685e802000000'),
    ('zero_count', 0x2a1fe68, '4885c00f841f010000'),
    ('option_sentinel', 0x2a1fe71, '498d95a800000048bf000000000000008048393a0f85c1010000'),
    ('clamp_and_variant', 0x2a1fe8b, '4883f805761049c7859000000005000000b80500000083f905744c83f904751a49c78598000000000000004883f8014883d0ff49898590000000'),
    ('resolve_latest', 0x2a1fec5, '4989dc488dbc24b0000000e89b1d0000488b9c24b0000000488bac24b80000004883fb030f85ca0300004c89e3'),
    ('latest_plus_one', 0x2a1fef2, '4989ecc68424b00000000949ffc40f85ae010000'),
    ('zero_result', 0x2a1ff90, 'c744243b00000000c744243800000000660f57c0660f29442420b8080000004889442448b810000000488944245848c7842440010000000000004531f648b80000000000000080488944241848c744245000000000b90800000048894c246048c74424100000000031ed4531ffe9f9070000'),
    ('nested_dispatch', 0x2a1fdea, '410fb685e8020000498d5d48488d0d2316befd486304814801c8ffe0'),
    ('limit_and_error', 0x2a2004c, '498b95b80000004883fa64761f48b800000000000000804989c740b517e98d070000'),
    ('percentile_loop', 0x2a20078, '498bbdb00000004883c708f20f10050d94a3fd0f1f4400004883fa020f82f1fdfffff20f104ff8660f2ec877b448ffca660f2e0f488d7f0876deeba5'),
    ('range_calculation', 0x2a200b4, '488dbc24b0000000e86ff2fcff498b85900000004939c4730a4d89a5900000004c89e04929c44d89a5c0000000'),
    ('backend_lookup_call', 0x2a201a7, '4c39e50f8294feffff498bb540010000498b8548010000488b10488dbc24b0000000e86263feff488b8424b000000048b900000000000000804839c80f851d010000'),
    ('backend_failure', 0x2a201e9, '0fb6ac24c00000008b8424c1000000898424680100008b8424c40000008984246b010000488b8424c800000048894424784c8bbc24d0000000660f108424d8000000660f29442420488b8424e800000048894424584c8ba424f0000000488b8424f80000004889842440010000488b8424000100004889442448488b8424080100004889442450488b8424100100004889442418488b84241801000048894424408b8424680100008b8c246b010000898424a8010000898c24ab01000041c60601'),
    ('range_future_poll', 0x2a20442, '4d8db5d8010000488dbc24b00000004c89f64c89fae864a8feff0fb6ac24b00000004080fd297537488b442460c60003488b8424a0010000c6000348b9000000000000008048ffc1488b8424d8010000488908b103488b5c2408e954060000'),
    ('range_result_decision', 0x2a2059d, '4080fd280f85b7000000488b5c247848899c24c00200004c89bc24c8020000660f6f44242066490f7ec4660fd68424d00200004d3ba5900000004c89bc24800100000f85af0000004d85e40f84401200004c89a424e00100004d69e4e00300004d01fc'),
    ('range_mismatch_cleanup', 0x2a20694, '49ffc44c89ff660f1f4400004983fc0174144c8db7e003000049ffcce82be08eff4c89f7ebe640b5094885db74124869f3e00300004c89ff31d2ff15ccedab03'),
    ('vector_cleanup', 0x2a20720, '498b85280100004885c07417498bbd3001000048c1e003488d344031d2ff155dedab0341c685e902000000498bb5100100004885f6488b1c247413498bbd1801000048c1e60331d2ff1532edab0341c685ea02000000498bb5f80000004885f64d89e67413498bbd0001000048c1e60431d2ff1508edab0341c685eb02000000498bb5e00000004885f67413498bbde800000048c1e60331d2ff15e1ecab0341c685ec02000000498bb5c80000004885f67413498bbdd000000048c1e60431d2ff15baecab03'),
    ('inner_result', 0x2a20a60, '488b8c2470020000488b8424d801000048894870488b8c247802000048894878488b8c246002000048894860488b8c246802000048894868488b8c245002000048894850488b8c2458020000488948580f108424400200000f114040660f10842400020000660f108c2410020000660f10942420020000660f109c2430020000660f115830660f115020660f114810660f1100b101888bf0020000'),
    ('block_stride_and_base', 0x2a20b0d, '4c8b7c24484981c7e00300004d39e70f84a407000041803f007416498b5f084d8bb5d80000004d3bb5c80000007414eb1d31db4d8bb5d80000004d3bb5c8000000750b488b7c2450ff15ad64ac03498b85d00000004c89f148c1e10448891c0848c74408080000000049ffc64d89b5d8000000'),
    ('block_ratio_input', 0x2a20b80, 'f2410f1087300200000f29442460f2410f1087280200000f29442420'),
    ('block_ratio_output', 0x2a20bba, 'f20f100d4e06a3fd660f285c24600f14d9660f28159df5a2fd660f5cda660f28c3660f15c3f20f58c3660f285c24200f14d9660f5cda660f28cb660f15cbf20f58cbf20f5ec1498b85e8000000f20f1104d848ffc349899df0000000'),
    ('blob_fee_select', 0x2a20c1b, '41837f200141be0000000041bf000000007526488b442448488b5028bf0100000041b8edf0320031f631c94531c9e8824ca0fe4989c64989d7'),
    ('blob_ratio', 0x2a20c90, '4c8b7c2448f2410f1047180f14056e05a3fd660f5c05c6f4a2fd660f28c8660f15c8f20f58c8f20f5e0df283a3fd660f294c242041807f1000750a660f57c0660f29442420498b9d20010000493b9d10010000750e488bbc2490010000ff155554ac03498b8518010000660f28442420f20f1104d848ffc349899d20010000'),
    ('reward_switch', 0x2a20d0f, '48b80000000000000080493985a80000000f84ecfdffff'),
    ('reward_quantile_math', 0x2a20fed, '483b6c24580f84d8000000f20f104500f20f59842440010000f20f5e058a84a3fdf2480f2cc04883c5084889c148c1f93f660f28c8f20f5c0d3683a3fdf2480f2cd14821ca4809c2660f57c9660f2ec1b900000000480f43ca660f2e050a7da3fd48c7c0ffffffff480f47c84c89f0'),
    ('last_block_absence', 0x2a2182e, '488d3d940bbefd488d156c36a203be0a000000ff1529dfab03eb30'),
    ('inner_unwind_state', 0x2a21bdb, '41c685e8020000024889dfe84593fcff4180bdf2020000007431'),
    ('resolver_name', 0x2a21c84, '4c8baed8030000498d7d10488d053d07befd488984246801000048c78424700100000f00000048c784246001000000000000'),
    ('resolver_branch', 0x2a21cc5, '4180bd60010000007456488d05152da1fd488984241001000048c784241801000016000000c7842420010000c601000049c7c780eeffff644c8b2425000000004d01fc64410fb6472083f801744683f802751f488d3dd11fa203ff1583ecab03488db42460010000e82ece0100e94c070000'),
    ('resolver_compare', 0x2a21de9, '4e39643b1875f04639743b1075e94e396c3b0875e24a8b3c3b488bb424000100004c89eaff15e5dbab0385c075c9'),
    ('registry_check', 0x2a06551, '4d85f60f846201000049837e18000f8457010000498b06498b4e0849bf0d03652069d95aa631d2660f6f0570f2a4fd660f76c949bcef0e206eed65ae37'),
    ('registry_lookup', 0x2a06591, '4821cef30f6f1430660f6fda660f74d8660fd7fb85ff7435f3440fbccf4901f14921c949c1e1054989c04d29c84d8b48e84d31f94d8b50e04d31e24d09ca742a448d47ff664121f84489c775cb660f74d1660fd7fa85ff0f85ce0000004801d64883c6104883c210eb96498b78f0498b40f8'),
    ('registry_identity', 0x2a065fb, '498b78f0498b40f8ff50284989c64889e74889c6ff52184d85f60f84a10000004c3324244c337c24084d09e70f858f000000410fb6461088842488000000410f10060f11442478'),
    ('registry_missing', 0x2a066bc, 'c643102548b80000000000000080488903488dbc2490000000e836e5fdff'),
    ('reader_dispatch', 0x2a0acd4, '0fb686f0000000488d0d7265bffd486304814801c848897c2408ffe0'),
    ('reader_range_overflow', 0x2a0ad1c, '4889e84c29f00f93c14883f8ff400f95c64020ce4080fe010f858a0000004889542410'),
    ('reader_spawn', 0x2a0afc9, '488d35888da303488d7c2470e8c62a1300488983a8000000488b5424104c896424104c8daba8000000488d7c24204c89eee881f94300488b6c24204883fd02751b'),
    ('reader_pending', 0x2a0b00a, '41c60603488b442410c60003488b442408c60029b003e93c010000'),
    ('reader_job_status', 0x2a0b055, 'ff50204c89ea83fd01752d488dbb980000004c8964242048895424284c89742430488d742420e80058faff4889c2488b442418c60001eb27488b442418c6000148b801000000000000804939c40f8466ffffff4c89e048f7d80f81c5000000'),
    ('reader_result_cases', 0x2a0b0e4, '4584ff4889ef74114c3bb3e0000000751641b7284c89f0eb4a4889f84c89e741b7274d89eceb3c49ffc6'),
    ('reader_return', 0x2a0b12a, '41b7094d85e474124969f4e00300004889ef31d2ff155c43ad034d89ec488b4c24084488394c89610848897910488941184c897120b0018883f0000000'),
    ('task_allocation', 0x2b3dc10, 'bf00010000be07000000ff1570199a034885c00f84960000004989c741f6d5410fb6c583e001c1e0064901c44981c4f8010000488db42480000000ba000100004c89ffff15af189a03488d4c24304c89e74c89feba01000000ff15a99a9a034885d20f95c120c180f9017458'),
    ('task_refcount_trap', 0x2b3db0d, '4885c0741a4881ca00020000498b541418f048ff007e06f048ff007f020f0b'),
    ('job_poll', 0x2e4aa0a, '498b3c24498b17488b4710488d742408ff5018837c2408020f94c00f104424080f104c24180f114b100f1103'),
    ('bridge_copy', 0x22d7b71, 'c68424f001000001410f104500410f104d10410f105520410f105d300f298424500100000f298c24600100000f299424700100000f299c2480010000410f1045400f29842490010000410f1045500f298424a0010000410f1045600f298424b0010000410f1045700f298424c001000048899c24d001000048894c244048898c24d80100004c89a424e0010000'),
    ('bridge_serialize', 0x22d7c0a, '488d8424d00000004889442458488dbc24500100004c8d6c245841b4014c89eee8313733004885c0'),
    ('envelope_select', 0x260b475, '49bf00000000000000804d8b26498d47014939c4752d4983c608488d7c24084c89f6e8941600004885c075c831c0f64424080175bf807c24090074b8488b5c2410eb68'),
    ('envelope_success', 0x260b503, '4d39fc75044d8b76084c89f74889dee83953cdff4885c00f8549ffffff'),
    ('field_base_fee', 0x22e08c3, '48837c245000488b5c2460743048895c2418488d35dfa130fe488d7c2408488d4c2418ba0d000000e8107b2d004885c0752e807c2408010f84dc010000'),
    ('field_gas_ratio', 0x22e0900, '488d4b18488d350da330fe488d7c2408ba0c000000e8f6002c004885c00f84d9000000'),
    ('field_blob_base_fee', 0x22e09fc, '48837c2448007438488d43304889442430807c2408010f84c4000000488d3505a230fe488d7c2408488d4c2430ba11000000e8cd792d004885c00f85e7feffff'),
    ('field_blob_ratio', 0x22e0a3c, '48837c244000742e807c2408010f848d000000488d4b48488d35460117fe488d7c2408ba10000000e8a7ff2b004885c00f85b1feffff'),
    ('field_oldest', 0x22e0a72, '488d43784889442430807c240801745a488d35aca130fe488d7c2408488d4c2430ba0b000000e833f92a004885c00f857dfeffff'),
    ('field_reward', 0x22e0aa6, '48f75c243870214883c36048895c2418488d7c2408488d742418e87b7e05004885c00f8555feffff'),
    ('reward_name', 0x2338940, '803f0075144889f1488d35f1222bfeba06000000e9e7c12700'),
    ('task_capture_and_table', 0x2b3db2c, '410f1007410f104f10410f1057200f114424440f114c24540f11542464498b7730488974247448c7842480000000cc00000048c784248800000000000000488d354fb990034889b4249000000048c784249800000000000000'),
    ('task_capture_to_object', 0x2b3db9d, 'c78424b8000000000000000f104424400f118424bc0000000f104424500f118424cc0000000f104424600f118424dc000000488b4c246c48898c24e8000000488b4c247448898c24f0000000'),
    ('task_poll_initialized', 0x2e4a997, '48c744240802000000'),
    ('task_runner_capture', 0x2b2323c, '488b434048896b404889c148f7d90f80bb02000048898424b0000000f30f6f4348f30f6f4b580f105368f30f7f8424b8000000f30f7f8c24c80000000f119424d8000000'),
    ('task_runner_query', 0x2b232ac, '488b8424e00000004889442430f30f6f8424b0000000f30f6f8c24c00000000f109424d00000000f29542420660f7f4c2410660f7f0424488b4424284889842410010000488b442430488984241801000048c784240001000000000000c684242001000000488dbc24e80000004989e4488d9424000100004c89e6e8d44cb7ff'),
    ('task_runner_result', 0x2b23541, '4c8bb424900000004939ee0f8451feffffc70424020000004889e6488d7b20e84be10000f30f6f84249800000048ffc54939ee0f840202000031c048894424584c89742460f30f7f442468c744245001000000488d742450488d7b20e80ee100004889dfe896150100'),
    ('task_result_copy', 0x2b31765, '410f1006410f104e10410f105620410f105e300f115d300f1155200f114d100f'),
    ('task_join_poll', 0x2b1688d, '488d7778ff15e9959c0384c07467410f104638410f104e48410f105658410f105e680f295c24500f295424400f294c24300f2944242041c7463802000000837c2420017538410f104640410f104e500f294c24100f290424833b0274084889dfe89ebdf8ff0f2804240f284c24100f114b100f11034883c4685b415ec3'),
    ('task_join_unexpected', 0x2b1690a, '488d3dc1ffaefd488d15483b9303be45000000ff15958d9c030f0b'),
    ('task_ready_bit', 0x5cdb259, '4c8b2fb10141f6c5020f854e0100004889f341f6c5107568'),
    ('store_query_bounds', 0x2698011, '4889d0488b52104c8b7818bd080000004c39fa771f4989f6488b48080fb63048894c24684885c90f94c1408874240f4084ce740b4531ff4531e4e93f040000'),
    ('store_bound_calls', 0x2698078, '4c8dac24800000004c89ef4c89f6e8451000004c8da424980000004c89e74c89f64c89fae82f100000488d7c24404c89f6e872feffff'),
    ('store_iterator_create', 0x26980b8, '4d8b7618ff15dee0e4034889c3498b7e404889c6ff15e6dae4034989c64c89bc24100100004c89bc242801000048899c24400100004885c00f84e8030000'),
    ('store_direction', 0x2698116, '807c240e0048895c245874414c8bbc24980000004c8ba424a0000000488b9424a80000004c89f74c89e6ff1562dae403c644240dff4d85ff740e4c89e74c89fe31d2ff154273e4034d89eceb3c4c8bbc24800000004c8bac2488000000488b9424900000004c89f74c89eeff1529dae403c644240d014d85ff740e4c89ef4c89fe31d2ff150173e403'),
    ('store_iterator_first_key', 0x26981bc, '4c89f7ff15e39ee40384c00f846c020000488b44244848894424704c8b642450488b1dc59ee4034c89742418eb1c660f1f4400004c89f7ff15d7cee4034c89f7ffd384c00f84330200004c89f7ffd384c00f842602000048c7842410010000000000004c89f7488db42410010000ff15809ee4034885c00f8400020000488bac24100100004989ed4d29e50f82ec0100004989c74889c7488b7424704c89e2ff159777e40385c00f85d0010000'),
    ('store_key_end_comparison', 0x2698269, '4d89e64989dc4889eb488b4424784829c3480f43e84c89ff488b7424204889eaff15c178e403489885c0480f45d84885db4c89e34d89f44c8b7424180f98c00f9fc128c13a4c240d0f8482010000'),
    ('store_value_and_suffix', 0x26982b7, '4c89f7ffd384c00f847501000048c7842410010000000000004c89f7488db42410010000ff15d79de4034885c00f844f010000488b9424100100004d85ed74294983fd080f851f0100004f8b3c27490fcfb9010000004883f9017419e9080100000f1f84000000000031c94883f9010f85f4000000488dbc24f80400004889c6e894020000'),
    ('store_bad_value', 0x269833c, '4c8bac24f80400004983fd027542488b8424000500004883f8020f82c4000000488bb424080500000f84a3000000488bbc24100500004883f8034885f60f84a100000031d2ff151971e403e994000000'),
    ('store_append_and_limit', 0x269838c, 'bad8030000488dbc2420010000488db42400050000ff156171e4034c89bc24100100004c89ac24180100004c8b7c24384c3b7c2428750b488d7c2428ff15dadde403488b6c24304969ffe80300004801efbae8030000488db42410010000ff151871e40349ffc74c897c2438807c240f00488b742410741c4c3b7c24687215eb3b488b064889f7ff1066662e0f1f840000000000'),
    ('store_next', 0x2698420, '807c240e000f85c5fdffff4c89f7ff15accce403e9c0fdffff'),
    ('store_finish', 0x2698439, '488b6c24304c8b7c2438488b7424104c8b6424284885f6740d488b7c242031d2ff154170e4034c89f7ff1540cce403488b7c2458ff1515d7e403488b7424404885f6740d488b7c244831d2ff151670e403488b7c24604969c7e80300004801e84889ac24b00000004889ac24b80000004c89a424c000000048898424c8000000488db424b00000004889fbe86737c8ff4889d84881c4d80800005b415c415d415e415f5dc3488d3ddb7cd903ff154573e4030f'),
    ('value_decode', 0x26985de, '4989d64989f74889fb4889742420488954242848897424304889542438c644244400c64424400166c74424422000488d7c2478488d74242031d2e803092dff837c2478020f85b7000000'),
    ('value_decode_return', 0x26986df, '488d742478bae00300004889dfff15166ee403eb26488b7424084885f6740d488b7c241031d2ff15956de40348c743080400000048c70302000000'),
    ('range_prefix_copy', 0x2697f2b, '488b5e104885db743f4989fc4c8b7e084889dfff153c75e4034885c00f84900000004989c648895c240848894424104889c74c89fe4889daff159f75e40348895c24184c89e7eb21'),
    ('range_bound_encoding', 0x26990d9, '4989d74989fe488d7c2408e837eeffffbf08000000ff158c63e4034885c074774889c3490fcf4c8938488b44241848894424300f104424080f2944242048c74424380800000048895c244048c744244808000000488d742420ba020000004c89f7e8b16dc8ff'),
    ('range_projection', 0x231bc80, '4c8b25e1381c044c89fd660f1f4400004889fe4c8dafe80300004883c608bae00300004889ef41ffd44c89ef4881c5e00300004d39f575d8'),
    ('resolver_raw_state_call', 0x2a21d25, '488db42460010000e82ece0100e94c070000'),
    ('resolver_instrumented_state_call', 0x2a22453, '488b5c2478488db424600100004889dfe8f8c601004989c6488dbc2480000000e89801ccff4c89f0488b9c24f80000004889430848c70303000000'),
    ('block_number_lock', 0x2a3eb6e, '4989f74889fb0fb687200b000088442428bf01000000e8575724034989c64189d44c8daba8060000488b83a806000089c183e108c1e9034883f8f00f93c208ca74124c89ef31f6b900ca9a3bff151824aa03eb0c488d4810f0490fb14d0075e2'),
    ('block_number_fast_state_read', 0x2a3ec21, '81bb2801000000ca9a3b4c897c24700f8585000000488b83000b00004c8bb0d839000048c7c0f0fffffff0480fc183a80600004883e0f24531e4e9bf010000'),
    ('block_number_slow_state_read', 0x2a3ed19, '48f7da4d19ff488b83000b0000488b80d839000048894424504c8ba3180100004d85e40f95c0894424440f84b5000000'),
    ('block_number_unlock', 0x2a3edfe, '4c8b742450448b64244448c7c0f0ffffff488d8ba8060000f0480fc1014883e0f24883f8120f845e010000'),
    ('block_number_return', 0x2a3ef75, '4c89f04883c4785b415c415d415e415f5dc3'),
    ('outer_parameter_error_handoff', 0x2d0ce5e, '0f299424e00000000f298c24d00000000f298424c0000000488b442418488b304885f67e0c488b7b5031d2ff1511267d03488b4360f048ff08750a488d7b60ff1515a07d03488b7b68e884c40e0049bd0100000000000080e91dfbffff'),
    ('envelope_error_select', 0x260b475, '49bf00000000000000804d8b26498d47014939c4752d4983c608488d7c24084c89f6e8941600004885c075c831c0f64424080175bf807c24090074b8488b5c2410eb68'),
    ('envelope_error_output', 0x260cb30, '554157415641554154534883ec28803f000f85380200004989f64989ff488b5f08807f0101741d488d35f648fefdba010000004889dfe80564ceff4885c00f852d02000041c6470102488d15995afefdb9050000004889dfe8d325fbff4885c00f850b020000488d35b848fefdba010000004889dfe8c663ceff4885c00f85ee010000'),
    ('error_code_selection', 0x260cbd3, '458b7e30418b6e34488d159ed2e4fdb9040000004889dfe87125fbff4885c00f85a9010000488d355648fefdba010000004889dfe86463ceff4885c00f858c0100004489f8488d0d6546fefd486304814801c8ffe0bd4480ffffeb28bda780ffffeb21bdf982ffffeb1abda880ffffeb13bda580ffffeb0cbdf782ffffeb05bda680ffff4889e689efe8bfe9feff4889df4889c6e80463ceff4885c00f8521010000'),
    ('error_message_output', 0x260cc75, '4d8b7e204d8b6628488d35d047fefdba010000004889dfe8df62ceff4885c00f85fc000000488d15b647fefdb9070000004889dfe8b224fbff4885c00f85df000000488d359747fefdba010000004889dfe8a562ceff4885c00f85c20000004889df4c89fa4c89e1e87e24fbff4885c00f85ab000000'),
    ('error_data_output', 0x260cceb, '4183fd027464488d355c47fefdba010000004889dfe86b62ceff4885c00f8588000000488d1543d4e4fdb9040000004889dfe83e24fbff4885c0756f488d352747fefdba010000004889dfe83562ceff4885c07556498b7608498b56104889dfe82062ceff4885c07541'),
    ('outer_error_handoff_moves', 0x2d0c9d8, '488b8424f000000048898424000500000f288424c00000000f288c24d00000000f289424e00000000f299424f00400000f298c24e00400000f298424d00400000f288424900100000f288c24a00100000f289424b00100000f289c24c00100000f298424500500000f298c24600500000f299424700500000f299c248005000041c6042401488b7c2418e879900e0048c78424d8050000000000004c89ac24e80500000f288424d00400000f288c24e00400000f289424f00400000f118424f00500000f118c24000600000f11942410060000488b842400050000'),
    ('reward_input_rows', 0x2a20d26, '498bb780030000498b8788030000488d0480488d14c6488dbc24a8010000e847a192ff41803f007406498b4708eb0231c0498badb0000000498b8db800000048894c2420498b8f38030000498b9740030000488bbc24b00100004c8bbc24b801000048898424f80100004869c2500100004801c84b8d34bf488d1cf74939d7490f42d748898c2480020000'),
    ('reward_source_total', 0x2a20de5, '488d8424f801000048898424b002000048c78424b802000000000000488dbc2468010000488db42480020000e8fa4793ff4d85ff742bf20f1043f00f1405e903a3fd660f5c0541f3a2fd660f28c8660f15c8f20f58c8660f298c2440010000eb0d660f57c0660f29842440010000'),
    ('reward_vector_limits', 0x2a20e64, '488b8c2478010000488d84248700000048898424880000004883f90248894c24180f83750300004885c9740b488b4424104c8b6010eb034531e4488b4c24204989ce49c1e60448b8ffffffffffffff0f4839c10f97c048b900000000000000804883c1f04939ce0f97c108c10f858d0900004d85f6741c4c89f7ff159ce5ab034885c0488b5424200f84570900004889d1eb0cb81000000031c9488b54242048898c248800000048898424c0010000488984249000000048c7842498000000000000004885d20f84a00100004c8b6c24184983ed01735d'),
    ('reward_empty_source', 0x2a20f3b, '4c8b64242049c1e403bb010000004531f6eb2c6690488b842490000000660f57c066420f29047048899c249800000048ffc34983c6084d39f40f8456010000488d43ff483b84248800000075c8488dbc2488000000ff157260ac03ebb8'),
    ('reward_threshold_cast', 0x2a20ff8, 'f20f104500f20f59842440010000f20f5e058a84a3fdf2480f2cc04883c5084889c148c1f93f660f28c8f20f5c0d3683a3fdf2480f2cd14821ca4809c2660f57c9660f2ec1b900000000480f43ca660f2e050a7da3fd48c7c0ffffffff480f47c8'),
    ('reward_cumulative_selection', 0x2a21059, '4c89f048c1e005480344241066662e0f1f8400000000004939cc731b4d39ee731649ffc64c036030488d402073e9e9250700000f1f4000488b7424184939f60f8325070000488b0848894c2420488b40084889442460'),
    ('reward_sort_selection', 0x2a21200, '4883f915732aba01000000488b7c2410488b742418488d8c2488000000e81ed3caff4c8b6c2408488b1c24e960fcffff488b7c2410488b742418488d942488000000ff15d05dac03ebd8'),
    ('reward_overflow_panic', 0x2a217b1, '488d3d4021a203ff1562ddab03e9b6000000488d151621a2034c89f7ff154ddeab03e9a1000000'),
    ('reward_overflow_ud2', 0x2a21879, '0f0b'),
    ('concat_sum_lengths', 0x231fefe, '4885d2743e4989f648c1e203488d1c5231f631c066666666662e0f1f84000000000049037406100f821e0100004883c0184839c375ec4885f6795631ffff1557f51b04'),
    ('concat_allocate', 0x231ff8f, '48897c2420741f4889f74989f7ff15def41b044c89fe4885c07510bf01000000ff15e3f41b04b8010000004889742408488944241048c7442418000000004531ed4531e4eb56'),
    ('concat_copy_segments', 0x2320000, '4a8d3c284c89fe4889ea4989c7ff15f5f41b044c89f84901ed4c896c24184983c4184c39e30f8436ffffff4f8b7c26084b8b6c2610488b4c24084c29e94839cd77934885ed75b9ebcd'),
]


def read_unique_section(rows, name):
    found = [row for row in rows if row['name'] == name]
    if len(found) != 1 or found[0]['type'] == 8:
        raise ValueError('missing, duplicate, or NOBITS section: ' + name)
    return found[0]


def file_offset(rows, va, size):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid virtual interval')
    matches = [row for row in rows if row['type'] != 8 and row['flags'] & 2
               and row['address'] <= va and va + size <= row['address'] + row['size']]
    if len(matches) != 1:
        raise ValueError('virtual interval is not uniquely file-backed')
    row = matches[0]
    return row['offset'] + va - row['address']


def frozen(actual, expected):
    if actual != bytes.fromhex(expected):
        raise ValueError('frozen instruction window differs')


def decode_rel32(va, raw):
    if len(raw) != 5 or raw[0] != 0xe8:
        raise ValueError('not a selected rel32 CALL')
    return va + len(raw) + struct.unpack_from('<i', raw, 1)[0]


def decode_indirect_slot(va, raw):
    if len(raw) != 6 or raw[:2] != bytes.fromhex('ff15'):
        raise ValueError('not a RIP-relative indirect call')
    return va + 6 + struct.unpack_from('<i', raw, 2)[0]


def decode_lea(va, raw):
    if len(raw) != 7 or not 0x48 <= raw[0] <= 0x4f or raw[1] != 0x8d or raw[2] & 0xc7 != 5:
        raise ValueError('not a selected RIP-relative LEA')
    return va + len(raw) + struct.unpack_from('<i', raw, 3)[0]


def decode_branch(va, raw):
    names = {0: 'jo', 2: 'jb', 3: 'jae', 4: 'je', 5: 'jne', 6: 'jbe', 7: 'ja'}
    if len(raw) == 2 and 0x70 <= raw[0] <= 0x7f:
        kind, disp = raw[0] & 15, struct.unpack_from('<b', raw, 1)[0]
    elif len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        kind, disp = raw[1] & 15, struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('not a selected x86 conditional branch')
    if kind not in names:
        raise ValueError('unsupported branch condition')
    return names[kind], va + len(raw) + disp


def compare_f64(a, b):
    # UCOMISD sets CF=ZF=PF=1 on unordered; JA is false and JBE true.
    if math.isnan(a) or math.isnan(b):
        return 'unordered'
    if a < b:
        return 'less'
    if a > b:
        return 'greater'
    return 'equal'


def local_percentile_branch(count, values, max_length, upper):
    """Model the selected instructions, not request parsing or target execution."""
    if count == 0:
        return 'zero_count'
    if values is None:
        return 'continue'
    if len(values) > max_length:
        return 'invalid'
    for previous, following in zip(values, values[1:]):
        if compare_f64(previous, upper) == 'greater':
            return 'invalid'
        if compare_f64(previous, following) == 'greater':
            return 'invalid'
    return 'continue'


def local_range(count, newest, selector, cap):
    """Model range instructions after successful decoding/resolution."""
    maximum = (1 << 64) - 1
    if not all(isinstance(x, int) for x in (count, newest, selector, cap)):
        raise ValueError('range operands must be integers')
    if not 0 <= count <= maximum or not 0 <= newest <= maximum or cap < 0:
        raise ValueError('range operands outside u64')
    if count == 0:
        return {'route': 'zero_count'}
    limited = min(count, cap)
    if selector == 4:
        limited = max(0, limited - 1)
    if newest == maximum:
        return {'route': 'increment_overflow'}
    upper = newest + 1
    actual = min(upper, limited)
    oldest = upper - actual
    if oldest > newest:
        return {'route': 'range_order_error', 'limited_count': actual, 'oldest': oldest, 'newest': newest}
    return {'route': 'range', 'limited_count': actual, 'oldest': oldest, 'newest': newest}


def model_bound_key(prefix, number):
    if not isinstance(prefix, bytes) or not isinstance(number, int) or not 0 <= number < (1 << 64):
        raise ValueError('invalid bound-key input')
    return prefix + number.to_bytes(8, 'big')


def model_key_suffix(prefix, key):
    if not isinstance(prefix, bytes) or not isinstance(key, bytes):
        raise ValueError('invalid key input')
    if not key.startswith(prefix) or len(key) != len(prefix) + 8:
        return None
    return int.from_bytes(key[len(prefix):], 'big')


def model_reward_selection(percentiles, rows, total):
    """Model selection after the unmodeled helper has ordered its rows.

    Each row is (u64 weight, u128 payload). The total comes from a separate
    source vector; this model does not assume it equals the sum of weights.
    """
    max64, max128 = (1 << 64) - 1, (1 << 128) - 1
    if not isinstance(total, int) or not 0 <= total <= max64:
        raise ValueError('reward total outside u64')
    if any(not isinstance(w, int) or not isinstance(p, int)
           or not 0 <= w <= max64 or not 0 <= p <= max128 for w, p in rows):
        raise ValueError('reward row outside integer bounds')
    if not rows:
        return [0 for _ in percentiles]
    cursor, accumulated, result = 0, rows[0][0], []
    for pct in percentiles:
        scaled = (pct * float(total)) / 100.0
        if math.isnan(scaled) or scaled <= 0.0:
            threshold = 0
        elif scaled >= float(1 << 64):
            threshold = max64
        else:
            threshold = int(scaled)
        while accumulated < threshold and cursor < len(rows) - 1:
            cursor += 1
            accumulated += rows[cursor][0]
            if accumulated > max64:
                raise OverflowError('reward cumulative weight overflow')
        result.append(rows[cursor][1])
    return result


class Image:
    def __init__(self, data, *, require_digest=True):
        self.data = data
        digest = hashlib.sha256(data).hexdigest()
        if require_digest and digest != DIGEST:
            raise ValueError('node 115 SHA-256 mismatch')
        self.digest = digest
        self.secs, indexed = unwind_index(data)
        self.index = {row['start']: row for row in indexed}
        if len(self.index) != len(indexed):
            raise ValueError('duplicate unwind start')
        self.cies, fdes = eh_frame_records(data, self.secs)
        starts = {}
        for row in fdes:
            starts.setdefault(row['start'], []).append(row)
        self.selected = {}
        for name, start in FUNCTIONS:
            if len(starts.get(start, [])) != 1 or start not in self.index:
                raise ValueError('selected FDE is missing or ambiguous')
            row = starts[start][0]
            if row['fde'] != self.index[start]['fde'] or row['end'] <= start:
                raise ValueError('FDE and unwind index disagree')
            self.read(start, row['end'] - start, executable=True)
            self.selected[start] = (name, row)
        self.ordered = sorted(self.selected)
        self.relocs = self.read_relocations()

    def offset(self, va, size=1):
        return file_offset(self.secs, va, size)

    def read(self, va, size, *, executable=False):
        off = self.offset(va, size)
        if executable:
            matches = [s for s in self.secs if s['type'] != 8 and s['flags'] & 4
                       and s['address'] <= va and va + size <= s['address'] + s['size']]
            if len(matches) != 1:
                raise ValueError('interval is not uniquely executable')
        result = self.data[off:off + size]
        if len(result) != size:
            raise ValueError('truncated data')
        return result

    def owner(self, va, size=1):
        i = bisect.bisect_right(self.ordered, va) - 1
        if i < 0:
            raise ValueError('site outside selected FDEs')
        start = self.ordered[i]
        name, row = self.selected[start]
        if va < start or va + size > row['end']:
            raise ValueError('site outside selected FDE')
        return name, row

    def lea(self, site):
        self.owner(site, 7)
        return decode_lea(site, self.read(site, 7, executable=True))

    def checked_window(self, site, expected):
        raw = self.read(site, len(expected) // 2, executable=True)
        self.owner(site, len(raw))
        frozen(raw, expected)
        return raw

    def read_relocations(self):
        sec = read_unique_section(self.secs, '.rela.dyn')
        if sec['size'] % 24:
            raise ValueError('truncated relocation section')
        wanted = ({slot for _, slot, _ in RELATIONS}
                  | {slot for _, _, slot, _ in INDIRECT_CALLS}
                  | {0x6444e90, 0x6444ea8, 0x6444ec0, 0x64455b0, 0x6444f08})
        result = {}
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            raw = self.data[off:off + 24]
            slot, info, addend = struct.unpack('<QQq', raw)
            if slot not in wanted:
                continue
            if slot in result:
                raise ValueError('duplicate selected relocation slot')
            if info != 8:
                raise ValueError('selected relocation is not R_X86_64_RELATIVE')
            self.read(slot, 8)
            result[slot] = {'slot': slot, 'addend': addend, 'file_offset': off, 'record': raw.hex()}
        if set(result) != wanted:
            raise ValueError('missing selected relocation')
        return result

    def fde_rows(self):
        header = read_unique_section(self.secs, '.eh_frame_hdr')
        rows = []
        for name, start in FUNCTIONS:
            _, f = self.selected[start]
            index = self.index[start]
            record_va = f['fde']
            length = struct.unpack('<I', self.read(record_va, 4))[0]
            if length in (0, 0xffffffff):
                raise ValueError('unsupported FDE size')
            record = self.read(record_va, 4 + length)
            cie_va = f['cie']
            cie_length = struct.unpack('<I', self.read(cie_va, 4))[0]
            cie = self.read(cie_va, 4 + cie_length)
            entry_off = header['offset'] + 12 + index['index'] * 8
            entry = self.data[entry_off:entry_off + 8]
            if len(entry) != 8:
                raise ValueError('truncated unwind entry')
            body = self.read(start, f['end'] - start, executable=True)
            rows.append({'role': name, 'start_va': hex(start), 'end_va_exclusive': hex(f['end']),
                         'file_offset': hex(self.offset(start, len(body))), 'size': len(body),
                         'body_sha256': hashlib.sha256(body).hexdigest(),
                         'fde_va': hex(record_va), 'fde_file_offset': hex(self.offset(record_va, len(record))),
                         'fde_bytes': record.hex(), 'cie_va': hex(cie_va), 'cie_bytes': cie.hex(),
                         'unwind_index': index['index'], 'unwind_entry_file_offset': hex(entry_off),
                         'unwind_entry_bytes': entry.hex(), 'lsda_va': None if f['lsda'] is None else hex(f['lsda'])})
        return rows

    def window_rows(self):
        out = []
        for label, start, expected in WINDOWS:
            raw = self.checked_window(start, expected)
            name, f = self.owner(start, len(raw))
            out.append({'label': label, 'owner': name, 'fde_start': hex(f['start']),
                        'va': hex(start), 'end_va_exclusive': hex(start + len(raw)),
                        'file_offset': hex(self.offset(start, len(raw))), 'bytes': raw.hex()})
        return out

    def call_rows(self):
        rows = []
        for label, site, expected in CALLS:
            owner, fde = self.owner(site, 5)
            raw = self.read(site, 5, executable=True)
            target = decode_rel32(site, raw)
            if target != expected:
                raise ValueError('selected call destination differs')
            rows.append({'label': label, 'owner': owner, 'fde_start': hex(fde['start']),
                         'site_va': hex(site), 'file_offset': hex(self.offset(site, 5)),
                         'bytes': raw.hex(), 'target_va': hex(target),
                         'target_selected': target in self.selected})
        return rows

    def branch_rows(self):
        rows = []
        for label, site, condition in BRANCHES:
            first = self.read(site, 1, executable=True)[0]
            size = 6 if first == 0x0f else 2
            owner, fde = self.owner(site, size)
            raw = self.read(site, size, executable=True)
            actual, target = decode_branch(site, raw)
            if actual != condition or not fde['start'] <= target < fde['end']:
                raise ValueError('branch condition or target differs')
            rows.append({'label': label, 'owner': owner, 'site_va': hex(site),
                         'file_offset': hex(self.offset(site, size)), 'bytes': raw.hex(),
                         'condition': actual, 'taken_va': hex(target), 'fallthrough_va': hex(site + size)})
        return rows

    def indirect_call_rows(self):
        rows = []
        for label, site, expected_slot, expected_target in INDIRECT_CALLS:
            owner, fde = self.owner(site, 6)
            raw = self.read(site, 6, executable=True)
            slot = decode_indirect_slot(site, raw)
            if slot != expected_slot:
                raise ValueError('indirect call slot differs')
            record = self.relocs[slot]
            if record['addend'] != expected_target:
                raise ValueError('indirect call relocation addend differs')
            rows.append({'label': label, 'owner': owner, 'fde_start': hex(fde['start']),
                         'site_va': hex(site), 'instruction_file_offset': hex(self.offset(site, 6)),
                         'instruction_bytes': raw.hex(), 'slot_va': hex(slot),
                         'slot_file_offset': hex(self.offset(slot, 8)), 'slot_bytes': self.read(slot, 8).hex(),
                         'rela_file_offset': hex(record['file_offset']), 'rela_bytes': record['record'],
                         'type': 8, 'addend_va': hex(expected_target),
                         'target_selected': expected_target in self.selected})
        return rows

    def external_symbol_rows(self):
        rela = read_unique_section(self.secs, '.rela.dyn')
        dynsym = read_unique_section(self.secs, '.dynsym')
        dynstr = read_unique_section(self.secs, '.dynstr')
        if rela['type'] != 4 or dynsym['type'] != 11 or dynstr['type'] != 3 or dynsym['size'] % 24:
            raise ValueError('unexpected dynamic symbol sections')
        wanted = {slot for _, _, slot, _ in EXTERNAL_CALLS}
        found = {}
        for off in range(rela['offset'], rela['offset'] + rela['size'], 24):
            record = self.data[off:off + 24]
            slot, info, addend = struct.unpack('<QQq', record)
            if slot not in wanted:
                continue
            if slot in found:
                raise ValueError('duplicate external relocation slot')
            if info & 0xffffffff != 6 or addend != 0:
                raise ValueError('unexpected external relocation')
            found[slot] = (off, record, info >> 32)
        if set(found) != wanted:
            raise ValueError('missing external relocation')
        rows = []
        for label, site, slot, expected in EXTERNAL_CALLS:
            self.owner(site, 6)
            ins = self.read(site, 6, executable=True)
            if decode_indirect_slot(site, ins) != slot:
                raise ValueError('external call slot differs')
            off, record, symbol_index = found[slot]
            if symbol_index >= dynsym['size'] // 24:
                raise ValueError('external symbol index out of bounds')
            symbol_va = dynsym['address'] + symbol_index * 24
            symbol = self.read(symbol_va, 24)
            name_off, st_info, st_other, st_shndx, st_value, st_size = struct.unpack('<IBBHQQ', symbol)
            if name_off >= dynstr['size'] or st_shndx != 0:
                raise ValueError('unexpected external symbol entry')
            string_off = dynstr['offset'] + name_off
            end = self.data.find(b'\0', string_off, dynstr['offset'] + dynstr['size'])
            if end < 0:
                raise ValueError('unterminated external symbol')
            name = bytes(self.data[string_off:end]).decode('ascii')
            if name != expected:
                raise ValueError('external symbol name differs')
            rows.append({'label': label, 'site_va': hex(site), 'instruction_bytes': ins.hex(),
                         'slot_va': hex(slot), 'slot_bytes': self.read(slot, 8).hex(),
                         'rela_file_offset': hex(off), 'rela_bytes': record.hex(), 'type': 6,
                         'symbol_index': symbol_index, 'symbol_va': hex(symbol_va),
                         'symbol_file_offset': hex(self.offset(symbol_va, 24)), 'symbol_bytes': symbol.hex(),
                         'name_file_offset': hex(string_off), 'name': name, 'name_bytes': bytes(self.data[string_off:end]).hex(),
                         'symbol_info': st_info, 'symbol_other': st_other, 'symbol_section_index': st_shndx,
                         'symbol_value': st_value, 'symbol_size': st_size})
        return rows

    def table_rows(self):
        rows = []
        for label, lea_site, count, owner_start in TABLES:
            base = self.lea(lea_site)
            _, fde = self.selected[owner_start]
            if self.owner(lea_site, 7)[1]['start'] != owner_start:
                raise ValueError('table LEA belongs to a different FDE')
            for i in range(count):
                raw = self.read(base + 4 * i, 4)
                delta = struct.unpack('<i', raw)[0]
                target = base + delta
                if not fde['start'] <= target < fde['end']:
                    raise ValueError('state table target outside its FDE')
                rows.append({'table': label, 'lea_va': hex(lea_site), 'table_va': hex(base),
                             'index': i, 'entry_va': hex(base + 4*i),
                             'file_offset': hex(self.offset(base + 4*i, 4)),
                             'bytes': raw.hex(), 'target_va': hex(target), 'owner_start': hex(owner_start)})
        return rows

    def relocation_rows(self):
        rows = []
        for label, slot, target in RELATIONS:
            record = self.relocs[slot]
            if record['addend'] != target:
                raise ValueError('selected relocation addend differs')
            if target not in self.selected:
                raise ValueError('relocation target lacks selected FDE')
            rows.append({'label': label, 'slot_va': hex(slot), 'slot_file_offset': hex(self.offset(slot, 8)),
                         'slot_bytes': self.read(slot, 8).hex(),
                         'rela_file_offset': hex(record['file_offset']),
                         'rela_bytes': record['record'], 'type': 8, 'addend_va': hex(target)})
        return rows

    def wire_error_code_rows(self):
        base = self.lea(0x260cc18)
        rows = []
        for i in range(8):
            entry = self.read(base + i * 4, 4)
            target = base + struct.unpack('<i', entry)[0]
            if self.owner(target)[1]['start'] != 0x260cb30:
                raise ValueError('wire error code target outside its FDE')
            if target == 0x260cc57:
                code, raw = 'input_i32_at_offset_0x34', b''
            else:
                raw = self.read(target, 5, executable=True)
                if raw[0] != 0xbd:
                    raise ValueError('wire error immediate instruction differs')
                code = struct.unpack_from('<i', raw, 1)[0]
            rows.append({'class': i, 'table_va': hex(base), 'entry_va': hex(base + 4*i),
                         'entry_bytes': entry.hex(), 'target_va': hex(target),
                         'code_instruction_bytes': raw.hex(), 'code': code})
        if rows[5]['code'] != -32602:
            raise ValueError('invalid-parameter wire code differs')
        return rows

    def table_descriptors(self):
        result = []
        for label, site, expected in [('registration_descriptor', 0x2d02548, 0x6450758),
                                      ('outer_future', 0x2d0331d, 0x6450a48),
                                      ('history_future', 0x2d0c7cb, 0x6445590)]:
            base = self.lea(site)
            if base != expected:
                raise ValueError('table LEA differs')
            size, align = struct.unpack('<QQ', self.read(base + 8, 16))
            result.append({'label': label, 'lea_va': hex(site), 'lea_bytes': self.read(site, 7).hex(),
                           'table_va': hex(base), 'table_file_offset': hex(self.offset(base, 24)),
                           'size': size, 'alignment': align, 'table_header_bytes': self.read(base, 24).hex()})
        return result

    def literal_rows(self):
        rows = []
        opcodes = {'esi': 0xbe, 'ecx': 0xb9, 'edx': 0xba}
        for label, lea_site, expected, length_site, register in LITERALS:
            address = self.lea(lea_site)
            raw_len = self.read(length_site, 5, executable=True)
            self.owner(length_site, 5)
            if raw_len[0] != opcodes[register]:
                raise ValueError('unexpected literal length instruction')
            length = struct.unpack_from('<I', raw_len, 1)[0]
            raw = self.read(address, length)
            if raw != expected:
                raise ValueError('selected literal differs')
            rows.append({'label': label, 'lea_va': hex(lea_site), 'lea_bytes': self.read(lea_site, 7).hex(),
                         'value': raw.decode('ascii'), 'va': hex(address),
                         'file_offset': hex(self.offset(address, length)), 'length': length,
                         'length_instruction_va': hex(length_site), 'length_instruction_bytes': raw_len.hex()})
        # Two overlapping immediate stores construct the missing-argument text.
        a = self.read(0x2d0c1a5, 10, executable=True)
        b = self.read(0x2d0c1b3, 10, executable=True)
        if a[:2] != b'\x48\xb9' or b[:2] != b'\x48\xb9':
            raise ValueError('missing-argument immediate stores differ')
        text = bytearray(14)
        text[6:14], text[0:8] = a[2:10], b[2:10]
        if bytes(text) != b'No more params':
            raise ValueError('missing-argument message differs')
        rows.append({'label': 'missing_parameter_message', 'value': bytes(text).decode('ascii'),
                     'first_instruction_va': hex(0x2d0c1a5), 'first_instruction_bytes': a.hex(),
                     'second_instruction_va': hex(0x2d0c1b3), 'second_instruction_bytes': b.hex()})
        method_site = 0x2a21c8f
        method_va = self.lea(method_site)
        length_ins = self.read(0x2a21c9e, 12, executable=True)
        if length_ins[:8] != bytes.fromhex('48c7842470010000'):
            raise ValueError('block-number label length instruction differs')
        length = struct.unpack_from('<I', length_ins, 8)[0]
        value = self.read(method_va, length)
        if value != b'eth_blockNumber':
            raise ValueError('block-number diagnostic label differs')
        rows.append({'label': 'block_number_diagnostic', 'lea_va': hex(method_site),
                     'lea_bytes': self.read(method_site, 7).hex(), 'value': value.decode('ascii'),
                     'va': hex(method_va), 'file_offset': hex(self.offset(method_va, length)), 'length': length,
                     'length_instruction_va': hex(0x2a21c9e), 'length_instruction_bytes': length_ins.hex()})
        candidate = b'eth_feeHistory'
        candidate_va = 0x6023fc
        if self.read(candidate_va, len(candidate)) != candidate:
            raise ValueError('candidate method literal differs')
        rows.append({'label': 'candidate_method_literal', 'value': candidate.decode('ascii'),
                     'va': hex(candidate_va), 'file_offset': hex(self.offset(candidate_va, len(candidate))),
                     'length': len(candidate), 'bytes': candidate.hex(),
                     'note': 'Data occurrence only; no registration edge is asserted.'})
        return rows

    def location_rows(self):
        rows = []
        for label, slot, site in [('history_helper_36', 0x6444e90, 0x2a217f2),
                                  ('history_helper_145', 0x6444ea8, 0x2a21835),
                                  ('rpc_514', 0x6444ec0, 0x2a21810),
                                  ('rpc_421', 0x64455b0, 0x2a217d8),
                                  ('store_465', 0x6444f08, 0x2a0b197)]:
            record = self.relocs[slot]
            if self.lea(site) != slot:
                raise ValueError('Location LEA does not point to record')
            length, line, column = struct.unpack('<QII', self.read(slot + 8, 16))
            if length == 0 or length > 128 or line > 10000 or column > 1000:
                raise ValueError('invalid selected Location record')
            string = self.read(record['addend'], length).decode('ascii')
            if not string.startswith('evm_rpc/src/') or not string.endswith('.rs'):
                raise ValueError('unexpected diagnostic path')
            rows.append({'label': label, 'lea_va': hex(site), 'lea_bytes': self.read(site, 7).hex(),
                         'slot_va': hex(slot), 'slot_file_offset': hex(self.offset(slot, 24)),
                         'record_bytes': self.read(slot, 24).hex(), 'rela_bytes': record['record'],
                         'path_va': hex(record['addend']), 'path_file_offset': hex(self.offset(record['addend'], length)),
                         'path': string, 'length': length, 'line': line, 'column': column})
        return rows

    def field_gate_rows(self):
        specs = [
            ('baseFeePerGas', 0x22e085e, 0x22e08c3, 0x22e08ce, 0x22e08d5),
            ('baseFeePerBlobGas', 0x22e0867, 0x22e09fc, 0x22e0a02, 0x22e0a18),
            ('blobGasUsedRatio', 0x22e0870, 0x22e0a3c, 0x22e0a42, 0x22e0a53),
            ('reward', 0x22e087e, 0x22e0aa6, 0x22e0aab, 0x2338948),
        ]
        rows = []
        for label, load, guard, branch, name_site in specs:
            raw_load = self.read(load, 4, executable=True)
            if raw_load[:3] != bytes.fromhex('488b47'):
                raise ValueError('serializer input field load differs')
            if label == 'reward':
                raw_guard = self.read(guard, 5, executable=True)
                if raw_guard[:4] != bytes.fromhex('48f75c24'):
                    raise ValueError('reward option guard differs')
            else:
                raw_guard = self.read(guard, 6, executable=True)
                if raw_guard[:4] != bytes.fromhex('48837c24') or raw_guard[-1] != 0:
                    raise ValueError('serializer length guard differs')
            raw_branch = self.read(branch, 2, executable=True)
            condition, target = decode_branch(branch, raw_branch)
            if condition != ('jo' if label == 'reward' else 'je'):
                raise ValueError('serializer omission branch differs')
            name_address = self.lea(name_site)
            expected = label.encode('ascii')
            if self.read(name_address, len(expected)) != expected:
                raise ValueError('serializer name differs')
            rows.append({'field': label, 'input_offset': hex(raw_load[3]), 'load_va': hex(load),
                         'load_bytes': raw_load.hex(), 'guard_va': hex(guard), 'guard_bytes': raw_guard.hex(),
                         'branch_va': hex(branch), 'branch_bytes': raw_branch.hex(),
                         'skip_condition': condition, 'skip_va': hex(target), 'name_va': hex(name_address)})
        return rows

    def forks(self):
        sec = read_unique_section(self.secs, '.rodata')
        raw = self.data[sec['offset']:sec['offset'] + sec['size']]
        out = []
        for prefix in FORK_PREFIXES:
            offsets, pos = [], 0
            while True:
                pos = raw.find(prefix, pos)
                if pos < 0:
                    break
                offsets.append(pos)
                pos += 1
            if not offsets:
                raise ValueError('expected selected fork path missing')
            first = offsets[0]
            end = raw.find(b'\0', first)
            if end < 0 or end - first > 200:
                raise ValueError('unterminated fork path')
            path = raw[first:end].decode('ascii')
            out.append({'prefix': prefix.decode('ascii'), 'first_path': path, 'occurrences': len(offsets),
                        'first_va': hex(sec['address'] + first),
                        'first_file_offset': hex(sec['offset'] + first)})
        return out

    def constants(self):
        cmp_cap = self.read(0x2a1fe8b, 4, executable=True)
        cmp_length = self.read(0x2a20053, 4, executable=True)
        error = self.read(0x2d0c1fc, 5, executable=True)
        invalid_tag = self.read(0x2a20066, 3, executable=True)
        stride = self.read(0x2a205f6, 7, executable=True)
        if cmp_cap[:3] != bytes.fromhex('4883f8') or cmp_length[:3] != bytes.fromhex('4883fa'):
            raise ValueError('expected immediate compare is absent')
        if error[0] != 0xbe or invalid_tag[:2] != bytes.fromhex('40b5') or stride[:3] != bytes.fromhex('4d69e4'):
            raise ValueError('expected immediate load is absent')
        count_cap, percent_cap = cmp_cap[3], cmp_length[3]
        code = struct.unpack_from('<i', error, 1)[0]
        ratio_stride = struct.unpack_from('<I', stride, 3)[0]
        selector_adjust = self.read(0x25cd8a9, 7, executable=True)
        arm = self.read(0x25cd953, 6, executable=True)
        if selector_adjust[:3] != bytes.fromhex('418d85') or arm[:2] != bytes.fromhex('41be'):
            raise ValueError('error classification instructions differ')
        index = code + struct.unpack_from('<i', selector_adjust, 3)[0]
        if index != 1 or self.lea(0x25cd8be) + struct.unpack('<i', self.read(self.lea(0x25cd8be) + 4 * index, 4))[0] != 0x25cd953:
            raise ValueError('error classification table differs')
        error_class = struct.unpack_from('<I', arm, 2)[0]
        doubles = []
        for label, site, opcode in [('percentile_upper', 0x2a20083, bytes.fromhex('f20f1005')),
                                     ('blob_ratio_divisor', 0x2a20cb6, bytes.fromhex('f20f5e0d')),
                                     ('reward_cast_split', 0x2a21022, bytes.fromhex('f20f5c0d')),
                                     ('reward_cast_upper', 0x2a21046, bytes.fromhex('660f2e05'))]:
            ins = self.read(site, 8, executable=True)
            if ins[:4] != opcode:
                raise ValueError('expected RIP-relative floating instruction absent')
            target = site + 8 + struct.unpack_from('<i', ins, 4)[0]
            raw = self.read(target, 8)
            value = struct.unpack('<d', raw)[0]
            if not math.isfinite(value):
                raise ValueError('non-finite captured constant')
            doubles.append({'label': label, 'instruction_va': hex(site), 'instruction_bytes': ins.hex(),
                            'va': hex(target), 'file_offset': hex(self.offset(target, 8)),
                            'bytes': raw.hex(), 'binary64': value})
        key_a = self.read(0x2a0656c, 10, executable=True)
        key_b = self.read(0x2a06584, 10, executable=True)
        if key_a[:2] != bytes.fromhex('49bf') or key_b[:2] != bytes.fromhex('49bc'):
            raise ValueError('typed context key instruction differs')
        key_width_ins = self.read(0x26982f7, 4, executable=True)
        entry_stride_ins = self.read(0x26983d3, 7, executable=True)
        decoded_size_ins = self.read(0x26986e4, 5, executable=True)
        state_pointer_ins = self.read(0x2a3ec36, 7, executable=True)
        block_number_ins = self.read(0x2a3ec3d, 7, executable=True)
        if (key_width_ins[:3] != bytes.fromhex('4983fd')
                or entry_stride_ins[:3] != bytes.fromhex('4969ff')
                or decoded_size_ins[0] != 0xba
                or state_pointer_ins[:3] != bytes.fromhex('488b83')
                or block_number_ins[:3] != bytes.fromhex('4c8bb0')):
            raise ValueError('expected store size instruction absent')
        return {'block_count_cap': count_cap, 'percentile_count_cap': percent_cap,
                'invalid_percentile_tag': invalid_tag[2], 'missing_parameter_error_code': code,
                'missing_parameter_error_class': error_class,
                'block_row_stride': ratio_stride, 'typed_key_words': [hex(struct.unpack_from('<Q', key_b, 2)[0]),
                                                                       hex(struct.unpack_from('<Q', key_a, 2)[0])],
                'typed_key_instruction_bytes': [key_b.hex(), key_a.hex()], 'binary64_constants': doubles,
                'store_key_suffix_width': key_width_ins[3], 'store_key_width_instruction': key_width_ins.hex(),
                'store_entry_stride': struct.unpack_from('<I', entry_stride_ins, 3)[0],
                'store_entry_stride_instruction': entry_stride_ins.hex(),
                'store_decoded_value_size': struct.unpack_from('<I', decoded_size_ins, 1)[0],
                'store_decoded_value_size_instruction': decoded_size_ins.hex(),
                'block_number_context_pointer_offset': struct.unpack_from('<I', state_pointer_ins, 3)[0],
                'block_number_nested_value_offset': struct.unpack_from('<I', block_number_ins, 3)[0],
                'block_number_read_instruction_bytes': [state_pointer_ins.hex(), block_number_ins.hex()]}


def to_tsv(rows):
    if not rows:
        raise ValueError('empty evidence table')
    keys = list(rows[0])
    for row in rows:
        if list(row) != keys:
            raise ValueError('inconsistent evidence table columns')
    def safe(value):
        s = str(value)
        if any(c in s for c in '\t\r\n'):
            raise ValueError('unsafe TSV value')
        return s
    return ('\t'.join(keys) + '\n' + ''.join('\t'.join(safe(row[k]) for k in keys) + '\n' for row in rows)).encode('utf-8')


def json_bytes(data):
    return (json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + '\n').encode('utf-8')


def collect(data):
    image = Image(data)
    functions = image.fde_rows()
    windows = image.window_rows()
    calls = image.call_rows()
    indirect_calls = image.indirect_call_rows()
    external_symbols = image.external_symbol_rows()
    branches = image.branch_rows()
    tables = image.table_rows()
    error_codes = image.wire_error_code_rows()
    relocs = image.relocation_rows()
    descriptors = image.table_descriptors()
    literals = image.literal_rows()
    locations = image.location_rows()
    forks = image.forks()
    constants = image.constants()
    field_gates = image.field_gate_rows()
    upper = next(row['binary64'] for row in constants['binary64_constants'] if row['label'] == 'percentile_upper')
    pcap = constants['percentile_count_cap']
    cap = constants['block_count_cap']
    cases = [
        ('no_option', 1, None),
        ('empty', 1, []),
        ('one_above_upper', 1, [upper + 1]),
        ('last_above_upper', 1, [upper, upper + 1]),
        ('previous_above_upper', 1, [upper + 1, upper + 1]),
        ('descending', 1, [1.0, 0.0]),
        ('negative_increasing', 1, [-1.0, 0.0]),
        ('unordered_first', 1, [float('nan'), 0.0]),
        ('unordered_last', 1, [0.0, float('nan')]),
        ('length_at_limit', 1, [0.0] * pcap),
        ('length_above_limit', 1, [0.0] * (pcap + 1)),
        ('zero_count_skips_length', 0, [0.0] * (pcap + 1)),
    ]
    p_rows = [{'case': label, 'count': count, 'array_length': None if vals is None else len(vals),
               'values': None if vals is None else ('all_zero' if len(vals) > 2 else
                   ['nan' if math.isnan(x) else x for x in vals]),
               'modeled_local_outcome': local_percentile_branch(count, vals, pcap, upper)}
              for label, count, vals in cases]
    max64 = (1 << 64) - 1
    ranges = [(0, 0, 5), (1, 0, 5), (1, 0, 4), (cap, 1, 5), (cap + 1, cap, 5),
              (cap + 1, cap, 4), (max64, max64, 5), (max64, cap, 5)]
    r_rows = [{'count': c, 'newest': n, 'selector': t, **local_range(c, n, t, cap)} for c, n, t in ranges]
    reward_cases = [
        ('empty_rows', [0.0, 50.0, 100.0], [], 10),
        ('threshold_boundary', [0.0, 10.0, 11.0, 100.0], [(1, 7), (9, 9)], 10),
        ('zero_first_weight', [0.0, 50.0, 100.0], [(0, 7), (2, 9)], 2),
        ('single_row', [0.0, 100.0], [(5, 7)], 5),
    ]
    reward_rows = [{'case': name, 'percentiles': pct, 'rows': rows, 'total': total,
                    'modeled_payloads': model_reward_selection(pct, rows, total)}
                   for name, pct, rows, total in reward_cases]
    metadata = {'release': '115', 'binary_sha256': image.digest, 'binary_size': len(data),
                'coordinates': 'linked ELF virtual addresses; exclusive FDE ends; zero-based file offsets',
                'function_count': len(functions), 'window_count': len(windows), 'direct_call_count': len(calls),
                'indirect_call_count': len(indirect_calls), 'external_symbol_call_count': len(external_symbols),
                'conditional_branch_count': len(branches), 'table_entry_count': len(tables),
                'selected_relocation_count': len(relocs), 'literal_count': len(literals),
                'location_count': len(locations), 'fork_prefix_count': len(forks),
                'notes': 'Selected records only; not complete CFG, function, dependency, or ELF coverage.'}
    return {'summary.json': json_bytes(metadata),
            'functions.json': json_bytes(functions),
            'windows.json': json_bytes(windows),
            'constants.json': json_bytes(constants),
            'descriptors.json': json_bytes(descriptors),
            'literals.json': json_bytes(literals),
            'locations.json': json_bytes(locations),
            'synthetic-cases.json': json_bytes({'note': 'Models of selected instruction paths, not target execution.',
                                                'percentile_cases': p_rows, 'range_cases': r_rows,
                                                'reward_selection_cases': reward_rows,
                                                'key_cases': [{'prefix_hex': '4206', 'number': n,
                                                               'modeled_key_hex': model_bound_key(bytes.fromhex('4206'), n).hex()}
                                                              for n in (0, 1, 255, 256, max64)]}),
            'calls.tsv': to_tsv(calls), 'indirect-calls.tsv': to_tsv(indirect_calls), 'branches.tsv': to_tsv(branches),
            'external-symbols.tsv': to_tsv(external_symbols),
            'error-code-map.tsv': to_tsv(error_codes),
            'state-tables.tsv': to_tsv(tables), 'relocations.tsv': to_tsv(relocs),
            'fork-paths.tsv': to_tsv(forks), 'field-gates.tsv': to_tsv(field_gates)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    # Generate everything before creating output, so a mismatch writes nothing.
    files = collect(BINARY.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (args.out / name).write_bytes(content)
    print('generated', len(files), 'static evidence files')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as error:
        print('evm_fee_history115:', error, file=sys.stderr)
        raise SystemExit(1)
