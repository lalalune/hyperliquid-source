"""Extract the selected node 115 configuration-to-command path from ELF bytes."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA115 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SHA94 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Half-open unwind ranges. These are selected extents, not a function census.
FUNCTIONS = (
    ('callback', 0x15b8cd0, 0x15b8e35),
    ('prelude_wrapper', 0x155f9e0, 0x155fa02),
    ('prelude_dispatch', 0x5c908b0, 0x5c90b47),
    ('entry', 0x155f8d0, 0x155f9d2),
    ('name_display', 0x1551630, 0x15516b1),
    ('select_build_path', 0x1564870, 0x1564b2b),
    ('prepare_command', 0x1564b30, 0x1565355),
    ('trim_boundary', 0x150caf0, 0x150cd87),
    ('find_delimiter', 0x1531b10, 0x1531e02),
    ('collect_arguments', 0x1532b70, 0x1532ed5),
    ('dispatch_loop', 0x1565f40, 0x15677fe),
    ('start_one', 0x1565460, 0x1565e45),
    ('start_error', 0x1565ec0, 0x1565f38),
    ('process_adapter', 0x5c84a40, 0x5c870b9),
    ('child_adapter', 0x5c870c0, 0x5c874cd),
    ('path_constructor', 0x5c94cb0, 0x5c95025),
    ('argument_adapter', 0x5c94bb0, 0x5c94ca2),
    ('nul_scanner', 0x141e960, 0x141eada),
    ('nul_terminator', 0x141e170, 0x141e251),
)

# Literal lengths are exact selected slices, not a search for a trailing zero in
# arbitrary following pool data. Names distinguish contextual older leads.
LITERALS = (
    ('api_url_template', 0x448b95, bytes.fromhex('0a2d2d6170692d75726c20c000')),
    ('command_suffix_template', 0x448bb1, bytes.fromhex('c00f207a69702d616e642d75706c6f616400')),
    ('description_template', 0x43779d, bytes.fromhex('0752656e2e727320c00120c000')),
    ('id_template', 0x430653, bytes.fromhex('c0045b69643dc0015d00')),
    ('join_template', 0x43aa84, bytes.fromhex('c0012fc000')),
    ('build_template', 0x449a91, bytes.fromhex('c00b2f6177735f6275696c642fc000')),
    ('client_template', 0x4366ce, bytes.fromhex('c0102f636f64652f72756e2d636c69656e7400')),
    ('log_template', 0x4449d2, bytes.fromhex('c00a2f646174612f6c6f672fc0072f6572726f722fc000')),
    ('bad_mode_template', 0x440ed2, bytes.fromhex('1a747269656420746f20676574206275696c645f646972206f6620c0082c2061206275673f00')),
    ('program', 0x467729, b'run-client'),
    ('profile_debug', 0x46771d, b'debug'),
    ('profile_release', 0x467722, b'release'),
    ('script_argument', 0x4677f8, b'--running-from-script'),
    ('nul_placeholder', 0x44c079, b'<string-with-nul>\x00'),
    ('context_cham', 0x44ab69, bytes.fromhex('c0052f6368616d00')),
    ('context_static', 0x4401ef, bytes.fromhex('c00e2f7374617469635f636f6e66696700')),
)

# Each transfer starts at an instruction established by bounded disassembly.
# All displacements, branch lengths and relocation addends are decoded below.
TRANSFERS = (
    ('callback_prelude', 0x15b8cfb, 'slot', 0x64e1310, 0x155f9e0),
    ('callback_entry', 0x15b8d05, 'slot', 0x64e1168, 0x155f8d0),
    ('prelude_wrapper_dispatch', 0x155f9f7, 'slot', 0x64e1188, 0x5c908b0),
    ('prelude_tls_error', 0x5c908f7, 'slot', 0x64e09a8, 0x5c9d1c0),
    ('prelude_tls_initialize', 0x5c90912, 'slot', 0x64e0510, 0x5ca0d20),
    ('prelude_tls_previous', 0x5c90931, 'slot', 0x64e15a8, 0x5ca5650),
    ('prelude_previous_release', 0x5c9094a, 'slot', 0x64e15b0, 0x5c98b90),
    ('prelude_remaining', 0x5c909f3, 'direct', 0x5c75270, None),
    ('prelude_unwind_resume', 0x5c90ae1, 'direct', 0x63f0a50, None),
    ('entry_formatter', 0x155f91e, 'slot', 0x64df6e8, 0x141e3a0),
    ('entry_prepare', 0x155f957, 'slot', 0x64e1170, 0x1564b30),
    ('entry_allocate', 0x155f962, 'slot', 0x64df480, None),
    ('entry_copy', 0x155f97d, 'slot', 0x64df508, None),
    ('entry_dispatch', 0x155f99f, 'slot', 0x64e1178, 0x1565f40),
    ('entry_allocation_failure', 0x155f9af, 'slot', 0x64df490, None),
    ('select_formatter_one', 0x156493e, 'slot', 0x64df6e8, 0x141e3a0),
    ('select_formatter_two', 0x1564996, 'slot', 0x64df6e8, 0x141e3a0),
    ('select_formatter_client', 0x1564a39, 'slot', 0x64df6e8, 0x141e3a0),
    ('select_alloc', 0x15649dc, 'slot', 0x64df480, None),
    ('select_alloc_failure', 0x1564b03, 'slot', 0x64df498, None),
    ('select_mode_failure', 0x1564abf, 'slot', 0x64df6b8, None),
    ('prepare_format_suffix', 0x1564bb2, 'slot', 0x64df6e8, 0x141e3a0),
    ('prepare_select', 0x1564c0d, 'slot', 0x64e1238, 0x1564870),
    ('prepare_format_description', 0x1564c6d, 'slot', 0x64df6e8, 0x141e3a0),
    ('prepare_format_id', 0x1564ce9, 'slot', 0x64df6e8, 0x141e3a0),
    ('prepare_trim', 0x1564d3c, 'direct', 0x150caf0, None),
    ('prepare_collect', 0x1564d9b, 'direct', 0x1532b70, None),
    ('prepare_grow', 0x1564e00, 'slot', 0x64e0c10, None),
    ('collect_find_first', 0x1532bc9, 'direct', 0x1531b10, None),
    ('collect_find_next', 0x1532d08, 'direct', 0x1531b10, None),
    ('dispatch_start', 0x1565f92, 'direct', 0x1565460, None),
    ('dispatch_bad_state', 0x1566036, 'slot', 0x64df730, None),
    ('start_format_log', 0x15657eb, 'slot', 0x64df6e8, 0x141e3a0),
    ('start_path_check', 0x1565801, 'slot', 0x64e0028, None),
    ('start_path_conversion', 0x1565879, 'slot', 0x64e0a30, None),
    ('start_log_open', 0x15658aa, 'direct', 0x5c97060, None),
    ('start_command', 0x1565a0d, 'slot', 0x64e0ee0, 0x5c94cb0),
    ('start_process_boundary', 0x1565a97, 'direct', 0x5c84a40, None),
    ('start_error_handler', 0x1565da4, 'direct', 0x1565ec0, None),
    ('error_report', 0x1565f15, 'slot', 0x64df6b8, None),
    ('native_socketpair', 0x5c85eaa, 'slot', 0x64eb078, None),
    ('native_fork', 0x5c85f02, 'slot', 0x64ec740, None),
    ('native_error_location', 0x5c860a2, 'slot', 0x64dffc8, None),
    ('native_pidfd_spawn', 0x5c86838, 'slot', 0x64ec738, None),
    ('native_posix_spawn', 0x5c868b3, 'slot', 0x64ec7b8, None),
    ('native_child_setup', 0x5c86b7f, 'direct', 0x5c870c0, None),
    ('native_child_exit', 0x5c86beb, 'slot', 0x64ec7c0, None),
    ('native_execvp', 0x5c8743f, 'slot', 0x64ec810, None),
    ('native_exec_error_location', 0x5c87445, 'slot', 0x64dffc8, None),
    ('path_convert', 0x5c94dca, 'slot', 0x64df718, 0x141e960),
    ('argument_convert', 0x5c94bc6, 'slot', 0x64df718, 0x141e960),
    ('nul_copy', 0x141e9ad, 'slot', 0x64df508, None),
    ('nul_terminate', 0x141ea80, 'slot', 0x64df690, 0x141e170),
    ('nul_terminate_failure', 0x141e210, 'slot', 0x64df498, None),
)

REFS = (
    ('name_formatter_slot', 0x155f8fb, 0x64e10f8),
    ('entry_api_template', 0x155f907, 0x448b95),
    ('entry_program', 0x155f937, 0x467729),
    ('display_table', 0x155164d, 0x466d28),
    ('select_release', 0x15648d0, 0x467722),
    ('select_debug', 0x15648f2, 0x46771d),
    ('select_join', 0x156492d, 0x43aa84),
    ('select_global_build', 0x156494e, 0x64e0918),
    ('select_build_template', 0x1564985, 0x449a91),
    ('select_global_client', 0x1564a02, 0x64e0918),
    ('select_client_template', 0x1564a2a, 0x4366ce),
    ('select_mode_error', 0x1564aac, 0x440ed2),
    ('prepare_suffix', 0x1564ba0, 0x448bb1),
    ('prepare_description', 0x1564c5e, 0x43779d),
    ('prepare_id', 0x1564cda, 0x430653),
    ('prepare_script_literal', 0x1564dd7, 0x4677f8),
    ('start_global', 0x1565771, 0x64e0918),
    ('start_log_template', 0x15657d7, 0x4449d2),
    ('start_argument_append_slot', 0x1565a37, 0x64e0ee8),
    ('path_nul_placeholder', 0x5c94e6f, 0x44c079),
    ('argument_nul_placeholder', 0x5c94bfb, 0x44c079),
)

BRANCHES = (
    ('prelude_tls_ready', 0x5c908e5, 0x5c9091f),
    ('prelude_tls_initialize', 0x5c908ee, 0x5c908ff),
    ('prelude_previous_null', 0x5c9093e, 0x5c90950),
    ('prelude_previous_shared', 0x5c90944, 0x5c90950),
    ('prelude_empty_vector', 0x5c90977, 0x5c909e9),
    ('prelude_vector_end', 0x5c9099f, 0x5c909de),
    ('prelude_element_size_zero', 0x5c909b7, 0x5c90990),
    ('prelude_empty_capacity', 0x5c909fb, 0x5c90a1d),
    ('select_zero_mode', 0x156488d, 0x15648de),
    ('select_wrong_length', 0x1564893, 0x15648b6),
    ('select_exact_client', 0x15648b0, 0x1564a02),
    ('select_debug_kind', 0x15648c2, 0x15648f2),
    ('select_bad_kind', 0x15648ca, 0x1564a96),
    ('select_local_length_sign', 0x15648e1, 0x15649d1),
    ('select_local_empty', 0x15649d1, 0x1564a41),
    ('select_local_alloc_null', 0x15649e5, 0x1564afb),
    ('select_build_init', 0x156495b, 0x1564a65),
    ('select_client_init', 0x1564a0f, 0x1564ac5),
    ('entry_alloc_null', 0x155f96b, 0x155f9a5),
    ('prepare_optional_word', 0x1564b5a, 0x1564b79),
    ('prepare_direct_tag', 0x1564dba, 0x1564ff2),
    ('prepare_flag_alloc_null', 0x1564dce, 0x156518a),
    ('prepare_capacity_available', 0x1564df9, 0x1564e06),
    ('prepare_extra_absent', 0x1564e5d, 0x1564ff2),
    ('prepare_extra_empty', 0x1564ea6, 0x1564f70),
    ('prepare_item_end', 0x1564f2d, 0x1564f6b),
    ('collect_end_first', 0x1532bd3, 0x1532bfb),
    ('collect_empty_first', 0x1532c29, 0x1532e2d),
    ('collect_empty_later', 0x1532d81, 0x1532db5),
    ('dispatch_zero_count', 0x1565f73, 0x1565f9c),
    ('dispatch_unexpected_state', 0x1565f7c, 0x1566023),
    ('start_fresh_state', 0x1565486, 0x1565526),
    ('start_prior_state', 0x1565493, 0x15654c5),
    ('start_prior_fd_absent', 0x156549e, 0x1565b8d),
    ('start_prior_call_failure', 0x15654bf, 0x1565ba7),
    ('start_time_field_equal', 0x1565542, 0x156554c),
    ('start_log_check_failure', 0x156580a, 0x1565c29),
    ('start_long_log_path', 0x1565847, 0x1565c5e),
    ('start_path_conversion_ok', 0x1565883, 0x156589b),
    ('start_log_open_error', 0x15658b4, 0x1565d5e),
    ('start_process_error', 0x1565aab, 0x1565d95),
    ('start_old_state_empty', 0x1565ae9, 0x1565b2f),
    ('start_skip_count', 0x1565b4c, 0x1565b64),
    ('native_fork_flags', 0x5c85bc7, 0x5c85e8c),
    ('native_fork_option_28', 0x5c85bf9, 0x5c85e8c),
    ('native_fork_option_b0', 0x5c85c0b, 0x5c85e8c),
    ('native_fork_option_a0', 0x5c85c1d, 0x5c85e8c),
    ('native_socketpair_error', 0x5c85eb3, 0x5c860a2),
    ('native_fork_error', 0x5c85f0b, 0x5c860ec),
    ('native_fork_child', 0x5c85f16, 0x5c86b24),
    ('native_spawn_retry_fork', 0x5c865a1, 0x5c85e8c),
    ('native_spawn_error_result', 0x5c865ab, 0x5c860b2),
    ('native_pidfd_mode_off', 0x5c867f1, 0x5c8687e),
    ('native_pidfd_unavailable_mode', 0x5c86800, 0x5c8687e),
    ('native_pidfd_symbol_null', 0x5c86811, 0x5c86c5d),
    ('native_pidfd_success', 0x5c86858, 0x5c8696a),
    ('native_pidfd_non38', 0x5c86861, 0x5c868d8),
    ('native_posix_success', 0x5c868bb, 0x5c8690e),
    ('native_skip_special_conversion', 0x5c84a81, 0x5c84ba3),
    ('native_nul_flag_clear', 0x5c84bb1, 0x5c859df),
    ('path_empty', 0x5c94cc7, 0x5c94da0),
    ('path_first_slash', 0x5c94cd3, 0x5c94dc6),
    ('path_short_internal_slash', 0x5c94cf4, 0x5c94dc3),
    ('path_converter_error', 0x5c94dde, 0x5c94e5b),
    ('argument_converter_error', 0x5c94bda, 0x5c94be1),
    ('argument_alloc_null', 0x5c94bf6, 0x5c94c72),
    ('argument_capacity_empty', 0x5c94c29, 0x5c94c63),
    ('nul_length_overflow', 0x141e977, 0x141eac1),
    ('nul_alloc_null', 0x141e992, 0x141eacc),
    ('nul_empty', 0x141e99e, 0x141ea70),
    ('nul_longer_than_15', 0x141e9b7, 0x141e9d9),
    ('nul_short_match', 0x141e9c6, 0x141eaa0),
    ('nul_alignment_match', 0x141ea46, 0x141eaa0),
    ('nul_tail_match', 0x141ea66, 0x141ea9d),
)

# These windows preserve setup, stores, branch conditions, cleanup and selected
# failure handoffs. They deliberately do not claim complete CFG reconstruction.
WINDOWS = (
    ('callback_input', 0x15b8cde, 0x15b8d0b),
    ('prelude_wrapper', 0x155f9e0, 0x155fa02),
    ('prelude_tls_gate', 0x5c908c1, 0x5c9091f),
    ('prelude_tls_swap', 0x5c9091f, 0x5c90950),
    ('prelude_vector_loop', 0x5c90950, 0x5c909e9),
    ('prelude_vector_finish', 0x5c909e9, 0x5c90a2c),
    ('prelude_unwind_tail', 0x5c90ac6, 0x5c90b00),
    ('entry_lookup', 0x155f8da, 0x155f924),
    ('entry_arguments', 0x155f924, 0x155f95d),
    ('entry_publish_and_failure', 0x155f95d, 0x155f9b7),
    ('display_dispatch', 0x1551630, 0x155165d),
    ('select_tests', 0x156487b, 0x15648de),
    ('select_profile', 0x15648de, 0x156493e),
    ('select_global_and_build', 0x156493e, 0x15649ad),
    ('select_tag_one', 0x15649ad, 0x15649d1),
    ('select_copy_and_special', 0x15649d1, 0x1564a56),
    ('select_errors', 0x1564a96, 0x1564b2b),
    ('prepare_option_and_suffix', 0x1564b55, 0x1564bcf),
    ('prepare_select_and_description', 0x1564bcf, 0x1564c73),
    ('prepare_tokenize', 0x1564d2c, 0x1564dc0),
    ('prepare_script_prepend', 0x1564dc0, 0x1564e45),
    ('prepare_extra_guard', 0x1564e45, 0x1564eac),
    ('prepare_extra_loop', 0x1564ed0, 0x1564f70),
    ('prepare_output', 0x156502b, 0x15650dd),
    ('prepare_allocation_failure', 0x156518a, 0x156519c),
    ('trim_ascii_start', 0x150cbc0, 0x150cbe1),
    ('trim_ascii_end', 0x150cc89, 0x150ccb0),
    ('find_first', 0x1531b1e, 0x1531b5b),
    ('find_match', 0x1531cc0, 0x1531cd0),
    ('collect_first', 0x1532bb6, 0x1532c2f),
    ('collect_next', 0x1532d03, 0x1532d81),
    ('collect_push_empty', 0x1532db5, 0x1532e0d),
    ('dispatch_initial_loop', 0x1565f51, 0x1565fa5),
    ('dispatch_state_error', 0x1566023, 0x1566041),
    ('start_state_and_time', 0x1565471, 0x156555b),
    ('start_log_path', 0x1565771, 0x156580a),
    ('start_log_open', 0x156580a, 0x15658ba),
    ('start_arg_loop', 0x15659fd, 0x1565a58),
    ('start_result', 0x1565a85, 0x1565b64),
    ('start_log_error', 0x1565d5e, 0x1565d95),
    ('start_process_error', 0x1565d95, 0x1565dab),
    ('failure_helper', 0x1565ec0, 0x1565f38),
    ('native_path_guards', 0x5c85bbd, 0x5c85c38),
    ('native_socket_and_fork', 0x5c85e8c, 0x5c85f1c),
    ('native_error_return', 0x5c860a2, 0x5c8610a),
    ('native_spawn_cleanup', 0x5c86583, 0x5c865db),
    ('native_pidfd_and_spawn', 0x5c867e0, 0x5c868de),
    ('native_fork_child', 0x5c86b24, 0x5c86bf1),
    ('native_exec_and_errno', 0x5c87430, 0x5c8745d),
    ('path_classification', 0x5c94cc1, 0x5c94d07),
    ('path_convert_and_tag', 0x5c94dc6, 0x5c94deb),
    ('path_nul_flag_save', 0x5c94dff, 0x5c94e2e),
    ('path_nul_error', 0x5c94e5b, 0x5c94e9f),
    ('path_state_fields', 0x5c94eea, 0x5c94fa0),
    ('argument_convert_and_error', 0x5c94bbf, 0x5c94c1e),
    ('argument_vector_insert', 0x5c94c1e, 0x5c94c63),
    ('nul_short_scan', 0x141e971, 0x141e9d9),
    ('nul_result_words', 0x141ea70, 0x141eaaf),
    ('nul_terminator_write', 0x141e17f, 0x141e1b7),
    ('native_initial_flags', 0x5c84a6a, 0x5c84a87),
    ('native_converter_error', 0x5c84ba3, 0x5c84bcd),
)


def authenticate(data, expected=SHA115):
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ValueError('artifact SHA-256 mismatch')
    return actual


def file_offset(secs, va, size):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid address or span')
    found = [s for s in secs if s['type'] != 8 and s['flags'] & 2
             and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('address does not have one file-backed allocated section')
    s = found[0]
    return s['offset'] + va - s['address']


def get(data, secs, va, size):
    off = file_offset(secs, va, size)
    return data[off:off + size]


def require(data, secs, va, expected):
    actual = get(data, secs, va, len(expected))
    if actual != expected:
        raise ValueError('unexpected selected instruction or literal at ' + hex(va))
    return actual


def decode_branch(raw, va):
    if len(raw) < 2:
        raise ValueError('short branch')
    if 0x70 <= raw[0] <= 0x7f:
        length, delta, condition = 2, struct.unpack_from('<b', raw, 1)[0], raw[0] & 15
    elif len(raw) >= 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        length, delta, condition = 6, struct.unpack_from('<i', raw, 2)[0], raw[1] & 15
    else:
        raise ValueError('unsupported selected branch')
    return {'bytes': raw[:length].hex(), 'fallthrough_va': hex(va + length),
            'taken_va': hex(va + length + delta), 'condition_code': condition}


def checked_branch(raw, va, expected_target):
    result = decode_branch(raw, va)
    if int(result['taken_va'], 16) != expected_target:
        raise ValueError('selected branch target mismatch at ' + hex(va))
    return result


def decode_transfer(raw, va):
    if len(raw) >= 5 and raw[0] == 0xe8:
        return 'direct', va + 5 + struct.unpack_from('<i', raw, 1)[0], raw[:5]
    if len(raw) >= 6 and raw[:2] == b'\xff\x15':
        return 'slot', va + 6 + struct.unpack_from('<i', raw, 2)[0], raw[:6]
    raise ValueError('unsupported selected call')


def decode_rip(raw, va):
    is_rex = len(raw) >= 7 and raw[0] in (0x48, 0x4c) and raw[1] in (0x8b, 0x8d) and raw[2] & 0xc7 == 5
    is_movups = len(raw) >= 7 and raw[:3] == bytes.fromhex('0f1005')
    if not (is_rex or is_movups):
        raise ValueError('unsupported selected RIP-relative operand')
    return va + 7 + struct.unpack_from('<i', raw, 3)[0]


def relocations(data, secs, required):
    matches = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(matches) != 1 or matches[0]['size'] % 24:
        raise ValueError('invalid dynamic relocation section')
    sec = matches[0]
    wanted = set(required)
    result = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        va, info, addend = struct.unpack_from('<QQq', data, off)
        if va not in wanted:
            continue
        if va in result or addend < 0:
            raise ValueError('duplicate or negative relocation')
        typ, symbol_index = info & 0xffffffff, info >> 32
        if typ == 8 and symbol_index == 0:
            symbol, symbol_meta = None, None
        elif typ == 6 and symbol_index > 0 and addend == 0:
            dyn = next(s for s in secs if s['name'] == '.dynsym' and s['type'] == 11)
            strings = next(s for s in secs if s['name'] == '.dynstr' and s['type'] == 3)
            if symbol_index * 24 + 24 > dyn['size']:
                raise ValueError('dynamic symbol outside table')
            sym_off = dyn['offset'] + symbol_index * 24
            name_off, sym_info, sym_other, sym_section, sym_value, sym_size = struct.unpack_from('<IBBHQQ', data, sym_off)
            symbol_meta = {'binding': sym_info >> 4, 'type': sym_info & 15,
                           'visibility': sym_other & 3, 'section_index': sym_section,
                           'value': hex(sym_value), 'size': sym_size}
            if name_off >= strings['size']:
                raise ValueError('dynamic symbol name outside table')
            begin = strings['offset'] + name_off
            end = data.find(b'\0', begin, strings['offset'] + strings['size'])
            if end < 0:
                raise ValueError('unterminated dynamic symbol name')
            symbol = data[begin:end].decode('ascii')
        else:
            raise ValueError('unsupported selected relocation')
        slot_offset = file_offset(secs, va, 8)
        result[va] = {'slot_va': hex(va), 'slot_file_offset': hex(slot_offset), 'record_file_offset': hex(off),
                      'r_info': hex(info), 'type': typ, 'symbol_index': symbol_index,
                      'symbol': symbol, 'symbol_metadata': symbol_meta,
                      'addend_va': hex(addend) if typ == 8 else None,
                      'record_hex': data[off:off + 24].hex()}
    if set(result) != wanted:
        raise ValueError('missing selected relocation')
    return result



def validate_native_imports(rels):
    expected = {0x64eb078: 'socketpair', 0x64ec740: 'fork', 0x64ec738: 'pidfd_spawnp',
                0x64ec7b8: 'posix_spawnp', 0x64ec7c0: '_exit', 0x64ec810: 'execvp',
                0x64dffc8: '__errno_location'}
    for slot, name in expected.items():
        row = rels.get(slot)
        meta = None if row is None else row['symbol_metadata']
        expected_binding = 2 if name == 'pidfd_spawnp' else 1
        if (row is None or row['symbol'] != name or meta is None or meta['type'] != 2
                or meta['section_index'] != 0 or meta['binding'] != expected_binding):
            raise ValueError('changed native import binding')


def prelude_constants(data, secs):
    require(data, secs, 0x155f9e4, bytes.fromhex('0f10070f104f100f294c24100f290424'))
    require(data, secs, 0x5c908db, bytes.fromhex('64410fb6442408'))
    first = get(data, secs, 0x5c908e2, 3)
    second = get(data, secs, 0x5c908eb, 3)
    if first != bytes.fromhex('83f801') or second != bytes.fromhex('83f802'):
        raise ValueError('changed prelude TLS comparisons')
    require(data, secs, 0x5c908fd, bytes.fromhex('0f0b'))
    require(data, secs, 0x5c90918, bytes.fromhex('6441c644240801'))
    require(data, secs, 0x5c90928, bytes.fromhex('644d893424'))
    require(data, secs, 0x5c9095e, bytes.fromhex('48c1e304'))
    require(data, secs, 0x5c909ac, bytes.fromhex('41ff5718'))
    return {'ready_byte': first[2], 'error_byte': second[2]}


def prelude_route(constants, value):
    if type(value) is not int or not 0 <= value <= 255:
        raise ValueError('prelude TLS value must be a byte')
    if value == constants['ready_byte']:
        return 'tls_swap'
    if value == constants['error_byte']:
        return 'error_call_then_ud2'
    return 'tls_initialize_then_swap'


def selector_constants(data, secs):
    require(data, secs, 0x1564888, bytes.fromhex('4489c008c8'))
    length_insn = get(data, secs, 0x156488f, 4)
    if length_insn[:3] != bytes.fromhex('4883fa'):
        raise ValueError('missing selector length comparison')
    require(data, secs, 0x1564895, bytes.fromhex('48b8'))
    first = get(data, secs, 0x1564897, 8)
    require(data, secs, 0x156489f, bytes.fromhex('4833060fb756084881f2'))
    last_value = struct.unpack('<I', get(data, secs, 0x15648a9, 4))[0]
    if last_value > 0xffff:
        raise ValueError('invalid trailing equality constant')
    special = first + struct.pack('<H', last_value)
    if special != get(data, secs, 0x467729, len(special)) or len(special) != length_insn[3]:
        raise ValueError('selector immediate and program literal disagree')
    require(data, secs, 0x15648ad, bytes.fromhex('4809c2'))
    require(data, secs, 0x15648bf, bytes.fromhex('80f901'))
    require(data, secs, 0x15648c7, bytes.fromhex('83f802'))
    require(data, secs, 0x15649ad, bytes.fromhex('c6431801'))
    require(data, secs, 0x1564a52, bytes.fromhex('c6431800'))
    return {'program': special, 'length': length_insn[3], 'debug': 1, 'release': 2}


def select_mode(constants, kind, flag, program):
    if type(kind) is not int or type(flag) is not int or not 0 <= kind <= 255 or not 0 <= flag <= 255:
        raise ValueError('mode inputs must be bytes')
    if not isinstance(program, bytes):
        raise ValueError('program must be bytes')
    if not (kind | flag):
        return 'local_copy', 0
    if len(program) == constants['length'] and program == constants['program']:
        return 'client_template', 0
    if kind == constants['debug']:
        return 'debug_template', 1
    if kind == constants['release']:
        return 'release_template', 1
    return 'mode_error', None


def short_nul_constants(data, secs):
    raw = get(data, secs, 0x141e9b3, 4)
    if raw[:3] != bytes.fromhex('4983ff') or raw[3] != 15:
        raise ValueError('unexpected short NUL scan limit')
    require(data, secs, 0x141e9c0, bytes.fromhex('41807c0d0000'))
    require(data, secs, 0x141ea8e, bytes.fromhex('48b80000000000000080'))
    require(data, secs, 0x141eaa0, bytes.fromhex('4c89334c8963084c897b1048894b18'))
    require(data, secs, 0x141e18f, bytes.fromhex('c6041800'))
    require(data, secs, 0x5c94dd8, bytes.fromhex('4c89e848f7d8'))
    require(data, secs, 0x5c94e83, bytes.fromhex('41b701'))
    require(data, secs, 0x5c94e24, bytes.fromhex('44897dcc'))
    require(data, secs, 0x5c94ef9, bytes.fromhex('4c89bb80000000'))
    require(data, secs, 0x5c94f4a, bytes.fromhex('8b45cc8883c0000000'))
    require(data, secs, 0x5c94f0f, bytes.fromhex('48c7437000000000'))
    require(data, secs, 0x5c94f17, bytes.fromhex('66c743780000'))
    require(data, secs, 0x15659fd, bytes.fromhex('488b7308488b5310'))
    require(data, secs, 0x5c94be1, bytes.fromhex('c683c000000001'))
    require(data, secs, 0x5c84a6a, bytes.fromhex('0fb646784c8b7e704d85ff0f95c108c180f901'))
    require(data, secs, 0x5c87430, bytes.fromhex('488b45b0488b7008488bb880000000'))
    require(data, secs, 0x5c84baa, bytes.fromhex('80bec000000000'))
    require(data, secs, 0x5c84bc2, bytes.fromhex('c70701000000'))
    return {'maximum_short_length': raw[3], 'nul_byte': 0}


def short_nul_model(raw, constants):
    if not isinstance(raw, bytes) or len(raw) > constants['maximum_short_length']:
        raise ValueError('input outside bounded short NUL model')
    index = raw.find(bytes((constants['nul_byte'],)))
    return ('success_sentinel', None) if index == -1 else ('nul_result', index)


def native_result_model(operation, value):
    if type(value) is not int:
        raise ValueError('native status must be an integer')
    if operation == 'pidfd':
        if not 0 <= value <= 0xffffffff:
            raise ValueError('invalid native status')
        if value == 0:
            return 'pidfd_success_path'
        if value == 38:
            return 'cache_two_then_fork_path'
        return 'error_result_path'
    if operation == 'posix':
        if not 0 <= value <= 0xffffffff:
            raise ValueError('invalid native status')
        return 'posix_success_cleanup' if value == 0 else 'error_result_path'
    if operation == 'fork':
        if not -(1 << 31) <= value < 1 << 31:
            raise ValueError('invalid fork status')
        return 'error_result_path' if value == -1 else ('child_setup' if value == 0 else 'parent_path')
    raise ValueError('unsupported native operation')


def counter_model(mode, count, date_changed, process_ok):
    if type(mode) is not int or not 0 <= mode <= 255 or type(count) is not int or not 0 <= count < 1 << 64:
        raise ValueError('invalid counter inputs')
    if type(date_changed) is not bool or type(process_ok) is not bool:
        raise ValueError('counter controls must be bool')
    observed = 0 if date_changed else count
    decremented = (mode - 1) & 255
    if process_ok and decremented < 2:
        observed = min(observed + 1, (1 << 64) - 1)
    return observed


def ascii_trim_split(raw, delimiter):
    """Model the bounded ASCII subset, with a single-byte delimiter."""
    if not isinstance(raw, bytes) or any(x >= 128 for x in raw):
        raise ValueError('ASCII-only model')
    if not isinstance(delimiter, int) or not 0 <= delimiter <= 127:
        raise ValueError('invalid delimiter')
    return raw.strip(bytes((9, 10, 11, 12, 13, 32))).split(bytes((delimiter,)))


def selected_name_anchors(data, secs, rels, base, expected):
    rows = []
    for index, wanted in expected:
        slot = base + 16 * index
        if slot not in rels or rels[slot]['addend_va'] is None:
            raise ValueError('missing name descriptor relocation')
        ptr = int(rels[slot]['addend_va'], 16)
        length = struct.unpack('<Q', get(data, secs, slot + 8, 8))[0]
        if length != len(wanted) or get(data, secs, ptr, length) != wanted:
            raise ValueError('name descriptor bytes or length disagree')
        rows.append({'index': index, 'slot_va': hex(slot), 'slot_file_offset': hex(file_offset(secs, slot, 16)),
                     'text_va': hex(ptr), 'text_file_offset': hex(file_offset(secs, ptr, length)),
                     'length': length, 'text': wanted.decode('ascii')})
    return rows


def make_name_rows(data, secs):
    require(data, secs, 0x155f8da, bytes.fromhex('89f9c0e10448b8'))
    packed = struct.unpack('<Q', get(data, secs, 0x155f8e1, 8))[0]
    require(data, secs, 0x155f8e9, bytes.fromhex('48d3e86689442438'))
    require(data, secs, 0x1551630, bytes.fromhex('0fb7076683e802b9050000000f43c8'))
    base = decode_rip(get(data, secs, 0x155164d, 7), 0x155164d)
    if base != 0x466d28:
        raise ValueError('changed display table reference')
    result = []
    for tag in range(4):
        word = (packed >> (tag * 16)) & 0xffff
        if word < 2:
            raise ValueError('selected display word takes fallback')
        slot = base + (word - 2) * 4
        displacement = struct.unpack('<i', get(data, secs, slot, 4))[0]
        arm = base + displacement
        insn = get(data, secs, arm, 14)
        if insn[:3] != bytes.fromhex('488d35') or insn[7] != 0xba or insn[12:14] != b'\xff\xe0':
            raise ValueError('changed display leaf')
        text_va = arm + 7 + struct.unpack_from('<i', insn, 3)[0]
        length = struct.unpack_from('<I', insn, 8)[0]
        name = get(data, secs, text_va, length)
        result.append({'input_byte': tag, 'packed_word': word, 'index': word - 2,
                       'table_entry_va': hex(slot), 'relative_offset': displacement,
                       'arm_va': hex(arm), 'arm_hex': insn.hex(), 'text_va': hex(text_va),
                       'text_file_offset': hex(file_offset(secs, text_va, length)),
                       'length': length, 'text': name.decode('ascii')})
    if [row['text'] for row in result] != ['Local', 'XyzSandbox', 'XyzTestnet', 'Xyz']:
        raise ValueError('unexpected selected display names')
    return result


def make_name_cases(data, secs, names):
    instruction = get(data, secs, 0x155f8dc, 3)
    if instruction != bytes.fromhex('c0e104'):
        raise ValueError('changed entry byte shift')
    require(data, secs, 0x155f8e9, bytes.fromhex('48d3e8'))
    packed = struct.unpack('<Q', get(data, secs, 0x155f8e1, 8))[0]
    by_word = {row['packed_word']: row for row in names}
    if len(by_word) != 4:
        raise ValueError('ambiguous selected display words')
    result = []
    for value in range(256):
        shift_byte = (value << instruction[2]) & 0xff
        shift_count = shift_byte & 63  # x86-64 masks a variable 64-bit shift to six bits.
        word = (packed >> shift_count) & 0xffff
        if word not in by_word:
            raise ValueError('unrecognized display word in byte model')
        row = by_word[word]
        result.append({'input_byte': value, 'shift_byte': shift_byte,
                       'shift_count': shift_count, 'packed_word': word,
                       'arm_va': row['arm_va'], 'text': row['text']})
    return result


def write_json(out, name, value):
    (out / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def write_tsv(out, name, columns, rows):
    with (out / name).open('w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, delimiter='\t', lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)


def collect(data):
    authenticate(data)
    secs = sections(data)
    _, indexed = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    fde_by_start = {}
    for fde in fdes:
        fde_by_start.setdefault(fde['start'], []).append(fde)
    index_by_start = {e['start']: e for e in indexed}
    funcs, bodies = [], []
    for role, start, end in FUNCTIONS:
        fs = fde_by_start.get(start, [])
        idx = index_by_start.get(start)
        if len(fs) != 1 or fs[0]['end'] != end or idx is None or idx['fde'] != fs[0]['fde']:
            raise ValueError('selected FDE/index mismatch at ' + hex(start))
        raw = get(data, secs, start, end - start)
        f = fs[0]
        funcs.append({'role': role, 'start_va': hex(start), 'end_va_exclusive': hex(end),
                      'size': len(raw), 'file_offset': hex(file_offset(secs, start, len(raw))),
                      'fde_va': hex(f['fde']), 'cie_va': hex(f['cie']),
                      'lsda_va': None if f['lsda'] is None else hex(f['lsda']),
                      'body_sha256': hashlib.sha256(raw).hexdigest()})
        bodies.append({'role': role, 'start_va': hex(start), 'end_va_exclusive': hex(end), 'bytes': raw.hex()})

    needed = {slot for _, _, kind, slot, _ in TRANSFERS if kind == 'slot'}
    needed.update((0x64e10f8, 0x64e0918, 0x64e0ee8, 0x64004e8))
    needed.update(0x63f8788 + 16 * index for index in (0, 32, 33, 34, 78))
    rels = relocations(data, secs, needed)
    fixed_relocations = {0x64e0918: 0x64f06c0, 0x64e10f8: 0x1551630,
                         0x64e0ee8: 0x5c94bb0, 0x63f8998: 0x464716,
                         0x64004e8: 0x15b8cd0}
    for slot, target in fixed_relocations.items():
        if int(rels[slot]['addend_va'], 16) != target:
            raise ValueError('changed fixed relocation')

    transfers = []
    for role, va, kind, target, resolved in TRANSFERS:
        observed_kind, observed_target, raw = decode_transfer(get(data, secs, va, 6), va)
        if observed_kind != kind or observed_target != target:
            raise ValueError('selected call target mismatch at ' + hex(va))
        record = None if kind == 'direct' else rels[target]
        actual_resolved = None if record is None or record['addend_va'] is None else int(record['addend_va'], 16)
        if resolved is not None and actual_resolved != resolved:
            raise ValueError('selected call relocation mismatch')
        transfers.append({'role': role, 'site_va': hex(va), 'file_offset': hex(file_offset(secs, va, len(raw))),
                          'bytes': raw.hex(), 'kind': kind, 'direct_target_or_slot_va': hex(target),
                          'slot_addend_va': '' if actual_resolved is None else hex(actual_resolved),
                          'dynamic_symbol': '' if record is None or record['symbol'] is None else record['symbol']})

    refs = []
    for role, va, target in REFS:
        raw = get(data, secs, va, 7)
        if decode_rip(raw, va) != target:
            raise ValueError('selected RIP-relative target mismatch at ' + hex(va))
        refs.append({'role': role, 'site_va': hex(va), 'file_offset': hex(file_offset(secs, va, 7)),
                     'bytes': raw.hex(), 'target_va': hex(target)})

    branch_rows = []
    for role, va, target in BRANCHES:
        decoded = checked_branch(get(data, secs, va, 6), va, target)
        branch_rows.append({'role': role, 'site_va': hex(va), **decoded})

    literal_rows = []
    for role, va, expected in LITERALS:
        raw = require(data, secs, va, expected)
        literal_rows.append({'role': role, 'va': hex(va), 'file_offset': hex(file_offset(secs, va, len(raw))),
                             'length': len(raw), 'bytes': raw.hex()})
    require(data, secs, 0x63f89a0, struct.pack('<Q', 9))
    require(data, secs, 0x464716, b'NvTestnet')
    require(data, secs, 0x464893, b'variant index 0 <= i < 79')

    window_rows = []
    for role, start, end in WINDOWS:
        raw = get(data, secs, start, end - start)
        window_rows.append({'role': role, 'start_va': hex(start), 'end_va_exclusive': hex(end),
                            'file_offset': hex(file_offset(secs, start, len(raw))), 'bytes': raw.hex()})

    prelude = prelude_constants(data, secs)
    constants = selector_constants(data, secs)
    nul_constants = short_nul_constants(data, secs)
    require(data, secs, 0x1564d6d, bytes.fromhex('48b82000000020000000'))
    require(data, secs, 0x1564d7f, bytes.fromhex('c684249800000001'))
    require(data, secs, 0x1564d87, bytes.fromhex('66c78424a00000000100'))
    require(data, secs, 0x150cbc9, bytes.fromhex('458d51f74183fa05'))
    require(data, secs, 0x150cbd7, bytes.fromhex('4183f920'))
    require(data, secs, 0x1564de1, bytes.fromhex('48b86d2d736372697074'))
    require(data, secs, 0x15650c4, bytes.fromhex('c7818000000002000000'))
    require(data, secs, 0x1565f75, bytes.fromhex('83bf8000000002'))
    require(data, secs, 0x1565b3f, bytes.fromhex('410f114e0c410f1106'))
    require(data, secs, 0x1565f1b, bytes.fromhex('0f0b'))
    require(data, secs, 0x15b8ce1, bytes.fromhex('0fb66f28'))
    require(data, secs, 0x15b8d01, bytes.fromhex('400fb6fd'))
    require(data, secs, 0x155f943, bytes.fromhex('ba0a0000004889d941b80200000041b901000000'))
    require(data, secs, 0x1564b41, bytes.fromhex('4489cd4589c54989d64989f7'))
    require(data, secs, 0x1564bfa, bytes.fromhex('410fb6cd440fb6c5'))
    require(data, secs, 0x1564c2d, bytes.fromhex('440fb67c2478'))
    require(data, secs, 0x1564da7, bytes.fromhex('4584ff'))
    require(data, secs, 0x1564955, bytes.fromhex('418b475085c0'))
    require(data, secs, 0x1564961, bytes.fromhex('4983c718'))
    require(data, secs, 0x1564a09, bytes.fromhex('418b465085c0'))
    require(data, secs, 0x1564a15, bytes.fromhex('4983c618'))
    require(data, secs, 0x1565778, bytes.fromhex('418b465085c0'))
    require(data, secs, 0x1565784, bytes.fromhex('4983c618'))
    require(data, secs, 0x1531b41, bytes.fromhex('440fb65e28460fb6741e1f'))
    require(data, secs, 0x1531bd0, bytes.fromhex('46383401'))
    require(data, secs, 0x1531cc0, bytes.fromhex('4d01c449ffc44c896610'))
    require(data, secs, 0x1532c11, bytes.fromhex('0f95c0410a47403c01'))
    require(data, secs, 0x1532db5, bytes.fromhex('41bc01000000'))
    require(data, secs, 0x1532dee, bytes.fromhex('4d896c06f04c896424084d896406f84d892c0648ffc5'))
    require(data, secs, 0x1565f90, bytes.fromhex('31f6'))
    require(data, secs, 0x1565471, bytes.fromhex('89f5'))
    require(data, secs, 0x1565544, bytes.fromhex('48c7437800000000'))
    require(data, secs, 0x15658d0, bytes.fromhex('40fecd'))
    require(data, secs, 0x1565b48, bytes.fromhex('4080fd02'))
    require(data, secs, 0x1565b4e, bytes.fromhex('488b437848ffc048c7c1ffffffff480f45c848894b78'))
    require(data, secs, 0x5c85eb0, bytes.fromhex('83f8ff'))
    require(data, secs, 0x5c85f08, bytes.fromhex('83f8ff'))
    require(data, secs, 0x5c85f14, bytes.fromhex('85c0'))
    require(data, secs, 0x5c860b2, bytes.fromhex('488b45b848895808c70001000000'))
    require(data, secs, 0x5c86100, bytes.fromhex('48894108c70101000000'))
    require(data, secs, 0x5c865d5, bytes.fromhex('c70100000000'))
    require(data, secs, 0x5c8685e, bytes.fromhex('83f826'))
    require(data, secs, 0x5c86863, bytes.fromhex('c605ee97870002'))
    require(data, secs, 0x5c868b9, bytes.fromhex('85c0'))
    validate_native_imports(rels)

    prelude_rows = [{'tls_byte': value, 'selected_route': prelude_route(prelude, value)}
                    for value in (0, prelude['ready_byte'], prelude['error_byte'], 3, 255)]
    cases = []
    for kind in range(256):
        for flag in (0, 1):
            for program_type, program in (('exact', constants['program']), ('other', b'run-clienT')):
                decision, tag = select_mode(constants, kind, flag, program)
                cases.append({'kind_byte': kind, 'flag_representative': flag, 'program_case': program_type,
                              'decision': decision, 'result_tag': '' if tag is None else tag})

    exhaustive = {}
    for program_type, program in (('exact', constants['program']), ('other', b'run-clienT')):
        counts = {}
        for kind in range(256):
            for flag in range(256):
                decision, _ = select_mode(constants, kind, flag, program)
                counts[decision] = counts.get(decision, 0) + 1
        exhaustive[program_type] = {'cases': sum(counts.values()), 'decisions': dict(sorted(counts.items()))}

    probes = []
    special = constants['program']
    for i in range(len(special) * 8):
        altered = bytearray(special)
        altered[i // 8] ^= 1 << (i % 8)
        decision, tag = select_mode(constants, 3, 0, bytes(altered))
        probes.append({'case': 'flip_' + str(i), 'input_hex': bytes(altered).hex(),
                       'kind': 3, 'flag': 0, 'decision': decision,
                       'result_tag': '' if tag is None else tag})
    for label, program in (('exact', special), ('short', special[:-1]),
                           ('long', special + b'2'), ('empty', b''), ('zero_suffix', special + b'\x00')):
        decision, tag = select_mode(constants, 3, 0, program)
        probes.append({'case': label, 'input_hex': program.hex(), 'kind': 3, 'flag': 0,
                       'decision': decision, 'result_tag': '' if tag is None else tag})

    names = make_name_rows(data, secs)
    name_cases = make_name_cases(data, secs, names)
    samples = ((b'', b' ', b'a', b'a b', b'a  b', b' a  b ', b'a\tb', b'\ta\tb\t') +
               tuple(b'--api-url ' + row['text'].encode('ascii') + b' zip-and-upload' for row in names) +
               (b'--api-url  Local zip-and-upload',))
    split_rows = []
    for sample in samples:
        pieces = ascii_trim_split(sample, 32)
        split_rows.append({'input_hex': sample.hex(), 'count': len(pieces),
                           'tokens_hex_json': json.dumps([x.hex() for x in pieces], separators=(',', ':'))})

    nul_rows = []
    for length in range(nul_constants['maximum_short_length'] + 1):
        candidates = [bytes((65,)) * length]
        for index in range(length):
            candidates.append(bytes((65,)) * index + bytes((nul_constants['nul_byte'],)) + bytes((65,)) * (length - index - 1))
        for raw in candidates:
            status, index = short_nul_model(raw, nul_constants)
            nul_rows.append({'input_hex': raw.hex(), 'length': len(raw), 'result': status,
                             'first_nul_index': '' if index is None else index})

    native_rows = []
    for operation, values in (('pidfd', (0, 1, 37, 38, 39, 255)),
                              ('posix', (0, 1, 38, 255)), ('fork', (-1, 0, 1, 100))):
        for value in values:
            native_rows.append({'operation': operation, 'status': value,
                                'selected_route': native_result_model(operation, value)})

    state_rows = []
    for mode in range(4):
        for initial in (0, 1, (1 << 64) - 2, (1 << 64) - 1):
            for changed in (False, True):
                for success in (False, True):
                    state_rows.append({'mode': mode, 'initial_count': hex(initial),
                                       'date_changed': int(changed), 'process_result_nonerror': int(success),
                                       'count_at_boundary': hex(counter_model(mode, initial, changed, success)),
                                       'outcome': 'result_copy' if success else 'error_handler'})
    diagnostic = get(data, secs, 0x464893, len(b'variant index 0 <= i < 79'))
    context_names = selected_name_anchors(data, secs, rels, 0x63f8788,
        ((0, b'Ec'), (32, b'SoloSandbox'), (33, b'NvTestnet'), (34, b'NvTestnet2'), (78, b'EbHlPerp')))
    anchors = {'global_pointer_slot_va': '0x64e0918',
               'global_relocation_addend_va': rels[0x64e0918]['addend_va'],
               'directory_field_offset': get(data, secs, 0x1564961, 4)[3],
               'name_slot_va': '0x63f8998', 'name_relocation_addend_va': rels[0x63f8998]['addend_va'],
               'name_table_base_va': '0x63f8788', 'name_index': (0x63f8998 - 0x63f8788) // 16,
               'name_length': struct.unpack('<Q', get(data, secs, 0x63f89a0, 8))[0],
               'name_bytes': get(data, secs, 0x464716, 9).hex(),
               'name_bound_diagnostic_va': '0x464893', 'name_bound_diagnostic_hex': diagnostic.hex(),
               'name_bound': int(diagnostic.split(b'< ')[1]), 'selected_name_anchors': context_names}

    summary = {'target_sha256': SHA115, 'functions': len(funcs),
               'selected_body_bytes': sum(row['size'] for row in funcs),
               'relocations': len(rels), 'transfers': len(transfers),
               'rip_references': len(refs), 'branches': len(branch_rows), 'literals': len(literal_rows),
               'windows': len(window_rows), 'mode_rows': len(cases), 'predicate_probes': len(probes),
               'ascii_split_cases': len(split_rows), 'state_cases': len(state_rows),
               'prelude_cases': len(prelude_rows),
               'native_cases': len(native_rows), 'short_nul_cases': len(nul_rows), 'name_rows': len(names),
               'name_byte_cases': len(name_cases),
               'limitations': 'Selected static ranges and operands only; no captured execution or completeness claim.'}
    return {'summary': summary, 'functions': funcs, 'bodies': bodies,
            'relocations': [rels[k] for k in sorted(rels)], 'transfers': transfers,
            'references': refs, 'branches': branch_rows, 'literals': literal_rows,
            'windows': window_rows, 'name_rows': names, 'name_cases': name_cases,
            'cases': cases, 'exhaustive': exhaustive, 'probes': probes, 'split': split_rows,
            'prelude_cases': prelude_rows,
            'state_cases': state_rows, 'native_cases': native_rows, 'nul_cases': nul_rows, 'anchors': anchors}


def emit(result, out):
    out.mkdir(parents=True, exist_ok=True)
    write_json(out, 'summary.json', result['summary'])
    write_json(out, 'functions.json', result['functions'])
    write_json(out, 'relocations.json', result['relocations'])
    write_json(out, 'name-dispatch.json', result['name_rows'])
    write_json(out, 'mode-exhaustive.json', result['exhaustive'])
    write_json(out, 'context-anchors.json', result['anchors'])
    write_tsv(out, 'bodies.tsv', ('role', 'start_va', 'end_va_exclusive', 'bytes'), result['bodies'])
    write_tsv(out, 'transfers.tsv', ('role', 'site_va', 'file_offset', 'bytes', 'kind', 'direct_target_or_slot_va', 'slot_addend_va', 'dynamic_symbol'), result['transfers'])
    write_tsv(out, 'references.tsv', ('role', 'site_va', 'file_offset', 'bytes', 'target_va'), result['references'])
    write_tsv(out, 'branches.tsv', ('role', 'site_va', 'bytes', 'fallthrough_va', 'taken_va', 'condition_code'), result['branches'])
    write_tsv(out, 'literals.tsv', ('role', 'va', 'file_offset', 'length', 'bytes'), result['literals'])
    write_tsv(out, 'windows.tsv', ('role', 'start_va', 'end_va_exclusive', 'file_offset', 'bytes'), result['windows'])
    write_tsv(out, 'mode-cases.tsv', ('kind_byte', 'flag_representative', 'program_case', 'decision', 'result_tag'), result['cases'])
    write_tsv(out, 'equality-probes.tsv', ('case', 'input_hex', 'kind', 'flag', 'decision', 'result_tag'), result['probes'])
    write_tsv(out, 'ascii-arguments.tsv', ('input_hex', 'count', 'tokens_hex_json'), result['split'])
    write_tsv(out, 'state-cases.tsv', ('mode', 'initial_count', 'date_changed', 'process_result_nonerror', 'count_at_boundary', 'outcome'), result['state_cases'])
    write_tsv(out, 'native-cases.tsv', ('operation', 'status', 'selected_route'), result['native_cases'])
    write_tsv(out, 'short-nul-cases.tsv', ('input_hex', 'length', 'result', 'first_nul_index'), result['nul_cases'])
    write_tsv(out, 'prelude-cases.tsv', ('tls_byte', 'selected_route'), result['prelude_cases'])
    write_tsv(out, 'name-byte-cases.tsv', ('input_byte', 'shift_byte', 'shift_count', 'packed_word', 'arm_va', 'text'), result['name_cases'])


def historical_compare(old, new):
    authenticate(old, SHA94)
    authenticate(new, SHA115)
    old_secs, new_secs = sections(old), sections(new)
    _, old_fdes = eh_frame_records(old, old_secs)
    old_matches = [x for x in old_fdes if x['start'] == 0x13cd410 and x['end'] == 0x13cd6cb]
    if len(old_matches) != 1:
        raise ValueError('historical selected FDE mismatch')
    pairs = []
    for role, old_va, new_va, raw in (
        ('cham', 0x1fc0ec, 0x44ab69, bytes.fromhex('c0052f6368616d00')),
        ('static', 0x1ef5f5, 0x4401ef, bytes.fromhex('c00e2f7374617469635f636f6e66696700')),
        ('build', 0x1fae07, 0x449a91, bytes.fromhex('c00b2f6177735f6275696c642fc000')),
        ('client', 0x1e4c77, 0x4366ce, bytes.fromhex('c0102f636f64652f72756e2d636c69656e7400')),
    ):
        require(old, old_secs, old_va, raw)
        require(new, new_secs, new_va, raw)
        pairs.append({'role': role, 'bytes': raw.hex(), 'old_va': hex(old_va),
                      'old_file_offset': hex(file_offset(old_secs, old_va, len(raw))),
                      'new_va': hex(new_va), 'new_file_offset': hex(file_offset(new_secs, new_va, len(raw)))})
    old_refs = ((0x13cd525, 0x1fae07), (0x13cd5be, 0x1e4c77),
                (0x164f840, 0x1fc0ec), (0x164fbae, 0x1ef5f5))
    old_rips = []
    for va, target in old_refs:
        raw = get(old, old_secs, va, 7)
        if decode_rip(raw, va) != target:
            raise ValueError('historical RIP-relative reference mismatch')
        old_rips.append({'site_va': hex(va), 'target_va': hex(target), 'bytes': raw.hex()})
    old_indices, new_indices = (0, 31, 32, 33, 75), (0, 32, 33, 34, 78)
    rel_old = relocations(old, old_secs, [0x5668288 + 16 * i for i in old_indices])
    rel_new = relocations(new, new_secs, [0x63f8788 + 16 * i for i in new_indices])
    old_names = selected_name_anchors(old, old_secs, rel_old, 0x5668288,
        ((0, b'Ec'), (31, b'SoloSandbox'), (32, b'NvTestnet'), (33, b'NvTestnet2'), (75, b'EbHlPerp')))
    new_names = selected_name_anchors(new, new_secs, rel_new, 0x63f8788,
        ((0, b'Ec'), (32, b'SoloSandbox'), (33, b'NvTestnet'), (34, b'NvTestnet2'), (78, b'EbHlPerp')))
    old_diagnostic = require(old, old_secs, 0x21823f, b'variant index 0 <= i < 76')
    new_diagnostic = require(new, new_secs, 0x464893, b'variant index 0 <= i < 79')
    for b, s, slot, text_va in ((old, old_secs, 0x5668488, 0x2180ff),
                                 (new, new_secs, 0x63f8998, 0x464716)):
        require(b, s, slot + 8, struct.pack('<Q', 9))
        require(b, s, text_va, b'NvTestnet')
    if int(rel_old[0x5668488]['addend_va'], 16) != 0x2180ff or int(rel_new[0x63f8998]['addend_va'], 16) != 0x464716:
        raise ValueError('historical name relocation mismatch')
    old_prefix = get(old, old_secs, 0x13cd410, 54)
    new_prefix = get(new, new_secs, 0x1564870, 54)
    if old_prefix != new_prefix:
        raise ValueError('selected comparison prefix differs')
    return {'old_sha256': SHA94, 'new_sha256': SHA115, 'old_selector_fde': {'start': '0x13cd410', 'end': '0x13cd6cb'},
            'new_selector_fde': {'start': '0x1564870', 'end': '0x1564b2b'},
            'equal_prefix_hex': old_prefix.hex(), 'equal_prefix_length': len(old_prefix),
            'templates': pairs, 'old_references': old_rips,
            'old_name_anchors': old_names, 'new_name_anchors': new_names,
            'old_name_bound_diagnostic_hex': old_diagnostic.hex(),
            'new_name_bound_diagnostic_hex': new_diagnostic.hex(),
            'name': {'old_slot': '0x5668488', 'old_text': '0x2180ff', 'old_index': (0x5668488 - 0x5668288) // 16,
                     'new_slot': '0x63f8998', 'new_text': '0x464716', 'new_index': (0x63f8998 - 0x63f8788) // 16,
                     'length': 9, 'bytes': b'NvTestnet'.hex()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--compare-94', type=Path)
    args = parser.parse_args()
    data = TARGET.read_bytes()
    result = collect(data)
    if args.compare_94 is not None:
        comparison = historical_compare(args.compare_94.read_bytes(), data)
        print(json.dumps(comparison, sort_keys=True))
    emit(result, args.out)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except OSError as error:
        print('re015_build_selection_115: ' + (error.strerror or 'I/O error'), file=sys.stderr)
        raise SystemExit(1)
    except (ValueError, struct.error) as error:
        print('re015_build_selection_115: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
