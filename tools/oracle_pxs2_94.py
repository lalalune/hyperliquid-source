#!/usr/bin/env python3
"""Recover selected #94 oracle pxs2 serialization facts from pinned ELF bytes.

All addresses are linked ELF virtual addresses; no captured program is executed.
The control-flow models deliberately exclude opaque helper behavior.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Starts identify selected FDEs, not a full census. Names describe observed roles.
FUNCTIONS = [
    ('snapshot_wrapper_writer', 0x325f530),
    ('pxs2_vector_writer', 0x322fbd0),
    ('triple_writer', 0x323c730),
    ('entry_writer', 0x32608a0),
    ('map_header_writer', 0x35984a0),
    ('array_header_writer', 0x3598cf0),
    ('unsigned_writer', 0x359af90),
    ('time_string_writer', 0x31ebc50),
    ('date_component_formatter', 0x151f240),
    ('clock_component_formatter', 0x15204a0),
    ('time_map_reader_wrapper', 0x3c0c6a0),
    ('time_optional_reader', 0x2a8d630),
    ('time_value_reader', 0x2a93110),
    ('time_text_reader', 0x3a0d6f0),
    ('snapshot_wrapper_reader', 0x2d39c90),
    ('pxs2_vector_reader', 0x2d8dc60),
    ('vector_collect_reader', 0x341a1a0),
    ('triple_reader', 0x2aa4970),
    ('entry_reader', 0x2e33e50),
    ('entry_field_classifier', 0x325c5b0),
]

# Every site below is checked as a direct rel32 call, and its target is checked.
CALLS = [
    ('wrapper_to_vector_write', 0x325f5b8, 0x322fbd0),
    ('vector_first_triple_write', 0x322fca3, 0x323c730),
    ('vector_loop_triple_write', 0x322fcf1, 0x323c730),
    ('triple_write_0', 0x323c80b, 0x32608a0),
    ('triple_write_1', 0x323c820, 0x32608a0),
    ('triple_write_2', 0x323c838, 0x32608a0),
    ('entry_map_header', 0x32608f3, 0x35984a0),
    ('entry_array_header', 0x326091f, 0x3598cf0),
    ('vector_array_header', 0x322fc52, 0x3598cf0),
    ('map_header_marker_select_external', 0x35984cd, 0x359be70),
    ('array_header_marker_select_external', 0x3598d1d, 0x359be70),
    ('entry_write_optional_time', 0x32609b0, 0x31ebc50),
    ('entry_write_p', 0x3260a07, 0x359af90),
    ('entry_write_d', 0x3260a5a, 0x359af90),
    ('time_write_string', 0x31ebcf8, 0x3599f00),
    ('time_read_wrapper', 0x3c0c6b0, 0x2a8d630),
    ('time_read_optional_value', 0x2a8d66c, 0x2a93110),
    ('time_read_text_value', 0x2a934c6, 0x3a0d6f0),
    ('time_read_alternate_text', 0x2a936e3, 0x39ac620),
    ('time_parse_text', 0x3a0d7cf, 0x1514b50),
    ('time_read_error', 0x3a0d848, 0x2aeac40),
    ('snapshot_read_pxs2_map', 0x2d3a6fc, 0x2d8dc60),
    ('snapshot_read_pxs2_seq', 0x2d3a8cb, 0x2d8dc60),
    ('snapshot_unknown', 0x2d3a36d, 0x2ddabf0),
    ('snapshot_missing_pxs2', 0x2d3a758, 0x2aead80),
    ('snapshot_duplicate_pxs2', 0x2d3adcc, 0x2aead80),
    ('vector_read_collect', 0x2d8e17b, 0x341a1a0),
    ('collect_read_triple', 0x341a2ab, 0x2aa4970),
    ('triple_read_0', 0x2aa5485, 0x2e33e50),
    ('triple_read_1', 0x2aa5501, 0x2e33e50),
    ('triple_read_2', 0x2aa557b, 0x2e33e50),
    ('entry_classify', 0x2e34ec5, 0x325c5b0),
    ('entry_map_read_time', 0x2e35205, 0x3c0c6a0),
    ('entry_map_read_d', 0x2e35256, 0x2aa0a00),
    ('entry_map_read_p', 0x2e352d2, 0x2aa0a00),
    ('entry_map_unknown', 0x2e3528a, 0x2ddabf0),
    ('entry_seq_read_time', 0x2e34425, 0x2a93110),
    ('entry_seq_read_p', 0x2e34488, 0x2aa0a00),
    ('entry_seq_read_d', 0x2e344bc, 0x2aa0a00),
    ('entry_missing_p', 0x2e34a46, 0x2aead80),
    ('entry_missing_d', 0x2e34ab3, 0x2aead80),
    ('entry_duplicate', 0x2e354c6, 0x2aead80),
]

BRANCHES = [
    ('group_write_error_0', 0x323c814, 0x323c877),
    ('group_write_error_1', 0x323c829, 0x323c877),
    ('group_write_error_2', 0x323c841, 0x323c877),
    ('entry_zero_helper_1', 0x32608c4, 0x3260b8a),
    ('entry_zero_helper_2', 0x326093b, 0x3260b8a),
    ('entry_omit_u', 0x3260956, 0x32609c4),
    ('snapshot_duplicate_pxs2', 0x2d3a6e9, 0x2d3ad82),
    ('snapshot_missing_pxs2', 0x2d3a7d3, 0x2d3a711),
    ('snapshot_seq_empty', 0x2d3a8bd, 0x2d3a9c1),
    ('snapshot_seq_exact_one', 0x2d3a912, 0x2d3a985),
    ('group_empty', 0x2aa5472, 0x2aa5740),
    ('group_one', 0x2aa54ee, 0x2aa582c),
    ('group_two', 0x2aa5568, 0x2aa59f8),
    ('group_more_than_three', 0x2aa56d8, 0x2aa5758),
    ('entry_duplicate_u', 0x2e351f4, 0x2e35481),
    ('entry_duplicate_d', 0x2e35239, 0x2e35478),
    ('entry_duplicate_p', 0x2e352b5, 0x2e3548a),
    ('entry_seq_no_p', 0x2e3446e, 0x2e3465a),
    ('entry_seq_no_d', 0x2e3449d, 0x2e34702),
    ('u8_boundary', 0x359af9f, 0x359afcf),
    ('positive_fixint_boundary', 0x359afa3, 0x359b080),
    ('u16_boundary', 0x359afd6, 0x359b027),
    ('u32_boundary', 0x359b02e, 0x359b0c6),
    ('time_format_date_error', 0x31ebcb1, 0x31ebd48),
    ('time_format_separator_error', 0x31ebccb, 0x31ebd48),
    ('time_format_time_error', 0x31ebce1, 0x31ebd48),
    ('time_string_writer_error', 0x31ebd0b, 0x31ebd1b),
    ('time_optional_child_error', 0x2a8d678, 0x2a8d698),
    ('time_decode_invalid_result', 0x2a93179, 0x2a93a1e),
    ('time_input_truncated', 0x2a93487, 0x2a93516),
    ('time_text_alternate', 0x2a934b3, 0x2a936d8),
    ('time_parse_first_zero', 0x3a0d7e6, 0x3a0d825),
    ('time_parse_second_nonzero', 0x3a0d7eb, 0x3a0d825),
    ('time_finalize_failed', 0x3a0d804, 0x3a0d83d),
    ('date_table_out_of_range', 0x151f26b, 0x151f43a),
    ('date_extended_year', 0x151f283, 0x151f347),
    ('clock_hour_over_99', 0x15204fd, 0x15205ed),
    ('clock_zero_fraction', 0x152061b, 0x1520663),
    ('clock_three_digit_fraction', 0x1520630, 0x1520667),
    ('clock_six_digit_fraction', 0x1520642, 0x1520695),
]

# Instruction windows retain branch predicates, operands, result checks and raw
# bytes around the call sites. They are bounded observations, not disassembly.
WINDOWS = [
    ('snapshot_wrapper_pxs2', 0x325f530, 0x325f5cd),
    ('vector_stride_and_gate', 0x322fbe9, 0x322fc40),
    ('vector_write_calls', 0x322fc82, 0x322fd0d),
    ('triple_write_layout', 0x323c7dc, 0x323c843),
    ('entry_write_count_and_u', 0x32608b7, 0x32609c4),
    ('entry_write_p_d', 0x32609c4, 0x3260a72),
    ('map_header_markers', 0x35984b0, 0x35984d2),
    ('array_header_markers', 0x3598d00, 0x3598d22),
    ('date_extract_and_table', 0x151f24e, 0x151f289),
    ('date_separators_and_month', 0x151f386, 0x151f3e4),
    ('date_day_digits', 0x151f3f7, 0x151f43a),
    ('clock_extract_and_bounds', 0x15204ae, 0x1520503),
    ('clock_hour_minute_separator', 0x152055f, 0x152056e),
    ('clock_minute_second_separator', 0x15205be, 0x15205cd),
    ('clock_fraction_dispatch', 0x1520618, 0x1520667),
    ('clock_fraction_three_digits', 0x1520667, 0x1520695),
    ('clock_fraction_six_digits', 0x1520695, 0x15206c1),
    ('time_string_format', 0x31ebc9b, 0x31ebcfd),
    ('time_string_result', 0x31ebcfd, 0x31ebd48),
    ('time_string_format_failure', 0x31ebd48, 0x31ebd6f),
    ('time_map_read_wrapper', 0x3c0c6a0, 0x3c0c6ba),
    ('time_optional_read_value', 0x2a8d638, 0x2a8d6c2),
    ('time_value_dispatch', 0x2a93110, 0x2a931a6),
    ('time_text_length_and_decode', 0x2a9347d, 0x2a934d0),
    ('time_alternate_text_decode', 0x2a936d8, 0x2a9370e),
    ('time_text_parse_gate', 0x3a0d7b7, 0x3a0d7ff),
    ('time_text_finalize_and_error', 0x3a0d7ff, 0x3a0d859),
    ('uint_boundaries_1', 0x359af98, 0x359afd8),
    ('uint_u16_be', 0x359afe8, 0x359b01d),
    ('uint_u32_be', 0x359b027, 0x359b070),
    ('uint_u8', 0x359b080, 0x359b0b6),
    ('uint_u64_be', 0x359b0c6, 0x359b103),
    ('snapshot_key_matching', 0x2d3a2b5, 0x2d3a382),
    ('snapshot_read_map', 0x2d3a6ba, 0x2d3a711),
    ('snapshot_missing_field', 0x2d3a711, 0x2d3a76c),
    ('snapshot_missing_branch', 0x2d3a7b4, 0x2d3a7de),
    ('snapshot_read_sequence', 0x2d3a890, 0x2d3a92c),
    ('snapshot_arity_diagnostic', 0x2d3a9c1, 0x2d3a9e0),
    ('snapshot_duplicate_field', 0x2d3ad82, 0x2d3add1),
    ('vector_read_fixarray', 0x2d8e139, 0x2d8e189),
    ('collect_capacity', 0x341a1bb, 0x341a1e6),
    ('collect_read_call', 0x341a28e, 0x341a2c0),
    ('triple_read_first_second', 0x2aa5444, 0x2aa5506),
    ('triple_read_second_third', 0x2aa552e, 0x2aa5580),
    ('triple_exact_length', 0x2aa56cd, 0x2aa56da),
    ('triple_length_error', 0x2aa5758, 0x2aa576e),
    ('entry_seq_fields', 0x2e343e1, 0x2e344ce),
    ('entry_seq_tail', 0x2e34532, 0x2e34558),
    ('entry_map_dispatch_u_d', 0x2e351dd, 0x2e35268),
    ('entry_map_unknown_p', 0x2e35277, 0x2e352e9),
    ('entry_missing_checks', 0x2e34264, 0x2e3428a),
    ('entry_missing_p', 0x2e349f2, 0x2e34a54),
    ('entry_missing_d', 0x2e34a5f, 0x2e34abb),
    ('entry_duplicate_error', 0x2e35478, 0x2e354cd),
    ('entry_classifier', 0x325c5b0, 0x325c632),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_digest(data):
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Input SHA-256 mismatch')


def va_offset(secs, va, length, executable=False):
    require(isinstance(va, int) and isinstance(length, int) and va >= 0 and length > 0,
            'Invalid address or length')
    found = [s for s in secs if s['type'] != 8 and (not executable or s['flags'] & 4)
             and s['address'] <= va and va + length <= s['address'] + s['size']]
    require(len(found) == 1, 'VA is not uniquely backed by file bytes')
    return found[0]['offset'] + va - found[0]['address']


def read_va(data, secs, va, length, executable=False):
    pos = va_offset(secs, va, length, executable)
    require(pos + length <= len(data), 'VA bytes outside file')
    return data[pos:pos + length]


def expect(data, secs, va, expected):
    actual = read_va(data, secs, va, len(expected), True)
    require(actual == expected, 'Unexpected instruction bytes at ' + hex(va))


def direct_call(data, secs, site):
    ins = read_va(data, secs, site, 5, True)
    require(ins[0] == 0xe8, 'Expected rel32 call at ' + hex(site))
    return site + 5 + struct.unpack('<i', ins[1:])[0]


def indirect_slot(data, secs, site):
    ins = read_va(data, secs, site, 6, True)
    require(ins[:2] == bytes.fromhex('ff15'), 'Expected RIP-relative indirect call at ' + hex(site))
    return site + 6 + struct.unpack('<i', ins[2:])[0]


def relocation_addends(data, secs, wanted):
    # ELF64 Rela entries only; decode selected R_X86_64_RELATIVE records.
    rela = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    require(len(rela) == 1 and rela[0]['size'] % 24 == 0, 'Invalid dynamic relocation section')
    section = rela[0]
    end = section['offset'] + section['size']
    require(end <= len(data), 'Truncated dynamic relocation section')
    found = {}
    for pos in range(section['offset'], end, 24):
        slot, info, addend = struct.unpack_from('<QQq', data, pos)
        if slot in wanted:
            require(slot not in found and info == 8, 'Unexpected or duplicate relocation')
            found[slot] = {'record_va': hex(section['address'] + pos - section['offset']),
                           'record_file_offset': hex(pos), 'raw_hex': data[pos:pos+24].hex(),
                           'addend_va': hex(addend)}
    require(set(found) == set(wanted), 'Missing selected relocation')
    return found


def conditional_target(data, secs, site):
    ins = read_va(data, secs, site, 2, True)
    if 0x70 <= ins[0] <= 0x7f:
        return site + 2 + struct.unpack('<b', ins[1:])[0], ins.hex()
    require(ins[0] == 0x0f and 0x80 <= ins[1] <= 0x8f,
            'Expected conditional branch at ' + hex(site))
    ins = read_va(data, secs, site, 6, True)
    return site + 6 + struct.unpack('<i', ins[2:])[0], ins.hex()


def jump_table(data, secs, address, count):
    raw = read_va(data, secs, address, count * 4)
    return [address + offset for offset in struct.unpack('<' + 'i' * count, raw)]


def field_names(data, secs):
    # Snapshot reader has an inline byte-by-byte pxs2 comparison. Another
    # path compares the same bytes through a read-only data reference.
    for addr, raw in [(0x2d3a2c6, '807d0070'), (0x2d3a2cc, '807d0178'),
                      (0x2d3a2d2, '807d0273'), (0x2d3a2d8, '807d0332')]:
        expect(data, secs, addr, bytes.fromhex(raw))
    snapshot_key = bytes(read_va(data, secs, a+3, 1, True)[0] for a in
                         (0x2d3a2c6, 0x2d3a2cc, 0x2d3a2d2, 0x2d3a2d8))
    require(snapshot_key == read_va(data, secs, 0x209ed8, 4), 'Snapshot key copies disagree')
    snapshot = [(snapshot_key, 0)]
    expect(data, secs, 0x325c5cc, bytes.fromhex('0fb60e83f964741b83f970742683f975744b'))
    expect(data, secs, 0x325c5e0, bytes.fromhex('48b96461696c795f7078'))
    expect(data, secs, 0x325c5f8, bytes.fromhex('66813e7078'))
    expect(data, secs, 0x325c60c, bytes.fromhex('660f74052c7cfafc'))
    entry = [(read_va(data, secs, 0x325c5db, 1, True), 0),
             (read_va(data, secs, 0x204240, 16), 0),
             (read_va(data, secs, 0x325c5d6, 1, True), 1),
             (read_va(data, secs, 0x325c5fb, 2, True), 1),
             (read_va(data, secs, 0x325c5d1, 1, True), 2),
             (read_va(data, secs, 0x325c5e2, 8, True), 2)]
    require(snapshot_key == b'pxs2', 'Unexpected snapshot field')
    require([s.decode('ascii') for s, _ in entry] == ['u', 'last_update_time', 'p', 'px', 'd', 'daily_px'],
            'Unexpected entry fields')
    targets = jump_table(data, secs, 0x581ec4, 16)
    expected = [0x325c5cc, 0x325c5f8] + [0x325c620] * 5 + [0x325c5e0] + [0x325c620] * 7 + [0x325c608]
    require(targets == expected, 'Unexpected entry length dispatch')
    return snapshot, entry


def classify(key, fields, unknown=3):
    return next((tag for literal, tag in fields if key == literal), unknown)


def uint_rules(data, secs):
    expect(data, secs, 0x359af98, bytes.fromhex('4881fa00010000'))
    expect(data, secs, 0x359afa1, bytes.fromhex('84d2'))
    expect(data, secs, 0x359afcf, bytes.fromhex('4881fa00000100'))
    expect(data, secs, 0x359b027, bytes.fromhex('4889d148c1e920'))
    expect(data, secs, 0x359aff8, bytes.fromhex('66c1c208'))
    expect(data, secs, 0x359b054, bytes.fromhex('0fca'))
    expect(data, secs, 0x359b0e6, bytes.fromhex('480fca'))
    for addr, prefix in [(0x359b094, '42c60409'), (0x359afec, '42c6040f'),
                         (0x359b048, '42c6040f'), (0x359b0da, '42c6040f')]:
        expect(data, secs, addr, bytes.fromhex(prefix))
    expect(data, secs, 0x35984c1, bytes.fromhex('bd80000000'))
    expect(data, secs, 0x3598d11, bytes.fromhex('bd90000000'))
    expect(data, secs, 0x32609df, bytes.fromhex('c60431a1'))
    expect(data, secs, 0x32609f3, bytes.fromhex('c6043170'))
    expect(data, secs, 0x3260a31, bytes.fromhex('c60431a1'))
    expect(data, secs, 0x3260a45, bytes.fromhex('c6043164'))
    return {'map_base': read_va(data, secs, 0x35984c2, 1)[0],
            'array_base': read_va(data, secs, 0x3598d12, 1)[0],
            'single_char_string_prefix': read_va(data, secs, 0x32609e2, 1)[0],
            'entry_keys': [read_va(data, secs, x, 1)[0] for x in (0x32609f6, 0x3260a48)],
            'u8_limit': struct.unpack('<I', read_va(data, secs, 0x359af9b, 4))[0],
            'u16_limit': struct.unpack('<I', read_va(data, secs, 0x359afd2, 4))[0],
            'u32_shift': read_va(data, secs, 0x359b02d, 1)[0],
            'markers': [read_va(data, secs, x, 1)[0] for x in
                        (0x359b098, 0x359aff0, 0x359b04c, 0x359b0de)]}


def temporal_rules(data, secs):
    # These exact instruction sequences bind the narrow models below. The date
    # lookup is file-backed .rodata; the fractional descriptors go to an
    # external formatter whose general format grammar is not closed here.
    expect(data, secs, 0x151f24e, bytes.fromhex(
        '8b1f4189dd41c1fd0d44896c2404c1eb0381e3ff03000081fbdd020000'
        '0f83c9010000488d05fd13d3fe0fb62c034181fd102700000f83be000000'))
    expect(data, secs, 0x151f389, bytes.fromhex('be2d000000'))
    expect(data, secs, 0x151f3d8, bytes.fromhex('be2d000000'))
    expect(data, secs, 0x15204ae, bytes.fromhex(
        '8b078b4f04bb89888888480fafd848c1eb256bd33c4189c44129d4'
        '448db9003665c481f900ca9a3b4183dcff81f900ca9a3b440f42f9'
        '41bec5b3a2914c0faff049c1ee2b44897c242cb0014180fe630f87ea000000'))
    expect(data, secs, 0x1520562, bytes.fromhex('be3a000000'))
    expect(data, secs, 0x15205c1, bytes.fromhex('be3a000000'))
    expect(data, secs, 0x1520618, bytes.fromhex(
        '4585ff74464489f84169cf3961c268c1c90681f9c61000007635'
        '4169cfd578e926c1c90381f9378941007651'))
    expect(data, secs, 0x1520667, bytes.fromhex('4869c083de1b4348c1e832'))
    expect(data, secs, 0x1520695, bytes.fromhex('4869c0d34d621048c1e826'))
    table_va = 0x250675
    table_size = struct.unpack('<I', read_va(data, secs, 0x151f267, 4, True))[0]
    table = read_va(data, secs, table_va, table_size)
    descriptors = read_va(data, secs, 0x250cb0, 30)
    require(descriptors == bytes.fromhex('012ec320000069030000012ec320000069060000012ec320000069090000'),
            'Unexpected fractional format descriptors')
    return {'date_table_va': hex(table_va), 'date_table_file_offset': hex(va_offset(secs, table_va, table_size)),
            'date_table_hex': table.hex(), 'date_index_mask': struct.unpack('<I', read_va(data, secs, 0x151f261, 4, True))[0],
            'date_year_limit': struct.unpack('<I', read_va(data, secs, 0x151f27f, 4, True))[0],
            'nanos_unit': struct.unpack('<I', read_va(data, secs, 0x15204d2, 4, True))[0],
            'fraction_multipliers': [struct.unpack('<I', read_va(data, secs, v, 4, True))[0]
                                     for v in (0x1520623, 0x1520635)],
            'fraction_thresholds': [struct.unpack('<I', read_va(data, secs, v, 4, True))[0]
                                    for v in (0x152062c, 0x152063e)],
            'fraction_rotations': [read_va(data, secs, v, 1, True)[0] for v in (0x1520629, 0x152063b)],
            'fraction_divide_multipliers': [struct.unpack('<I', read_va(data, secs, v, 4, True))[0]
                                           for v in (0x152066a, 0x1520698)],
            'fraction_divide_shifts': [read_va(data, secs, v, 1, True)[0] for v in (0x1520671, 0x152069f)],
            'fraction_descriptor_va': '0x250cb0', 'fraction_descriptors_hex': descriptors.hex(),
            'fraction_widths': [descriptors[i] for i in (7, 17, 27)]}


def ror32(value, count):
    value &= 0xffffffff
    require(0 < count < 32, 'Invalid rotation')
    return ((value >> count) | (value << (32-count))) & 0xffffffff


def modeled_time(date_word, seconds, nanos, rules):
    # Bounded ordinary route only; no validation that the synthetic input is a
    # valid date, leap second or admitted node state. Extended years and times
    # outside one day are deliberately outside this model.
    require(type(date_word) is int and 0 <= date_word < 1 << 32, 'Date word outside u32')
    require(type(seconds) is int and 0 <= seconds < 86400, 'Seconds outside modeled day')
    unit = rules['nanos_unit']
    require(type(nanos) is int and 0 <= nanos < 2 * unit, 'Fraction outside modeled range')
    signed = date_word if date_word < 1 << 31 else date_word - (1 << 32)
    year = signed >> 13
    require(0 <= year < rules['date_year_limit'], 'Extended year outside model')
    index = (date_word >> 3) & rules['date_index_mask']
    table = bytes.fromhex(rules['date_table_hex'])
    require(index < len(table), 'Date lookup out of bounds')
    month_day = index + table[index]
    month, day = month_day >> 6, (month_day >> 1) & 31
    hour = seconds // 3600
    minute = (seconds // 60) % 60
    second = seconds % 60
    if nanos >= unit:
        second += 1
        nanos -= unit
    formatted = f'{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}'
    if nanos:
        first = ror32(nanos * rules['fraction_multipliers'][0], rules['fraction_rotations'][0])
        second_test = ror32(nanos * rules['fraction_multipliers'][1], rules['fraction_rotations'][1])
        if first <= rules['fraction_thresholds'][0]:
            width = rules['fraction_widths'][0]
            value = (nanos * rules['fraction_divide_multipliers'][0]) >> rules['fraction_divide_shifts'][0]
        elif second_test <= rules['fraction_thresholds'][1]:
            width = rules['fraction_widths'][1]
            value = (nanos * rules['fraction_divide_multipliers'][1]) >> rules['fraction_divide_shifts'][1]
        else:
            width, value = rules['fraction_widths'][2], nanos
        formatted += f'.{value:0{width}d}'
    return formatted


def encode_unsigned(value, rules):
    require(type(value) is int and 0 <= value < 1 << 64, 'Unsigned value out of range')
    if value < 128:
        return bytes([value])
    if value < rules['u8_limit']:
        return bytes([rules['markers'][0], value])
    if value < rules['u16_limit']:
        return bytes([rules['markers'][1]]) + value.to_bytes(2, 'big')
    if value < 1 << rules['u32_shift']:
        return bytes([rules['markers'][2]]) + value.to_bytes(4, 'big')
    return bytes([rules['markers'][3]]) + value.to_bytes(8, 'big')


def compact_named_entry(p, d, rules):
    # The header helper's previously established fixed-map selector is an
    # external dependency. The two keys and unsigned operands are local.
    out = bytearray([rules['map_base'] | 2])
    for key, value in zip(rules['entry_keys'], (p, d)):
        out.extend((rules['single_char_string_prefix'], key))
        out.extend(encode_unsigned(value, rules))
    return bytes(out)


def entry_decisions(first, second, lo, mid, hi):
    # Two independent helper calls control count and emission. No equality of
    # their results is assumed. Helper zero goes to a separate failure path.
    require(all(type(x) is int and 0 <= x < 1 << 32 for x in (first, second, lo, mid, hi)),
            'Expected five unsigned 32-bit words')
    require(first != 0 and second != 0, 'Helper returned zero')
    return (2 if lo == first and mid == 0 and hi == 0 else 3,
            not (lo == second and mid == 0 and hi == 0))


def parsed_time_route(first, second):
    # Exact branch inputs after an external parse, without attributing meanings
    # to the returned pair or assuming anything about reachable combinations.
    require(type(first) is int and type(second) is int and 0 <= first < 1 << 64 and 0 <= second < 1 << 64,
            'Parser result words must be unsigned 64-bit values')
    return 'finalize' if first != 0 and second == 0 else 'error_conversion'


def field_route(tag, seen):
    # The decoder branches on these already-computed slots, not on the raw
    # numeric value. Child decode and niche representations remain opaque.
    require(type(tag) is int and 0 <= tag <= 3 and type(seen) is bool, 'Invalid tag or seen flag')
    return 'unknown_helper' if tag == 3 else ('duplicate_diagnostic' if seen else 'decode_value')


def group_path(length):
    require(type(length) is int and 0 <= length <= 15, 'Expected fixarray length')
    return ('missing_' + str(length)) if length < 3 else ('exact_3' if length == 3 else 'excess')


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def gather(data):
    verify_digest(data)
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    funcs = []
    for name, start in FUNCTIONS:
        matches = [f for f in fdes if f['start'] == start]
        require(len(matches) == 1, 'Missing or ambiguous selected FDE: ' + hex(start))
        fde = matches[0]
        require(fde['end'] > start, 'Empty FDE extent')
        body = read_va(data, secs, start, fde['end'] - start, True)
        funcs.append({'role': name, 'start_va': hex(start), 'end_va_exclusive': hex(fde['end']),
                      'fde_va': hex(fde['fde']), 'file_offset': hex(va_offset(secs, start, len(body), True)),
                      'body_sha256': hashlib.sha256(body).hexdigest()})
    calls = []
    for name, site, expected in CALLS:
        target = direct_call(data, secs, site)
        require(target == expected, 'Wrong call target: ' + name)
        calls.append([name, hex(site), read_va(data, secs, site, 5, True).hex(), hex(target)])
    branches = []
    for name, site, expected in BRANCHES:
        target, raw = conditional_target(data, secs, site)
        require(target == expected, 'Wrong branch target: ' + name)
        branches.append([name, hex(site), raw, hex(target)])
    windows = [[name, hex(start), hex(end), hex(va_offset(secs, start, end-start, True)),
                read_va(data, secs, start, end-start, True).hex()] for name, start, end in WINDOWS]
    snapshot, entry = field_names(data, secs)
    rules = uint_rules(data, secs)
    temporal = temporal_rules(data, secs)
    indirect_sites = [('default_helper_first', 0x32608bc, 0x576e890),
                      ('default_helper_second', 0x3260933, 0x576e890),
                      ('time_date_formatter', 0x31ebca9, 0x576f560),
                      ('time_clock_formatter', 0x31ebcd9, 0x576f568),
                      ('missing_time_default', 0x2e3426c, 0x5770e28),
                      ('sequence_time_default', 0x2e34466, 0x5770e28),
                      ('time_generic_decode', 0x2a9316d, 0x576e750),
                      ('time_text_input_check', 0x2a934a8, 0x576e3f8),
                      ('time_parsed_value_finalize', 0x3a0d7f9, 0x576ff00)]
    relocs = relocation_addends(data, secs, {x[2] for x in indirect_sites} | {0x56d8498})
    indirect = []
    for name, site, slot in indirect_sites:
        require(indirect_slot(data, secs, site) == slot, 'Unexpected indirect slot: ' + name)
        row = {'role': name, 'site_va': hex(site), 'instruction_hex': read_va(data, secs, site, 6, True).hex(),
               'slot_va': hex(slot), **relocs[slot]}
        indirect.append(row)
    expect(data, secs, 0x31ebcc1, bytes.fromhex('be54000000ff5020'))
    expect(data, secs, 0x2d3a9c6, bytes.fromhex('488d15cbda9902'))
    descriptor = relocs[0x56d8498]
    require(descriptor['addend_va'] == '0x578892', 'Unexpected snapshot descriptor relocation')
    descriptor_size = struct.unpack('<Q', read_va(data, secs, 0x56d84a0, 8))[0]
    descriptor['slot_va'] = '0x56d8498'
    descriptor['length'] = descriptor_size
    descriptor['text'] = read_va(data, secs, 0x578892, descriptor_size).decode('ascii')
    require(descriptor['text'] == 'struct OracleSnapshot with 1 element', 'Unexpected snapshot descriptor')
    tables = {}
    for name, address, count in [('entry_field_tags', 0x54e5e8, 4),
                                 ('entry_key_lengths_1_to_16', 0x581ec4, 16)]:
        targets = jump_table(data, secs, address, count)
        tables[name] = {'table_va': hex(address), 'file_offset': hex(va_offset(secs, address, count * 4)),
                        'raw_le_i32': read_va(data, secs, address, count * 4).hex(),
                        'target_va': [hex(v) for v in targets]}
    require(tables['entry_field_tags']['target_va'] == list(map(hex, [0x2e351ec, 0x2e352af, 0x2e3522d, 0x2e35277])), 'Unexpected entry dispatch')
    constants = {'oracle_kind_map': read_va(data, secs, 0x59b552, 13).decode('ascii'),
                 'snapshot_pxs2': read_va(data, secs, 0x209ed8, 4).decode('ascii'),
                 'entry_u': read_va(data, secs, 0x5768a4, 1).decode('ascii'),
                 'entry_p': read_va(data, secs, 0x576bc9, 1).decode('ascii'),
                 'entry_d': read_va(data, secs, 0x5771df, 1).decode('ascii'),
                 'time_type': read_va(data, secs, 0x209e8c, 4).decode('ascii'),
                 'time_separator': read_va(data, secs, 0x31ebcc2, 1).decode('ascii')}
    require(constants == {'oracle_kind_map': 'OracleKindMap', 'snapshot_pxs2': 'pxs2',
                          'entry_u': 'u', 'entry_p': 'p', 'entry_d': 'd',
                          'time_type': 'Time', 'time_separator': 'T'}, 'Unexpected literal')
    return secs, funcs, calls, branches, windows, snapshot, entry, rules, tables, constants, indirect, descriptor, temporal


def generate(data, out):
    secs, funcs, calls, branches, windows, snapshot, entry, rules, tables, constants, indirect, descriptor, temporal = gather(data)
    out.mkdir(parents=True, exist_ok=True)
    evidence = {'target_sha256': SHA256, 'coordinate_system': 'linked ELF virtual addresses; file offsets are zero-based',
                'functions': funcs, 'jump_tables': tables, 'literals': constants, 'unsigned_rules': rules,
                'indirect_calls_and_relocations': indirect, 'snapshot_diagnostic_descriptor': descriptor, 'temporal_rules': temporal,
                'scope': 'Selected FDE extents and instruction windows; direct-call and branch targets are not full CFGs.'}
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    write_tsv(out / 'calls.tsv', ['role', 'site_va', 'instruction_hex', 'target_va'], calls)
    write_tsv(out / 'branches.tsv', ['role', 'site_va', 'instruction_hex', 'target_va'], branches)
    write_tsv(out / 'windows.tsv', ['role', 'start_va', 'end_va_exclusive', 'file_offset', 'bytes_hex'], windows)
    rows = []
    for domain, fields, unknown in [('snapshot', snapshot, 1), ('entry', entry, 3)]:
        for literal, tag in fields:
            rows.append([domain, literal.decode('ascii'), tag, 'exact'])
            for i in range(len(literal)):
                mutated = literal[:i] + bytes([literal[i] ^ 1]) + literal[i+1:]
                rows.append([domain, mutated.hex(), classify(mutated, fields, unknown), 'single_bit_mutation_hex'])
        rows.extend([[domain, '', classify(b'', fields, unknown), 'empty'],
                     [domain, 'ff', classify(b'\xff', fields, unknown), 'non_ascii_hex']])
    write_tsv(out / 'classifier-cases.tsv', ['domain', 'key_or_hex', 'modeled_tag', 'case'], rows)
    boundary_values = [0, 1, 127, 128, 255, 256, 65535, 65536,
                       (1 << 32) - 1, 1 << 32, (1 << 64) - 1]
    write_tsv(out / 'unsigned-cases.tsv', ['value_decimal', 'modeled_output_hex'],
              [[v, encode_unsigned(v, rules).hex()] for v in boundary_values])
    examples = [(0, 0), (1, 2), (127, 128), (255, 256), (65535, 65536)]
    write_tsv(out / 'compact-entry-cases.tsv', ['p_decimal', 'd_decimal', 'modeled_named_map_hex'],
              [[p, d, compact_named_entry(p, d, rules).hex()] for p, d in examples])
    write_tsv(out / 'triple-cases.tsv', ['fixarray_length', 'modeled_branch_if_prior_children_succeed_and_are_present'],
              [[length, group_path(length)] for length in range(16)])
    write_tsv(out / 'time-parse-route-cases.tsv', ['first_word', 'second_word', 'modeled_branch'],
              [[a, b, parsed_time_route(a, b)] for a in (0, 1) for b in (0, 1)])
    write_tsv(out / 'field-route-cases.tsv', ['entry_tag', 'seen_slot_nonzero', 'modeled_branch'],
              [[tag, int(seen), field_route(tag, seen)] for tag in range(4) for seen in (False, True)])
    defaults = [(7, 7, 7, 0, 0), (7, 7, 8, 0, 0), (7, 7, 7, 1, 0),
                (7, 7, 7, 0, 1), (7, 8, 7, 0, 0), (7, 8, 8, 0, 0)]
    time_cases = [((1970 << 13) | (3 << 3), 0, 0),
                  ((2024 << 13) | (120 << 3), 45296, 123000000),
                  ((2024 << 13) | (120 << 3), 45296, 123456000),
                  ((2024 << 13) | (120 << 3), 45296, 123456789),
                  ((2024 << 13) | (732 << 3), 86399, 1000000000),
                  ((2024 << 13) | (732 << 3), 86399, 1000000001)]
    write_tsv(out / 'time-model-cases.tsv', ['date_word_hex', 'seconds', 'nanos', 'modeled_time_text'],
              [[hex(word), sec, nano, modeled_time(word, sec, nano, temporal)] for word, sec, nano in time_cases])
    write_tsv(out / 'entry-default-cases.tsv', ['first_helper', 'second_helper', 'word0', 'word1', 'word2',
              'modeled_header_field_count', 'modeled_emit_u'],
              [[*case, entry_decisions(*case)[0], int(entry_decisions(*case)[1])] for case in defaults])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    generate(TARGET.read_bytes(), args.out)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as exc:
        print('oracle_pxs2_94:', exc, file=sys.stderr)
        raise SystemExit(1)
