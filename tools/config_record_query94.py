#!/usr/bin/env python3
"""Static node #94 name-gated record-query evidence; no target execution.

Selected instruction lengths, direct edges and operands are decoded from the
captured bytes. This is a fixed-scope decoder and is not a general x86 decoder.
"""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import struct
import sys

TOOL_DIR = Path(__file__).resolve().parent
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))
from elf_index import sections
from fde_extents import eh_frame_records, uleb

ROOT = TOOL_DIR.parent
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
FUNCTIONS = (
    ('query_wrapper', 0x2586d80, 0x2586eb4, '611111a1768d605baa8eee83600502cecad207011c0a346ee94388ce148b3252'),
    ('locked_query', 0x27d5d60, 0x27d6035, 'ccc594b1a73f5e50b7cad89873e3337bdc23d89f5cd9474a88132458c9af866d'),
    ('collect_records', 0x257ed30, 0x257ef7a, '5c94c323048f6fb4f091a73100763eac64c5aa85d0eab6594d702287e8fdaeae'),
    ('select_next', 0x24c1430, 0x24c1639, 'f12ae5724be3acf07e957c789f6e76961fa926190666d3cf0b72c5457df5aaec'),
    ('cleanup_row', 0x250c2b0, 0x250c34b, '017d1910877eb0e5ebaeb7e475488b64697c86211b9f0583a35e4dfc45c770df'),
    ('cleanup_vector', 0x250f0d0, 0x250f4b3, '2d6f71c65602c0a9423b933ff967cb91befb091e0f841a8e4513c103a6aac960'),
)


def verify_identity(data):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('node 94 artifact size or SHA-256 mismatch')


class View:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)

    def offset(self, va, size=1):
        if va < 0 or size <= 0:
            raise ValueError('negative address or size')
        matches = [s for s in self.sections if s['type'] != 8 and s['size'] and
                   s['address'] <= va and va + size <= s['address'] + s['size'] and
                   s['offset'] + va - s['address'] + size <= len(self.data)]
        if len(matches) != 1:
            raise ValueError('address range is not uniquely file-backed')
        return matches[0]['offset'] + va - matches[0]['address']

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]


def require(view, label, va, expected):
    raw = view.read(va, len(expected))
    if raw != expected:
        raise ValueError(f'{label}: selected bytes changed at {va:#x}')
    return raw


def _need(body, pos, count):
    if pos < 0 or count < 0 or pos + count > len(body):
        raise ValueError('truncated instruction')


def decode_one(body, off, base):
    """Decode one length and control-transfer form; no full mnemonic claim."""
    start = off
    prefix66 = False
    rex = 0
    while True:
        _need(body, off, 1)
        p = body[off]
        if p in (0x66, 0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65):
            prefix66 |= p == 0x66
            off += 1
        elif 0x40 <= p <= 0x4f:
            rex = p
            off += 1
        else:
            break
        if off - start > 8:
            raise ValueError('too many prefixes')
    op = body[off]
    off += 1
    kind = 'instruction'
    target = None
    rel_width = 0
    modrm_needed = False
    imm = 0
    op2 = None
    if op == 0x0f:
        _need(body, off, 1)
        op2 = body[off]
        off += 1
        if 0x80 <= op2 <= 0x8f:
            kind, rel_width = 'conditional', 4
        elif op2 == 0x0b:
            kind = 'trap'
        elif (op2 in (0x10, 0x11, 0x14, 0x15, 0x1f, 0x28, 0x29, 0x2a, 0x2e, 0x2f, 0x57, 0x58, 0x5c, 0x5e,
                      0x60, 0x6e, 0x6f, 0x70, 0x74, 0x7e, 0x7f, 0xa3, 0xaf, 0xb6, 0xb7,
                      0xb0, 0xb1, 0xbc, 0xbe, 0xbf, 0xc1, 0xd6, 0xd7, 0xdb, 0xdf, 0xeb, 0xef)
              or 0x40 <= op2 <= 0x4f or 0x90 <= op2 <= 0x9f):
            modrm_needed = True
        else:
            raise ValueError(f'unsupported 0f opcode {op2:02x} at {base + start:#x}')
    elif op in (0xe8, 0xe9):
        kind, rel_width = ('call' if op == 0xe8 else 'jump'), 4
    elif op == 0xeb or 0x70 <= op <= 0x7f:
        kind, rel_width = ('jump' if op == 0xeb else 'conditional'), 1
    elif op in (0xc3, 0xcb):
        kind = 'return'
    elif op == 0xc2:
        kind, imm = 'return', 2
    elif op in (0xcc, 0xf4):
        kind = 'trap'
    elif 0x50 <= op <= 0x5f or op in (0x90, 0x98, 0x99, 0xc9):
        pass
    elif 0xb8 <= op <= 0xbf:
        imm = 8 if rex & 8 else (2 if prefix66 else 4)
    elif 0xb0 <= op <= 0xb7 or op in (0x6a, 0xa8, 0x04, 0x0c, 0x24, 0x2c, 0x34, 0x3c):
        imm = 1
    elif op in (0x68, 0xa9, 0x05, 0x0d, 0x25, 0x2d, 0x35, 0x3d):
        imm = 2 if prefix66 else 4
    elif op in (0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b,
                0x20, 0x21, 0x22, 0x23, 0x28, 0x29, 0x2a, 0x2b,
                0x30, 0x31, 0x32, 0x33, 0x38, 0x39, 0x3a, 0x3b,
                0x63, 0x69, 0x6b, 0x80, 0x81, 0x83, 0x84, 0x85,
                0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8d, 0x8f,
                0xc0, 0xc1, 0xc6, 0xc7, 0xd0, 0xd1, 0xd2, 0xd3,
                0xf6, 0xf7, 0xfe, 0xff):
        modrm_needed = True
    else:
        raise ValueError(f'unsupported opcode {op:02x} at {base + start:#x}')

    rip_disp_pos = None
    modrm = None
    if modrm_needed:
        _need(body, off, 1)
        modrm = body[off]
        off += 1
        mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
        sib_base = None
        if mod != 3 and rm == 4:
            _need(body, off, 1)
            sib_base = body[off] & 7
            off += 1
        if mod == 0 and rm == 5:
            rip_disp_pos = off
            off += 4
        elif mod == 0 and sib_base == 5:
            off += 4
        elif mod == 1:
            off += 1
        elif mod == 2:
            off += 4
        if op == 0x0f and op2 == 0x70:
            imm = 1
        elif op in (0x80, 0x83, 0x6b, 0xc0, 0xc1, 0xc6):
            imm = 1
        elif op in (0x81, 0x69, 0xc7):
            imm = 2 if prefix66 else 4
        elif op == 0xf6 and reg in (0, 1):
            imm = 1
        elif op == 0xf7 and reg in (0, 1):
            imm = 2 if prefix66 else 4
        if op == 0xff and reg in (2, 4):
            kind = 'indirect_call' if reg == 2 else 'indirect_jump'
    if rel_width:
        _need(body, off, rel_width)
        delta = int.from_bytes(body[off:off + rel_width], 'little', signed=True)
        off += rel_width
        target = base + off + delta
    else:
        _need(body, off, imm)
        off += imm
        if rip_disp_pos is not None:
            _need(body, rip_disp_pos, 4)
            target = base + off + struct.unpack_from('<i', body, rip_disp_pos)[0]
    if off - start > 15:
        raise ValueError('instruction exceeds x86 maximum')
    _need(body, start, off - start)
    return {'va': base + start, 'end': base + off, 'kind': kind,
            'target': target, 'bytes': bytes(body[start:off]),
            'opcode': (op, op2), 'modrm': modrm,
            'rip_relative': rip_disp_pos is not None}


def decode_body(body, base):
    result = []
    offset = 0
    while offset < len(body):
        row = decode_one(body, offset, base)
        result.append(row)
        offset = row['end'] - base
    if offset != len(body):
        raise ValueError('function decoding exceeded extent')
    starts = {r['va'] for r in result}
    end = base + len(body)
    for row in result:
        if row['kind'] in ('jump', 'conditional') and base <= row['target'] < end:
            if row['target'] not in starts:
                raise ValueError(f'branch into an instruction at {row["va"]:#x}')
        if row['kind'] == 'conditional' and row['end'] < end and row['end'] not in starts:
            raise ValueError('fallthrough is not an instruction boundary')
    return result




def reachable(decoded, source, destination, forbidden=()):
    """Over-approximate normal flow: all conditions feasible and calls return."""
    by_va = {ins['va']: ins for ins in decoded}
    if source not in by_va or destination not in by_va:
        raise ValueError('CFG query is not at an instruction boundary')
    forbidden = set(forbidden)
    if any(va not in by_va for va in forbidden):
        raise ValueError('CFG forbidden VA is not an instruction boundary')
    pending, seen = [source], set()
    while pending:
        va = pending.pop()
        if va in forbidden or va in seen or va not in by_va:
            continue
        if va == destination:
            return True
        seen.add(va)
        ins = by_va[va]
        kind = ins['kind']
        if kind in ('return', 'trap', 'indirect_jump'):
            continue
        if kind == 'jump':
            pending.append(ins['target'])
        elif kind == 'conditional':
            pending.extend((ins['target'], ins['end']))
        else:
            pending.append(ins['end'])
    return False


def parse_lsda(view, start, end, lsda_va):
    """Read this target's ULEB call-site table; do not interpret actions/types."""
    containing = [s for s in view.sections if s['name'] == '.gcc_except_table'
                  and s['type'] != 8 and s['address'] <= lsda_va < s['address'] + s['size']]
    if len(containing) != 1:
        raise ValueError('LSDA outside file-backed exception table')
    sec = containing[0]
    pos = view.offset(lsda_va, 2)
    section_end = sec['offset'] + sec['size']
    data = view.data
    lp_encoding, type_encoding = data[pos], data[pos+1]
    pos += 2
    if lp_encoding != 0xff or type_encoding not in (0xff, 0x9b):
        raise ValueError('unsupported LSDA header encoding')
    type_base = None
    if type_encoding != 0xff:
        relative, pos = uleb(data, pos, section_end)
        type_base = pos + relative
        if type_base > section_end:
            raise ValueError('LSDA type table outside section')
    if pos >= section_end or data[pos] != 1:
        raise ValueError('unsupported LSDA call-site encoding')
    pos += 1
    size, pos = uleb(data, pos, section_end)
    stop = pos + size
    if stop > section_end or (type_base is not None and stop > type_base):
        raise ValueError('LSDA call-site table outside bounds')
    begin = pos
    rows = []
    previous_end = 0
    while pos < stop:
        entry_off = pos
        region, pos = uleb(data, pos, stop)
        length, pos = uleb(data, pos, stop)
        landing, pos = uleb(data, pos, stop)
        action, pos = uleb(data, pos, stop)
        if not length or region < previous_end or region + length > end - start:
            raise ValueError('LSDA protected range invalid')
        if landing and landing >= end - start:
            raise ValueError('LSDA landing pad outside selected FDE')
        previous_end = region + length
        rows.append({'function': hex(start), 'lsda_va': hex(lsda_va),
                     'entry_file_offset': hex(entry_off), 'start_va': hex(start + region),
                     'end_va': hex(start + region + length),
                     'landing_va': hex(start + landing) if landing else '', 'action_index': action})
    header = {'function': hex(start), 'lsda_va': hex(lsda_va),
              'header_file_offset': hex(view.offset(lsda_va, 2)),
              'lpstart_encoding': hex(lp_encoding), 'type_encoding': hex(type_encoding),
              'callsite_encoding': '0x1', 'callsite_file_offset': hex(begin),
              'callsite_size': size, 'entries': len(rows)}
    return header, rows



CONTRACTS = (
    ('pass_owner', 0x2586d99, '4881c6c8020000'),
    ('load_extra_flag', 0x2586da0, '440fb69288050000'),
    ('push_extra_flag', 0x2586dad, '4152'),
    ('push_context', 0x2586daf, '50'),
    ('call_locked', 0x2586db0, 'e8abef2400'),
    ('load_wait_seconds', 0x2586dc8, 'f20f104c2420'),
    ('add_elapsed_seconds', 0x2586dce, 'f20f584c2428'),
    ('compare_three_seconds', 0x2586dd9, '660f2e0dd73cc8fd'),
    ('time_skip', 0x2586de1, '762d'),
    ('global_cell_slot', 0x2586de3, '4c8b353e7b1e03'),
    ('config_once_word', 0x2586dea, '418b4650'),
    ('config_slow_branch', 0x2586df0, '753a'),
    ('config_name_byte', 0x2586df2, '410fb64648'),
    ('name_upper_bound', 0x2586df7, '83f81f'),
    ('name_bound_skip', 0x2586dfa, '7714'),
    ('name_mask_immediate', 0x2586dfc, 'b900603c80'),
    ('name_mask_bit', 0x2586e01, '0fa3c1'),
    ('name_mask_skip', 0x2586e04, '730a'),
    ('invocation_once_word', 0x2586e06, '8b058c3d1f03'),
    ('invocation_slow_branch', 0x2586e0e, '754c'),
    ('copy_result_tail', 0x2586e15, '48894310'),
    ('copy_result_prefix', 0x2586e1e, '0f1103'),
    ('return_wrapper', 0x2586e2b, 'c3'),
    ('config_once_call', 0x2586e54, 'ff155e7a1e03'),
    ('config_once_rejoin', 0x2586e5a, 'eb96'),
    ('invocation_cell_address', 0x2586e5c, '488d051d3d1f03'),
    ('invocation_once_call', 0x2586e8e, 'ff15247a1e03'),
    ('invocation_rejoin', 0x2586e94, 'e977ffffff'),
    ('wrapper_cleanup', 0x2586ea1, 'e82a82f8ff'),
    ('lock_address', 0x27d5d91, '4d8da768050000'),
    ('lock_contended_bit', 0x27d5da1, '83e108'),
    ('lock_high_bound', 0x27d5da7, '4883f8f0'),
    ('lock_fast_branch', 0x27d5db0, '7412'),
    ('lock_slow_call', 0x27d5dbc, 'ff152698f902'),
    ('lock_fast_increment', 0x27d5dc4, '488d4810'),
    ('lock_fast_cmpxchg', 0x27d5dc8, 'f0490fb10c24'),
    ('lock_fast_retry', 0x27d5dce, '75e2'),
    ('first_difference_tag', 0x27d5e0b, '807c241000'),
    ('first_difference_invalid', 0x27d5e1a, '7539'),
    ('rows_pointer', 0x27d5e55, '498b8778050000'),
    ('rows_count_scale', 0x27d5e5c, '496b8f8005000078'),
    ('call_collector', 0x27d5e8f, 'e89c8edaff'),
    ('lock_release_delta', 0x27d5e94, '48c7c0f0ffffff'),
    ('lock_release_xadd', 0x27d5ea0, 'f0480fc107'),
    ('lock_release_mask', 0x27d5ea5, '4883e0f2'),
    ('lock_wake_compare', 0x27d5ea9, '4883f812'),
    ('lock_wake_branch', 0x27d5ead, '0f84e9000000'),
    ('load_stack_extra_flag', 0x27d5ee6, '0fb68424c8000000'),
    ('second_difference_tag', 0x27d5eee, '807c241000'),
    ('second_difference_invalid', 0x27d5ef7, '7536'),
    ('conditional_extra_flag', 0x27d5f55, '84c0'),
    ('conditional_extra_branch', 0x27d5f57, '740b'),
    ('conditional_delay_argument', 0x27d5f59, 'bf32000000'),
    ('conditional_delay_call', 0x27d5f5e, 'ff159489f902'),
    ('return_vector_tail', 0x27d5f69, '48894320'),
    ('return_vector_prefix', 0x27d5f84, '0f1103'),
    ('lock_wake_call', 0x27d5f9c, 'ff155696f902'),
    ('optional_unwind_cleanup', 0x27d5faf, 'e8ac6bfaff'),
    ('lock_unwind_release', 0x27d6008, 'f0480fc10a'),
    ('collector_first_next', 0x257ed4c, 'e8df26f4ff'),
    ('collector_first_tag', 0x257ed51, '837c244803'),
    ('collector_nonempty_branch', 0x257ed56, '751c'),
    ('collector_empty_capacity', 0x257ed58, '48c70300000000'),
    ('collector_empty_pointer', 0x257ed5f, '48c7430808000000'),
    ('collector_empty_length', 0x257ed67, '48c7431000000000'),
    ('collector_allocate_bytes', 0x257ed79, 'bfe0010000'),
    ('collector_allocate_call', 0x257ed7e, 'ff1554f21e03'),
    ('collector_allocate_failure', 0x257ed87, '0f849b010000'),
    ('collector_initial_capacity', 0x257edea, '48c7042404000000'),
    ('collector_initial_pointer', 0x257edf2, '4c89742408'),
    ('collector_initial_length', 0x257edf7, '48c744241001000000'),
    ('collector_initial_count', 0x257ee13, '41bf01000000'),
    ('collector_row_stride', 0x257ee19, 'bb78000000'),
    ('collector_length_increment', 0x257eeae, '49ffc7'),
    ('collector_cursor_increment', 0x257eeb6, '4883c378'),
    ('collector_loop_next', 0x257eec0, 'e86b25f4ff'),
    ('collector_loop_tag', 0x257eec5, '83bc24c000000003'),
    ('collector_end_branch', 0x257eecd, '742f'),
    ('collector_capacity_compare', 0x257eecf, '4c3b3c24'),
    ('collector_no_growth', 0x257eed3, '0f8567ffffff'),
    ('collector_grow_call', 0x257eeef, 'e87cc1f9ff'),
    ('collector_allocation_failure_args', 0x257ef28, 'bf08000000'),
    ('collector_allocation_failure_call', 0x257ef32, 'ff1580f01e03'),
    ('collector_failure_trap', 0x257ef38, '0f0b'),
    ('collector_unwind_cleanup', 0x257ef67, 'e86401f9ff'),
    ('iterator_start', 0x24c1441, '4c8b2e'),
    ('iterator_end', 0x24c1444, '488b4608'),
    ('iterator_end_compare', 0x24c1448, '4939c5'),
    ('iterator_initial_end_branch', 0x24c144b, '0f84af000000'),
    ('iterator_filter_pointer', 0x24c1451, '488b4e10'),
    ('iterator_threshold_pointer', 0x24c1455, '488b5618'),
    ('iterator_threshold_load', 0x24c1459, '488b12'),
    ('iterator_key_offset', 0x24c145c, '4983c55c'),
    ('iterator_threshold_compare', 0x24c1470, '493955e4'),
    ('iterator_threshold_match', 0x24c1474, '7358'),
    ('iterator_next_row', 0x24c1476, '498d7d78'),
    ('iterator_advance', 0x24c147a, '4983c51c'),
    ('iterator_advance_compare', 0x24c147e, '4939c5'),
    ('iterator_advance_end', 0x24c1484, '7473'),
    ('iterator_filter_bit', 0x24c1498, 'f6042401'),
    ('iterator_use_threshold', 0x24c149c, '74d2'),
    ('iterator_key_first_16', 0x24c149e, 'f3410f6f4500'),
    ('iterator_filter_first_16', 0x24c14a4, 'f30f6f4c2401'),
    ('iterator_first_compare', 0x24c14aa, '660f74c8'),
    ('iterator_key_last_4', 0x24c14ae, '66410f6e4510'),
    ('iterator_filter_last_4', 0x24c14b4, '660f6e542411'),
    ('iterator_last_compare', 0x24c14ba, '660f74d0'),
    ('iterator_combine_compare', 0x24c14be, '660fdbd1'),
    ('iterator_compare_mask', 0x24c14c2, '660fd7fa'),
    ('iterator_compare_all', 0x24c14c6, '81ffffff0000'),
    ('iterator_key_mismatch', 0x24c14cc, '75a8'),
    ('iterator_result_next', 0x24c14ce, '498d451c'),
    ('iterator_store_next', 0x24c14d2, '488906'),
    ('iterator_owned_pointer', 0x24c14d5, '4d8b65cc'),
    ('iterator_owned_length', 0x24c14d9, '4d8b75d4'),
    ('iterator_nonempty_copy', 0x24c14e0, '742a'),
    ('iterator_allocation_call', 0x24c14e5, 'ff15edca2a03'),
    ('iterator_allocation_failure', 0x24c14ee, '0f8419010000'),
    ('iterator_exhausted_store', 0x24c14fd, '48893e'),
    ('iterator_end_tag', 0x24c1500, '48c70303000000'),
    ('iterator_empty_pointer', 0x24c150c, '41bf01000000'),
    ('iterator_copy_call', 0x24c151b, 'ff15bfca2a03'),
    ('iterator_record_tag', 0x24c152c, '4d8b65a4'),
    ('iterator_nested_tag_compare', 0x24c1530, '4983fc02'),
    ('iterator_without_nested', 0x24c1534, '725c'),
    ('iterator_nested_exists', 0x24c1536, '49837dbc00'),
    ('iterator_nested_pointer', 0x24c1543, '498b75ac'),
    ('iterator_nested_absent_panic', 0x24c154a, '0f84ae000000'),
    ('iterator_nested_clone', 0x24c1557, 'e894e03d00'),
    ('iterator_return_tag', 0x24c15c4, '4c8923'),
    ('iterator_panic_call', 0x24c1605, 'ff1565ce2a03'),
    ('iterator_panic_trap', 0x24c160b, '0f0b'),
    ('iterator_allocation_failure_call', 0x24c1615, 'ff159dc92a03'),
    ('iterator_unwind_cleanup', 0x24c162b, 'ff15dfc92a03'),
    ('row_owned_length', 0x250c2ba, '488b7720'),
    ('row_owned_zero_test', 0x250c2be, '4885f6'),
    ('row_owned_zero_branch', 0x250c2c1, '740c'),
    ('row_owned_pointer', 0x250c2c3, '488b7b28'),
    ('row_owned_release', 0x250c2c9, 'ff15411d2603'),
    ('row_tag_compare', 0x250c2cf, '833b02'),
    ('row_skip_nested_branch', 0x250c2d2, '726f'),
    ('row_nested_pointer', 0x250c2d4, '488b4b08'),
    ('row_nested_empty_branch', 0x250c2db, '7435'),
    ('row_next_nested', 0x250c336, 'e8250f3600'),
    ('row_nested_result', 0x250c33b, '48837c245000'),
    ('row_nested_loop', 0x250c341, '75ed'),
    ('row_cleanup_return', 0x250c34a, 'c3'),
    ('vector_pointer', 0x250f0e1, '488b6f08'),
    ('vector_length', 0x250f0e9, '488b4710'),
    ('vector_length_test', 0x250f0f2, '4885c0'),
    ('vector_empty_branch', 0x250f0f5, '0f8410030000'),
    ('vector_next_row_init', 0x250f100, '4c8d7d78'),
    ('vector_row_index_stride', 0x250f15c, '486bc378'),
    ('vector_row_owned_length', 0x250f164, '488b740520'),
    ('vector_row_no_allocation', 0x250f16c, '740c'),
    ('vector_row_owned_pointer', 0x250f16e, '498b7d28'),
    ('vector_row_release', 0x250f174, 'ff1596ee2503'),
    ('vector_row_tag_compare', 0x250f17a, '41837d0002'),
    ('vector_row_skip_nested', 0x250f17f, '72c6'),
    ('vector_nested_step_call', 0x250f2ab, 'e8d07361ff'),
    ('vector_nested_step_result', 0x250f2b0, '48837c246800'),
    ('vector_capacity_load', 0x250f40f, '488b00'),
    ('vector_capacity_test', 0x250f412, '4885c0'),
    ('vector_no_backing_branch', 0x250f415, '7420'),
    ('vector_backing_size', 0x250f417, '486bf078'),
    ('vector_backing_release_tail', 0x250f431, 'ff25d9eb2503'),
    ('vector_cleanup_return', 0x250f448, 'c3'),
    ('vector_error_helper', 0x250f45f, 'ff150bf02503'),
    ('vector_remaining_decrement', 0x250f470, '49ffce'),
    ('vector_remaining_done', 0x250f473, '7411'),
    ('vector_remaining_advance', 0x250f475, '498d5f78'),
    ('vector_remaining_row_cleanup', 0x250f47c, 'e82fceffff'),
    ('vector_unwind_backing_size', 0x250f492, '486bf078'),
    ('vector_unwind_backing_release', 0x250f49d, 'ff156deb2503'),
    ('vector_unwind_resume', 0x250f4a6, 'e8650c1503'),
    ('vector_cleanup_abort_edge', 0x250f4ab, 'ff1577ec2503'),
)


def collect_contracts(view, decodes):
    """Bind meaningful local decisions to instruction starts and exact bytes."""
    starts = {i['va']: i for body in decodes.values() for i in body}
    if len(starts) != sum(map(len, decodes.values())):
        raise ValueError('overlapping decoded instructions')
    rows = []
    seen_names, seen_va = set(), set()
    for label, va, expected in CONTRACTS:
        if label in seen_names or va in seen_va:
            raise ValueError('duplicate instruction contract')
        seen_names.add(label)
        seen_va.add(va)
        raw = require(view, label, va, bytes.fromhex(expected))
        if va not in starts or raw != starts[va]['bytes']:
            raise ValueError('contract is not a complete decoded instruction')
        rows.append({'label': label, 'va': hex(va),
                     'file_offset': hex(view.offset(va, len(raw))), 'bytes': raw.hex()})
    return rows


def selected_relocations(view, slots):
    """Read only requested ELF64 RELA entries, rejecting ambiguity and wrong type."""
    candidates = [s for s in view.sections if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(candidates) != 1 or candidates[0]['size'] % 24:
        raise ValueError('invalid RELA section')
    sec = candidates[0]
    rows = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', view.data, off)
        if where not in slots:
            continue
        if where in rows:
            raise ValueError('duplicate relocation for selected slot')
        if info != 8:
            raise ValueError('selected relocation is not symbol-zero RELATIVE')
        view.offset(where, 8)
        rows[where] = {'slot': hex(where), 'record_offset': hex(off),
                       'type': info & 0xffffffff, 'symbol': info >> 32,
                       'addend': hex(addend)}
    if set(rows) != set(slots):
        raise ValueError('missing selected RELATIVE relocation')
    return rows


def ascii_descriptors(view, relocs, slots):
    rows = []
    for index, slot, selected in slots:
        rel = relocs[slot]
        pointer = int(rel['addend'], 16)
        size = struct.unpack('<Q', view.read(slot + 8, 8))[0]
        if not 1 <= size <= 32:
            raise ValueError('descriptor length out of expected bounds')
        raw = view.read(pointer, size)
        if not raw.isascii() or not all(32 < c < 127 for c in raw):
            raise ValueError('descriptor is not printable ASCII')
        rows.append({'index': index, 'slot': hex(slot), 'slot_file_offset': hex(view.offset(slot, 16)),
                     'relocation_offset': rel['record_offset'], 'text_va': hex(pointer),
                     'text_file_offset': hex(view.offset(pointer, size)), 'length': size,
                     'bytes': raw.hex(), 'text': raw.decode('ascii'), 'selected_by_gate': int(selected)})
    return rows


EXPECTED_DESCRIPTORS = {
    13: 'HeavyTestnet', 14: 'HeavyMainnet', 18: 'SoloTestnet',
    19: 'SoloMainnet', 20: 'LockerTestnet', 21: 'LockerMainnet',
    31: 'SoloSandbox', 32: 'NvTestnet',
}

HANDOFF_START = 0x27e50bd
HANDOFF_BYTES = bytes.fromhex(
    '4c8d0502eac0fd488d7c2460'
    '488d4c244841b919000000e8a71cdaff'
)


def handoff_context(view, fdes):
    """Check one call-site excerpt in an already-indexed caller, without owning it."""
    raw = require(view, 'earlier caller handoff', HANDOFF_START, HANDOFF_BYTES)
    owners = [fde for fde in fdes if fde['start'] <= HANDOFF_START and
              HANDOFF_START + len(raw) <= fde['end']]
    if len(owners) != 1:
        raise ValueError('handoff does not have one enclosing unwind extent')
    ins = decode_body(raw, HANDOFF_START)
    by_va = {row['va']: row for row in ins}
    lea, length, call = (by_va[x] for x in (0x27e50bd, 0x27e50ce, 0x27e50d4))
    if not lea['rip_relative'] or length['bytes'][:2] != bytes.fromhex('41b9'):
        raise ValueError('handoff pointer or length encoding changed')
    size = struct.unpack_from('<I', length['bytes'], 2)[0]
    if call['kind'] != 'call' or call['target'] != FUNCTIONS[0][1]:
        raise ValueError('handoff call destination changed')
    text_va = lea['target']
    payload = view.read(text_va, size)
    if payload != b'small_vault_summaries_get':
        raise ValueError('handoff label changed')
    # Adjacent bytes are retained so a reviewer can distinguish the bounded
    # slice from an assumed NUL-terminated string.
    before = view.read(text_va - 1, 1)
    after = view.read(text_va + size, 1)
    if before == b'\0' or after == b'\0':
        raise ValueError('handoff neighbor unexpectedly terminated')
    label = {'text_va': hex(text_va), 'file_offset': hex(view.offset(text_va, size)),
             'length': size, 'bytes': payload.hex(), 'text': payload.decode('ascii'),
             'before': before.hex(), 'after': after.hex(), 'enclosing_fde': hex(owners[0]['fde'])}
    instructions = [{'va': hex(i['va']), 'file_offset': hex(view.offset(i['va'], len(i['bytes']))),
                     'bytes': i['bytes'].hex(), 'kind': i['kind'],
                     'target': '' if i['target'] is None else hex(i['target'])} for i in ins]
    return label, instructions


def check_descriptors(rows):
    found = {row['index']: row['text'] for row in rows}
    if len(found) != len(rows) or found != EXPECTED_DESCRIPTORS:
        raise ValueError('selected descriptor text or index changed')


def derived_constants(view):
    """Extract bounded selector constants only after their encodings are fixed."""
    mask = struct.unpack('<I', require(view, 'mask', 0x2586dfc, bytes.fromhex('b900603c80'))[1:])[0]
    upper = require(view, 'name bound', 0x2586df7, bytes.fromhex('83f81f'))[-1]
    flag_mask = require(view, 'filter flag', 0x24c1498, bytes.fromhex('f6042401'))[-1]
    key_offset = require(view, 'key offset', 0x24c145c, bytes.fromhex('4983c55c'))[-1]
    threshold_back = require(view, 'threshold offset', 0x24c1470, bytes.fromhex('493955e4'))[-1]
    threshold_offset = key_offset + int.from_bytes(bytes([threshold_back]), 'little', signed=True)
    stride = require(view, 'stride', 0x257ee19, bytes.fromhex('bb78000000'))
    stride = struct.unpack_from('<I', stride, 1)[0]
    allocation = require(view, 'initial allocation', 0x257ed79, bytes.fromhex('bfe0010000'))
    allocation = struct.unpack_from('<I', allocation, 1)[0]
    capacity = require(view, 'initial capacity', 0x257edea, bytes.fromhex('48c7042404000000'))
    capacity = struct.unpack_from('<I', capacity, 4)[0]
    sentinel = require(view, 'iterator sentinel', 0x257ed51, bytes.fromhex('837c244803'))[-1]
    lock_step = require(view, 'fast-lock step', 0x27d5dc4, bytes.fromhex('488d4810'))[-1]
    contention_bit = require(view, 'lock bit', 0x27d5da1, bytes.fromhex('83e108'))[-1]
    lock_limit_byte = require(view, 'lock bound', 0x27d5da7, bytes.fromhex('4883f8f0'))[-1]
    lock_limit = int.from_bytes(bytes([lock_limit_byte]), 'little', signed=True) % (1 << 64)
    release_mask_byte = require(view, 'lock release mask', 0x27d5ea5, bytes.fromhex('4883e0f2'))[-1]
    release_mask = int.from_bytes(bytes([release_mask_byte]), 'little', signed=True) % (1 << 64)
    wake_match = require(view, 'lock wake compare', 0x27d5ea9, bytes.fromhex('4883f812'))[-1]
    extra_flag_load = require(view, 'extra flag load', 0x2586da0, bytes.fromhex('440fb69288050000'))
    extra_flag_offset = struct.unpack_from('<I', extra_flag_load, 4)[0]
    optional_arg = require(view, 'optional call argument', 0x27d5f59, bytes.fromhex('bf32000000'))
    optional_argument = struct.unpack_from('<I', optional_arg, 1)[0]
    cleanup_tag_bound = require(view, 'row cleanup tag', 0x250c2cf, bytes.fromhex('833b02'))[-1]
    cleanup_blob_length_offset = require(view, 'row cleanup length', 0x250c2ba, bytes.fromhex('488b7720'))[-1]
    cleanup_blob_pointer_offset = require(view, 'row cleanup pointer', 0x250c2c3, bytes.fromhex('488b7b28'))[-1]
    threshold_va = 0x20aab8
    raw = view.read(threshold_va, 8)
    time_limit = struct.unpack('<d', raw)[0]
    if flag_mask != 1 or key_offset != 0x5c or threshold_offset != 0x40:
        raise ValueError('unexpected record selector layout')
    if not 0 <= upper < 32 or allocation != capacity * stride or time_limit != 3.0:
        raise ValueError('selector constants do not fit observed layout')
    admitted = [i for i in range(upper + 1) if mask & (1 << i)]
    return {'name_mask': mask, 'name_upper_bound': upper, 'admitted_names': admitted,
            'filter_flag_mask': flag_mask, 'key_offset': key_offset, 'key_length': 16 + 4,
            'threshold_offset': threshold_offset, 'record_stride': stride,
            'initial_capacity': capacity, 'initial_allocation_bytes': allocation,
            'end_sentinel': sentinel, 'lock_step': lock_step,
            'lock_contention_bit': contention_bit, 'lock_slow_limit': lock_limit,
            'lock_release_mask': release_mask, 'lock_wake_match': wake_match,
            'extra_flag_offset': extra_flag_offset, 'optional_helper_argument': optional_argument,
            'cleanup_tag_bound': cleanup_tag_bound,
            'cleanup_blob_length_offset': cleanup_blob_length_offset,
            'cleanup_blob_pointer_offset': cleanup_blob_pointer_offset,
            'time_limit_va': threshold_va,
            'time_limit_bytes': raw.hex(), 'time_limit': time_limit}


def gate_reaches_invocation_word(name_byte, total, constants):
    """Transfer of the ordered-float and name-bit branches, assuming normal returns."""
    if type(name_byte) is not int or not 0 <= name_byte <= 255:
        raise ValueError('name must be a byte')
    return (not math.isnan(total) and total > constants['time_limit'] and
            name_byte <= constants['name_upper_bound'] and
            bool(constants['name_mask'] & (1 << name_byte)))


def optional_helper_argument(flag, constants):
    """Model only the byte flag and immediate argument, not the helper."""
    if type(flag) is not int or not 0 <= flag <= 255:
        raise ValueError('extra flag must be a byte')
    return constants['optional_helper_argument'] if flag else None


def lock_acquisition(old, cmpxchg_succeeds, constants):
    """Model the local fast/slow edge; the external slow helper is not simulated."""
    if type(old) is not int or not 0 <= old < (1 << 64) or type(cmpxchg_succeeds) is not bool:
        raise ValueError('invalid lock input')
    if old & constants['lock_contention_bit'] or old >= constants['lock_slow_limit']:
        return 'slow', None
    if not cmpxchg_succeeds:
        return 'slow', None  # The competing write and slow helper are not modeled.
    return 'fast', old + constants['lock_step']


def lock_release(old, constants):
    """Model xadd and the wake edge from the pre-release value."""
    if type(old) is not int or not 0 <= old < (1 << 64):
        raise ValueError('invalid lock input')
    new = (old - constants['lock_step']) % (1 << 64)
    return new, (old & constants['lock_release_mask']) == constants['lock_wake_match']


def cleanup_row_paths(tag, allocation_length, constants):
    """Model two local guards; nested and allocator helpers are not simulated."""
    if (type(tag) is not int or not 0 <= tag < (1 << 64) or
            type(allocation_length) is not int or not 0 <= allocation_length < (1 << 64)):
        raise ValueError('invalid synthetic row cleanup input')
    return allocation_length != 0, (tag & 0xffffffff) >= constants['cleanup_tag_bound']


def cleanup_vector_backing(capacity, constants):
    """Model the zero-capacity guard and the machine-width size product."""
    if type(capacity) is not int or not 0 <= capacity < (1 << 64):
        raise ValueError('invalid synthetic vector capacity')
    return capacity != 0, (capacity * constants['record_stride']) % (1 << 64)


def select_record(records, start, flag, key, threshold, constants):
    """Static selector model over synthetic fixed-size rows, not target execution."""
    stride, width = constants['record_stride'], constants['key_length']
    if (type(start) is not int or start < 0 or start > len(records) or
            type(flag) is not int or not 0 <= flag <= 255 or
            not isinstance(key, (bytes, bytearray)) or len(key) != width or
            type(threshold) is not int or not 0 <= threshold < (1 << 64)):
        raise ValueError('invalid synthetic selector input')
    for row in records:
        if not isinstance(row, (bytes, bytearray)) or len(row) != stride:
            raise ValueError('invalid synthetic row size')
    for index in range(start, len(records)):
        row = records[index]
        if flag & constants['filter_flag_mask']:
            keep = row[constants['key_offset']:constants['key_offset'] + width] == key
        else:
            value = struct.unpack_from('<Q', row, constants['threshold_offset'])[0]
            keep = value >= threshold
        if keep:
            return index, index + 1
    return None, len(records)


def collect_synthetic(records, start, flag, key, threshold, constants):
    """Model selection/cursor/end-tag only, assuming row cloning returns normally."""
    selected = []
    cursor = start
    while True:
        index, cursor = select_record(records, cursor, flag, key, threshold, constants)
        if index is None:
            return selected, cursor, 'exhausted'
        # The caller compares only the low dword of the produced row's tag.
        tag = struct.unpack_from('<I', records[index], 0)[0]
        if tag == constants['end_sentinel']:
            return selected, cursor, 'selected_sentinel'
        selected.append(index)


def checked_flow(decodes):
    # A normal-flow graph over-approximates branch conditions and calls as returning.
    checks = (
        ('query_call_precedes_config_load', 'query_wrapper', 0x2586d80, 0x2586de3, (0x2586db0,), False),
        ('config_path_does_not_repeat_query', 'query_wrapper', 0x2586de3, 0x2586db0, (), False),
        ('short_duration_bypasses_config', 'query_wrapper', 0x2586de1, 0x2586e10, (0x2586de3,), True),
        ('name_gate_can_touch_second_once', 'query_wrapper', 0x2586df2, 0x2586e06, (0x2586e10,), True),
        ('name_gate_can_bypass_second_once', 'query_wrapper', 0x2586df2, 0x2586e10, (0x2586e06,), True),
        ('normal_return_passes_result_copy', 'query_wrapper', 0x2586de1, 0x2586e2b, (0x2586e1e,), False),
        ('config_once_returns_to_name_load', 'query_wrapper', 0x2586e54, 0x2586df2, (), True),
        ('invocation_once_returns_to_result', 'query_wrapper', 0x2586e8e, 0x2586e10, (), True),
        ('key_match_without_threshold_compare', 'select_next', 0x24c149e, 0x24c14ce, (0x24c1470, 0x24c1476), True),
        ('flag_clear_to_threshold', 'select_next', 0x24c149c, 0x24c1470, (0x24c149e,), True),
        ('key_mismatch_rescans', 'select_next', 0x24c14cc, 0x24c1486, (0x24c14ce,), True),
        ('advance_precedes_row_allocation', 'select_next', 0x24c14ce, 0x24c14e5, (0x24c14d2,), False),
        ('empty_skips_vector_allocation', 'collect_records', 0x257ed51, 0x257ef13, (0x257ed79,), True),
        ('nonempty_reaches_allocation', 'collect_records', 0x257ed56, 0x257ed7e, (0x257ed58,), True),
        ('capacity_can_skip_grow', 'collect_records', 0x257eecf, 0x257ee40, (0x257eeef,), True),
        ('grow_rejoins_copy', 'collect_records', 0x257eeef, 0x257ee40, (), True),
        ('normal_result_releases_lock', 'locked_query', 0x27d5e8f, 0x27d5f84, (0x27d5ea0,), False),
        ('wake_can_be_bypassed', 'locked_query', 0x27d5ea9, 0x27d5f84, (0x27d5f9c,), True),
        ('first_difference_can_skip_conversion', 'locked_query', 0x27d5e0b, 0x27d5e55, (0x27d5e1c,), True),
        ('second_difference_can_skip_conversion', 'locked_query', 0x27d5eee, 0x27d5f2f, (0x27d5ef9,), True),
        ('optional_call_can_be_bypassed', 'locked_query', 0x27d5f55, 0x27d5f84, (0x27d5f5e,), True),
        ('optional_call_can_be_taken', 'locked_query', 0x27d5f55, 0x27d5f5e, (0x27d5f64,), True),
        ('release_precedes_optional_call', 'locked_query', 0x27d5e8f, 0x27d5f5e, (0x27d5ea0,), False),
        ('row_empty_allocation_skips_release', 'cleanup_row', 0x250c2ba, 0x250c2cf, (0x250c2c9,), True),
        ('row_small_tag_skips_nested_walk', 'cleanup_row', 0x250c2cf, 0x250c34a, (0x250c336,), True),
        ('vector_zero_length_reaches_capacity_check', 'cleanup_vector', 0x250f0f2, 0x250f40f, (0x250f15c,), True),
        ('vector_zero_capacity_can_return', 'cleanup_vector', 0x250f40f, 0x250f448, (0x250f431,), True),
        ('vector_backing_release_needs_size', 'cleanup_vector', 0x250f40f, 0x250f431, (0x250f417,), False),
        ('unwind_cleanup_can_visit_remaining_row', 'cleanup_vector', 0x250f469, 0x250f47c, (), True),
    )
    rows = []
    for name, function, source, target, forbidden, expected in checks:
        actual = reachable(decodes[function], source, target, forbidden)
        if actual != expected:
            raise ValueError(f'normal CFG proposition changed: {name}')
        rows.append({'proposition': name, 'function': function, 'source': hex(source),
                     'target': hex(target), 'forbidden': ','.join(hex(x) for x in forbidden),
                     'reachable': int(actual)})
    return rows


def checked_failure_routes(lsda_rows):
    # Selected call sites and expected LPD destinations are checked against
    # the full call-site tables, not inferred from adjacent machine code.
    sites = (
        ('wrapper_to_locked_query', 0x2586d80, 0x2586db0, None),
        ('config_initialization', 0x2586d80, 0x2586e54, 0x2586e99),
        ('invocation_initialization', 0x2586d80, 0x2586e8e, 0x2586e99),
        ('locked_collector', 0x27d5d60, 0x27d5e8f, 0x27d5fbc),
        ('optional_helper', 0x27d5d60, 0x27d5f5e, 0x27d5fa7),
        ('first_next', 0x257ed30, 0x257ed4c, None),
        ('vector_allocation_failure', 0x257ed30, 0x257ef32, 0x257ef3a),
        ('next_after_allocation', 0x257ed30, 0x257eec0, 0x257ef61),
        ('vector_growth', 0x257ed30, 0x257eeef, 0x257ef49),
        ('row_allocation', 0x24c1430, 0x24c14e5, None),
        ('nested_clone', 0x24c1430, 0x24c1557, 0x24c161b),
        ('nested_pointer_panic', 0x24c1430, 0x24c1605, 0x24c161b),
        ('vector_nested_step', 0x250f0d0, 0x250f2ab, 0x250f467),
        ('vector_cleanup_panic', 0x250f0d0, 0x250f45f, 0x250f469),
        ('remaining_row_cleanup', 0x250f0d0, 0x250f47c, 0x250f4ab),
    )
    result = []
    for label, function, site, expected in sites:
        matches = [r for r in lsda_rows if int(r['function'], 16) == function and
                   int(r['start_va'], 16) <= site < int(r['end_va'], 16)]
        if len(matches) != 1:
            raise ValueError(f'LSDA site missing or ambiguous: {label}')
        row = matches[0]
        landing = int(row['landing_va'], 16) if row['landing_va'] else None
        if landing != expected:
            raise ValueError(f'LSDA landing changed: {label}')
        result.append({'boundary': label, 'function': hex(function), 'call_site': hex(site),
                       'start': row['start_va'], 'end_exclusive': row['end_va'],
                       'landing': row['landing_va'], 'action_index': row['action_index']})
    return result

JCC = ('jo', 'jno', 'jb', 'jae', 'je', 'jne', 'jbe', 'ja',
       'js', 'jns', 'jp', 'jnp', 'jl', 'jge', 'jle', 'jg')


def branch_name(ins):
    if ins['kind'] == 'jump':
        return 'jmp'
    op, op2 = ins['opcode']
    if ins['kind'] != 'conditional':
        raise ValueError('not a direct conditional branch')
    nibble = (op2 if op == 0x0f else op) & 15
    return JCC[nibble]


def tsv(path, rows, columns):
    with path.open('w', encoding='utf-8', newline='') as out:
        writer = csv.DictWriter(out, columns, delimiter='\t', lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)


def scenario_rows(constants):
    width, stride = constants['key_length'], constants['record_stride']
    key_a, key_b = bytes([0x41]) * width, bytes([0x41]) * (width - 1) + b'B'

    def row(key, value, tag=0):
        data = bytearray(stride)
        struct.pack_into('<Q', data, 0, tag)
        data[constants['key_offset']:constants['key_offset'] + width] = key
        struct.pack_into('<Q', data, constants['threshold_offset'], value)
        return bytes(data)

    a1, a5, b9 = row(key_a, 1), row(key_a, 5), row(key_b, 9)
    cases = (
        ('empty', (), 0, 0, key_a, 5),
        ('threshold_equal', (a1, a5, b9), 0, 0, key_a, 5),
        ('threshold_exhausted', (a1, a5), 0, 0, key_a, 6),
        ('key_overrides_threshold', (a1, b9), 0, 1, key_a, 99),
        ('key_mismatch_ignores_threshold', (a5, b9), 0, 1, key_b, 0),
        ('twentieth_byte_mismatch', (a5, b9), 0, 1, key_b, 99),
        ('other_flag_bit_uses_threshold', (a1, b9), 0, 2, key_a, 5),
        ('start_after_first', (a5, b9), 1, 0, key_a, 5),
        ('unsigned_upper_half', (row(key_a, 1 << 63),), 0, 0, key_a, (1 << 63) - 1),
        ('matched_sentinel', (row(key_a, 5, 3), row(key_a, 6)), 0, 1, key_a, 0),
        ('matched_sentinel_high_word', (row(key_a, 5, (1 << 32) + 3), row(key_a, 6)), 0, 1, key_a, 0),
    )
    rows = []
    for label, records, start, flag, key, threshold in cases:
        hit, cursor = select_record(records, start, flag, key, threshold, constants)
        collected, final_cursor, stop = collect_synthetic(records, start, flag, key, threshold, constants)
        rows.append({'scenario': label, 'synthetic_input_rows': len(records), 'start_index': start,
                     'flag': flag, 'threshold': threshold,
                     'key_bytes': key.hex(), 'row_bytes': ','.join(r.hex() for r in records),
                     'selected_index': '' if hit is None else hit,
                     'next_index': cursor, 'collected_indices': ','.join(str(i) for i in collected),
                     'final_index': final_cursor, 'stop': stop})
    return rows


def collect(data):
    verify_identity(data)
    view = View(data)
    _, fdes = eh_frame_records(data, view.sections)
    label, handoff = handoff_context(view, fdes)
    grouped = {}
    for fde in fdes:
        grouped.setdefault(fde['start'], []).append(fde)
    functions, decodes, lsda_rows, lsda_headers = [], {}, [], []
    for name, start, end, digest in FUNCTIONS:
        matching = grouped.get(start, [])
        if len(matching) != 1 or matching[0]['end'] != end:
            raise ValueError(f'selected FDE missing, duplicated or resized: {name}')
        fde = matching[0]
        raw = view.read(start, end - start)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError(f'selected body hash mismatch: {name}')
        section = next((s for s in view.sections if s['type'] != 8 and s['flags'] & 4 and
                        s['address'] <= start and end <= s['address'] + s['size']), None)
        if section is None:
            raise ValueError('selected FDE is not executable file-backed bytes')
        body = decode_body(raw, start)
        decodes[name] = body
        if fde['lsda'] is None:
            if name != 'cleanup_row':
                raise ValueError('selected FDE unexpectedly lacks an LSDA')
        else:
            if name == 'cleanup_row':
                raise ValueError('row cleanup unexpectedly has an LSDA')
            header, records = parse_lsda(view, start, end, fde['lsda'])
            inst_starts = {i['va'] for i in body}
            for record in records:
                if record['landing_va'] and int(record['landing_va'], 16) not in inst_starts:
                    raise ValueError('LSDA landing is not a decoded instruction')
            lsda_headers.append(header)
            lsda_rows.extend(records)
        functions.append({'name': name, 'start': hex(start), 'end_exclusive': hex(end),
                          'file_offset': hex(view.offset(start, end - start)), 'size': len(raw),
                          'fde': hex(fde['fde']), 'lsda': hex(fde['lsda']) if fde['lsda'] else '',
                          'sha256': hashlib.sha256(raw).hexdigest(), 'instructions': len(body)})
    contracts = collect_contracts(view, decodes)
    constants = derived_constants(view)

    table = 0x5668288
    default_context = 32  # Existing constants packet identifies this as the default.
    indices = constants['admitted_names'] + [default_context]
    if len(indices) != len(set(indices)):
        raise ValueError('default unexpectedly selected by this gate')
    desc_slots = [(i, table + 16 * i, i != default_context) for i in indices]
    known_slots = {0x576e928: 0x577b288, 0x576e8b8: 0x4ee3b20,
                   0x577ab80: 0x143ef30, 0x576f5e8: 0x4e0b770,
                   0x576f5f8: 0x4e0be20, 0x576e8f8: 0x13c9e20,
                   0x576dfd8: 0x54c06b0, 0x576dfb8: 0x1346068,
                   0x576e010: 0x54c8cb0, 0x576e470: 0x157a9f0,
                   0x576e128: 0x157b63b}
    slots = set(known_slots) | {slot for _, slot, _ in desc_slots}
    relocs = selected_relocations(view, slots)
    for slot, expected in known_slots.items():
        if int(relocs[slot]['addend'], 16) != expected:
            raise ValueError('selected relocation target changed')
    descriptors = ascii_descriptors(view, relocs, desc_slots)
    check_descriptors(descriptors)

    instructions, branches, calls = [], [], []
    for function, body in decodes.items():
        for ins in body:
            row = {'function': function, 'va': hex(ins['va']),
                   'file_offset': hex(view.offset(ins['va'], len(ins['bytes']))),
                   'bytes': ins['bytes'].hex(), 'kind': ins['kind'],
                   'target': '' if ins['target'] is None else hex(ins['target']),
                   'rip_relative': int(ins['rip_relative'])}
            instructions.append(row)
            if ins['kind'] in ('conditional', 'jump'):
                branches.append({'function': function, 'va': row['va'], 'bytes': row['bytes'],
                                 'condition': branch_name(ins), 'target': row['target'],
                                 'fallthrough': hex(ins['end']) if ins['kind'] == 'conditional' else ''})
            if ins['kind'] in ('call', 'indirect_call', 'indirect_jump'):
                target = ins['target']
                reloc = relocs.get(target, {})
                calls.append({'function': function, 'va': row['va'], 'bytes': row['bytes'],
                              'kind': ins['kind'], 'target_or_slot': row['target'],
                              'selected_rela_addend': reloc.get('addend', '')})
    flows = checked_flow(decodes)
    failures = checked_failure_routes(lsda_rows)
    scenarios = scenario_rows(constants)
    summaries = {'artifact_sha256': DIGEST, 'functions': len(functions),
                 'function_bytes': sum(x['size'] for x in functions),
                 'instructions': len(instructions), 'instruction_contracts': len(contracts),
                 'direct_branches': len(branches), 'calls_and_indirect_transfers': len(calls),
                 'selected_relocations': len(relocs), 'selected_descriptors': len(descriptors),
                 'lsda_entries': len(lsda_rows), 'normal_cfg_propositions': len(flows),
                 'selected_failure_boundaries': len(failures),
                 'handoff_instructions': len(handoff), 'bounded_handoff_label': label,
                 'synthetic_selector_cases': len(scenarios), 'constants': constants,
                 'limits': 'Static observations only. FDEs are unwind extents. CFG paths assume calls return and do not prove feasibility. Synthetic cases are not node executions.'}
    return {'summary': summaries, 'functions': functions, 'instructions': instructions,
            'branches': branches, 'calls': calls, 'contracts': contracts,
            'descriptors': descriptors, 'relocations': [relocs[k] for k in sorted(relocs)],
            'lsda_headers': lsda_headers, 'lsda': lsda_rows, 'cfg': flows,
            'handoff': handoff,
            'failure_routes': failures,
            'synthetic_cases': scenarios}


def generate(data, out):
    results = collect(data)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    tables = {
        'functions.tsv': ('functions', ('name', 'start', 'end_exclusive', 'file_offset', 'size', 'fde', 'lsda', 'sha256', 'instructions')),
        'instructions.tsv': ('instructions', ('function', 'va', 'file_offset', 'bytes', 'kind', 'target', 'rip_relative')),
        'handoff.tsv': ('handoff', ('va', 'file_offset', 'bytes', 'kind', 'target')),
        'branches.tsv': ('branches', ('function', 'va', 'bytes', 'condition', 'target', 'fallthrough')),
        'calls.tsv': ('calls', ('function', 'va', 'bytes', 'kind', 'target_or_slot', 'selected_rela_addend')),
        'contracts.tsv': ('contracts', ('label', 'va', 'file_offset', 'bytes')),
        'descriptors.tsv': ('descriptors', ('index', 'slot', 'slot_file_offset', 'relocation_offset', 'text_va', 'text_file_offset', 'length', 'bytes', 'text', 'selected_by_gate')),
        'relocations.tsv': ('relocations', ('slot', 'record_offset', 'type', 'symbol', 'addend')),
        'lsda.tsv': ('lsda', ('function', 'lsda_va', 'entry_file_offset', 'start_va', 'end_va', 'landing_va', 'action_index')),
        'cfg.tsv': ('cfg', ('proposition', 'function', 'source', 'target', 'forbidden', 'reachable')),
        'failure-routes.tsv': ('failure_routes', ('boundary', 'function', 'call_site', 'start', 'end_exclusive', 'landing', 'action_index')),
        'synthetic-cases.tsv': ('synthetic_cases', ('scenario', 'synthetic_input_rows', 'start_index', 'flag', 'threshold', 'key_bytes', 'row_bytes', 'selected_index', 'next_index', 'collected_indices', 'final_index', 'stop')),
    }
    for filename, (key, columns) in tables.items():
        tsv(out / filename, results[key], columns)
    (out / 'evidence.json').write_text(json.dumps({'summary': results['summary'],
        'lsda_headers': results['lsda_headers']}, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return results['summary']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = generate(TARGET.read_bytes(), args.out)
    except (OSError, ValueError, struct.error) as exc:
        parser.exit(1, f'error: {exc}\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
