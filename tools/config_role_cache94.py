#!/usr/bin/env python3
"""Recover selected node 94 role-cache and name-gate paths from static ELF bytes.

Instruction lengths and transfer targets use a fixed-scope decoder adapted from
RE-015 name-gated record-query research. It is not a general x86 decoder.
No captured executable or external program is run.
"""
import argparse
import csv
import hashlib
import itertools
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
    ('cache_insert', 0x1f851b0, 0x1f854dc, '1c39995ec8c7ffe93c79f0b1d4049e6a05b2eeeede10117b4beda9d74d7e17f7'),
    ('cache_lookup', 0x1f854e0, 0x1f85618, '543bb30cb04926d463b48d1b479ce327cb33eb25ae0b7dd2d4c6899970454f0e'),
    ('index_remove', 0x2047aa0, 0x2047c76, '8b6ac3a9665ebfe5c8827fc969c10f8f7536479d37d7bf8f685fc0082c406431'),
    ('index_insert', 0x2047c80, 0x2047ec3, 'd02ab5e37a49bcfc5c9923335f72f3c1182577fa1efdab9ef04121443b871a33'),
    ('role_wrapper', 0x25869c0, 0x2586adb, '658ef0b1e7a02e38fb524ec7726034498fa860a5d1cd854c424c368261c96947'),
    ('update_wrapper', 0x258ac60, 0x258ad73, '40dba4566919cdb0c12b0e05a178f18f1777f4642127f3b789b2bddfbb26f139'),
    ('role_select', 0x27cfdd0, 0x27d0428, 'bcab9a6b533d8868251ff63fb243d20ec287ee7f6ecc6ec8aa171f865dc66514'),
    ('cache_update', 0x27d2d90, 0x27d30a0, '62d354687bfe66ddeb0120fb6b4a122ab61c924605b169c319a167c9f69f76b2'),
    ('cache_peek', 0x27d5ac0, 0x27d5d57, '228620798cc22fabaaa142543ed1de2e6ac7b4a050a98f7c2c2fe3e5b1902d68'),
    ('agent_data_helper', 0x29fb8b0, 0x29fbae1, 'cf6571929e0ca5e37e7cb323c5f276e023fe1db429660e5ec6967d8fb046f6be'),
    ('role_field_helper', 0x29fbd30, 0x29fbf4c, '6060ae175e24681dc4181532d4eaeb5e45cab0820d2836ee6002d7c8542343fa'),
    ('subaccount_data_helper', 0x2a04fb0, 0x2a051e1, 'ad13a9fd6531659ac783d1cac7a825d0769449bcb95ebbab48445769cdee59b6'),
    ('role_descriptor_writer', 0x2a287e0, 0x2a28bb2, '6dac56b03ada3b1cc4bf50a867793de1adb2374e85399b3184369ec6676e128a'),
    ('subaccount_nested_writer', 0x2a28bc0, 0x2a28cea, 'e5777b5174fe413ff691f8322cc885e36f1cfa601dcbaaee23f6b8d3121a1cb5'),
    ('agent_nested_writer', 0x2a28cf0, 0x2a28e1a, '6c11bc23bdb6e882012e6a97732a28a904e8813b670e3b8725715063329485df'),
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
            raise ValueError('negative address or nonpositive size')
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
                      0x60, 0x62, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x72, 0x73, 0x74, 0x76, 0x7e, 0x7f, 0xa3, 0xaf, 0xb6, 0xb7,
                      0xb0, 0xb1, 0xbc, 0xbd, 0xbe, 0xbf, 0xc1, 0xd6, 0xd7, 0xdb, 0xdf, 0xe6, 0xeb, 0xef)
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
        if op == 0x0f and op2 in (0x70, 0x72, 0x73):
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




# Selected complete instruction bytes: semantic labels are independent interpretations.
CONTRACTS = (
    ('insert_load_count', 0x1f851c9, '4c8b6e18'),
    ('insert_count_zero', 0x1f851cd, '4d85ed'),
    ('insert_count_nonzero', 0x1f851d0, '0f8580000000'),
    ('insert_capacity_cmp', 0x1f851e8, '4d3b6e28'),
    ('insert_not_full', 0x1f851ec, '0f852f020000'),
    ('insert_tail_sentinel', 0x1f851f2, '498b4638'),
    ('insert_tail_previous', 0x1f851f6, '488b7030'),
    ('insert_tail_key', 0x1f851fa, '4883c640'),
    ('insert_remove_tail', 0x1f85201, 'e89a280c00'),
    ('insert_remove_test', 0x1f85206, '4885c0'),
    ('insert_missing_tail', 0x1f85209, '0f84a6020000'),
    ('insert_reuse_key_last', 0x1f85213, '894850'),
    ('insert_reuse_key_first', 0x1f8521a, '0f114040'),
    ('insert_reuse_value_0', 0x1f8522f, 'f30f7f00'),
    ('insert_reuse_value_1', 0x1f85233, 'f30f7f4810'),
    ('insert_reuse_value_2', 0x1f85238, 'f30f7f5020'),
    ('insert_reuse_unlink_next', 0x1f85245, '48895138'),
    ('insert_reuse_unlink_prev', 0x1f8524d, '48894a30'),
    ('insert_hash_key_length', 0x1f85265, 'be14000000'),
    ('insert_hash_call', 0x1f8526d, 'ff157db77e03'),
    ('insert_match_bytes', 0x1f8530c, '4181fbffff0000'),
    ('insert_match_branch', 0x1f85313, '7438'),
    ('insert_found_node', 0x1f85354, '4a8b4401f8'),
    ('insert_swap_value_0_old', 0x1f85359, '0f1000'),
    ('insert_swap_value_0_new', 0x1f85364, '0f1108'),
    ('insert_swap_value_1_new', 0x1f85375, '0f114810'),
    ('insert_swap_value_2_new', 0x1f85387, '0f114820'),
    ('insert_existing_unlink_next', 0x1f85393, '48895138'),
    ('insert_existing_unlink_prev', 0x1f8539b, '48894a30'),
    ('insert_existing_link_next', 0x1f853af, '48894138'),
    ('insert_existing_link_prev', 0x1f853b7, '48894130'),
    ('insert_new_allocation_size', 0x1f85421, 'bf58000000'),
    ('insert_new_alloc_call', 0x1f85426, 'ff15ac8b7e03'),
    ('insert_new_alloc_failure', 0x1f8542f, '7474'),
    ('insert_new_key_first', 0x1f8545b, 'f30f7f4040'),
    ('insert_new_key_last', 0x1f85465, '894850'),
    ('insert_new_link_next', 0x1f85478, '48894138'),
    ('insert_new_link_prev', 0x1f85480, '48894130'),
    ('insert_new_index_call', 0x1f8548e, 'e8ed270c00'),
    ('insert_no_old_tag', 0x1f85493, 'c6432c05'),
    ('insert_allocation_error', 0x1f854af, 'ff156b8b7e03'),
    ('insert_missing_node_error', 0x1f854bc, 'ff15ae8f7e03'),
    ('lookup_count_zero', 0x1f854e4, '48837f1800'),
    ('lookup_nonempty', 0x1f854e9, '7507'),
    ('lookup_empty_zero', 0x1f854eb, '31c0'),
    ('lookup_hash_key_length', 0x1f85504, 'be14000000'),
    ('lookup_hash_call', 0x1f85512, 'ff15d8b47e03'),
    ('lookup_match_cmp', 0x1f855b1, '81fdffff0000'),
    ('lookup_match_branch', 0x1f855b7, '7434'),
    ('lookup_empty_control_exit', 0x1f855c7, '0f851effffff'),
    ('lookup_node_pointer', 0x1f855f4, '4a8b4409f8'),
    ('lookup_overflow_error', 0x1f85605, 'ff150d8b7e03'),
    ('remove_hash_key_length', 0x2047abc, 'be14000000'),
    ('remove_match_cmp', 0x2047b63, '81fdffff0000'),
    ('remove_match_branch', 0x2047b69, '7436'),
    ('remove_distance_calc', 0x2047bde, '4401c7'),
    ('remove_tombstone', 0x2047be1, 'b180'),
    ('remove_distance_limit', 0x2047be3, '6683ff0f'),
    ('remove_distance_branch', 0x2047be7, '7713'),
    ('remove_growth_counter', 0x2047be9, '488b4b10'),
    ('remove_counter_overflow', 0x2047bf1, '7469'),
    ('remove_counter_inc', 0x2047bf6, '48894b10'),
    ('remove_empty_marker', 0x2047bfa, 'b1ff'),
    ('remove_control_primary', 0x2047c02, '880c32'),
    ('remove_control_mirror', 0x2047c05, '884c0210'),
    ('remove_length_zero', 0x2047c0d, '4885c0'),
    ('remove_length_failure', 0x2047c10, '743d'),
    ('remove_length_dec', 0x2047c1c, '48ffc8'),
    ('remove_length_store', 0x2047c1f, '48894318'),
    ('remove_node_pointer', 0x2047c23, '488b4af8'),
    ('index_key_length', 0x2047ca3, 'be14000000'),
    ('index_growth_zero', 0x2047cb1, '49837f1000'),
    ('index_growth_branch', 0x2047cb6, '0f8482010000'),
    ('index_key_match_cmp', 0x2047d5b, '4181fdffff0000'),
    ('index_key_match_branch', 0x2047d62, '745d'),
    ('index_replace_pointer', 0x2047dc8, '4a895c19f8'),
    ('index_free_growth_sub', 0x2047dee, '4c29c0'),
    ('index_growth_underflow', 0x2047df1, '0f8298000000'),
    ('index_growth_store', 0x2047df7, '49894710'),
    ('index_control_primary', 0x2047e0c, '881439'),
    ('index_control_mirror', 0x2047e0f, '88540110'),
    ('index_count_overflow', 0x2047e1b, '0f8488000000'),
    ('index_count_increment', 0x2047e21, '48ffc0'),
    ('index_count_store', 0x2047e24, '49894718'),
    ('index_key_pointer_store', 0x2047e38, '4c8970f0'),
    ('index_growth_call', 0x2047e52, 'ff1510b87203'),
    ('role_wrapper_call', 0x2586a05, 'e8c6932400'),
    ('role_wrapper_sum', 0x2586a1e, 'f20f584c2430'),
    ('role_wrapper_threshold', 0x2586a27, '660f2e0d8940c8fd'),
    ('role_wrapper_threshold_branch', 0x2586a2f, '762d'),
    ('role_wrapper_global_slot', 0x2586a31, '4c8b3df07e1e03'),
    ('role_wrapper_state_load', 0x2586a38, '418b4750'),
    ('role_wrapper_name_byte', 0x2586a40, '410fb64748'),
    ('role_wrapper_name_limit', 0x2586a45, '83f81f'),
    ('role_wrapper_name_reject', 0x2586a48, '7714'),
    ('role_wrapper_mask', 0x2586a4a, 'b900603c80'),
    ('role_wrapper_bit_test', 0x2586a4f, '0fa3c1'),
    ('role_wrapper_mask_reject', 0x2586a52, '730a'),
    ('role_wrapper_second_state', 0x2586a54, '8b053e411f03'),
    ('role_wrapper_second_once_branch', 0x2586a5c, '7545'),
    ('update_wrapper_call', 0x258ac89, 'e802812400'),
    ('update_wrapper_copy_0', 0x258acb1, '0f1103'),
    ('update_wrapper_threshold', 0x258acb4, '660f2e0dfcfdc7fd'),
    ('update_wrapper_threshold_branch', 0x258acbc, '762d'),
    ('update_wrapper_global_slot', 0x258acbe, '4c8b35633c1e03'),
    ('update_wrapper_name_byte', 0x258accd, '410fb64648'),
    ('update_wrapper_name_limit', 0x258acd2, '83f81f'),
    ('update_wrapper_mask', 0x258acd7, 'b900603c80'),
    ('update_wrapper_bit_test', 0x258acdc, '0fa3c1'),
    ('role_first_count', 0x27cfea9, '4983be3847000000'),
    ('role_first_skip', 0x27cfeb5, '0f84d3000000'),
    ('role_first_hash', 0x27cfec7, 'e8d4c81c01'),
    ('role_first_pointer', 0x27cfed3, '498b8e20470000'),
    ('role_first_compare', 0x27cff54, '4181faffff0000'),
    ('role_first_match', 0x27cff5b, '0f84f9000000'),
    ('role_tree_root', 0x27cff93, '4d8bb6c0180000'),
    ('role_tree_skip', 0x27cffa2, '0f84eb000000'),
    ('role_tree_key_length', 0x27cfff9, 'ba14000000'),
    ('role_tree_compare', 0x27d0003, '41ffd7'),
    ('role_tree_equal', 0x27d0028, 'eb52'),
    ('role_tree_depth', 0x27d0042, '4883ed01'),
    ('role_tree_child', 0x27d004d, '4d8bb4de78080000'),
    ('role_tag_2', 0x27d0074, '41b602'),
    ('role_tag_3', 0x27d007c, '41b603'),
    ('role_second_count', 0x27d00ac, '4883bb1848000000'),
    ('role_second_skip', 0x27d00b9, '0f84d1000000'),
    ('role_second_pointer', 0x27d00d7, '488b8b00480000'),
    ('role_second_compare', 0x27d0158, '4181faffff0000'),
    ('role_second_match', 0x27d015f, '0f840c010000'),
    ('role_last_count', 0x27d0190, '4883bb4817000000'),
    ('role_last_skip', 0x27d0198, '0f84f2000000'),
    ('role_last_pointer', 0x27d01b6, '488b8b30170000'),
    ('role_tag_1', 0x27d023a, '41b601'),
    ('role_last_compare', 0x27d023d, '4181f9ffff0000'),
    ('role_last_match', 0x27d0244, '744d'),
    ('role_tag_4', 0x27d028b, '41b604'),
    ('role_tag_0', 0x27d0290, '4531f6'),
    ('role_unlock_xadd', 0x27d029a, 'f0490fc10424'),
    ('role_unlock_mask', 0x27d02a8, '4883e0f2'),
    ('role_unlock_compare', 0x27d02ac, '4883f812'),
    ('role_unlock_wake', 0x27d02b0, '0f8402010000'),
    ('role_store_tag', 0x27d0387, '45887710'),
    ('role_store_payload_first', 0x27d0393, '410f114711'),
    ('role_store_payload_last', 0x27d039f, '41894721'),
    ('role_unwind_unlock', 0x27d03cd, 'f0490fc10c24'),
    ('update_lock_address', 0x27d2dbb, '498d842468050000'),
    ('update_lock_cmpxchg', 0x27d2dce, 'f0490fb18c2468050000'),
    ('update_lock_slow', 0x27d2dd8, '0f8547020000'),
    ('update_seq_increment', 0x27d2e72, '48ffc0'),
    ('update_seq_max', 0x27d2e75, '48c7c1ffffffff'),
    ('update_seq_saturate', 0x27d2e7c, '480f45c8'),
    ('update_map_offset', 0x27d2e80, '4981c470050000'),
    ('update_insert_call', 0x27d2ea1, 'e80a237bff'),
    ('update_return_tag', 0x27d2eaf, '4180fd05'),
    ('update_no_old_branch', 0x27d2eb3, '743b'),
    ('update_unlock_cmpxchg', 0x27d2f04, 'f0480fb10f'),
    ('update_unlock_slow', 0x27d2f09, '0f852a010000'),
    ('update_return_store_tag', 0x27d2fdf, '44886b14'),
    ('update_lock_slow_call', 0x27d302e, 'ff15ccc5f902'),
    ('update_unlock_slow_call', 0x27d303b, 'ff15c7c5f902'),
    ('update_unwind_unlock', 0x27d3054, 'f0480fb10a'),
    ('peek_lock_cmpxchg', 0x27d5b23, 'f0490fb10f'),
    ('peek_lookup_offset', 0x27d5b76, '4981c570050000'),
    ('peek_lookup_call', 0x27d5b85, 'e856f97aff'),
    ('peek_null_test', 0x27d5b8a, '4885c0'),
    ('peek_null_branch', 0x27d5b8d, '7428'),
    ('peek_hit_tag', 0x27d5b9e, '440fb67014'),
    ('peek_missing_tag', 0x27d5bb7, '41b605'),
    ('peek_unlock_xadd', 0x27d5bc5, 'f0480fc107'),
    ('peek_unlock_mask', 0x27d5bd3, '4883e0f2'),
    ('peek_unlock_wake', 0x27d5bdb, '0f8405010000'),
    ('peek_store_tag', 0x27d5ca6, '44887314'),
    ('peek_unwind_unlock', 0x27d5cfc, 'f0480fc10a'),
    ('agent_data_state_compare', 0x29fb8c5, '483b07'),
    ('agent_data_state_branch', 0x29fb8c8, '0f8090010000'),
    ('agent_data_alloc_call', 0x29fb8ec, 'ff15e626d702'),
    ('agent_data_alloc_null_test', 0x29fb8f2, '4885c0'),
    ('agent_data_alloc_failure_branch', 0x29fb8f5, '0f84b8010000'),
    ('agent_data_copy_call', 0x29fb919, 'ff15c126d702'),
    ('agent_data_old_length', 0x29fb91f, '498b7648'),
    ('agent_data_old_value_compare', 0x29fb923, '4c39ee'),
    ('agent_data_old_value_branch', 0x29fb926, '7411'),
    ('agent_data_old_value_empty_branch', 0x29fb92b, '740c'),
    ('agent_data_old_value_free', 0x29fb933, 'ff15d726d702'),
    ('agent_data_write_pointer', 0x29fb939, '4d896650'),
    ('agent_data_write_length', 0x29fb93d, '49895e58'),
    ('agent_data_write_capacity', 0x29fb941, '4d896e48'),
    ('agent_data_nested_call', 0x29fb963, 'e888d30200'),
    ('agent_data_nested_result_compare', 0x29fb96c, '4c396c2468'),
    ('agent_data_nested_result_branch', 0x29fb971, '7529'),
    ('agent_data_result_buffer_free', 0x29fb98e, 'ff157c26d702'),
    ('agent_data_success_continuation', 0x29fb9f9, 'e842e50300'),
    ('agent_data_result_drop', 0x29fba55, 'e8962cffff'),
    ('agent_data_alloc_failure', 0x29fbabb, 'ff15f724d702'),
    ('agent_data_unwind_free', 0x29fbad3, 'ff153725d702'),
    ('agent_data_resume', 0x29fbadc, 'e82f46c602'),
    ('subaccount_data_state_compare', 0x2a04fc5, '483b07'),
    ('subaccount_data_state_branch', 0x2a04fc8, '0f8090010000'),
    ('subaccount_data_alloc_call', 0x2a04fec, 'ff15e68fd602'),
    ('subaccount_data_alloc_null_test', 0x2a04ff2, '4885c0'),
    ('subaccount_data_alloc_failure_branch', 0x2a04ff5, '0f84b8010000'),
    ('subaccount_data_copy_call', 0x2a05019, 'ff15c18fd602'),
    ('subaccount_data_old_length', 0x2a0501f, '498b7648'),
    ('subaccount_data_old_value_compare', 0x2a05023, '4c39ee'),
    ('subaccount_data_old_value_branch', 0x2a05026, '7411'),
    ('subaccount_data_old_value_empty_branch', 0x2a0502b, '740c'),
    ('subaccount_data_old_value_free', 0x2a05033, 'ff15d78fd602'),
    ('subaccount_data_write_pointer', 0x2a05039, '4d896650'),
    ('subaccount_data_write_length', 0x2a0503d, '49895e58'),
    ('subaccount_data_write_capacity', 0x2a05041, '4d896e48'),
    ('subaccount_data_nested_call', 0x2a05063, 'e8583b0200'),
    ('subaccount_data_nested_result_compare', 0x2a0506c, '4c396c2468'),
    ('subaccount_data_nested_result_branch', 0x2a05071, '7529'),
    ('subaccount_data_result_buffer_free', 0x2a0508e, 'ff157c8fd602'),
    ('subaccount_data_success_continuation', 0x2a050f9, 'e8424e0300'),
    ('subaccount_data_result_drop', 0x2a05155, 'e89695feff'),
    ('subaccount_data_alloc_failure', 0x2a051bb, 'ff15f78dd602'),
    ('subaccount_data_unwind_free', 0x2a051d3, 'ff15378ed602'),
    ('subaccount_data_resume', 0x2a051dc, 'e82fafc502'),
    ('agent_nested_input_value', 0x2a28cff, '4c8b36'),
    ('agent_nested_initial_call', 0x2a28d04, 'e8d7884902'),
    ('agent_nested_initial_null_test', 0x2a28d09, '4885c0'),
    ('agent_nested_initial_failure_branch', 0x2a28d0c, '0f84e2000000'),
    ('agent_nested_key_pointer', 0x2a28d5e, '488d3557117efd'),
    ('agent_nested_key_length', 0x2a28d68, 'ba04000000'),
    ('agent_nested_field_call', 0x2a28d70, 'e8cbf7fcff'),
    ('agent_nested_field_result_test', 0x2a28d75, '4885c0'),
    ('agent_nested_field_result_branch', 0x2a28d78, '7415'),
    ('agent_nested_result_store', 0x2a28d7a, '48894308'),
    ('agent_nested_cleanup_call', 0x2a28d88, 'e803100000'),
    ('agent_nested_success_continuation', 0x2a28dde, 'ff150cc3d402'),
    ('agent_nested_initial_failure', 0x2a28dfb, 'ff15175bd402'),
    ('agent_nested_unwind_cleanup', 0x2a28e07, 'e8840f0000'),
    ('agent_nested_unwind_resume', 0x2a28e0f, 'e8fc72c302'),
    ('agent_nested_cleanup_failure', 0x2a28e14, 'ff150e53d402'),
    ('subaccount_nested_input_value', 0x2a28bcf, '4c8b36'),
    ('subaccount_nested_initial_call', 0x2a28bd4, 'e8078a4902'),
    ('subaccount_nested_initial_null_test', 0x2a28bd9, '4885c0'),
    ('subaccount_nested_initial_failure_branch', 0x2a28bdc, '0f84e2000000'),
    ('subaccount_nested_key_pointer', 0x2a28c2e, '488d35596f9ffd'),
    ('subaccount_nested_key_length', 0x2a28c38, 'ba06000000'),
    ('subaccount_nested_field_call', 0x2a28c40, 'e8fbf8fcff'),
    ('subaccount_nested_field_result_test', 0x2a28c45, '4885c0'),
    ('subaccount_nested_field_result_branch', 0x2a28c48, '7415'),
    ('subaccount_nested_result_store', 0x2a28c4a, '48894308'),
    ('subaccount_nested_cleanup_call', 0x2a28c58, 'e833110000'),
    ('subaccount_nested_success_continuation', 0x2a28cae, 'ff153cc4d402'),
    ('subaccount_nested_initial_failure', 0x2a28ccb, 'ff15475cd402'),
    ('subaccount_nested_unwind_cleanup', 0x2a28cd7, 'e8b4100000'),
    ('subaccount_nested_unwind_resume', 0x2a28cdf, 'e82c74c302'),
    ('subaccount_nested_cleanup_failure', 0x2a28ce4, 'ff153e54d402'),

)



# Descriptor-name field path and its selected failure boundaries.
CONTRACTS += (
    ('role_field_state_compare', 0x29fbd46, '483b07'),
    ('role_field_state_branch', 0x29fbd49, '0f806f010000'),
    ('role_field_key_length_test', 0x29fbd4f, '4885db'),
    ('role_field_key_negative_branch', 0x29fbd52, '790b'),
    ('role_field_key_size_failure', 0x29fbd59, 'ff155922d702'),
    ('role_field_key_empty_branch', 0x29fbd65, '741d'),
    ('role_field_key_allocate', 0x29fbd6d, 'ff156522d702'),
    ('role_field_key_alloc_test', 0x29fbd73, '4885c0'),
    ('role_field_key_alloc_failure', 0x29fbd76, '0f8498010000'),
    ('role_field_key_bytes_call', 0x29fbd9a, 'ff154022d702'),
    ('role_field_old_key_length', 0x29fbda0, '498b7648'),
    ('role_field_old_key_compare', 0x29fbda4, '4839ee'),
    ('role_field_old_key_skip_sentinel', 0x29fbda7, '7411'),
    ('role_field_old_key_skip_empty', 0x29fbdac, '740c'),
    ('role_field_old_key_free', 0x29fbdb4, 'ff155622d702'),
    ('role_field_new_key_pointer', 0x29fbdba, '4d896650'),
    ('role_field_new_key_length', 0x29fbdbe, '49895e58'),
    ('role_field_new_key_capacity', 0x29fbdc2, '49896e48'),
    ('role_field_variant_length', 0x29fbddd, '4d8b6718'),
    ('role_field_variant_length_test', 0x29fbde1, '4d85e4'),
    ('role_field_variant_negative_branch', 0x29fbde4, '790d'),
    ('role_field_variant_failure_call', 0x29fbdeb, 'ff15c721d702'),
    ('role_field_variant_failure_trap', 0x29fbdf1, '0f0b'),
    ('role_field_variant_pointer', 0x29fbdf3, '4d8b7f10'),
    ('role_field_variant_empty_branch', 0x29fbdf7, '7417'),
    ('role_field_variant_allocate', 0x29fbdfc, 'ff15d621d702'),
    ('role_field_variant_alloc_test', 0x29fbe02, '4885c0'),
    ('role_field_variant_alloc_failure', 0x29fbe05, '0f8417010000'),
    ('role_field_variant_empty_pointer', 0x29fbe10, '41bd01000000'),
    ('role_field_variant_bytes_call', 0x29fbe1f, 'ff15bb21d702'),
    ('role_field_object_call', 0x29fbe5e, 'e8dde00300'),
    ('role_field_object_result_compare', 0x29fbea9, '48396c2470'),
    ('role_field_object_result_branch', 0x29fbeae, '740a'),
    ('role_field_object_result_drop', 0x29fbeb5, 'e83628ffff'),
    ('role_field_result_zero', 0x29fbeba, '31c0'),
    ('role_field_state_fallback', 0x29fbebe, '4883fb1e'),
    ('role_field_state_fallback_length', 0x29fbec2, '7526'),
    ('role_field_state_fallback_call', 0x29fbefc, 'ff157e30d702'),
    ('role_field_key_alloc_failure_boundary', 0x29fbf1c, 'ff159620d702'),
    ('role_field_variant_alloc_failure_boundary', 0x29fbf22, 'bf01000000'),
    ('role_field_variant_alloc_failure_jump', 0x29fbf27, 'e9bcfeffff'),
    ('role_field_landing_entry', 0x29fbf2c, '4989c6'),
    ('role_field_landing_skip_free', 0x29fbf32, '7410'),
    ('role_field_landing_free', 0x29fbf3e, 'ff15cc20d702'),
    ('role_field_landing_resume', 0x29fbf47, 'e8c441c602'),
)

# Additional exact contracts for the five-arm descriptor writer.
CONTRACTS += (
    ('writer_input_tag', 0x2a287f2, '0fb606'),
    ('writer_jump_table_base', 0x2a287f5, '488d0d406b9ffd'),
    ('writer_table_offset', 0x2a287fc, '48630481'),
    ('writer_table_add', 0x2a28800, '4801c8'),
    ('writer_indirect_jump', 0x2a28803, 'ffe0'),
    ('writer_first_null', 0x2a2880f, '0f8443030000'),
    ('writer_missing_descriptor', 0x2a2886c, '488d0d45c9ca02'),
    ('writer_missing_call', 0x2a2887b, 'e8b034fdff'),
    ('writer_subaccount_descriptor', 0x2a288ec, '488d0d65c9ca02'),
    ('writer_subaccount_call', 0x2a288fb, 'e83034fdff'),
    ('writer_subaccount_status', 0x2a28900, '4885c0'),
    ('writer_subaccount_failure', 0x2a28903, '0f85d0000000'),
    ('writer_subaccount_payload_call', 0x2a28925, 'e886c6fdff'),
    ('writer_agent_descriptor', 0x2a28996, '488d0d6bc8ca02'),
    ('writer_agent_call', 0x2a289a5, 'e88633fdff'),
    ('writer_agent_failure', 0x2a289ad, '752a'),
    ('writer_agent_payload_call', 0x2a289cb, 'e8e02efdff'),
    ('writer_vault_descriptor', 0x2a28a4c, '488d0dddc7ca02'),
    ('writer_vault_call', 0x2a28a5b, 'e8d032fdff'),
    ('writer_user_descriptor', 0x2a28ac9, '488d0d10c7ca02'),
    ('writer_user_call', 0x2a28ad8, 'e85332fdff'),
    ('writer_common_success', 0x2a28ae0, '7411'),
    ('writer_error_pointer', 0x2a28ae2, '48894308'),
    ('writer_error_cleanup', 0x2a28aec, 'e89f120000'),
    ('writer_finish_call', 0x2a28b42, 'ff15a8c5d402'),
    ('writer_null_failure', 0x2a28b5f, 'ff15b35dd402'),
    ('writer_missing_landing', 0x2a28b72, '4889c3'),
    ('writer_missing_cleanup', 0x2a28b78, 'e813120000'),
    ('writer_resume', 0x2a28ba7, 'e86475c302'),
)


# Key and payload handoffs within the descriptor writer.
CONTRACTS += (
    ('writer_missing_role_key', 0x2a28865, '488d35a8147efd'),
    ('writer_subaccount_role_key', 0x2a288e5, '488d3528147efd'),
    ('writer_agent_role_key', 0x2a2898f, '488d357e137efd'),
    ('writer_vault_role_key', 0x2a28a45, '488d35c8127efd'),
    ('writer_user_role_key', 0x2a28ac2, '488d354b127efd'),
    ('writer_subaccount_payload_pointer', 0x2a28909, '49ffc6'),
    ('writer_subaccount_data_key', 0x2a28911, '488d3574177efd'),
    ('writer_subaccount_data_length', 0x2a28920, 'ba04000000'),
    ('writer_agent_payload_pointer', 0x2a289af, '49ffc6'),
    ('writer_agent_data_key', 0x2a289b7, '488d35ce167efd'),
    ('writer_agent_data_length', 0x2a289c6, 'ba04000000'),
    ('writer_payload_status', 0x2a289d0, '4885c0'),
    ('writer_payload_success', 0x2a289d3, '0f841a010000'),
)


# The five role-key lengths are independently pinned.
CONTRACTS += (
    ('writer_missing_role_length', 0x2a28876, 'ba04000000'),
    ('writer_subaccount_role_length', 0x2a288f6, 'ba04000000'),
    ('writer_agent_role_length', 0x2a289a0, 'ba04000000'),
    ('writer_vault_role_length', 0x2a28a56, 'ba04000000'),
    ('writer_user_role_length', 0x2a28ad3, 'ba04000000'),
)

# Handoffs in previously inventoried callers; no caller body is selected.
CONTEXT = (
    ('peek_label_pointer', 0x27e537a, '4c8d055ee7c0fd'),
    ('peek_label_length', 0x27e5386, '41b914000000'),
    ('peek_boundary_call', 0x27e538f, 'e82c07ffff'),
    ('peek_tag_compare', 0x27e5412, '4180fe05'),
    ('peek_hit_branch', 0x27e5416, '0f85e8010000'),
    ('outer_vtable_pointer', 0x27e54b2, '488d055febed02'),
    ('outer_indirect_poll', 0x27e54d4, 'ff5018'),
    ('inner_vtable_pointer', 0x27f75c0, '488d0529cfec02'),
    ('inner_indirect_poll', 0x27f75dd, 'ff5018'),
    ('role_boundary_call', 0x27f9400, 'e8bbd5d8ff'),
    ('update_label_pointer', 0x27e55a3, '488d0d49e5c0fd'),
    ('update_label_length', 0x27e55be, '41b816000000'),
    ('update_boundary_call', 0x27e55c4, 'e89756daff'),
)

# Selected relocation slots connect global configuration, cache helpers and the
# two already-inventoried caller handoffs. They are not selected function bodies.
RELOCATIONS = {
    0x5668488: 0x2180ff,
    0x56c4030: 0x27f7530,
    0x56c4508: 0x27f93b0,
    0x56d51b8: 0x20b0e8,
    0x56d51c8: 0x41fb73,
    0x56d51e0: 0x20b0e8,
    0x56d51f0: 0x209ebc,
    0x56d5208: 0x20b0e8,
    0x56d5218: 0x41fb7a,
    0x56d5230: 0x20b0e8,
    0x56d5240: 0x41fb7f,
    0x56d5258: 0x20b0e8,
    0x56d5268: 0x41fb84,
    0x576dfd8: 0x54c06b0,
    0x576e010: 0x54c8cb0,
    0x576e020: 0x1345e2a,
    0x576e8b8: 0x4ee3b20,
    0x576e8f8: 0x13c9e20,
    0x576e928: 0x577b288,
    0x576f5e8: 0x4e0b770,
    0x576f5f8: 0x4e0be20,
    0x576f600: 0x4e0c150,
    0x576f608: 0x4e0d2c0,
    0x57709f0: 0x1648b10,
    0x5770a08: 0x5788378,
    0x5773668: 0x488f410,
    0x577ab80: 0x143ef30,
    0x577b288: 0x164ff00,
}
JCC = ('o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a',
       's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g')


def selected_relocations(view, slots):
    """Read requested ELF64 RELA records from the shared ELF section map."""
    candidates = [s for s in view.sections if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(candidates) != 1 or candidates[0]['size'] % 24:
        raise ValueError('invalid RELA section')
    sec = candidates[0]
    result = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', view.data, off)
        if slot not in slots:
            continue
        if slot in result or info != 8:
            raise ValueError('duplicate or non-RELATIVE selected relocation')
        view.offset(slot, 8)
        result[slot] = {'slot': hex(slot), 'record_file_offset': hex(off),
                        'type': info & 0xffffffff, 'symbol': info >> 32,
                        'addend': hex(addend)}
    if set(result) != set(slots):
        raise ValueError('selected relocation missing')
    for slot, expected in slots.items():
        if int(result[slot]['addend'], 16) != expected:
            raise ValueError('selected relocation target mismatch')
    return result


def collect_contracts(view, decodes):
    starts = {i['va']: i for body in decodes.values() for i in body}
    if len(starts) != sum(len(x) for x in decodes.values()):
        raise ValueError('selected instructions overlap')
    rows, seen_names, seen_va = [], set(), set()
    for label, va, expected in CONTRACTS:
        if label in seen_names or va in seen_va:
            raise ValueError('duplicate instruction contract')
        seen_names.add(label)
        seen_va.add(va)
        raw = require(view, label, va, bytes.fromhex(expected))
        if va not in starts or raw != starts[va]['bytes']:
            raise ValueError('contract is not one complete decoded instruction')
        rows.append({'label': label, 'va': hex(va), 'file_offset': hex(view.offset(va, len(raw))),
                     'bytes': raw.hex()})
    return rows


def collect_context(view):
    """Check selected instructions in previously inventoried callers only."""
    rows, decoded = [], {}
    for label, va, expected in CONTEXT:
        if label in decoded:
            raise ValueError('duplicate handoff label')
        ins = decode_one(view.read(va, 15), 0, va)
        if ins['bytes'] != bytes.fromhex(expected):
            raise ValueError('handoff bytes changed')
        decoded[label] = ins
        rows.append({'label': label, 'va': hex(va),
                     'file_offset': hex(view.offset(va, len(ins['bytes']))),
                     'bytes': ins['bytes'].hex(), 'kind': ins['kind'],
                     'target': '' if ins['target'] is None else hex(ins['target'])})
    expected_targets = {'peek_label_pointer': 0x3f3adf, 'peek_boundary_call': 0x27d5ac0,
                        'outer_vtable_pointer': 0x56c4018,
                        'inner_vtable_pointer': 0x56c44f0,
                        'role_boundary_call': 0x25869c0,
                        'update_label_pointer': 0x3f3af3, 'update_boundary_call': 0x258ac60}
    for label, target in expected_targets.items():
        if decoded[label]['target'] != target:
            raise ValueError('handoff target changed')
    if decoded['peek_label_length']['bytes'][-4:] != struct.pack('<I', 20):
        raise ValueError('peek label length changed')
    if decoded['update_label_length']['bytes'][-4:] != struct.pack('<I', 22):
        raise ValueError('update label length changed')
    return rows, decoded


def collect_pools(view, relocs, context):
    items = []
    for label, target_label, length_label, expected in (
            ('peek_label', 'peek_label_pointer', 'peek_label_length', b'user_role_cache_peek'),
            ('update_label', 'update_label_pointer', 'update_label_length', b'user_role_cache_update')):
        va = context[target_label]['target']
        size = int.from_bytes(context[length_label]['bytes'][-4:], 'little')
        raw = view.read(va, size)
        if raw != expected:
            raise ValueError('bounded label differs')
        before, after = view.read(va - 1, 1), view.read(va + size, 1)
        items.append({'label': label, 'va': hex(va), 'file_offset': hex(view.offset(va, size)),
                      'length': size, 'bytes': raw.hex(), 'text': raw.decode('ascii'),
                      'before': before.hex(), 'after': after.hex()})
    slot = 0x5668488
    va = int(relocs[slot]['addend'], 16)
    size = struct.unpack('<Q', view.read(slot + 8, 8))[0]
    raw = view.read(va, size)
    if raw != b'NvTestnet':
        raise ValueError('default descriptor mismatch')
    items.append({'label': 'prior_default_name_descriptor', 'va': hex(va),
                  'file_offset': hex(view.offset(va, size)), 'length': size,
                  'bytes': raw.hex(), 'text': raw.decode('ascii'),
                  'before': view.read(va - 1, 1).hex(),
                  'after': view.read(va + size, 1).hex()})
    return items


def branch_name(ins):
    if ins['kind'] == 'jump':
        return 'jmp'
    if ins['kind'] != 'conditional':
        raise ValueError('not a conditional branch')
    op, op2 = ins['opcode']
    return JCC[(op2 if op == 0x0f else op) & 15]


# Each slice identifies an immediate or displacement in one exact contract.
# Values are decoded from the selected ELF instructions, not from disassembly.
LAYOUT_FIELDS = (
    ('first_map_count', 0x27cfea9, 3, 4),
    ('first_map_pointer', 0x27cfed3, 3, 4),
    ('tree_root', 0x27cff93, 3, 4),
    ('second_map_count', 0x27d00ac, 3, 4),
    ('second_map_pointer', 0x27d00d7, 3, 4),
    ('third_map_count', 0x27d0190, 3, 4),
    ('third_map_pointer', 0x27d01b6, 3, 4),
    ('selector_result_tag', 0x27d0387, 3, 1),
    ('selector_result_payload_first', 0x27d0393, 4, 1),
    ('selector_result_payload_last', 0x27d039f, 3, 1),
    ('cache_lock', 0x27d2dbb, 4, 4),
    ('cache_update_index', 0x27d2e80, 3, 4),
    ('cache_peek_index', 0x27d5b76, 3, 4),
    ('cache_record_tag', 0x27d5b9e, 4, 1),
    ('cache_node_allocation_size', 0x1f85421, 1, 4),
    ('global_cell_state', 0x2586a38, 3, 1),
    ('global_cell_name', 0x2586a40, 4, 1),
    ('role_descriptor_variant_length', 0x29fbddd, 3, 1),
    ('role_descriptor_variant_pointer', 0x29fbdf3, 3, 1),
)


def layout_rows(view, decodes):
    contracts = {va: bytes.fromhex(raw) for _, va, raw in CONTRACTS}
    instructions = {r['va']: r for body in decodes.values() for r in body}
    rows = []
    for label, va, offset, width in LAYOUT_FIELDS:
        if va not in contracts or va not in instructions:
            raise ValueError('layout field lacks a complete instruction contract')
        raw = require(view, label, va, contracts[va])
        if raw != instructions[va]['bytes'] or offset < 0 or offset + width > len(raw):
            raise ValueError('layout operand is outside its instruction')
        value = int.from_bytes(raw[offset:offset + width], 'little')
        rows.append({'label': label, 'va': hex(va), 'file_offset': hex(view.offset(va, len(raw))),
                     'bytes': raw.hex(), 'operand_offset': offset, 'operand_width': width,
                     'value': value, 'value_hex': hex(value)})
    return rows


def constants_from_bytes(view, decodes):
    instructions = {i['va']: i for body in decodes.values() for i in body}
    def raw(va):
        return instructions[va]['bytes']
    name_mask = int.from_bytes(raw(0x2586a4a)[1:5], 'little')
    if name_mask != int.from_bytes(raw(0x258acd7)[1:5], 'little'):
        raise ValueError('wrapper mask disagreement')
    limit = raw(0x2586a45)[-1]
    if raw(0x258acd2)[-1] != limit:
        raise ValueError('wrapper name bounds disagree')
    threshold_va = instructions[0x2586a27]['target']
    if instructions[0x258acb4]['target'] != threshold_va:
        raise ValueError('wrapper thresholds disagree')
    threshold_bytes = require(view, 'name gate threshold', threshold_va, bytes.fromhex('0000000000000840'))
    threshold = struct.unpack('<d', threshold_bytes)[0]
    if not math.isfinite(threshold):
        raise ValueError('threshold is not finite')
    key_lengths = [int.from_bytes(raw(a)[-4:], 'little') for a in
                   (0x1f85265, 0x1f85504, 0x2047abc, 0x2047ca3, 0x27cfff9)]
    if len(set(key_lengths)) != 1:
        raise ValueError('selected key lengths disagree')
    miss = raw(0x1f85493)[-1]
    if miss != raw(0x27d5bb7)[-1] or miss != raw(0x27d2eaf)[-1]:
        raise ValueError('cache sentinel values disagree')
    tag_values = {'first_map': raw(0x27d0074)[-1], 'tree': raw(0x27d007c)[-1],
                  'second_map': raw(0x27d028b)[-1], 'third_map': raw(0x27d023a)[-1],
                  'none': 0}
    if len(set(tag_values.values())) != 5 or miss in tag_values.values():
        raise ValueError('role tags or missing sentinel collide')
    return {'key_bytes': key_lengths[0], 'name_limit': limit, 'name_mask': name_mask,
            'threshold_va': hex(threshold_va), 'threshold_bytes': threshold_bytes.hex(),
            'threshold': threshold, 'cache_miss_tag': miss, 'role_tags': tag_values,
            'remove_distance_limit': raw(0x2047be3)[-1],
            'remove_long_marker': raw(0x2047be1)[-1],
            'remove_short_marker': raw(0x2047bfa)[-1],
            'selected_name_bytes': [i for i in range(limit + 1) if name_mask >> i & 1]}


def key_equal20(left, right, key_bytes):
    if len(left) != key_bytes or len(right) != key_bytes:
        raise ValueError('research model requires two complete keys')
    return left[:16] == right[:16] and left[16:] == right[16:]


def role_choice(hits, constants):
    if len(hits) != 4 or any(type(x) is not bool for x in hits):
        raise ValueError('four boolean search results required')
    sources = ('first_map', 'tree', 'second_map', 'third_map')
    source = next((name for name, hit in zip(sources, hits) if hit), 'none')
    return source, constants['role_tags'][source]


def gate_uses_second_state(name, total, constants):
    if type(name) is not int or not 0 <= name <= 255:
        raise ValueError('name byte outside model domain')
    return (not math.isnan(total) and total > constants['threshold'] and
            name <= constants['name_limit'] and bool(constants['name_mask'] & (1 << name)))


def saturating_next(value):
    if type(value) is not int or not 0 <= value < (1 << 64):
        raise ValueError('counter outside unsigned 64-bit model domain')
    return min(value + 1, (1 << 64) - 1)


def cache_step(order, key, capacity, key_bytes):
    """Synthetic model of normal local paths; keys are ordered front to tail."""
    order = list(order)
    if type(capacity) is not int or capacity <= 0 or len(order) > capacity:
        raise ValueError('invalid model capacity')
    if len(set(order)) != len(order) or any(len(k) != key_bytes for k in order + [key]):
        raise ValueError('invalid model keys')
    if key in order:
        order.remove(key)
        order.insert(0, key)
        return 'replace', order
    if len(order) == capacity:
        order.pop()
        action = 'reuse_tail'
    else:
        action = 'allocate'
    order.insert(0, key)
    return action, order


def removal_marker(distance, growth, constants):
    """Model the selected 16-bit distance and checked unsigned counter."""
    if type(distance) is not int or not 0 <= distance <= 0xffff:
        raise ValueError('distance outside unsigned 16-bit model domain')
    if type(growth) is not int or not 0 <= growth < (1 << 64):
        raise ValueError('growth counter outside unsigned 64-bit model domain')
    if distance > constants['remove_distance_limit']:
        return constants['remove_long_marker'], growth, False
    if growth == (1 << 64) - 1:
        return None, growth, True
    return constants['remove_short_marker'], growth + 1, False


ROLE_DESCRIPTOR_LEAS = (0x2a2886c, 0x2a28ac9, 0x2a28996, 0x2a28a4c, 0x2a288ec)


def role_descriptors(view, decodes, relocs):
    body = decodes['role_descriptor_writer']
    instructions = {i['va']: i for i in body}
    table = instructions[0x2a287f5]['target']
    if table != 0x41f33c:
        raise ValueError('role dispatch table base changed')
    rows = []
    for tag, lea in enumerate(ROLE_DESCRIPTOR_LEAS):
        entry = table + 4 * tag
        raw = view.read(entry, 4)
        arm = table + int.from_bytes(raw, 'little', signed=True)
        if arm not in instructions:
            raise ValueError('role dispatch arm is not an instruction start')
        reach = [reachable(body, arm, candidate) for candidate in ROLE_DESCRIPTOR_LEAS]
        if reach != [index == tag for index in range(len(ROLE_DESCRIPTOR_LEAS))]:
            raise ValueError('role dispatch arm reaches the wrong descriptor')
        payload_sites = (0x2a289cb, 0x2a28925)
        payload_reach = [reachable(body, arm, site) for site in payload_sites]
        expected_payload = [tag == 2, tag == 4]
        if payload_reach != expected_payload:
            raise ValueError('role writer payload path changed')
        descriptor = instructions[lea]['target']
        name_va = int(relocs[descriptor]['addend'], 16)
        variant_va = int(relocs[descriptor + 16]['addend'], 16)
        name_len = struct.unpack('<Q', view.read(descriptor + 8, 8))[0]
        variant_len = struct.unpack('<Q', view.read(descriptor + 24, 8))[0]
        ordinal = struct.unpack('<Q', view.read(descriptor + 32, 8))[0]
        name = view.read(name_va, name_len)
        variant = view.read(variant_va, variant_len)
        if name != b'UserRole' or ordinal != tag:
            raise ValueError('role descriptor type or ordinal changed')
        rows.append({'tag': tag, 'jump_entry': hex(entry),
                     'jump_file_offset': hex(view.offset(entry, 4)), 'jump_bytes': raw.hex(),
                     'arm': hex(arm), 'descriptor_lea': hex(lea), 'descriptor': hex(descriptor),
                     'enum_name_va': hex(name_va), 'enum_length': name_len,
                     'enum_name': name.decode('ascii'), 'variant_va': hex(variant_va),
                     'variant_length': variant_len, 'variant': variant.decode('ascii'),
                     'payload_call': hex(payload_sites[payload_reach.index(True)]) if any(payload_reach) else '',
                     'ordinal': ordinal})
    if [x['variant'] for x in rows] != ['missing', 'user', 'agent', 'vault', 'subAccount']:
        raise ValueError('role descriptor names changed')
    return rows


def writer_literals(view, decodes):
    instructions = {i['va']: i for body in decodes.values() for i in body}
    role_leas = (0x2a28865, 0x2a288e5, 0x2a2898f, 0x2a28a45, 0x2a28ac2)
    role_lengths = (0x2a28876, 0x2a288f6, 0x2a289a0, 0x2a28a56, 0x2a28ad3)
    data_leas = (0x2a28911, 0x2a289b7)
    data_lengths = (0x2a28920, 0x2a289c6)
    rows = []
    for label, leas, lengths, expected in (('role_key', role_leas, role_lengths, b'role'),
                                            ('data_key', data_leas, data_lengths, b'data'),
                                            ('agent_user_key', (0x2a28d5e,), (0x2a28d68,), b'user'),
                                            ('subaccount_master_key', (0x2a28c2e,), (0x2a28c38,), b'master')):
        targets = {instructions[va]['target'] for va in leas}
        sizes = {int.from_bytes(instructions[va]['bytes'][-4:], 'little') for va in lengths}
        if len(targets) != 1 or sizes != {len(expected)}:
            raise ValueError('writer key pointer or size changed')
        va = next(iter(targets))
        raw = require(view, label, va, expected)
        rows.append({'label': label, 'va': hex(va), 'file_offset': hex(view.offset(va, len(raw))),
                     'length': len(raw), 'bytes': raw.hex(), 'text': raw.decode('ascii'),
                     'references': ','.join(hex(x) for x in leas)})
    return rows


def writer_variant(tag, rows):
    # This is an analysis-domain guard, not a claim that target code bounds-checks.
    if type(tag) is not int or not 0 <= tag < len(rows):
        raise ValueError('tag outside analysed writer domain')
    if rows[tag]['tag'] != tag:
        raise ValueError('descriptor rows reordered')
    return rows[tag]['variant']


def make_scenarios(constants, descriptors):
    role_rows = []
    for hits in itertools.product((False, True), repeat=4):
        source, tag = role_choice(hits, constants)
        role_rows.append({'first_map': int(hits[0]), 'tree': int(hits[1]),
                          'second_map': int(hits[2]), 'third_map': int(hits[3]),
                          'selected_source': source, 'tag': tag,
                          'writer_descriptor_if_tag_reused': writer_variant(tag, descriptors),
                          'map_payload_selected': int(source in ('first_map', 'second_map'))})
    keys = [bytes([i]) * constants['key_bytes'] for i in (1, 2, 3)]
    cache_rows = []
    for name, before, key, capacity, counter in (
            ('replace_tail', keys[:2], keys[1], 2, 0),
            ('insert_with_space', keys[:2], keys[2], 3, 41),
            ('insert_full_reuses_tail', keys[:2], keys[2], 2, (1 << 64) - 1)):
        action, after = cache_step(before, key, capacity, constants['key_bytes'])
        cache_rows.append({'case': name, 'before': ','.join(x.hex() for x in before),
                           'key': key.hex(), 'capacity': capacity, 'action': action,
                           'after': ','.join(x.hex() for x in after), 'counter': counter,
                           'next_counter': saturating_next(counter)})
    gate_rows = []
    for name in (12, 13, 14, 18, 19, 20, 21, 30, 31, 32, 75, 255):
        for value, text in ((3.0, '3'), (3.5, '3.5'), (float('nan'), 'nan')):
            gate_rows.append({'name_byte': name, 'sum': text,
                              'second_state': int(gate_uses_second_state(name, value, constants))})
    marker_rows = []
    for distance in (0, 14, 15, 16, 31, 65535):
        for growth in (0, (1 << 64) - 2, (1 << 64) - 1):
            marker, after, overflow = removal_marker(distance, growth, constants)
            marker_rows.append({'distance': distance, 'growth_before': growth,
                                'marker': '' if marker is None else hex(marker),
                                'growth_after': after, 'overflow_boundary': int(overflow)})
    return role_rows, cache_rows, gate_rows, marker_rows

FLOW_CHECKS = (
    ('first_match_to_publish', 'role_select', 0x27d005a, 0x27d0387, True),
    ('first_match_reaches_tree', 'role_select', 0x27d005a, 0x27cff93, False),
    ('tree_match_to_publish', 'role_select', 0x27d007c, 0x27d0387, True),
    ('tree_match_reaches_second_map', 'role_select', 0x27d007c, 0x27d00ac, False),
    ('second_map_to_publish', 'role_select', 0x27d0271, 0x27d0387, True),
    ('second_map_reaches_last_map', 'role_select', 0x27d0271, 0x27d0190, False),
    ('last_map_to_publish', 'role_select', 0x27d023a, 0x27d0387, True),
    ('replacement_relinks', 'cache_insert', 0x1f8534d, 0x1f853af, True),
    ('replacement_reaches_allocation', 'cache_insert', 0x1f8534d, 0x1f85421, False),
    ('replacement_reaches_new_index', 'cache_insert', 0x1f8534d, 0x1f8548e, False),
    ('reused_tail_reaches_index', 'cache_insert', 0x1f85201, 0x1f8548e, True),
    ('allocated_node_reaches_index', 'cache_insert', 0x1f85421, 0x1f8548e, True),
    ('peek_hit_reaches_output', 'cache_peek', 0x27d5b8f, 0x27d5ca6, True),
    ('peek_hit_reaches_miss_store', 'cache_peek', 0x27d5b8f, 0x27d5bb7, False),
    ('peek_miss_reaches_output', 'cache_peek', 0x27d5bb7, 0x27d5ca6, True),
    ('update_insert_reaches_unlock', 'cache_update', 0x27d2ea1, 0x27d2f04, True),
    ('update_landing_reaches_resume', 'cache_update', 0x27d3046, 0x27d3087, True),
    ('peek_landing_reaches_resume', 'cache_peek', 0x27d5cf1, 0x27d5d40, True),
    ('role_landing_reaches_resume', 'role_select', 0x27d03c6, 0x27d0410, True),
    ('agent_nested_nonzero_cleans', 'agent_nested_writer', 0x2a28d7a, 0x2a28d88, True),
    ('agent_nested_nonzero_skips_finish', 'agent_nested_writer', 0x2a28d7a, 0x2a28dde, False),
    ('agent_nested_zero_finishes', 'agent_nested_writer', 0x2a28d8f, 0x2a28dde, True),
    ('agent_nested_landing_resumes', 'agent_nested_writer', 0x2a28e01, 0x2a28e0f, True),
    ('subaccount_nested_nonzero_cleans', 'subaccount_nested_writer', 0x2a28c4a, 0x2a28c58, True),
    ('subaccount_nested_nonzero_skips_finish', 'subaccount_nested_writer', 0x2a28c4a, 0x2a28cae, False),
    ('subaccount_nested_zero_finishes', 'subaccount_nested_writer', 0x2a28c5f, 0x2a28cae, True),
    ('subaccount_nested_landing_resumes', 'subaccount_nested_writer', 0x2a28cd1, 0x2a28cdf, True),
    ('agent_data_landing_resumes', 'agent_data_helper', 0x29fbac1, 0x29fbadc, True),
    ('subaccount_data_landing_resumes', 'subaccount_data_helper', 0x2a051c1, 0x2a051dc, True),
    ('role_field_nonempty_reaches_bytes_call', 'role_field_helper', 0x29fbdf9, 0x29fbe1f, True),
    ('role_field_empty_reaches_bytes_call', 'role_field_helper', 0x29fbe10, 0x29fbe1f, True),
    ('role_field_bytes_call_reaches_object', 'role_field_helper', 0x29fbe1f, 0x29fbe5e, True),
    ('role_field_failure_reaches_trap', 'role_field_helper', 0x29fbf22, 0x29fbdf1, True),
    ('role_field_landing_resumes', 'role_field_helper', 0x29fbf2c, 0x29fbf47, True),
)
FAILURE_CALLS = (
    ('first_hash', 'role_select', 0x27cfec7, 0x27d03c6),
    ('second_hash', 'role_select', 0x27d00cb, 0x27d03c6),
    ('cache_insert', 'cache_update', 0x27d2ea1, 0x27d3046),
    ('cache_lookup', 'cache_peek', 0x27d5b85, 0x27d5cf1),
    ('writer_missing', 'role_descriptor_writer', 0x2a2887b, 0x2a28b72),
    ('writer_subaccount', 'role_descriptor_writer', 0x2a288fb, 0x2a28b99),
    ('writer_agent', 'role_descriptor_writer', 0x2a289a5, 0x2a28b8c),
    ('writer_vault', 'role_descriptor_writer', 0x2a28a5b, 0x2a28b7f),
    ('writer_user', 'role_descriptor_writer', 0x2a28ad8, 0x2a28b65),
    ('agent_data_nested', 'agent_data_helper', 0x29fb963, 0x29fbac1),
    ('subaccount_data_nested', 'subaccount_data_helper', 0x2a05063, 0x2a051c1),
    ('agent_nested_field', 'agent_nested_writer', 0x2a28d70, 0x2a28e01),
    ('subaccount_nested_field', 'subaccount_nested_writer', 0x2a28c40, 0x2a28cd1),
    ('role_field_size_failure', 'role_field_helper', 0x29fbdeb, 0x29fbf2c),
)
EXPECTED_CALLS = {
    0x1f85201: 0x2047aa0,
    0x1f8548e: 0x2047c80,
    0x2586a05: 0x27cfdd0,
    0x258ac89: 0x27d2d90,
    0x27d2ea1: 0x1f851b0,
    0x27d5b85: 0x1f854e0,
    0x2a2887b: 0x29fbd30,
    0x2a288fb: 0x29fbd30,
    0x2a289a5: 0x29fbd30,
    0x2a28a5b: 0x29fbd30,
    0x2a28ad8: 0x29fbd30,
    0x29fbe5e: 0x2a39f40,
    0x2a289cb: 0x29fb8b0,
    0x2a28925: 0x2a04fb0,
    0x29fb963: 0x2a28cf0,
    0x2a05063: 0x2a28bc0,
    0x2a28d70: 0x29f8540,
    0x2a28c40: 0x29f8540,
}


def checked_flow(decodes):
    rows = []
    for label, function, source, target, expected in FLOW_CHECKS:
        result = reachable(decodes[function], source, target)
        if result != expected:
            raise ValueError(f'normal CFG proposition changed: {label}')
        rows.append({'proposition': label, 'function': function, 'source': hex(source),
                     'target': hex(target), 'reachable': int(result)})
    return rows


def checked_failures(lsda_rows):
    rows = []
    for label, function, site, expected in FAILURE_CALLS:
        matching = [row for row in lsda_rows if row['function_name'] == function and
                    int(row['start_va'], 16) <= site < int(row['end_va'], 16)]
        if len(matching) != 1 or matching[0]['landing_va'] != hex(expected):
            raise ValueError(f'failure landing changed: {label}')
        record = matching[0]
        rows.append({'boundary': label, 'function': function, 'call_site': hex(site),
                     'protected_start': record['start_va'], 'protected_end': record['end_va'],
                     'landing': record['landing_va'], 'action_index': record['action_index']})
    return rows


def collect(data):
    verify_identity(data)
    view = View(data)
    _, fdes = eh_frame_records(data, view.sections)
    by_start = {}
    for fde in fdes:
        by_start.setdefault(fde['start'], []).append(fde)
    functions, decodes, lsda_rows, lsda_headers = [], {}, [], []
    for label, start, end, digest in FUNCTIONS:
        found = by_start.get(start, [])
        if len(found) != 1 or found[0]['end'] != end:
            raise ValueError(f'selected FDE missing, duplicated or resized: {label}')
        fde = found[0]
        executable = [s for s in view.sections if s['type'] != 8 and s['flags'] & 4 and
                      s['address'] <= start and end <= s['address'] + s['size']]
        if len(executable) != 1:
            raise ValueError('selected FDE is not uniquely executable and file-backed')
        raw = view.read(start, end - start)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError(f'selected body digest changed: {label}')
        decoded = decode_body(raw, start)
        decodes[label] = decoded
        if fde['lsda'] is not None:
            header, records = parse_lsda(view, start, end, fde['lsda'])
            inst_starts = {i['va'] for i in decoded}
            for record in records:
                if record['landing_va'] and int(record['landing_va'], 16) not in inst_starts:
                    raise ValueError('exception landing is not a decoded instruction')
                record['function_name'] = label
            lsda_rows.extend(records)
            lsda_headers.append(header)
        functions.append({'function': label, 'start_va': hex(start), 'end_va_exclusive': hex(end),
                          'file_offset': hex(view.offset(start, end - start)), 'bytes': len(raw),
                          'fde_va': hex(fde['fde']), 'lsda_va': hex(fde['lsda']) if fde['lsda'] else '',
                          'body_sha256': hashlib.sha256(raw).hexdigest(),
                          'decoded_instructions': len(decoded)})
    contracts = collect_contracts(view, decodes)
    layout = layout_rows(view, decodes)
    context, handoffs = collect_context(view)
    relocations = selected_relocations(view, RELOCATIONS)
    pools = collect_pools(view, relocations, handoffs)
    constants = constants_from_bytes(view, decodes)
    descriptors = role_descriptors(view, decodes, relocations)
    writer_keys = writer_literals(view, decodes)
    role_cases, cache_cases, gate_cases, marker_cases = make_scenarios(constants, descriptors)

    instructions, branches, transfers = [], [], []
    by_va = {}
    for function, body in decodes.items():
        for ins in body:
            by_va[ins['va']] = ins
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
                rel = relocations.get(ins['target'], {})
                transfers.append({'function': function, 'va': row['va'], 'bytes': row['bytes'],
                                  'kind': ins['kind'], 'target_or_slot': row['target'],
                                  'selected_addend': rel.get('addend', '')})
    for site, expected in EXPECTED_CALLS.items():
        if site not in by_va or by_va[site]['kind'] != 'call' or by_va[site]['target'] != expected:
            raise ValueError('selected path call changed')
    # The selected vtables are reached by the boundary-only caller instructions.
    if handoffs['outer_vtable_pointer']['target'] + 0x18 != 0x56c4030:
        raise ValueError('outer vtable slot changed')
    if handoffs['inner_vtable_pointer']['target'] + 0x18 != 0x56c4508:
        raise ValueError('inner vtable slot changed')
    flows = checked_flow(decodes)
    failures = checked_failures(lsda_rows)
    summary = {'artifact_sha256': DIGEST, 'selected_fdes': len(functions),
               'selected_fde_bytes': sum(row['bytes'] for row in functions),
               'decoded_instructions': len(instructions), 'instruction_contracts': len(contracts),
               'direct_branches': len(branches), 'calls_and_indirect_transfers': len(transfers),
               'boundary_handoffs': len(context), 'selected_relocations': len(relocations),
               'pool_slices': len(pools), 'layout_fields': len(layout), 'writer_keys': len(writer_keys), 'role_descriptors': len(descriptors), 'lsda_entries': len(lsda_rows),
               'cfg_propositions': len(flows), 'failure_call_sites': len(failures),
               'role_models': len(role_cases), 'cache_models': len(cache_cases),
               'gate_models': len(gate_cases), 'marker_models': len(marker_cases), 'constants': constants,
               'limitations': ('Static observations; selected FDEs are unwind ranges, not a function census. '
                               'CFG queries assume normal call returns. Models are synthetic, not node execution.')}
    return {'summary': summary, 'functions': functions, 'instructions': instructions,
            'branches': branches, 'transfers': transfers, 'contracts': contracts, 'layout': layout,
            'handoffs': context, 'pools': pools,
            'relocations': [relocations[x] for x in sorted(relocations)],
            'lsda_headers': lsda_headers, 'lsda': lsda_rows, 'cfg': flows,
            'failures': failures, 'role_cases': role_cases, 'cache_cases': cache_cases,
            'gate_cases': gate_cases, 'marker_cases': marker_cases, 'descriptors': descriptors, 'writer_keys': writer_keys}


def write_tsv(path, rows, columns):
    with path.open('w', encoding='utf-8', newline='') as out:
        writer = csv.DictWriter(out, columns, delimiter='\t', lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)


def generate(data, out):
    result = collect(data)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    tables = {
        'functions.tsv': ('functions', ('function', 'start_va', 'end_va_exclusive', 'file_offset', 'bytes', 'fde_va', 'lsda_va', 'body_sha256', 'decoded_instructions')),
        'instructions.tsv': ('instructions', ('function', 'va', 'file_offset', 'bytes', 'kind', 'target', 'rip_relative')),
        'branches.tsv': ('branches', ('function', 'va', 'bytes', 'condition', 'target', 'fallthrough')),
        'transfers.tsv': ('transfers', ('function', 'va', 'bytes', 'kind', 'target_or_slot', 'selected_addend')),
        'contracts.tsv': ('contracts', ('label', 'va', 'file_offset', 'bytes')),
        'layout.tsv': ('layout', ('label', 'va', 'file_offset', 'bytes', 'operand_offset', 'operand_width', 'value', 'value_hex')),
        'handoffs.tsv': ('handoffs', ('label', 'va', 'file_offset', 'bytes', 'kind', 'target')),
        'pools.tsv': ('pools', ('label', 'va', 'file_offset', 'length', 'bytes', 'text', 'before', 'after')),
        'relocations.tsv': ('relocations', ('slot', 'record_file_offset', 'type', 'symbol', 'addend')),
        'lsda.tsv': ('lsda', ('function_name', 'function', 'lsda_va', 'entry_file_offset', 'start_va', 'end_va', 'landing_va', 'action_index')),
        'cfg.tsv': ('cfg', ('proposition', 'function', 'source', 'target', 'reachable')),
        'failure-routes.tsv': ('failures', ('boundary', 'function', 'call_site', 'protected_start', 'protected_end', 'landing', 'action_index')),
        'role-cases.tsv': ('role_cases', ('first_map', 'tree', 'second_map', 'third_map', 'selected_source', 'tag', 'writer_descriptor_if_tag_reused', 'map_payload_selected')),
        'writer-keys.tsv': ('writer_keys', ('label', 'va', 'file_offset', 'length', 'bytes', 'text', 'references')),
        'role-descriptors.tsv': ('descriptors', ('tag', 'jump_entry', 'jump_file_offset', 'jump_bytes', 'arm', 'descriptor_lea', 'descriptor', 'enum_name_va', 'enum_length', 'enum_name', 'variant_va', 'variant_length', 'variant', 'payload_call', 'ordinal')),
        'cache-cases.tsv': ('cache_cases', ('case', 'before', 'key', 'capacity', 'action', 'after', 'counter', 'next_counter')),
        'gate-cases.tsv': ('gate_cases', ('name_byte', 'sum', 'second_state')),
        'marker-cases.tsv': ('marker_cases', ('distance', 'growth_before', 'marker', 'growth_after', 'overflow_boundary')),
    }
    for filename, (key, columns) in tables.items():
        write_tsv(out / filename, result[key], columns)
    (out / 'summary.json').write_text(json.dumps({'summary': result['summary'],
        'lsda_headers': result['lsda_headers']}, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return result['summary']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    result = generate(TARGET.read_bytes(), args.out)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as exc:
        print(f'config_role_cache94: {exc}', file=sys.stderr)
        raise SystemExit(1)
