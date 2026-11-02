#!/usr/bin/env python3
"""Extract node 94 configuration IPv4-map paths from authenticated ELF bytes.

The restricted instruction-length/control-transfer decoder is adapted from
independent MIT RE-015 replica-route and nested-map research. It is not a
complete x86 decoder. No artifact is executed and no external program is used.
"""
import argparse
import csv
import hashlib
import io
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records, uleb

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
ARTIFACT = ROOT / 'artifacts/node/94/hl-node'

def require(ok, message):
    if not ok:
        raise ValueError(message)

def verify_identity(data):
    require(len(data) == SIZE and hashlib.sha256(data).hexdigest() == DIGEST, 'artifact identity mismatch')

class View:
    def __init__(self, data, secs=None):
        self.data = data
        self.sections = sections(data) if secs is None else secs

    def offset(self, va, size):
        require(type(va) is int and type(size) is int and va >= 0 and size > 0 and va + size <= 1 << 64, 'invalid virtual range')
        candidates = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2 and s['size'] and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(candidates) == 1, 'virtual range lacks unique file-backed section')
        offset = candidates[0]['offset'] + va - candidates[0]['address']
        require(offset >= 0 and offset + size <= len(self.data), 'file-backed range truncated')
        return offset

    def read(self, va, size):
        pos = self.offset(va, size)
        return self.data[pos:pos + size]

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
        elif 0xc8 <= op2 <= 0xcf:
            pass
        elif (op2 in (0x10, 0x11, 0x13, 0x14, 0x15, 0x1f, 0x28, 0x29, 0x2a, 0x2e, 0x2f, 0x57, 0x58, 0x5c, 0x5e,
                      0x60, 0x62, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x72, 0x73, 0x74, 0x7e, 0x7f, 0xa3, 0xaf, 0xb6, 0xb7,
                      0xb0, 0xb1, 0xbc, 0xc1, 0xbe, 0xbf, 0xd6, 0xd7, 0xdb, 0xdf, 0xe6, 0xeb, 0xef)
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

FUNCTIONS = (
    ('binary_ip_map', 0x13bf580, 0x13bff97, 'ba7d71945660d1101f9f842b04309da8d71866448734cbe9bf4f66ac1e037be3'),
    ('binary_ipv4_text', 0x13b7e20, 0x13b8601, 'a9deec95b036992d47412730ed44b723a7fa761de7c04e29876e431c7651010f'),
    ('binary_ipv4_other', 0x13b6c50, 0x13b7621, '032917c62bdfad9dabc5c05ea3c0688d751bb67cefb608c1f22d11c40f1091cf'),
    ('json_ipv4_value', 0x14bdbe0, 0x14bdd1b, 'fa34636b0fd6dce71528f17b462c1a49bce8d6cbe04d4b4e57ed886fdea75491'),
    ('map_insert', 0x14cb140, 0x14cb3f6, '36620fba33e26624cb6952b06ded2bf790563dc5fff82bf9ca18800dc4296f35'),
    ('map_insert_split', 0x1398430, 0x139911c, 'd8bc2a683d43f102f5e42f9e7ac27901e11630d3efb9d667a88ca8c0f6d4751a'),
    ('map_drop', 0x14da680, 0x14da744, '8f20996918a8355d4a1e353ee48b1f08e51274a4f5eb7299138bdd614063ad95'),
    ('map_drop_iterator', 0x14ce920, 0x14ceccd, 'fecc42f42f0a40ee47aeabfb0cc232b0e2074ec980855bb6568e6360c7e1a856'),
)

TABLES = (
    ('map_state', 0x214d38, 225, 'binary_ip_map', '7e77b6e5cb5d421b611f0ee07057d36e153fc68e6eedcaa81457209c45764670'),
    ('map_extended', 0x2150bc, 18, 'binary_ip_map', 'bdbe067ad4466b19ff11f500a780406429929ba17b8363efc90618fb032e4e4b'),
    ('map_marker_c0_df', 0x215104, 32, 'binary_ip_map', '66f55309325c65ef3c33c3719b01eeead048e8df88ea070a955356fcc77270c2'),
    ('text_state', 0x21155c, 225, 'binary_ipv4_text', '68b5a835c4727a406180117b7d5fb3ff27cf8ba6104792562878810ae069b34b'),
    ('text_extended', 0x2118e0, 18, 'binary_ipv4_text', '63d7fec674dfde2fafa0d51df366e00f70ab8e2f008f2efd1c2e7d5833a760fe'),
    ('text_marker_c0_df', 0x211928, 32, 'binary_ipv4_text', '77cacd0661b4309022c939a67a0879a786c252f260f92a4f97d626af6f9969ed'),
    ('other_state', 0x210cc4, 225, 'binary_ipv4_other', 'bc1ad34abef3459e8ad88fb50638ead6996f38e1aeaebb71f6777e29dffa72a7'),
    ('other_extended', 0x211048, 18, 'binary_ipv4_other', '95dc860739096018026f4761e7b2fa59533936f4584260580e491082fbac0502'),
    ('other_marker_c0_df', 0x211090, 32, 'binary_ipv4_other', '877c713441b424e8567d08149664d89d06224bcba613433c0746f21c0b2d3770'),
)

def load_functions(view):
    _, fdes = eh_frame_records(view.data, view.sections)
    selected = {}
    starts = {s for _, s, _, _ in FUNCTIONS}
    for f in fdes:
        if f['start'] in starts:
            require(f['start'] not in selected, 'ambiguous FDE start')
            selected[f['start']] = f
    require(set(selected) == starts, 'missing selected FDE')
    out = []
    for role, start, expected_end, digest in FUNCTIONS:
        f = selected[start]
        require(f['end'] == expected_end, 'FDE extent mismatch')
        body = view.read(start, f['end'] - start)
        require(hashlib.sha256(body).hexdigest() == digest, 'selected FDE bytes mismatch')
        rows = decode_body(body, start)
        out.append((role, f, rows, digest))
    return fdes, out

# Contracts lock semantic witnesses to instruction bytes; labels are analysis.
CONTRACTS = (
    (0x13bf597, 'cached_state_load', '0fb67e20'),
    (0x13bf5a3, 'cached_state_reset', '41c6462001'),
    (0x13bf90f, 'raw_marker_upper', '3cdf'),
    (0x13bf911, 'raw_marker_above_upper', '0f87a2fcffff'),
    (0x13bf917, 'raw_marker_map_cutoff', '3c90'),
    (0x13bf919, 'raw_marker_nonmap_branch', '0f8396030000'),
    (0x13bf91f, 'map_length_low_nibble', '240f'),
    (0x13bf925, 'map_depth_load', '410fb74622'),
    (0x13bf92d, 'zero_depth_branch', '0f8498050000'),
    (0x13bf933, 'map_depth_decrement', '66ffc8'),
    (0x13bf936, 'map_depth_store', '6641894622'),
    (0x13bf93b, 'depleted_depth_branch', '0f8421050000'),
    (0x13bf950, 'map_root_zero', '48c744247800000000'),
    (0x13bf959, 'map_count_zero', '48c784248800000000000000'),
    (0x13bf9b0, 'remaining_key_count_test', '4585ff'),
    (0x13bf9c0, 'key_reader_boundary', 'e80be3ffff'),
    (0x13bf9c9, 'key_status_compare', '80fb09'),
    (0x13bf9d2, 'remaining_key_decrement', '41ffcf'),
    (0x13bf9f6, 'format_selector', '41807e2400'),
    (0x13bf9fd, 'value_diagnostic_length', 'b90c000000'),
    (0x13bfa0a, 'value_diagnostic_pool_reference', '488d156eb6e5fe'),
    (0x13bfa17, 'text_value_reader_call', 'e80484ffff'),
    (0x13bfa26, 'other_value_reader_call', 'e82572ffff'),
    (0x13bfa53, 'value_status_compare', '807c242009'),
    (0x13bfa5e, 'read_four_byte_value', '8b6c2421'),
    (0x13bf9ab, 'insert_decoded_pair', 'e890b71000'),
    (0x13bfab9, 'remaining_key_count_at_end', '4585ed'),
    (0x13bfac6, 'subtract_remaining_count', '4429e8'),
    (0x13bfae0, 'drop_on_count_error', 'e89bab1100'),
    (0x13bfb83, 'map_success_tag', 'c644245009'),
    (0x13bfb8d, 'map_depth_restore_load', '410fb74622'),
    (0x13bfb92, 'map_depth_restore_limit', '6683f8ff'),
    (0x13bfb96, 'map_depth_restore_overflow_branch', '0f8449030000'),
    (0x13bfb9c, 'map_depth_restore_increment', 'ffc0'),
    (0x13bfb9e, 'map_depth_restore_store', '6641894622'),
    (0x13bfb1e, 'drop_on_key_error', 'e85dab1100'),
    (0x13bff84, 'drop_on_unwind', 'e8f7a61100'),
    (0x13bf742, 'raw_marker_remaining_load', '498b4e18'),
    (0x13bf749, 'raw_marker_missing', '0f8492010000'),
    (0x13bf756, 'raw_marker_read', '0fb606'),
    (0x13bf764, 'raw_marker_sign_test', '84c0'),
    (0x13bf766, 'raw_marker_sign_branch', '0f88a0010000'),
    (0x13bfcb5, 'raw_marker_array_cutoff', '3ca0'),
    (0x13bfcb7, 'raw_marker_above_array_branch', '0f83fc000000'),
    (0x13bfdb9, 'raw_marker_table_cutoff', '3cc0'),
    (0x13bfdbb, 'raw_marker_table_branch', '734b'),
    (0x13bfe0b, 'raw_marker_table_index', '81c740ffffff'),
    (0x13bfe11, 'raw_marker_table_reference', '4c8d05ec52e5fe'),
    (0x13bfe21, 'raw_marker_table_jump', '41ffe1'),
    (0x13bf718, 'raw_map16_header_size', '4883f902'),
    (0x13bf71c, 'raw_map16_short_branch', '0f82d7000000'),
    (0x13bf726, 'raw_map16_load', '0fb706'),
    (0x13bf729, 'raw_map16_swap', '66c1c008'),
    (0x13bf739, 'raw_map16_count', '440fb7f8'),
    (0x13bf6c0, 'raw_map32_header_size', '4883f904'),
    (0x13bf6c4, 'raw_map32_short_branch', '0f822f010000'),
    (0x13bf6ce, 'raw_map32_load', '448b3e'),
    (0x13bf6d5, 'raw_map32_swap', '410fcf'),
    (0x13bfe62, 'depleted_depth_return_tag', '41c6450008'),
    (0x13b809a, 'text_value_max_length', '4883f80f'),
    (0x13b809e, 'text_length_reject', '0f8742020000'),
    (0x13b80b8, 'text_ipv4_parser_boundary', 'e833ba1b00'),
    (0x13b80bd, 'text_remaining_length', '48837c242800'),
    (0x13b80c3, 'text_trailing_reject', '0f851d020000'),
    (0x13b80c9, 'text_result_flag', 'a801'),
    (0x13b80cb, 'text_flag_reject', '0f8415020000'),
    (0x13b80ea, 'text_success_tag', '41c6450009'),
    (0x13b6d62, 'other_value_mode_test', '84d2'),
    (0x13b6d64, 'other_value_mode_branch', '0f85da050000'),
    (0x13b7078, 'other_first_byte', '884f01'),
    (0x13b707b, 'other_second_byte', '885702'),
    (0x13b707e, 'other_third_byte', '44884703'),
    (0x13b7082, 'other_fourth_byte', '884704'),
    (0x13b7085, 'other_success_tag', 'c60709'),
    (0x14bdc02, 'json_empty_input_branch', '7342'),
    (0x14bdc5b, 'json_open_quote', '4983f822'),
    (0x14bdc80, 'json_string_reader_boundary', 'ff151a102b04'),
    (0x14bdc86, 'json_string_error_status', '833c2402'),
    (0x14bdc9f, 'json_value_max_length', '4883f90f'),
    (0x14bdca3, 'json_length_reject', '7736'),
    (0x14bdcb4, 'json_ipv4_parser_boundary', 'e8375e0b00'),
    (0x14bdcb9, 'json_remaining_length', '48837c242000'),
    (0x14bdcbf, 'json_trailing_reject', '751a'),
    (0x14bdcc1, 'json_result_flag', 'a801'),
    (0x14bdcc3, 'json_flag_reject', '7416'),
    (0x14bdcc9, 'json_store_four_bytes', '894301'),
    (0x14bdccc, 'json_clear_success_tag', '31c0'),
    (0x14bdcce, 'json_store_result_tag', '8803'),
    (0x14cb151, 'map_root_load', '488b0f'),
    (0x14cb154, 'map_root_test', '4885c9'),
    (0x14cb185, 'node_key_count', '0fb7893e010000'),
    (0x14cb1c4, 'compare_key_lengths', '4929d4'),
    (0x14cb1c7, 'compare_min_length', '480f42d3'),
    (0x14cb1ce, 'compare_bytes_slot', 'ff15b4322a04'),
    (0x14cb1fb, 'equal_key_branch', '742a'),
    (0x14cb23e, 'equal_free_incoming_key', 'ff15cc2d2a04'),
    (0x14cb261, 'equal_read_old_ipv4', '8b8cbb10010000'),
    (0x14cb268, 'equal_replace_ipv4', '8994bb10010000'),
    (0x14cb26f, 'equal_result_flag', 'b001'),
    (0x14cb31c, 'nonempty_insert_helper', 'e80fd1ecff'),
    (0x14cb32b, 'empty_root_allocation_size', 'bf40010000'),
    (0x14cb339, 'empty_root_allocation_failure', '746e'),
    (0x14cb342, 'empty_root_count_zero', '66c7803e0100000000'),
    (0x14cb34b, 'empty_root_publish', '498907'),
    (0x14cb35d, 'node_capacity', '4883f90b'),
    (0x14cb361, 'node_capacity_failure', '7358'),
    (0x14cb366, 'node_count_store', '6689903e010000'),
    (0x14cb36d, 'node_key_stride', '488d1449'),
    (0x14cb380, 'node_value_store', '89ac8810010000'),
    (0x14cb387, 'map_count_increment', '49ff4710'),
    (0x139844a, 'split_key_count', '450fb7a53e010000'),
    (0x1398452, 'split_capacity', '4983fc0b'),
    (0x1398456, 'nonfull_leaf_branch', '7229'),
    (0x139845c, 'split_first_threshold', '4883fd05'),
    (0x139846d, 'split_first_threshold_branch', '7342'),
    (0x1398474, 'split_pivot_four', 'bd04000000'),
    (0x13984b1, 'split_equal_five', '0f84c7000000'),
    (0x13984b7, 'split_second_threshold', '4883fd06'),
    (0x13984bb, 'split_not_six', '0f85c7000000'),
    (0x13984c1, 'split_pivot_five', 'bd05000000'),
    (0x1398588, 'split_offset_seven', '4883c5f9'),
    (0x1398591, 'split_pivot_six', 'bd06000000'),
    (0x13985b2, 'split_allocation_size', 'bf40010000'),
    (0x13985b7, 'split_allocation_slot', 'ff151b5a3d04'),
    (0x13985c0, 'split_allocation_failure', '0f84f0090000'),
    (0x1398562, 'nonfull_count_increment', '41ffc4'),
    (0x1398565, 'nonfull_value_store', '4589b48d10010000'),
    (0x139856d, 'nonfull_node_count', '664589a53e010000'),
    (0x1398784, 'split_parent_pointer', '498b4500'),
    (0x139878b, 'split_no_parent_branch', '0f8465040000'),
    (0x13987c4, 'parent_node_count', '440fb7a83e010000'),
    (0x13987cc, 'parent_capacity', '4983fd0b'),
    (0x13987e2, 'parent_nonfull_branch', '0f820a050000'),
    (0x1398850, 'full_parent_node_allocation_size', 'bfa0010000'),
    (0x1398855, 'full_parent_node_allocation_slot', 'ff157d573d04'),
    (0x139885e, 'full_parent_allocation_failure', '0f8406070000'),
    (0x1398beb, 'parent_loop_pointer_test', '4885c0'),
    (0x1398bee, 'parent_loop_branch', '0f85bcfbffff'),
    (0x1398c28, 'old_root_pointer_test', '4d85e4'),
    (0x1398c2b, 'missing_old_root_failure', '0f8497030000'),
    (0x1398c35, 'new_root_allocation_size', 'bfa0010000'),
    (0x1398c3a, 'new_root_allocation_slot', 'ff1598533d04'),
    (0x1398c43, 'new_root_allocation_failure', '0f848e030000'),
    (0x1398c5c, 'new_root_old_child', '4c89a040010000'),
    (0x1398c66, 'root_height_increment', '48ffc0'),
    (0x1398c69, 'root_height_overflow_branch', '0f847a030000'),
    (0x1398c6f, 'old_child_parent_link', '4d893424'),
    (0x1398c73, 'old_child_index_zero', '6641c784243c0100000000'),
    (0x1398c7e, 'new_root_publish', '4d8937'),
    (0x1398c81, 'root_height_publish', '49894708'),
    (0x1398cce, 'new_root_promoted_value', '4189948610010000'),
    (0x1398cd6, 'new_root_sibling_child', '49899cc648010000'),
    (0x1398cde, 'new_child_parent_link', '4c8933'),
    (0x1398ce1, 'new_child_index', '66898b3c010000'),
    (0x1398e04, 'nonfull_parent_new_child', '4d8984ea48010000'),
    (0x1398e0c, 'nonfull_parent_count', '664189b23e010000'),
    (0x1398e44, 'shifted_child_parent_link', '4c8917'),
    (0x1398e4b, 'shifted_child_index', '664489873c010000'),
    (0x14da68c, 'drop_root_test', '4885c9'),
    (0x14da6e1, 'drop_iterator_call', 'e83a42ffff'),
    (0x14da6ed, 'drop_end_branch', '744b'),
    (0x14da71d, 'drop_key_first_word', '488b74c808'),
    (0x14da722, 'drop_key_first_word_test', '4885f6'),
    (0x14da735, 'drop_indirect_deallocation', '41ffd7'),
    (0x14ce92e, 'iterator_remaining_load', '488b4640'),
    (0x14ce935, 'iterator_end_branch', '0f842e010000'),
    (0x14ce93b, 'iterator_remaining_decrement', '48ffc8'),
    (0x14ce93e, 'iterator_remaining_store', '48894640'),
    (0x14ce9fb, 'iterator_node_count', '0fb78f3e010000'),
)

# Prior work owns the enclosing visitors; these are handoff bytes only.
CONTEXT = (
    (0x13c791e, 'previous_name_leaf', 'c6400827', None),
    (0x13ad20e, 'binary_mode_argument', 'ba01000000', None),
    (0x13ad213, 'previous_binary_visitor_call', 'e868230100', 0x13bf580),
    (0x14a3bf9, 'previous_json_visitor_boundary', 'e8f2670100', 0x14ba3f0),
    (0x14ba46d, 'json_object_open', '83fe7b', None),
    (0x14ba470, 'json_nonobject_branch', '0f85d1030000', 0x14ba847),
    (0x14ba4da, 'json_key_reader_boundary', 'e841bdffff', 0x14b6220),
    (0x14ba560, 'json_colon_compare', '4883ff3a', None),
    (0x14ba564, 'json_bad_colon_branch', '0f85bf020000', 0x14ba829),
    (0x14ba577, 'json_value_diagnostic_length', 'b90c000000', None),
    (0x14ba584, 'json_value_diagnostic', '488d15f40ad6fe', 0x21b07f),
    (0x14ba58b, 'json_value_handoff', 'e850360000', 0x14bdbe0),
    (0x14ba5db, 'json_pair_insert_handoff', 'e8600b0100', 0x14cb140),
)

CFG = (
    ('json_length_check_required', 'json_ipv4_value', 0x14bdc9f, 0x14bdcc9, (0x14bdca3,), False),
    ('json_trailing_check_required', 'json_ipv4_value', 0x14bdcb4, 0x14bdcc9, (0x14bdcbf,), False),
    ('json_flag_check_required', 'json_ipv4_value', 0x14bdcb4, 0x14bdcc9, (0x14bdcc3,), False),
    ('text_length_check_required', 'binary_ipv4_text', 0x13b809a, 0x13b80ea, (0x13b809e,), False),
    ('text_trailing_check_required', 'binary_ipv4_text', 0x13b80b8, 0x13b80ea, (0x13b80c3,), False),
    ('text_flag_check_required', 'binary_ipv4_text', 0x13b80b8, 0x13b80ea, (0x13b80cb,), False),
    ('equal_key_can_replace', 'map_insert', 0x14cb227, 0x14cb268, (), True),
    ('equal_key_bypasses_increment', 'map_insert', 0x14cb227, 0x14cb387, (), False),
    ('empty_root_can_publish_and_increment', 'map_insert', 0x14cb328, 0x14cb387, (), True),
    ('empty_root_requires_allocation', 'map_insert', 0x14cb328, 0x14cb387, (0x14cb32b,), False),
    ('nonfull_leaf_can_store', 'map_insert_split', 0x1398481, 0x1398565, (), True),
    ('nonfull_leaf_bypasses_split_allocation', 'map_insert_split', 0x1398481, 0x13985b2, (), False),
    ('full_split_can_allocate', 'map_insert_split', 0x1398452, 0x13985b2, (), True),
    ('value_failure_can_drop_map', 'binary_ip_map', 0x13bfbb2, 0x13bfbf6, (), True),
    ('key_failure_can_drop_map', 'binary_ip_map', 0x13bfaea, 0x13bfb1e, (), True),
    ('map_depth_decrement_required', 'binary_ip_map', 0x13bf925, 0x13bf950, (0x13bf933,), False),
    ('map_depth_overflow_check_required', 'binary_ip_map', 0x13bfb8d, 0x13bfba3, (0x13bfb96,), False),
    ('parent_can_accept_split', 'map_insert_split', 0x13987cc, 0x1398cf2, (), True),
    ('full_parent_can_allocate', 'map_insert_split', 0x13987cc, 0x1398850, (), True),
    ('missing_parent_can_allocate_root', 'map_insert_split', 0x1398784, 0x1398c35, (), True),
    ('root_publish_requires_alloc_check', 'map_insert_split', 0x1398c35, 0x1398c7e, (0x1398c43,), False),
    ('root_publish_can_update_height', 'map_insert_split', 0x1398c7e, 0x1398c81, (), True),
)

CONTRACTS += (
    (0x13b6d09, 'raw_c4_cursor_load', '488b4610'),
    (0x13b6d14, 'raw_c4_header_short', '0f84b0010000'),
    (0x13b6d1d, 'raw_c4_length_byte', '0fb608'),
    (0x13b6d43, 'raw_c4_header_cursor_store', '48894610'),
    (0x13b6d4d, 'raw_payload_remaining_subtract', '4929c8'),
    (0x13b6d50, 'raw_payload_truncated', '0f8206020000'),
    (0x13b6d56, 'raw_payload_end', '4c8d0c08'),
    (0x13b6d5a, 'raw_payload_cursor_advance', '4c894e10'),
    (0x13b6d5e, 'raw_payload_remaining_store', '4c894618'),
    (0x13b6d6a, 'raw_payload_length_test', '4885c9'),
    (0x13b6fde, 'raw_missing_first_byte', '0f8546050000'),
    (0x13b700e, 'raw_missing_second_byte', '0f8529050000'),
    (0x13b703f, 'raw_missing_third_byte', '0f850b050000'),
    (0x13b706d, 'raw_missing_fourth_byte', '0f85f0040000'),
)

CFG += (
    ('raw_payload_can_reach_four_byte_success', 'binary_ipv4_other', 0x13b6d09, 0x13b7085, (), True),
    ('raw_payload_requires_length_bound', 'binary_ipv4_other', 0x13b6d09, 0x13b7085, (0x13b6d50,), False),
    ('raw_payload_requires_cursor_advance', 'binary_ipv4_other', 0x13b6d09, 0x13b7085, (0x13b6d5a,), False),
    ('raw_payload_requires_fourth_byte', 'binary_ipv4_other', 0x13b6d09, 0x13b7085, (0x13b706d,), False),
)

def section_one(view, name, kind):
    found = [s for s in view.sections if s['name'] == name and s['type'] == kind]
    require(len(found) == 1, 'missing or ambiguous selected section')
    return found[0]


def relocation_rows(view, slots):
    """Read symbol indices and names only for referenced relocation slots."""
    dynsym = section_one(view, '.dynsym', 11)
    dynstr = section_one(view, '.dynstr', 3)
    require(dynsym['size'] % 24 == 0, 'bad dynamic-symbol table')
    strings = view.data[dynstr['offset']:dynstr['offset'] + dynstr['size']]
    found = {}
    for sec in (s for s in view.sections if s['type'] == 4):
        require(sec['size'] % 24 == 0, 'partial RELA entry')
        for pos in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', view.data, pos)
            if slot not in slots:
                continue
            require(slot not in found, 'duplicate selected relocation')
            kind, symbol = info & 0xffffffff, info >> 32
            name = ''
            if symbol:
                require(symbol * 24 + 24 <= dynsym['size'], 'symbol out of range')
                name_off = struct.unpack_from('<I', view.data, dynsym['offset'] + symbol * 24)[0]
                require(name_off < len(strings), 'symbol name offset out of range')
                end = strings.find(b'\0', name_off)
                require(end >= 0, 'unterminated symbol name')
                name = strings[name_off:end].decode('ascii')
            found[slot] = (sec['name'], pos, kind, symbol, name, addend, view.data[pos:pos + 24].hex())
    return found


def hx(value):
    return '' if value is None else hex(value)


def exception_sites(view, all_fdes, functions, starts, call_rows):
    """Parse selected LSDA call sites; action/type semantics are not decoded."""
    sec = section_one(view, '.gcc_except_table', 1)
    known = sorted({f['lsda'] for f in all_fdes if f['lsda'] is not None})
    headers, rows = [], []
    for role, fde, _, _ in functions:
        address = fde['lsda']
        if address is None:
            continue
        upper = sec['address'] + sec['size']
        require(sec['address'] <= address < upper, 'LSDA outside section')
        following = [x for x in known if address < x < upper]
        if following:
            upper = following[0]
        raw = view.read(address, upper - address)
        require(len(raw) >= 4 and raw[0] == 0xff and raw[1] in (0xff, 0x9b), 'unsupported LSDA header')
        type_encoding = raw[1]
        pos, type_base = 2, None
        if type_encoding != 0xff:
            displacement, pos = uleb(raw, pos, len(raw))
            type_base = pos + displacement
            require(type_base <= len(raw), 'LSDA type base outside record')
        require(pos < len(raw) and raw[pos] == 1, 'unsupported call-site encoding')
        pos += 1
        length, pos = uleb(raw, pos, len(raw))
        table_end = pos + length
        require(table_end <= len(raw) and (type_base is None or table_end <= type_base), 'LSDA table outside record')
        headers.append((role, hx(address), hx(view.offset(address, 1)), hx(upper), raw[:pos].hex(), length, hx(type_encoding), '' if type_base is None else hx(address + type_base)))
        previous = 0
        while pos < table_end:
            begin = pos
            values = []
            for _ in range(4):
                item, pos = uleb(raw, pos, table_end)
                values.append(item)
            start, size, landing, action = values
            require(size > 0 and start >= previous and start + size <= fde['end'] - fde['start'], 'invalid LSDA call-site interval')
            first, last = fde['start'] + start, fde['start'] + start + size
            target = fde['start'] + landing if landing else None
            require(first in starts and (last in starts or last == fde['end']), 'LSDA interval not instruction aligned')
            require(target is None or (fde['start'] <= target < fde['end'] and target in starts), 'invalid LSDA landing')
            inside = ','.join(hx(r['va']) for r in call_rows if first <= r['va'] < last)
            rows.append((role, hx(address), hx(address + begin), raw[begin:pos].hex(), hx(first), hx(last), hx(target), action, inside))
            previous = start + size
        require(pos == table_end, 'truncated LSDA table')
    return headers, rows


def compare_keys(left, right):
    """Model the byte comparator's documented zero/sign and length contracts."""
    require(isinstance(left, bytes) and isinstance(right, bytes), 'key model requires bytes')
    prefix = min(len(left), len(right))
    for a, b in zip(left[:prefix], right[:prefix]):
        if a != b:
            return -1 if a < b else 1
    return (len(left) > len(right)) - (len(left) < len(right))


def value_gate(length, success, remaining, limit):
    """Conditional wrapper decision, with the IPv4 parser treated as a boundary."""
    require(all(type(x) is int for x in (length, success, remaining, limit)) and
            length >= 0 and success in (0, 1) and remaining >= 0 and limit >= 0, 'invalid gate model input')
    return length <= limit and success == 1 and remaining == 0


def c4_value_model(payload, declared):
    """Model c4 payload only after its marker was cached and mode is zero.

    `payload` excludes the length byte. The caller is assumed to have read that
    byte. Result is conditional on the literal code paths and no target execution.
    """
    require(isinstance(payload, bytes) and type(declared) is int and 0 <= declared <= 255, 'invalid c4 model input')
    if declared > len(payload):
        return ('short_payload', 0, len(payload), '')
    # The capture advances the outer cursor over the declared payload before
    # trying to read its four octets. The error constructor remains external.
    remaining = len(payload) - declared
    if declared < 4:
        return ('short_four_byte_value', declared, remaining, '')
    return ('success', declared, remaining, payload[:4].hex())


def map_header_model(data):
    """Model the fresh-marker path (cached state 1), not general map parsing."""
    require(isinstance(data, bytes), 'map header model requires bytes')
    if not data:
        return ('short_marker', 0, None)
    marker = data[0]
    if 0x80 <= marker < 0x90:
        return ('map_count', 1, marker & 0x0f)
    if marker not in (0xde, 0xdf):
        return ('other_route', 1, None)
    width = 2 if marker == 0xde else 4
    if len(data) - 1 < width:
        return ('short_count', len(data), None)
    return ('map_count', width + 1, int.from_bytes(data[1:width + 1], 'big'))


def map_depth_model(phase, value):
    """Model only the selected unsigned 16-bit depth guard and restore."""
    require(phase in ('enter', 'restore') and type(value) is int and 0 <= value <= 0xffff,
            'invalid depth model input')
    if phase == 'restore':
        return ('overflow_boundary', value) if value == 0xffff else ('continue', value + 1)
    if value == 0:
        return ('zero_depth_boundary', value)
    after = value - 1
    return ('return_tag_8', after) if after == 0 else ('continue', after)


def split_model(index, capacity, threshold, upper, pivot_low, pivot_mid, pivot_high):
    require(type(index) is int and 0 <= index <= capacity, 'insertion index out of model range')
    if index < threshold:
        return pivot_low, 0, index
    if index == threshold:
        return index, 0, index
    if index == upper:
        return pivot_mid, 1, 0
    return pivot_high, 1, index - (upper + 1)


def tsv_bytes(header, rows):
    output = io.StringIO(newline='')
    writer = csv.writer(output, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return output.getvalue().encode('utf-8')

def inspect(data, authenticate=True):
    if authenticate:
        verify_identity(data)
    view = View(data)
    all_fdes, functions = load_functions(view)
    by_role = {role: rows for role, _, rows, _ in functions}
    indexed = {row['va']: (role, row) for role, _, rows, _ in functions for row in rows}
    require(len(indexed) == sum(len(rows) for _, _, rows, _ in functions), 'overlapping decoded ranges')
    starts = set(indexed)
    function_rows, instructions, branches, transfers, references = [], [], [], [], []
    calls = []
    for role, fde, rows, digest in functions:
        function_rows.append((role, hx(fde['start']), hx(fde['end']), hx(view.offset(fde['start'], 1)),
                              fde['end'] - fde['start'], hx(fde['fde']), hx(fde['cie']), hx(fde['lsda']), len(rows), digest))
        for row in rows:
            address, end = row['va'], row['end']
            instructions.append((role, hx(address), hx(view.offset(address, end - address)), end - address,
                                 row['bytes'].hex(), row['kind'], hx(row['target'])))
            if row['kind'] in ('conditional', 'jump'):
                branches.append((role, hx(address), row['bytes'].hex(), row['kind'], hx(row['target']),
                                 hx(end) if row['kind'] == 'conditional' else ''))
            if row['kind'] in ('call', 'indirect_call', 'indirect_jump'):
                fallthrough = '' if row['kind'] == 'indirect_jump' else hx(end)
                transfers.append((role, hx(address), row['bytes'].hex(), row['kind'], hx(row['target']), fallthrough))
                if row['kind'] != 'indirect_jump':
                    calls.append(row)
            if row['rip_relative']:
                references.append((role, hx(address), row['bytes'].hex(), hx(row['target']), row['kind']))
    contract_rows = []
    for address, label, expected in CONTRACTS:
        require(address in indexed, 'contract is not a selected instruction')
        role, row = indexed[address]
        require(row['bytes'].hex() == expected, 'instruction contract mismatch: ' + label)
        contract_rows.append((label, role, hx(address), hx(view.offset(address, len(row['bytes']))), row['bytes'].hex(),
                              row['kind'], hx(row['target'])))
    anchor_rows = []
    for address, label, expected, expected_target in CONTEXT:
        raw = view.read(address, len(bytes.fromhex(expected)))
        require(raw.hex() == expected, 'context byte mismatch: ' + label)
        row = decode_one(raw, 0, address)
        require(row['end'] == address + len(raw), 'context instruction length mismatch')
        require(row['target'] == expected_target, 'context target mismatch')
        anchor_rows.append((label, hx(address), hx(view.offset(address, len(raw))), len(raw), raw.hex(), hx(row['target'])))
    for label, address, literal in (('field_name', 0x21bc13, b'internal_ips'), ('value_diagnostic', 0x21b07f, b'IPv4 address')):
        raw = view.read(address, len(literal))
        require(raw == literal, 'diagnostic or field name changed')
        anchor_rows.append((label, hx(address), hx(view.offset(address, len(raw))), len(raw), raw.hex(), ''))
    table_base, tag_base, field_tag = 0x20faa0, 0x16, view.read(0x13c791e, 4)[3]
    cell = table_base + 4 * (field_tag - tag_base)
    require(field_tag == 0x27 and cell == 0x20fae4, 'field dispatch index changed')
    data4 = view.read(cell, 4)
    target = table_base + struct.unpack('<i', data4)[0]
    require(target == 0x13ad1e4, 'binary field arm mismatch')
    anchor_rows.append(('previous_binary_field_table', hx(cell), hx(view.offset(cell, 4)), 4, data4.hex(), hx(target)))
    table_rows = []
    for name, base, count, owner, digest in TABLES:
        raw = view.read(base, 4 * count)
        require(hashlib.sha256(raw).hexdigest() == digest, 'dispatch table bytes mismatch: ' + name)
        owned_starts = {r['va'] for r in by_role[owner]}
        for index in range(count):
            word = raw[4 * index:4 * index + 4]
            destination = base + struct.unpack('<i', word)[0]
            require(destination in owned_starts, 'dispatch target is not a selected instruction start')
            table_rows.append((name, index, hx(base + index * 4), hx(view.offset(base + index * 4, 4)), word.hex(), hx(destination)))
    state_c4 = [r for r in table_rows if r[0] == 'other_state' and r[1] == 0xc4]
    require(len(state_c4) == 1 and state_c4[0][-1] == hx(0x13b6d09), 'c4 dispatch target mismatch')
    map_markers = {r[1]: r[-1] for r in table_rows if r[0] == 'map_marker_c0_df'}
    require(map_markers[0x1e] == hx(0x13bf718) and map_markers[0x1f] == hx(0x13bf6c0),
            'map header dispatch target mismatch')
    cfg_rows = []
    for label, role, source, destination, forbidden, expected in CFG:
        observed = reachable(by_role[role], source, destination, forbidden)
        require(observed == expected, 'CFG expectation mismatch: ' + label)
        cfg_rows.append((label, role, hx(source), hx(destination), ','.join(hx(v) for v in forbidden), str(observed).lower()))
    slot_set = {r['target'] for r in calls if r['kind'] == 'indirect_call' and r['rip_relative'] and r['target'] is not None}
    slots = relocation_rows(view, slot_set)
    relocation_output = []
    for slot in sorted(slot_set):
        entry = slots.get(slot)
        if entry is None:
            relocation_output.append((hx(slot), '', '', '', '', '', '', ''))
        else:
            section, pos, kind, symbol, name, addend, raw = entry
            relocation_output.append((hx(slot), section, hx(pos), kind, symbol, name, hx(addend), raw))
    # Assert key imported comparisons, including the symbol rather than guessing.
    require(0x576e488 in slots and slots[0x576e488][4] == 'memcmp', 'key comparison relocation mismatch')
    lsda_headers, exceptions = exception_sites(view, all_fdes, functions, starts, calls)
    gate_limit = view.read(0x14bdc9f, 4)[3]
    require(gate_limit == view.read(0x13b809a, 4)[3] == 15, 'IPv4 text limits disagree')
    gate_rows = []
    for length in (0, gate_limit - 1, gate_limit, gate_limit + 1):
        for success in (0, 1):
            for tail in (0, 1):
                gate_rows.append((length, success, tail, gate_limit, str(value_gate(length, success, tail, gate_limit)).lower()))
    payload_cases = []
    example = bytes(range(1, 9))
    for declared in range(0, 10):
        result, consumed, remain, value = c4_value_model(example, declared)
        payload_cases.append((declared, example.hex(), result, consumed, remain, value))
    for n in (0, 1, 2, 3, 4, 5):
        payload = bytes(range(1, n + 1))
        result, consumed, remain, value = c4_value_model(payload, 4)
        payload_cases.append((4, payload.hex(), result, consumed, remain, value))
    # These are conditional finite models after the cached-state=1 dispatch.
    header_examples = ([b''] + [bytes((marker,)) for marker in range(0x80, 0x90)] +
                       [bytes((marker,)) for marker in (0x7f, 0x90, 0x9f, 0xa0, 0xc0, 0xdd, 0xe0, 0xff)] +
                       [b'\xde', b'\xde\x00', b'\xde\x00\x00', b'\xde\xff\xff\xaa',
                        b'\xdf', b'\xdf\x00', b'\xdf\x00\x00', b'\xdf\x00\x00\x00',
                        b'\xdf\x00\x00\x00\x00', b'\xdf\xff\xff\xff\xff\xaa'])
    header_rows = []
    for example in header_examples:
        outcome, consumed, count = map_header_model(example)
        header_rows.append((example.hex(), outcome, consumed, '' if count is None else count))
    depth_rows = []
    for phase in ('enter', 'restore'):
        for value in (0, 1, 2, 0xfffe, 0xffff):
            outcome, after = map_depth_model(phase, value)
            depth_rows.append((phase, value, outcome, after))
    capacity = view.read(0x1398452, 4)[3]
    threshold = view.read(0x139845c, 4)[3]
    upper = view.read(0x13984b7, 4)[3]
    low = int.from_bytes(view.read(0x1398474, 5)[1:], 'little')
    mid = int.from_bytes(view.read(0x13984c1, 5)[1:], 'little')
    high = int.from_bytes(view.read(0x1398591, 5)[1:], 'little')
    require((capacity, threshold, upper, low, mid, high) == (11, 5, 6, 4, 5, 6), 'split thresholds changed')
    split_rows = []
    for index in range(capacity + 1):
        pivot, side, local = split_model(index, capacity, threshold, upper, low, mid, high)
        split_rows.append((index, capacity, pivot, side, local))
    key_cases = ((b'', b''), (b'a', b'a'), (b'a', b'aa'), (b'aa', b'a'), (b'a', b'b'), (b'b', b'a'),
                 (b'NODE', b'node'), (b'a\0b', b'a\0c'), (b'\x80', b'\x7f'), (b'\xff', b'\0'))
    key_rows = [(a.hex(), b.hex(), compare_keys(a, b)) for a, b in key_cases]
    summary = {
        'schema_version': 1,
        'artifact': 'artifacts/node/94/hl-node',
        'artifact_size': len(data), 'artifact_sha256': hashlib.sha256(data).hexdigest(),
        'selected_fdes': len(function_rows), 'selected_bytes': sum(f['end'] - f['start'] for _, f, _, _ in functions),
        'linear_instructions': len(instructions), 'direct_branches_and_jumps': len(branches),
        'transfers': len(transfers), 'rip_relative_references': len(references),
        'byte_contracts': len(contract_rows), 'context_anchors': len(anchor_rows),
        'dispatch_words': len(table_rows), 'dispatch_tables': len(TABLES),
        'relocation_slots': len(relocation_output), 'lsda_headers': len(lsda_headers),
        'lsda_call_sites': len(exceptions), 'normal_flow_propositions': len(cfg_rows),
        'gate_model_cases': len(gate_rows), 'raw_c4_model_cases': len(payload_cases),
        'map_header_model_cases': len(header_rows), 'map_depth_model_cases': len(depth_rows),
        'split_model_cases': len(split_rows), 'key_comparison_model_cases': len(key_rows),
        'limits': 'Static linear instruction decoding and conditional models only. FDE extents are not a complete function census. Indirect calls and exception actions remain boundaries.'
    }
    return {
        'summary.json': (json.dumps(summary, indent=2, sort_keys=True) + '\n').encode(),
        'functions.tsv': tsv_bytes(('role','start_va','end_va_exclusive','file_offset','size','fde_va','cie_va','lsda_va','linear_instructions','sha256'), function_rows),
        'instructions.tsv': tsv_bytes(('role','va','file_offset','size','bytes','kind','target_va'), instructions),
        'branches.tsv': tsv_bytes(('role','site_va','bytes','kind','target_va','fallthrough_va'), branches),
        'transfers.tsv': tsv_bytes(('role','site_va','bytes','kind','target_va','fallthrough_va'), transfers),
        'rip-references.tsv': tsv_bytes(('role','site_va','bytes','target_va','kind'), references),
        'contracts.tsv': tsv_bytes(('label','role','va','file_offset','bytes','kind','target_va'), contract_rows),
        'prior-handoffs.tsv': tsv_bytes(('label','va','file_offset','size','bytes','target_va'), anchor_rows),
        'dispatch-tables.tsv': tsv_bytes(('table','index','entry_va','file_offset','raw','target_va'), table_rows),
        'relocations.tsv': tsv_bytes(('slot_va','section','record_file_offset','type','symbol_index','symbol_name','addend','record_bytes'), relocation_output),
        'lsda-headers.tsv': tsv_bytes(('role','lsda_va','file_offset','exclusive_bound_va','header_bytes','table_size','type_encoding','type_base_va'), lsda_headers),
        'lsda-sites.tsv': tsv_bytes(('role','lsda_va','entry_va','bytes','start_va','end_va_exclusive','landing_va','action_raw','calls_in_range'), exceptions),
        'cfg.tsv': tsv_bytes(('claim','role','from_va','to_va','forbidden_va','reachable_assuming_calls_return'), cfg_rows),
        'text-gate-cases.tsv': tsv_bytes(('length','parser_success','remaining','limit','accepted_if_assumptions_hold'), gate_rows),
        'raw-c4-cases.tsv': tsv_bytes(('declared_length','available_payload_hex','outcome','payload_bytes_consumed','outer_remaining','stored_octets'), payload_cases),
        'map-header-cases.tsv': tsv_bytes(('input_hex','outcome','header_bytes_consumed','map_count'), header_rows),
        'map-depth-cases.tsv': tsv_bytes(('phase','input_u16','outcome','depth_after'), depth_rows),
        'split-index-cases.tsv': tsv_bytes(('insertion_index','full_node_count','pivot_index','right_side_flag','local_index'), split_rows),
        'key-order-cases.tsv': tsv_bytes(('left_hex','right_hex','modeled_sign'), key_rows),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    data = ARTIFACT.read_bytes()
    verify_identity(data)
    outputs = inspect(data, authenticate=False)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(outputs.items()):
        (args.out / name).write_bytes(content)
    print('wrote', len(outputs), 'evidence files')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, struct.error) as error:
        print('config_ipv4_map94:', error, file=sys.stderr)
        raise SystemExit(1)
