#!/usr/bin/env python3
"""Reproduce static node 94 evidence for the EVM-to-L1 remaining ledger."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/94/hl-node'
# Addresses are linked ELF VAs and are discovery seeds, not file offsets.
FUNCTIONS = {
    'named_field_writer': 0x27b4450,
    'map_writer': 0x25ebac0,
    'tree_pointer_collector': 0x2566dd0,
    'array_writer': 0x1e15cb0,
    'pair_writer': 0x1dd3870,
    'buffered_pair_writer': 0x1e025a0,
    'alternate_named_writer': 0x3798960,
    'alternate_map_writer': 0x360b8f0,
    'alternate_tree_pointer_collector': 0x3bcb9f0,
    'alternate_array_writer': 0x3203ee0,
    'alternate_pair_writer': 0x31ca400,
    'json_field_writer': 0x295aeb0,
    'json_map_writer': 0x25df960,
    'json_array_writer': 0x2919ea0,
    'json_unsigned_decimal': 0x27869f0,
    'alternate_json_field_writer': 0x3c87920,
    'alternate_json_map_writer': 0x3612a80,
    'alternate_json_array_writer': 0x3c767b0,
}
# Fixed instruction windows. The interpretation is scoped to these checked bytes.
ANCHORS = {
 'field_context': (0x275b67a, '498d96503a00004889e74c89fee8c48d0500'),
 'hash_context': (0x281ac15, 'c744240800040001c644240c00488b36488dbc24080100004889e2e88b0eddff'),
 'named_gate': (0x27b445b, '807e0b007420'),
 'named_field': (0x27b4461, '488d3504b2c3fdba1f000000'),
 'tail_jump': (0x27b448c, 'e92f76e3ff'),
 'named_failure': (0x27b447b, '4883f8027510'),
 'map_empty': (0x25ebacf, '488b0e4885c97435488b'),
 'iter_call': (0x25ebb2a, 'e8a1b2f7ff'),
 'array_call': (0x25ebb38, 'e873a182ff'),
 'allocation': (0x2566dd8, '4c8b66404d89e749c1e7044c89e048c1e83c0f95c048b9f8ffffffffffff7f4939cf0f97c108c1'),
 'collector_size_guard': (0x2566dfd, '08c1740b31ff4c89feff15ac712003'),
 'collector_null': (0x2566e2c, '4885c00f845e020000'),
 'zero_allocation': (0x2566e3f, 'bb080000004531f64d85e40f840b020000'),
 'entry_pointers': (0x2566e70, '4c8d42014c89ce48ffc94c8d14924f8d14914983c260498d14d14883c2084989c149c1e1044e89140b4a89540b0848ffc041b1014c89'),
 'tree_count': (0x2566ec0, '4885f6741b440fb78e3e0100004c39ca0f83ba000000'),
 'array_threshold': (0x1e15cd1, '4c89f048c1e8200f94c1807e0c00410f95c44120cc7418'),
 'array_large_branch': (0x1e15d00, '4c89ed4885c00f85f6000000'),
 'array_large_allocation': (0x1e15e02, 'bf80000000ff15cb819503'),
 'array_header_result': (0x1e15d1c, '488b4424404883f8020f85b3000000'),
 'array_header': (0x1e15d0c, '488d7c24404c89fe4489f2e8b43e7900'),
 'array_loop': (0x1e15e90, '488b5500488b4d084c89f74c89fee8cdd9fbff488b4424404839d80f85dffeffff4883c5104c39ed75d6'),
 'pair_gate': (0x1dd3891, '4d8d6c24fc4c392e75104d8b7f2841807f0c02753e4531edeb'),
 'pair_header': (0x1dd38e4, '4889d5488d7c24084c89feba02000000e8d7627d00488b4424'),
 'pair_header_result': (0x1dd38f9, '488b4424084883f8020f85b6000000'),
 'pair_key': (0x1dd3927, 'c744244002000000488d7c2408488d742420e8629703004c396424'),
 'pair_value': (0x1dd3945, '488d7c2408488d7424204c89f2e839a803004c39642408'),
 'pair_error': (0x1dd396d, '488b442418488943100f104424080f1103488b742420488d0475000000004885c0743e488b7c'),
 'buffer_pair': (0x1e025c0, '80791c02750431c0eb21488b71104839310f84ba000000488b4108c604309248ffc648897110498d4424fc'),
 'buffer_key': (0x1e0260f, '4889e7488d742418e8a4b000004c39242475'),
 'buffer_value': (0x1e02622, '4889e7488d7424184c89f2e8febd00004c39'),
 'key_format_args': (0x1e0d174, '0f57c00f1144243a0f294424300f29442420488d7c2420be2a000000b9140000004531c0ff15825f96034c89f74889'),
 'value_arg': (0x1e0e25f, '488b124889e74c89f6e863de7900'),
 'alternate_map_iter': (0x360b95a, 'e891005c00'),
 'alternate_map_array': (0x360b968, 'e87385bfff'),
 'alternate_array_threshold': (0x3203f01, '4c89f048c1e8200f94c1807e0c00410f95c44120cc7418'),
 'alternate_array_loop': (0x32040c0, '488b5500488b4d084c89f74c89fee82d63fcff488b4424404839d80f85dffeffff4883c5104c39ed75d6'),
 'alternate_pair_gate': (0x31ca421, '4d8d6c24fc4c392e75104d8b7f2841807f0c02753e4531edeb'),
 'alternate_pair_header': (0x31ca474, '4889d5488d7c24084c89feba02000000e897e93c00488b4424'),
 'alternate_pair_key': (0x31ca4b7, 'c744244002000000488d7c2408488d742420e8922a03004c396424'),
 'alternate_pair_value': (0x31ca4d5, '488d7c2408488d7424204c89f2e8694803004c39642408'),
 'alternate_pair_error': (0x31ca4fd, '488b442418488943100f104424080f1103488b742420488d0475000000004885c0743e488b7c'),
 'alternate_collector': (0x3bcb9f9, '4c8b7e404d89fe49c1e6044c89f848c1e83c0f95c048b9f8ffffffffffff7f4939ce0f97c108c1'),
 'json_field_context': (0x275c07b, '488d8b503a0000488d35e335c9fd4889e7ba1f000000e81aee1f00'),
 'json_field_header': (0x295aeb5, '4889cb4989fee8d092010041803e0174'),
 'json_value': (0x295aeef, '4889df4c89f6e8664ac8ff4885c074065b'),
 'json_iter': (0x25df9bf, '488d7424204c89f7e80474f8ff4889df4c89f6e8c9a43300'),
 'json_open': (0x2919ee0, '498b460842c604385b49ffc74d897e104885ed0f84'),
 'json_pair_open': (0x291a054, '488b450842c604305b49ffc64c8975'),
 'json_key_args': (0x291a0e0, '0f57c00f1144244a0f294424400f29442430be2a000000b914000000488d7c2430488b5424284c8b6424104d89e0e87d85ecff'),
 'json_u64': (0x291a1c0, '488b442420488b384c8b6c24104d8b7500488d742430e815c8e6ff'),
 'json_close_pair': (0x291a2b2, '18498b470842c604305d49ffc64d89'),
 'json_close_outer': (0x291a4cb, '51498b460842c604385d49ffc74d89'),
 'decimal_start': (0x27869f0, '53b8140000004881ff102700000f82aa0000'),
 'decimal_single': (0x2786a9a, '4883fa0a734d48ffc8707380ca30881406'),
 'alternate_field_context': (0x3753e0a, '498d96301f00004889e74c89fee8444b0400'),
 'alternate_json_context': (0x37533bb, '488d8b301f0000488d352357e4fc4889e7ba1f000000e84a455300'),
 'alternate_json_field': (0x3c87925, '4889cb4989fee89070010041803e0174'),
 'alternate_json_value': (0x3c8795f, '4889df4c89f6e816b198ff4885c074065b'),
 'alternate_json_iter': (0x3612adf, '488d7424204c89f7e8048f5b004889df4c89f6e8b93c6600'),
 'alternate_json_array_open': (0x3c767f0, '498b460842c604385b49ffc74d897e104885ed0f84'),
 'alternate_json_pointer_pair': (0x3c76830, '488b114889542428488b51084889542420'),
 'copy_field': (0x3798971, '488d357401e0fcba1f000000'),
 'copy_tail': (0x379899c, 'e94f2fe7ff'),
 'u64_fixint_limit': (0x25ac100, '84d20f8813010000'),
 'array_be16': (0x25a9cde, '89f866c1c008498b4e0866'),
 'array_be32': (0x25a9d2b, '488b5c240889f80fc8498b4e'),
 'str8': (0x25aa81f, '81fa00010000731440b5d9'),
 'format_return': (0x1e0d198, 'ff15825f96034c89f74889c6e847d6790048'),
 'u64_threshold_8': (0x25ac0e0, '4881fa000100007346'),
 'u64_threshold_16': (0x25ac12f, '4881fa000001007324'),
 'u64_threshold_32': (0x25ac15c, '4889d048c1e8207524'),
 'u64_marker_8': (0x25ac224, '498b4608c60430cc'),
 'u64_marker_16': (0x25ac5a3, '488b4f08c60401cd'),
 'u64_marker_32': (0x25ac7d3, '488b4f08c60401ce'),
 'u64_marker_64': (0x25aca04, '488b4f08c60401cf'),
 'u64_big_endian_16': (0x25ac639, '66c1c608488b4f0866893401'),
 'u64_big_endian_32': (0x25ac869, '0fce488b470842893408'),
 'u64_big_endian_64': (0x25aca9c, '480fce488b47084a893408'),
 'array_markers': (0x25a9bde, '81fa000001000f92c034dd83fa100fb6c0bd90000000'),
 'marker_dispatch': (0x25acc20, '89f80fb6c88d9140ffffff83fa207301c381f98f0000007e1b81f990000000742281f9a00000007508'),
 'array_fix_marker': (0x25acc63, '4080e60f4080ce9089f0c3'),
 'str8_length_store': (0x25aa943, '498b410844883c38bf01000000'),
 'string_markers': (0x25aa803, '488b1f83fa20731440b5a0'),
}

class View:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
    def read(self, va, length, executable=False):
        if not isinstance(va, int) or not isinstance(length, int) or va < 0 or length <= 0:
            raise ValueError('invalid address or size')
        found = [s for s in self.sections if s['type'] != 8 and s['address'] <= va
                 and va + length <= s['address'] + s['size'] and (not executable or s['flags'] & 4)]
        if len(found) != 1:
            raise ValueError('address not uniquely file-backed')
        sec = found[0]
        off = sec['offset'] + va - sec['address']
        return self.data[off:off + length]
    def offset(self, va, length):
        self.read(va, length)
        s = next(s for s in self.sections if s['type'] != 8 and s['address'] <= va and va + length <= s['address'] + s['size'])
        return s['offset'] + va - s['address']


def verify_identity(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        raise ValueError('node 94 SHA-256 mismatch')
    return digest


def check_windows(view):
    result = []
    for label, (address, expected) in ANCHORS.items():
        actual = view.read(address, len(expected) // 2, executable=True)
        if actual.hex() != expected:
            raise ValueError('instruction window mismatch: ' + label)
        result.append({'label': label, 'va': hex(address), 'file_offset': hex(view.offset(address, len(actual))), 'bytes': actual.hex()})
    return result


def rel32(view, va, opcode):
    raw = view.read(va, 5, executable=True)
    if raw[0] != opcode:
        raise ValueError('unexpected branch opcode')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def rel8(view, va, opcode):
    raw = view.read(va, 2, executable=True)
    if raw[0] != opcode:
        raise ValueError('unexpected short-branch opcode')
    return va + 2 + struct.unpack_from('<b', raw, 1)[0]


def reljcc32(view, va, opcode):
    raw = view.read(va, 6, executable=True)
    if raw[:2] != bytes((0x0f, opcode)):
        raise ValueError('unexpected conditional-branch opcode')
    return va + 6 + struct.unpack_from('<i', raw, 2)[0]


def rip_lea(view, va):
    raw = view.read(va, 7, executable=True)
    if raw[:3] != b'\x48\x8d\x35':
        raise ValueError('unexpected field reference')
    return va + 7 + struct.unpack_from('<i', raw, 3)[0]


def require_equal(actual, expected, label):
    if actual != expected:
        raise ValueError(label + ' mismatch')
    return actual


def encode_u64(n):
    if type(n) is not int or not 0 <= n < 1 << 64:
        raise ValueError('value outside u64')
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0xcc, n])
    if n < 0x10000:
        return b'\xcd' + n.to_bytes(2, 'big')
    if n < 1 << 32:
        return b'\xce' + n.to_bytes(4, 'big')
    return b'\xcf' + n.to_bytes(8, 'big')


def encode_array_header(n):
    if type(n) is not int or not 0 <= n < 1 << 32:
        raise ValueError('count outside selected u32 domain')
    if n < 16:
        return bytes([0x90 | n])
    if n < 0x10000:
        return b'\xdc' + n.to_bytes(2, 'big')
    return b'\xdd' + n.to_bytes(4, 'big')


def encode_rows(rows):
    # Caller provides traversal order. This model does not sort or run the ELF.
    out = bytearray(encode_array_header(len(rows)))
    for address, amount in rows:
        if not isinstance(address, bytes) or len(address) != 20:
            raise ValueError('address must be exactly 20 bytes')
        key = b'0x' + address.hex().encode('ascii')
        out += b'\x92\xd9\x2a' + key + encode_u64(amount)
    return bytes(out)


def resolve_relative(view, slot):
    rs = [s for s in view.sections if s['name'] == '.rela.dyn' and s['type'] != 8]
    if len(rs) != 1 or rs[0]['size'] % 24:
        raise ValueError('invalid relocation section')
    sec = rs[0]
    slots = []
    for pos in range(sec['offset'], sec['offset'] + sec['size'], 24):
        off, info, addend = struct.unpack_from('<QQq', view.data, pos)
        if off == slot:
            slots.append((info, addend))
    require_equal(len(slots), 1, 'formatter relocation count')
    require_equal(slots[0][0], 8, 'formatter relocation type')
    return slots[0][1]


def analyze(data):
    digest = verify_identity(data)
    view = View(data)
    windows = check_windows(view)
    _, records = eh_frame_records(data, view.sections)
    bodies = []
    for label, start in FUNCTIONS.items():
        matches = [r for r in records if r['start'] == start]
        if len(matches) != 1:
            raise ValueError('ambiguous or absent FDE: ' + label)
        fde = matches[0]
        code = view.read(start, fde['end'] - start, executable=True)
        bodies.append({'role': label, 'start_va': hex(start), 'end_va_exclusive': hex(fde['end']),
                       'file_offset': hex(view.offset(start, len(code))), 'size': len(code),
                       'fde_va': hex(fde['fde']), 'sha256': hashlib.sha256(code).hexdigest()})
    edges = []
    for label, site, opcode, destination in (
        ('named field to map', 0x27b448c, 0xe9, FUNCTIONS['map_writer']),
        ('map to tree collector', 0x25ebb2a, 0xe8, FUNCTIONS['tree_pointer_collector']),
        ('map to array writer', 0x25ebb38, 0xe8, FUNCTIONS['array_writer']),
        ('array to pair, first', 0x1e15d6f, 0xe8, FUNCTIONS['pair_writer']),
        ('array to pair, loop', 0x1e15e9e, 0xe8, FUNCTIONS['pair_writer']),
        ('pair to buffered pair', 0x1dd38b9, 0xe8, FUNCTIONS['buffered_pair_writer']),
        ('alternate field to map', 0x379899c, 0xe9, FUNCTIONS['alternate_map_writer']),
        ('alternate map to collector', 0x360b95a, 0xe8, FUNCTIONS['alternate_tree_pointer_collector']),
        ('alternate map to array', 0x360b968, 0xe8, FUNCTIONS['alternate_array_writer']),
        ('alternate array to pair, first', 0x3203f9f, 0xe8, FUNCTIONS['alternate_pair_writer']),
        ('alternate array to pair, loop', 0x32040ce, 0xe8, FUNCTIONS['alternate_pair_writer']),
        ('JSON field to map', 0x295aef5, 0xe8, FUNCTIONS['json_map_writer']),
        ('JSON map to collector', 0x25df9c7, 0xe8, FUNCTIONS['tree_pointer_collector']),
        ('JSON map to array', 0x25df9d2, 0xe8, FUNCTIONS['json_array_writer']),
        ('JSON array to decimal', 0x291a1d6, 0xe8, FUNCTIONS['json_unsigned_decimal']),
        ('alternate JSON field to map', 0x3c87965, 0xe8, FUNCTIONS['alternate_json_map_writer']),
        ('alternate JSON map to collector', 0x3612ae7, 0xe8, FUNCTIONS['alternate_tree_pointer_collector']),
        ('alternate JSON map to array', 0x3612af2, 0xe8, FUNCTIONS['alternate_json_array_writer']),
    ):
        target = require_equal(rel32(view, site, opcode), destination, label)
        edges.append({'role': label, 'site_va': hex(site), 'target_va': hex(target),
                      'bytes': view.read(site, 5, executable=True).hex()})
    field_address = rip_lea(view, 0x27b4461)
    field_length = struct.unpack('<I', view.read(0x27b4469, 4, True))[0]
    field = view.read(field_address, field_length)
    require_equal(field, b'user_to_evm_to_l1_wei_remaining', 'field')
    alternate = rip_lea(view, 0x3798971)
    alternate_length = struct.unpack('<I', view.read(0x3798979, 4, True))[0]
    require_equal(view.read(alternate, alternate_length), field, 'alternate field')
    displacement = struct.unpack('<i', view.read(0x275b67d, 4, True))[0]
    require_equal(displacement, 0x3a50, 'state offset')
    require_equal(rel32(view, 0x275b687, 0xe8), FUNCTIONS['named_field_writer'], 'state field call')
    require_equal(rel32(view, 0x281ac30, 0xe8), FUNCTIONS['map_writer'], 'hash input call')
    require_equal(rel32(view, 0x275c091, 0xe8), FUNCTIONS['json_field_writer'], 'JSON field call')
    require_equal(rip_lea(view, 0x275c082), field_address, 'JSON field text')
    alternate_offset = struct.unpack('<i', view.read(0x3753e0d, 4, True))[0]
    require_equal(alternate_offset, 0x1f30, 'alternate state offset')
    require_equal(struct.unpack('<i', view.read(0x37533be, 4, True))[0], alternate_offset, 'alternate JSON offset')
    require_equal(rip_lea(view, 0x37533c2), alternate, 'alternate JSON field text')
    require_equal(rel32(view, 0x3753e17, 0xe8), FUNCTIONS['alternate_named_writer'], 'alternate state field call')
    require_equal(rel32(view, 0x37533d1, 0xe8), FUNCTIONS['alternate_json_field_writer'], 'alternate JSON field call')
    branches = []
    for role, va, opcode in (('named mode zero bypasses key',0x27b445f,0x74),
                             ('key writer failure',0x27b447f,0x75),
                             ('tree root absent',0x25ebad5,0x74),
                             ('collector size valid',0x2566dff,0x74),
                             ('pair key failure',0x1dd3943,0x75),
                             ('pair value failure',0x1dd395c,0x75),
                             ('alternate pair key failure',0x31ca4d3,0x75),
                             ('alternate pair value failure',0x31ca4ec,0x75),
                             ('JSON invalid field state',0x295aec4,0x74),
                             ('JSON value success',0x295aefd,0x74),
                             ('alternate JSON field tag 1',0x3c87934,0x74),
                             ('alternate JSON value success',0x3c8796d,0x74)):
        branches.append({'role':role, 'site_va':hex(va), 'target_va':hex(rel8(view, va, opcode))})
    for role, va, opcode in (('collector allocation null', 0x2566e2f, 0x84),
                             ('array count exceeds u32', 0x1e15d06, 0x85),
                             ('outer header failure', 0x1e15d25, 0x85),
                             ('pair header failure', 0x1dd3902, 0x85)):
        branches.append({'role':role, 'site_va':hex(va), 'target_va':hex(reljcc32(view, va, opcode))})
    # Read the relocation without conflating repeated slots.
    target = resolve_relative(view, 0x5773120)
    require_equal(target, 0x29ed380, 'formatter relocation addend')
    require_equal(view.read(0x208620, 16), b'0123456789abcdef', 'hex alphabet')
    digits = view.read(0x3f02cd, 200)
    require_equal(digits, b''.join(str(i).zfill(2).encode('ascii') for i in range(100)), 'decimal digit table')
    summary = {'binary_sha256': digest, 'coordinate_system': 'linked ELF virtual addresses; ends exclusive',
      'field': {'name': field.decode('ascii'), 'address':hex(field_address), 'length':len(field),
                'alternate_address':hex(alternate), 'state_offset':hex(displacement),
                'alternate_state_offset':hex(alternate_offset)},
      'format_call': {'site_va':hex(0x1e0d198), 'slot_va':hex(0x5773120),
                      'target_va':hex(target), 'input_bytes':struct.unpack('<I', view.read(0x1e0d191,4,True))[0],
                      'output_capacity':struct.unpack('<I', view.read(0x1e0d18c,4,True))[0], 'mode':view.read(0x1e0d195,3,True).hex()},
      'hex_alphabet': {'address':hex(0x208620), 'bytes':view.read(0x208620, 16).decode('ascii')},
      'decimal_pairs': {'address':hex(0x3f02cd), 'bytes':digits.decode('ascii')},
      'functions': bodies, 'edges':edges, 'branches':branches,
      'limitations':'Static windows only; no target execution, tree order proof, full decoder, full hash or component identity.'}
    return summary, windows


def write_tsv(path, headings, rows):
    with path.open('w', encoding='utf-8', newline='') as f:
        w = csv.writer(f, delimiter='\t', lineterminator='\n')
        w.writerow(headings)
        w.writerows(rows)


def generate(data, out):
    summary, windows = analyze(data)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'records.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    write_tsv(out / 'windows.tsv', ('label','va','file_offset','bytes'),
              ((x['label'], x['va'], x['file_offset'], x['bytes']) for x in windows))
    # Synthetic boundary examples, not executions of the target. Zero address isolates the amount.
    view = View(data)
    u8_end = struct.unpack('<I', view.read(0x25ac0e3, 4, True))[0]
    u16_end = struct.unpack('<I', view.read(0x25ac132, 4, True))[0]
    u32_end = 1 << view.read(0x25ac162, 1, True)[0]
    fixint_end = u8_end // 2
    values = [0, fixint_end - 1, fixint_end, u8_end - 1, u8_end,
              u16_end - 1, u16_end, u32_end - 1, u32_end, (u32_end * u32_end) - 1]
    write_tsv(out / 'examples.tsv', ('case','address_hex','amount','modeled_bytes'),
              (('one_row', '00' * 20, n, encode_rows([(bytes(20), n)]).hex()) for n in values))
    array16 = view.read(0x25a9beb, 1, True)[0]
    array32 = struct.unpack('<I', view.read(0x25a9be0, 4, True))[0]
    sizes = [0, 1, array16 - 1, array16, array32 - 1, array32, (1 << 32) - 1]
    write_tsv(out / 'count-headers.tsv', ('synthetic_count','modeled_header'),
              ((n, encode_array_header(n).hex()) for n in sizes))
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    generate(BINARY.read_bytes(), a.out)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as e:
        print('evm_l1_remaining94: ' + str(e), file=sys.stderr)
        raise SystemExit(1)
