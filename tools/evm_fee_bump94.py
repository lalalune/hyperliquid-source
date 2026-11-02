#!/usr/bin/env python3
"""Extract a static, digest-bound EVM fee-price replacement path from node 94."""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import elf_index
import fde_extents

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MAX128 = (1 << 128) - 1
MASK64 = (1 << 64) - 1

# Each hash covers the entire FDE-described extent, including all code paths.
FUNCTIONS = [
    (0x3428000, 0x3428462, 'replacement scan and arithmetic', 'a3e61d3c9088f3a3cee7b6446b4e74a25cf81c415a2a156cc7f8ef3aa3a100bf'),
    (0x1e478a0, 0x1e47c34, 'transaction vector serializer', 'b593657f0a8099287850c2686c728397d3ebee59579b4910dd0987286be57409'),
    (0x2430350, 0x2430621, 'transaction variant serializer', '628b9eb7aa2c9e28f362a3e8e991cccd628492666252eda4ed337f74052800f5'),
    (0x1e650b0, 0x1e65300, 'Legacy fields', '531ff1dc3004e297096401761175fe3d68ceaec9df173345d94941a0bc8073eb'),
    (0x1e66730, 0x1e66999, 'Eip2930 fields', '502a650bee256852f2b5b00b4b087009dcdb539fc477b681dfe08cc636cafad3'),
    (0x1e658a0, 0x1e65b35, 'Eip1559 fields', '515783205c80cdc6048d801623fea8a459bd8bf0c787f42a4e39ce4dc1e0188b'),
    (0x242c3a0, 0x242c67c, 'Eip4844 fields', '125096e6d88d7eb00d42832a14a60f050af92d0faea06ec294562d60188490f9'),
    (0x1e67470, 0x1e67721, 'Eip7702 fields', 'ce3e018703005587731097142a88c9686e9e778e2fe29656aaad24bcae27fb71'),
    (0x4e59850, 0x4e59e8e, 'outer error formatter', '31648e1a2793aba92b136cf5eed2706c1eea3aa6080fb9338d97350d5b34da95'),
    (0x4e59f80, 0x4e5a0cb, 'inner error formatter', 'ced0a006ecce23d9fc95cb635d296bd2548d493818d2843f8200dddc47483d1e'),
]

# Tags are indices into the serializer's five-entry relative jump table.
# Each key/load pair is a label reference followed by the corresponding load.
VARIANTS = [
    (0, 0x243044a, 0x243046b, 0x2430494, 0x1e650b0,
     [(0x1e6516e, 0x1e6518c, 'nonce', 8), (0x1e651b6, 0x1e651d4, 'gasPrice', 16)]),
    (1, 0x243058f, 0x24305ac, 0x24305d1, 0x1e66730,
     [(0x1e667f0, 0x1e6680e, 'nonce', 8), (0x1e66838, 0x1e66856, 'gasPrice', 16)]),
    (2, 0x24304f2, 0x2430513, 0x243053c, 0x1e658a0,
     [(0x1e65960, 0x1e6597e, 'nonce', 8), (0x1e659f0, 0x1e65a0e, 'maxFeePerGas', 16),
      (0x1e65a39, 0x1e65a57, 'maxPriorityFeePerGas', 16)]),
    (3, 0x2430546, 0x2430563, 0x2430588, 0x242c3a0,
     [(0x242c460, 0x242c47e, 'nonce', 8), (0x242c4f3, 0x242c511, 'maxFeePerGas', 16),
      (0x242c53c, 0x242c55a, 'maxPriorityFeePerGas', 16)]),
    (4, 0x243049e, 0x24304bf, 0x24304e8, 0x1e67470,
     [(0x1e67530, 0x1e6754e, 'nonce', 8), (0x1e675c0, 0x1e675de, 'maxFeePerGas', 16),
      (0x1e67609, 0x1e67627, 'maxPriorityFeePerGas', 16)]),
]
LABELS = ['Legacy', 'Eip2930', 'Eip1559', 'Eip4844', 'Eip7702']

# Curated conditional branches, bound to fixed opcodes and targets below.
BRANCHES = [
    (0x3428025, 'je', 0x342840b, 'empty root returns tag 33'),
    (0x34280c3, 'jb', 0x342840b, 'search exhausted returns tag 33'),
    (0x34280e1, 'je', 0x342840b, 'empty row vector returns tag 33'),
    (0x342815e, 'je', 0x342840b, 'row vector exhausted returns tag 33'),
    (0x34281c0, 'jb', 0x3428449, 'time arithmetic exceptional path'),
    (0x34281f5, 'je', 0x3428449, 'time conversion exceptional path'),
    (0x3428212, 'jbe', 0x3428150, 'row time comparison skips row'),
    (0x3428222, 'je', 0x3428150, 'row time comparison skips row'),
    (0x342822e, 'jne', 0x34283e6, 'populate old 32-byte cache'),
    (0x3428253, 'jne', 0x34283fa, 'populate new 32-byte cache'),
    (0x342827e, 'je', 0x3428425, 'equal 32-byte values return tag 3 payload 0'),
    (0x34282dd, 'jne', 0x3428150, 'different selected nonce skips row'),
    (0x342831c, 'jne', 0x3428437, 'first product overflows'),
    (0x342834e, 'jb', 0x3428437, 'new first value is below threshold'),
    (0x3428361, 'jbe', 0x3428371, 'old tag at most 1 gives second value zero'),
    (0x3428375, 'jb', 0x3428150, 'new tag below 2 skips second check'),
    (0x342839d, 'jne', 0x3428150, 'either second value zero skips second check'),
    (0x34283d6, 'jne', 0x3428437, 'second product overflows'),
    (0x34283de, 'jae', 0x3428150, 'new second value meets threshold'),
    (0x34283e4, 'jmp', 0x3428437, 'new second value is below threshold'),
]

# Window boundaries are instruction boundaries from a manual reading; bytes are
# copied from the ELF, not from a disassembler or an external program.
WINDOWS = [
    ('row_stride', 0x34280e7, 0x34280f2),
    ('new_and_old_bases', 0x342810b, 0x3428146),
    ('time_gate', 0x3428164, 0x3428228),
    ('cache_and_equality', 0x3428228, 0x3428284),
    ('variant_nonce_selection', 0x3428284, 0x34282e3),
    ('first_product_and_compare', 0x34282e3, 0x3428354),
    ('second_presence_product_and_compare', 0x3428354, 0x34283e6),
    ('result_tags', 0x342840b, 0x3428449),
    ('transaction_vector_loop', 0x1e479a0, 0x1e479c8),
    ('transaction_tag_dispatch', 0x2430433, 0x243044a),
    ('outer_error_tag_dispatch', 0x4e59850, 0x4e59867),
    ('outer_error_payload_to_inner', 0x4e599f6, 0x4e59a04),
    ('inner_error_tag_dispatch', 0x4e59f80, 0x4e59f93),
    ('underpriced_message', 0x4e59fbd, 0x4e59fd6),
    ('already_known_message', 0x4e5a035, 0x4e5a04e),
]


def select_nonoverlapping_fdes(fdes, ranges):
    selected = {}
    overlaps = {}
    for start, end in ranges:
        matches = [f for f in fdes if f['start'] < end and start < f['end']]
        if len(matches) != 1 or matches[0]['start'] != start or matches[0]['end'] != end:
            raise ValueError('selected FDE is missing or overlaps another extent')
        selected[start] = matches[0]
        overlaps[start] = matches
    return selected, overlaps


def check_digest(data):
    actual = hashlib.sha256(data).hexdigest()
    if actual != DIGEST:
        raise ValueError('node 94 SHA-256 mismatch')
    return actual


def file_offset(secs, va, size, executable=False):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid virtual address or size')
    matches = [s for s in secs if s['type'] != 8 and s['size'] and
               (not executable or s['flags'] & 4) and
               s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('virtual range is not in exactly one file-backed section')
    s = matches[0]
    return s['offset'] + va - s['address']


class Image:
    def __init__(self, data):
        self.digest = check_digest(data)
        self.data = data
        self.secs = elf_index.sections(data)
        _, fdes = fde_extents.eh_frame_records(data, self.secs)
        self.fdes, self.overlaps = select_nonoverlapping_fdes(
            fdes, [(start, end) for start, end, _, _ in FUNCTIONS])

    def read(self, va, size, executable=False):
        off = file_offset(self.secs, va, size, executable)
        result = self.data[off:off + size]
        if len(result) != size:
            raise ValueError('truncated file bytes')
        return result

    def offset(self, va, size=1, executable=False):
        return file_offset(self.secs, va, size, executable)

    def validate_functions(self):
        result = []
        for start, end, role, expected_hash in FUNCTIONS:
            fde = self.fdes.get(start)
            if fde is None or fde['end'] != end:
                raise ValueError('FDE extent differs from selected extent')
            raw = self.read(start, end - start, True)
            if hashlib.sha256(raw).hexdigest() != expected_hash:
                raise ValueError('selected function bytes differ')
            result.append({'role': role, 'start_va': hex(start), 'end_va_exclusive': hex(end),
                           'file_offset': hex(self.offset(start, len(raw), True)), 'size': len(raw),
                           'fde_va': hex(fde['fde']), 'cie_va': hex(fde['cie']),
                           'overlapping_fde_count': len(self.overlaps[start]),
                           'sha256': expected_hash, 'bytes_hex': raw.hex()})
        return result

    def expect(self, va, expected):
        if self.read(va, len(expected), True) != expected:
            raise ValueError('instruction pattern differs at ' + hex(va))

    def rel32_table(self, base, index):
        return base + struct.unpack('<i', self.read(base + index * 4, 4))[0]

    def u64_table(self, base, index):
        return struct.unpack('<Q', self.read(base + index * 8, 8))[0]

    def lea_string(self, va):
        raw = self.read(va, 12, True)
        if raw[:3] != b'\x48\x8d\x35' or raw[7] != 0xba:
            raise ValueError('unsupported label reference')
        addr = va + 7 + struct.unpack('<i', raw[3:7])[0]
        length = struct.unpack('<I', raw[8:12])[0]
        if length > 64:
            raise ValueError('label length exceeds supported bound')
        return addr, self.read(addr, length).decode('ascii')

    def call_target(self, va):
        raw = self.read(va, 5, True)
        if raw[0] != 0xe8:
            raise ValueError('expected direct call')
        return va + 5 + struct.unpack('<i', raw[1:])[0]

    def relocation_record(self, slot):
        matches = []
        for sec in self.secs:
            if sec['type'] != 4:
                continue
            for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
                place, info, addend = struct.unpack_from('<QQq', self.data, off)
                if place == slot:
                    matches.append((info, addend, off))
        if len(matches) != 1 or matches[0][0] != 8:
            raise ValueError('expected one symbol-free relative relocation')
        info, addend, off = matches[0]
        return {'slot_va': hex(slot), 'type_and_symbol': hex(info), 'addend_va': hex(addend),
                'file_offset': hex(off), 'bytes_hex': self.data[off:off + 24].hex()}

    def relocation_target(self, slot):
        return int(self.relocation_record(slot)['addend_va'], 16)


def decode_branch(raw, va):
    near = {0x84: 'je', 0x85: 'jne', 0x82: 'jb', 0x86: 'jbe', 0x83: 'jae'}
    short = {0x74: 'je', 0x75: 'jne', 0x72: 'jb', 0x76: 'jbe', 0x73: 'jae', 0xeb: 'jmp'}
    if len(raw) >= 6 and raw[0] == 0x0f and raw[1] in near:
        return near[raw[1]], va + 6 + struct.unpack('<i', raw[2:6])[0], 6
    if len(raw) >= 2 and raw[0] in short:
        return short[raw[0]], va + 2 + struct.unpack('<b', raw[1:2])[0], 2
    raise ValueError('unsupported conditional or jump opcode')


def extracted_branches(img):
    rows = []
    for va, mnemonic, target, taken in BRANCHES:
        got, actual_target, size = decode_branch(img.read(va, 6, True), va)
        if (got, actual_target) != (mnemonic, target):
            raise ValueError('branch differs at ' + hex(va))
        rows.append((hex(va), img.read(va, size, True).hex(), got, hex(target),
                     '' if got == 'jmp' else hex(va + size), taken))
    return rows


def get_variants(img):
    img.expect(0x2430433, bytes.fromhex('498b074983c710'))
    img.expect(0x342828b, bytes.fromhex('488d05264316fd'))
    img.expect(0x34282c7, bytes.fromhex('488d0dea6f16fd'))
    stack_pointers = {}
    for lea, store, length in [(0x342810f, 0x3428113, 4), (0x3428118, 0x342811f, 7),
                               (0x3428124, 0x3428128, 4), (0x342812d, 0x3428131, 4)]:
        load = img.read(lea, length, True)
        if length == 4 and load[:3] == bytes.fromhex('488d48'):
            offset = load[3]
        elif length == 7 and load[:3] == bytes.fromhex('488d88'):
            offset = struct.unpack('<I', load[3:])[0]
        else:
            raise ValueError('unexpected new nonce pointer instruction')
        save = img.read(store, 5, True)
        if save[:4] != bytes.fromhex('48894c24') or save[4] in stack_pointers:
            raise ValueError('unexpected nonce pointer stack slot')
        stack_pointers[save[4]] = offset
    first_cmp = img.read(0x3428346, 5, True)
    first_index = img.read(0x342833a, 3, True)
    second_load = img.read(0x342837f, 4, True)
    if (first_cmp[:4], first_index[:2], second_load[:3]) != (bytes.fromhex('4839440f'),
            bytes.fromhex('c1e1'), bytes.fromhex('4c8b62')):
        raise ValueError('unexpected fee field selection')
    first_base, first_step, second_offset = first_cmp[4], 1 << first_index[2], second_load[3]
    bridge = get_layout_bridge(img)
    if (first_base, first_step, second_offset) != (bridge['new_first_offset'],
            bridge['first_step_nonzero_tag'], bridge['new_second_offset']):
        raise ValueError('new fee selections disagree with row layout')
    rows = []
    for tag, arm, lea, call, callee, fields in VARIANTS:
        if img.rel32_table(0x3e1ee0, tag) != arm:
            raise ValueError('variant jump table changed')
        addr, name = img.lea_string(lea)
        if name != LABELS[tag] or img.call_target(call) != callee:
            raise ValueError('variant label or callee changed')
        field_rows = []
        for key_lea, load_va, expected, width in fields:
            key_va, key = img.lea_string(key_lea)
            load = img.read(load_va, 5 if width == 16 else 4, True)
            prefix = b'\x41\x0f\x28\x46' if width == 16 else b'\x49\x8b\x46'
            if key != expected or not load.startswith(prefix):
                raise ValueError('field label/load differs')
            offset = load[-1]
            field_rows.append({'field': key, 'label_va': hex(key_va), 'label_insn_va': hex(key_lea),
                               'load_va': hex(load_va), 'payload_offset': hex(offset),
                               'tagged_offset': hex(offset + 0x10), 'width_bytes': width,
                               'evidence_hex': img.read(key_lea, load_va + len(load) - key_lea, True).hex()})
        nonce = next(x for x in field_rows if x['field'] == 'nonce')
        target = img.rel32_table(0x58c5b8, tag)
        # The first case uses the default pointer already loaded before JMP.
        selector = 0x3428299 if target == 0x34282c0 else target
        load = img.read(selector, 5, True)
        if load[:4] != bytes.fromhex('488b4424') or load[4] not in stack_pointers:
            raise ValueError('new nonce jump does not load a known pointer')
        new_nonce = stack_pointers[load[4]]
        old_nonce = img.u64_table(0x58f2b8, tag)
        if int(nonce['tagged_offset'], 16) != new_nonce or old_nonce != new_nonce + bridge['old_row_tagged_offset']:
            raise ValueError('nonce layout does not match serializer')
        first = field_rows[1]
        if int(first['tagged_offset'], 16) != first_base + (first_step if tag else 0):
            raise ValueError('first fee offset does not match arithmetic')
        if tag >= 2 and int(field_rows[2]['tagged_offset'], 16) != second_offset:
            raise ValueError('second fee offset does not match arithmetic')
        rows.append({'tag': tag, 'name': name, 'variant_string_va': hex(addr),
                     'arm_va': hex(arm), 'call_va': hex(call), 'callee_va': hex(callee),
                     'new_nonce_jump_va': hex(target), 'new_nonce_offset': hex(new_nonce),
                     'old_row_nonce_offset': hex(old_nonce), 'fields': field_rows})
    return rows



def get_layout_bridge(img):
    img.expect(0x1e479a0, bytes.fromhex('4c89ef4c89e64c89fa'))
    if img.call_target(0x1e479a9) != 0x2430350:
        raise ValueError('vector-to-variant serializer call differs')
    vector_step = img.read(0x1e479bc, 7, True)
    row_step = img.read(0x34280eb, 7, True)
    old_base = img.read(0x342813d, 7, True)
    tag_load = img.read(0x34282c0, 7, True)
    if (vector_step[:3], row_step[:3], old_base[:3], tag_load[:3]) != (
            bytes.fromhex('4981c4'), bytes.fromhex('4869d8'),
            bytes.fromhex('4981c7'), bytes.fromhex('498baf')):
        raise ValueError('unexpected stride or old tag instructions')
    vector_stride = struct.unpack('<I', vector_step[3:])[0]
    row_stride = struct.unpack('<I', row_step[3:])[0]
    old_anchor = struct.unpack('<I', old_base[3:])[0]
    tagged_offset = old_anchor + struct.unpack('<i', tag_load[3:])[0]
    if (vector_stride, row_stride, tagged_offset) != (0x150, 0x160, 0x10):
        raise ValueError('row and serializer layouts differ')
    def old_offset(va, prefix):
        raw = img.read(va, len(prefix) + 4, True)
        if raw[:len(prefix)] != prefix:
            raise ValueError('unexpected old fee field instruction')
        return old_anchor + struct.unpack('<i', raw[len(prefix):])[0] - tagged_offset
    old_first = old_offset(0x3428308, bytes.fromhex('49f7a437'))
    old_first_hi = old_offset(0x34282f4, bytes.fromhex('49f7a437'))
    old_second = old_offset(0x3428363, bytes.fromhex('498b8f'))
    old_second_hi = old_offset(0x342836a, bytes.fromhex('498b87'))
    first_shift = img.read(0x34282ec, 3, True)
    if first_shift[:2] != bytes.fromhex('c1e6'):
        raise ValueError('unexpected old fee tag selector')
    step = 1 << first_shift[2]
    new_first, new_first_hi = img.read(0x3428346, 5, True), img.read(0x3428341, 5, True)
    new_second, new_second_hi = img.read(0x342837f, 4, True), img.read(0x3428383, 4, True)
    if (new_first[:4], new_first_hi[:4], new_second[:3], new_second_hi[:3]) != (
            bytes.fromhex('4839440f'), bytes.fromhex('488b740f'),
            bytes.fromhex('4c8b62'), bytes.fromhex('4c8b72')):
        raise ValueError('unexpected new fee field instruction')
    if (old_first, old_first_hi, old_second, old_second_hi) != (
            new_first[4], new_first_hi[4], new_second[3], new_second_hi[3]):
        raise ValueError('old and new fee field layouts differ')
    if old_first_hi != old_first + 8 or old_second_hi != old_second + 8:
        raise ValueError('fee fields are not contiguous two-limb values')
    return {'vector_serializer_va': hex(0x1e478a0), 'call_va': hex(0x1e479a9),
            'variant_serializer_va': hex(0x2430350), 'vector_stride': vector_stride,
            'scanner_row_stride': row_stride, 'old_row_tagged_offset': tagged_offset,
            'stride_difference': row_stride - vector_stride, 'new_first_offset': new_first[4],
            'old_first_offset': old_first, 'first_step_nonzero_tag': step,
            'new_second_offset': new_second[3], 'old_second_offset': old_second,
            'interpretation': 'Compatible stride and field offsets; this alone does not prove runtime object handoff.'}


def assert_arithmetic_patterns(img):
    patterns = [
        (0x34282e3, '31f64885ed400f95c6c1e604b86e000000'),
        (0x34282f4, '49f7a43720ffffff4889c1400f90c7b86e000000'),
        (0x3428308, '49f7a43718ffffff4889d64801ce0f92c14008f9'),
        (0x3428322, 'ba640000004889c731c9'),
        (0x3428332, '31c94d85e40f95c1c1e104488b3c24488b740f484839440f404819d6'),
        (0x3428354, 'b900000000b80000000083fd01'),
        (0x3428363, '498b8f38ffffff498b8740ffffff'),
        (0x3428371, '4183fc02'),
        (0x342837b, '488b14244c8b62604c8b72684889ca4809c20f94c24c89e64c09f6400f94c64008d6'),
        (0x34283a3, '41b86e00000049f7e04889c6400f90c74889c849f7e04801d6400f92c54008fd'),
        (0x34283c3, 'ba640000004889c731c9'),
        (0x34283d3, '4084ed'),
        (0x34283d8, '4939c44919d6'),
        (0x3428410, 'c60021'),
        (0x342842a, 'c6000348c7400800000000'),
        (0x342843c, 'c6000348c7400804000000'),
    ]
    for va, pattern in patterns:
        img.expect(va, bytes.fromhex(pattern))
    multiplier = struct.unpack('<I', img.read(0x34282f0, 4, True))[0]
    divisor = struct.unpack('<I', img.read(0x3428323, 4, True))[0]
    if (multiplier, divisor) != (110, 100):
        raise ValueError('unexpected scale')
    for va in (0x342832c, 0x34283cd):
        insn = img.read(va, 6, True)
        if insn[:2] != b'\xff\x15':
            raise ValueError('expected indirect division call')
        slot = va + 6 + struct.unpack('<i', insn[2:])[0]
        if slot != 0x576e1a8 or img.relocation_target(slot) != 0x565f5a0:
            raise ValueError('unexpected division relocation')
    return multiplier, divisor


def get_errors(img):
    img.expect(0x4e59850, bytes.fromhex('4883ec380fb607'))
    img.expect(0x4e599f6, bytes.fromhex('4883c7084883c438ff254cd49100'))
    raw = img.read(0x4e599fe, 6, True)
    slot = 0x4e599fe + 6 + struct.unpack('<i', raw[2:])[0]
    if img.rel32_table(0x7c1b04, 3) != 0x4e599f6 or img.relocation_target(slot) != 0x4e59f80:
        raise ValueError('outer error formatter path differs')
    rows = []
    for payload, target, lea, expected in [(0, 0x4e5a035, 0x4e5a040, 'already known'),
                                           (4, 0x4e59fbd, 0x4e59fc8, 'replacement transaction underpriced')]:
        if img.rel32_table(0x7c1bb4, payload) != target:
            raise ValueError('inner error table differs')
        addr, text = img.lea_string(lea)
        if text != expected:
            raise ValueError('error message differs')
        rows.append({'outer_tag': 3, 'payload': payload, 'outer_target_va': hex(0x4e599f6),
                     'relocation_slot_va': hex(slot), 'inner_target_va': hex(target),
                     'message_va': hex(addr), 'message': text})
    return rows


def limbs_product(value, multiplier=110, divisor=100):
    """Project the two 64-bit MULs, carry/overflow bits and quotient."""
    if not isinstance(value, int) or not 0 <= value <= MAX128:
        raise ValueError('input outside u128')
    lo, hi = value & MASK64, value >> 64
    upper = hi * multiplier
    lower = lo * multiplier
    sum_high = (upper & MASK64) + (lower >> 64)
    overflow = upper > MASK64 or sum_high > MASK64
    wrapped = ((sum_high & MASK64) << 64) | (lower & MASK64)
    return overflow, wrapped // divisor


def evaluate(old_tag, new_tag, old_first, new_first, old_second, new_second,
             multiplier=110, divisor=100):
    """Model only one already-selected row after its time, key and cache gates."""
    if old_tag not in range(5) or new_tag not in range(5):
        raise ValueError('unsupported transaction tag')
    for value in (old_first, new_first, old_second, new_second):
        if not isinstance(value, int) or not 0 <= value <= MAX128:
            raise ValueError('field outside u128')
    overflow, first = limbs_product(old_first, multiplier, divisor)
    if overflow:
        return 'first_overflow', 3, 4
    if new_first < first:
        return 'first_below', 3, 4
    if new_tag < 2:
        return 'second_absent_new', None, None
    effective_old_second = old_second if old_tag >= 2 else 0
    if not effective_old_second or not new_second:
        return 'second_zero', None, None
    overflow, second = limbs_product(effective_old_second, multiplier, divisor)
    if overflow:
        return 'second_overflow', 3, 4
    if new_second < second:
        return 'second_below', 3, 4
    return 'second_pass', None, None



def scale_proof(multiplier, divisor):
    """Check finite residue and coefficient obligations for all integer inputs."""
    if multiplier <= 0 or divisor <= 0:
        raise ValueError('scale must be positive')
    gcd = math.gcd(multiplier, divisor)
    period, advance = divisor // gcd, multiplier // gcd
    if (period, advance) != (10, 11) or multiplier * period != divisor * advance:
        raise ValueError('scale is not the proved 11/10 ratio')
    residues = []
    for r in range(period):
        quotient, remainder = divmod(multiplier * r, divisor)
        if quotient != r or remainder != gcd * r or not 0 <= remainder < divisor:
            raise ValueError('residue proof obligation failed')
        residues.append((r, multiplier * r, quotient, remainder))
    bound = MAX128 // multiplier
    if not bound * multiplier <= MAX128 < (bound + 1) * multiplier:
        raise ValueError('overflow endpoint proof obligation failed')
    proof = {
        'statement': 'For every unsigned 128-bit x, the checked product fits iff x is at most the recorded bound. When it fits, the quotient is x + floor(x/10).',
        'assumptions': ['The selected FDE bytes have passed their hashes and fixed instruction checks.',
                        'The relocated unsigned 128-bit division helper obeys its independently established nonzero-divisor contract.',
                        'Memory and enum values satisfy the ordinary valid-call domain.'],
        'limb_proof': 'Let B=2^64 and x=h*B+l with 0<=h,l<B. Write m*h=a*B+b and m*l=c*B+d, with b,d<B. Then m*x=a*B^2+(b+c)*B+d. The high MUL overflow flag is a!=0 and the ADD carry is b+c>=B; their OR is exactly m*x>=B^2.',
        'quotient_proof': 'For arbitrary nonnegative x, write x=period*q+r with 0<=r<period. The verified coefficient equality gives m*x=divisor*advance*q+m*r. The finite residue rows give floor(m*r/divisor)=r, so the quotient is advance*q+r=x+q.',
        'multiplier': multiplier, 'divisor': divisor, 'gcd': gcd,
        'period': period, 'advance': advance,
        'coefficient_left': multiplier * period, 'coefficient_right': divisor * advance,
        'residue_obligations': len(residues), 'largest_nonoverflow_input': str(bound),
        'last_fitting_product': str(bound * multiplier), 'first_overflow_product': str((bound + 1) * multiplier),
        'maximum_u128': str(MAX128),
        'limits': 'The identities are a static arithmetic proof, not an observation of node execution or a proof of surrounding object identity.'
    }
    return proof, residues


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def write_json(path, obj):
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')


def generate(out, img=None):
    img = img if img is not None else Image(ARTIFACT.read_bytes())
    functions = img.validate_functions()
    variants = get_variants(img)
    layout_bridge = get_layout_bridge(img)
    branches = extracted_branches(img)
    multiplier, divisor = assert_arithmetic_patterns(img)
    errors = get_errors(img)
    out.mkdir(parents=True, exist_ok=True)
    windows = []
    for label, start, end in WINDOWS:
        windows.append((label, hex(start), hex(end), hex(img.offset(start, end - start, True)),
                        img.read(start, end - start, True).hex()))
    proof, residues = scale_proof(multiplier, divisor)
    bound = MAX128 // multiplier
    values = sorted(set(list(range(0, 111)) + [999, 1000, (1 << 64) - 1, 1 << 64,
                       (1 << 64) + 1, bound - 1, bound, bound + 1, MAX128]))
    scalar_rows = []
    for x in values:
        overflow, quotient = limbs_product(x, multiplier, divisor)
        if overflow != (x > bound):
            raise ValueError('limb overflow disagrees with arithmetic boundary')
        if not overflow and quotient != x + x // 10:
            raise ValueError('limb quotient disagrees with rational identity')
        scalar_rows.append((str(x), int(overflow), '' if overflow else str(quotient),
                            str((x * multiplier) // divisor)))
    case_specs = [
        ('first_equal_tiny', 9, 9, 10, 11),
        ('first_one_below', 10, 10, 10, 11),
        ('first_exact', 10, 11, 10, 11),
        ('second_one_below', 10, 11, 10, 10),
        ('second_zero_new', 10, 11, 10, 0),
        ('second_zero_old', 10, 11, 0, 10),
        ('second_exact', 10, 11, 10, 11),
        ('both_zero', 0, 0, 0, 0),
        ('first_overflow', bound + 1, MAX128, 10, 11),
        ('second_overflow', 10, 11, bound + 1, MAX128),
    ]
    case_rows = []
    for old_tag in range(5):
        for new_tag in range(5):
            for name, a, b, c, d in case_specs:
                path, tag, payload = evaluate(old_tag, new_tag, a, b, c, d, multiplier, divisor)
                case_rows.append((old_tag, new_tag, name, str(a), str(b), str(c), str(d), path,
                                  '' if tag is None else tag, '' if payload is None else payload))
    tables = []
    for name, va, size in [('variant_rel32', 0x3e1ee0, 20), ('new_nonce_rel32', 0x58c5b8, 20),
                           ('old_row_nonce_u64', 0x58f2b8, 40), ('outer_error_rel32', 0x7c1b04, 16),
                           ('inner_error_rel32', 0x7c1bb4, 20)]:
        tables.append({'name': name, 'va': hex(va), 'file_offset': hex(img.offset(va, size)),
                       'bytes_hex': img.read(va, size).hex()})
    info = {'target': 'node 94', 'artifact_sha256': img.digest,
            'coordinates': 'ELF virtual addresses before load bias and file offsets',
            'functions': functions, 'variants': variants, 'layout_bridge': layout_bridge, 'error_paths': errors,
            'data_tables': tables, 'relocations': [img.relocation_record(0x576e1a8),
                                                   img.relocation_record(0x5776e50)],
            'scale': {'multiplier': multiplier, 'divisor': divisor, 'max_u128': str(MAX128),
                      'largest_nonoverflow_input': str(bound), 'first_overflow_input': str(bound + 1),
                      'division_slot_va': hex(0x576e1a8), 'division_target_va': hex(0x565f5a0)},
            'counts': {'selected_fdes': len(functions), 'variants': len(variants),
                       'branches': len(branches), 'byte_windows': len(windows),
                       'scalar_model_cases': len(scalar_rows), 'row_model_cases': len(case_rows),
                       'residue_rows': len(residues)},
            'scope': 'Static extraction and a conditional one-row arithmetic model, not target execution.'}
    write_json(out / 'evidence.json', info)
    write_json(out / 'arithmetic-proof.json', proof)
    write_tsv(out / 'branches.tsv', ['va', 'bytes_hex', 'condition', 'taken_va', 'fallthrough_va', 'taken_meaning'], branches)
    write_tsv(out / 'windows.tsv', ['name', 'start_va', 'end_va_exclusive', 'file_offset', 'bytes_hex'], windows)
    write_tsv(out / 'scalar-model.tsv', ['old_u128', 'multiply_overflow', 'native_quotient_if_no_overflow', 'unbounded_mathematical_quotient'], scalar_rows)
    write_tsv(out / 'row-model.tsv', ['old_tag', 'new_tag', 'case', 'old_first', 'new_first', 'old_second', 'new_second', 'modeled_path', 'output_tag_if_return', 'output_payload_if_return'], case_rows)
    write_tsv(out / 'residues.tsv', ['r', 'multiplier_times_r', 'quotient_by_divisor', 'remainder_by_divisor'], residues)
    return info['counts']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(generate(args.out), sort_keys=True))


if __name__ == '__main__':
    main()
