#!/usr/bin/env python3
"""Extract bounded node 94 Hyperliquidity snapshot decisions from ELF bytes."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/94/hl-node'

# Extents are unwind ranges, not claims that every instruction is reachable.
FUNCTIONS = {
    'field_classifier': 0x16ce960,
    'binary_outer_reader': 0x195b220,
    'binary_outer_sequence_adapter': 0x1701640,
    'binary_spot_map_reader': 0x17aa010,
    'binary_map_entries': 0x264be00,
    'binary_pair_entries': 0x267b1d0,
    'binary_pair_reader': 0x1854410,
    'optional_range_reader': 0x168caa0,
    'range_reader': 0x175ad70,
    'guard_default': 0x32636a0,
    'binary_writer': 0x3263290,
    'json_reader': 0x1c76610,
    'json_writer': 0x32633c0,
}

# Byte anchors selected at instruction starts from manually reviewed flow. A
# mismatch aborts rather than silently applying these labels to different code.
ANCHORS = [
    ('sequence-empty', 0x195b7ad, '85ed0f847c020000'),
    ('sequence-first', 0x195b7c2, 'e849e8e4ff0fb64424404883f8097579'),
    ('sequence-one', 0x195b7ec, '83fd010f85d0000000ff15a56de103'),
    ('sequence-second', 0x195b8c5, '488d15fb41a6fe488d7c2440b90b0000004c89f6e8f213d5ff0fb6442440'),
    ('sequence-two', 0x195b946, '83fd020f8582000000'),
    ('sequence-extra', 0x195b9d1, 'c684249800000004c784249c0000000200000048c784249000000000000000'),
    ('map-field-guard', 0x195c882, '0fb644244183f802746083f8010f85aa0000004883bc2428010000000f85e8020000'),
    ('map-field-values', 0x195c93f, '4c8bbc24100100004d85ff0f85b1020000410fb6562448c784241001000000000000488d7c24604c89f6e8a2d6e4ff'),
    ('map-close', 0x195bf1a, 'f6842410010000010f84ed000000'),
    ('map-guard-default', 0x195bf5c, '4d85e40f8551f7ffffff153566e103'),
    ('map-required', 0x195b62d, '4531e4488d05f94fa5fe488984245001000048c78424580100000d000000488d8424500100004889442440488d0531bd8500488944'),
    ('guard-duplicate', 0x195cbaa, '488d058c3aa5fe488944244048c744244819000000488d'),
    ('map-duplicate', 0x195cc1f, '488d050a3aa5fe488944244048c74424480d000000488d'),
    ('map-unknown', 0x195c8ec, '488d7c24604c89f6ba01000000e8d2b90000807c2460090f84'),
    ('default-arithmetic', 0x326371e, '4869c8005c260531c04885c9480f4fc148b99b5271f6e133ec0a48f7e148c1ea07b8b80b0000'),
    ('default-constant', 0x3263738, '48f7e148c1ea07b8b80b000059c3'),
    ('default-date', 0x32636a0, '50bfa8fa0a00ff15e4b1500285c00f8492000000'),
    ('binary-writer-header', 0x32632b0, '807a0b007432488d7c24084c89f6ba02000000e8084f3300488b'),
    ('binary-writer-array', 0x32632e8, '488d7c24084c89f6ba02000000e8265b3300488b4424084883f80275ce41'),
    ('binary-writer-first', 0x3263305, '41807e0b01751a488d35ae0e32fdba0d0000004c89f7e8206733004883f802755a498d7710488d7c24084c89f2e8c9543a004d8d6c2404'),
    ('binary-writer-second', 0x3263343, '41807e0b01751a488d357d0e32fdba190000004c89f7e8e26633004883f802751c488d7c24084c89fe4c89f2e85cc310004c396c240875'),
    ('map-reader-map', 0x17aa3cd, '4989fe4989f74889742460895c2468488d7c2420488d742460e8151aea000fb64424203c'),
    ('map-reader-array', 0x17aa511, '4989fe4989f74889742460895c2468488d7c2420488d742460e8a10ced000fb6442420'),
    ('map-insert-key', 0x264be50, '41895e08b9040000004c89ef4c89fe488d15dae1bbfde8155504ff0fb64424283c090f8557010000488b6c24304c89ef4c89fee8180c04ff'),
    ('map-insert-value', 0x264be78, '488b6c24304c89ef4c89fee8180c04ff488b442430837c2428010f845d0100004c39'),
    ('map-insert-call', 0x264bebf, '4c89ef488d7424104889ea488d8c2488000000e8e9162000488b44242848b901000000000000804839c87536'),
    ('map-duplicate-msg', 0x264bf40, 'bf0d000000ff158d2012034885c04c8b6424080f84b101000048b963617465206b65794889480548b96475706c6963617448890848'),
    ('pairs-insert', 0x267b230, '41895e084c89e74c89fe31d2e8cf911dff488b542450488b442458807c2448000f8587'),
    ('pairs-duplicate-msg', 0x267b320, 'bf0d000000ff15ad2c0f034885c04c8b64240849bd00000000000000800f846201000048b963617465206b65794889480548b96475706c69636174488908'),
    ('pair-key', 0x1854944, '488d7c24784889f3e8dffbe2ff0fb64424783c09757283fd010f843b020000'),
    ('pair-value', 0x1854963, '4c8bbc2480000000488d7c24784889dee82881e3ff488b8c2480'),
    ('pair-size', 0x1854a75, '488b44242883fd027534'),
    ('optional-nil', 0x168cb3f, '48b800000000000000804889430848c703000000004889d84883c4305bc3'),
    ('optional-child', 0x168cb5d, '884620884e21488d7c240831d2e801e20c00'),
    ('json-missing', 0x1c77065, '488d05dc1374fe488984248000000048c78424880000000d0000004c894c2438488d050403540048894424404531e4488d3d588856fe488d742438e8'),
    ('json-duplicate-a', 0x1c77472, '488d05cf0f74fe488984248000000048c78424880000000d0000004889542438488d05f7fe53004889442440488d3d309b56fe488d7424384989cce82e3a2400e9'),
    ('json-duplicate-b', 0x1c774c5, '488d05890f74fe488984248000000048c78424880000001900000048897c2438488d05a4fe53004889442440488d3ddd9a56fe488d7424384c8b642408e8d93924'),
    ('json-default', 0x1c76d82, 'ff1518b8af03'),
    ('json-writer-first', 0x3263415, '488d35a50d32fd488d7c2408ba0d000000e8'),
    ('range-missing-size', 0x175b17c, '488d05adfeaafe488944243048c744243808000000488d4424304889'),
    ('range-missing-points', 0x175b1eb, '488d057f4dc5fe488944243048c744243806000000488d4424304889'),
    ('range-duplicate-points', 0x175c1f2, '488d05783dc5fe488944243048c744243806000000488d4424304889'),
    ('range-duplicate-size', 0x175c271, '488d05b8edaafe488944243048c744243808000000488d4424304889'),
    ('range-sequence-zero', 0x175b3c5, '85ed0f84b7010000488d15a08ec9'),
    ('range-first-reader', 0x175b3cd, '488d15a08ec9fe488d7c2450b9020000004c89f6e83a4df6ff0fb64424503c'),
    ('range-second-reader', 0x175b3f3, '83fd010f84e90100004c8b7c2458488d7c24504c89f631d2e8a03c1800'),
    ('range-arity-two', 0x175b47f, '83fd020f85a4000000'),
    ('json-writer-second', 0x326347e, '488d35490d32fd488d7c2408ba19000000e82cb5a300'),
]

DIRECT_CALLS = [
    ('sequence_adapter_to_outer', 0x170165e, 0x195b220),
    ('outer_sequence_to_spot_map', 0x195b7c2, 0x17aa010),
    ('outer_map_to_spot_map', 0x195c969, 0x17aa010),
    ('outer_key_string_classifier', 0x195c702, 0x16ce960),
    ('outer_key_bytes_classifier', 0x195c534, 0x16ce960),
    ('spot_map_to_entries', 0x17aa3e6, 0x264be00),
    ('spot_array_to_pairs', 0x17aa52a, 0x267b1d0),
    ('pair_entries_to_pair', 0x267b23c, 0x1854410),
    ('entries_to_spot_key', 0x264be66, 0x1691380),
    ('entries_to_optional_range', 0x264be83, 0x168caa0),
    ('entries_insert', 0x264bed2, 0x284d5c0),
    ('pair_entries_insert', 0x267b2ab, 0x284d5c0),
    ('pair_to_key', 0x185494c, 0x1684530),
    ('pair_to_optional_range', 0x1854973, 0x168caa0),
    ('optional_to_range', 0x168cb6a, 0x175ad70),
    ('range_sequence_order_size', 0x175b3e1, 0x16c0120),
    ('range_sequence_points', 0x175b40b, 0x18df0b0),
    ('binary_writer_spot_map', 0x3263332, 0x3608800),
    ('binary_writer_guard', 0x326336f, 0x336f6d0),
    ('json_writer_spot_map', 0x326346b, 0x3607d00),
    ('json_writer_guard', 0x32634d3, 0x336f4a0),
]
SLOT_CALLS = [
    ('sequence_default', 0x195b7f5, 0x57725a0, 0x32636a0),
    ('map_default', 0x195bf65, 0x57725a0, 0x32636a0),
    ('json_default', 0x1c76d82, 0x57725a0, 0x32636a0),
    ('default_date_helper', 0x32636a6, 0x576e890, 0x151f6f0),
]
BRANCHES = [
    ('empty_outer_sequence', 0x195b7af, 'je', 0x195ba31),
    ('first_child_failure', 0x195b7d0, 'jne', 0x195b84b),
    ('sequence_not_one', 0x195b7ef, 'jne', 0x195b8c5),
    ('sequence_not_two', 0x195b949, 'jne', 0x195b9d1),
    ('unknown_field_selector', 0x195c88a, 'je', 0x195c8ec),
    ('spot_selector', 0x195c88f, 'jne', 0x195c93f),
    ('duplicate_guard', 0x195c89e, 'jne', 0x195cb8c),
    ('duplicate_spot', 0x195c94a, 'jne', 0x195cc01),
    ('missing_spot', 0x195bf22, 'je', 0x195c015),
    ('guard_present', 0x195bf5f, 'jne', 0x195b6b6),
    ('pair_not_two', 0x1854a7d, 'jne', 0x1854ab3),
    ('map_duplicate_value', 0x264bee9, 'jne', 0x264bf21),
    ('pairs_duplicate_value', 0x267b2c2, 'jne', 0x267b301),
    ('optional_nil', 0x168cab9, 'je', 0x168cb3f),
    ('default_invalid_date', 0x32636ae, 'je', 0x3263746),
    ('writer_array', 0x32632b4, 'je', 0x32632e8),
    ('range_sequence_empty', 0x175b3c7, 'je', 0x175b584),
    ('range_sequence_one', 0x175b3f6, 'je', 0x175b5e5),
    ('range_sequence_not_two', 0x175b482, 'jne', 0x175b52c),
]

class EvidenceError(ValueError):
    pass


def verify_digest(data, expected=SHA):
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        raise EvidenceError('artifact SHA-256 mismatch')
    return digest


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        _, rows = eh_frame_records(data, self.sections)
        self.fdes = {}
        for f in rows:
            if f['start'] in self.fdes:
                raise EvidenceError('duplicate FDE start')
            self.fdes[f['start']] = f

    def offset(self, va, size=1):
        if size < 0 or va < 0:
            raise EvidenceError('invalid address or size')
        hits = [s for s in self.sections if s['type'] != 8 and s['size'] and
                s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(hits) != 1:
            raise EvidenceError('address not uniquely backed by file bytes')
        return hits[0]['offset'] + va - hits[0]['address']

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def function(self, start):
        if start not in self.fdes:
            raise EvidenceError('missing FDE start')
        f = self.fdes[start]
        if f['end'] <= start:
            raise EvidenceError('empty FDE')
        body = self.read(start, f['end'] - start)
        return {'start': start, 'end_exclusive': f['end'], 'fde': f['fde'],
                'file_offset': self.offset(start, len(body)), 'size': len(body),
                'sha256': hashlib.sha256(body).hexdigest()}

    def relocations(self):
        rows = [s for s in self.sections if s['name'] == '.rela.dyn' and s['type'] != 8]
        if len(rows) != 1 or rows[0]['size'] % 24:
            raise EvidenceError('invalid relocation section')
        section = rows[0]
        result = {}
        for p in range(section['offset'], section['offset'] + section['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', self.data, p)
            if info & 0xffffffff == 8:
                if slot in result:
                    raise EvidenceError('duplicate relative relocation')
                result[slot] = addend
        return result


def check_anchors(read):
    rows = []
    for name, va, expected_hex in ANCHORS:
        expected = bytes.fromhex(expected_hex)
        actual = read(va, len(expected))
        if actual != expected:
            raise EvidenceError('anchor mismatch: ' + name)
        rows.append({'name': name, 'va': va, 'size': len(actual), 'bytes': actual.hex()})
    return rows


def lea_target(read, site):
    raw = read(site, 7)
    if len(raw) != 7 or raw[0] not in (0x48, 0x4c) or raw[1] != 0x8d or raw[2] & 0xc7 != 5:
        raise EvidenceError('not RIP-relative lea')
    return site + 7 + struct.unpack_from('<i', raw, 3)[0]


def direct_call(read, site):
    raw = read(site, 5)
    if len(raw) != 5 or raw[0] != 0xe8:
        raise EvidenceError('not direct call')
    return site + 5 + struct.unpack_from('<i', raw, 1)[0]


def slot_call(read, site):
    raw = read(site, 6)
    if len(raw) != 6 or raw[:2] != b'\xff\x15':
        raise EvidenceError('not indirect RIP-relative call')
    return site + 6 + struct.unpack_from('<i', raw, 2)[0]


def branch(read, site):
    raw = read(site, 6)
    if raw[0] in (0x74, 0x75):
        cond = {0x74: 'je', 0x75: 'jne'}[raw[0]]
        size = 2
        disp = struct.unpack_from('<b', raw, 1)[0]
    elif raw[:2] in (b'\x0f\x84', b'\x0f\x85'):
        cond = {0x84: 'je', 0x85: 'jne'}[raw[1]]
        size = 6
        disp = struct.unpack_from('<i', raw, 2)[0]
    else:
        raise EvidenceError('not supported conditional branch')
    return {'condition': cond, 'size': size, 'target': site + size + disp,
            'fallthrough': site + size, 'bytes': raw[:size].hex()}


def decode_classifier(read):
    """Decode the two byte-comparison chains and their mismatch branches."""
    if read(0x16ce960, 3) != b'\x83\xfa\x19' or read(0x16ce969, 3) != b'\x83\xfa\x0d':
        raise EvidenceError('classifier length guards changed')
    for site, kind, target in [(0x16ce963, 'je', 0x16ce9fc), (0x16ce96c, 'jne', 0x16ceaa3)]:
        r = branch(read, site)
        if r['condition'] != kind or r['target'] != target:
            raise EvidenceError('classifier length branch changed')
    decoded = []
    for start, n in ((0x16ce972, 13), (0x16ce9fc, 25)):
        pos, chars, positions = start, [], []
        for i in range(n):
            if i == 24 and n == 25:
                if read(pos, 2) != b'\xb0\x01':
                    raise EvidenceError('classifier success tag changed')
                pos += 2
            size = 3 if i == 0 else 4
            raw = read(pos, size)
            if raw[:2] != (b'\x80\x3e' if i == 0 else b'\x80\x7e'):
                raise EvidenceError('classifier comparison opcode changed')
            if i and raw[2] != i:
                raise EvidenceError('classifier byte offset changed')
            chars.append(raw[-1]); positions.append(pos)
            pos += size
            edge = branch(read, pos)
            if i == 24 and n == 25:
                if edge['condition'] != 'je' or edge['target'] != 0x16ceaa5:
                    raise EvidenceError('classifier final branch changed')
            elif edge['condition'] != 'jne' or edge['target'] != 0x16ceaa3:
                raise EvidenceError('classifier mismatch branch changed')
            pos += edge['size']
        decoded.append((bytes(chars), positions))
    if read(0x16ce9f3, 9) != bytes.fromhex('31c0884701c60709c3'):
        raise EvidenceError('classifier first return changed')
    if read(0x16ceaa3, 9) != bytes.fromhex('b002884701c60709c3'):
        raise EvidenceError('classifier fallback return changed')
    if [x[0] for x in decoded] != [read(0x3b0630, 13), read(0x3b063d, 25)]:
        raise EvidenceError('classifier text differs from field literals')
    return decoded


def classify(key, names):
    if key == names[0]: return 0
    if key == names[1]: return 1
    return 2


def collect(image):
    functions = [{'name': name, **image.function(va)} for name, va in FUNCTIONS.items()]
    anchors = check_anchors(image.read)
    names_and_sites = decode_classifier(image.read)
    names = [a for a, _ in names_and_sites]
    edges = []
    for name, site, target in DIRECT_CALLS:
        if direct_call(image.read, site) != target:
            raise EvidenceError('call target mismatch: ' + name)
        edges.append({'name': name, 'site': site, 'kind': 'rel32', 'target': target,
                      'bytes': image.read(site, 5).hex()})
    reloc = image.relocations()
    for name, site, slot, target in SLOT_CALLS:
        if slot_call(image.read, site) != slot or reloc.get(slot) != target:
            raise EvidenceError('relocated call mismatch: ' + name)
        edges.append({'name': name, 'site': site, 'kind': 'relocated_slot', 'slot': slot,
                      'target': target, 'bytes': image.read(site, 6).hex()})
    branches = []
    for name, va, condition, target in BRANCHES:
        row = branch(image.read, va)
        if row['condition'] != condition or row['target'] != target:
            raise EvidenceError('branch mismatch: ' + name)
        branches.append({'name': name, 'site': va, **row})
    literals = []
    for name, site, target, value in [
        ('spot_key_label', 0x264be5f, 0x20a040, b'Spot'),
        ('outer_missing_spot', 0x195b630, 0x3b0630, b'spot_to_range'),
        ('outer_duplicate_spot', 0x195cc1f, 0x3b0630, b'spot_to_range'),
        ('outer_duplicate_guard', 0x195cbaa, 0x3b063d, b'ensure_order_bucket_guard'),
        ('range_missing_order_size', 0x175b17c, 0x20b030, b'order_sz'),
        ('range_missing_points', 0x175b1eb, 0x3aff71, b'points'),
        ('range_duplicate_order_size', 0x175c271, 0x20b030, b'order_sz'),
        ('range_duplicate_points', 0x175c1f2, 0x3aff71, b'points'),
        ('binary_writer_spot', 0x326330c, 0x5841c1, b'spot_to_range'),
        ('binary_writer_guard', 0x326334a, 0x5841ce, b'ensure_order_bucket_guard'),
        ('json_writer_spot', 0x3263415, 0x5841c1, b'spot_to_range'),
        ('json_writer_guard', 0x326347e, 0x5841ce, b'ensure_order_bucket_guard')]:
        if lea_target(image.read, site) != target or image.read(target, len(value)) != value:
            raise EvidenceError('literal reference changed: ' + name)
        literals.append({'name': name, 'site': site, 'literal_va': target,
                         'length': len(value), 'text': value.decode('ascii')})
    templates = []
    for name, site, target, value in [
        ('outer_missing', 0x195b667, 0x1df8f3, b'\x0fmissing field `\xc0\x01`'),
        ('outer_duplicate_spot', 0x195cc50, 0x1e0fd5, b'\x11duplicate field `\xc0\x01`'),
        ('outer_duplicate_guard', 0x195cbdb, 0x1e0fd5, b'\x11duplicate field `\xc0\x01`'),
        ('range_missing_size', 0x175b1b5, 0x1df8f3, b'\x0fmissing field `\xc0\x01`'),
        ('range_missing_points', 0x175b224, 0x1df8f3, b'\x0fmissing field `\xc0\x01`'),
        ('range_duplicate_size', 0x175c2aa, 0x1e0fd5, b'\x11duplicate field `\xc0\x01`'),
        ('range_duplicate_points', 0x175c22b, 0x1e0fd5, b'\x11duplicate field `\xc0\x01`')]:
        if lea_target(image.read, site) != target or image.read(target, len(value)) != value:
            raise EvidenceError('diagnostic template changed: ' + name)
        templates.append({'name': name, 'site': site, 'literal_va': target, 'bytes': value.hex()})
    # The two duplicate paths each construct the same diagnostic from two
    # overlapping imm64 stores, rather than referencing a string pool.
    diagnostics = []
    for name, tail_site, head_site in [('map_entries', 0x264bf59, 0x264bf67),
                                       ('pair_entries', 0x267b343, 0x267b351)]:
        tail = image.read(tail_site, 10)
        head = image.read(head_site, 10)
        if tail[:2] != b'\x48\xb9' or head[:2] != b'\x48\xb9':
            raise EvidenceError('diagnostic immediate opcode changed')
        message = head[2:7] + tail[2:10]
        if message != b'duplicate key':
            raise EvidenceError('diagnostic immediate changed')
        diagnostics.append({'path': name, 'tail_site': tail_site, 'head_site': head_site,
                            'text': message.decode('ascii')})
    # These type names come from RELATIVE relocation addends plus stored lengths.
    descriptors = []
    for name, slot, literal in [('outer', 0x5687558, b'struct Hyperliquidity with 2 elements'),
                                ('range', 0x5685de8, b'struct Range with 2 elements')]:
        target = reloc.get(slot)
        if target is None or struct.unpack('<Q', image.read(slot + 8, 8))[0] != len(literal):
            raise EvidenceError('type descriptor mismatch')
        if image.read(target, len(literal)) != literal:
            raise EvidenceError('type text mismatch')
        descriptors.append({'name': name, 'slot': slot, 'literal_va': target,
                            'length': len(literal), 'text': literal.decode('ascii')})
    comparisons = []
    for index, (key, sites) in enumerate(names_and_sites):
        for offset, site in enumerate(sites):
            comparisons.append({'selector': index, 'offset': offset,
                                'byte': key[offset], 'site': site})
    mutation_checks = 0
    for key in names:
        for i, original in enumerate(key):
            for byte in range(256):
                if byte == original:
                    continue
                altered = bytearray(key)
                altered[i] = byte
                if classify(bytes(altered), names) != 2:
                    raise EvidenceError('classifier substitution accepted')
                mutation_checks += 1
    default_values = {
        'date_argument': struct.unpack('<I', image.read(0x32636a2, 4))[0],
        'day_millis_factor': struct.unpack('<I', image.read(0x3263721, 4))[0],
        'multiply_high_constant': struct.unpack('<Q', image.read(0x3263730, 8))[0],
        'right_shift': image.read(0x326373e, 1)[0],
        'returned_first_word': struct.unpack('<I', image.read(0x3263740, 4))[0],
    }
    cases = []
    for expected, key in enumerate(names):
        cases.append({'name': f'field_{expected}', 'key_hex': key.hex(), 'selector': classify(key, names)})
        for i in range(len(key)):
            changed = bytearray(key); changed[i] ^= 1
            cases.append({'name': f'field_{expected}_change_{i}', 'key_hex': bytes(changed).hex(),
                          'selector': classify(bytes(changed), names)})
        cases.append({'name': f'field_{expected}_short', 'key_hex': key[:-1].hex(),
                      'selector': classify(key[:-1], names)})
        cases.append({'name': f'field_{expected}_long', 'key_hex': (key+b'!').hex(),
                      'selector': classify(key+b'!', names)})
    cases.append({'name': 'empty', 'key_hex': '', 'selector': classify(b'', names)})
    return {'binary_sha256': SHA, 'functions': functions, 'anchors': anchors,
            'edges': edges, 'branches': branches, 'descriptors': descriptors,
            'comparisons': comparisons, 'classifier_cases': cases, 'literals': literals, 'templates': templates, 'duplicate_diagnostics': diagnostics,
            'field_names': [x.decode('ascii') for x in names],
            'classifier_single_byte_rejections': mutation_checks, 'default_values': default_values,
            'limits': 'Static fixed-window analysis; FDE ranges are unwind extents; child codecs and runtime behaviour are not fully established.'}


def write_tsv(path, rows, columns):
    with path.open('w', encoding='utf-8', newline='') as out:
        writer = csv.DictWriter(out, fieldnames=columns, delimiter='\t', lineterminator='\n')
        writer.writeheader()
        for row in rows:
            writer.writerow({k: (hex(row[k]) if k in {'start', 'end_exclusive', 'fde', 'file_offset', 'site', 'target', 'fallthrough', 'slot', 'va', 'literal_va'} and k in row else row.get(k, '')) for k in columns})


def generate(data, out):
    verify_digest(data)
    record = collect(Image(data))
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    write_tsv(out / 'functions.tsv', record['functions'], ['name', 'start', 'end_exclusive', 'fde', 'file_offset', 'size', 'sha256'])
    write_tsv(out / 'anchors.tsv', record['anchors'], ['name', 'va', 'size', 'bytes'])
    write_tsv(out / 'edges.tsv', record['edges'], ['name', 'site', 'kind', 'slot', 'target', 'bytes'])
    write_tsv(out / 'branches.tsv', record['branches'], ['name', 'site', 'condition', 'target', 'fallthrough', 'bytes'])
    write_tsv(out / 'field-comparisons.tsv', record['comparisons'], ['selector', 'offset', 'byte', 'site'])
    write_tsv(out / 'classifier-cases.tsv', record['classifier_cases'], ['name', 'key_hex', 'selector'])
    write_tsv(out / 'literals.tsv', record['literals'], ['name', 'site', 'literal_va', 'length', 'text'])
    write_tsv(out / 'templates.tsv', record['templates'], ['name', 'site', 'literal_va', 'bytes'])
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    generate(BINARY.read_bytes(), args.out)


if __name__ == '__main__':
    try:
        main()
    except (EvidenceError, ValueError, OSError, struct.error) as exc:
        print('hyperliquidity_snapshot94: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
