#!/usr/bin/env python3
"""Static, digest-bound evidence for a node 94 order-index deletion path.

The target is read, never executed. Separate synthetic tests illustrate
relationships inferred from pinned instructions; they are not an ELF emulator.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import fde_extents

ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / 'artifacts/node/94/hl-node'
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Each extent and body hash is independently checked after FDE decoding.
FUNCTIONS = (
    ('cancel-tree-perp', 0x28660a0, 0x2866413, '9fc9908c9ee6378a87621e1de0ba53f74acaff2ca81856fcefa03a77b275dd9c'),
    ('cancel-tree-spot', 0x2866870, 0x2866be3, '313e2db7f5b26c70ffcc014e191a6a758d89f14a6f236588b0762110e1a0bd09'),
    ('remove-handle', 0x1b22a90, 0x1b22d6a, 'dba142677c572f1a7252a09e8f90fe2f70f21a41c4976e8e1cb2565ea5d1beac'),
    ('delete-leaf-repair', 0x1b17160, 0x1b17e10, '043f42f51e96818f287243b1dbba78d2fd7d9d87492cbf811ec32a4a7163e0d1'),
    ('borrow-left', 0x1af72d0, 0x1af7617, '5ff69884d76830a4e4d3f78a2f527fbd698417a525a758c809e70a66fdfeacc2'),
    ('borrow-right', 0x1afcfe0, 0x1afd39e, '7e0f52399899b74b3d5636c9bdd6cc1074b5c17c99bdc10561fc64eb4e356186'),
)

# Fixed instruction sequences. These are witnesses, not an x86 decoder.
PINS = (
    ('spot-user-map-member', 0x26de562, '4c8db3b8000000'),
    ('spot-caller-tree-member', 0x26de590, '488d7038'),
    ('spot-returned-tag-test', 0x26de5a9, '83bc24d0040000024c897c24100f85a4000000'),
    ('perp-user-map-member', 0x26df5b2, '498dbeb8000000'),
    ('perp-caller-tree-member', 0x26df5e6, '488d7038'),
    ('perp-returned-tag-test', 0x26df646, '83bc24e0040000020f85a4000000'),
    ('spot-empty-root-and-absent-tag', 0x2866884, '488b0641bd020000004885c00f84e9020000'),
    ('tree-height-and-key', 0x2866899, '488b4e08488b12'),
    ('node-key-count', 0x28668a0, '0fb7b84a080000'),
    ('key-comparison', 0x28668c5, '483b54f010410f97c14180d900'),
    ('search-child-array', 0x28668fd, '488b84f050080000'),
    ('removed-payload-first-word', 0x2866937, '488bac2498000000'),
    ('tree-length-decrement', 0x28669e9, '49ff4e10'),
    ('root-replacement', 0x28669fd, '807c240f01753e498b3e4885ff0f8487010000498b46084885c00f8489010000488b8f5008000049890e48ffc84989460848c70100000000beb008000031d2'),
    ('root-replacement-indirect-call', 0x2866a3c, 'ff15ce75f002'),
    ('removed-value-sentinel-test', 0x2866ae3, '4883fd020f8492000000'),
    ('handle-height-and-child', 0x1b22aa4, '488b06488b7e08488b4e104885ff0f84eb010000488b8cc850080000'),
    ('predecessor-last-key', 0x1b22b8e, '0fb7814a08000048ffc848894c242048c7442428000000004889442430'),
    ('predecessor-copy-indirect-call', 0x1b22bd1, 'ff1509b4c403'),
    ('internal-key-value-swap', 0x1b22c18, '4969c4b80000004d8d34074983c6604b8b44e708488904244f896ce708'),
    ('handle-return-key-and-value', 0x1b22d21, '488b0424488903488d7b08488d742438bab8000000ff15a4b2c403'),
    ('leaf-key-removal', 0x1b17181, '4c8b264c8b7e10450fb7ac244a0800004b8d7cfc084b8b44fc0848898424800000004b8d34fc4883c6104d89fe49f7d64d01ee4a8d14f500000000488b2d1d6fc503ffd5'),
    ('leaf-value-removal', 0x1b172a2, '498d34044881c6180100004969d6b80000004d89e6ffd5418d7dff664189bc244a080000'),
    ('underflow-and-parent', 0x1b172b9, '418d7dff664189bc244a080000488b43086683ff0448894424680f87f20400004d8b264d85e40f84e6040000'),
    ('choose-left-sibling', 0x1b172ea, '488d5001410fb7b6480800004885f6488914240f84cd0300004c89f34c8d76ff498b8cf448080000'),
    ('left-merge-or-borrow', 0x1b1734a, '0fb7a94a0800004101ed4183fd0c0f8319040000'),
    ('left-merge-cursor-guard', 0x1b1736d, '48395424480f87e7030000'),
    ('merge-capacity-guard', 0x1b1738e, '4801e948ffc14883f90c0f83310a0000'),
    ('choose-right-sibling', 0x1b176d0, '664183bc244a080000000f84d4060000498b9c2458080000'),
    ('right-merge-or-borrow', 0x1b1772d, '0fb78b4a0800004101cd4183fd0c735a'),
    ('right-merge-cursor-guard', 0x1b17754, '48395424480f8619fcffff'),
    ('parent-occupancy-recheck', 0x1b177ad, '498b2e4885ed74110fb7854a0800006683f8040f86e6000000'),
    ('ancestor-sibling-choice', 0x1b178f6, '0fb799480800004885db48893c240f8486000000'),
    ('root-empty-flag', 0x1b17d3d, '4885c00f8580faffff488b442478c60001'),
    ('ancestor-borrow-left-count', 0x1b17d65, 'be050000004829c6488dbc2400010000e856f5fdff'),
    ('ancestor-borrow-right-count', 0x1b17d7f, 'be050000004829c6488dbc2438010000e84c52feff'),
    ('merge-parent-count', 0x1b1759a, '6641ff8c244a080000be50080000488b1c'),
    ('merge-child-parent-links', 0x1b17510, '488d4301498bb4dc500800004c892666899e480800004889c348ffca75e2'),
    ('left-borrow-guards', 0x1af72e1, '4c8b7f28450fb7af4a0800004a8d042e4883f80c0f83d10200004989f4488b5f180fb7ab4a0800004989ee4929f60f82d002000048897c2450664489b34a0800004889442428664189874a080000'),
    ('right-borrow-guards', 0x1afcff1, '4c8b7718450fb7a64a0800004a8d04264883f80c0f83610300004989f54889fb4c8b7f28410fb78f4a0800004829f10f825f030000664189864a0800006641898f4a080000'),
    ('left-borrow-copy-length-guard', 0x1af7381, '4c29e54c896c2440498d45ff4839c50f8568020000'),
    ('left-borrow-paired-levels', 0x1af7487, '49837c242000498b442430746a4885c0746e'),
    ('right-borrow-paired-levels', 0x1afd18b, '4883782000488b40300f84ff0000004885c00f84ff000000'),
    ('left-borrow-child-parent', 0x1af7530, '498bb4cf500800004c893e89cf66898e48080000'),
    ('right-borrow-child-parent', 0x1afd1f5, '4a8b84ed58080000488928488b4c241866898848080000'),
)

# A direct edge is independently decoded and its destination is checked.
CALLS = (
    ('spot-cancel-context', 0x26de5a4, 0x2866870),
    ('perp-cancel-context', 0x26df5fa, 0x28660a0),
    ('spot-find-to-remove', 0x2866932, 0x1b22a90),
    ('perp-find-to-remove', 0x2866162, 0x1b22a90),
    ('internal-predecessor-delete', 0x1b22bb5, 0x1b17160),
    ('leaf-direct-delete', 0x1b22cbe, 0x1b17160),
    ('leaf-borrow-left', 0x1b17784, 0x1af72d0),
    ('leaf-borrow-right', 0x1b177a4, 0x1afcfe0),
    ('ancestor-borrow-left', 0x1b17d75, 0x1af72d0),
    ('ancestor-borrow-right', 0x1b17d8f, 0x1afcfe0),
)

# Labels describe the taken edge; sites and targets are decoded from raw bytes.
BRANCHES = (
    ('empty-root', 0x2866890, 'je'),
    ('search-node-exhausted', 0x28668c3, 'je'),
    ('search-greater-next-key', 0x28668dd, 'je'),
    ('search-key-equal', 0x28668e5, 'je'),
    ('search-ran-out-of-height', 0x28668f7, 'jb'),
    ('no-root-replacement', 0x2866a02, 'jne'),
    ('root-replacement-null-root', 0x2866a0a, 'je'),
    ('root-replacement-height-zero', 0x2866a17, 'je'),
    ('removed-value-is-sentinel', 0x2866ae7, 'je'),
    ('handle-is-leaf', 0x1b22ab2, 'je'),
    ('predecessor-is-immediate-child', 0x1b22ac6, 'je'),
    ('replacement-cursor-in-node', 0x1b22bfa, 'jb'),
    ('replacement-cursor-at-leaf', 0x1b22c62, 'je'),
    ('leaf-occupancy-at-least-minimum', 0x1b172d3, 'ja'),
    ('underfull-leaf-is-root', 0x1b172df, 'je'),
    ('left-edge-uses-right-sibling', 0x1b172fd, 'je'),
    ('left-sibling-borrow', 0x1b17358, 'jae'),
    ('left-merge-cursor-out-of-range', 0x1b17372, 'ja'),
    ('merge-capacity-error', 0x1b17398, 'jae'),
    ('right-sibling-needs-parent-key', 0x1b176da, 'je'),
    ('right-sibling-borrow', 0x1b1773b, 'jae'),
    ('right-merge-cursor-in-range', 0x1b17759, 'jbe'),
    ('parent-needs-repair', 0x1b177c0, 'jbe'),
    ('ancestor-is-root', 0x1b178e9, 'je'),
    ('ancestor-left-edge-uses-right-sibling', 0x1b17904, 'je'),
    ('ancestor-left-sibling-borrow', 0x1b1795d, 'jae'),
    ('ancestor-right-sibling-borrow', 0x1b179fa, 'jae'),
    ('root-still-nonempty', 0x1b17d40, 'jne'),
    ('left-borrow-capacity-error', 0x1af72f5, 'jae'),
    ('left-borrow-source-underflow', 0x1af730f, 'jb'),
    ('left-borrow-copy-length-error', 0x1af7390, 'jne'),
    ('left-borrow-first-level-zero', 0x1af7492, 'je'),
    ('left-borrow-second-level-zero', 0x1af7497, 'je'),
    ('left-borrow-both-levels-zero', 0x1af7501, 'je'),
    ('right-borrow-capacity-error', 0x1afd005, 'jae'),
    ('right-borrow-source-underflow', 0x1afd020, 'jb'),
    ('right-borrow-first-level-zero', 0x1afd194, 'je'),
    ('right-borrow-second-level-zero', 0x1afd19d, 'je'),
    ('right-borrow-both-levels-zero', 0x1afd29c, 'je'),
)

# Nine RIP-relative operands are masked only for the explicit copy comparison.
# The bytes hidden in each operand and the resolved targets are retained.
MASKS = (
    (0xc2, 'call', 1, 5), (0x1cc, 'indirect-call', 2, 6),
    (0x327, 'lea', 3, 7), (0x32e, 'indirect-call', 2, 6),
    (0x336, 'lea', 3, 7), (0x33d, 'lea', 3, 7),
    (0x349, 'indirect-call', 2, 6), (0x365, 'indirect-call', 2, 6),
    (0x36e, 'call', 1, 5),
)

# Each assertion is located by its RIP-relative string load and immediate
# length. Text is checked against the target, not copied from a reference tree.
ASSERTIONS = (
    ('left-borrow-capacity', 0x1af75cc, 0x1af75da, 'assertion failed: old_right_len + count <= CAPACITY'),
    ('left-borrow-source', 0x1af75e5, 0x1af75f3, 'assertion failed: old_left_len >= count'),
    ('left-borrow-copy-length', 0x1af75fe, 0x1af760c, 'assertion failed: src.len() == dst.len()'),
    ('left-borrow-paired-levels', 0x1af7507, 0x1af7515, 'internal error: entered unreachable code'),
    ('right-borrow-capacity', 0x1afd36c, 0x1afd37a, 'assertion failed: old_left_len + count <= CAPACITY'),
    ('right-borrow-source', 0x1afd385, 0x1afd393, 'assertion failed: old_right_len >= count'),
    ('right-borrow-paired-levels', 0x1afd2a2, 0x1afd2b0, 'internal error: entered unreachable code'),
    ('merged-node-capacity', 0x1b17ddb, 0x1b17dd6, 'assertion failed: new_left_len <= CAPACITY'),
    ('merge-cursor-range', 0x1b1776b, 0x1b17766,
     'assertion failed: match track_edge_idx {\n    LeftOrRight::Left(idx) => idx <= old_left_len,\n    LeftOrRight::Right(idx) => idx <= right_len,\n}'),
    ('replacement-height', 0x2866ba6, 0x2866bb4, 'assertion failed: self.height > 0'),
)

# The instruction forms are pinned here; the displacement and relocation are
# decoded independently. The first site loads a function pointer, the rest
# call through a RIP-relative slot. This is not indirect-call census coverage.
INDIRECT_REFS = (
    ('leaf-memmove-load', 0x1b171bc, 'load', 0x576e0e0),
    ('predecessor-copy', 0x1b22bd1, 'call', 0x576dfe0),
    ('root-replacement', 0x2866a3c, 'call', 0x576e010),
    ('replacement-null-root', 0x2866b9e, 'call', 0x576e470),
    ('replacement-zero-height', 0x2866bb9, 'call', 0x576e108),
    ('left-borrow-capacity-failure', 0x1af75df, 'call', 0x576e108),
    ('left-borrow-source-failure', 0x1af75f8, 'call', 0x576e108),
    ('left-borrow-copy-length-failure', 0x1af7611, 'call', 0x576e108),
    ('left-borrow-level-mismatch', 0x1af751a, 'call', 0x576e108),
    ('right-borrow-capacity-failure', 0x1afd37f, 'call', 0x576e108),
    ('right-borrow-source-failure', 0x1afd398, 'call', 0x576e108),
    ('right-borrow-level-mismatch', 0x1afd2b5, 'call', 0x576e108),
    ('merge-capacity-and-cursor-failure', 0x1b17de2, 'call', 0x576e108),
    ('missing-parent-key-failure', 0x1b17dc7, 'call', 0x576e098),
)


class EvidenceError(ValueError):
    pass


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)

    def offset(self, va, size=1, executable=False):
        if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
            raise EvidenceError('invalid virtual address or length')
        matching = [s for s in self.sections if s['type'] != 8
                    and (not executable or s['flags'] & 4)
                    and s['address'] <= va
                    and va + size <= s['address'] + s['size']]
        if len(matching) != 1:
            raise EvidenceError('address has no unique file-backed section')
        sec = matching[0]
        off = sec['offset'] + va - sec['address']
        if off < 0 or off + size > len(self.data):
            raise EvidenceError('file-backed range outside input')
        return off

    def read(self, va, size, executable=False):
        off = self.offset(va, size, executable)
        return self.data[off:off + size]


def authenticate(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest != TARGET_SHA256:
        raise EvidenceError('target SHA-256 mismatch')
    return digest


def validate_pins(image):
    rows = []
    for name, address, hex_bytes in PINS:
        expected = bytes.fromhex(hex_bytes)
        actual = image.read(address, len(expected), executable=True)
        if actual != expected:
            raise EvidenceError('instruction witness changed: ' + name)
        rows.append({'name': name, 'va': address, 'file_offset': image.offset(address, len(actual), True),
                     'bytes': actual.hex()})
    return rows


def decode_call(image, site):
    raw = image.read(site, 5, executable=True)
    if raw[0] != 0xe8:
        raise EvidenceError('direct call opcode changed')
    return site + len(raw) + struct.unpack_from('<i', raw, 1)[0]


def decode_branch(image, site):
    first = image.read(site, 1, executable=True)[0]
    short = {0x72: 'jb', 0x73: 'jae', 0x74: 'je', 0x75: 'jne', 0x76: 'jbe', 0x77: 'ja'}
    if first in short:
        raw = image.read(site, 2, executable=True)
        return short[first], site + 2 + struct.unpack_from('<b', raw, 1)[0], raw
    if first == 0x0f:
        raw = image.read(site, 6, executable=True)
        near = {0x82: 'jb', 0x83: 'jae', 0x84: 'je', 0x85: 'jne', 0x86: 'jbe', 0x87: 'ja'}
        if raw[1] in near:
            return near[raw[1]], site + 6 + struct.unpack_from('<i', raw, 2)[0], raw
    raise EvidenceError('unsupported conditional-branch bytes')


def limits_from_image(image):
    # Each read is covered by a complete fixed instruction witness above.
    marker = image.read(0x2866887, 6, True)
    if marker[:2] != bytes.fromhex('41bd'):
        raise EvidenceError('sentinel opcode changed')
    absent = struct.unpack_from('<I', marker, 2)[0]
    count_off = struct.unpack_from('<I', image.read(0x28668a0, 7, True), 3)[0]
    child_off = struct.unpack_from('<I', image.read(0x28668fd, 8, True), 4)[0]
    value_stride = struct.unpack_from('<I', image.read(0x1b22c18, 7, True), 3)[0]
    value_off = image.read(0x1b22c23, 4, True)[3]
    key_off = image.read(0x1b17191, 5, True)[4]
    tree_off = image.read(0x26de590, 4, True)[3]
    tree_count_off = image.read(0x28669e9, 4, True)[3]
    parent_index_off = struct.unpack_from('<I', image.read(0x1b172ee, 8, True), 4)[0]
    merge_limit = image.read(0x1b17354, 4, True)[3]
    underflow_max = image.read(0x1b172ca, 4, True)[3]
    node_bytes = struct.unpack_from('<I', image.read(0x2866a35, 5, True), 1)[0]
    if image.read(0x1b172d9, 3, True) != bytes.fromhex('4d8b26'):
        raise EvidenceError('zero-offset parent load changed')
    parent_off = 0  # The validated x86 load has no displacement.
    minimum = underflow_max + 1
    maximum = merge_limit - 1
    if (absent, tree_off, tree_count_off, key_off, value_off, value_stride,
            parent_index_off, count_off, child_off, minimum, maximum, node_bytes) != (
            2, 0x38, 0x10, 0x08, 0x60, 0xb8, 0x848, 0x84a, 0x850, 5, 11, 0x8b0):
        raise EvidenceError('decoded layout or limits are inconsistent')
    key_bytes = value_off - key_off
    value_bytes = parent_index_off - value_off
    child_bytes = node_bytes - child_off
    if (key_bytes, value_bytes, child_bytes) != (maximum * 8, maximum * value_stride, (maximum + 1) * 8):
        raise EvidenceError('node storage regions do not match decoded capacity')
    return {'absent_tag': absent, 'user_entry_tree_offset': tree_off,
            'header_count_offset': tree_count_off, 'node_key_offset': key_off,
            'node_value_offset': value_off, 'value_stride': value_stride,
            'node_parent_offset': parent_off, 'node_parent_index_offset': parent_index_off,
            'node_key_count_offset': count_off, 'node_child_offset': child_off,
            'minimum_nonroot_keys': minimum, 'maximum_keys': maximum,
            'key_slots_from_layout': key_bytes // 8,
            'value_slots_from_layout': value_bytes // value_stride,
            'child_slots_from_layout': child_bytes // 8,
            'internal_allocation_bytes': node_bytes}


def function_records(data, image):
    _, fdes, _ = fde_extents(data)
    by_start = {row['start']: row for row in fdes}
    out = []
    for name, start, end, expected_hash in FUNCTIONS:
        fde = by_start.get(start)
        if fde is None or fde['end'] != end:
            raise EvidenceError('FDE extent changed: ' + name)
        body = image.read(start, end - start, executable=True)
        digest = hashlib.sha256(body).hexdigest()
        if digest != expected_hash:
            raise EvidenceError('function body changed: ' + name)
        out.append({'name': name, 'start': start, 'end': end, 'bytes': len(body),
                    'file_offset': image.offset(start, len(body), True),
                    'fde': fde['fde'], 'cie': fde['cie'], 'sha256': digest})
    return out


def validate_calls(image):
    result = []
    for name, site, expected in CALLS:
        actual = decode_call(image, site)
        if actual != expected:
            raise EvidenceError('direct call target changed: ' + name)
        result.append({'name': name, 'site': site, 'target': actual,
                       'bytes': image.read(site, 5, True).hex()})
    return result


def branch_records(image):
    rows = []
    for label, site, expected in BRANCHES:
        condition, target, raw = decode_branch(image, site)
        if condition != expected:
            raise EvidenceError('condition changed: ' + label)
        owners = [row for row in FUNCTIONS if row[1] <= site and site + len(raw) <= row[2]]
        if len(owners) != 1 or not (owners[0][1] <= target < owners[0][2]):
            raise EvidenceError('branch target outside its FDE: ' + label)
        rows.append({'label': label, 'site': site, 'condition': condition,
                     'taken_target': target, 'fallthrough': site + len(raw), 'bytes': raw.hex()})
    return rows


def compare_copies(image):
    a = next(row for row in FUNCTIONS if row[0] == 'cancel-tree-perp')
    b = next(row for row in FUNCTIONS if row[0] == 'cancel-tree-spot')
    x = image.read(a[1], a[2] - a[1], True)
    y = image.read(b[1], b[2] - b[1], True)
    if len(x) != len(y):
        raise EvidenceError('wrapper sizes differ')
    masked_x, masked_y = bytearray(x), bytearray(y)
    operands = []
    occupied = set()
    for relative, kind, disp_at, inst_len in MASKS:
        if kind == 'call':
            expected_prefix = b'\xe8'
        elif kind == 'indirect-call':
            expected_prefix = b'\xff\x15'
        else:
            expected_prefix = None
        left, right = x[relative:relative + inst_len], y[relative:relative + inst_len]
        if len(left) != inst_len or len(right) != inst_len:
            raise EvidenceError('truncated copy-comparison instruction')
        if expected_prefix is not None:
            if not left.startswith(expected_prefix) or not right.startswith(expected_prefix):
                raise EvidenceError('copy-comparison opcode changed')
        elif left[:2] != b'\x48\x8d' or right[:3] != left[:3]:
            raise EvidenceError('copy-comparison lea changed')
        dl = struct.unpack_from('<i', left, disp_at)[0]
        dr = struct.unpack_from('<i', right, disp_at)[0]
        target_left = a[1] + relative + inst_len + dl
        target_right = b[1] + relative + inst_len + dr
        if target_left != target_right:
            raise EvidenceError('masked operands resolve to different targets')
        covered = set(range(relative + disp_at, relative + disp_at + 4))
        if occupied & covered:
            raise EvidenceError('overlapping operand masks')
        occupied |= covered
        masked_x[relative + disp_at:relative + disp_at + 4] = b'\0' * 4
        masked_y[relative + disp_at:relative + disp_at + 4] = b'\0' * 4
        operands.append({'offset': relative, 'kind': kind, 'instruction_size': inst_len,
                         'mask_offset': relative + disp_at, 'mask_size': 4,
                         'perp_site': a[1] + relative, 'spot_site': b[1] + relative,
                         'perp_bytes': left.hex(), 'spot_bytes': right.hex(), 'target': target_left})
    if masked_x != masked_y:
        raise EvidenceError('wrapper bytes differ outside declared masks')
    differences = [{'offset': i, 'perp': x[i], 'spot': y[i]} for i in range(len(x)) if x[i] != y[i]]
    if any(row['offset'] not in occupied for row in differences):
        raise EvidenceError('unmasked difference')
    return operands, differences, hashlib.sha256(masked_x).hexdigest()


def dyn_symbol_slots(image):
    names = {s['name']: s for s in image.sections}
    rela, dynsym, dynstr = (names[n] for n in ('.rela.dyn', '.dynsym', '.dynstr'))
    if any(s['type'] == 8 for s in (rela, dynsym, dynstr)) or rela['size'] % 24 or dynsym['size'] % 24:
        raise EvidenceError('unsupported dynamic tables')
    # The two GLOB_DAT symbols and three RELATIVE call slots are distinct.
    # RELATIVE addends are recorded as bytes specify them, without inferring
    # a symbol or treating the dynamic loader as having been run.
    wanted = {
        0x576dfe0: (6, 'memcpy', 0),
        0x576e0e0: (6, 'memmove', 0),
        0x576e010: (8, '', 0x54c8cb0),
        0x576e098: (8, '', 0x157b810),
        0x576e108: (8, '', 0x157b7f0),
        0x576e470: (8, '', 0x157a9f0),
    }
    found = {}
    for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', image.data, pos)
        if slot not in wanted:
            continue
        symbol, kind = info >> 32, info & 0xffffffff
        if slot in found or kind not in (6, 8):
            raise EvidenceError('unexpected dynamic relocation')
        name = ''
        if kind == 6:
            if symbol * 24 >= dynsym['size']:
                raise EvidenceError('dynamic symbol outside table')
            name_index = struct.unpack_from('<I', image.data, dynsym['offset'] + symbol * 24)[0]
            if name_index >= dynstr['size']:
                raise EvidenceError('dynamic name outside table')
            start = dynstr['offset'] + name_index
            end = image.data.find(b'\0', start, dynstr['offset'] + dynstr['size'])
            if end < 0:
                raise EvidenceError('unterminated dynamic name')
            name = image.data[start:end].decode('ascii')
        elif symbol:
            raise EvidenceError('relative relocation has a symbol')
        if (kind, name, addend) != wanted[slot]:
            raise EvidenceError('dynamic relocation content mismatch')
        found[slot] = {'slot': slot, 'relocation_type': kind, 'symbol': name, 'addend': addend,
                       'record_file_offset': pos}
    if set(found) != set(wanted):
        raise EvidenceError('dynamic relocation missing')
    return [found[slot] for slot in sorted(found)]


def indirect_references(image, relocations):
    slots = {item['slot'] for item in relocations}
    rows = []
    for name, site, form, expected in INDIRECT_REFS:
        prefix = b'\x48\x8b\x2d' if form == 'load' else b'\xff\x15'
        raw = image.read(site, len(prefix) + 4, True)
        if not raw.startswith(prefix):
            raise EvidenceError('indirect reference opcode changed: ' + name)
        target = site + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]
        if target != expected or target not in slots:
            raise EvidenceError('indirect reference target mismatch: ' + name)
        rows.append({'name': name, 'site': site, 'form': form,
                     'slot': target, 'bytes': raw.hex()})
    return rows


def assertion_records(image):
    rows = []
    for name, lea_site, length_site, expected in ASSERTIONS:
        lea = image.read(lea_site, 7, True)
        length_insn = image.read(length_site, 5, True)
        if lea[:3] != b'\x48\x8d\x3d' or length_insn[0] != 0xbe:
            raise EvidenceError('assertion operand opcode changed: ' + name)
        target = lea_site + 7 + struct.unpack_from('<i', lea, 3)[0]
        size = struct.unpack_from('<I', length_insn, 1)[0]
        raw = image.read(target, size)
        if raw != expected.encode('ascii'):
            raise EvidenceError('assertion text changed: ' + name)
        rows.append({'name': name, 'lea_site': lea_site, 'length_site': length_site,
                     'target': target, 'size': size, 'text': raw.decode('ascii')})
    return rows


def hx(value):
    return hex(value)


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def generate(data, destination):
    digest = authenticate(data)
    image = Image(data)
    pins = validate_pins(image)
    layout = limits_from_image(image)
    functions = function_records(data, image)
    calls = validate_calls(image)
    branches = branch_records(image)
    operands, differences, normalized = compare_copies(image)
    symbols = dyn_symbol_slots(image)
    indirect = indirect_references(image, symbols)
    assertions = assertion_records(image)
    destination.mkdir(parents=True, exist_ok=True)
    summary = {
        'target': {'artifact': 'artifacts/node/94/hl-node', 'sha256': digest, 'bytes': len(data)},
        'coordinate_system': 'linked ELF virtual addresses; file offsets resolved from file-backed sections',
        'functions': functions,
        'layout_and_limits': layout,
        'dynamic_relocations': symbols,
        'copy_comparison': {'wrapper_size': functions[0]['bytes'], 'raw_differing_bytes': len(differences),
                            'mask_count': len(operands), 'masked_bytes': sum(item['mask_size'] for item in operands),
                            'masked_sha256': normalized,
                            'scope': 'two wrapper FDE byte strings; only listed four-byte relative operands are masked'},
        'counts': {'function_records': len(functions), 'fixed_byte_witnesses': len(pins),
                   'direct_edges': len(calls), 'conditional_branch_records': len(branches),
                   'assertion_messages': len(assertions), 'indirect_references': len(indirect)},
        'limitations': ['Static evidence only; target bytes are not executed.',
                        'Fixture results are an independently authored model, not observations of target execution.',
                        'FDE ranges are unwind ranges, not proof of complete function discovery.',
                        'Outer user lookup and higher cancellation effects are outside this packet.',
                        'No Rust-to-target comparison or whole-node equivalence is claimed.'],
    }
    (destination / 'evidence.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    write_tsv(destination / 'functions.tsv', ['role', 'start_va', 'end_va', 'size', 'file_offset', 'fde_va', 'cie_va', 'sha256'],
              ((r['name'], hx(r['start']), hx(r['end']), r['bytes'], hx(r['file_offset']),
                hx(r['fde']), hx(r['cie']), r['sha256']) for r in functions))
    write_tsv(destination / 'witnesses.tsv', ['name', 'va', 'file_offset', 'bytes'],
              ((r['name'], hx(r['va']), hx(r['file_offset']), r['bytes']) for r in pins))
    write_tsv(destination / 'calls.tsv', ['label', 'site_va', 'target_va', 'bytes'],
              ((r['name'], hx(r['site']), hx(r['target']), r['bytes']) for r in calls))
    write_tsv(destination / 'branches.tsv', ['label', 'site_va', 'condition', 'taken_target_va', 'fallthrough_va', 'bytes'],
              ((r['label'], hx(r['site']), r['condition'], hx(r['taken_target']), hx(r['fallthrough']), r['bytes']) for r in branches))
    write_tsv(destination / 'fatal-assertions.tsv', ['label', 'lea_site_va', 'length_site_va', 'text_va', 'text_bytes', 'text'],
              ((r['name'], hx(r['lea_site']), hx(r['length_site']), hx(r['target']), r['size'],
                r['text'].replace('\\', '\\\\').replace('\n', '\\n')) for r in assertions))
    write_tsv(destination / 'relocations.tsv', ['slot_va', 'type', 'symbol', 'addend', 'record_file_offset'],
              ((hx(r['slot']), r['relocation_type'], r['symbol'], hx(r['addend']), hx(r['record_file_offset'])) for r in symbols))
    write_tsv(destination / 'indirect-references.tsv', ['label', 'site_va', 'form', 'slot_va', 'bytes'],
              ((r['name'], hx(r['site']), r['form'], hx(r['slot']), r['bytes']) for r in indirect))
    write_tsv(destination / 'masked-operands.tsv', ['offset', 'kind', 'instruction_size', 'mask_offset', 'mask_size',
                                                     'perp_site', 'spot_site', 'perp_bytes', 'spot_bytes', 'target'],
              ((hx(r['offset']), r['kind'], r['instruction_size'], hx(r['mask_offset']), r['mask_size'],
                hx(r['perp_site']), hx(r['spot_site']), r['perp_bytes'], r['spot_bytes'], hx(r['target'])) for r in operands))
    write_tsv(destination / 'copy-differences.tsv', ['offset', 'perp_byte', 'spot_byte'],
              ((hx(r['offset']), '%02x' % r['perp'], '%02x' % r['spot']) for r in differences))
    # Complete raw FDE bytes for inspection. Rows are fixed-width file reads,
    # not parsed disassembler output.
    body_rows = []
    for r in functions:
        body = image.read(r['start'], r['bytes'], True)
        for offset in range(0, len(body), 16):
            part = body[offset:offset + 16]
            body_rows.append((r['name'], hx(r['start'] + offset), hx(r['file_offset'] + offset), part.hex()))
    write_tsv(destination / 'function-bytes.tsv', ['role', 'va', 'file_offset', 'hex_bytes'], body_rows)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path, help='directory for generated evidence')
    args = parser.parse_args()
    try:
        result = generate(BINARY.read_bytes(), args.out)
    except (EvidenceError, ValueError, OSError, struct.error) as error:
        parser.exit(1, 'evidence error: %s\n' % error)
    print('generated %d functions and %d direct edges' % (
        result['counts']['function_records'], result['counts']['direct_edges']))


if __name__ == '__main__':
    main()
