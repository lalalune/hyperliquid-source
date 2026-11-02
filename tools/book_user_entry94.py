#!/usr/bin/env python3
"""Recover the node 94 book-user entry insertion path from authenticated ELF bytes.

Addresses are linked ELF VAs. Instruction sites are manually selected after
inspection; only the fixed encodings used at those sites are interpreted here.
The tool does not execute the captured binary or invoke external programs.
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
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

TARGET = ROOT / 'artifacts/node/94/hl-node'
TARGET_DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Only these FDEs are analyzed as bodies. The order-insert context is a
# bounded caller window, not a fourth recovered function.
FUNCTIONS = (
    ('user-entry', 0x25a7730, 0x25a78d6,
     '8cf580355147964285fe6141466edb4f01e656dadb7a74912103da20a83f2b16'),
    ('vacant-entry-insert', 0x287ae20, 0x287aff0,
     'c43ccbaa8e8771640369ff853cc4f163c961a8fec5334dd8acbd26dfc1b133d9'),
    ('node-insert-and-split', 0x1a9a820, 0x1a9bc1a,
     '62217606421248791ba73593067b7a380f72f18bdccf467d3c0c0037cf3bd1be'),
    ('conditional-queue-append', 0x2517560, 0x25175b2,
     '5f6978f6a37f128eb95a30d2dea8fedfdd18ae691221ddf2d649937ca0731456'),
    ('wrapped-queue-growth', 0x3438fc0, 0x343904a,
     '1a62f9213e29176a0147169cc8358bec8fbdf01174d736e4608f387996adc1b2'),
)

# SHA-256 pins cover whole selected instruction windows, including operands;
# they also make local corruption visible when testing without a whole-file hash.
WINDOWS = (
    ('caller-reduce-flag', 0x26ebdf9, 0x26ebe0d, 'feeb7de4fcbb6e1c431f185833777473639584eefcd34e11d87edc7fd7777d82'),
    ('caller-id-input', 0x26ebfcb, 0x26ebfe9, 'abc42692ad864990effd3d524a23adf150985713ce6dca6a300bd702048dcbf7'),
    ('caller-id-select', 0x26ec841, 0x26ec87b, '1d1d9c75dcb7aaf07a4a5f79642f61d38fad4149212ae3f6145b1d58355102ee'),
    ('caller-id-save', 0x26eca18, 0x26eca20, 'f84bdf961ffb18df156bcd6c4bfcf59b386438be803712f225a4d26fe842f0da'),
    ('caller-queue-gate', 0x26ee079, 0x26ee0c0, 'a73e4c1ef7d47a3a061543f8fa640aa08aa3ee61aa31ace5e3280d064e2246ca'),
    ('queue-append', 0x2517564, 0x25175b2, 'cdf75caeed523e070edc6227597e96e9555c708b300ac58dac6f1c21641c3132'),
    ('wrapped-queue-growth', 0x3438fc5, 0x343904a, '652e4412231d5f07a9389a4c8459cbbbe35db38967af2fef05785bc245ce9178'),
    ('caller-entry-book', 0x26ebdda, 0x26ebde2, 'd5854f0ae7a8a8cc31c20936376ebe7aa337de0fa96b49ddbddc339bc8b0fe09'),
    ('caller-user-key', 0x26ec0f7, 0x26ec126, '8de205d183d6c90d8c491d946615b23356717d97a2daff2d15725a9c3bb898b9'),
    ('caller-slot-and-links', 0x26edf1d, 0x26edf95, '6b227f22bf1d33f83e8c17fa4a73eed0c40740a2263959ef19efe50c85a0d979'),
    ('order-insert-context', 0x26edfff, 0x26ee045, 'f6de572294ea4138e313018948bb9dddbd24c74d6937341798879a39ae050944'),
    ('entry-search', 0x25a7741, 0x25a7805, 'e51d6e08e8368d762e876fbb39864fd496ef02832d3f0385eedacdcaf1faed02'),
    ('entry-default', 0x25a7805, 0x25a78aa, '5b669051e531c31530a850a3c720ef8b740812b2bb7a79909262e6fbb6c53cc7'),
    ('entry-result', 0x25a78aa, 0x25a78c4, 'edfab2f6bcb236a22edbe983e3ba785b2e09b0dc05c5c277f89d7764a7106208'),
    ('allocate-dispatch', 0x287ae37, 0x287ae9a, '6e593f7c3bfeabda8e1a58ca3f4f2238ed6718987078bfa1b1e797c803435854'),
    ('empty-allocation', 0x287ae9a, 0x287aed2, '5b83586ab1ce9314088b1268711e219a9126a252eb99714ca64db60301d1da9b'),
    ('empty-fill', 0x287aed2, 0x287af86, '9c0fb9886686cffe06543db2710aebe474d3bcbc5bb9a8d8b9cbdc74b3ed8559'),
    ('allocator-failures', 0x287af95, 0x287afc2, '2754bdcde7826e29aae668f55a2cb8f8b52974d8c575dc48c712da5d26d39685'),
    ('leaf-probe', 0x1a9a841, 0x1a9a884, 'df8faacde9a532acf8a323bc0cb139a65dd715ab51deccee8de1d3fa2e695315'),
    ('split-position', 0x1a9a8f8, 0x1a9a91f, 'eb95e2f2c352b571aba34155bf1b30613c4444702323a31b409475f7159bf991'),
    ('split-position-tail', 0x1a9aa6a, 0x1a9aa85, 'b2c7618d5e75ac20ddd9d3906ba666509729d733951317c65b65bb3de5f734b9'),
    ('leaf-placement', 0x1a9a884, 0x1a9aa65, '28997ec03fa15b7ab0082423bc48213a5349194867ab52993ee8fd65821d7f8d'),
    ('leaf-split', 0x1a9aa85, 0x1a9ae5c, 'b8fbde26346097e2f74ef67b4ca52de9a8fd7530a563323096da2900e70e1112'),
    ('ancestor-insert', 0x1a9aed2, 0x1a9b1fa, 'c724fa835570934f9bb1723480f9b7baa2fe07bed9a287d0d7f11c9fa2f43f13'),
    ('ancestor-split', 0x1a9b220, 0x1a9b848, '93e356e1e65148c2bceccdb92f75108c8e828cf2cab14a371aef5a752dee7598'),
    ('root-install', 0x1a9b8ef, 0x1a9ba23, '93452a63501e2966fb15deb72d40201580ffcbc0ff1d57defa61b39df9e04cc2'),
    ('diagnostics', 0x1a9ba23, 0x1a9bb3f, '01184cfa14d1e17465d3f22456d426bef1fa902fda1b7f1ac593356a2abbefb6'),
)

# Branches were individually inspected as instruction starts. The table is
# selected, not a claim to decode every conditional instruction in these FDEs.
BRANCHES = (
    (0x2517574, 'jne', 'queue has spare capacity: skip growth'),
    (0x3438fe2, 'jbe', 'queue data is not wrapped in old allocation'),
    (0x343900b, 'jne', 'copy the shorter front segment into appended capacity'),
    (0x25a774f, 'je', 'null root enters vacant-entry construction'),
    (0x25a779c, 'je', 'all live keys examined'),
    (0x25a77ca, 'je', 'search key greater than node key: advance'),
    (0x25a77d1, 'je', 'equal key returns existing value'),
    (0x25a77ee, 'jb', 'height exhausted: create a vacant entry'),
    (0x287ae3c, 'je', 'no node: allocate first leaf'),
    (0x287aeab, 'je', 'first-leaf allocation returned null'),
    (0x287af0e, 'jae', 'first-leaf count not below capacity'),
    (0x1a9a862, 'jb', 'leaf has room'),
    (0x1a9a86c, 'jae', 'full leaf insertion position at least midpoint'),
    (0x1a9a8a3, 'jbe', 'non-full leaf insertion shifts existing entries'),
    (0x1a9a8f8, 'je', 'full leaf insertion position equals midpoint'),
    (0x1a9a902, 'jne', 'full leaf insertion position differs from midpoint plus one'),
    (0x1a9aa9c, 'je', 'new right-leaf allocation returned null'),
    (0x1a9ab4c, 'jae', 'split right length is outside expected range'),
    (0x1a9ac65, 'jbe', 'selected split leaf insertion at or after end'),
    (0x1a9aedc, 'je', 'split node has no parent: install root'),
    (0x1a9af48, 'jne', 'ancestor edge height assertion'),
    (0x1a9af5f, 'jae', 'ancestor is full: split'),
    (0x1a9af7c, 'jae', 'ancestor insertion is at end'),
    (0x1a9b09a, 'jae', 'full ancestor insertion position at least midpoint'),
    (0x1a9b224, 'je', 'full ancestor insertion position equals midpoint'),
    (0x1a9b22a, 'jne', 'full ancestor insertion position differs from midpoint plus one'),
    (0x1a9b26e, 'je', 'right internal-node allocation returned null'),
    (0x1a9b312, 'jae', 'internal split right length outside key range'),
    (0x1a9b3e2, 'jae', 'internal split edge length outside range'),
    (0x1a9b3f1, 'jne', 'internal edge copy lengths disagree'),
    (0x1a9b83d, 'jne', 'parent exists: propagate another split'),
    (0x1a9b8f9, 'je', 'root expected during split is null'),
    (0x1a9b911, 'je', 'new-root allocation returned null'),
    (0x1a9b93b, 'je', 'root height increment wraps'),
    (0x1a9b95c, 'jne', 'root edge height assertion'),
    (0x1a9b96e, 'jae', 'new-root key count is not below capacity'),
)

DIRECT_CALLS = (
    ('order insertion to user entry', 0x26ee02f, 0x25a7730),
    ('user entry to vacant insertion', 0x25a78aa, 0x287ae20),
    ('existing root to node insert', 0x287ae7e, 0x1a9a820),
    ('conditional second user lookup', 0x26ee0a9, 0x25a7730),
    ('conditional queue append', 0x26ee0bb, 0x2517560),
)

# RIP-relative indirect calls or pointer loads whose slots have ELF relocations.
REFERENCES = (
    ('full queue to growth slot', 0x2517579, 'ff15', 0x5771620),
    ('queue backing storage growth', 0x3438fcb, 'ff15', 0x5774458),
    ('wrapped high-segment move', 0x3439023, 'ff15', 0x576e0e0),
    ('wrapped low-segment copy', 0x3439044, 'ff25', 0x576dfe0),
    ('key comparison', 0x25a77aa, 'ff15', 0x576e488),
    ('first leaf allocate', 0x287aea2, 'ff15', 0x576dfd8),
    ('first leaf allocation error', 0x287af9f, 'ff15', 0x576e020),
    ('first leaf capacity assertion', 0x287afba, 'ff15', 0x576e108),
    ('leaf key shift', 0x1a9a94f, 'ff15', 0x576e0e0),
    ('right leaf allocate', 0x1a9aa93, 'ff15', 0x576dfd8),
    ('split copy pointer load', 0x1a9ab81, '4c8b25', 0x576dfe0),
    ('split key shift', 0x1a9ac94, 'ff15', 0x576e0e0),
    ('parent key shift', 0x1a9afc0, 'ff15', 0x576e0e0),
    ('right internal allocate', 0x1a9b265, 'ff15', 0x576dfd8),
    ('internal split copy pointer load', 0x1a9b342, '488b05', 0x576dfe0),
    ('new root allocate', 0x1a9b908, 'ff15', 0x576dfd8),
    ('ancestor height assertion', 0x1a9ba36, 'ff15', 0x576e108),
    ('internal split bounds error', 0x1a9ba52, 'ff15', 0x576e2e0),
    ('internal allocation error', 0x1a9ba83, 'ff15', 0x576e020),
    ('null root failure', 0x1a9bade, 'ff15', 0x576e470),
    ('root assertions', 0x1a9bb37, 'ff15', 0x576e108),
)

DIAGNOSTICS = (
    ('node capacity', 0x287afa7, 0x287afb5),
    ('ancestor edge height', 0x1a9ba23, 0x1a9ba31),
    ('split edge copy lengths', 0x1a9ba8e, 0x1a9ba9c),
    ('new-root edge height', 0x1a9bb13, 0x1a9bb0e),
    ('new-root capacity', 0x1a9bb28, 0x1a9bb23),
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_digest(data, expected=TARGET_DIGEST):
    if digest(data) != expected:
        raise ValueError('node 94 SHA-256 mismatch')


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)

    def offset(self, va, size, executable=False):
        if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
            raise ValueError('invalid address or size')
        candidates = [s for s in self.sections
                      if s['type'] != 8 and s['flags'] & 2
                      and (not executable or s['flags'] & 4)
                      and s['address'] <= va
                      and va + size <= s['address'] + s['size']]
        if len(candidates) != 1:
            raise ValueError('address is not uniquely file-backed')
        s = candidates[0]
        return s['offset'] + va - s['address']

    def read(self, va, size, executable=False):
        o = self.offset(va, size, executable)
        return self.data[o:o + size]

    def section(self, name):
        rows = [s for s in self.sections if s['name'] == name and s['type'] != 8]
        if len(rows) != 1:
            raise ValueError('missing or ambiguous file-backed section')
        return rows[0]


def require_bytes(image, va, pattern):
    expected = bytes.fromhex(pattern)
    got = image.read(va, len(expected), executable=True)
    if got != expected:
        raise ValueError(f'instruction bytes differ at {va:#x}')
    return got


def constants(image):
    # Values are decoded from instructions, not a separately supplied schema.
    pins = {
        'key_size': (0x25a77a2, 'ba14000000', 1, '<I'),
        'value_stride_neg': (0x25a7767, '4d8d7c24b0', 4, '<b'),
        'keys_offset': (0x25a7786, 'bd78030000', 1, '<I'),
        'node_length_offset': (0x25a775e, '410fb7842456040000', 5, '<I'),
        'edge_offset': (0x25a77f5, '4d8ba4dc58040000', 4, '<I'),
        'parent_offset': (0x1a9aed2, '4d8baa70030000', 3, '<I'),
        'parent_index_offset': (0x1a9aef0, '450fb79a54040000', 4, '<I'),
        'capacity': (0x1a9a84c, '4983fd0b', 3, '<B'),
        'midpoint': (0x1a9a868, '4983fd05', 3, '<B'),
        'left_pivot': (0x1a9a877, '41bd04000000', 2, '<I'),
        'right_pivot': (0x1a9aa7c, '41bd06000000', 2, '<I'),
        'right_adjust': (0x1a9aa73, '4983c5f9', 3, '<b'),
        'leaf_bytes': (0x287ae9d, 'bf58040000', 1, '<I'),
        'internal_bytes': (0x1a9b260, 'bfb8040000', 1, '<I'),
        'book_user_offset': (0x26edfff, '4c8db0b8000000', 3, '<I'),
        'order_user_offset': (0x26ec0f7, '488d8bb8000000', 3, '<I'),
        'user_index_offset': (0x26ee034, '4883c020', 3, '<B'),
        'slot_stride': (0x26edf67, '4869c9f8000000', 3, '<I'),
        'slot_vacant_tag': (0x26edf6e, '833c0802', 3, '<B'),
        'order_flag_offset': (0x26ebe02, '0fb68290000000', 3, '<I'),
        'queue_length_offset': (0x251756d, '488b4f18', 3, '<B'),
        'queue_head_offset': (0x251758e, '49034e10', 3, '<B'),
        'queue_pointer_offset': (0x251759e, '498b5608', 3, '<B'),
    }
    out = {}
    for name, (va, raw, off, fmt) in pins.items():
        inst = require_bytes(image, va, raw)
        out[name] = struct.unpack_from(fmt, inst, off)[0]
    out['value_stride'] = -out.pop('value_stride_neg')
    modrm = require_bytes(image, 0x251756a, '488b07')[2]
    if modrm & 0xc7 != 7:
        raise ValueError('unexpected queue capacity addressing')
    out['queue_capacity_offset'] = modrm >> 6
    sib = require_bytes(image, 0x25175a6, '48891cca')[3]
    out['queue_item_stride'] = 1 << (sib >> 6)
    # Pin the compare, unsigned set conditions and their OR before modeling
    # the wrapped-growth decision; do not infer them from disassembler text.
    for va, pattern in (
        (0x2517594, '4839c1'), (0x2517597, '480f43d0'),
        (0x3438fdf, '4839c1'), (0x3438ff0, '4839d0'),
        (0x3438ff3, '400f96c6'), (0x3438ffd, '4839d7'),
        (0x3439000, '400f92c7'), (0x3439004, '4008f7'),
        (0x3439007, '4080ff01'),
    ):
        require_bytes(image, va, pattern)
    if (out['queue_capacity_offset'], out['queue_pointer_offset'],
            out['queue_head_offset'], out['queue_length_offset'], out['queue_item_stride']) != (0, 8, 16, 24, 8):
        raise ValueError('inconsistent queue layout')
    if not (out['left_pivot'] + 1 == out['midpoint']
            and out['right_pivot'] == out['midpoint'] + 1
            and out['right_adjust'] == -(out['right_pivot'] + 1)):
        raise ValueError('inconsistent split-position constants')
    if not (out['keys_offset'] == out['value_stride'] * out['capacity'] + 8
            and out['parent_offset'] == out['value_stride'] * out['capacity']
            and out['parent_index_offset'] == out['keys_offset'] + out['key_size'] * out['capacity']
            and out['node_length_offset'] == out['parent_index_offset'] + 2
            and out['edge_offset'] == out['leaf_bytes']
            and out['internal_bytes'] == out['leaf_bytes'] + 8 * (out['capacity'] + 1)):
        raise ValueError('inconsistent node layout')
    return out



def initial_stores(image):
    # Decode the six writes to the value initialized on the stack. Bytes at
    # other offsets are intentionally not assigned a value by this table.
    base_inst = require_bytes(image, 0x25a78a2, '488d942488000000')
    base = struct.unpack_from('<I', base_inst, 4)[0]
    require_bytes(image, 0x25a7861, '0f57c0')  # xorps xmm0, xmm0
    instructions = (
        (0x25a7855, '48c78424a800000000000000', 'qword'),
        (0x25a7864, '0f118424b8000000', 'xmm-zero'),
        (0x25a786c, '48c784248800000000000000', 'qword'),
        (0x25a7878, '48c784249000000008000000', 'qword'),
        (0x25a7884, '48c78424d000000000000000', 'qword'),
        (0x25a7890, '0f11842498000000', 'xmm-zero'),
    )
    rows = []
    for va, pattern, kind in instructions:
        raw = require_bytes(image, va, pattern)
        disp = struct.unpack_from('<I', raw, 4)[0]
        width = 8 if kind == 'qword' else 16
        value = struct.unpack_from('<I', raw, 8)[0] if kind == 'qword' else 0
        if disp < base or disp + width > base + 0x50:
            raise ValueError('initial value write outside record')
        rows.append([hex(va), raw.hex(), hex(disp - base), width, value])
    return sorted(rows, key=lambda row: int(row[2], 16))


def selected_fdes(image):
    _, table = unwind_index(image.data)
    _, records = eh_frame_records(image.data, image.sections)
    by_fde = {r['fde']: r for r in records}
    result = []
    for role, start, end, expected_hash in FUNCTIONS:
        rows = [r for r in table if r['start'] == start]
        if len(rows) != 1:
            raise ValueError('selected start has no unique unwind index entry')
        record = by_fde.get(rows[0]['fde'])
        if record is None or record['start'] != start or record['end'] != end:
            raise ValueError('selected FDE extent differs')
        body = image.read(start, end - start, executable=True)
        if digest(body) != expected_hash:
            raise ValueError(f'function bytes differ at {start:#x}')
        result.append((role, record, image.offset(start, len(body), True), body))
    return result


def window_rows(image):
    out = []
    for name, start, end, expected_hash in WINDOWS:
        raw = image.read(start, end - start, executable=True)
        actual = digest(raw)
        if actual != expected_hash:
            raise ValueError(f'witness bytes differ at {start:#x}')
        out.append([name, hex(start), hex(end), hex(image.offset(start, len(raw), True)),
                    len(raw), raw.hex(), actual])
    return out


def direct_call(image, site, target):
    raw = image.read(site, 5, executable=True)
    if raw[0] != 0xe8:
        raise ValueError(f'not a direct call at {site:#x}')
    actual = site + 5 + struct.unpack_from('<i', raw, 1)[0]
    if actual != target:
        raise ValueError(f'call target differs at {site:#x}')
    return raw, actual


CONDITION_NAMES = {2: 'jb', 3: 'jae', 4: 'je', 5: 'jne', 6: 'jbe'}


def branch(image, va, expected):
    head = image.read(va, 2, executable=True)
    if 0x70 <= head[0] <= 0x7f:
        length = 2
        cc = head[0] & 15
        displacement = struct.unpack_from('<b', head, 1)[0]
    elif head[0] == 0x0f and 0x80 <= head[1] <= 0x8f:
        length = 6
        cc = head[1] & 15
        raw = image.read(va, length, executable=True)
        displacement = struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError(f'unsupported branch encoding at {va:#x}')
    name = CONDITION_NAMES.get(cc)
    if name != expected:
        raise ValueError(f'branch condition differs at {va:#x}')
    return image.read(va, length, True), va + length, va + length + displacement


def rip_reference(image, site, prefix, expected_slot=None):
    op = bytes.fromhex(prefix)
    raw = image.read(site, len(op) + 4, executable=True)
    if not raw.startswith(op):
        raise ValueError(f'RIP-relative encoding differs at {site:#x}')
    target = site + len(raw) + struct.unpack_from('<i', raw, len(op))[0]
    if expected_slot is not None and target != expected_slot:
        raise ValueError(f'RIP-relative target differs at {site:#x}')
    return raw, target


def relocations(image, wanted):
    rel = image.section('.rela.dyn')
    symbols = image.section('.dynsym')
    strings = image.section('.dynstr')
    if rel['size'] % 24 or symbols['size'] % 24:
        raise ValueError('unexpected ELF record size')
    found = {}
    for off in range(rel['offset'], rel['offset'] + rel['size'], 24):
        dest, info, addend = struct.unpack_from('<QQq', image.data, off)
        if dest not in wanted:
            continue
        if dest in found:
            raise ValueError('duplicate relocation slot')
        typ, symbol_index = info & 0xffffffff, info >> 32
        name = ''
        if symbol_index:
            if symbol_index * 24 >= symbols['size']:
                raise ValueError('dynamic symbol out of range')
            name_off = struct.unpack_from('<I', image.data, symbols['offset'] + symbol_index * 24)[0]
            if name_off >= strings['size']:
                raise ValueError('dynamic string out of range')
            start = strings['offset'] + name_off
            end = image.data.find(b'\0', start, strings['offset'] + strings['size'])
            if end < 0:
                raise ValueError('unterminated dynamic symbol')
            name = image.data[start:end].decode('ascii')
        found[dest] = (typ, symbol_index, addend, name, off)
    if set(found) != set(wanted):
        raise ValueError('missing selected relocation')
    expected = {
        0x576dfd8: (8, '', 0x54c06b0), 0x576dfe0: (6, 'memcpy', 0),
        0x576e020: (8, '', 0x1345e2a), 0x576e0e0: (6, 'memmove', 0),
        0x576e108: (8, '', 0x157b7f0), 0x576e2e0: (8, '', 0x157a6f0),
        0x576e470: (8, '', 0x157a9f0), 0x576e488: (6, 'memcmp', 0),
        0x5771620: (8, '', 0x3438fc0), 0x5774458: (8, '', 0x32d5780),
    }
    for slot, (typ, symbol_index, addend, name, _) in found.items():
        if (typ, name, addend) != expected[slot]:
            raise ValueError('selected relocation type, symbol or addend differs')
        if typ == 8:
            if symbol_index or addend <= 0:
                raise ValueError('invalid relative relocation')
            image.offset(addend, 1, executable=True)
        elif addend != 0 or symbol_index == 0:
            raise ValueError('invalid external-symbol relocation')
    return found


def diagnostic(image, label, lea_site, length_site):
    raw, text_va = rip_reference(image, lea_site, '488d3d')
    imm = image.read(length_site, 5, executable=True)
    if imm[0] != 0xbe:
        raise ValueError('unexpected diagnostic length instruction')
    length = struct.unpack_from('<I', imm, 1)[0]
    if not 0 < length <= 200:
        raise ValueError('invalid diagnostic length')
    text = image.read(text_va, length).decode('ascii')
    expected = {
        'node capacity': 'assertion failed: idx < CAPACITY',
        'ancestor edge height': 'assertion failed: edge.height == self.node.height - 1',
        'split edge copy lengths': 'assertion failed: src.len() == dst.len()',
        'new-root edge height': 'assertion failed: edge.height == self.height - 1',
        'new-root capacity': 'assertion failed: idx < CAPACITY',
    }
    if text != expected[label]:
        raise ValueError('diagnostic text differs')
    return [label, hex(lea_site), raw.hex(), hex(text_va), hex(length_site), length, text]


def split_position(position, c):
    """Return the observed split choice for a valid full-node insertion slot."""
    if not 0 <= position <= c['capacity']:
        raise ValueError('insertion position outside full node')
    mid = c['midpoint']
    if position < mid:
        return c['left_pivot'], 'left', position
    if position == mid:
        return mid, 'left', position
    if position == mid + 1:
        return mid, 'right', 0
    return c['right_pivot'], 'right', position + c['right_adjust']


def split_example(position, c):
    # Synthetic ordered integer labels represent distinct 20-byte keys. This
    # models the stated interpretation; it never executes the target code.
    old = list(range(2, 2 * c['capacity'] + 1, 2))
    incoming = position * 2 + 1
    pivot, side, local = split_position(position, c)
    left, promoted, right = old[:pivot], old[pivot], old[pivot + 1:]
    (left if side == 'left' else right).insert(local, incoming)
    if left + [promoted] + right != sorted(old + [incoming]):
        raise ValueError('split model lost key ordering')
    return [position, pivot, side, local, incoming, promoted,
            len(left), len(right), ','.join(map(str, left)), ','.join(map(str, right))]



def queue_append_index(capacity, head, length):
    # This is a model for valid queue states, not an input validator in node 94.
    max_word = (1 << 64) - 1
    if (capacity <= 0 or capacity > max_word or not 0 <= head < capacity
            or not 0 <= length < capacity or head + length > max_word):
        raise ValueError('invalid synthetic queue state')
    total = head + length
    return total - capacity if total >= capacity else total


def queue_growth_example(capacity, head, new_capacity):
    """Synthetic full-queue resize, conditional append, and ordering check.

    The backing allocator is an external contract: new_capacity is a selected
    test input, not a claim about the target allocator's growth policy.
    """
    if capacity < 0 or new_capacity <= capacity:
        raise ValueError('invalid capacities')
    if capacity == 0:
        if head != 0:
            raise ValueError('empty queue head must be zero')
        return [0, 0, 0, new_capacity, 0, 0, 'no-wrap', 0, 0, '1']
    if not 0 <= head < capacity:
        raise ValueError('invalid head')
    length = capacity  # the selected caller grows only on length == capacity
    buffer = [None] * new_capacity
    for i in range(length):
        buffer[(head + i) % capacity] = i + 1
    high = capacity - head
    low = length - high
    if head <= capacity - length:
        action, new_head = 'no-wrap', head
    elif high <= low or new_capacity - capacity < low:
        action, new_head = 'move-high', new_capacity - high
        buffer[new_head:new_head + high] = buffer[head:head + high]
    else:
        action, new_head = 'copy-low', head
        buffer[capacity:capacity + low] = buffer[:low]
    append_index = queue_append_index(new_capacity, new_head, length)
    buffer[append_index] = length + 1
    logical = [buffer[(new_head + i) % new_capacity] for i in range(length + 1)]
    if logical != list(range(1, length + 2)):
        raise ValueError('synthetic queue order changed during growth')
    return [capacity, head, length, new_capacity, high, low, action, new_head,
            append_index, ','.join(map(str, logical))]


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def generate(data, out):
    verify_digest(data)
    image = Image(data)
    fdes = selected_fdes(image)
    const = constants(image)
    windows = window_rows(image)
    init_rows = initial_stores(image)
    branch_rows = []
    for va, condition, note in BRANCHES:
        raw, fallthrough, target = branch(image, va, condition)
        if not any(start <= va and target < end and target >= start for _, start, end, _ in FUNCTIONS):
            raise ValueError('selected branch leaves its claimed FDE')
        branch_rows.append([hex(va), raw.hex(), condition, hex(fallthrough), hex(target), note])
    edge_rows = []
    for label, va, target in DIRECT_CALLS:
        raw, destination = direct_call(image, va, target)
        edge_rows.append([label, hex(va), raw.hex(), hex(destination)])
    indirect_rows = []
    for label, va, prefix, target in REFERENCES:
        raw, slot = rip_reference(image, va, prefix, target)
        indirect_rows.append([label, hex(va), raw.hex(), hex(slot)])
    rels = relocations(image, {row[3] for row in REFERENCES})
    rel_rows = [[hex(k), hex(v[0]), v[1], hex(v[2]) if v[2] >= 0 else str(v[2]), v[3], hex(v[4])]
                for k, v in sorted(rels.items())]
    diag_rows = [diagnostic(image, *row) for row in DIAGNOSTICS]
    split_rows = [split_example(i, const) for i in range(const['capacity'] + 1)]
    queue_rows = [queue_growth_example(0, 0, 1)]
    queue_rows.extend(queue_growth_example(capacity, head, capacity + extra)
                      for capacity in range(1, const['capacity'] + 1)
                      for head in range(capacity)
                      for extra in range(1, capacity + 1))
    out.mkdir(parents=True, exist_ok=True)
    function_rows, bytes_rows = [], []
    for role, r, file_off, body in fdes:
        function_rows.append([role, hex(r['start']), hex(r['end']), len(body), hex(file_off),
                              hex(r['fde']), hex(r['cie']), '' if r['lsda'] is None else hex(r['lsda']), digest(body)])
        for i in range(0, len(body), 16):
            bytes_rows.append([role, hex(r['start'] + i), hex(file_off + i), body[i:i + 16].hex()])
    write_tsv(out / 'functions.tsv', ['role', 'start_va', 'end_va', 'bytes', 'file_offset', 'fde_va', 'cie_va', 'lsda_va', 'sha256'], function_rows)
    write_tsv(out / 'function-bytes.tsv', ['role', 'va', 'file_offset', 'hex'], bytes_rows)
    write_tsv(out / 'witnesses.tsv', ['label', 'start_va', 'end_va', 'file_offset', 'size', 'hex', 'sha256'], windows)
    write_tsv(out / 'branches.tsv', ['site_va', 'hex', 'condition', 'fallthrough_va', 'target_va', 'taken_interpretation'], branch_rows)
    write_tsv(out / 'calls.tsv', ['meaning', 'site_va', 'hex', 'target_va'], edge_rows)
    write_tsv(out / 'indirect-references.tsv', ['meaning', 'site_va', 'hex', 'slot_va'], indirect_rows)
    write_tsv(out / 'relocations.tsv', ['slot_va', 'type', 'symbol_index', 'addend', 'symbol', 'record_file_offset'], rel_rows)
    write_tsv(out / 'failure-diagnostics.tsv', ['meaning', 'lea_va', 'lea_hex', 'text_va', 'length_instruction_va', 'length', 'ascii'], diag_rows)
    write_tsv(out / 'initial-value.tsv', ['site_va', 'hex', 'value_offset', 'width', 'value'], init_rows)
    write_tsv(out / 'queue-growth-cases.tsv', ['old_capacity', 'old_head', 'old_length', 'new_capacity', 'high_count', 'low_count', 'movement', 'new_head', 'append_index', 'logical_after'], queue_rows)
    write_tsv(out / 'split-cases.tsv', ['insertion_position', 'promoted_old_index', 'receiving_side', 'local_position', 'incoming_key', 'promoted_key', 'left_count', 'right_count', 'left_keys', 'right_keys'], split_rows)
    summary = {
        'target_sha256': digest(data),
        'coordinate_system': 'linked ELF virtual addresses; byte ranges are half-open',
        'constants_from_instructions': const,
        'counts': {'selected_fdes': len(fdes), 'selected_windows': len(windows),
                   'selected_branches': len(branch_rows), 'direct_call_edges': len(edge_rows),
                   'indirect_references': len(indirect_rows), 'relocation_slots': len(rel_rows),
                   'diagnostic_references': len(diag_rows), 'initial_value_writes': len(init_rows),
                   'synthetic_split_positions': len(split_rows),
                   'synthetic_queue_growth_cases': len(queue_rows)},
        'limitations': 'Manually selected branch sites; no exhaustive disassembly, target execution, Rust comparison, or complete helper closure.',
    }
    (out / 'evidence.json').write_text(json.dumps(summary, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = generate(TARGET.read_bytes(), args.out)
    print(json.dumps(result['counts'], sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, UnicodeError, ValueError, struct.error) as error:
        print(f'book_user_entry94: {error}', file=sys.stderr)
        raise SystemExit(1)
