#!/usr/bin/env python3
"""Extract node 94 insertion-result ownership witnesses, without running the node."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import fde_extents, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# The two already researched insertion bodies supply bounded call-site context only.
SELECTED = {
    0x32d5e80: (0x32d5ee4, 'dca215a5f52d85b9fdf97197d3298fa7a29551d2236316a8cac3dd1d23b0e427', 'wide growth'),
    0x454f1f0: (0x454f254, '9a9187e2249182d46869dfb574d459afd8ee18efa8032262837b49401cd10aca', 'narrow growth'),
    0x277b220: (0x277b4e3, 'b6ba511c2f2a7da68cdf23f77cf1a61b4a620836b27f3dcb1d94d016363d1cd9', 'wide cleanup'),
    0x433f6a0: (0x433f963, '8cff5669e291d0ec9c2dc413cbc6d7c17bf015f6b0705b91b0bee300fca93c87', 'narrow cleanup'),
}
CONTEXT = {0x26ebdc0: 0x26eff10, 0x430d610: 0x4311140}
WINDOWS = (
    ('initial-state', 0x26ec954, 0x26ec9d3, 'c784c9b5d655539b336d1dedec3adfbd4b9c8ed052f76f8b3d89e4adee7cc7aa'),
    ('append-wide', 0x26ed2cb, 0x26ed312, '4ce21c6995f42df1f6ad5ccf42c1f87112cd78ef37948bb9fd0ca2c30f39a85f'),
    ('copy-wide-context', 0x26ed985, 0x26eda3f, 'c6929bb06a809a5046bb729de71ddb00eea754a8539beac2c336f3cee919b1fa'),
    ('success-transfer-wide', 0x26ef670, 0x26ef71f, '4699922eddd30bbbd9af5fac1af2d4a049ae4a59c40a4e342e31a0fb9aa04681'),
    ('success-cleanup-wide', 0x26ef71f, 0x26ef782, 'cbbc07df88ad9c2475a1809ee790687a9410eaaf0804183d343e1ae28ec5b0cb'),
    ('growth-landing-wide', 0x26efdc6, 0x26efe02, '8ee0c908ab33de25bdeb5842544c1936b6ecc7f30cf76d97d654daa42eec0ed7'),
    ('unwind-drop-wide', 0x26efe96, 0x26efeb2, '8f47c22d97f0ac65238b0f6fee40b816bcc22d61d13730122197d0b19de424ba'),
    ('append-narrow', 0x430f1ec, 0x430f293, 'bc3cf10e1b65e5cc3225afa5c7f2636d3fab1f8196130b7f9a019fada34b0576'),
    ('growth-landing-narrow', 0x4311018, 0x431102c, '7e759750ffda9d787d9ba8db34b4991cd3791d1dc466578c4db67bbaa740f492'),
    ('unwind-drop-narrow', 0x43110d6, 0x43110ee, 'f0222afdbec2c510304b132ec6234396f1db671fe6beb861b5012a2f76041435'),
    ('drop-wide-vectors', 0x277b323, 0x277b375, '18dde945d986f6ad8bea57d14fec3e7b0deed6e548dda8f295c391cd8af242fa'),
    ('drop-wide-nested', 0x277b375, 0x277b43f, '0099bb7ac3752ee42d97316701db9e6b044e80907fa52489d5f51f05a22a5f9a'),
    ('drop-wide-unwind', 0x277b449, 0x277b4dd, '2a27a6ff9c11de5310136f65fd5f411d31409aa9d00b3f0d9127be21b96c8d56'),
    ('drop-narrow-vectors', 0x433f7a3, 0x433f7f5, '30592fee3313a4b4398112b01a94643bd4a29e51aafa313dc6cd17d0390dccc7'),
    ('drop-narrow-nested', 0x433f7f5, 0x433f8bf, '28a5ecf20a3a4225aaf3a9ed7ad5d415a3bff058034ca918d7c6dfcdda3e305f'),
    ('drop-narrow-unwind', 0x433f8c9, 0x433f95d, 'cb5634ee22819f4b3e029ad35d5ea062bdd7d1736d019e292a0f48c6ca558eb1'),
    ('wide-drop-normal-copy', 0x26ef878, 0x26ef885, '2727b835ed59f076aaf15a365f1241ef37519f60f62c3ddfc97cdb39217addc5'),
    ('wide-drop-normal-original', 0x26ef907, 0x26ef914, 'ad201dbde38d4209fce63859f67468bc0476733c4d728264e300672e369bd5e8'),
    ('wide-drop-exception-copy', 0x26efe74, 0x26efe81, '6b3781f9a7759ac7dfb1e80742b45d79b7067eec43164052fce43ddc2595931e'),
    ('narrow-drop-normal-copy', 0x4310cba, 0x4310cc7, 'd22564496169d9dce296ca244459e86bad87eae14f1fb159f5ddb7d6bc3329e7'),
    ('narrow-drop-normal-original', 0x4310dea, 0x4310df7, '5730dcf7078df177a6817d5eb42f0608e00d8836f04657cf3b31d40b6d050a6f'),
    ('narrow-drop-exception-copy', 0x4311096, 0x43110a3, 'd154e1ca3d90314ca90556a2f1f9681f179a2e6711b52ad6665b27dca5a53138'),
    ('initial-copy-source', 0x26ecaa0, 0x26ecab0, '9a2f36efff01a7b59a22787103aed90fb1cfaccaabfb786d7f1688522cb4b89e'),
    ('alternate-copy-source', 0x26ed886, 0x26ed896, '43533bb976389e2057402ad0f5f62094055abd5c624ad311e2636f65c57e380b'),
    ('wide-unwind-resume', 0x26efeeb, 0x26eff10, '01d75f7776988fdf90812ac84de265b6f8c65632d24dd579c8f2302da2f7acf4'),
    ('narrow-unwind-resume', 0x43110ee, 0x4311140, 'bfe9fea8b08c85799b2ae3613b23a2b31c8c0b6686728ac784a102531338c296'),
)

# Manually inspected instruction starts, not an unaligned opcode census.
DIRECT = (
    (0x32d5eb5, 0x32d6740), (0x454f225, 0x454f420),
    (0x277b296, 0x286d260), (0x277b316, 0x286d260),
    (0x277b3d6, 0x286ada0), (0x277b406, 0x286ada0),
    (0x277b45b, 0x28a8ac0), (0x277b499, 0x28b05a0),
    (0x277b4a1, 0x5660110),
    (0x433f716, 0x49478b0), (0x433f796, 0x49478b0),
    (0x433f856, 0x4948400), (0x433f886, 0x4948400),
    (0x433f8db, 0x49b05e0), (0x433f919, 0x49b0100),
    (0x433f921, 0x5660110),
    (0x26ef880, 0x277b220), (0x26ef90f, 0x277b220),
    (0x26efe7c, 0x277b220), (0x26efea3, 0x277b220),
    (0x4310cc2, 0x433f6a0), (0x4310df2, 0x433f6a0),
    (0x431109e, 0x433f6a0), (0x43110e9, 0x433f6a0),
    (0x26efeee, 0x5660110), (0x26eff0b, 0x5660110),
    (0x4311123, 0x5660110), (0x431113b, 0x5660110),
)
INDIRECT = (
    (0x26ed2e5, 0x5774870), (0x430f206, 0x5774838),
    (0x32d5ede, 0x576dfb8), (0x454f24e, 0x576dfb8),
    (0x277b336, 0x576e010), (0x277b352, 0x576e010),
    (0x277b36f, 0x576e010), (0x277b489, 0x576e010),
    (0x277b4b0, 0x576e010), (0x277b4cc, 0x576e010),
    (0x277b4dd, 0x576e128),
    (0x433f7b6, 0x576e010), (0x433f7d2, 0x576e010),
    (0x433f7ef, 0x576e010), (0x433f909, 0x576e010),
    (0x433f930, 0x576e010), (0x433f94c, 0x576e010),
    (0x433f95d, 0x576e128),
    (0x26ed302, 0x576dfe0), (0x430f237, 0x576dfe0),
    (0x26ef757, 0x576e010), (0x26ef77c, 0x576e010),
)
RELOCATIONS = {
    0x5774870: (8, 0x32d5e80), 0x5774838: (8, 0x454f1f0),
    0x576e010: (8, 0x54c8cb0), 0x576dfb8: (8, 0x1346068),
    0x576e128: (8, 0x157b63b),
    0x576dfe0: (0x600000006, 0),
    0x5778db0: (0x700000007, 0),
}
SYMBOLS = {0x576dfe0: 'memcpy', 0x5778db0: '_Unwind_Resume'}
BRANCHES = (
    (0x32d5ebe, 0x32d5ed4), (0x454f22e, 0x454f244),
    (0x26ed2db, 0x26ed2eb), (0x430f1fc, 0x430f20c),
    (0x26ed9c4, 0x26eda04), (0x26ef72d, 0x26ef73c),
    (0x26ef747, 0x26ef75d), (0x26ef768, 0x26ef782),
    (0x26efdd6, 0x26efe99), (0x26efde2, 0x26efe99),
    (0x277b233, 0x277b270), (0x277b2a1, 0x277b290),
    (0x277b2a7, 0x277b323), (0x277b2b0, 0x277b2e7),
    (0x277b321, 0x277b310), (0x277b32a, 0x277b33c),
    (0x277b343, 0x277b358), (0x277b35f, 0x277b375),
    (0x277b37f, 0x277b3bc), (0x277b3e3, 0x277b43f),
    (0x277b413, 0x277b43f), (0x277b426, 0x277b400),
    (0x277b455, 0x277b460), (0x277b467, 0x277b4a6),
    (0x277b470, 0x277b4bf), (0x277b479, 0x277b48f),
    (0x277b4bd, 0x277b472), (0x277b4d9, 0x277b47b),
    (0x433f6b3, 0x433f6f0), (0x433f721, 0x433f710),
    (0x433f727, 0x433f7a3), (0x433f730, 0x433f767),
    (0x433f7a1, 0x433f790), (0x433f7aa, 0x433f7bc),
    (0x433f7c3, 0x433f7d8), (0x433f7df, 0x433f7f5),
    (0x433f7ff, 0x433f83c), (0x433f863, 0x433f8bf),
    (0x433f893, 0x433f8bf), (0x433f8a6, 0x433f880),
    (0x433f8d5, 0x433f8e0), (0x433f8e7, 0x433f926),
    (0x433f8f0, 0x433f93f), (0x433f8f9, 0x433f90f),
    (0x433f93d, 0x433f8f2), (0x433f959, 0x433f8fb),
)
JNE_SITES = frozenset((0x26ed2db, 0x430f1fc, 0x26ed9c4, 0x277b2a1,
                       0x277b321, 0x277b467, 0x277b470, 0x277b4d9,
                       0x433f721, 0x433f7a1, 0x433f8e7, 0x433f8f0, 0x433f959))
NEAR_OPCODES = {0x26efdd6: b'\x0f\x84', 0x26efde2: b'\x0f\x8e'}

# Exactly these 4-byte operands are masked for the two bounded comparisons.
# Size operands are listed separately because their values intentionally differ.
GROW_MASKS = ((0x2e, 'element size'), (0x36, 'direct-call displacement'),
              (0x60, 'RIP-slot displacement'))
DROP_MASKS = tuple((x, 'PC-relative displacement') for x in
                   (0x77, 0xf7, 0x118, 0x134, 0x151, 0x1b7, 0x1d0, 0x1e7,
                    0x23c, 0x26b, 0x27a, 0x282, 0x292, 0x2ae, 0x2bf)) + (
                        (0x12c, 'element size'), (0x2a6, 'element size'))

class EvidenceError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise EvidenceError(message)


def authenticate(data):
    require(hashlib.sha256(data).hexdigest() == SHA256, 'node 94 SHA-256 mismatch')


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)

    def read(self, va, size):
        require(isinstance(va, int) and isinstance(size, int) and va >= 0 and size > 0,
                'invalid address or length')
        matches = [s for s in self.sections if s['type'] != 8 and
                   s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'address has no unique file-backed section')
        s = matches[0]
        off = s['offset'] + va - s['address']
        require(off + size <= len(self.data), 'file range truncated')
        return off, self.data[off:off + size]

    def relocations(self):
        rows = {}
        for s in self.sections:
            if s['type'] != 4:
                continue
            require(s['size'] % 24 == 0, 'partial relocation record')
            for off in range(s['offset'], s['offset'] + s['size'], 24):
                slot, info, addend = struct.unpack_from('<QQq', self.data, off)
                if slot in RELOCATIONS:
                    require(slot not in rows, 'duplicate selected relocation')
                    require((info, addend) == RELOCATIONS[slot], 'selected relocation changed')
                    sym_index = info >> 32
                    name = None
                    if sym_index:
                        syms = [x for x in self.sections if x['name'] == '.dynsym' and x['type'] != 8]
                        strings = [x for x in self.sections if x['name'] == '.dynstr' and x['type'] != 8]
                        require(len(syms) == len(strings) == 1, 'missing dynamic symbol data')
                        sym, st = syms[0], strings[0]
                        require((sym_index + 1) * 24 <= sym['size'], 'dynamic symbol out of range')
                        name_offset = struct.unpack_from('<I', self.data, sym['offset'] + sym_index * 24)[0]
                        require(name_offset < st['size'], 'dynamic name out of range')
                        start = st['offset'] + name_offset
                        end = self.data.find(b'\0', start, st['offset'] + st['size'])
                        require(end >= 0, 'unterminated dynamic name')
                        name = bytes(self.data[start:end]).decode('ascii')
                        require(name == SYMBOLS.get(slot), 'unexpected dynamic symbol')
                    rows[slot] = {'slot_va': hex(slot), 'info': hex(info), 'addend': hex(addend),
                                  'symbol_index': sym_index, 'symbol_name': name,
                                  'rela_file_offset': hex(off), 'raw_hex': self.data[off:off+24].hex()}
        require(set(rows) == set(RELOCATIONS), 'selected relocation missing')
        return [rows[k] for k in sorted(rows)]


def call_target(image, site, indirect=False):
    size = 6 if indirect else 5
    _, raw = image.read(site, size)
    require(raw[:2] == b'\xff\x15' if indirect else raw[0] == 0xe8,
            'unexpected call instruction')
    disp = struct.unpack_from('<i', raw, 2 if indirect else 1)[0]
    return site + size + disp, raw


def branch_target(image, site):
    _, raw = image.read(site, 2)
    if 0x70 <= raw[0] <= 0x7f:
        return site + 2 + struct.unpack_from('<b', raw, 1)[0], raw
    require(raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f, 'unexpected conditional branch')
    _, raw = image.read(site, 6)
    return site + 6 + struct.unpack_from('<i', raw, 2)[0], raw


def selected_windows(image):
    rows = []
    for label, start, end, digest in WINDOWS:
        off, raw = image.read(start, end - start)
        require(hashlib.sha256(raw).hexdigest() == digest, 'changed witness: ' + label)
        rows.append({'label': label, 'start_va': hex(start), 'end_va': hex(end),
                     'file_offset': hex(off), 'sha256': digest, 'raw_hex': raw.hex()})
    return rows


def validate_bodies(image):
    for start, (end, digest, _) in SELECTED.items():
        _, raw = image.read(start, end - start)
        require(hashlib.sha256(raw).hexdigest() == digest, 'selected FDE body changed')


def selected_edges(image):
    edges = []
    for indirect, pairs in ((False, DIRECT), (True, INDIRECT)):
        for site, expected in pairs:
            target, raw = call_target(image, site, indirect)
            require(target == expected, 'call target changed')
            edges.append({'site_va': hex(site), 'kind': 'rip-slot' if indirect else 'direct',
                          'target_va': hex(target), 'raw_hex': raw.hex()})
    return edges


def plt_binding(image):
    site = 0x5660110
    _, raw = image.read(site, 6)
    require(raw[:2] == b'\xff\x25', 'unexpected PLT instruction')
    target = site + 6 + struct.unpack_from('<i', raw, 2)[0]
    require(target == 0x5778db0, 'unexpected PLT slot')
    return {'site_va': hex(site), 'slot_va': hex(target), 'raw_hex': raw.hex()}


def selected_branches(image):
    branches = []
    for site, expected in BRANCHES:
        dest, raw = branch_target(image, site)
        require(dest == expected, 'branch target changed')
        opcode = NEAR_OPCODES.get(site, b'\x75' if site in JNE_SITES else b'\x74')
        require(raw.startswith(opcode), 'branch predicate changed')
        branches.append({'site_va': hex(site), 'taken_va': hex(dest),
                         'fallthrough_va': hex(site + len(raw)), 'raw_hex': raw.hex()})
    return branches


def compare_masked(image, first, second, length, masks):
    a = bytearray(image.read(first, length)[1])
    b = bytearray(image.read(second, length)[1])
    changed = [i for i, (left, right) in enumerate(zip(a, b)) if left != right]
    for offset, _ in masks:
        require(0 <= offset <= length - 4, 'comparison mask outside function')
        a[offset:offset+4] = b'\0' * 4
        b[offset:offset+4] = b'\0' * 4
    require(a == b, 'unmasked function bytes differ')
    return {'first_va': hex(first), 'second_va': hex(second),
            'length': length, 'different_byte_offsets': [hex(i) for i in changed],
            'masks': [{'offset': hex(offset), 'length': 4, 'purpose': purpose}
                      for offset, purpose in masks],
            'masked_sha256': hashlib.sha256(a).hexdigest()}


def decode_lsda(image, frame):
    va = frame['lsda']
    require(va is not None, 'missing LSDA')
    matches = [s for s in image.sections if s['name'] == '.gcc_except_table' and s['type'] != 8]
    require(len(matches) == 1, 'missing exception section')
    s = matches[0]
    require(s['address'] <= va < s['address'] + s['size'], 'LSDA not file-backed')
    start = s['offset'] + va - s['address']
    limit = s['offset'] + s['size']
    require(image.data[start:start+2] == b'\xff\x9b', 'unsupported LSDA header')
    type_delta, p = uleb(image.data, start + 2, limit)
    require(p + type_delta <= limit and p < limit and image.data[p] == 1, 'invalid LSDA encoding')
    size, p = uleb(image.data, p + 1, limit)
    end = p + size
    require(end <= limit, 'truncated LSDA call-site table')
    rows, previous = [], 0
    while p < end:
        begin = p
        vals = []
        for _ in range(4):
            value, p = uleb(image.data, p, end)
            vals.append(value)
        offset, length, landing, action = vals
        require(offset >= previous and offset + length <= frame['end'] - frame['start'], 'invalid LSDA interval')
        require(landing == 0 or landing < frame['end'] - frame['start'], 'invalid landing pad')
        previous = offset + length
        rows.append({'start_va': hex(frame['start'] + offset),
                     'end_va': hex(frame['start'] + offset + length),
                     'landing_va': hex(frame['start'] + landing) if landing else None,
                     'action': action, 'raw_hex': image.data[begin:p].hex()})
    require(p == end, 'LSDA overrun')
    return {'function_va': hex(frame['start']), 'lsda_va': hex(va),
            'file_offset': hex(start), 'header_and_table_hex': image.data[start:end].hex(),
            'type_table_offset': type_delta, 'rows': rows}


def growth(capacity, minimum, threshold):
    require(type(capacity) is int and 0 <= capacity < (1 << 64), 'capacity outside u64')
    doubled = (capacity * 2) & ((1 << 64) - 1)
    return doubled if doubled >= threshold else minimum


def drop_projection(optional, caps, inner, stride, widths=(0x20, 0x28, 8)):
    """Synthetic event projection assuming terminating iterators and non-aliasing buffers."""
    require(type(optional) is int and 0 <= optional < (1 << 64) and len(caps) == 3 and len(inner) <= 3, 'bad fixture')
    require(stride in (0x228, 0x238) and all(type(x) is int and 0 <= x <= 3 for x in (*caps, *inner)), 'bad fixture')
    require(widths == (0x20, 0x28, 8), 'bad element widths')
    events = ['visit-first-tree']
    if optional:
        events.append('visit-optional-tree')
    for name, cap, width in zip(('vector-20', 'vector-38', 'vector-50'), caps, (widths[0], stride, widths[1])):
        if cap:
            events.append(f'{name}:release:{cap * width}')
    events.append('visit-last-tree')
    for cap in inner:
        if cap:
            events.append(f'inner:release:{cap * widths[2]}')
    return events


def collect(data):
    authenticate(data)
    image = Image(data)
    summary, frames, _ = fde_extents(data)
    by_start = {}
    for frame in frames:
        if frame['start'] in SELECTED or frame['start'] in CONTEXT:
            require(frame['start'] not in by_start, 'duplicate selected FDE')
            by_start[frame['start']] = frame
    require(set(by_start) == set(SELECTED) | set(CONTEXT), 'selected FDE missing')
    _, header_entries = unwind_index(data)
    header_by_fde = {row['fde']: row for row in header_entries}
    for frame in by_start.values():
        entry = header_by_fde.get(frame['fde'])
        require(entry is not None and entry['start'] == frame['start'] and
                frame.get('index') == entry['index'], 'FDE and unwind header disagree')
    validate_bodies(image)
    funcs = []
    for start in sorted(SELECTED):
        end, digest, role = SELECTED[start]
        frame = by_start[start]
        require(frame['end'] == end, 'selected FDE extent changed')
        off, raw = image.read(start, end - start)
        require(hashlib.sha256(raw).hexdigest() == digest, 'selected FDE body changed')
        funcs.append({'role': role, 'start_va': hex(start), 'end_va': hex(end),
                      'fde_va': hex(frame['fde']), 'unwind_index': frame['index'],
                      'lsda_va': hex(frame['lsda']) if frame['lsda'] else None,
                      'file_offset': hex(off), 'length': len(raw), 'sha256': digest, 'raw_hex': raw.hex()})
    for start, end in CONTEXT.items():
        require(by_start[start]['end'] == end, 'context FDE extent changed')
    windows = selected_windows(image)
    edges = selected_edges(image)
    branches = selected_branches(image)
    relocs = image.relocations()
    slot_loads = []
    for site in (0x277b3ed, 0x433f86d):
        _, raw = image.read(site, 7)
        require(raw[:3] == b'\x4c\x8b\x3d', 'unexpected slot-load instruction')
        slot = site + 7 + struct.unpack_from('<i', raw, 3)[0]
        require(slot == 0x576e010, 'unexpected slot-load target')
        slot_loads.append({'site_va': hex(site), 'slot_va': hex(slot), 'raw_hex': raw.hex()})
    comparisons = [compare_masked(image, 0x32d5e80, 0x454f1f0, 0x64, GROW_MASKS),
                   compare_masked(image, 0x277b220, 0x433f6a0, 0x2c3, DROP_MASKS)]
    lsdas = [decode_lsda(image, by_start[x]) for x in (0x277b220, 0x433f6a0, 0x26ebdc0, 0x430d610)]
    def landing(function, site):
        table = next(x for x in lsdas if int(x['function_va'], 16) == function)
        found = [r for r in table['rows'] if int(r['start_va'], 16) <= site < int(r['end_va'], 16)]
        require(len(found) == 1, 'call has no unique LSDA interval')
        return found[0]['landing_va']
    for function, site, expected in ((0x26ebdc0, 0x26ed2e5, 0x26efdc6),
                                     (0x430d610, 0x430f206, 0x4311027),
                                     (0x277b220, 0x277b296, 0x277b44e),
                                     (0x277b220, 0x277b316, 0x277b449),
                                     (0x433f6a0, 0x433f716, 0x433f8ce),
                                     (0x433f6a0, 0x433f796, 0x433f8c9)):
        require(landing(function, site) == hex(expected), 'unexpected landing pad')
    # Extract growth operands from their pinned machine instructions.
    def operand(va, prefix, size):
        _, raw = image.read(va, len(prefix) + size)
        require(raw.startswith(prefix), 'operand instruction changed')
        return int.from_bytes(raw[len(prefix):], 'little')
    minimum = operand(0x32d5e95, b'\x41\xbe', 4)
    threshold = operand(0x32d5e91, b'\x48\x83\xf8', 1)
    wide = operand(0x32d5eac, b'\x41\xb9', 4)
    narrow = operand(0x454f21c, b'\x41\xb9', 4)
    require((minimum, threshold, wide, narrow) == (4, 5, 0x238, 0x228), 'growth operands changed')
    require(operand(0x277b349, b'\x48\x69\xf0', 4) == wide, 'wide drop stride changed')
    require(operand(0x433f7c9, b'\x48\x69\xf0', 4) == narrow, 'narrow drop stride changed')
    require(operand(0x26ed2eb, b'\x48\x69\xfb', 4) == wide, 'wide append stride changed')
    require(operand(0x430f21f, b'\x4c\x69\xf5', 4) == narrow, 'narrow append stride changed')
    vector20 = 1 << operand(0x277b330, b'\x48\xc1\xe6', 1)
    vector50 = (1 << operand(0x277b365, b'\x48\xc1\xe0', 1)) * 5
    require(image.read(0x277b369, 4)[1] == b'\x48\x8d\x34\x80', 'scaled add changed')
    inner_width = 1 << operand(0x277b434, b'\x48\xc1\xe6', 1)
    widths = (vector20, vector50, inner_width)
    require(widths == (0x20, 0x28, 8), 'cleanup widths changed')
    layout = {
        'first_tree': operand(0x277b22c, b'\x48\x8b\x4f', 1),
        'first_tree_second_word': operand(0x277b235, b'\x48\x8b\x93', 4),
        'first_tree_third_word': operand(0x277b23c, b'\x48\x8b\x83', 4),
        'optional_tree_root': operand(0x277b2a9, b'\x48\x8b\x4b', 1),
        'vector20_capacity': operand(0x277b323, b'\x48\x8b\x73', 1),
        'vector20_pointer': operand(0x277b32c, b'\x48\x8b\x7b', 1),
        'vector38_capacity': operand(0x277b33c, b'\x48\x8b\x43', 1),
        'vector38_pointer': operand(0x277b345, b'\x48\x8b\x7b', 1),
        'vector50_capacity': operand(0x277b358, b'\x48\x8b\x43', 1),
        'vector50_pointer': operand(0x277b361, b'\x48\x8b\x7b', 1),
        'last_tree': operand(0x277b375, b'\x48\x8b\x8b', 4),
        'last_tree_second_word': operand(0x277b381, b'\x48\x8b\x93', 4),
        'last_tree_third_word': operand(0x277b388, b'\x48\x8b\x83', 4),
    }
    # The normal-success fragment has a copied object on the stack; the
    # preceding LEA passes that same stack slot to full cleanup on other exits.
    copied_base = operand(0x26ef878, b'\x48\x8d\xbc\x24', 4)
    transfer = {
        'source_vector_header': operand(0x26ef680, b'\x0f\x10\x84\x24', 4) - copied_base,
        'source_vector_length': operand(0x26ef670, b'\x48\x8b\x84\x24', 4) - copied_base,
        'source_last_tree_header': operand(0x26ef690, b'\x0f\x10\x84\x24', 4) - copied_base,
        'source_last_tree_third_word': operand(0x26ef6a0, b'\x48\x8b\x84\x24', 4) - copied_base,
        'result_vector_length': operand(0x26ef702, b'\x49\x89\x40', 1),
        'result_tree_first_word': operand(0x26ef706, b'\x49\x89\x50', 1),
        'result_tree_second_word': operand(0x26ef6f2, b'\x49\x89\x70', 1),
        'result_tree_third_word': operand(0x26ef6fe, b'\x49\x89\x70', 1),
    }
    narrow_record = {
        'prefix_copy_bytes': operand(0x430f22a, b'\xba', 4),
        'first_qword_store': operand(0x430f23d, b'\x4f\x89\xac\x34', 4),
        'second_qword_store': operand(0x430f24d, b'\x4b\x89\x84\x34', 4),
        'third_qword_store': operand(0x430f25a, b'\x4b\x89\x84\x34', 4),
        'first_simd_store': operand(0x430f274, b'\xf3\x43\x0f\x7f\x84\x34', 4),
        'second_simd_store': operand(0x430f27e, b'\xf3\x43\x0f\x7f\x8c\x34', 4),
    }
    return {'identity': {'release': 'node 94', 'sha256': SHA256, 'target_bytes': len(data)},
            'coordinate_system': 'linked ELF virtual address; file offsets from file-backed sections',
            'fde_records_in_input': summary['fde_records'],
            'functions': funcs, 'windows': windows, 'branches': branches, 'calls': edges,
            'relocations': relocs, 'slot_loads': slot_loads, 'plt_binding': plt_binding(image),
            'masked_comparisons': comparisons,
            'lsdas': lsdas, 'derived_layout': layout, 'success_transfer': transfer,
            'narrow_record_stores': narrow_record,
            'derived_operands': {'minimum_capacity': minimum, 'double_threshold': threshold,
                                 'wide_record_size': wide, 'narrow_record_size': narrow,
                                 'vector20_element_size': vector20, 'vector50_element_size': vector50,
                                 'nested_element_size': inner_width}}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    result = collect(TARGET.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'evidence.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    print('wrote evidence.json')


if __name__ == '__main__':
    try:
        main()
    except (EvidenceError, OSError, ValueError, struct.error) as exc:
        print('book_match_result_ownership94: ' + str(exc), file=sys.stderr)
        sys.exit(1)
