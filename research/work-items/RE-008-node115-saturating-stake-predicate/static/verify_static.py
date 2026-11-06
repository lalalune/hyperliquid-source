#!/usr/bin/env python3
"""Fixed node115 stake certificate checker. No target execution or state evaluator."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

TARGET_SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET_SIZE = 105896032
FREEZE_SHA = '3ded1e5f428bc795fe602bda98a7aab621582d51ad7fe904792130502f1d49b9'
BINDINGS_SHA = 'b2141ffdf32eec2e59dbfc7094f3f1236f77a11f3f2ce278f388b746655bee94'
LABELS = ('predicate', 'selected-fold', 'all-fold', 'key-iterator', 'flat-lookup')
SCOPE = ((0x4d3e1a0, 0x4d3e30d), (0x4e44c00, 0x4e44e03),
         (0x4e406f0, 0x4e4098d), (0x5138730, 0x5138946), (0x57f54e0, 0x57f56ab))
EXPECTED_CIES = (
    '1400000000000000017a5200017810011b0c070890010000',
    '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000',
)

# Exact intervals of the sealed instruction partition. Expected bytes come only
# from admitted, immutable exports, never from a mutation or decoded result.
# These anchors bind the manual proof; they are not an instruction interpreter.
GUARDS = (
    ('predicate.key-header', 0x4d3e1af, 0x4d3e1c7),
    ('predicate.key-descriptor', 0x4d3e1c7, 0x4d3e20b),
    ('predicate.map-kind', 0x4d3e21f, 0x4d3e22a),
    ('predicate.flat-spans', 0x4d3e24c, 0x4d3e2d3),
    ('predicate.wide-strict', 0x4d3e2e4, 0x4d3e305),
    ('selected.descriptor-copy', 0x4e44c0e, 0x4e44c43),
    ('selected.first-empty', 0x4e44c4d, 0x4e44c5d),
    ('selected.saturation', 0x4e44c60, 0x4e44c7b),
    ('selected.hit-continuation', 0x4e44c85, 0x4e44c98),
    ('selected.miss-continuation', 0x4e44caa, 0x4e44ccb),
    ('selected.flat-weight', 0x4e44dab, 0x4e44de8),
    ('selected.return-joins', 0x4e44de8, 0x4e44df4),
    ('iterator.count-tag', 0x5138731, 0x513874a),
    ('iterator.front-count', 0x513874a, 0x5138773),
    ('iterator.empty-return', 0x5138773, 0x5138777),
    ('iterator.initial-descent', 0x5138777, 0x5138813),
    ('iterator.initial-empty-leaf', 0x5138813, 0x5138823),
    ('iterator.parent-ascent', 0x5138830, 0x5138852),
    ('iterator.right-descent', 0x5138852, 0x51388f1),
    ('iterator.key-and-front', 0x51388f1, 0x5138916),
    ('iterator.initial-unroll-tail', 0x5138916, 0x5138928),
    ('lookup.header', 0x57f54eb, 0x57f5516),
    ('lookup.seam', 0x57f5516, 0x57f5561),
    ('lookup.contiguous-setup', 0x57f5561, 0x57f5598),
    ('lookup.first-last-equal', 0x57f55a0, 0x57f560d),
    ('lookup.segment-route', 0x57f560d, 0x57f562b),
    ('lookup.second-last-equal', 0x57f5630, 0x57f5699),
    ('lookup.return', 0x57f5699, 0x57f56ab),
    ('all.flat-saturation', 0x4e406f1, 0x4e4075b),
)

# ID, actual instruction VA, byte offset, old bytes, replacement bytes, guard.
# Each is a real same-width byte substitution, not an edited expected outcome.
SEMANTIC_CONTROLS = (
    ('K-root-tag-inversion', 0x4d3e1be, 1, '95', '94', 'predicate.key-header'),
    ('K-count-header-offset', 0x4d3e1c3, 3, '10', '18', 'predicate.key-header'),
    ('K-remaining-store-offset', 0x4d3e1f7, 4, '50', '48', 'predicate.key-descriptor'),
    ('K-map-pointer-store-offset', 0x4d3e1fc, 4, '58', '50', 'predicate.key-descriptor'),
    ('iterator-remaining-load', 0x5138731, 3, '40', '38', 'iterator.count-tag'),
    ('iterator-decrement-to-increment', 0x513873a, 2, 'c8', 'c0', 'iterator.count-tag'),
    ('iterator-zero-count-branch', 0x5138738, 0, '74', '75', 'iterator.count-tag'),
    ('iterator-tag-value', 0x5138741, 2, '01', '00', 'iterator.count-tag'),
    ('iterator-keycount-offset', 0x513875b, 3, 'e6', 'e4', 'iterator.front-count'),
    ('iterator-exhausted-equality', 0x5138765, 1, '83', '87', 'iterator.front-count'),
    ('iterator-first-child', 0x51387a0, 3, 'e8', 'f0', 'iterator.initial-descent'),
    ('iterator-eight-edge-unroll', 0x51387c7, 3, 'e8', 'f0', 'iterator.initial-descent'),
    ('iterator-parent-edge-offset', 0x513883f, 3, 'e4', 'e6', 'iterator.parent-ascent'),
    ('iterator-right-child-offset', 0x513885b, 3, 'f0', 'e8', 'iterator.right-descent'),
    ('iterator-front-next-index', 0x5138892, 3, '01', '00', 'iterator.right-descent'),
    ('iterator-key-stride', 0x51388f1, 3, '80', '40', 'iterator.key-and-front'),
    ('iterator-key-base', 0x51388f9, 3, '08', '10', 'iterator.key-and-front'),
    ('lookup-live-count-offset', 0x57f54eb, 3, '18', '10', 'lookup.header'),
    ('lookup-empty-branch', 0x57f54f6, 0, '74', '75', 'lookup.header'),
    ('lookup-head-normalization', 0x57f5504, 2, '43', '42', 'lookup.header'),
    ('lookup-seam-key-width', 0x57f551a, 1, '14', '13', 'lookup.seam'),
    ('lookup-seam-equality', 0x57f553a, 1, '84', '85', 'lookup.seam'),
    ('lookup-segment-sign-route', 0x57f5540, 1, 'ff', '01', 'lookup.seam'),
    ('lookup-first-duplicate-direction', 0x57f55c7, 2, '4f', '4d', 'lookup.first-last-equal'),
    ('lookup-first-row-stride', 0x57f55af, 3, '05', '04', 'lookup.first-last-equal'),
    ('lookup-final-key-width', 0x57f55de, 1, '14', '13', 'lookup.first-last-equal'),
    ('lookup-second-duplicate-direction', 0x57f565b, 2, '4f', '4d', 'lookup.second-last-equal'),
    ('lookup-second-logical-offset', 0x57f5696, 1, '01', '29', 'lookup.second-last-equal'),
    ('selected-status-low-bit', 0x4e44dab, 1, '01', '02', 'selected.flat-weight'),
    ('selected-live-bound-offset', 0x4e44db3, 4, '18', '10', 'selected.flat-weight'),
    ('selected-head-add-offset', 0x4e44dbe, 4, '10', '18', 'selected.flat-weight'),
    ('selected-row-stride', 0x4e44dd7, 3, '05', '04', 'selected.flat-weight'),
    ('selected-weight-offset', 0x4e44ddf, 3, '18', '10', 'selected.flat-weight'),
    ('selected-first-carry-clamp', 0x4e44c73, 2, '42', '43', 'selected.saturation'),
    ('selected-final-carry-clamp', 0x4e44c77, 2, '42', '43', 'selected.saturation'),
    ('selected-last-miss-restore', 0x4e44de8, 4, '08', '10', 'selected.return-joins'),
    ('total-span-split-polarity', 0x4d3e271, 0, '77', '76', 'predicate.flat-spans'),
    ('total-span-row-stride', 0x4d3e287, 3, '05', '04', 'predicate.flat-spans'),
    ('total-flat-tag', 0x4d3e29c, 2, '02', '03', 'predicate.flat-spans'),
    ('total-weight-offset', 0x4e40729, 3, '18', '10', 'all.flat-saturation'),
    ('total-row-advance', 0x4e40734, 3, '20', '10', 'all.flat-saturation'),
    ('total-final-carry-clamp', 0x4e40738, 2, '42', '43', 'all.flat-saturation'),
    ('total-second-span-start', 0x4e4074a, 2, 'c8', 'd0', 'all.flat-saturation'),
    ('total-second-empty-polarity', 0x4e40744, 1, '84', '85', 'all.flat-saturation'),
    ('wide-three-to-two', 0x4d3e2ee, 1, '03', '02', 'predicate.wide-strict'),
    ('wide-high-shift', 0x4d3e2ea, 3, '3f', '3e', 'predicate.wide-strict'),
    ('wide-borrow-to-carry', 0x4d3e2ff, 1, '19', '11', 'predicate.wide-strict'),
    ('wide-strict-to-inclusive', 0x4d3e302, 1, '92', '96', 'predicate.wide-strict'),
)


class Rejection(Exception):
    def __init__(self, code, detail):
        super().__init__(code + ': ' + detail)
        self.code, self.detail = code, detail


def need(value, code, detail):
    if not value:
        raise Rejection(code, detail)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def bounded(data, offset, size, code='elf.bounds'):
    need(isinstance(offset, int) and isinstance(size, int) and 0 <= offset <= len(data)
         and 0 <= size <= len(data) - offset, code, 'file span out of bounds')
    return data[offset:offset + size]


def unpack(fmt, data, offset, code='elf.bounds'):
    return struct.unpack(fmt, bounded(data, offset, struct.calcsize(fmt), code))


def cstring(data, offset, code):
    need(0 <= offset < len(data), code, 'bad string offset')
    end = data.find(b'\0', offset)
    need(end >= offset, code, 'unterminated string')
    try:
        return bytes(data[offset:end]).decode('ascii')
    except UnicodeDecodeError as error:
        raise Rejection(code, 'non-ASCII ELF string') from error


def target_admission(image):
    need(len(image) == TARGET_SIZE, 'identity.size', 'wrong target size')
    need(sha(image) == TARGET_SHA, 'identity.sha256', 'wrong whole-target digest')


def read_target(path):
    need(path.is_file(), 'identity.kind', 'regular target file required')
    need(path.stat().st_size == TARGET_SIZE, 'identity.size', 'wrong target file size')
    with path.open('rb') as stream:
        image = stream.read(TARGET_SIZE + 1)
    target_admission(image)
    return image


class Elf:
    def __init__(self, image):
        self.image = image
        need(bytes(bounded(image, 0, 6)) == b'\x7fELF\x02\x01', 'elf.identity', 'ELF64 little endian required')
        need(unpack('<H', image, 18)[0] == 62, 'elf.identity', 'x86-64 required')
        phoff, shoff = unpack('<QQ', image, 32)
        ehsize, phsize, phcount, shsize, shcount, names_index = unpack('<HHHHHH', image, 52)
        need((ehsize, phsize, shsize) == (64, 56, 64) and phcount > 0 and shcount > 0,
             'elf.layout', 'unsupported ELF header sizes/counts')
        bounded(image, phoff, phsize * phcount)
        bounded(image, shoff, shsize * shcount)
        self.loads = []
        for i in range(phcount):
            off = phoff + i * phsize
            p = unpack('<IIQQQQQQ', image, off)
            if p[0] == 1:
                bounded(image, p[2], p[5])
                need(p[5] <= p[6] and p[3] + p[6] < 1 << 64, 'elf.segment', 'invalid PT_LOAD extent')
                self.loads.append((p, off))
        self.sections = [unpack('<IIQQQQIIQQ', image, shoff + i * shsize) for i in range(shcount)]
        need(names_index < shcount, 'elf.sections', 'bad name-table index')
        n = self.sections[names_index]
        names = bounded(image, n[4], n[5])
        self.named = {}
        for s in self.sections:
            name = cstring(names, s[0], 'elf.sections')
            need(name not in self.named, 'elf.sections', 'duplicate section name')
            self.named[name] = s
        need('.eh_frame' in self.named, 'elf.sections', 'missing .eh_frame')
        self.relas = {}
        self.rela_count = 0
        self.rela_types = {}
        for s in self.sections:
            if s[1] != 4:
                continue
            need(s[9] == 24 and s[5] % 24 == 0 and s[6] < shcount, 'rela.layout', 'invalid RELA section')
            bounded(image, s[4], s[5])
            for off in range(s[4], s[4] + s[5], 24):
                va, info, addend = unpack('<QQq', image, off)
                self.relas.setdefault(va, []).append((info, addend, off, s[6]))
                self.rela_count += 1
                kind = str(info & 0xffffffff)
                self.rela_types[kind] = self.rela_types.get(kind, 0) + 1

    def mapping(self, va, size):
        matches = [p for p, _ in self.loads if p[3] <= va and va + size <= p[3] + p[5]]
        need(len(matches) == 1, 'elf.mapping', 'nonunique or missing file-backed span')
        p = matches[0]
        off = p[2] + va - p[3]
        return off, bounded(self.image, off, size)

    def relocation(self, slot):
        rs = self.relas.get(slot, [])
        need(len(rs) == 1, 'rela.unique', 'slot must have exactly one relocation')
        info, addend, off, symsec = rs[0]
        sym = self.sections[symsec]
        need(sym[9] == 24 and sym[6] < len(self.sections), 'symbol.layout', 'bad symbol table')
        index = info >> 32
        need(index < sym[5] // 24, 'symbol.bounds', 'symbol outside table')
        so = sym[4] + index * 24
        no, si, other, ndx, value, size = unpack('<IBBHQQ', self.image, so)
        strings = self.sections[sym[6]]
        name = cstring(bounded(self.image, strings[4], strings[5]), no, 'symbol.name')
        return {'type': info & 0xffffffff, 'index': index, 'addend': addend,
                'offset': off, 'name': name, 'info': si, 'other': other,
                'section_index': ndx, 'value': value, 'size': size, 'symbol_offset': so}


def read_evidence(directory):
    raw = (directory / 'INDEPENDENT-FREEZE.json').read_bytes()
    need(sha(raw) == FREEZE_SHA, 'evidence.freeze', 'wrong independent freeze')
    freeze = json.loads(raw)
    need(len(freeze['entries']) == 12, 'evidence.entries', 'wrong frozen entry count')
    admitted = {}
    for entry in freeze['entries']:
        name = entry['path']
        need(isinstance(name, str) and Path(name).name == name and name not in admitted,
             'evidence.path', 'unsafe or duplicate frozen path')
        p = directory / name
        need(p.stat().st_size <= 1_000_000, 'evidence.size', 'oversized frozen file')
        b = p.read_bytes()
        need(len(b) == entry['size'] and sha(b) == entry['sha256'], 'evidence.hash', name)
        admitted[name] = b
    need(sha(admitted['native-bindings.json']) == BINDINGS_SHA, 'evidence.bindings', 'wrong binding receipt')
    bindings = json.loads(admitted['native-bindings.json'])
    need(len(bindings['bodies']) == 5 and len(bindings['calls']) == 16 and len(bindings['branches']) == 98,
         'evidence.shape', 'unexpected fixed certificate shape')
    exports = {label: admitted[label + '.gnu.txt'] for label in LABELS}
    return {'files': admitted, 'bindings': bindings, 'exports': exports}


ROW = re.compile(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)(.*?)\s*$')
ADDRESS = re.compile(r'^\s*[0-9a-f]+:')


def parse_export(raw, start, end):
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError as error:
        raise Rejection('export.syntax', 'invalid text encoding') from error
    rows = []
    cursor = start
    for line in text.splitlines():
        m = ROW.fullmatch(line)
        if not m:
            need(not ADDRESS.match(line), 'export.syntax', 'malformed addressed row')
            continue
        va, opcode, assembly = int(m[1], 16), bytes.fromhex(m[2]), m[3]
        need(va == cursor and 1 <= len(opcode) <= 15 and cursor + len(opcode) <= end,
             'export.partition', 'gap, duplicate, overlap or wrong instruction width')
        rows.append((va, opcode, assembly))
        cursor += len(opcode)
    need(cursor == end and rows, 'export.partition', 'incomplete FDE export')
    return rows


def check_cie(elf, section_offset, expected_hex):
    s = elf.named['.eh_frame']
    expected = bytes.fromhex(expected_hex)
    off = s[4] + section_offset
    raw = bounded(elf.image, off, len(expected), 'cie.bounds')
    need(unpack('<I', raw, 4, 'cie.bounds')[0] == 0 and raw[8] == 1, 'cie.identity', 'CIE id/version')
    aug = cstring(raw, 9, 'cie.augmentation')
    need(aug in ('zR', 'zPLR'), 'cie.augmentation', 'unsupported CIE augmentation')
    encoding_offset = 16 if aug == 'zR' else 24
    need(raw[encoding_offset] == 0x1b, 'cie.encoding', 'FDE must use pcrel sdata4')
    need(expected_hex in EXPECTED_CIES and bytes(raw) == expected, 'cie.raw', 'changed complete reviewed CIE')


def check_frames(elf, bodies):
    section = elf.named['.eh_frame']
    for body in bodies:
        f = body['fde']
        fo, co = int(f['fde_section_offset'], 16), int(f['cie_section_offset'], 16)
        expected = bytes.fromhex(f['fde_record_hex'])
        need(0 <= fo <= section[5] - len(expected), 'fde.bounds', 'FDE outside section')
        raw = bounded(elf.image, section[4] + fo, len(expected), 'fde.bounds')
        n, cie_delta = unpack('<II', raw, 0, 'fde.bounds')
        need(n + 4 == len(expected), 'fde.length', 'FDE record length')
        need(fo + 4 - cie_delta == co, 'fde.cie-reference', 'CIE back-reference')
        check_cie(elf, co, f['cie_record_hex'])
        start = section[3] + fo + 8 + unpack('<i', raw, 8, 'fde.bounds')[0]
        size = unpack('<I', raw, 12, 'fde.bounds')[0]
        need(start == int(body['start'], 16), 'fde.start', 'decoded FDE start')
        need(start + size == int(body['end'], 16), 'fde.extent', 'decoded FDE extent')
        need(bytes(raw) == expected, 'fde.raw', 'changed FDE augmentation/CFI bytes')


def check_calls_branches(elf, bindings, row_map):
    for call in bindings['calls']:
        va = int(call['va'], 16)
        row = row_map[va]
        raw = bytes(elf.mapping(va, len(row[0]))[1])
        need(row[1].startswith('call'), 'call.partition', 'call anchor missing')
        if call['kind'] == 'direct':
            need(len(raw) == 5 and raw[0] == 0xe8, 'call.encoding', 'direct call width/opcode')
            target = va + 5 + struct.unpack_from('<i', raw, 1)[0]
            need(target == int(call['target'], 16), 'call.target', 'direct target changed')
        elif call['kind'] == 'rip-slot':
            need(len(raw) == 6 and raw[:2] == b'\xff\x15', 'call.encoding', 'RIP call width/opcode')
            slot = va + 6 + struct.unpack_from('<i', raw, 2)[0]
            need(slot == int(call['slot'], 16), 'call.slot', 'RIP slot changed')
        else:
            need(call['kind'] == 'register' and va == 0x57f55bf and raw == b'\xff\xd5',
                 'call.register', 'unexpected register call')
            load = bytes(elf.mapping(0x57f5591, 7)[1])
            need(load[:3] == b'\x48\x8b\x2d', 'call.register-load', 'RBP load opcode')
            need(0x57f5598 + struct.unpack_from('<i', load, 3)[0] == 0x64dfb50,
                 'call.register-slot', 'RBP source slot')
    for branch in bindings['branches']:
        va = int(branch['va'], 16)
        raw = bytes(elf.mapping(va, len(row_map[va][0]))[1])
        if len(raw) == 2 and (0x70 <= raw[0] <= 0x7f or raw[0] == 0xeb):
            target = va + 2 + struct.unpack_from('<b', raw, 1)[0]
        elif len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
            target = va + 6 + struct.unpack_from('<i', raw, 2)[0]
        elif len(raw) == 5 and raw[0] == 0xe9:
            target = va + 5 + struct.unpack_from('<i', raw, 1)[0]
        else:
            raise Rejection('branch.encoding', 'changed branch width/opcode')
        need(target == int(branch['target'], 16) and target in row_map,
             'branch.target', 'changed branch target')
        # Polarity is deliberately checked by semantic guards below, not hidden
        # by a generic branch-byte equality check before those controls run.


def check_imports_data(elf, bindings):
    m = elf.relocation(0x64dfb50)
    need(m['type'] == 6 and m['addend'] == 0, 'import.kind', 'memcmp relocation kind/addend')
    need(m['index'] == 12, 'import.symbol-index', 'memcmp symbol index')
    need(m['name'] == 'memcmp' and (m['info'], m['section_index'], m['value'], m['size'], m['other']) == (18, 0, 0, 0, 0),
         'import.symbol', 'memcmp dynamic symbol')
    f = elf.relocation(0x64df830)
    need((f['type'], f['index'], f['addend']) == (8, 0, 0x1680c10), 'import.failure-target', 'failure binding')
    for saved in bindings['import_and_failure_bindings']:
        slot = int(saved['slot'], 16)
        r = elf.relocation(slot)
        need(bytes(bounded(elf.image, r['offset'], 24)).hex() == saved['relocation_bytes'], 'import.raw-rela', 'changed raw relocation')
        need(bytes(elf.mapping(slot, 8)[1]).hex() == saved['slot_file_bytes'], 'import.slot-initializer', 'changed on-file slot')
    for item in bindings['data']:
        va, size = int(item['va'], 16), item['size']
        raw = bytes(elf.mapping(va, size)[1])
        if va in (0x649cd70, 0x649cd58):
            r = elf.relocation(va)
            need((r['type'], r['index'], r['addend']) == (8, 0, 0x44ae86), 'data.location-relocation', 'source pointer')
            need(unpack('<QII', raw, 8) == (38, item['line'], 15), 'data.location', 'source length/line/column')
        code = 'data.source-text' if va == 0x44ae86 else 'data.raw'
        need(raw.hex() == item['bytes'], code, 'changed bound data span')


def verify(image, evidence, below_identity=False, exports_override=None):
    if not below_identity:
        target_admission(image)
    else:
        need(len(image) == TARGET_SIZE, 'identity.size', 'mutation must preserve file size')
    elf = Elf(image)
    bindings = evidence['bindings']
    need(elf.rela_count == bindings['rela_count'] and elf.rela_types == bindings['rela_types'],
         'rela.census', 'changed relocation type census')
    exports = evidence['exports'] if exports_override is None else exports_override
    row_map = {}
    guard_bytes = {}
    body_hashes = []
    for i, label in enumerate(LABELS):
        body = bindings['bodies'][i]
        start, end = SCOPE[i]
        need((int(body['start'], 16), int(body['end'], 16), body['label']) == (start, end, label), 'evidence.scope', 'wrong scope')
        rows = parse_export(exports[label], start, end)
        need(len(rows) == body['rows'], 'export.row-count', 'wrong row count')
        body_offset, mapped_body = elf.mapping(start, end - start)
        need(body_offset == int(body['file_offset'], 16), 'elf.body-mapping', 'changed PT_LOAD file mapping')
        raw_body = bytes(mapped_body)
        if not below_identity:
            need(sha(raw_body) == body['body_sha256'], 'body.sha256', label)
            need(b''.join(row[1] for row in rows) == raw_body, 'export.bytes', label)
        for va, raw, assembly in rows:
            need(va not in row_map, 'export.partition', 'overlapping bodies')
            row_map[va] = (raw, assembly)
        body_hashes.append({'label': label, 'sha256': sha(raw_body)})
        for name, a, z in GUARDS:
            if start <= a < z <= end:
                selected = [(va, raw) for va, raw, _ in rows if a <= va < z]
                need(selected and selected[0][0] == a and selected[-1][0] + len(selected[-1][1]) == z,
                     'guard.partition', name)
                guard_bytes[name] = b''.join(raw for _, raw in selected)
        need(not any(start - 16 < va < end for va in elf.relas), 'rela.code-overlap', 'RELA near body')
    need(len(row_map) == 643 and len(guard_bytes) == len(GUARDS), 'evidence.coverage', 'incomplete partition/guards')
    check_frames(elf, bindings['bodies'])
    check_calls_branches(elf, bindings, row_map)
    check_imports_data(elf, bindings)
    for name, start, end in GUARDS:
        actual = bytes(elf.mapping(start, end - start)[1])
        need(actual == guard_bytes[name], 'semantic:' + name, 'changed proof-guard instructions')
    return {'body_hashes': body_hashes, 'bodies': 5, 'bytes': 2542, 'rows': len(row_map),
            'calls': len(bindings['calls']), 'branches': len(bindings['branches']),
            'relocations': elf.rela_count, 'semantic_guards': len(GUARDS)}


def patch_at(image, offset, old, new):
    old, new = bytes.fromhex(old), bytes.fromhex(new)
    need(len(old) == len(new) and old != new and bytes(bounded(image, offset, len(old))) == old,
         'control.definition', 'wrong original bytes, width or no-op patch')
    mutant = bytearray(image)
    mutant[offset:offset + len(old)] = new
    return mutant


def run_controls(image, evidence):
    baseline = Elf(image)
    # The unmodified image must pass the same path that bypasses only the three
    # universal byte-identity layers. No semantic/binding guard is bypassed.
    verify(image, evidence, below_identity=True)
    definitions = []
    for name, va, displacement, old, new, guard in SEMANTIC_CONTROLS:
        off = baseline.mapping(va + displacement, len(bytes.fromhex(old)))[0]
        definitions.append((name, 'semantic-byte', off, old, new, 'semantic:' + guard))
    definitions += [
        ('direct-iterator-call-target', 'call-binding', baseline.mapping(0x4e44c49, 1)[0], 'e3', 'e4', 'call.target'),
        ('register-memcmp-source-slot', 'call-binding', baseline.mapping(0x57f5594, 1)[0], 'b8', 'c0', 'call.register-slot'),
        ('iterator-empty-branch-target', 'branch-binding', baseline.mapping(0x5138739, 1)[0], '39', '3d', 'branch.target'),
        ('wrong-ELF-machine', 'malformed-ELF', 18, '3e', '03', 'elf.identity'),
    ]
    frame_section = baseline.named['.eh_frame'][4]
    body = evidence['bindings']['bodies'][0]
    fde = frame_section + int(body['fde']['fde_section_offset'], 16)
    cie = frame_section + int(body['fde']['cie_section_offset'], 16)
    definitions += [
        ('FDE-record-length', 'unwind-binding', fde, '28', '24', 'fde.length'),
        ('FDE-CIE-backreference', 'unwind-binding', fde + 4, '7c', '7d', 'fde.cie-reference'),
        ('FDE-start', 'unwind-binding', fde + 8, '48', '49', 'fde.start'),
        ('FDE-extent', 'unwind-binding', fde + 12, '6d', '6c', 'fde.extent'),
        ('CIE-pointer-encoding', 'unwind-binding', cie + 16, '1b', '03', 'cie.encoding'),
    ]
    memcmp = baseline.relocation(0x64dfb50)
    failure = baseline.relocation(0x64df830)
    definitions += [
        ('memcmp-symbol-index', 'import-binding', memcmp['offset'] + 12, '0c', '0d', 'import.symbol-index'),
        ('failure-relative-target', 'import-binding', failure['offset'] + 16, '10', '11', 'import.failure-target'),
        ('Location-length', 'data-binding', baseline.mapping(0x649cd78, 1)[0], '26', '27', 'data.location'),
        ('Location-line', 'data-binding', baseline.mapping(0x649cd80, 1)[0], '1e', '1f', 'data.location'),
        ('source-path-byte', 'data-binding', baseline.mapping(0x44ae86, 1)[0], '6e', '6f', 'data.source-text'),
    ]
    results = []

    def record(name, category, expected, action, mutation):
        try:
            action()
        except Rejection as error:
            results.append({'name': name, 'category': category, 'expected': expected,
                            'actual': error.code, 'passed': error.code == expected, 'mutation': mutation})
        except Exception as error:
            results.append({'name': name, 'category': category, 'expected': expected,
                            'actual': 'unexpected-exception:' + type(error).__name__, 'passed': False,
                            'mutation': mutation})
        else:
            results.append({'name': name, 'category': category, 'expected': expected,
                            'actual': 'unexpected-admission', 'passed': False, 'mutation': mutation})

    for name, category, off, old, new, expected in definitions:
        mutant = patch_at(image, off, old, new)
        record(name, category, expected, lambda: verify(mutant, evidence, below_identity=True),
               {'file_offset': hex(off), 'old': old, 'new': new})
    record('whole-target-size', 'outer-admission', 'identity.size', lambda: target_admission(image[:-1]), {'removed': 'last byte'})
    wrong_sha = bytearray(image)
    wrong_sha[-1] ^= 1
    record('whole-target-digest', 'outer-admission', 'identity.sha256', lambda: target_admission(wrong_sha), {'xor_last_byte': 1})
    malformed_elf = bytearray(image)
    malformed_elf[40:48] = struct.pack('<Q', len(image) - 4)
    record('section-table-out-of-file', 'malformed-ELF', 'elf.bounds',
           lambda: verify(malformed_elf, evidence, below_identity=True), {'file_offset': '0x28', 'new_section_offset': len(image) - 4})
    original = evidence['exports']['predicate']
    lines = original.decode('utf-8').splitlines(keepends=True)
    first = next(i for i, line in enumerate(lines) if ROW.fullmatch(line.rstrip('\r\n')))
    malformed = (
        ('export-first-row-gap', lines[:first] + lines[first + 1:], 'export.partition'),
        ('export-duplicate-row', lines[:first] + [lines[first]] + lines[first:], 'export.partition'),
        ('export-invalid-hex', lines[:first] + [lines[first].replace('41 56', 'gg 56', 1)] + lines[first + 1:], 'export.syntax'),
    )
    for name, changed, expected in malformed:
        replacement = ''.join(changed).encode('utf-8')
        need(replacement != original, 'control.definition', 'malformed export edit is a no-op')
        exports = dict(evidence['exports'])
        exports['predicate'] = replacement
        record(name, 'malformed-export', expected,
               lambda: verify(image, evidence, below_identity=True, exports_override=exports),
               {'export': 'predicate.gnu.txt', 'edited_text_sha256': sha(replacement)})
    return results


def main():
    source_sha = sha(Path(__file__).read_bytes())
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target', type=Path, required=True)
    p.add_argument('--evidence', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--controls', action='store_true')
    args = p.parse_args()
    need(not args.out.exists() and not args.out.is_symlink(), 'output.exists', 'fresh output directory required')
    output = args.out.resolve()
    evidence_root = args.evidence.resolve()
    need(output != evidence_root and evidence_root not in output.parents, 'output.sealed', 'do not write inside sealed evidence')
    image = read_target(args.target)  # Before any output artifact is created.
    evidence = read_evidence(args.evidence)
    baseline = verify(image, evidence)
    controls = run_controls(image, evidence) if args.controls else []
    # Re-admit originals before writing the deterministic result. Control copies
    # never modify the file or the sealed export bytes on disk.
    read_target(args.target)
    read_evidence(args.evidence)
    need(sha(Path(__file__).read_bytes()) == source_sha, 'source.changed', 'verifier changed during run')
    result = {'schema': 'stake-static-qualification-v1', 'target_sha256': TARGET_SHA,
              'target_size': TARGET_SIZE, 'freeze_sha256': FREEZE_SHA,
              'bindings_sha256': BINDINGS_SHA, 'verifier_sha256': source_sha,
              'baseline': baseline, 'controls_requested': args.controls,
              'below_identity_unchanged_image_passed': bool(args.controls),
              'controls': controls, 'control_count': len(controls),
              'failed_control_count': sum(not item['passed'] for item in controls),
              'captured_execution_or_emulation': False,
              'limit': 'Static certificate/guard qualification only; no dynamic behavior, register machine, corpus, Rust or imported-provider verification.'}
    args.out.mkdir(parents=True)
    raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode('utf-8')
    (args.out / 'result.json').write_bytes(raw)
    print(json.dumps({'baseline': 'pass', 'controls': len(controls),
                      'failed_controls': result['failed_control_count'], 'result_sha256': sha(raw)}, sort_keys=True))
    return 1 if result['failed_control_count'] else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Rejection as failure:
        print(json.dumps({'status': 'rejected', 'code': failure.code, 'detail': failure.detail}, sort_keys=True), file=sys.stderr)
        sys.exit(2)
    except (OSError, ValueError, KeyError, TypeError, struct.error) as failure:
        print(json.dumps({'status': 'inconclusive-input-error', 'exception': type(failure).__name__}, sort_keys=True), file=sys.stderr)
        sys.exit(3)
