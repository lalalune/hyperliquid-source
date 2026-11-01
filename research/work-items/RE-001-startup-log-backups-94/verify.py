#!/usr/bin/env python3
"""Reproduce static node94 startup log backup evidence. No capture execution or emulation."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BODIES = {
    'archive': (0x1438630, 0x1438d69, 0xfceb60, 'd43caad24ba7477210d5bbe8742e08def1674cee032a21fa00d9d5ead9bc134f'),
    'regular_file': (0x144a710, 0x144a884, 0xfcf764, '46da0a7173f325bd07246d3f14d16e95e5a319e7512a68586a52083c335f5f9c'),
    'content': (0x144c330, 0x144c436, 0xfcf944, '660ec2e890c155e3871aa30fd3a7ef1dc46bb97e644de36d0f4344955f91c17d'),
    'move_request': (0x144cf90, 0x144d0c9, 0xfcfb08, '9c98d8858e64010887f5cb77455cad3a4680b5e8ac360261283825887859fc0e'),
    'exists': (0x144a2f0, 0x144a3dc, 0xfcf6e0, '1b7890464a6d42ae17dd182bb7370e59e0e4a33a2e516580407ed12b2cb4c260'),
}
SUPPORT = {
    'caller': (0x2275d02, 0x2275d1f, 0x2275a10, 0x227a0db),
    'stat_fallback': (0x4edfcc0, 0x4edfcf6, 0x4edfb40, 0x4edfd58),
}
SLOTS = {
    0x576f490: 0x1438630,
    0x576e040: 0x1344760,
    0x576e928: 0x577b288,
    0x576e8a0: 0x151cba0,
    0x576ea48: 0x151cec0,
    0x576ea60: 0x1454a00,
    0x576e9e8: 0x144a710,
    0x576e958: 0x144c330,
    0x576f498: 0x144cf90,
    0x576e090: 0x1570900,
    0x576f610: 0x144a2f0,
    0x576f618: 0x4edfb40,
    0x576f648: 0x4ed9180,
    0x576e8c8: 0x13e4e40,
    0x576e960: 0x4edbb20,
}

def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        names = [s['name'] for s in self.sections]
        require(len(names) == len(set(names)), 'duplicate section names')

    def off(self, va, size=1):
        matches = [s for s in self.sections if s['type'] != 8 and
                   s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'ambiguous or unbacked VA')
        return matches[0]['offset'] + va - matches[0]['address']

    def get(self, va, size):
        offset = self.off(va, size)
        raw = self.data[offset:offset + size]
        require(len(raw) == size, 'truncated VA bytes')
        return raw

    def relocs(self):
        sec, = [s for s in self.sections if s['name'] == '.rela.dyn']
        require(sec['size'] % 24 == 0, 'partial RELA record')
        result = {}
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', self.data, off)
            require(slot not in result, 'duplicate relocation slot')
            result[slot] = (info, addend, off)
        return result


def export_rows(image, name, start, end):
    """Require byte-complete independent exports with equal instruction starts."""
    providers = []
    for provider in ('gnu', 'llvm'):
        cursor, rows = start, []
        for line in (PACKET / f'{name}.{provider}.txt').read_text().splitlines():
            match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)(.*)$', line)
            if not match:
                continue
            va, raw, asm = int(match[1], 16), bytes.fromhex(match[2]), match[3].strip()
            require(va == cursor and va + len(raw) <= end, 'export range: ' + name)
            require(image.get(va, len(raw)) == raw, 'export bytes: ' + name)
            if asm:
                # LLVM 18 prints LOCK as a separate one-byte pseudo-instruction.
                # Join only a literal F0/lock row to its immediately adjacent opcode.
                if rows and rows[-1][1] == b'\xf0' and rows[-1][2] == 'lock':
                    prefix_va, prefix, _ = rows.pop()
                    require(prefix_va + 1 == va, 'noncontiguous LOCK prefix')
                    rows.append((prefix_va, prefix + raw, 'lock ' + asm))
                else:
                    rows.append((va, raw, asm))
            else:
                require(bool(rows), 'orphan export continuation')
                a, previous, text = rows[-1]
                rows[-1] = (a, previous + raw, text)
            cursor += len(raw)
        require(cursor == end, 'incomplete export: ' + name)
        providers.append(rows)
    require([(a, b) for a, b, _ in providers[0]] == [(a, b) for a, b, _ in providers[1]],
            'independent decoder boundaries differ: ' + name)
    return providers[0]


def call_candidates(image, target, prefix):
    text, = [s for s in image.sections if s['name'] == '.text']
    raw = image.data[text['offset']:text['offset'] + text['size']]
    pos, found = 0, []
    while True:
        pos = raw.find(prefix, pos)
        if pos < 0 or pos + len(prefix) + 4 > len(raw):
            return found
        va = text['address'] + pos
        to = va + len(prefix) + 4 + struct.unpack_from('<i', raw, pos + len(prefix))[0]
        if to == target:
            found.append(va)
        pos += 1


LOCATIONS = {
    0x566a0d8: (0x1dfb41, '/home/ubuntu/hl/code_Mainnet/base/src/production.rs', 141, 38),
    0x566a0f0: (0x1dfb41, '/home/ubuntu/hl/code_Mainnet/base/src/production.rs', 141, 68),
    0x566a108: (0x1dfb41, '/home/ubuntu/hl/code_Mainnet/base/src/production.rs', 149, 39),
}
LITERALS = {
    'error_level': (0x2194e1, b'error'), 'warn_level': (0x209d2c, b'warn'),
    'move_token': (0x219c6a, b'mv'), 'caller_role': (0x3d7680, b'infra'),
    'path_template': (0x1f4ea6, bytes.fromhex('c00a2f646174612f6c6f672fc0012fc0012fc000')),
    'backup_template': (0x1de8d5, bytes.fromhex('c0075f6261636b7570c000')),
    'renamed_template': (0x1e113f, bytes.fromhex('0872656e616d656420c004202d3e20c0010a00')),
}
RETURNS = {'archive': 0x1438c50, 'regular_file': 0x144a78c,
           'content': 0x144c3ef, 'move_request': 0x144d066, 'exists': 0x144a394}


def simple_template(raw):
    """Only the literal/implicit-row subset used here; not a general renderer."""
    result, cursor, index = [], 0, 0
    while cursor < len(raw):
        tag = raw[cursor]
        cursor += 1
        if tag == 0:
            require(cursor == len(raw), 'template trailing data')
            return result
        if tag == 0xc0:
            result.append({'argument': index})
            index += 1
        else:
            require(1 <= tag <= 127 and cursor + tag <= len(raw), 'template literal bounds/tag')
            result.append({'literal': raw[cursor:cursor + tag].decode('ascii')})
            cursor += tag
    raise ValueError('template missing terminator')


def dynamic_symbol(image, info):
    sym, = [s for s in image.sections if s['name'] == '.dynsym']
    strings, = [s for s in image.sections if s['name'] == '.dynstr']
    index = info >> 32
    require((index + 1) * 24 <= sym['size'], 'dynamic symbol index')
    off = sym['offset'] + index * 24
    name, flags, other, shndx, value, size = struct.unpack_from('<IBBHQQ', image.data, off)
    require(name < strings['size'], 'dynamic string index')
    start = strings['offset'] + name
    end = image.data.find(b'\0', start, strings['offset'] + strings['size'])
    require(end >= start, 'unterminated dynamic symbol')
    return {'name': image.data[start:end].decode('ascii'), 'symbol_index': index,
            'symbol_file_offset': hex(off), 'name_file_offset': hex(start),
            'info': flags, 'other': other, 'section_index': shndx,
            'value': hex(value), 'size': size}


def observe(data, *, body_hashes=True, exports=True):
    image = Image(data)
    _, fdes = eh_frame_records(data, image.sections)
    relocs = image.relocs()
    bodies, support, starts, ends = [], [], set(), set()
    for name, spec in {**BODIES, **SUPPORT}.items():
        begin, end = spec[:2]
        fs, fe = (begin, end) if name in BODIES else spec[2:]
        found = [f for f in fdes if f['start'] == fs]
        require(len(found) == 1 and found[0]['end'] == fe, 'FDE binding: ' + name)
        raw = image.get(begin, end - begin)
        if name in BODIES:
            require(found[0]['fde'] == spec[2], 'FDE record: ' + name)
            if body_hashes:
                require(sha(raw) == spec[3], 'body digest: ' + name)
        row = dict(role=name, start=hex(begin), end=hex(end), bytes=len(raw),
                   sha256=sha(raw), file_offset=hex(image.off(begin)), enclosing_fde=found[0])
        if exports:
            decoded = export_rows(image, name, begin, end)
            row['instructions'] = len(decoded)
            starts.update(a for a, _, _ in decoded)
            ends.update(a + len(b) for a, b, _ in decoded)
            row['calls'] = []
            for va, opcode, asm in decoded:
                if not re.match(r'call\s', asm):
                    continue
                call = {'site': hex(va), 'bytes': opcode.hex(), 'disassembly': asm}
                if opcode[:1] == b'\xe8' and len(opcode) == 5:
                    to = va + 5 + struct.unpack_from('<i', opcode, 1)[0]
                    call['direct_target'] = hex(to)
                    call['target_fde'] = next((f for f in fdes if f['start'] == to), None)
                elif opcode[:2] == b'\xff\x15' and len(opcode) == 6:
                    slot = va + 6 + struct.unpack_from('<i', opcode, 2)[0]
                    require(slot in relocs, 'unbound indirect slot')
                    info, target, off = relocs[slot]
                    call.update(slot=hex(slot), relocation_info=hex(info),
                                relocation_addend=hex(target), relocation_file_offset=hex(off))
                    if info & 0xffffffff != 8:
                        call['dynamic_symbol'] = dynamic_symbol(image, info)
                else:
                    call['unresolved'] = 'register/vtable target; no concrete type or callback body claimed'
                row['calls'].append(call)
            if name in BODIES:
                local_starts = {a for a, _, _ in decoded}
                for va, opcode, asm in decoded:
                    match = re.match(r'j\w+\s+([0-9a-f]+)\s', asm)
                    if match:
                        require(int(match[1], 16) in local_starts, 'branch leaves decoded body')
                row['return_sites'] = [hex(a) for a, _, asm in decoded if asm == 'ret']
                require(row['return_sites'] == [hex(RETURNS[name])],
                        'normal return census: ' + name)
        (bodies if name in BODIES else support).append(row)
    obligations = json.loads((PACKET / 'obligations.json').read_text())
    for name, record in obligations.items():
        va, end = int(record['va'], 16), int(record['end'], 16)
        expected = bytes.fromhex(record['bytes'])
        require(len(expected) == end - va and image.get(va, len(expected)) == expected,
                'instruction obligation: ' + name)
        if exports:
            require(va in starts and end in ends, 'obligation boundary: ' + name)
    if exports:
        frame, = [s for s in image.sections if s['name'] == '.eh_frame']
        headers = re.findall(r'^([0-9a-f]+) .*FDE cie=([0-9a-f]+) pc=([0-9a-f]+)\.\.([0-9a-f]+)$',
                             (PACKET / 'fdes.readelf.txt').read_text(), re.MULTILINE)
        actual = sorted(tuple(int(x, 16) for x in row) for row in headers)
        expected = sorted((r['enclosing_fde']['fde'] - frame['address'],
                           r['enclosing_fde']['cie'] - frame['address'],
                           int(r['start'], 16), int(r['end'], 16)) for r in bodies)
        require(actual == expected, 'independent readelf FDE headers')
    bindings = []
    for slot, target in SLOTS.items():
        require(relocs.get(slot, ())[:2] == (8, target), 'RELATIVE binding: ' + hex(slot))
        bindings.append({'slot': hex(slot), 'target': hex(target), 'kind': 'R_X86_64_RELATIVE',
                         'record_file_offset': hex(relocs[slot][2])})
    dynamic = []
    for slot, expected in [(0x57772d8, 'stat64'), (0x576dfe0, 'memcpy')]:
        info, addend, off = relocs[slot]
        require(info & 0xffffffff == 6 and addend == 0, 'GLOB_DAT binding: ' + hex(slot))
        symbol = dynamic_symbol(image, info)
        require(symbol['name'] == expected and symbol['section_index'] == 0 and symbol['value'] == '0x0',
                'dynamic symbol binding: ' + expected)
        dynamic.append({'slot': hex(slot), 'relocation_info': hex(info),
                        'record_file_offset': hex(off), 'symbol': symbol})
    locations = []
    for record, (pointer, path, line, column) in LOCATIONS.items():
        require(relocs.get(record, ())[:2] == (8, pointer), 'Location pointer: ' + hex(record))
        size, actual_line, actual_column = struct.unpack('<QII', image.get(record + 8, 16))
        require((size, actual_line, actual_column) == (len(path), line, column), 'Location fields: ' + hex(record))
        require(image.get(pointer, size) == path.encode(), 'Location path: ' + hex(record))
        locations.append({'record': hex(record), 'pointer': hex(pointer), 'path': path,
                          'length': size, 'line': line, 'column': column})
    literals = []
    for name, (va, expected) in LITERALS.items():
        raw = image.get(va, len(expected))
        require(raw == expected, 'literal binding: ' + name)
        row = {'role': name, 'va': hex(va), 'bytes': raw.hex(), 'length': len(raw)}
        if name.endswith('_template'):
            row['tokens'] = simple_template(raw)
        else:
            row['text'] = raw.decode('ascii')
        literals.append(row)
    census = []
    for target, prefix, expected in [(0x1438630, b'\xe8', []),
                                     (0x576f490, b'\xff\x15', [0x2275d19]),
                                     (0x576f490, b'\xff\x25', [])]:
        candidates = call_candidates(image, target, prefix)
        require(candidates == expected, 'archive incoming candidate census')
        if exports:
            require(set(candidates) <= starts, 'incoming call not at retained decoded boundary')
        census.append({'target_or_slot': hex(target), 'prefix': prefix.hex(),
                       'sites': [hex(a) for a in candidates]})
    incoming_slots = [slot for slot, (info, target, _) in relocs.items() if info == 8 and target == 0x1438630]
    require(incoming_slots == [0x576f490], 'archive relocation target census')
    return {'schema': 1, 'target_sha256': sha(data), 'coordinates': 'ELF virtual address; exclusive end',
            'primary_bodies': bodies, 'support_windows': support,
            'primary_bytes': sum(x['bytes'] for x in bodies),
            'support_bytes': sum(x['bytes'] for x in support), 'obligation_count': len(obligations),
            'relative_bindings': bindings, 'dynamic_bindings': dynamic,
            'source_locations': locations, 'literals': literals,
            'incoming_candidates': census, 'incoming_RELATIVE_slots': [hex(x) for x in incoming_slots],
            'captured_code_executed_or_emulated': False}


def build(data):
    require(sha(data) == DIGEST, 'wrong node94 SHA-256')
    return observe(data)


def controls(data):
    image = Image(data)
    obligations = json.loads((PACKET / 'obligations.json').read_text())
    offsets = [(image.off(int(r['end'], 16) - 1), 'instruction ' + name) for name, r in obligations.items()]
    relocs = image.relocs()
    offsets += [(relocs[slot][2] + 16, 'relative target ' + hex(slot)) for slot in SLOTS]
    for slot in (0x57772d8, 0x576dfe0):
        info, _, off = relocs[slot]
        offsets += [(off + 8, 'dynamic relocation type ' + hex(slot)),
                    (int(dynamic_symbol(image, info)['name_file_offset'], 16), 'dynamic name ' + hex(slot))]
    for record, (pointer, _, _, _) in LOCATIONS.items():
        offsets += [(relocs[record][2] + 16, 'Location pointer ' + hex(record)),
                    (image.off(record + 8), 'Location length ' + hex(record)),
                    (image.off(record + 16), 'Location line ' + hex(record))]
    offsets += [(image.off(va), 'literal ' + name) for name, (va, _) in LITERALS.items()]
    offsets += [(image.off(spec[2]) + 12, 'FDE range ' + name) for name, spec in BODIES.items()]
    result = []
    for off, label in offsets:
        changed = bytearray(data)
        changed[off] ^= 1
        try:
            observe(changed, body_hashes=False, exports=False)
        except ValueError as error:
            result.append({'control': label, 'file_offset': hex(off), 'rejection': str(error)})
        else:
            raise ValueError('corruption survived: ' + label)
    return {'digest_and_export_guards_bypassed': True, 'rejected': result, 'survived': []}


def encoded(obj):
    return json.dumps(obj, indent=2, sort_keys=True) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='regenerate machine records')
    parser.add_argument('--controls', action='store_true', help='run deep corruption checks')
    args = parser.parse_args()
    data = TARGET.read_bytes()
    result = build(data)
    outputs = {'records.json': result}
    if args.controls:
        outputs['controls.json'] = controls(data)
    for name, value in outputs.items():
        text = encoded(value)
        if args.write:
            (PACKET / name).write_text(text)
        else:
            require((PACKET / name).read_text() == text, 'regeneration mismatch: ' + name)
    print(f"PASS: {len(result['primary_bodies'])} complete FDE bodies / {result['primary_bytes']} bytes")
    if args.controls:
        print(f"PASS: {len(outputs['controls.json']['rejected'])} corruption controls rejected")


if __name__ == '__main__':
    main()
