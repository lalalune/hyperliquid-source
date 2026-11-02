#!/usr/bin/env python3
"""Reproduce static node94 production wait-cycle evidence. No capture execution or emulation."""
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
    'production': (0x1487370, 0x14875bf, 0xfd704c, 'a07abd6959e5da25340352ec6bb6194cf4b7a882bf65fc79202031e57b8b8bec'),
    'wait': (0x14799a0, 0x1479d2a, 0xfd5554, '09307513d9c40e4e76ca077f08b54c1a45e78b5148989e8d1c1d8343bfbadddc'),
}
SUPPORT = {
    'caller': (0x14b8004, 0x14b8015, 0x14b7cf0, 0x14b8179),
    'duration_add': (0x4f65d4e, 0x4f65d88, 0x4f65d40, 0x4f65edd),
    'clock_read': (0x4ee3800, 0x4ee3830, 0x4ee3800, 0x4ee38c9),
}
SLOTS = {0x576f038: 0x157b560, 0x576f040: 0x157b540,
         0x576f728: 0x4f65d40, 0x576f088: 0x4f68f00,
         0x576f4b0: 0x4f049e0, 0x576f4b8: 0x4f581b0}

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
    0x566c590: (0x1dfb41, '/home/ubuntu/hl/code_Mainnet/base/src/production.rs', 120, 61),
    0x566ebd0: (0x1ea4e5, '/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/std/src/thread/functions.rs', 131, 29),
    0x566c680: (0x1e4dcc, '/home/ubuntu/hl/code_Mainnet/base/src/lu.rs', 60, 46),
    0x566c698: (0x1e4dcc, '/home/ubuntu/hl/code_Mainnet/base/src/lu.rs', 72, 5),
    0x566c6b0: (0x1e4dcc, '/home/ubuntu/hl/code_Mainnet/base/src/lu.rs', 71, 57),
}
TABLES = {
    0x21a450: [0x14799cc, 0x1479c7f, 0x1479c72, 0x14799eb],
    0x21a460: [0x1479a09, 0x1479c9b, 0x1479c8c, 0x1479c31],
}


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
                require(row['return_sites'] == ([hex(0x14874ef)] if name == 'production' else [hex(0x1479c71)]),
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
    for slot, expected in [(0x576f4a8, 'pthread_detach'), (0x576ea88, 'clock_gettime')]:
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
    tables = []
    for va, targets in TABLES.items():
        raw = image.get(va, 16)
        actual = [va + offset for offset in struct.unpack('<4i', raw)]
        require(actual == targets, 'state table: ' + hex(va))
        if exports:
            require(set(actual) <= starts, 'state-table target boundary')
        tables.append({'base': hex(va), 'bytes': raw.hex(), 'targets_0_to_3': [hex(x) for x in actual]})
    candidates = call_candidates(image, 0x1487370, b'\xe8')
    require(candidates == [0x14b800c], 'production incoming E8 census')
    if exports:
        require(set(candidates) <= starts, 'incoming call not at retained decoded boundary')
    require(not [slot for slot, (info, target, _) in relocs.items() if info == 8 and target == 0x1487370],
            'unexpected production relocation target')
    bits, = struct.unpack('<Q', image.get(0x1487462, 8))
    value, = struct.unpack('<d', image.get(0x1487462, 8))
    require(bits == 0x4082c00000000000 and value == 600.0, 'production duration')
    return {'schema': 1, 'target_sha256': sha(data), 'coordinates': 'ELF virtual address; exclusive end',
            'primary_bodies': bodies, 'support_windows': support,
            'primary_bytes': sum(x['bytes'] for x in bodies),
            'support_bytes': sum(x['bytes'] for x in support), 'obligation_count': len(obligations),
            'relative_bindings': bindings, 'dynamic_bindings': dynamic,
            'source_locations': locations, 'state_tables': tables,
            'duration_literal': {'bits': hex(bits), 'binary64_value': value},
            'incoming_E8_candidates': [hex(a) for a in candidates],
            'incoming_RELATIVE_slots': [], 'captured_code_executed_or_emulated': False}


def build(data):
    require(sha(data) == DIGEST, 'wrong node94 SHA-256')
    return observe(data)


def controls(data):
    image = Image(data)
    obligations = json.loads((PACKET / 'obligations.json').read_text())
    offsets = [(image.off(int(r['end'], 16) - 1), 'instruction ' + name) for name, r in obligations.items()]
    relocs = image.relocs()
    offsets += [(relocs[slot][2] + 16, 'relative target ' + hex(slot)) for slot in SLOTS]
    for slot in (0x576f4a8, 0x576ea88):
        info, _, off = relocs[slot]
        offsets += [(off + 8, 'dynamic relocation type ' + hex(slot)),
                    (int(dynamic_symbol(image, info)['name_file_offset'], 16), 'dynamic name ' + hex(slot))]
    for record, (pointer, _, _, _) in LOCATIONS.items():
        offsets += [(relocs[record][2] + 16, 'Location pointer ' + hex(record)),
                    (image.off(record + 8), 'Location length ' + hex(record)),
                    (image.off(record + 16), 'Location line ' + hex(record))]
    for table in TABLES:
        offsets += [(image.off(table + 4 * state), f'state table {hex(table)} entry {state}') for state in range(4)]
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
