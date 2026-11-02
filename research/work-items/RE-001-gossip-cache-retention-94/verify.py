#!/usr/bin/env python3
"""Reproduce static node94 cache evidence. No capture execution or emulation."""
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
    'update': (0x473ce40, 0x473d120, 0x12870bc,
               'daac27e319ee7423e5ea71422b75948847ccd56cdd8347d701ae1c34ba79681a'),
    'insert': (0x49344d0, 0x49346ef, 0x12a84d8,
               '04f100a44a41409cbdfb929e339ed002dac3b5c17375132fe8ca0ba1e4dae54a'),
    'pop_first': (0x4947160, 0x4947323, 0x12a96b0,
                  'f814042648686c944a1dd73f632f969004894c43a2249fdcd47c08cd1d26718e'),
}
SUPPORT = {
    'caller_a': (0x2017f31, 0x2017f42, 0x2017c80, 0x2018ded),
    'caller_b': (0x474c232, 0x474c248, 0x474bfa0, 0x474e1a1),
    'remove_leaf_route': (0x42b0262, 0x42b028e, 0x42b0060, 0x42b0311),
}
SLOTS = {
    0x5773578: 0x473ce40, 0x57730a8: 0x4761900, 0x57730b0: 0x4761470,
    0x576ef30: 0x4e0f640, 0x576ef38: 0x4e0f2c0, 0x572eb18: 0x1fe9e1,
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


def observe(data, *, body_hashes=True, exports=True):
    image = Image(data)
    _, fdes = eh_frame_records(data, image.sections)
    bodies, starts = [], set()
    for name, (begin, end, fde, expected) in BODIES.items():
        found = [f for f in fdes if f['start'] == begin]
        require(len(found) == 1 and found[0]['end'] == end and found[0]['fde'] == fde,
                'FDE binding: ' + name)
        raw = image.get(begin, end - begin)
        if body_hashes:
            require(sha(raw) == expected, 'body digest: ' + name)
        row = dict(found[0], role=name, file_offset=image.off(begin), bytes=len(raw), sha256=sha(raw))
        if exports:
            decoded = export_rows(image, name, begin, end)
            row['instructions'] = len(decoded)
            starts.update(a for a, _, _ in decoded)
            # List every call in each full primary export, including unknown register calls.
            row['calls'] = []
            for va, opcode, asm in decoded:
                if not re.match(r'call\s', asm):
                    continue
                call = {'site': hex(va), 'bytes': opcode.hex(), 'disassembly': asm}
                if opcode[:1] == b'\xe8' and len(opcode) == 5:
                    call['direct_target'] = hex(va + 5 + struct.unpack_from('<i', opcode, 1)[0])
                elif opcode[:2] == b'\xff\x15' and len(opcode) == 6:
                    call['slot'] = hex(va + 6 + struct.unpack_from('<i', opcode, 2)[0])
                row['calls'].append(call)
        bodies.append(row)
    support = []
    for name, (begin, end, fs, fe) in SUPPORT.items():
        found = [f for f in fdes if f['start'] == fs]
        require(len(found) == 1 and found[0]['end'] == fe, 'support FDE: ' + name)
        record = {'name': name, 'start': hex(begin), 'end': hex(end),
                  'enclosing_fde_start': hex(fs), 'enclosing_fde_end': hex(fe),
                  'bytes': end - begin, 'sha256': sha(image.get(begin, end - begin))}
        if exports:
            decoded = export_rows(image, name, begin, end)
            starts.update(a for a, _, _ in decoded)
            record['instructions'] = len(decoded)
        support.append(record)
    obligations = json.loads((PACKET / 'obligations.json').read_text())
    for name, record in obligations.items():
        va, expected = int(record['va'], 16), bytes.fromhex(record['bytes'])
        require(image.get(va, len(expected)) == expected, 'instruction obligation: ' + name)
        if exports:
            require(va in starts, 'obligation not at instruction boundary: ' + name)
    if exports:
        frame, = [s for s in image.sections if s['name'] == '.eh_frame']
        readelf = (PACKET / 'fdes.readelf.txt').read_text()
        headers = re.findall(r'^([0-9a-f]+) .*FDE cie=([0-9a-f]+) pc=([0-9a-f]+)\.\.([0-9a-f]+)$',
                             readelf, re.MULTILINE)
        actual = sorted(tuple(int(x, 16) for x in row) for row in headers)
        expected = sorted((r['fde'] - frame['address'], r['cie'] - frame['address'],
                           r['start'], r['end']) for r in bodies)
        require(actual == expected, 'independent readelf FDE headers')
    relocs = image.relocs()
    for body in bodies:
        for call in body.get('calls', []):
            if 'slot' in call:
                slot = int(call['slot'], 16)
                require(slot in relocs, 'unbound call relocation')
                info, addend, off = relocs[slot]
                call['relocation_info'] = hex(info)
                call['relocation_addend'] = hex(addend)
                call['relocation_record_file_offset'] = hex(off)
    bindings = []
    for slot, target in SLOTS.items():
        require(relocs.get(slot, ())[:2] == (8, target), 'RELATIVE binding: ' + hex(slot))
        bindings.append({'slot': hex(slot), 'target': hex(target), 'kind': 'R_X86_64_RELATIVE',
                         'record_file_offset': hex(relocs[slot][2])})
    require([slot for slot, (info, target, _) in relocs.items() if target == 0x473ce40] == [0x5773578],
            'update relocation-target census')
    source = b'/home/ubuntu/hl/code_Mainnet/node/src/gossip_rpc.rs'
    length, line, column = struct.unpack('<QII', image.get(0x572eb20, 16))
    path_bytes = image.get(0x1fe9e1, length)
    require(path_bytes == source, 'gossip source Location bytes')
    require((line, column) == (235, 43), 'gossip source Location coordinates')
    # No executing code: only decode the compare immediates/field displacements.
    entry_limit = struct.unpack('<I', image.get(0x473cfe8, 4))[0]
    repeat_limit = struct.unpack('<I', image.get(0x473d014, 4))[0]
    require(entry_limit == repeat_limit + 1, 'retention bounds disagree')
    xrefs = []
    for target, prefix, expected in [
        (0x473ce40, b'\xe8', []), (0x49344d0, b'\xe8', [0x473cfae]),
        (0x4947160, b'\xe8', [0x473d020]),
        (0x5773578, b'\xff\x15', [0x2017f3c, 0x474c242]),
        (0x5773578, b'\xff\x25', []),
    ]:
        found = call_candidates(image, target, prefix)
        require(found == expected, 'call candidate census: ' + hex(target) + '/' + prefix.hex())
        if exports:
            require(set(found) <= starts, 'call candidate not at retained decoded boundary')
        xrefs.append({'target_or_slot': hex(target), 'prefix': prefix.hex(), 'sites': [hex(a) for a in found]})
    return {'schema': 1, 'target_sha256': sha(data), 'coordinates': 'ELF virtual address; exclusive end',
            'primary_bodies': bodies, 'support_windows': support,
            'primary_bytes': sum(x['bytes'] for x in bodies),
            'obligation_count': len(obligations), 'relative_bindings': bindings,
            'source_location': {'record': '0x572eb18', 'pointer': '0x1fe9e1',
                                'raw_path_hex': path_bytes.hex(), 'length': length,
                                'line': line, 'column': column},
            'retention': {'entry_comparison': 'unsigned length < immediate skips eviction',
                          'entry_immediate': entry_limit, 'repeat_comparison': 'unsigned length <= immediate exits loop',
                          'repeat_immediate': repeat_limit},
            'call_candidate_census': xrefs, 'captured_code_executed_or_emulated': False}


def build(data):
    require(sha(data) == DIGEST, 'wrong node94 SHA-256')
    return observe(data)


def controls(data):
    image = Image(data)
    # Bypass whole-file/body digests AND disassembly byte equality. These must be
    # caught by the claimed instruction/data/FDE/relocation obligations themselves.
    mutations = [
        (0x473ce68, 'lock byte displacement'), (0x473cea9, 'rightmost child slot'),
        (0x473cf60, 'greatest-key address'), (0x473cf6f, 'empty-map fallback'),
        (0x473cf7d, 'comparison input field'), (0x473cf81, 'comparison equality branch'),
        (0x473cf86, 'sticky flag reset value'), (0x473cf8a, 'insertion key field'),
        (0x473cfe8, 'entry limit'), (0x473cfed, 'entry unsigned branch'),
        (0x473d014, 'repeat limit'), (0x473d018, 'repeat unsigned branch'),
        (0x473d021, 'eviction call target'), (0x4934519, 'key column'),
        (0x493451f, 'unsigned ordering'), (0x4934539, 'replace branch'),
        (0x493457d, 'replace skips length increment'), (0x4934677, 'insert count field'),
        (0x49471a3, 'leftmost edge displacement'), (0x4947210, 'zero-index request'),
        (0x494724c, 'eviction decrement'), (0x49472b9, 'empty sentinel field'),
        (0x2017f3e, 'first caller slot'), (0x474c244, 'second caller slot'),
    ]
    offsets = [(image.off(va), label) for va, label in mutations]
    offsets += [(image.relocs()[slot][2] + 16, 'relocation ' + hex(slot)) for slot in SLOTS]
    offsets += [(image.off(0x572eb20), 'source Location length'),
                (image.off(0x572eb28), 'source Location line'),
                (image.off(BODIES['update'][2]) + 12, 'FDE range')]
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
