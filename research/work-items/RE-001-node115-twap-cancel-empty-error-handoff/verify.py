#!/usr/bin/env python3
"""Authenticate node115 twap-cancel-empty-error-handoff; static reads only, no capture execution."""
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
TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BODIES = {'perp_remove_context': (47367904, 47370265, 18464780, '1d64b62c4c54eea8c604dd80217f513a1a7d1471adfdb73a61624e17d3a4d480'), 'spot_remove_context': (47370272, 47372633, 18464864, 'f8dcdb096f083d52ce2056522652ab6fdac46b37efc7998571aae8c88c65845e'), 'cancel_core': (46329888, 46331842, 18396580, '634ffb41b81654a9c95e981c3b0ea823afd000fc1a3b47d6efc2b4a5c0d4d3d9'), 'direct_wrapper_context': (44235632, 44236034, 14129016, '3a49776d1d7782510f89cf0b4cccb0910ba7042d6322661ecd92f80d928bad05'), 'api_wrapper_context': (46179856, 46181191, 18389088, 'bc885f1dbbffebceeb57c91c03532a68641c0d79d2001ed0efca52dada838198'), 'perp_handoff': (37853200, 37856192, 17861388, '2281ecee1c3eb5959a62b8521b5bfe26753d602e8231ffcee3c293984f88f480'), 'spot_handoff': (37856192, 37859479, 17861476, 'aa305d0ec336a4d34a3bef4a6bfea1aa66f3b8586828ff308a80050d84414b92'), 'perp_records_drop': (42086224, 42086418, 18142660, '6dc2507ce52a29199c63bd97f82fb410cc571d910293a2e7e6dc0db8cd013a0e'), 'spot_records_drop': (42092432, 42092626, 18144432, '56c46c1659dc23c27b2e398e0cc4970d013b773d1f037d22f7dda43f0e82ee19')}
SLOTS = {105772192: 104193584, 105772224: 23596203, 105798184: 93728928, 105795464: 93725456, 105398592: 69411024, 105397792: 4406198, 105772704: 23596080, 105432568: 72222736, 105429392: 4410392, 105798456: 74099712, 105462576: 4496553, 105772576: 23596223, 105798464: 71866096, 105798472: 71869296, 105798480: 71858448, 105429416: 4410392, 105795296: 62977648, 105798488: 62973184, 105798496: 62980096, 105798504: 62986464, 105798512: 62971552}
SUPPORT = {}
LITERALS = {'source_0x433bb6': (4406198, b'l1/src/dex_registry/perp_dex.rs'), 'location_0x6483e20': (105397800, b'\x1f\x00\x00\x00\x00\x00\x00\x00"\x00\x00\x00!\x00\x00\x00'), 'source_0x434c18': (4410392, b'l1/src/dex_registry/clearinghouses.rs'), 'location_0x648b990': (105429400, b'%\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x1d\x00\x00\x00'), 'source_0x449ca9': (4496553, b'/home/ubuntu/hl/code_Mainnet/z_vendor/indexmap/src/map.rs'), 'location_0x6493b30': (105462584, b'9\x00\x00\x00\x00\x00\x00\x00\xfa\x02\x00\x00\x1a\x00\x00\x00'), 'location_0x648b9a8': (105429424, b'%\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00!\x00\x00\x00'), 'literal_context_0x7c95fa': (8164858, b'called `Result::unwrap()` on an `Err` value0001020304050607080910111213141516171'), 'literal_context_0x7d3212': (8204818, b'called `Result::unwrap()` on an `Err` value0001020304050607080910111213141516171')}
IMPORTS = {105773904: (12, 'memcmp'), 105772296: (7, 'memcpy')}
INCOMING = {'perp_remove_context': [], 'spot_remove_context': [], 'cancel_core': [], 'direct_wrapper_context': [], 'api_wrapper_context': [], 'perp_handoff': [], 'spot_handoff': [], 'perp_records_drop': [], 'spot_records_drop': []}
# Image/export helpers adapted from MIT-authored packets #2111, #2141, #2154 and #2184/#2200.
# All target spans, constants and semantic deductions below are newly measured.
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



def incoming(image, fdes):
    """Qualified .text encoded-form census; not arbitrary dynamic dispatch."""
    import capstone
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cache, result, bindings = {}, [], []
    for name in INCOMING:
        target = BODIES[name][0]
        slots = [s for s, (info, value, _) in image.relocs().items() if info == 8 and value == target]
        expected = INCOMING[name]
        require(slots == expected, 'incoming RELATIVE census: ' + name)
        bindings.append({'role': name, 'target': hex(target), 'slots': [hex(s) for s in slots]})
        forms = [(target, b'\xe8')] + [(s, pre) for s in slots for pre in (b'\xff\x15', b'\xff\x25')]
        for address, prefix in forms:
            for site in call_candidates(image, address, prefix):
                owners = [f for f in fdes if f['start'] <= site < f['end']]
                require(len(owners) == 1, 'incoming FDE ownership')
                f, = owners
                if f['start'] not in cache:
                    raw = image.get(f['start'], f['end'] - f['start'])
                    rows = list(decoder.disasm_lite(raw, f['start']))
                    require(sum(row[1] for row in rows) == len(raw), 'incoming complete decode')
                    cache[f['start']] = {row[0]: row for row in rows}
                row = cache[f['start']].get(site)
                require(row and row[1] == len(prefix) + 4 and row[2] in ('call', 'jmp'), 'incoming instruction boundary')
                result.append({'role': name, 'site': hex(site), 'target_or_slot': hex(address),
                               'instruction': row[2] + ' ' + row[3], 'bytes': image.get(site, row[1]).hex(), 'owner': f})
    return {'qualified_candidates': result, 'relative_bindings': bindings,
            'limits': 'Only E8 and RIP-relative FF15/FF25 forms in .text; no arbitrary register/vtable caller or runtime-reachability claim.'}


def observe(data, *, body_hashes=True, exports=True):
    image = Image(data)
    _, fdes = eh_frame_records(data, image.sections)
    relocs = image.relocs()
    bodies, boundaries, ends = [], set(), set()
    for name, (start, end, fde_va, digest) in BODIES.items():
        fs = [f for f in fdes if f['start'] == start]
        require(len(fs) == 1 and fs[0]['end'] == end and fs[0]['fde'] == fde_va,
                'FDE binding: ' + name)
        raw = image.get(start, end - start)
        if body_hashes:
            require(sha(raw) == digest, 'body digest: ' + name)
        row = {'role': name, 'start': hex(start), 'end': hex(end), 'bytes': len(raw),
               'sha256': sha(raw), 'file_offset': hex(image.off(start)), 'enclosing_fde': fs[0]}
        if exports:
            decoded = export_rows(image, name, start, end)
            starts = {a for a, _, _ in decoded}
            boundaries.update(starts)
            ends.update(a + len(b) for a, b, _ in decoded)
            row['instructions'], row['calls_and_tail_jumps'], row['returns'] = len(decoded), [], []
            row['scope'] = 'Close the conditional TWAP cancellation error continuation after a compact removal count store: removed tag two maps to internal d4; both routes pass their original empty record vectors to handoffs that skip record processing and whose zero-capacity empty drops make no calls, then return through wrappers without restoration in that traced path. Prior removal, dispatch and result-copy behavior is credited context. No reachability claim for malformed state, complete removal reconstruction, outer transaction commit, durable persistence, exploit or target execution/emulation.'
            for va, raw, asm in decoded:
                branch = re.match(r'j\w+\s+([0-9a-f]+)\s', asm)
                if branch:
                    require(int(branch[1], 16) in starts or asm.startswith('jmp'), 'conditional branch outside decoded FDE')
                if asm == 'ret':
                    row['returns'].append(hex(va))
                if not re.match(r'call\s', asm) and raw[:2] != b'\xff\x25':
                    continue
                call = {'site': hex(va), 'bytes': raw.hex(), 'disassembly': asm}
                if raw[:1] == b'\xe8':
                    to = va + 5 + struct.unpack_from('<i', raw, 1)[0]
                    call['direct_target'] = hex(to)
                    call['target_fde'] = next((f for f in fdes if f['start'] == to), None)
                elif raw[:2] in (b'\xff\x15', b'\xff\x25'):
                    slot = va + 6 + struct.unpack_from('<i', raw, 2)[0]
                    require(slot in relocs, 'unbound call slot')
                    info, target, off = relocs[slot]
                    call.update(slot=hex(slot), relocation_info=hex(info), addend=hex(target),
                                relocation_file_offset=hex(off))
                    if info & 0xffffffff != 8:
                        call['symbol'] = dynamic_symbol(image, info)
                else:
                    call['qualification'] = 'Register-indirect call; concrete target remains unresolved'
                row['calls_and_tail_jumps'].append(call)
        bodies.append(row)
    obligations = json.loads((PACKET / 'obligations.json').read_text())
    for name, r in obligations.items():
        start, end, raw = int(r['va'], 16), int(r['end'], 16), bytes.fromhex(r['bytes'])
        require(len(raw) == end - start and image.get(start, len(raw)) == raw,
                'instruction obligation: ' + name)
        if exports:
            require(start in boundaries and end in ends, 'instruction span boundary: ' + name)
    bindings = []
    for slot, target in SLOTS.items():
        require(relocs.get(slot, ())[:2] == (8, target), 'RELATIVE binding: ' + hex(slot))
        bindings.append({'slot': hex(slot), 'target': hex(target),
                         'relocation_file_offset': hex(relocs[slot][2])})
    imports = []
    for slot, (index, name) in IMPORTS.items():
        require(relocs.get(slot, ())[:2] == ((index << 32) | 6, 0), 'GLOB_DAT binding: ' + name)
        symbol = dynamic_symbol(image, relocs[slot][0])
        require(symbol['name'] == name and symbol['info'] == 18 and symbol['other'] == 0 and
                symbol['section_index'] == 0 and symbol['value'] == '0x0' and symbol['size'] == 0,
                'undefined dynamic function: ' + name)
        imports.append({'slot': hex(slot), 'relocation_info': hex(relocs[slot][0]), 'symbol': symbol})
    literals = []
    for name, (va, expected) in LITERALS.items():
        require(image.get(va, len(expected)) == expected, 'literal binding: ' + name)
        literals.append({'role': name, 'va': hex(va), 'file_offset': hex(image.off(va)),
                         'bytes': expected.hex(), 'length': len(expected)})
    if exports:
        frame, = [s for s in image.sections if s['name'] == '.eh_frame']
        headers = re.findall(r'^([0-9a-f]+) .*FDE cie=([0-9a-f]+) pc=([0-9a-f]+)\.\.([0-9a-f]+)$',
                             (PACKET / 'fdes.readelf.txt').read_text(), re.MULTILINE)
        actual = sorted(tuple(int(x, 16) for x in row) for row in headers)
        expected = sorted((r['enclosing_fde']['fde'] - frame['address'],
                           r['enclosing_fde']['cie'] - frame['address'],
                           int(r['start'], 16), int(r['end'], 16)) for r in bodies)
        require(actual == expected, 'independent readelf FDE headers')
    return {'schema': 1, 'target_sha256': sha(data), 'coordinates': 'ELF VA; exclusive ends',
            'bodies': bodies, 'measured_bytes': sum(r['bytes'] for r in bodies),
            'obligations': len(obligations), 'relative_bindings': bindings,
            'literals': literals, 'dynamic_imports': imports,
            'incoming': incoming(image, fdes) if exports else None,
            'captured_code_executed_or_emulated': False}


def build(data):
    require(len(data) == 105896032 and sha(data) == DIGEST, 'wrong node115 SHA-256 or size')
    return observe(data)


def controls(data):
    image, offsets = Image(data), []
    relocs = image.relocs()
    for name, r in json.loads((PACKET / 'obligations.json').read_text()).items():
        offsets.append((image.off(int(r['end'], 16) - 1), 'instruction ' + name))
    offsets += [(relocs[s][2] + 16, 'relative ' + hex(s)) for s in SLOTS]
    offsets += [(image.off(a), 'literal ' + name) for name, (a, _) in LITERALS.items()]
    offsets += [(image.off(b[2]) + 12, 'FDE range ' + name) for name, b in BODIES.items()]
    for slot, (index, name) in IMPORTS.items():
        symbol = dynamic_symbol(image, relocs[slot][0])
        offsets += [(relocs[slot][2] + 8, 'import relocation kind ' + name),
                    (relocs[slot][2] + 12, 'import symbol index ' + name),
                    (int(symbol['symbol_file_offset'], 16), 'import symbol name offset ' + name),
                    (int(symbol['name_file_offset'], 16), 'import symbol text ' + name)]
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
    return {'whole_image_body_and_export_guards_bypassed': True, 'rejected': result, 'survived': []}


def encoded(value):
    return json.dumps(value, indent=2, sort_keys=True) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--controls', action='store_true')
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
    print(f"PASS: {len(result['bodies'])} complete FDEs / {result['measured_bytes']} bytes")
    if args.controls:
        print(f"PASS: {len(outputs['controls.json']['rejected'])} deep corruption controls")


if __name__ == '__main__':
    main()
