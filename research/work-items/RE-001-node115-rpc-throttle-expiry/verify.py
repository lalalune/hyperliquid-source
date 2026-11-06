#!/usr/bin/env python3
"""Authenticate node115 rpc-throttle-expiry; static reads only, no capture execution."""
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
BODIES = {'owner_context': (48273632, 48304448, 18555152, '3605ca6d67167d3359733cfee3b66ca0a8ca675731b909e97f331fb90d252dc6'), 'flat_prune': (38542992, 38545100, 17923296, '0bce6e5e7faeab547aef870f5587902cafc4c8e091021b3f406a403e0c39eeea'), 'tree_extract': (37338704, 37339738, 13656964, '273f5dda0e17f2305754327a78f4ce909d2ca148527f35eb40c4de3631eae1a0'), 'duration_context': (22993248, 22993793, 13355552, '5df08bc22d9dc4ca7ada201a6f3772b6c2df78611093e2527f575ae01485c42e')}
SLOTS = {105777216: 97460160, 105780112: 22579024, 105777768: 22045936, 105802848: 59612256, 105805064: 82616320, 105809664: 91995536, 105800880: 93709760, 105809672: 93700720, 105809680: 94839536, 105809688: 94838160, 105779224: 22482736, 105809696: 94838304, 105777952: 22415936, 105772192: 104193584, 105192328: 4448430, 105777944: 22065936, 105809704: 92173264, 105809712: 94834208, 105809720: 93701024, 105809728: 94837232, 105777552: 23238288, 105779072: 22308208, 105775136: 21773104, 105779080: 105905744, 105779128: 22309488, 105809736: 95597664, 105779664: 22415824, 105777896: 97105968, 105192496: 4519578, 105794744: 94955456, 105841088: 22449632, 104850040: 4514591, 105773552: 97025360, 105192472: 4519578, 105809744: 94836960, 105809624: 93729264, 105809752: 94836528, 105809760: 81787760, 105775608: 96164304, 105779000: 96163408, 105809768: 92178544, 105809776: 94839648, 105775112: 22335040, 105178176: 4461672, 105192232: 4448430, 105192256: 4448430, 105809640: 80995088, 105504016: 4501165, 105773104: 23596048, 105052912: 4457165, 105772912: 23595984, 105809784: 83116256, 105772224: 23596203, 105779056: 22993248, 105779064: 23243168, 105777824: 23236816, 105795864: 93726576, 105059776: 4518121, 105772848: 23596640, 105781392: 104791616}
SUPPORT = {}
LITERALS = {'source_0x43e0ae': (4448430, b'node/src/consensus/state.rs'), 'location_0x6451b88': (105192336, b'\x1b\x00\x00\x00\x00\x00\x00\x00&\x02\x00\x00\x11\x00\x00\x00'), 'source_0x44f69a': (4519578, b'node/src/consensus/mempool.rs'), 'location_0x6451c30': (105192504, b'\x1d\x00\x00\x00\x00\x00\x00\x00\x8d\x03\x00\x00\r\x00\x00\x00'), 'source_0x44e31f': (4514591, b'/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sync/once.rs'), 'location_0x63fe278': (104850048, b'L\x00\x00\x00\x00\x00\x00\x00\xdb\x00\x00\x00\x14\x00\x00\x00'), 'location_0x6451c18': (105192480, b'\x1d\x00\x00\x00\x00\x00\x00\x00f\x01\x00\x00 \x00\x00\x00'), 'source_0x441468': (4461672, b'node/src/consensus/signature_tracker.rs'), 'location_0x644e440': (105178184, b"'\x00\x00\x00\x00\x00\x00\x00:\x00\x00\x00\x14\x00\x00\x00"), 'location_0x6451b28': (105192240, b'\x1b\x00\x00\x00\x00\x00\x00\x00\x9d\x02\x00\x00\x19\x00\x00\x00'), 'location_0x6451b40': (105192264, b"\x1b\x00\x00\x00\x00\x00\x00\x00\xaa\x02\x00\x00'\x00\x00\x00"), 'source_0x44aead': (4501165, b'node/src/consensus/timer.rs'), 'location_0x649dd10': (105504024, b'\x1b\x00\x00\x00\x00\x00\x00\x00\x17\x00\x00\x00Z\x00\x00\x00'), 'source_0x4402cd': (4457165, b'base/src/l1_map/entry.rs'), 'location_0x642faf0': (105052920, b'\x18\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x11\x00\x00\x00'), 'source_0x44f0e9': (4518121, b'/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/alloc/src/collections/vec_deque/mod.rs'), 'location_0x64315c0': (105059784, b'^\x00\x00\x00\x00\x00\x00\x00\xcb\x03\x00\x00\t\x00\x00\x00'), 'thirty_seconds': (4558040, b'\x00\x00\x00\x00\x00\x00>@'), 'invalid_deadline_triple': (4618704, b'\xde\xd6\xff\x7f\x7fQ\x01\x00\xff\xc9\x9a;'), 'prune_diagnostic': (6386362, b'Pruned rpc request throttle'), 'literal_context_0x6170f9': (6385913, b'Not sending heartbeat because execution round is far behind qcstatusBlockHashadd'), 'literal_context_0x61721f': (6386207, b'handle_blocks_and_txsReceived partial BlocksAndTxs responseReceived large Blocks'), 'literal_context_0x617234': (6386228, b'Received partial BlocksAndTxs responseReceived large BlocksAndTxs response. Is t'), 'literal_context_0x61725a': (6386266, b'Received large BlocksAndTxs response. Is the node falling behind?CONFIGURATION E'), 'literal_context_0x617146': (6385990, b'add_rpc_txknownaddederrstore_block unknown tx hashescommittedblock hashestx hash'), 'literal_context_0x617155': (6386005, b'addederrstore_block unknown tx hashescommittedblock hashestx hashescommitted blo'), 'literal_context_0x61715a': (6386010, b'errstore_block unknown tx hashescommittedblock hashestx hashescommitted block si'), 'literal_context_0x617150': (6386000, b'knownaddederrstore_block unknown tx hashescommittedblock hashestx hashescommitte'), 'literal_context_0x6171fd': (6386173, b'Size statsevicting displaced blockhandle_blocks_and_txsReceived partial BlocksAn'), 'literal_context_0x6171ca': (6386122, b'committed_tx_hashesproposable_txsblocksrpc_requestsSize statsevicting displaced '), 'literal_context_0x6171dd': (6386141, b'proposable_txsblocksrpc_requestsSize statsevicting displaced blockhandle_blocks_'), 'literal_context_0x6171eb': (6386155, b'blocksrpc_requestsSize statsevicting displaced blockhandle_blocks_and_txsReceive'), 'literal_context_0x6171f1': (6386161, b'rpc_requestsSize statsevicting displaced blockhandle_blocks_and_txsReceived part'), 'literal_context_0x6172ba': (6386362, b'Pruned rpc request throttleMaking requestadd_txokRegisteredNotNewEquivocationn_b'), 'literal_context_0x5ee15f': (6218079, b'Out of bounds accessoccupied entry indexdescription() is deprecated; use Display')}
IMPORTS = {105772296: (7, 'memcpy'), 105773904: (12, 'memcmp')}
INCOMING = {'owner_context': [], 'flat_prune': [], 'tree_extract': [], 'duration_context': [105779056]}
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
            row['scope'] = 'Consensus RPC throttle pruning removes rows only when the supplied current triple is strictly later than a helper-derived deadline using a30.0-second duration argument. Both flat and tree forms use signed comparison for the first word and unsigned comparison for the remaining words, retain equality, and collect40-byte diagnostics only from expired rows with raw flag exactly1. Date helper internals, generic map repair, cadence scheduling and full consensus behavior remain outside the claim.'
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
