#!/usr/bin/env python3
"""Authenticate the bounded node115 startup line-count evidence; never run the ELF.

Uses the repository's MIT ELF, FDE, native-export and LSDA parsers.  This is a
packet-specific static verifier, not a recovered runtime or instruction engine.
"""
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
from fde_extents import fde_extents
from foundation_millis import decode_export
from node115_cli_command_factory import lsda_table

TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
WHITE = [*range(9, 14), 32, 0x85, 0xa0, 0x1680, *range(0x2000, 0x200b),
         0x2028, 0x2029, 0x202f, 0x205f, 0x3000]


def require(ok, message):
    if not ok:
        raise ValueError(message)


def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def span(blob, secs, address, size):
    require(isinstance(size, int) and size >= 0, 'invalid read size')
    found = [s for s in secs if s['type'] != 8 and s['address'] <= address
             and address + size <= s['address'] + s['size']]
    require(len(found) == 1, 'nonunique or absent file-backed VA')
    offset = found[0]['offset'] + address - found[0]['address']
    require(offset + size <= len(blob), 'truncated file-backed read')
    return bytes(blob[offset:offset + size])


def relocations(blob, secs):
    """Raw RELA writers and dynamic names; never apply runtime relocations."""
    sym = next(s for s in secs if s['name'] == '.dynsym')
    strings = next(s for s in secs if s['name'] == '.dynstr')
    names = blob[strings['offset']:strings['offset'] + strings['size']]
    result = {}
    for sec in secs:
        if sec['type'] != 4:
            continue
        require(sec['size'] % 24 == 0, 'RELA entry extent')
        for p in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', blob, p)
            symbol = info >> 32
            name = None
            if symbol:
                require(symbol * 24 + 24 <= sym['size'], 'dynamic symbol extent')
                n = struct.unpack_from('<I', blob, sym['offset'] + symbol * 24)[0]
                require(n < len(names), 'dynamic symbol string extent')
                stop = names.find(b'\0', n)
                require(stop >= n, 'unterminated dynamic name')
                name = bytes(names[n:stop]).decode('ascii')
            require(slot not in result, 'multiple RELA writers')
            result[slot] = {'slot': hex(slot), 'fileOffset': hex(p),
                            'info': hex(info), 'type': info & 0xffffffff,
                            'addend': hex(addend), 'symbol': name}
    return result


def contract(blob, spec):
    """Check selected semantic obligations independently of whole-body hashes.

    Displacements/immediates are read from actual instruction bytes.  This does
    not evaluate instructions, execute the target, or infer arbitrary CFGs.
    """
    secs = sections(blob)
    rels = relocations(blob, secs)
    for group, rows in spec['obligations'].items():
        for row in rows:
            raw = bytes.fromhex(row['raw'])
            require(span(blob, secs, int(row['va'], 16), len(raw)) == raw,
                    'semantic obligation: ' + group + ' at ' + row['va'])
    for row in spec['literals']:
        raw = span(blob, secs, int(row['va'], 16), row['size'])
        require(raw.hex() == row['raw'], 'literal/table: ' + row['label'])
    for row in spec['bindings']:
        actual = rels.get(int(row['slot'], 16))
        require(actual is not None and actual['type'] == 8
                and actual['addend'] == row['target'] and actual['symbol'] is None,
                'relative binding: ' + row['slot'])
    declarations = []
    for site, store, expected in [(0x1500e89, 0x1500e95, b'wc'),
                                   (0x1500e9e, 0x1500eaa, b'-l')]:
        code = span(blob, secs, site, 7)
        require(code[:3] == b'\x48\x8d\x05', 'command LEA shape')
        va = site + 7 + struct.unpack('<i', code[3:])[0]
        code = span(blob, secs, store, 9)
        require(code[:4] == b'\x48\xc7\x44\x24', 'command length-store shape')
        length = struct.unpack('<I', code[-4:])[0]
        require(length == len(expected) and span(blob, secs, va, length) == expected,
                'command declaration')
        declarations.append({'va': hex(va), 'length': length, 'hex': expected.hex()})
    references = []
    width_table = bytes([1] * 128 + [0] * 66 + [2] * 30 + [3] * 16 + [4] * 5 + [0] * 11)
    for site, opcode, address, expected in [
            (0x15b052f, b'\x48\x8d\x0d', 0x468cca, b' '),
            (0x1536743, b'\x48\x8d\x35', 0x466adc, b'/bin/sh'),
            (0x1536767, b'\x48\x8d\x35', 0x466ada, b'-c'),
            (0x168160b, b'\x4c\x8d\x15', 0x46ebe7, width_table),
            (0x595b750, b'\x8b\x05', 0x459e84, b'.lz4')]:
        size = len(opcode) + 4
        code = span(blob, secs, site, size)
        require(code[:len(opcode)] == opcode, 'data reference opcode')
        target = site + size + struct.unpack('<i', code[-4:])[0]
        require(target == address and span(blob, secs, target, len(expected)) == expected,
                'data reference: ' + hex(site))
        references.append({'site':hex(site), 'target':hex(target), 'bytes':len(expected),
                           'dataSha256':hashlib.sha256(expected).hexdigest()})
    # Derive the whitespace set from the target table and actual ASCII mask.
    mask = int.from_bytes(span(blob, secs, 0x1500f46, 10)[2:], 'little')
    table_va = int(rels[0x64dfc30]['addend'], 16)
    table = span(blob, secs, table_va, 256)
    white = sorted({*[i for i in range(64) if mask >> i & 1],
                    *[i for i, x in enumerate(table) if x & 1],
                    *[0x2000 + i for i, x in enumerate(table) if x & 2],
                    0x1680, 0x3000})
    require(white == WHITE, 'derived whitespace set')
    call = span(blob, secs, 0x595bb9c, 6)
    require(call[:2] == b'\xff\x15', 'startup caller call shape')
    slot = 0x595bba2 + struct.unpack('<i', call[2:])[0]
    require(slot == 0x64e0958 and int(rels[slot]['addend'], 16) == 0x1500e50,
            'startup caller edge')
    stub = span(blob, secs, 0x63f0a50, 6)
    require(stub[:2] == b'\xff\x25', 'unwind PLT shape')
    slot = 0x63f0a56 + struct.unpack('<i', stub[2:])[0]
    require(rels[slot]['symbol'] == '_Unwind_Resume', 'unwind import')
    return {'commandDeclarations': declarations, 'dataReferences':references, 'separatorHex': '20',
            'whitespaceCodepoints': [hex(x) for x in white],
            'caller': {'site': '0x595bb9c', 'slot': '0x64e0958', 'target': '0x1500e50'},
            'unwind': {'stub': '0x63f0a50', 'writer': rels[slot]},
            'limits': 'Static obligations, not a runtime or behavioral oracle.'}


def frame_bytes(blob, secs, va):
    length = struct.unpack('<I', span(blob, secs, va, 4))[0]
    require(0 < length < 65536, 'bounded DWARF32 record')
    return {'va': hex(va), 'raw': span(blob, secs, va, length + 4).hex()}


def checked_frame(by_range, scope):
    found = by_range.get((int(scope['start'], 16), int(scope['end'], 16)), [])
    require(len(found) == 1, 'complete FDE extent or multiplicity')
    require(found[0] == scope['fde'], 'FDE record identity')
    return found[0]


def checked_native_frame(blob, secs, frame, headers):
    start, end = frame['start'], frame['end']
    lines = [line for line in headers.splitlines()
             if 'pc=' + format(start, '016x') + '..' + format(end, '016x') in line]
    require(len(lines) == 1, 'independent native FDE header')
    match = re.fullmatch(r'([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+) FDE cie=([0-9a-f]+) pc=([0-9a-f]+)\.\.([0-9a-f]+)', lines[0])
    require(match is not None, 'native FDE header syntax')
    offset, length, pointer, cie, a, b = [int(x, 16) for x in match.groups()]
    section = next(s for s in secs if s['name'] == '.eh_frame')
    require(offset == frame['fde'] - section['address']
            and length == struct.unpack('<I', span(blob, secs, frame['fde'], 4))[0]
            and pointer == frame['fde'] + 4 - frame['cie']
            and cie == frame['cie'] - section['address'] and (a, b) == (start, end),
            'native FDE offset/length/CIE identity')


def collect(blob, packet=PACKET):
    # Identity precedes ELF parsing, output creation and every evidence read.
    require(len(blob) == SIZE and hashlib.sha256(blob).hexdigest() == TARGET,
            'node115 identity mismatch')
    spec = load(packet / 'spec.json')
    require(spec['target'] == TARGET, 'packet target')
    secs = sections(blob)
    _, frames, _ = fde_extents(blob)
    by_range = {}
    for f in frames:
        by_range.setdefault((f['start'], f['end']), []).append(f)
    rels = relocations(blob, secs)
    headers = (packet / 'fdes.readelf.txt').read_text(encoding='utf-8')
    bodies = []
    for scope in spec['scopes']:
        start, end = int(scope['start'], 16), int(scope['end'], 16)
        require(0 < end - start <= 32768, 'bounded body extent')
        f = checked_frame(by_range, scope)
        body = span(blob, secs, start, end - start)
        require(hashlib.sha256(body).hexdigest() == scope['bodySha256'], 'whole body hash')
        text = (packet / scope['export']).read_text(encoding='utf-8')
        rows = decode_export(text, start, end, body)
        require(len(rows) == scope['instructions'], 'instruction denominator')
        checked_native_frame(blob, secs, f, headers)
        calls = []
        for pc, code in rows.items():
            if len(code) == 5 and code[0] in (0xe8, 0xe9):
                target = pc + 5 + struct.unpack('<i', code[1:])[0]
                if start <= target < end and code[0] == 0xe9:
                    continue
                calls.append({'site': hex(pc), 'opcode': code[:1].hex(), 'target': hex(target)})
            elif len(code) == 6 and code[:2] in (b'\xff\x15', b'\xff\x25'):
                slot = pc + 6 + struct.unpack('<i', code[2:])[0]
                calls.append({'site': hex(pc), 'opcode': code[:2].hex(),
                              'slot': hex(slot), 'writer': rels.get(slot)})
        lsda = lsda_table(blob, secs, {'start': hex(start), 'end': hex(end),
                                    'lsda': hex(f['lsda']) if f['lsda'] is not None else None})
        if lsda:
            lsda['raw'] = span(blob, secs, int(lsda['va'], 16), lsda['headerAndCallSiteBytes']).hex()
        bodies.append({'start': hex(start), 'end': hex(end), 'role': scope['role'],
                       'contextReused': scope['contextReused'], 'bytes': len(body),
                       'sha256': hashlib.sha256(body).hexdigest(), 'instructions': len(rows),
                       'fde': f, 'rawFDE': frame_bytes(blob, secs, f['fde']),
                       'rawCIE': frame_bytes(blob, secs, f['cie']), 'lsda': lsda,
                       'callsAndTailJumps': calls,
                       'limits': 'E8/E9/FF15/FF25 edges only; register-indirect targets not resolved.'})
    facts = contract(blob, spec)
    new = [x for x in bodies if not x['contextReused']]
    return {'schema': 1, 'target': TARGET, 'sourceBase': spec['sourceBase'],
            'coordinates': 'ELF virtual addresses before load bias; no operand normalization',
            'bodies': bodies, 'contract': facts,
            'metrics': {'newStaticFDEs': len(new), 'newStaticBytes': sum(x['bytes'] for x in new),
                        'reusedContextFDEs': len(bodies) - len(new),
                        'compiledCodeComparisons': 0, 'gateChanges': 0},
            'capturedExecution': False, 'emulation': False,
            'limits': 'No source ABI, allocator/process/error-object closure or whole-node equivalence.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    parser.add_argument('--write-records', action='store_true', help='write deterministic packet records after authentication')
    parser.add_argument('--output', type=Path, help='optional verification summary JSON')
    args = parser.parse_args(argv)
    result = collect(args.target.read_bytes())
    if args.write_records:
        (PACKET / 'records.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    else:
        require(result == load(PACKET / 'records.json'), 'static snapshot differs')
    summary = {'status': 'passed', 'target': TARGET, **result['metrics'],
               'capturedExecution': False, 'emulation': False}
    if args.output:
        args.output.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    main()
