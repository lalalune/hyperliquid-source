#!/usr/bin/env python3
"""Collect static node #94 singleton-like registry lifecycle evidence; never execute it."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from artifacts import ROOT, check
from elf_index import sections

RANGES = {'alternate-like': (0x14396C0, 0x1439A3F), 'strict-like': (0x1439A40, 0x1439BF9),
          'cleanup-like': (0x1445950, 0x1445AAB), 'table-add-path': (0x14CC320, 0x14CC597),
          'table-remove-path': (0x14CC7C0, 0x14CC997), 'unlock-path': (0x143F6D0, 0x143F6E3)}
SLOTS = {0x576EFA0: 0x14396C0, 0x576F4E0: 0x1439A40, 0x576F008: 0x1445950,
         0x576E040: 0x1344760, 0x576E9D8: 0x13CC380,
         0x576EF30: 0x4E0F640, 0x576EF38: 0x4E0F2C0,
         0x566A168: 0x1F8990, 0x566A180: 0x1F8990, 0x566A198: 0x1F8990}


def read_va(data, va, size):
    matches = [s for s in sections(data) if s['type'] != 8 and
               s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'Expected one file-backed mapping at {va:#x}')
    offset = matches[0]['offset'] + va - matches[0]['address']
    return offset, data[offset:offset + size]


def controls(data):
    expected = {
        0x1439A64: 'f00fb00dace83404',  # shared byte CAS
        0x1439AB4: '488d35126bdbfe',  # shared descriptor
        0x1439ACB: '488d3d4ee83404',  # same table address
        0x1439AD7: 'e84428090084c0753a',  # add-path result -> duplicate failure
        0x1439B1A: '488d3df7e73404e8aa5b0000',  # release before strict panic
        0x1439B92: '4c897b184c8973204c892348896b084c896310c6432800',  # stored pair/owned triple/flag
        0x14396E9: 'f00fb00d27ec3404',
        0x1439744: '488d35826edbfe',
        0x143975B: '488d3dbeeb3404',
        0x1439780: '84c90f84fe000000',  # first result zero bypasses fallback
        0x1439790: 'ff1542523304',  # opaque word provider
        0x14397BB: '488d3520eddafe',  # alternate descriptor
        0x143981A: '488d35ac6ddbfe',  # same key descriptor, second attempt
        0x1439831: '488d3de8ea3404',
        0x143983D: 'e8de2a0900',
        0x1439853: '84c90f8510010000',  # second failure, no rerandomization loop
        0x143987D: 'c6432801',
        0x1439941: 'c6432800',
        0x1445955: '0f1047080f104f180f114c24400f11442450',  # stored pairs reordered for descriptor
        0x144598C: '488d353aacdafe',
        0x14459A7: 'f00fb00d69293404',
        0x14459B1: '488d3d68293404',
        0x14459C0: 'e8fb6d0800',
        0x14459D6: '84c97446',  # zero remove-path result -> failure
        0x14CC402: '40b501',  # existing-key path returns 1
        0x14CC522: '48ff461031ed',  # add-path increments table count, returns 0
        0x14CC8D7: '48ff4b10',  # remove-path decrements same count offset
        0x14CC93A: 'b001eb0231c0',  # found/nonfound result values
        0x143F6D0: '31c9b001f00fb00f7501c3',
    }
    for va, value in expected.items():
        if read_va(data, va, len(bytes.fromhex(value)))[1] != bytes.fromhex(value):
            raise ValueError(f'Lifecycle instruction control changed at {va:#x}')
    literals = {0x1F05CD: bytes.fromhex('c0023a3ac000'), 0x1E84E2: bytes.fromhex('c0015fc000'),
                0x1E6381: b'\x1bSingleton already created: \xc0\x00',
                0x2019CD: b'\x19Singleton never created: \xc0\x00',
                0x1DE8E0: b'\x20SingletonSet could not register \xc0\x02::\xc0\x00',
                0x1F8990: b'/home/ubuntu/hl/code_Mainnet/base/src/singleton_set.rs'}
    for va, literal in literals.items():
        if read_va(data, va, len(literal))[1] != literal:
            raise ValueError(f'Lifecycle descriptor/path control changed at {va:#x}')
    return ([{'va': hex(va), 'bytes': value} for va, value in expected.items()],
            [{'va': hex(va), 'file_offset': hex(read_va(data, va, len(value))[0]),
              'bytes': value.hex()} for va, value in literals.items()])


def relocations(data):
    found = {}
    for section in sections(data):
        if section['type'] != 4:
            continue
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, offset)
            if slot in SLOTS:
                if info != 8 or addend != SLOTS[slot]:
                    raise ValueError(f'Lifecycle RELA target changed at {slot:#x}')
                found[slot] = {'slot_va': hex(slot), 'type': 'R_X86_64_RELATIVE', 'addend': hex(addend)}
    if set(found) != set(SLOTS):
        raise ValueError('Missing lifecycle RELA binding')
    return [found[slot] for slot in sorted(found)]


def decoded_reference(line):
    match = re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(?:call|jmp)\s', line)
    if not match:
        return None
    va, body = int(match[1], 16), bytes.fromhex(match[2])
    if len(body) == 6 and body[:2] in (b'\xff\x15', b'\xff\x25'):
        return va, 'GOT', va + 6 + struct.unpack_from('<i', body, 2)[0]
    if len(body) == 5 and body[0] in (0xe8, 0xe9):
        return va, 'direct', va + 5 + struct.unpack_from('<i', body, 1)[0]
    return None


def generate(binary, output):
    identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                    if i['path'] == 'artifacts/node/94/hl-node')
    check(binary, identity)
    data = binary.read_bytes()
    instructions, descriptors = controls(data)
    rela = relocations(data)
    frames = subprocess.check_output(['readelf', '-wf', str(binary)], text=True)
    fdes = [(int(a, 16), int(b, 16)) for a, b in
            re.findall(r'FDE[^\n]*pc=([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)', frames)]
    for pair in RANGES.values():
        if fdes.count(pair) != 1:
            raise ValueError(f'Expected one decoded FDE for {pair}')
    inbound, outgoing = [], []
    primary = list(RANGES.values())[:3]
    with subprocess.Popen(['objdump', '-d', '-j', '.text', str(binary)],
                          stdout=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            ref = decoded_reference(line)
            if not ref:
                continue
            site, kind, target = ref
            row = {'site_va': hex(site), 'kind': kind, 'target_va': hex(target)}
            if (kind == 'GOT' and target in {0x576EFA0, 0x576F4E0, 0x576F008}) or (
                    kind == 'direct' and target in {a for a, _ in primary}):
                inbound.append(row)
            if any(begin <= site < end for begin, end in primary):
                outgoing.append(row)
        if process.wait() != 0:
            raise ValueError('Complete .text disassembly failed')
    output.mkdir(parents=True, exist_ok=True)
    ranges = {}
    for name, (begin, end) in RANGES.items():
        offset, body = read_va(data, begin, end - begin)
        ranges[name] = {'start_va': hex(begin), 'end_va': hex(end), 'file_offset': hex(offset),
                        'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
        text = subprocess.check_output(['objdump', '-d', f'--start-address={begin:#x}',
                                        f'--stop-address={end:#x}', str(binary)], text=True)
        (output / f'{name}.objdump.txt').write_text(text.replace(str(binary), '<authenticated-node94>'))
    (output / 'frames.txt').write_text('\n'.join(line for line in frames.splitlines()
        if 'FDE' in line and any(f'pc={a:016x}..{b:016x}' in line for a, b in RANGES.values())) + '\n')
    rela_text = subprocess.check_output(['readelf', '-rW', str(binary)], text=True)
    rela_rows = [line for line in rela_text.splitlines() if re.match(r'^[0-9a-f]+\s', line)
                 and int(line.split()[0], 16) in {*SLOTS, 0x576E488}]
    (output / 'relocations.txt').write_text('\n'.join(rela_rows) + '\n')
    records = {'target_sha256': identity['sha256'], 'target_bytes': len(data), 'ranges': ranges,
               'decoded_fde_count': len(fdes), 'instruction_controls': instructions,
               'descriptors_and_path': descriptors, 'relocations': rela,
               'decoded_inbound_references': inbound, 'decoded_primary_outgoing_references': outgoing,
               'shared_storage_va': {'atomic_byte': '0x5788318', 'table': '0x5788320'},
               'captured_binary_executed': False,
               'limits': 'Six bounded unwind regions; role names inferred. Format engine, word source, tree primitives, allocation, scheduling, automatic destruction and full concurrency/API semantics not closed.'}
    (output / 'records.json').write_text(json.dumps(records, indent=2) + '\n')
    return records


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--output', type=Path, default=ROOT / 'work/singleton-lifecycle-94')
    args = parser.parse_args()
    print(json.dumps(generate(args.binary.resolve(), args.output), indent=2))
