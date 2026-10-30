#!/usr/bin/env python3
"""RE-001: node94 hourly-liner aggregate output ABI, no target execution."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents

TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
RANGES = [(0x14019b0, 0x1401d36), (0x14016d0, 0x1401853)]
CONTROLS = {
    0x14019c1: '4889f34889bc24b8000000',  # RSI object, save RDI output
    0x14019e1: '3d00100e000f8320020000',
    0x14019ec: '3d905f01000f833c020000',
    0x1401a00: '41bfc5b3a2914c0faff849c1ef2b',
    0x1401a0e: '89ab98000000c683a8000000014488bba9000000',
    0x1401ae2: '4c8bb424b8000000',  # recover output as R14
    0x1401b35: '4c8d7b4848b80000000000000080483943487408',
    0x1401b51: '0f28442450410f114740',
    0x1401b6f: '410f115f30410f115720410f114f10410f1107',
    0x1401bce: 'bab00000004c89f74889de',  # memcpy(output, object,176)
    0x1401bf7: '4c89f0',  # aggregate return pointer
    0x1401c82: '0f28442450410f114740',  # install staged member during cleanup
    0x1401ca0: '410f115f30410f115720410f114f10410f1107',
    0x1401cef: '48b80000000000000080483943487409',
    0x1401781: '488dbc24c0000000488d742410',  # caller output/input
    0x14017ae: '488db424c0000000bab0000000',  # consume returned176B
}
RIP = {
    (0x14019d4, 'ff15'): 0x576e8a0,
    (0x1401a64, '488d35'): 0x1e938e,
    (0x1401acb, '488d35'): 0x1e9393,
    (0x1401af4, 'ff15'): 0x576eac0,
    (0x1401b4c, 'e8'): 0x1406b80,
    (0x1401bd9, 'ff15'): 0x576dfe0,
    (0x1401d03, 'e8'): 0x1406b80,
    (0x140178e, 'ff15'): 0x576ef78,
    (0x14017bb, 'ff15'): 0x576dfe0,
}


def locate(data, va, size, secs=None):
    secs = secs if secs is not None else sections(data)
    found = [s['offset'] + va - s['address'] for s in secs if s['type'] != 8
             and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('expected unique file-backed mapping')
    offset = found[0]
    return offset, bytes(data[offset:offset + size])


def analyze(data):
    secs = sections(data)
    _, frames, _ = fde_extents(data)
    bounds = {(f['start'], f['end']) for f in frames}
    if not set(RANGES) <= bounds:
        raise ValueError('selected hourly/caller FDE changed')
    for va, value in CONTROLS.items():
        if locate(data, va, len(bytes.fromhex(value)), secs)[1] != bytes.fromhex(value):
            raise ValueError(f'ABI/control bytes changed at {va:#x}')
    for (va, prefix), expected in RIP.items():
        prefix = bytes.fromhex(prefix)
        raw = locate(data, va, len(prefix) + 4, secs)[1]
        if raw[:len(prefix)] != prefix or va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0] != expected:
            raise ValueError('call or descriptor target changed')
    literals = {0x1e938e: b'\xc0\x01/\xc0\0', 0x1e9393: b'\xc0\x08/hourly/\xc0\x01/\xc0\0'}
    for va, value in literals.items():
        if locate(data, va, len(value), secs)[1] != value:
            raise ValueError('daily/hourly descriptor changed')
    relative = {}
    memcpy = None
    named = {s['name']: s for s in secs}
    for section in secs:
        if section['type'] != 4:
            continue
        for pos in range(section['offset'], section['offset'] + section['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, pos)
            if info & 0xffffffff == 8:
                relative[slot] = addend
            if slot == 0x576dfe0:
                if info & 0xffffffff != 6 or not info >> 32:
                    raise ValueError('memcpy must be the actual dynamic symbol binding')
                sym = named['.dynsym']['offset'] + (info >> 32) * 24
                name = named['.dynstr']['offset'] + struct.unpack_from('<I', data, sym)[0]
                if data[name:data.index(b'\0', name)] != b'memcpy':
                    raise ValueError('copy slot does not name memcpy')
                memcpy = {'slot_va': hex(slot), 'relocation_file_offset': hex(pos),
                          'info': hex(info), 'symbol': 'memcpy'}
    expected = {0x576ef78: 0x14019b0, 0x576e8a0: 0x151cba0, 0x576eac0: 0x13d1720}
    if memcpy is None or any(relative.get(slot) != target for slot, target in expected.items()):
        raise ValueError('entry/clock/member constructor relocation changed')
    records = []
    for start, end in RANGES:
        off, raw = locate(data, start, end - start, secs)
        records.append({'start_va': hex(start), 'end_va': hex(end), 'file_offset': hex(off),
                        'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'body_hex': raw.hex()})
    return {'target_sha256': SHA256, 'ranges': records, 'aggregate_copy_bytes': 176,
            'object_field_offsets': {'packed_date_store': '0x98', 'mode_byte_store': '0xa8',
                                     'hour_byte_store': '0xa9', 'replaced_member': '0x48'},
            'member_copy_bytes': 80, 'member_empty_sentinel': '0x8000000000000000',
            'memcpy': memcpy, 'relative_bindings': {hex(slot): hex(value) for slot, value in expected.items()},
            'controls': {hex(va): value for va, value in CONTROLS.items()},
            'rip_targets': [{'instruction_va': hex(va), 'prefix': prefix, 'target_va': hex(target)} for (va, prefix), target in RIP.items()],
            'descriptors': [{'va': hex(va), 'hex': value.hex()} for va, value in literals.items()],
            'captured_binary_executed': False,
            'limits': 'One FDE candidate plus one caller. Function name, precise Rust signature/ownership, source type layout, file operations, helper closure, exception reachability and runtime equivalence remain unproved.'}


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != 91774280 or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('expected pinned node94 capture')
    report = analyze(data)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / 'node94.elf'
        snapshot.write_bytes(data)
        frames = subprocess.check_output(['readelf', '-wf', str(snapshot)], text=True)
        lines = [line for line in frames.splitlines() if any(f'pc={start:016x}..{end:016x}' in line for start, end in RANGES)]
        if len(lines) != 2:
            raise ValueError('readelf did not confirm both FDEs')
        (output / 'frames.txt').write_text('\n'.join(lines) + '\n')
        for start, end in RANGES:
            asm = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                                           f'--start-address={start:#x}', f'--stop-address={end:#x}', str(snapshot)], text=True)
            starts = {int(m.group(1), 16) for m in re.finditer(r'^\s*([0-9a-f]+):\s', asm, re.M)}
            wanted = set(CONTROLS) | {va for va, _ in RIP}
            if not {va for va in wanted if start <= va < end} <= starts:
                raise ValueError('ABI controls must begin at decoded instruction boundaries')
            (output / f'{start:x}.objdump.txt').write_text(asm.replace(str(snapshot), '<authenticated-node94>'))
    (output / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path, default=ROOT / 'work/hourly-rotation-94')
    args = parser.parse_args()
    report = generate(args.binary, args.output)
    print(json.dumps({'sha256': SHA256, 'selected_extents': len(report['ranges']), 'executed': False}))
