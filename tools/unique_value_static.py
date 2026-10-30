#!/usr/bin/env python3
"""RE-001: node94 key-filtered 32-byte uniqueness specialization, static evidence only."""
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
RANGES = [(0x33690c0, 0x33694fc), (0x336a4e0, 0x336a890)]
CONTROLS = {
    0x33690cf: '4c8b463066b897004d85c00f84bc030000',
    0x33690e4: '450fb7981a020000',
    0x3369115: '4b3b4cc810400f97c54080dd00',
    0x3369143: '4883ee010f824f0300004f8b84c820020000',
    0x3369157: '4f8b5c10384d85db0f84fd020000',
    0x3369165: '4b8b4410484885c00f84ef020000',
    0x3369182: '4531c04531c9',
    0x3369367: '4d89f349c1e306',
    0x336936e: 'f3420f6f441b18f30f6f0a660f74c8',
    0x336937d: '66420f6e441b28660f6e5210660f74d0660fdbd166440fd7da4181fbffff00000f85edfdffff',
    0x33693a3: '49c1e6054e8d1c334981c3c0020000',
    0x33693dc: '41f6c0017450',
    0x33693fc: 'f30f6f442441f30f6f4c2451f30f6f542461660f74d0',
    0x3369412: 'f30f6f442471660f74c1660fdbc266440fd7c04181f8ffff00000f8580000000',
    0x3369432: '410f1003410f104b100f294c24100f29042441b001e957fdffff',
    0x3369462: '66b82a00eb34',
    0x336947c: '66b82a0041f6c0017416',
    0x3369490: '0f114f120f11470266b886016689074889f8',
    0x33694f8: '0f0b0f0b',
    0x336a51c: '4889e74c89c64889ca4889c1',
    0x336a52e: '0fb704240f104424020f104c2412',
    0x336a54c: '3d860100000f856d020000',
}
RIP = {(0x33694be, '488d05'): 0x33de3e0,
       (0x33694d4, '488d3d'): 0x1ed4ee,
       (0x33694db, '488d15'): 0x56e9e38,
       (0x33694e5, 'ff15'): 0x576e098,
       (0x33694eb, '488d3d'): 0x56e9fe8,
       (0x33694f2, 'ff15'): 0x576e470,
       (0x336a528, 'ff15'): 0x5773148}


def read(data, va, size, secs=None):
    secs = sections(data) if secs is None else secs
    found = [s['offset'] + va - s['address'] for s in secs if s['type'] != 8
             and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('expected unique file-backed mapping')
    off = found[0]
    return off, bytes(data[off:off + size])


def descriptor_parts(raw):
    """Only the short-literal/default-placeholder forms actually in this template."""
    parts, pos = [], 0
    while pos < len(raw):
        tag = raw[pos]
        pos += 1
        if tag == 0:
            if pos != len(raw):
                raise ValueError('trailing descriptor bytes')
            return parts
        if tag == 0xc0:
            parts.append({'placeholder': 'default'})
        elif 0 < tag < 128 and pos + tag <= len(raw):
            parts.append({'literal': raw[pos:pos + tag].decode('utf-8')})
            pos += tag
        else:
            raise ValueError('unsupported or truncated scoped descriptor')
    raise ValueError('missing descriptor end')


def analyze(data):
    secs = sections(data)
    _, frames, _ = fde_extents(data)
    if not set(RANGES) <= {(f['start'], f['end']) for f in frames}:
        raise ValueError('selected FDE changed')
    for va, value in CONTROLS.items():
        if read(data, va, len(bytes.fromhex(value)), secs)[1] != bytes.fromhex(value):
            raise ValueError(f'uniqueness instruction changed at {va:#x}')
    for (va, prefix), expected in RIP.items():
        prefix = bytes.fromhex(prefix)
        raw = read(data, va, len(prefix) + 4, secs)[1]
        if not raw.startswith(prefix) or va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0] != expected:
            raise ValueError('panic/caller target changed')
    prefix = b'ChamIterator::unique_elem: not unique elems: ['
    descriptor = bytes([len(prefix)]) + prefix + b'\xc0\x02, \xc0\x06, ...]\0'
    if read(data, 0x1ed4ee, len(descriptor), secs)[1] != descriptor:
        raise ValueError('compact diagnostic descriptor changed')
    relative = {}
    for s in secs:
        if s['type'] == 4:
            for off in range(s['offset'], s['offset'] + s['size'], 24):
                slot, info, addend = struct.unpack_from('<QQq', data, off)
                if info & 0xffffffff == 8:
                    relative[slot] = addend
    expected = {0x5773148: 0x33690c0, 0x576e098: 0x157b810,
                0x576e470: 0x157a9f0, 0x56e9e38: 0x1ebfb7, 0x56e9fe8: 0x1f75d4}
    if any(relative.get(slot) != value for slot, value in expected.items()):
        raise ValueError('source/helper relocation changed')
    path = b'/home/ubuntu/hl/code_Mainnet/base/src/iter.rs'
    if read(data, 0x1ebfb7, len(path), secs)[1] != path:
        raise ValueError('source path changed')
    if read(data, 0x56e9e40, 16, secs)[1] != struct.pack('<QII', len(path), 132, 21):
        raise ValueError('source Location changed')
    rows = []
    for start, end in RANGES:
        off, raw = read(data, start, end - start, secs)
        rows.append({'start_va': hex(start), 'end_va': hex(end), 'file_offset': hex(off),
                     'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'body_hex': raw.hex()})
    return {'target_sha256': SHA256, 'ranges': rows, 'filter_bytes': 20, 'value_bytes': 32,
            'return_tags': {'missing_outer_entry': '0x97', 'empty_filtered_result': '0x2a', 'unique_payload': '0x186'},
            'payload_output_offsets': ['0x2', '0x12'],
            'diagnostic': {'va': '0x1ed4ee', 'descriptor_hex': descriptor.hex(),
                           'first_byte': 46, 'following_prefix_ascii': prefix.decode(),
                           'scoped_parts': descriptor_parts(descriptor),
                           'source_contract': 'rust-lang/rust@e408947bfd200af42db322daf0fadfe7e26d3bd1/library/core/src/fmt/mod.rs:612-710',
                           'limit': 'Upstream stamped format contract treats 0x2e as literal length, not punctuation; complete target formatter output is not executed or proved.'},
            'source': {'slot_va': '0x56e9e38', 'file': path.decode(), 'line': 132, 'column': 21},
            'relative_bindings': {hex(slot): hex(value) for slot, value in expected.items()},
            'controls': {hex(va): value for va, value in CONTROLS.items()},
            'rip_targets': [{'instruction_va': hex(va), 'prefix_hex': prefix, 'target_va': hex(value)} for (va, prefix), value in RIP.items()],
            'captured_binary_executed': False,
            'limits': 'One specialized helper and one caller. Concrete Rust types, validity/reachability of all tree states, complete formatter semantics, transitive helper closure and runtime equivalence remain unproved.'}


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != 91774280 or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('expected pinned node94')
    result = analyze(data)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / 'node94.elf'
        snapshot.write_bytes(data)
        frames = subprocess.check_output(['readelf', '-wf', str(snapshot)], text=True)
        selected = [line for line in frames.splitlines() if any(f'pc={a:016x}..{b:016x}' in line for a, b in RANGES)]
        if len(selected) != 2:
            raise ValueError('readelf FDE confirmation failed')
        (output / 'frames.txt').write_text('\n'.join(selected) + '\n')
        for start, end in RANGES:
            asm = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                                           f'--start-address={start:#x}', f'--stop-address={end:#x}', str(snapshot)], text=True)
            boundaries = {int(m.group(1), 16) for m in re.finditer(r'^\s*([0-9a-f]+):\s', asm, re.M)}
            if not {va for va in set(CONTROLS) | {va for va, _ in RIP} if start <= va < end} <= boundaries:
                raise ValueError('controls must be decoded instruction starts')
            (output / f'{start:x}.objdump.txt').write_text(asm.replace(str(snapshot), '<authenticated-node94>'))
    (output / 'records.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path, default=ROOT / 'work/unique-value-94')
    args = parser.parse_args()
    result = generate(args.binary, args.output)
    print(json.dumps({'sha256': SHA256, 'ranges': len(result['ranges']), 'executed': False}))
