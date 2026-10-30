#!/usr/bin/env python3
"""RE-001: three node94 funding-labelled bucket-advance fragments, static only."""
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
# start, interval field, previous-bucket field, label data, outgoing call
PROFILES = [(0x2702420, 0x37d0, 0x37d8, 0x3efa58, 0x222af40),
            (0x4ceec70, 0x37d0, 0x37d8, 0x714e59, 0x4713110),
            (0x4ceee00, 0x4250, 0x4258, 0x714e59, 0x4715760)]
SIZE = 387
CONTROLS = {0xbb: '31c04885c9480f4fc1',
            0xcb: '4889c24809ca48c1ea200f848f00000031d248f7f1',
            0xe7: '4839c87607', 0xf3: '4839c8',
            0x102: '48c744244814000000', 0x112: '0f11442450',
            0x117: '0f97442460', 0x165: '4883c468c3',
            0x16a: '31d2f7f1', 0x175: '4839c80f876effffffe970ffffff'}


def mapping(data, va, size, secs=None):
    secs = secs if secs is not None else sections(data)
    found = [s['offset'] + va - s['address'] for s in secs if s['type'] != 8
             and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('expected one file-backed mapping')
    offset = found[0]
    return offset, bytes(data[offset:offset + size])


def fragment(dividend, divisor, previous):
    """Architectural fragment model, not execution of the capture or calendar conversion."""
    if not 0 <= dividend < 1 << 63 or not 0 < divisor < 1 << 64 or not 0 <= previous < 1 << 64:
        raise ValueError('fragment requires post-clamp dividend and nonzero unsigned divisor')
    width = 32 if (dividend | divisor) >> 32 == 0 else 64
    bucket = dividend // divisor
    acquired = bucket > previous
    return {'division_width': width, 'bucket': bucket, 'acquired': acquired,
            'stored_bucket': bucket if acquired else previous}


def analyze(data):
    secs = sections(data)
    _, frames, _ = fde_extents(data)
    actual = {(f['start'], f['end']) for f in frames}
    rows = []
    for start, interval, previous, label, target in PROFILES:
        if (start, start + SIZE) not in actual:
            raise ValueError('funding wrapper FDE changed')
        offset, raw = mapping(data, start, SIZE, secs)
        def expect(at, value):
            if raw[at:at + len(value)] != value:
                raise ValueError(f'fragment instruction changed at {start + at:#x}')
        for at, value in CONTROLS.items():
            expect(at, bytes.fromhex(value))
        for at, prefix, field in [(0xc4, b'\x48\x8b\x8f', interval),
                                  (0xe0, b'\x48\x8b\x8f', previous),
                                  (0xec, b'\x48\x89\x87', previous),
                                  (0x16e, b'\x48\x8b\x8f', previous)]:
            expect(at, prefix + struct.pack('<I', field))
        targets = []
        for at, prefix, wanted in [(0xf6, b'\x48\x8d\x05', label),
                                   (0x10b, b'\x0f\x28\x05', 0x205e70),
                                   (0x160, b'\xe8', target)]:
            expect(at, prefix)
            observed = start + at + len(prefix) + 4 + struct.unpack_from('<i', raw, at + len(prefix))[0]
            if observed != wanted:
                raise ValueError('label, constant or outgoing call changed')
            targets.append({'instruction_va': hex(start + at), 'target_va': hex(observed)})
        label_offset, text = mapping(data, label, 20, secs)
        if text != b'update_funding_rates':
            raise ValueError('work label changed')
        rows.append({'start_va': hex(start), 'end_va': hex(start + SIZE), 'file_offset': hex(offset),
                     'bytes': SIZE, 'sha256': hashlib.sha256(raw).hexdigest(), 'body_hex': raw.hex(),
                     'interval_field_offset': hex(interval), 'previous_bucket_field_offset': hex(previous),
                     'label': {'va': hex(label), 'file_offset': hex(label_offset), 'text': text.decode()},
                     'targets': targets, 'calendar_prefix_sha256': hashlib.sha256(raw[:0xbb]).hexdigest()})
    constant_offset, constant = mapping(data, 0x205e70, 16, secs)
    if constant != struct.pack('<dd', 0.01, 0.05):
        raise ValueError('shared 16-byte constant changed')
    return {'target_sha256': SHA256, 'ranges': rows,
            'controls_relative_to_each_start': {hex(at): value for at, value in CONTROLS.items()},
            'stack_constant': {'va': '0x205e70', 'file_offset': hex(constant_offset), 'hex': constant.hex(),
                               'f64_interpretation': [0.01, 0.05]},
            'captured_binary_executed': False,
            'limits': 'Three FDE-described wrappers, not a global census. Calendar input validity, zero-divisor reachability, source type names, downstream work and complete behavior remain unproved. The fragment model is not target execution.'}


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
        chosen = [line for line in frames.splitlines() if any(
            f'pc={start:016x}..{start + SIZE:016x}' in line for start, *_ in PROFILES)]
        if len(chosen) != 3:
            raise ValueError('independent readelf range check failed')
        (output / 'frames.txt').write_text('\n'.join(chosen) + '\n')
        for start, *_ in PROFILES:
            text = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                                            f'--start-address={start:#x}', f'--stop-address={start + SIZE:#x}', str(snapshot)], text=True)
            addresses = {int(m.group(1), 16) for m in re.finditer(r'^\s*([0-9a-f]+):\s', text, re.M)}
            positions = set(CONTROLS) | {0xc4, 0xe0, 0xec, 0x16e, 0xf6, 0x10b, 0x160}
            if not {start + at for at in positions} <= addresses:
                raise ValueError('fragment controls must be instruction starts')
            (output / f'{start:x}.objdump.txt').write_text(text.replace(str(snapshot), '<authenticated-node94>'))
    (output / 'records.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path, default=ROOT / 'work/funding-bucket-94')
    args = parser.parse_args()
    result = generate(args.binary, args.output)
    print(json.dumps({'sha256': result['target_sha256'], 'wrappers': len(result['ranges']), 'executed': False}))
