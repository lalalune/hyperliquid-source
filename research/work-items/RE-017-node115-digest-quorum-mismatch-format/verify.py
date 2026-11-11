#!/usr/bin/env python3
"""Verify a bounded node #115 mismatch-formatting evidence snapshot."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
TARGET_REL = Path('artifacts/node/115/hl-node')
TARGET_SIZE = 105_896_032
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
EXPECTED_FDES = {
    'comparison': (0x1546570, 0x15466f3),
    'callback': (0x141e3a0, 0x141e538),
}
EXPECTED_RELOCATIONS = {
    0x64df6e8: (0, 8, 0x141e3a0),
    0x64e0f58: (0, 8, 0x1567ad0),
    0x64e0f80: (0, 8, 0x1546570),
}
EXPECTED_TEMPLATES = {
    0x43ab07: bytes.fromhex('c0082f686f75726c792fc0012fc0'),
    0x43aa84: bytes.fromhex('c0012fc0'),
}

sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def section_bytes(data, secs, address, length, *, executable=None):
    end = address + length
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= address
               and end <= s['address'] + s['size']
               and (executable is None or bool(s['flags'] & 4) == executable)]
    if len(matches) != 1:
        raise ValueError(f'VA range has {len(matches)} file-backed section mappings: {address:#x}..{end:#x}')
    section = matches[0]
    offset = section['offset'] + address - section['address']
    return data[offset:offset + length]


def capture(data):
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    found_fdes = {}
    for name, (start, end) in EXPECTED_FDES.items():
        rows = [f for f in fdes if f['start'] <= start < f['end']]
        if len(rows) != 1 or (rows[0]['start'], rows[0]['end']) != (start, end):
            raise ValueError(f'{name} FDE extent mismatch')
        found_fdes[name] = {'start': hex(start), 'end': hex(end)}

    rela = [s for s in secs if s['name'] == '.rela.dyn']
    if len(rela) != 1 or rela[0]['size'] % 24:
        raise ValueError('Expected one complete ELF64 .rela.dyn table')
    relocations = {}
    for offset in range(rela[0]['offset'], rela[0]['offset'] + rela[0]['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, offset)
        if slot in EXPECTED_RELOCATIONS:
            if hex(slot) in relocations:
                raise ValueError(f'Duplicate relocation slot: {slot:#x}')
            relocations[hex(slot)] = [info >> 32, info & 0xffffffff, hex(addend)]
    if set(relocations) != {hex(slot) for slot in EXPECTED_RELOCATIONS}:
        raise ValueError('Expected relocation slots are incomplete')

    code = []
    for name, (start, end) in EXPECTED_FDES.items():
        raw = section_bytes(data, secs, start, end - start, executable=True)
        code.append({'name': name, 'start': hex(start), 'end': hex(end),
                     'sha256': sha256(raw), 'bytes_hex': raw.hex()})

    templates = {}
    for address, expected in EXPECTED_TEMPLATES.items():
        raw = section_bytes(data, secs, address, len(expected), executable=False)
        templates[hex(address)] = {'length': len(raw), 'bytes_hex': raw.hex()}

    return {
        'target': {'path': str(TARGET_REL), 'size': len(data), 'sha256': sha256(data)},
        'fde_extents': found_fdes,
        'relocations': relocations,
        'templates': templates,
        'code_windows': code,
    }


def validate(snapshot, actual):
    if snapshot != actual:
        raise ValueError('Recorded snapshot differs from target-derived facts')
    if snapshot['target'] != {'path': str(TARGET_REL), 'size': TARGET_SIZE, 'sha256': TARGET_SHA256}:
        raise ValueError('Target identity mismatch')
    expected_fdes = {name: {'start': hex(bounds[0]), 'end': hex(bounds[1])}
                     for name, bounds in EXPECTED_FDES.items()}
    if snapshot['fde_extents'] != expected_fdes:
        raise ValueError('FDE extent facts mismatch')
    if snapshot['relocations'] != {hex(k): [v[0], v[1], hex(v[2])]
                                   for k, v in EXPECTED_RELOCATIONS.items()}:
        raise ValueError('Relocation facts mismatch')
    if snapshot['templates'] != {hex(k): {'length': len(v), 'bytes_hex': v.hex()}
                                 for k, v in EXPECTED_TEMPLATES.items()}:
        raise ValueError('Template facts mismatch')
    if [row['name'] for row in snapshot['code_windows']] != ['comparison', 'callback']:
        raise ValueError('Code-window set mismatch')
    for row in snapshot['code_windows']:
        raw = bytes.fromhex(row['bytes_hex'])
        if row['sha256'] != sha256(raw):
            raise ValueError('Code-window digest mismatch')


def corruption_controls(snapshot, actual):
    mutations = [
        lambda x: x['fde_extents']['comparison'].__setitem__('end', hex(0x15466f4)),
        lambda x: x['relocations']['0x64df6e8'].__setitem__(2, hex(0x141e3a1)),
        lambda x: x['templates']['0x43ab07'].__setitem__('bytes_hex', '00'),
        lambda x: x['code_windows'][0].__setitem__('bytes_hex', '00'),
        lambda x: x['target'].__setitem__('sha256', '0' * 64),
    ]
    rejected = 0
    for mutate in mutations:
        corrupted = copy.deepcopy(snapshot)
        mutate(corrupted)
        try:
            validate(corrupted, actual)
        except (KeyError, ValueError):
            rejected += 1
    if rejected != len(mutations):
        raise ValueError(f'Only {rejected}/{len(mutations)} corruption controls rejected')
    return rejected


def manifest_check():
    manifest = PACKET / 'MANIFEST.sha256'
    rows = manifest.read_text(encoding='utf-8').splitlines()
    checked = set()
    for row in rows:
        digest, relative = row.split('  ', 1)
        if relative in checked:
            raise ValueError(f'Duplicate manifest row: {relative}')
        checked.add(relative)
        path = PACKET / relative
        if not path.is_file() or sha256(path.read_bytes()) != digest:
            raise ValueError(f'Manifest mismatch: {relative}')
    if checked != {'README.md', 'snapshot.json', 'verify.py', 'verification.json', 'disassembly.txt'}:
        raise ValueError('Manifest file set mismatch')


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=ROOT / TARGET_REL)
    parser.add_argument('--write', action='store_true', help='regenerate snapshot and verification output')
    args = parser.parse_args()
    data = args.target.read_bytes()
    actual = capture(data)
    if args.write:
        validate(actual, actual)
        (PACKET / 'snapshot.json').write_text(json.dumps(actual, indent=2) + '\n', encoding='utf-8')
    snapshot = actual if args.write else json.loads((PACKET / 'snapshot.json').read_text(encoding='utf-8'))
    validate(snapshot, actual)
    rejected = corruption_controls(snapshot, actual)
    result = {'target_sha256': TARGET_SHA256, 'target_size': TARGET_SIZE,
              'fde_extents': len(snapshot['fde_extents']),
              'code_windows': len(snapshot['code_windows']),
              'relocations': len(snapshot['relocations']),
              'templates': len(snapshot['templates']),
              'corruption_controls_rejected': rejected}
    if args.write:
        (PACKET / 'verification.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    else:
        manifest_check()
        recorded = json.loads((PACKET / 'verification.json').read_text(encoding='utf-8'))
        if recorded != result:
            raise ValueError('Recorded verification summary mismatch')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, struct.error) as error:
        print(f'verify: {error}', file=sys.stderr)
        raise SystemExit(1)
