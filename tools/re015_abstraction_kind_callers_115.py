#!/usr/bin/env python3
"""Verify direct node #115 callers of the abstraction-kind visitor copies."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
EXPECTED = {
    0x23c65f0: [(0x1c0ef86, 0x1c0eab0, 0x1c0f199)],
    0x3bdd720: [(0x3164176, 0x3163ca0, 0x3164389)],
    0x4d6b5d0: [(0x48d2956, 0x48d2480, 0x48d2b69)],
    0x23c6720: [(0x1debabf, 0x1deba10, 0x1debb91),
                (0x1e22089, 0x1e21fc0, 0x1e220e3)],
    0x3bdd5e0: [(0x3f7f8cf, 0x3f7f820, 0x3f7f9a1),
                (0x3fbb239, 0x3fbb170, 0x3fbb293)],
}


def extract(data):
    actual_hash = hashlib.sha256(data).hexdigest()
    if actual_hash != TARGET_SHA256:
        raise ValueError(f'target digest mismatch: {actual_hash}')
    secs = sections(data)
    texts = [s for s in secs if s['name'] == '.text' and s['type'] != 8]
    if len(texts) != 1:
        raise ValueError('expected one file-backed .text section')
    text = texts[0]
    _, fdes = eh_frame_records(data, secs)
    actual = {entry: [] for entry in EXPECTED}
    for pos in range(text['offset'], text['offset'] + text['size'] - 4):
        if data[pos] != 0xe8:
            continue
        site = text['address'] + pos - text['offset']
        dest = site + 5 + struct.unpack_from('<i', data, pos + 1)[0]
        if dest in actual:
            owners = [f for f in fdes if f['start'] <= site < f['end']]
            if len(owners) != 1:
                raise ValueError(f'{site:#x}: expected one containing FDE, got {len(owners)}')
            actual[dest].append({'call_site': site, 'call_bytes': data[pos:pos + 5].hex(),
                                 'fde_start': owners[0]['start'], 'fde_end': owners[0]['end']})
    groups = []
    for entry, expected_rows in EXPECTED.items():
        rows = sorted(actual[entry], key=lambda row: row['call_site'])
        observed = [(r['call_site'], r['fde_start'], r['fde_end']) for r in rows]
        if observed != expected_rows:
            raise ValueError(f'{entry:#x}: caller census or FDE changed: {observed}')
        for row in rows:
            raw = bytes.fromhex(row['call_bytes'])
            dest = row['call_site'] + 5 + struct.unpack('<i', raw[1:])[0]
            if raw[0] != 0xe8 or dest != entry:
                raise ValueError(f"{row['call_site']:#x}: invalid direct-call evidence")
        groups.append({'visitor_entry': entry, 'direct_call_count': len(rows), 'sites': rows})
    return {'target': {'release': 115, 'sha256': actual_hash,
                       'coordinate': 'ELF virtual address'},
            'section': {'name': '.text', 'address': text['address'],
                        'file_offset': text['offset'], 'size': text['size']},
            'method': 'complete .text E8 rel32 byte scan, signed destination calculation, '
                      'focused GNU objdump call-site confirmation, and containing FDE lookup',
            'callers': groups,
            'total_direct_calls': sum(len(group['sites']) for group in groups),
            'limitations': ['No indirect-call or tail-jump census.',
                            'FDE ranges are unwind evidence, not validated source function names.',
                            'No input field, source struct, action, or visitor semantics are inferred.']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=TARGET)
    args = parser.parse_args()
    report = extract(args.binary.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"verified visitors={len(report['callers'])} direct_calls={report['total_direct_calls']}")


if __name__ == '__main__':
    main()
