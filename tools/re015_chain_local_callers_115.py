#!/usr/bin/env python3
"""List direct node #115 call sites to the Local/Sandbox/Testnet/Mainnet codec copy."""
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
    0x2674b80: [0x24062c7, 0x2407423, 0x2407ee4, 0x2408c93, 0x240aef8,
                0x240bc38, 0x240d2e7, 0x240e063, 0x240f423, 0x24101b8,
                0x2411b97, 0x24129d8, 0x24132b8, 0x2d3c353, 0x2d3e0b8,
                0x2d3ebe7, 0x2d40297],
    0x467f2d0: [0x44b0817, 0x44b16d3, 0x44b4c14, 0x44b6813, 0x44b7888,
                0x44c3463, 0x44c5b17, 0x44c8178, 0x44c8cf8, 0x44c9897,
                0x44ca427, 0x44cae03, 0x44cc038, 0x44cf327, 0x44d0597,
                0x44d0db8, 0x44d15f8],
    0x57c1de0: [0x5380b77, 0x53c6228, 0x53c6da3, 0x53cbef7, 0x591f333,
                0x591f7c4, 0x5921063, 0x5926987, 0x5928ad8, 0x5929328,
                0x592a6f7, 0x592b7f3, 0x592cf48, 0x592eeb7, 0x5935c17,
                0x5936ab8, 0x5936eb7, 0x5937988],
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
    all_hits = {target: [] for target in EXPECTED}
    for pos in range(text['offset'], text['offset'] + text['size'] - 4):
        if data[pos] != 0xe8:
            continue
        site = text['address'] + pos - text['offset']
        destination = site + 5 + struct.unpack_from('<i', data, pos + 1)[0]
        if destination not in all_hits:
            continue
        owners = [f for f in fdes if f['start'] <= site < f['end']]
        if len(owners) != 1:
            raise ValueError(f'{site:#x}: expected exactly one containing FDE, found {len(owners)}')
        all_hits[destination].append({
            'call_site': site,
            'call_bytes': data[pos:pos + 5].hex(),
            'fde_start': owners[0]['start'],
            'fde_end': owners[0]['end'],
        })
    output = []
    for target, expected_sites in EXPECTED.items():
        rows = sorted(all_hits[target], key=lambda r: r['call_site'])
        sites = [row['call_site'] for row in rows]
        if sites != expected_sites:
            raise ValueError(f'{target:#x}: caller census changed: {[hex(x) for x in sites]}')
        for row in rows:
            raw = bytes.fromhex(row['call_bytes'])
            if raw[0] != 0xe8 or row['call_site'] + 5 + struct.unpack('<i', raw[1:])[0] != target:
                raise ValueError(f"invalid direct call evidence at {row['call_site']:#x}")
        output.append({'serializer_entry': target, 'direct_call_count': len(rows), 'sites': rows})
    return {
        'target': {'release': 115, 'sha256': actual_hash, 'coordinate': 'ELF virtual address'},
        'section': {'name': '.text', 'address': text['address'], 'file_offset': text['offset'],
                    'size': text['size']},
        'method': 'exhaustive byte scan for E8 rel32 candidates, exact destination calculation, '
                  'candidate instruction confirmation by GNU objdump, containing FDE lookup',
        'direct_callers': output,
        'total_direct_calls': sum(len(row['sites']) for row in output),
        'limitations': ['No indirect-call or tail-jump census.',
                        'FDE containment does not establish source function names or ownership.',
                        'No map-key literals, serializer semantics, or struct identity are inferred.'],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=TARGET)
    args = parser.parse_args()
    report = extract(args.binary.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"verified serializers={len(report['direct_callers'])} direct_calls={report['total_direct_calls']}")


if __name__ == '__main__':
    main()
