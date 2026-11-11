#!/usr/bin/env python3
"""Verify four #115 byte-prefix calls and how one containing FDE consumes results."""
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
HELPER = 0x5434bb0
FDE = (0x534f7a0, 0x5350b9a)
CALLS = [
    {'site': 0x534f9b1, 'call': 'e8fa510e00', 'mismatch': '0f85cc0a0000',
     'constant_store': '48c70363000000', 'constant': 0x63,
     'success_jump': 'e976110000'},
    {'site': 0x534fb6b, 'call': 'e840500e00', 'mismatch': '0f8512090000',
     'constant_store': '48c70385000000', 'constant': 0x85,
     'success_jump': 'e9bc0f0000'},
    {'site': 0x534ff57, 'call': 'e8544c0e00', 'mismatch': '0f8526050000',
     'constant_store': '48c7033c000000', 'constant': 0x3c,
     'success_jump': 'e9d00b0000'},
    {'site': 0x5350475, 'call': 'e836470e00', 'mismatch': '750c',
     'constant_store': '48c70326000000', 'constant': 0x26,
     'success_jump': 'e9b6060000'},
]
COMMON_COPY = {
    0x535048c: '0f100424',
    0x5350490: '0f104c2410',
    0x5350495: '0f114b18',
    0x5350499: '0f114308',
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

    def read_text(va, size):
        offset = text['offset'] + va - text['address']
        if va < text['address'] or offset + size > text['offset'] + text['size']:
            raise ValueError(f'{va:#x}: outside .text')
        return data[offset:offset + size]

    _, fdes = eh_frame_records(data, secs)
    candidates = []
    for pos in range(text['offset'], text['offset'] + text['size'] - 4):
        if data[pos] != 0xe8:
            continue
        site = text['address'] + pos - text['offset']
        if site + 5 + struct.unpack_from('<i', data, pos + 1)[0] == HELPER:
            candidates.append(site)
    if candidates != [row['site'] for row in CALLS]:
        raise ValueError(f'direct caller census changed: {[hex(x) for x in candidates]}')
    rows = []
    for item in CALLS:
        site = item['site']
        expected = {
            site - 6: '4889e7',       # mov rsp, rdi (local output)
            site - 3: '4c89f6',       # mov r14, rsi
            site: item['call'],
            site + 5: '803c2409',     # cmp byte [rsp], 9
            site + 9: item['mismatch'],
        }
        store_site = site + (15 if len(bytes.fromhex(item['mismatch'])) == 6 else 11)
        jump_site = store_site + 7
        expected[store_site] = item['constant_store']
        expected[jump_site] = item['success_jump']
        for va, encoded in expected.items():
            if read_text(va, len(bytes.fromhex(encoded))).hex() != encoded:
                raise ValueError(f'{va:#x}: caller instruction changed')
        if site + 5 + struct.unpack('<i', bytes.fromhex(item['call'])[1:])[0] != HELPER:
            raise ValueError(f'{site:#x}: call target changed')
        branch_site = site + 9
        mismatch = bytes.fromhex(item['mismatch'])
        if len(mismatch) == 6:
            branch_target = branch_site + len(mismatch) + struct.unpack('<i', mismatch[2:])[0]
        else:
            branch_target = branch_site + len(mismatch) + struct.unpack('<b', mismatch[1:])[0]
        if branch_target != 0x535048c:
            raise ValueError(f'{site:#x}: non-9 path target changed')
        success = bytes.fromhex(item['success_jump'])
        if jump_site + len(success) + struct.unpack('<i', success[1:])[0] != 0x5350b42:
            raise ValueError(f'{site:#x}: 9-result path target changed')
        owners = [f for f in fdes if f['start'] <= site < f['end']]
        if len(owners) != 1 or (owners[0]['start'], owners[0]['end']) != FDE:
            raise ValueError(f'{site:#x}: containing FDE changed or ambiguous')
        rows.append({'call_site': site, 'call_bytes': item['call'],
                     'helper_entry': HELPER, 'rdi_output': 'rsp', 'rsi_state': 'r14',
                     'test': {'site': site + 5, 'bytes': '803c2409', 'condition': 'output byte 0 == 9'},
                     'non_9_branch': {'site': branch_site, 'bytes': item['mismatch'],
                                      'target': branch_target},
                     'tag_9_action': {'store_site': store_site,
                                      'store_bytes': item['constant_store'],
                                      'u64_value': item['constant'],
                                      'jump_target': 0x5350b42},
                     'fde': {'start': owners[0]['start'], 'end': owners[0]['end']}})
    for va, encoded in COMMON_COPY.items():
        if read_text(va, len(bytes.fromhex(encoded))).hex() != encoded:
            raise ValueError(f'{va:#x}: common result-copy bytes changed')
    return {'target': {'release': 115, 'sha256': actual_hash,
                       'coordinate': 'ELF virtual address'},
            'caller_fde': {'start': FDE[0], 'end': FDE[1]},
            'calls': rows,
            'non_9_output_copy': {'target': 0x535048c,
                                  'instructions': [{'address': va, 'bytes': raw}
                                                   for va, raw in COMMON_COPY.items()],
                                  'effect': 'copy 32 local-output bytes at rsp+0 to rbx+8'},
            'limitations': ['One caller FDE and its four direct calls only.',
                            'No source names or meaning for the four constants are inferred.',
                            'No runtime reachability or captured-code execution is claimed.']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=TARGET)
    args = parser.parse_args()
    report = extract(args.binary.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"verified calls={len(report['calls'])} non_9_copy_bytes=32")


if __name__ == '__main__':
    main()
