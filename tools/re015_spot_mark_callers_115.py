#!/usr/bin/env python3
"""Verify node #115 direct callers and MessagePack key prefixes for Spot/Mark codecs."""
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
    0x22e3810: {'call_site': 0x25d6860, 'fde': (0x25d67b0, 0x25d6a43),
                'prefix': [(0x25d67dc, 'c6040181'), (0x25d67f7, 'c60401a1'),
                           (0x25d680b, 'c6040170'), (0x25d682d, 'c6040192')],
                'call_bytes': 'e8abcfd0ff'},
    0x3d4d420: {'call_site': 0x36712c0, 'fde': (0x3671210, 0x36714a3),
                'prefix': [(0x367123c, 'c6040181'), (0x3671257, 'c60401a1'),
                           (0x367126b, 'c6040170'), (0x367128d, 'c6040192')],
                'call_bytes': 'e85bc16d00'},
    0x5361090: {'call_site': 0x50bc360, 'fde': (0x50bc2b0, 0x50bc543),
                'prefix': [(0x50bc2dc, 'c6040181'), (0x50bc2f7, 'c60401a1'),
                           (0x50bc30b, 'c6040170'), (0x50bc32d, 'c6040192')],
                'call_bytes': 'e82b4d2a00'},
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

    def bytes_at(va, size):
        offset = text['offset'] + va - text['address']
        if va < text['address'] or offset + size > text['offset'] + text['size']:
            raise ValueError(f'{va:#x}: address outside .text')
        return data[offset:offset + size]

    sites = {entry: [] for entry in EXPECTED}
    for pos in range(text['offset'], text['offset'] + text['size'] - 4):
        if data[pos] != 0xe8:
            continue
        site = text['address'] + pos - text['offset']
        destination = site + 5 + struct.unpack_from('<i', data, pos + 1)[0]
        if destination in sites:
            sites[destination].append(site)

    rows = []
    for entry, expected in EXPECTED.items():
        if sites[entry] != [expected['call_site']]:
            raise ValueError(f'{entry:#x}: direct call-site census changed: {sites[entry]}')
        site = expected['call_site']
        call_bytes = bytes_at(site, 5).hex()
        if call_bytes != expected['call_bytes']:
            raise ValueError(f'{site:#x}: call instruction bytes changed')
        if site + 5 + struct.unpack('<i', bytes.fromhex(call_bytes)[1:])[0] != entry:
            raise ValueError(f'{site:#x}: call destination mismatch')
        owners = [f for f in fdes if f['start'] <= site < f['end']]
        if len(owners) != 1 or (owners[0]['start'], owners[0]['end']) != expected['fde']:
            raise ValueError(f'{site:#x}: containing FDE changed or ambiguous')
        prefix = []
        for address, raw in expected['prefix']:
            observed = bytes_at(address, len(bytes.fromhex(raw))).hex()
            if observed != raw:
                raise ValueError(f'{address:#x}: map-prefix store bytes changed')
            prefix.append({'address': address, 'instruction_bytes': observed,
                           'stored_byte': bytes.fromhex(raw)[-1]})
        rows.append({'serializer_entry': entry, 'call_site': site,
                     'call_bytes': call_bytes,
                     'containing_fde': {'start': owners[0]['start'], 'end': owners[0]['end']},
                     'prefix_stores': prefix})
    return {
        'target': {'release': 115, 'sha256': actual_hash, 'coordinate': 'ELF virtual address'},
        'section': {'name': '.text', 'address': text['address'], 'file_offset': text['offset'],
                    'size': text['size']},
        'method': 'exhaustive E8 rel32 byte scan for the three exact destinations, exact instruction '
                  'byte checks, focused GNU objdump confirmation, and containing FDE lookup',
        'msgpack_prefix': {'bytes': ['0x81', '0xa1', '0x70', '0x92'],
                           'observation': 'fixmap(1), fixstr(1), byte 0x70 (ASCII p), fixarray(2)'},
        'callers': rows,
        'limitations': ['The prefix stores are observed in the caller instruction stream; no source '
                        'struct or second array element is identified.',
                        'No indirect-call or tail-jump census.',
                        'FDE containment does not establish complete function boundaries.'],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=TARGET)
    args = parser.parse_args()
    report = extract(args.binary.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"verified direct_calls={len(report['callers'])} key_byte=0x70")


if __name__ == '__main__':
    main()
