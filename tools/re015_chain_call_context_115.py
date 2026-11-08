#!/usr/bin/env python3
"""Verify one node #115 chain-codec caller's literal key and call context."""
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
TEXT_SPANS = {
    0x240627b: '41807e1b01',  # cmp byte [r14+0x1b], 1; jne skips the selected writer path
    0x2406296: 'c60402b0',    # append MessagePack fixstr(16) marker
    0x24062ae: '0f1005dbf704fe',  # RIP-relative load of 16 key bytes
    0x24062b5: '0f110402',    # append the loaded 16 bytes at [rdx+rax]
    0x24062c7: 'e8b4e82600',  # direct call to 0x2674b80
}
CALL_SITE = 0x24062c7
CALL_TARGET = 0x2674b80
FDE_RANGE = (0x2406120, 0x24064e4)
KEY_VA = 0x455a90
KEY_BYTES = b'hyperliquidChain'


def extract(data):
    actual_hash = hashlib.sha256(data).hexdigest()
    if actual_hash != TARGET_SHA256:
        raise ValueError(f'target digest mismatch: {actual_hash}')
    secs = sections(data)
    text = [s for s in secs if s['name'] == '.text' and s['type'] != 8]
    if len(text) != 1:
        raise ValueError('expected one file-backed .text section')
    text = text[0]

    def section_bytes(name, va, size):
        matches = [s for s in secs if s['name'] == name and s['type'] != 8
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError(f'{va:#x}: no unique file-backed {name} mapping')
        row = matches[0]
        offset = row['offset'] + va - row['address']
        return data[offset:offset + size]

    for va, expected in TEXT_SPANS.items():
        if section_bytes('.text', va, len(bytes.fromhex(expected))).hex() != expected:
            raise ValueError(f'{va:#x}: instruction bytes changed')
    call = bytes.fromhex(TEXT_SPANS[CALL_SITE])
    destination = CALL_SITE + len(call) + struct.unpack('<i', call[1:])[0]
    if destination != CALL_TARGET:
        raise ValueError('serializer call target changed')
    rip_load = bytes.fromhex(TEXT_SPANS[0x24062ae])
    key_target = 0x24062ae + len(rip_load) + struct.unpack('<i', rip_load[3:])[0]
    if key_target != KEY_VA:
        raise ValueError(f'key reference changed: {key_target:#x}')
    observed_key = section_bytes('.rodata', KEY_VA, len(KEY_BYTES))
    if observed_key != KEY_BYTES:
        raise ValueError(f'key bytes changed: {observed_key!r}')
    _, fdes = eh_frame_records(data, secs)
    owners = [f for f in fdes if f['start'] <= CALL_SITE < f['end']]
    if len(owners) != 1 or (owners[0]['start'], owners[0]['end']) != FDE_RANGE:
        raise ValueError('caller FDE range changed or ambiguous')
    return {
        'target': {'release': 115, 'sha256': actual_hash, 'coordinate': 'ELF virtual address'},
        'caller': {'direct_call_site': CALL_SITE, 'call_bytes': call.hex(),
                   'codec_entry': CALL_TARGET,
                   'fde': {'start': owners[0]['start'], 'end': owners[0]['end']}},
        'selected_path': {'branch_instruction': 0x240627b,
                          'branch_bytes': TEXT_SPANS[0x240627b],
                          'condition': 'byte [r14+0x1b] equals 1 to fall through'},
        'map_key': {'marker_site': 0x2406296, 'marker_bytes': TEXT_SPANS[0x2406296],
                    'marker': 0xb0, 'fixstr_length': len(KEY_BYTES),
                    'load_site': 0x24062ae, 'load_bytes': rip_load.hex(),
                    'load_target': key_target, 'bytes_hex': observed_key.hex(),
                    'text': observed_key.decode('ascii')},
        'value_prefix_and_call': {'append_site': 0x24062b5,
                                  'append_bytes': TEXT_SPANS[0x24062b5],
                                  'codec_call_site': CALL_SITE},
        'limitations': ['One caller only; no complete call graph or claim of source-level struct '
                        'ownership.', 'No domain semantics for the key or serialized value are inferred.',
                        'The containing FDE is not claimed as a validated full source function.'],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=TARGET)
    args = parser.parse_args()
    report = extract(args.binary.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"verified call={report['caller']['direct_call_site']:#x} key={report['map_key']['text']}")


if __name__ == '__main__':
    main()
