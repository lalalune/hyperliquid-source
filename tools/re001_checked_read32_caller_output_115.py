#!/usr/bin/env python3
"""Verify one #115 checked-read32 caller and its output-tag wrapping."""
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
CALL_SITE = 0x4e182ed
HELPER = 0x5821430
FDE = (0x4e182e0, 0x4e18353)
INSTRUCTIONS = {
    0x4e182e0: '53', 0x4e182e1: '4883ec50', 0x4e182e5: '4889fb',
    0x4e182e8: '488d7c2428', 0x4e182ed: 'e83e91a000',
    0x4e182f2: '807c242801', 0x4e182f7: '7522',
    0x4e182f9: '488d442407', 0x4e182fe: '0f10442430',
    0x4e18303: '0f104c2440', 0x4e18308: '0f114c2417',
    0x4e1830d: '0f11442407', 0x4e18312: 'b101',
    0x4e18314: 'ba08000000', 0x4e18319: 'eb1d',
    0x4e1831b: '0f10442429', 0x4e18320: '0f104c2439',
    0x4e18325: '0f294c2410', 0x4e1832a: '0f290424',
    0x4e1832e: '4889e0', 0x4e18331: 'ba01000000',
    0x4e18336: '31c9', 0x4e18338: '0f1000',
    0x4e1833b: '0f104810', 0x4e1833f: '0f114c1310',
    0x4e18344: '0f110413', 0x4e18348: '880b',
    0x4e1834a: '4889d8', 0x4e1834d: '4883c450',
    0x4e18351: '5b', 0x4e18352: 'c3',
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
    for va, expected in INSTRUCTIONS.items():
        offset = text['offset'] + va - text['address']
        if va < text['address'] or offset + len(bytes.fromhex(expected)) > text['offset'] + text['size']:
            raise ValueError(f'{va:#x}: outside .text')
        if data[offset:offset + len(bytes.fromhex(expected))].hex() != expected:
            raise ValueError(f'{va:#x}: instruction bytes changed')
    call = bytes.fromhex(INSTRUCTIONS[CALL_SITE])
    if CALL_SITE + len(call) + struct.unpack('<i', call[1:])[0] != HELPER:
        raise ValueError('direct call target changed')
    cmp_bytes = bytes.fromhex(INSTRUCTIONS[0x4e182f2])
    branch = bytes.fromhex(INSTRUCTIONS[0x4e182f7])
    mismatch_target = 0x4e182f7 + len(branch) + struct.unpack('<b', branch[1:])[0]
    if mismatch_target != 0x4e1831b or cmp_bytes != bytes.fromhex('807c242801'):
        raise ValueError('helper tag branch changed')
    _, fdes = eh_frame_records(data, secs)
    owners = [f for f in fdes if f['start'] <= CALL_SITE < f['end']]
    if len(owners) != 1 or (owners[0]['start'], owners[0]['end']) != FDE:
        raise ValueError('caller FDE changed or ambiguous')
    return {
        'target': {'release': 115, 'sha256': actual_hash, 'coordinate': 'ELF virtual address'},
        'caller_fde': {'start': owners[0]['start'], 'end': owners[0]['end']},
        'helper_call': {'site': CALL_SITE, 'bytes': call.hex(), 'destination': HELPER,
                        'output_argument': 'rsp+0x28 in rdi',
                        'other_arguments': 'rsi and rdx are passed through unchanged'},
        'tag_test': {'site': 0x4e182f2, 'bytes': cmp_bytes.hex(),
                     'tested_byte': '[rsp+0x28]', 'equal_to': 1,
                     'not_equal_target': mismatch_target},
        'tag_1_result': {'outer_tag': 1, 'tag_store_site': 0x4e18348,
                         'payload_source': 'helper output bytes [8,40)',
                         'outer_payload': 'output bytes [8,40)'},
        'other_result': {'outer_tag': 0, 'tag_store_site': 0x4e18348,
                         'payload_source': 'helper output bytes [1,33)',
                         'outer_payload': 'output bytes [1,33)'},
        'limitations': ['One caller only; no caller-of-caller input provenance.',
                        'The copied 32-byte windows are byte movement observations; this packet '
                        'does not assert every byte is initialized for every helper outcome.',
                        'No source type, error meaning, or runtime behavior is inferred.'],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=TARGET)
    args = parser.parse_args()
    report = extract(args.binary.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"verified caller=0x{CALL_SITE:x} helper=0x{HELPER:x} branches=2")


if __name__ == '__main__':
    main()
