#!/usr/bin/env python3
"""Verify one E114A payload helper's fixed 40-byte result envelope."""
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
DISPATCH_ARMS = ROOT / 'research/work-items/RE-010-variant-payload-dispatch-115/arms.tsv'
TARGET_SIZE = 105_896_032
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
FDE_BODIES = {
    0x18bf680: (0x18bf6f6, '9da3454c4d7a9b1973b0b8de193d7693e3b2b8ad6d824e48ecb4b970fb6a36bb'),
    0x18be120: (0x18be1ba, '1843d78f492ce208e9a206c7f17e56e5a81e9d88fe9a463346655d81943e8a00'),
    0x141e3a0: (0x141e538, 'aa4d4d0611c533e38c65e1577c0426b5163846c01225556743d4d4345cadd1fe'),
}
EXPECTED_RELOCATIONS = {
    0x64df480: (8, 0, 0x6355830),
    0x64df498: (8, 0, 0x141e264),
    0x64df4a0: (8, 0, 0x635de30),
    0x64df6a0: (8, 0, 0x1680c30),
    0x64df6e8: (8, 0, 0x141e3a0),
    0x64df6f0: (8, 0, 0x1680500),
    0x64dfed0: (8, 0, 0x5c4f380),
    0x64df508: (6, 7, 0),
}
RODATA_WITNESS = (0x44f07a, bytes.fromhex(
    '0e696e76616c696420747970653a20c00b2c20657870656374656420c0002f68'))


def require(ok, message):
    if not ok:
        raise ValueError(message)


def section_at(all_sections, name):
    return next(s for s in all_sections if s['name'] == name and s['type'] != 8)


def read_at(data, section, address, size):
    require(section['address'] <= address and address + size <= section['address'] + section['size'],
            f'{address:#x}: witness outside {section["name"]}')
    start = section['offset'] + address - section['address']
    return data[start:start + size]


def relocations(data, all_sections):
    section = next(s for s in all_sections if s['name'] == '.rela.dyn')
    require(section['size'] % 24 == 0, '.rela.dyn has a non-RELA64 size')
    found = {}
    for offset in range(section['offset'], section['offset'] + section['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, offset)
        if slot in EXPECTED_RELOCATIONS:
            found[slot] = (info & 0xffffffff, info >> 32, addend)
    for slot, expected in EXPECTED_RELOCATIONS.items():
        require(found.get(slot) == expected,
                f'relocation mismatch at {slot:#x}: observed {found.get(slot)!r}, expected {expected!r}')
    return {hex(slot): {'type': values[0], 'symbol_index': values[1], 'addend': hex(values[2])}
            for slot, values in sorted(found.items())}


def extract(data, *, expected_digest=TARGET_SHA256):
    digest = hashlib.sha256(data).hexdigest()
    if expected_digest is not None:
        require(len(data) == TARGET_SIZE and digest == expected_digest,
                f'target size/SHA-256 mismatch: size={len(data)}, sha256={digest}')
    all_sections = sections(data)
    text = section_at(all_sections, '.text')
    rodata = section_at(all_sections, '.rodata')
    _, fdes = eh_frame_records(data, all_sections)
    extent_map = {fde['start']: fde['end'] for fde in fdes}
    bodies = {}
    for start, (end, expected_body_hash) in FDE_BODIES.items():
        require(extent_map.get(start) == end,
                f'FDE mismatch at {start:#x}: observed {extent_map.get(start)!r}, expected {end:#x}')
        body = read_at(data, text, start, end - start)
        body_hash = hashlib.sha256(body).hexdigest()
        require(body_hash == expected_body_hash,
                f'body digest mismatch at {start:#x}: {body_hash}')
        bodies[hex(start)] = {'end': hex(end), 'size': len(body), 'sha256': body_hash,
                              'bytes': body.hex()}
    literal = read_at(data, rodata, RODATA_WITNESS[0], len(RODATA_WITNESS[1]))
    require(literal == RODATA_WITNESS[1], 'rodata witness mismatch at 0x44f07a')
    relocation_evidence = relocations(data, all_sections)
    arm_lines = DISPATCH_ARMS.read_text(encoding='utf-8').splitlines()
    e114a_helper_variants = sorted({int(line.split('\t')[1]) for line in arm_lines[1:]
                                    if line.split('\t')[0] == 'E114A' and '18bf680~' in line})
    expected_variants = [2, 7, 8, 12, 14, 16, 17, 19, 20, 21, 70, 71, 75, 92, 100, 102, 109]
    require(e114a_helper_variants == expected_variants,
            f'E114A dispatch crosswalk changed: {e114a_helper_variants!r}')
    return {
        'target': {'release': 115, 'size': len(data), 'sha256': digest},
        'component': 'action-dispatch',
        'question': 'What 40-byte result envelope does E114A helper 0x18bf680 write, and what formatter path constructs its inner object?',
        'fdes': bodies,
        'relocations': relocation_evidence,
        'dispatch_crosswalk': {
            'evidence_file': 'research/work-items/RE-010-variant-payload-dispatch-115/arms.tsv',
            'helper': '0x18bf680',
            'variants': e114a_helper_variants,
            'count': len(e114a_helper_variants),
        },
        'rodata': {'address': hex(RODATA_WITNESS[0]), 'bytes': literal.hex()},
        'observations': [
            {'address': '0x18bf680', 'fact': 'The helper receives an output pointer, passes output+8 to 0x18be120, then stores the 64-bit value 1 at output+0 and returns the original output pointer.'},
            {'address': 'research/work-items/RE-010-variant-payload-dispatch-115/arms.tsv', 'fact': 'The verified E114A dispatch table maps 17 variants (2, 7, 8, 12, 14, 16, 17, 19, 20, 21, 70, 71, 75, 92, 100, 102 and 109) to this same helper.'},
            {'address': '0x18be120', 'fact': 'The inner constructor writes byte tag 6 at its output base and writes three qwords at offsets +8, +16 and +24 from local values; the resulting inner object occupies 32 bytes.'},
            {'address': '0x18be175', 'fact': 'On the tagged-length branch, the three qwords are length, pointer (or empty sentinel 1), and length; nonempty input is allocated and copied through the observed relocation slots.'},
            {'address': '0x18be137', 'fact': 'On the even-pointer branch, the constructor delegates initialization to the function pointer loaded from GOT slot 0x64df6e8, then copies three qwords from its local record.'},
            {'address': '0x64df6e8', 'fact': 'The R_X86_64_RELATIVE relocation resolves this slot to 0x141e3a0, whose complete FDE is included below.'},
            {'address': '0x141e3a0', 'fact': 'The relocated helper receives an output record, the saved format-text pointer and the descriptor; it allocates a string buffer, passes the buffer plus format/descriptor to slot 0x64df6f0, then copies its three-qword string record to the caller output.'},
            {'address': '0x64df6f0', 'fact': 'The formatter call slot relocates to 0x1680500; this packet records the call boundary and does not claim that callee body.'},
            {'address': '0x18bf6d5', 'fact': 'The helper supplies rodata address 0x44f07a and a descriptor record to the inner constructor; the witnessed bytes begin with the tagged format text `invalid type: ... expected ...`.'},
        ],
        'inference': [
            'Combining the two functions, the bounded output layout is an outer 8-byte value 1 followed by a 32-byte object whose first byte is 6 and whose remaining bytes contain three constructor-produced qwords. These bytes are observed; source-level enum/type names are not established.',
            'For the tagged-length branch, the three qwords have the observed length/pointer/length dataflow. Their Rust-level ownership or semantic field names are not claimed.',
        ],
        'unresolved': [
            'The implementation behind formatter slot 0x64df6f0 and exact formatted output bytes for supplied descriptor values.',
            'The source-level E114A payload type and meaning of the outer value 1 / inner tag 6.',
            'The complete formatting result bytes and runtime reachability of this helper.',
        ],
        'scope': 'Partial static helper result-layout evidence only; no payload type naming, full action path, Rust implementation, runtime execution, or component gate is claimed.',
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    result = extract(args.target.read_bytes())
    rendered = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding='utf-8')
    else:
        print(rendered, end='')


if __name__ == '__main__':
    main()
