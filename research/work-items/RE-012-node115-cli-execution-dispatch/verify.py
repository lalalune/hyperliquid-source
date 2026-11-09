#!/usr/bin/env python3
"""Verify the selected node115 CLI-to-executor call/relocation chain."""
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
import artifacts
import elf_index
import fde_extents

TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ARTIFACT = 'artifacts/node/115/hl-node'
RANGES = {
    0x2cd8370: 0x2cd83af,
    0x2ae1690: 0x2ae27b2,
    0x2ae41e0: 0x2ae6d66,
    0x564cce0: 0x564cf36,
    0x5654bf0: 0x5655d5c,
}
DISPATCH_TARGETS = [
    0x2ae420b, 0x2ae5ff9, 0x2ae5fec, 0x2ae5482,
    0x2ae461d, 0x2ae520a, 0x2ae47ec, 0x2ae553e,
    0x2ae5b9f, 0x2ae5d84, 0x2ae4e81, 0x2ae4b92,
    0x2ae4d9e, 0x2ae57d9, 0x2ae457f, 0x2ae53e9,
]


def expect(condition, message):
    if not condition:
        raise ValueError(message)


def mapped_bytes(data, sections, address, size):
    matches = [s for s in sections if s['type'] != 8 and s['address'] <= address
               and address + size <= s['address'] + s['size']]
    expect(len(matches) == 1, f'VA mapping is not unique: {address:#x}')
    section = matches[0]
    offset = section['offset'] + address - section['address']
    return data[offset:offset + size]


def direct_target(data, sections, address):
    raw = mapped_bytes(data, sections, address, 5)
    expect(raw[0] == 0xe8, f'expected direct CALL at {address:#x}')
    return address + 5 + struct.unpack_from('<i', raw, 1)[0]


def indirect_slot(data, sections, address):
    raw = mapped_bytes(data, sections, address, 6)
    expect(raw[:2] == b'\xff\x15', f'expected RIP-relative indirect CALL at {address:#x}')
    return address + 6 + struct.unpack_from('<i', raw, 2)[0]


def relative_addend(data, sections, slot):
    rela = [s for s in sections if s['name'] == '.rela.dyn']
    expect(len(rela) == 1 and rela[0]['size'] % 24 == 0, 'unexpected .rela.dyn layout')
    sec = rela[0]
    for offset in range(sec['offset'], sec['offset'] + sec['size'], 24):
        place, info, addend = struct.unpack_from('<QQq', data, offset)
        if place == slot:
            expect(info & 0xffffffff == 8 and info >> 32 == 0,
                   f'expected R_X86_64_RELATIVE at {slot:#x}')
            return addend
    raise ValueError(f'no dynamic relocation at {slot:#x}')


def verify(path):
    item = artifacts.manifest_item(ROOT, ARTIFACT)
    artifacts.check(path, item)
    expect(item['sha256'] == TARGET, 'artifact manifest target digest changed')
    data = Path(path).read_bytes()
    sections = elf_index.sections(data)

    _, fdes, _ = fde_extents.fde_extents(data)
    actual = {row['start']: row['end'] for row in fdes if row['start'] in RANGES}
    expect(actual == RANGES, f'selected FDE extent mismatch: {actual!r}')

    edges = [(0x2cd83a2, 0x2ae1690), (0x2ae1a47, 0x2ae41e0)]
    for source, target in edges:
        expect(direct_target(data, sections, source) == target,
               f'direct call target mismatch at {source:#x}')
    # Negative control: the verifier must reject a wrong expected destination.
    try:
        expect(direct_target(data, sections, 0x2cd83a2) == 0x2ae1691,
               'negative control was not rejected')
    except ValueError:
        pass
    else:
        raise ValueError('negative control unexpectedly accepted a corrupt target')

    expect(mapped_bytes(data, sections, 0x2ae41f4, 7) == bytes.fromhex('0fb6871a020000'),
           'dispatch byte load changed')
    expect(mapped_bytes(data, sections, 0x2ae41fb, 7) == bytes.fromhex('488d0de2feb1fd'),
           'dispatch table-base calculation changed')
    expect(mapped_bytes(data, sections, 0x2ae4202, 7) == bytes.fromhex('486304814801c8'),
           'dispatch table index calculation changed')
    # Include the final indirect jump in the independently bounded bytes.
    expect(mapped_bytes(data, sections, 0x2ae4209, 2) == bytes.fromhex('ffe0'),
           'dispatch indirect jump changed')
    table = mapped_bytes(data, sections, 0x6040e4, 4 * len(DISPATCH_TARGETS))
    actual_targets = [0x6040e4 + struct.unpack_from('<i', table, 4 * i)[0]
                      for i in range(len(DISPATCH_TARGETS))]
    expect(actual_targets == DISPATCH_TARGETS, 'dispatch relative table target changed')

    calls = [(0x2ae42f5, 0x64e73c0, 0x564d700),
             (0x2ae437a, 0x64e73c8, 0x564cce0),
             (0x564ce57, 0x64ebcb0, 0x5654bf0)]
    for source, slot, target in calls:
        expect(indirect_slot(data, sections, source) == slot,
               f'indirect slot mismatch at {source:#x}')
        expect(relative_addend(data, sections, slot) == target,
               f'relative relocation addend mismatch at {slot:#x}')
    print('Verified 5 FDE extents, 2 direct calls, 3 indirect calls/relative relocations, 16 dispatch entries, and 1 negative control.')


if __name__ == '__main__':
    try:
        verify(ROOT / ARTIFACT)
    except (OSError, ValueError) as error:
        print(f'cli execution dispatch verification failed: {error}', file=sys.stderr)
        raise SystemExit(1)
