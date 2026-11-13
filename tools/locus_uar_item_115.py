#!/usr/bin/env python3
"""Node #115: each item of Locus field `uaR` is an enum whose first four variants are Perp, Spot, Token and Pdi.

Open PR #6591 showed that the `uaR` value reader 0x329edf0 reads a sequence
and decodes each item through 0x2f3c470, and did not map 0x2f3c470. This
tool checks that item decoder, one level down:

1. 0x2f3c470 accepts only a MessagePack map with exactly one entry: fixmap
   (0x80), map16 (0xde) or map32 (0xdf), each with length 1. Any other
   length stores error tag 4 with the length. Any other marker stores error
   tag 2 with the marker. With one entry, it calls 0x3bdc730. This is the
   shape of an enum written as {variant: value}.
2. 0x3bdc730 reads the variant index through 0x3163ca0 and, on result tag 9,
   jumps through the table 0x7b2e68. Entries 0 to 6 point inside 0x3bdc730.
   Entry 7 (0x7b2e84) is the start of the next function's table: 0x3bdca00
   loads 0x7b2e84 itself. So the variant table has 7 entries.
3. Arms 0 to 3 each pass a type name and its length to the same reader
   0x2f48380 and, on result tag 9, store a variant number: Perp (4 bytes) ->
   0, Spot (4) -> 1, Token (5) -> 2, Pdi (3) -> 3. The success path stores
   result tag 9.
4. Arms 4 to 6 are listed by address only.

The variant-name matcher 0x3163ca0 is a boundary: this tool checks only the
call to it, not its table. The tool only compares fixed bytes at fixed
addresses, jump-table entries, branch and call targets, RIP-relative
references, function starts from .eh_frame_hdr, and strings. The captured
binary is not executed. objdump and readelf are not started. Addresses are
ELF virtual addresses.
"""
import argparse
import bisect
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections, unwind_index

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-locus-uar-item-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

VALUE = 0x329edf0
ITEM = 0x2f3c470
VARIANT = 0x3bdc730
INDEX_READER = 0x3163ca0
NEWTYPE = 0x2f48380
TABLE = 0x7b2e68
TABLE_SIZE = 7
NEXT_FUNC = 0x3bdca00
NEXT_TABLE_LEA = 0x3bdca18

PINS = {   # address -> (bytes, meaning)
    0x329efe2: ('4889e74989f4e883d4c9ff', 'uaR value loop: item through 0x2f3c470 (#6591)'),
    0x2f3c4b7: ('80f9800f8422010000', 'item: fixmap -> length check 0x2f3c5e2'),
    0x2f3c4c3: ('81fade000000742381fadf000000754e', 'item: map16 / map32, any other marker -> 0x2f3c521'),
    0x2f3c521: ('c644240802884c2409', 'item: other marker -> error tag 2 with the marker'),
    0x2f3c58d: ('83f801751b', 'item: map16 length must be 1'),
    0x2f3c5a8: ('83f801743d', 'item: map32 length must be 1'),
    0x2f3c5ad: ('c60304894304', 'item: other length -> error tag 4 with the length'),
    0x2f3c5e5: ('83f80175c3', 'item: fixmap length must be 1'),
    0x2f3c5ea: ('c6462001', 'item: one entry -> variant reader'),
    0x3bdc742: ('ba01000000', 'variant reader: index read argument 1'),
    0x3bdc756: ('80f909754b', 'variant reader: index result tag 9'),
    0x3bdc767: ('48630481', 'variant reader: table load'),
    0x3bdc76b: ('4801c8ffe0', 'variant reader: jump through table'),
    0x3bdc8e4: ('c60309', 'variant reader: success tag 9'),
}
# call / jump site -> (opcode bytes, instruction length, target)
JUMPS = {
    0x329efe8: ('e8', 5, ITEM),
    0x2f3c5f1: ('e8', 5, VARIANT),
    0x3bdc747: ('e8', 5, INDEX_READER),
    0x3bdc784: ('e8', 5, NEWTYPE),
    0x3bdc8c7: ('e8', 5, NEWTYPE),
    0x3bdc869: ('e8', 5, NEWTYPE),
    0x3bdc898: ('e8', 5, NEWTYPE),
}
# variant arm -> (index, lea site, name address, name, length site, store site, variant number)
ARMS = {
    0x3bdc770: (0, 0x3bdc770, 0x45a0d0, 'Perp', 0x3bdc77c, 0x3bdc799, 0),
    0x3bdc8b3: (1, 0x3bdc8b3, 0x45a114, 'Spot', 0x3bdc8bf, 0x3bdc8d8, 1),
    0x3bdc855: (2, 0x3bdc855, 0x7c8235, 'Token', 0x3bdc861, 0x3bdc87a, 2),
    0x3bdc884: (3, 0x3bdc884, 0x7d3bf8, 'Pdi', 0x3bdc890, 0x3bdc8a9, 3),
}
# table index -> arm, for every entry
TABLE_ARMS = {
    0: 0x3bdc770, 1: 0x3bdc8b3, 2: 0x3bdc855, 3: 0x3bdc884, 4: 0x3bdc7df,
    5: 0x3bdc902, 6: 0x3bdc965,
}
TABLE_LEA = 0x3bdc760
# site -> function that holds it (from .eh_frame_hdr)
HOLDERS = {
    0x329efe8: VALUE, 0x2f3c5f1: ITEM, 0x2f3c521: ITEM, 0x3bdc747: VARIANT,
    0x3bdc784: VARIANT, 0x3bdc8c7: VARIANT, 0x3bdc869: VARIANT, 0x3bdc898: VARIANT,
    0x3bdc7df: VARIANT, 0x3bdc902: VARIANT, 0x3bdc965: VARIANT, NEXT_TABLE_LEA: NEXT_FUNC,
}


def read_va(data, va, size):
    hits = [s for s in sections(data)
            if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(hits) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = hits[0]['offset'] + va - hits[0]['address']
    return data[off:off + size]


def rel_target(data, va, length):
    return va + length + struct.unpack('<i', read_va(data, va + length - 4, 4))[0]


def pin_check(data):
    for va, (want, meaning) in PINS.items():
        raw = bytes.fromhex(want)
        if read_va(data, va, len(raw)) != raw:
            raise ValueError(f'instruction bytes changed at {va:#x} ({meaning})')


def branch(data, site, op, length, target):
    if read_va(data, site, len(op) // 2) != bytes.fromhex(op) or rel_target(data, site, length) != target:
        raise ValueError(f'branch at {site:#x} is not to {target:#x}')


def jumps(data):
    out = {}
    for site, (op, length, target) in JUMPS.items():
        branch(data, site, op, length, target)
        out[hex(site)] = hex(target)
    return out


def lea_to(data, site, addr):
    if read_va(data, site, 3)[1:2] != b'\x8d' or rel_target(data, site, 7) != addr:
        raise ValueError(f'lea at {site:#x} is not to {addr:#x}')


def table(data):
    lea_to(data, TABLE_LEA, TABLE)
    out = {}
    for index in range(TABLE_SIZE):
        got = TABLE + struct.unpack('<i', read_va(data, TABLE + 4 * index, 4))[0]
        if got != TABLE_ARMS[index]:
            raise ValueError(f'table {TABLE:#x} entry {index} is {got:#x}, not {TABLE_ARMS[index]:#x}')
        out[str(index)] = hex(got)
    lea_to(data, NEXT_TABLE_LEA, TABLE + 4 * TABLE_SIZE)
    return out


def variants(data):
    out = []
    for arm, (index, lea_site, addr, name, len_site, store_site, number) in ARMS.items():
        if TABLE_ARMS[index] != arm:
            raise ValueError(f'arm {arm:#x} is not table entry {index}')
        lea_to(data, lea_site, addr)
        if read_va(data, addr, len(name)) != name.encode():
            raise ValueError(f'string at {addr:#x} is not {name!r}')
        if read_va(data, len_site, 5) != b'\xb9' + struct.pack('<I', len(name)):
            raise ValueError(f'name length at {len_site:#x} is not {len(name)}')
        if read_va(data, store_site, 8) != b'\x48\xc7\x43\x08' + struct.pack('<I', number):
            raise ValueError(f'variant store at {store_site:#x} is not {number}')
        out.append({'index': index, 'type_name': name, 'variant': number, 'arm': hex(arm)})
    return out


def holders(data):
    _, entries = unwind_index(data)
    starts = [e['start'] for e in entries]
    out = {}
    for site, func in HOLDERS.items():
        i = bisect.bisect_right(starts, site) - 1
        if i < 0 or starts[i] != func or not site < entries[i]['next_index_upper_bound']:
            raise ValueError(f'site {site:#x} is not in function {func:#x}')
        out[hex(site)] = hex(func)
    return out


def bind(data):
    pin_check(data)
    return {
        'target': {'path': RELATIVE, 'sha256': SHA256},
        'item_decoder': {
            'address': hex(ITEM),
            'accepted': 'MessagePack map with exactly one entry (fixmap, map16, map32)',
            'other_length': 'error tag 4 with the length',
            'other_marker': 'error tag 2 with the marker',
            'variant_reader': hex(VARIANT),
        },
        'variant_reader': {
            'index_reader': hex(INDEX_READER), 'index_reader_mapped': False,
            'table': hex(TABLE), 'entries': table(data),
            'table_end': {'next_table': hex(TABLE + 4 * TABLE_SIZE), 'loaded_by': hex(NEXT_FUNC)},
            'newtype_reader': hex(NEWTYPE),
            'mapped_variants': variants(data),
            'unmapped_arms': ['0x3bdc7df', '0x3bdc902', '0x3bdc965'],
        },
        'branches': jumps(data),
        'holders': holders(data),
        'meaning_of_uaR_name': 'not proven',
        'links': {'uar_value_reader': '#6591', 'locus_arms': '#6589'},
        'pins': len(PINS),
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    result = bind(binary.read_bytes())
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_bytes(render(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    expected = (PACKET / 'evidence.json').read_bytes() if args.check else None
    result = generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    names = [v['type_name'] for v in result['variant_reader']['mapped_variants']]
    print(f"pins={result['pins']} branches={len(result['branches'])} variants={names}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
