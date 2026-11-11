#!/usr/bin/env python3
"""Node #115: per-user value field `l` is read as a formatted date and time string.

Open PR #6239 showed that the first per-user value visitor 0x1a212f0 reads
field `l` through 0x17ce890 and passes the 4-byte name `Time`. Open PR #6582
showed the same for the second visitor 0x30bcb40, which reads `l` through
0x2f6fa30. This tool checks what those two decoders do with the value.

1. Both visitors call their `l` decoder with the name `Time` (0x459f78,
   length 4): 0x1a221f0 calls 0x17ce890, 0x30bd6cf calls 0x2f6fa30.
2. Both decoders have an unwind extent of 0xa00 bytes. At offset 0x10 each
   compares the name length with 10 and the name with `_ExtStruct`, the
   MessagePack extension newtype name. `Time` is not that name, so `Time` is
   the newtype name the caller passes, not a value.
3. At offset 0x150 each decoder reads the value through slot 0x64dfec0. The
   slot has one R_X86_64_RELATIVE relocation, to the reader 0x14b93c0.
4. 0x14b93c0 dispatches markers 0xc0..0xe0 through the table 0x463358. The
   f32 marker 0xca goes to 0x14b93e5, which reads 4 bytes and calls
   0x155d7e0. That function widens the float, stores tag 3 (an unexpected
   float) and passes the expected-text vtable 0x63fe1f0.
5. The entry 0x63fe208 (vtable + 0x18) has one R_X86_64_RELATIVE relocation,
   to 0x1560950. That function loads 0x457c60 with length 0x20: the text
   `a formatted date and time string`.

So an f32 in field `l` is rejected, and the error says the field expects a
formatted date and time string. Other markers (f64, strings, integers) are
not covered here.

The tool only compares fixed bytes at fixed addresses, branch and call
targets, RIP-relative references, relocations, function extents from
.eh_frame_hdr, and strings. The captured binary is not executed. objdump and
readelf are not started. Addresses are ELF virtual addresses.
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
PACKET = ROOT / 'research/work-items/RE-008-user-value-l-time-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

FIRST_VISITOR = 0x1a212f0
SECOND_VISITOR = 0x30bcb40
FIRST_L = 0x17ce890
SECOND_L = 0x2f6fa30
DECODER_EXTENT = 0xa00
NAME_TIME = 0x459f78
SLOT = 0x64dfec0
READER = 0x14b93c0
TABLE = 0x463358
F32_ARM = 0x14b93e5
F32_VISIT = 0x155d7e0
EXPECTED_VTABLE = 0x63fe1f0
EXPECTED_ENTRY = 0x63fe208
EXPECTED_FN = 0x1560950
EXPECTED_TEXT = 0x457c60
TEXT = b'a formatted date and time string'

# Same bytes at these offsets of both decoders.
DECODER_PINS = {   # offset -> (bytes, meaning)
    0x10: ('4883f90a', 'name length compared with 10'),
    0x16: ('48b85f45787453747275', "name compared with '_ExtStru'"),
    0x27: ('4881f163740000', "name compared with 'ct'"),
    0x150: ('ff15', 'value read through a slot'),
}
PINS = {   # address -> (bytes, meaning)
    0x14b93c5: ('418d8040ffffff83f820', 'marker range 0xc0..0xe0'),
    0x155d7e8: ('f30f5ac0', 'f32 widened to f64'),
    0x155d7f2: ('c644243803', 'unexpected float (tag 3)'),
    0x1560962: ('ba20000000', 'expected text length 0x20'),
}
# call site -> (caller function, decoder)
CALLS = {0x1a221f0: (FIRST_VISITOR, FIRST_L), 0x30bd6cf: (SECOND_VISITOR, SECOND_L)}
# lea site -> target
LEAS = {0x1a221e9: NAME_TIME, 0x30bd6c8: NAME_TIME, 0x14b93d5: TABLE,
        0x155d801: EXPECTED_VTABLE, 0x156095b: EXPECTED_TEXT}


def read_va(data, va, size):
    hits = [s for s in sections(data)
            if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(hits) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = hits[0]['offset'] + va - hits[0]['address']
    return data[off:off + size]


def rel_target(data, va, length):
    return va + length + struct.unpack('<i', read_va(data, va + length - 4, 4))[0]


def relocation(data, slot):
    rela = [s for s in sections(data) if s['name'] == '.rela.dyn']
    if len(rela) != 1 or rela[0]['size'] % 24:
        raise ValueError('invalid relocation table')
    hits = []
    for off in range(rela[0]['offset'], rela[0]['offset'] + rela[0]['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', data, off)
        if where == slot:
            hits.append((info, addend))
    if len(hits) != 1 or hits[0][0] != 8:
        raise ValueError(f'slot {slot:#x} has no single relative relocation')
    return hits[0][1]


def pin_check(data):
    for va, (want, meaning) in PINS.items():
        raw = bytes.fromhex(want)
        if read_va(data, va, len(raw)) != raw:
            raise ValueError(f'instruction bytes changed at {va:#x} ({meaning})')
    for func in (FIRST_L, SECOND_L):
        for off, (want, meaning) in DECODER_PINS.items():
            raw = bytes.fromhex(want)
            if read_va(data, func + off, len(raw)) != raw:
                raise ValueError(f'decoder {func:#x} offset {off:#x} changed ({meaning})')


def calls(data):
    out = {}
    for site, (_, target) in CALLS.items():
        if read_va(data, site, 1) != b'\xe8' or rel_target(data, site, 5) != target:
            raise ValueError(f'call at {site:#x} is not to {target:#x}')
        out[hex(site)] = hex(target)
    for site in (0x1a221d9, 0x30bd6b8):
        if read_va(data, site, 5) != bytes.fromhex('b904000000'):
            raise ValueError(f'name length at {site:#x} is not 4')
    return out


def leas(data):
    for site, target in LEAS.items():
        if read_va(data, site, 3)[1:2] != b'\x8d' or rel_target(data, site, 7) != target:
            raise ValueError(f'lea at {site:#x} is not to {target:#x}')
    if read_va(data, NAME_TIME, 4) != b'Time':
        raise ValueError(f'string at {NAME_TIME:#x} is not Time')
    if read_va(data, EXPECTED_TEXT, len(TEXT)) != TEXT:
        raise ValueError(f'string at {EXPECTED_TEXT:#x} is not the expected text')


def value_path(data):
    for func in (FIRST_L, SECOND_L):
        if rel_target(data, func + 0x150, 6) != SLOT:
            raise ValueError(f'decoder {func:#x} value read is not through slot {SLOT:#x}')
    if relocation(data, SLOT) != READER:
        raise ValueError(f'slot {SLOT:#x} is not relocated to {READER:#x}')
    entry = TABLE + 4 * (0xca - 0xc0)
    if TABLE + struct.unpack('<i', read_va(data, entry, 4))[0] != F32_ARM:
        raise ValueError(f'table entry for 0xca is not {F32_ARM:#x}')
    if read_va(data, 0x14b9412, 1) != b'\xe8' or rel_target(data, 0x14b9412, 5) != F32_VISIT:
        raise ValueError(f'f32 arm does not call {F32_VISIT:#x}')
    if relocation(data, EXPECTED_ENTRY) != EXPECTED_FN:
        raise ValueError(f'entry {EXPECTED_ENTRY:#x} is not relocated to {EXPECTED_FN:#x}')


def extents(data):
    _, entries = unwind_index(data)
    starts = [e['start'] for e in entries]
    size = {}
    for func in (FIRST_L, SECOND_L, READER, F32_VISIT, EXPECTED_FN, FIRST_VISITOR, SECOND_VISITOR):
        i = bisect.bisect_left(starts, func)
        if i == len(starts) or starts[i] != func:
            raise ValueError(f'no unwind entry starts at {func:#x}')
        size[func] = entries[i]['next_index_upper_bound'] - func
    for func in (FIRST_L, SECOND_L):
        if size[func] != DECODER_EXTENT:
            raise ValueError(f'decoder {func:#x} extent is not {DECODER_EXTENT:#x}')
    for site, (func, _) in CALLS.items():
        if not func <= site < func + size[func]:
            raise ValueError(f'site {site:#x} is not in function {func:#x}')
    return {hex(f): hex(s) for f, s in size.items()}


def bind(data):
    pin_check(data)
    leas(data)
    value_path(data)
    return {
        'target': {'path': RELATIVE, 'sha256': SHA256},
        'callers': calls(data),
        'newtype_name': 'Time',
        'decoders': {hex(FIRST_L): '#6239', hex(SECOND_L): '#6582'},
        'decoder_checks': {hex(off): m for off, (_, m) in sorted(DECODER_PINS.items())},
        'value_read': {'slot': hex(SLOT), 'reader': hex(READER), 'offset_in_decoder': '0x150'},
        'f32': {'table': hex(TABLE), 'arm': hex(F32_ARM), 'visit': hex(F32_VISIT),
                'unexpected_tag': 3, 'expected_vtable': hex(EXPECTED_VTABLE),
                'expected_fn': hex(EXPECTED_FN)},
        'expected_text': TEXT.decode(),
        'not_covered': ['f64 and other markers', 'field u'],
        'extents': extents(data),
        'pins': len(PINS) + 2 * len(DECODER_PINS),
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
    print(f"pins={result['pins']} text={result['expected_text']!r}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
