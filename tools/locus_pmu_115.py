#!/usr/bin/env python3
"""Node #115: Locus field 14 `pmu` is a required non-negative integer (u64).

Open PR #6589 mapped the 16 field arms of the MessagePack Locus visitor
0x332c430 and noted that arm 14 (`pmu`, at 0x332ca3c) calls no separate
decoder. This tool checks what that arm reads:

1. Arm 14 first tests the seen flag at rsp+0xa0. If it is already 1, it
   jumps to 0x3330010, which loads the name `pmu` (0x794eb4, 3 bytes) for
   the duplicate-field error.
2. Otherwise it reads one MessagePack marker byte inline, classifies it, and
   calls the value reader through slot 0x64dfeb0. That slot has one
   R_X86_64_RELATIVE relocation to 0x14b7aa0.
3. On result tag 9 it keeps the 8-byte value at rsp+0x2a8 and sets the seen
   flag to 1.
4. 0x14b7aa0 dispatches markers 0xc0..0xe0 through the table 0x462eb4:
   - positive fixint, u8, u16, u32 and u64 store the number and tag 9;
   - i8 to i64 and negative fixint keep a value >= 0 and report a negative
     one as an unexpected signed integer (tag 2);
   - f32 is widened and reported as an unexpected float (tag 3);
   - true and false are reported as an unexpected bool (tag 0);
   - nil, and other markers, are rejected.
   This is the shape of a u64 visitor.
5. If `pmu` is missing at the end, the visitor loads the name `pmu` and the
   template `missing field `...`` (0x4325c4) and calls the error builder
   0x3046740. No default value is stored.

The tool only compares fixed bytes at fixed addresses, jump-table entries,
branch and call targets, RIP-relative references, one relocation, function
starts from .eh_frame_hdr, and strings. The captured binary is not executed.
objdump and readelf are not started. Addresses are ELF virtual addresses.
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
PACKET = ROOT / 'research/work-items/RE-008-locus-pmu-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

LOCUS = 0x332c430
ARM = 0x332ca3c
DUPLICATE = 0x3330010
SLOT = 0x64dfeb0
READER = 0x14b7aa0
TABLE = 0x462eb4
ERROR_BUILDER = 0x3046740
NAME = 0x794eb4
TEMPLATE = 0x4325c4
FLOAT_ERROR = 0x15165f0
BOOL_ERROR = 0x1513c80

PINS = {   # address -> (bytes, meaning)
    ARM: ('4883bc24a000000001', 'arm 14: seen flag compared with 1'),
    0x332d80f: ('488dbc24700c00004c89fe', 'arm 14: result buffer and reader state'),
    0x332d820: ('0fb68424700c0000488b8c24780c00003c09', 'arm 14: result tag compared with 9'),
    0x332d838: ('48898c24a8020000b801000000488984 24a0000000'.replace(' ', ''),
                'arm 14: 8-byte value kept at rsp+0x2a8, seen flag set to 1'),
    0x333001f: ('48c78424f802000003000000', 'duplicate: name length 3'),
    0x332fb72: ('f68424a000000001757a', 'end: seen flag tested'),
    0x332fb8b: ('48c78424e000000003000000', 'missing: name length 3'),
    0x14b7aa5: ('440fb6c2418d8040ffffff83f820774b', 'reader: marker - 0xc0, at most 0x20'),
    0x14b7abc: ('496304804c01c0', 'reader: table load'),
    0x14b7b09: ('c60702885701884f02', 'reader: other marker -> error tag 2'),
    0x14b7b9e: ('84c90f889f0100000fb6c148894708', 'reader: fixint >= 0 kept, < 0 rejected'),
    0x14b7cff: ('480fca48894610 48894e18 48895708'.replace(' ', ''), 'reader: u64 read big-endian'),
    0x14b7d0e: ('c60709', 'reader: success tag 9'),
    0x14b7cb1: ('4885d27954', 'reader: i64 kept only when >= 0'),
    0x14b7d5a: ('c644243802', 'reader: unexpected signed integer, tag 2'),
    0x15165f8: ('f30f5ac0f20f11442440c644243803', 'f32: widened, unexpected float tag 3'),
    0x1513c88: ('40887424 39c644243800'.replace(' ', ''), 'bool: unexpected bool tag 0'),
}
# call / jump site -> (opcode bytes, instruction length, target)
JUMPS = {
    0x332ca45: ('0f84', 6, DUPLICATE),
    0x332fbcd: ('e8', 5, ERROR_BUILDER),
    0x14b7ba0: ('0f88', 6, 0x14b7d45),
    0x14b7d37: ('e8', 5, BOOL_ERROR),
}
# lea site -> (target, string expected there or None)
LEAS = {
    DUPLICATE: (NAME, b'pmu'),
    0x332fb7c: (NAME, b'pmu'),
    0x332fbb6: (TEMPLATE, b'\x0fmissing field `'),
    0x14b7ab5: (TABLE, None),
}
SLOT_CALL = 0x332d81a
# marker -> (table target, meaning)
MARKERS = {
    0xc0: (0x14b7d1a, 'nil rejected'),
    0xc1: (0x14b7b09, 'unused marker rejected'),
    0xc2: (0x14b7d2f, 'false rejected'),
    0xc3: (0x14b7d2b, 'true rejected'),
    0xca: (0x14b7ac5, 'f32 rejected'),
    0xcc: (0x14b7b77, 'u8'),
    0xcd: (0x14b7be9, 'u16'),
    0xce: (0x14b7b54, 'u32'),
    0xcf: (0x14b7cc0, 'u64'),
    0xcb: (0x14b7c1e, 'f64 (body not pinned)'),
    0xd0: (0x14b7c5c, 'i8'),
    0xd1: (0x14b7bb2, 'i16'),
    0xd2: (0x14b7b1b, 'i32'),
    0xd3: (0x14b7c8d, 'i64'),
    0xe0: (0x14b7b9e, 'fixint'),
}
# site -> function that holds it (from .eh_frame_hdr)
HOLDERS = {
    ARM: LOCUS, SLOT_CALL: LOCUS, DUPLICATE: LOCUS, 0x332fb72: LOCUS, 0x332fbcd: LOCUS,
    0x14b7ab5: READER, 0x14b7d0e: READER, 0x14b7d5a: READER, 0x1516602: FLOAT_ERROR,
    0x1513c8d: BOOL_ERROR,
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


def jumps(data):
    out = {}
    for site, (op, length, target) in JUMPS.items():
        if read_va(data, site, len(op) // 2) != bytes.fromhex(op) or rel_target(data, site, length) != target:
            raise ValueError(f'branch at {site:#x} is not to {target:#x}')
        out[hex(site)] = hex(target)
    return out


def leas(data):
    out = {}
    for site, (target, text) in LEAS.items():
        if read_va(data, site, 3)[1:2] != b'\x8d' or rel_target(data, site, 7) != target:
            raise ValueError(f'lea at {site:#x} is not to {target:#x}')
        if text is not None and read_va(data, target, len(text)) != text:
            raise ValueError(f'string at {target:#x} is not {text!r}')
        out[hex(site)] = hex(target)
    return out


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


def slot_call(data):
    if read_va(data, SLOT_CALL, 2) != b'\xff\x15' or rel_target(data, SLOT_CALL, 6) != SLOT:
        raise ValueError(f'call at {SLOT_CALL:#x} is not through slot {SLOT:#x}')
    target = relocation(data, SLOT)
    if target != READER:
        raise ValueError(f'slot {SLOT:#x} is relocated to {target:#x}, not {READER:#x}')
    return {'site': hex(SLOT_CALL), 'slot': hex(SLOT), 'relocated_to': hex(target)}


def markers(data):
    out = {}
    for marker, (target, meaning) in MARKERS.items():
        got = TABLE + struct.unpack('<i', read_va(data, TABLE + 4 * (marker - 0xc0), 4))[0]
        if got != target:
            raise ValueError(f'table entry for marker {marker:#x} is {got:#x}, not {target:#x}')
        out[hex(marker)] = {'arm': hex(got), 'meaning': meaning}
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
        'field': {'locus_index': 14, 'key': 'pmu', 'arm': hex(ARM), 'visitor': hex(LOCUS)},
        'value': {
            'reader': slot_call(data),
            'kind': 'u64 visitor: non-negative integers kept; negative, float, bool and nil rejected',
            'stored_at': 'rsp+0x2a8 (8 bytes)',
            'markers': markers(data),
        },
        'duplicate': {'branch': hex(DUPLICATE), 'name': 'pmu'},
        'missing': {'error_builder': hex(ERROR_BUILDER), 'template': hex(TEMPLATE),
                    'default': 'none'},
        'branches': jumps(data),
        'references': leas(data),
        'holders': holders(data),
        'meaning_of_pmu_name': 'not proven',
        'links': {'locus_arms': '#6589'},
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
    print(f"pins={result['pins']} markers={len(result['value']['markers'])} "
          f"reader={result['value']['reader']['relocated_to']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
