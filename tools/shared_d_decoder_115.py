#!/usr/bin/env python3
"""Node #115: the D decoder 0x3215260 is a map from a `Date` key to {a, c}.

Open PRs #6582 and #6596 showed that the second perp per-user value visitor
0x30bcb40 and the spot per-user value 0x3208ad0 both read field `D` through
0x3215260. This tool checks what 0x3215260 reads and compares it with the
first D decoder 0x18d4f40 from open PR #6319 (a map from `Date` to {a, c}).

1. 0x3215260 has four direct calls: 0x30bd65b and 0x30be31e in 0x30bcb40,
   0x320935d and 0x3209966 in 0x3208ad0.
2. A fixmap marker (below 0x90) goes to the map visitor 0x3730e50 (call at
   0x3215395). A fixarray marker (0x90..0x9f) goes to the sequence visitor
   0x376e720 (call at 0x3215443).
3. The map visitor reads each key through 0x2f68710 with the 4-byte type name
   `Date` and each value through 0x3242730. A repeated key gives the 13-byte
   text `duplicate key`. The sequence visitor loads the same text.
4. 0x3242730 matches each one-byte key inline: `a` is field 0, `c` is
   field 1, any other key is 2. Field 2 is skipped through 0x31d5e50.
5. Fields 0 and 1 are read through slot 0x64e2580 (the integer read slot that
   field `r` of the per-user value uses in #6239). Field `a` is kept at
   rsp+0xa0 with seen flag rsp+0x90; field `c` at rsp+0x98 with seen flag
   rsp+0x88. Both flags start at 0.
6. A repeated `a` or `c` reports its one-byte name with the template
   `duplicate field `...``.
7. At the end, each field whose seen flag is still 0 is set to 0 (two `cmove`
   from a zeroed register). No field is required.

The layout is the one #6319 found for 0x18d4f40: the same key type name, the
same two keys in the same order, integer values and 0 defaults.

The tool only compares fixed bytes at fixed addresses, branch and call
targets, RIP-relative references, function starts from .eh_frame_hdr, and
strings. The captured binary is not executed. objdump and readelf are not
started. Addresses are ELF virtual addresses.
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
PACKET = ROOT / 'research/work-items/RE-008-shared-d-decoder-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

PERP_VISITOR = 0x30bcb40
SPOT_VALUE = 0x3208ad0
DECODER = 0x3215260
MAP_VISITOR = 0x3730e50
SEQ_VISITOR = 0x376e720
KEY_READER = 0x2f68710
VALUE = 0x3242730
SKIP = 0x31d5e50
ARM_A = 0x3242d00
ARM_C = 0x3242964
DUP_A = 0x3243698
DUP_C = 0x32436a4
DATE = 0x459fd0
DUP_KEY = 0x79dce8
DUP_FIELD = 0x43351a
NAME_A = 0x793f7f
NAME_C = 0x793bef
INT_SLOT = 0x64e2580

PINS = {   # address -> (bytes, meaning)
    0x32152b5: ('3c90', 'first marker compared with 0x90 (fixmap below)'),
    0x32152c3: ('3ca0', 'first marker compared with 0xa0 (fixarray below)'),
    0x3730eeb: ('b904000000', 'map key: type name length 4'),
    0x3730f07: ('3c09', 'map key: result tag 9 is success'),
    0x3730f15: ('31d2', 'map value: second argument 0'),
    0x3731051: ('ba0d000000', 'map visitor: duplicate key text length 13'),
    0x376e8f4: ('ba0d000000', 'sequence visitor: duplicate key text length 13'),
    0x3242c52: ('3c63', "value: key byte compared with 'c'"),
    0x3242c57: ('b202', 'value: other key is field 2'),
    0x3242c5b: ('3c61', "value: key byte compared with 'a'"),
    0x3242c60: ('b900000000', "value: 'a' is field 0"),
    0x3242950: ('84c0', 'value: field 0 test'),
    0x324295b: ('83f801', 'value: field 1 test'),
    0x3242864: ('48c784249000000000000000', 'value: seen flag of a starts at 0'),
    0x3242870: ('48c784248800000000000000', 'value: seen flag of c starts at 0'),
    0x3242884: ('ba01000000', 'value: skip an unknown key'),
    ARM_A: ('4883bc249000000001', 'field a arm: tests seen flag rsp+0x90'),
    ARM_C: ('4883bc248800000001', 'field c arm: tests seen flag rsp+0x88'),
    0x3242ea1: ('48898c24a0000000', 'field a: value kept at rsp+0xa0'),
    0x3242ea9: ('b80100000048898424900000', 'field a: seen flag set to 1'),
    0x3242ef2: ('48898c2498000000', 'field c: value kept at rsp+0x98'),
    0x3242efa: ('b80100000048898424880000', 'field c: seen flag set to 1'),
    0x32436b3: ('48c744244801000000', 'duplicate name length 1'),
    0x324342c: ('31c0f684249000000001488b8c24a0000000480f44c8',
                'end: a is 0 when not seen'),
    0x3243442: ('f684248800000001488b942498000000480f44d0',
                'end: c is 0 when not seen'),
}

# call / jump site -> (opcode bytes, instruction length, target)
JUMPS = {
    0x30bd65b: ('e8', 5, DECODER),
    0x30be31e: ('e8', 5, DECODER),
    0x320935d: ('e8', 5, DECODER),
    0x3209966: ('e8', 5, DECODER),
    0x3215395: ('e8', 5, MAP_VISITOR),
    0x3215443: ('e8', 5, SEQ_VISITOR),
    0x3730efd: ('e8', 5, KEY_READER),
    0x3730f17: ('e8', 5, VALUE),
    0x3242952: ('0f84', 6, ARM_A),
    0x324295e: ('0f85', 6, 0x324287e),
    0x3242889: ('e8', 5, SKIP),
    0x3242d09: ('0f84', 6, DUP_A),
    0x324296d: ('0f84', 6, DUP_C),
    0x3242d1e: ('0f85', 6, 0x3242e7e),
    0x3242982: ('0f85', 6, 0x3242ecf),
}
# indirect call site through INT_SLOT -> field
SLOT_CALLS = {0x3242e8a: 'a', 0x3242edb: 'c'}
# lea site -> (target, string)
STRINGS = {
    0x3730ef6: (DATE, b'Date'),
    0x373104a: (DUP_KEY, b'duplicate key'),
    0x376e8ed: (DUP_KEY, b'duplicate key'),
    0x324369b: (NAME_A, b'a'),
    0x32436a7: (NAME_C, b'c'),
    0x32436d1: (DUP_FIELD, b'\x11duplicate field `'),
}
HOLDER = {
    PERP_VISITOR: (0x30bd65b, 0x30be31e),
    SPOT_VALUE: (0x320935d, 0x3209966),
    DECODER: (0x32152b5, 0x32152c3, 0x3215395, 0x3215443),
    MAP_VISITOR: (0x3730eeb, 0x3730ef6, 0x3730efd, 0x3730f07, 0x3730f15, 0x3730f17,
                  0x373104a, 0x3731051),
    SEQ_VISITOR: (0x376e8ed, 0x376e8f4),
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


def jump(data, site, op, length, target):
    if read_va(data, site, len(op) // 2) != bytes.fromhex(op) or rel_target(data, site, length) != target:
        raise ValueError(f'branch at {site:#x} is not to {target:#x}')
    return hex(target)


def slot_call(data, site):
    if read_va(data, site, 2) != b'\xff\x15' or rel_target(data, site, 6) != INT_SLOT:
        raise ValueError(f'call at {site:#x} is not through slot {INT_SLOT:#x}')
    return hex(INT_SLOT)


def lea(data, site, target):
    if read_va(data, site, 3)[1:2] != b'\x8d' or rel_target(data, site, 7) != target:
        raise ValueError(f'lea at {site:#x} is not to {target:#x}')


def strings(data):
    out = {}
    for site, (target, want) in STRINGS.items():
        lea(data, site, target)
        if read_va(data, target, len(want)) != want:
            raise ValueError(f'string at {target:#x} is not {want!r}')
        out[hex(site)] = want.decode().lstrip('\x11')
    return out


def holders(data):
    _, entries = unwind_index(data)
    starts = [e['start'] for e in entries]
    sites = {}
    for func, vas in HOLDER.items():
        for va in vas:
            sites[va] = func
    for va in [v for v in PINS if VALUE <= v < 0x3243700] + \
              [s for s in JUMPS if VALUE <= s < 0x3243700] + \
              [s for s in STRINGS if VALUE <= s < 0x3243700] + list(SLOT_CALLS):
        sites[va] = VALUE
    for site, func in sites.items():
        i = bisect.bisect_right(starts, site) - 1
        if i < 0 or starts[i] != func or not site < entries[i]['next_index_upper_bound']:
            raise ValueError(f'site {site:#x} is not in function {func:#x}')
    return len(sites)


def bind(data):
    pin_check(data)
    jumps = {hex(s): jump(data, s, *v) for s, v in JUMPS.items()}
    slots = {hex(s): slot_call(data, s) for s in SLOT_CALLS}
    return {
        'target': {'path': RELATIVE, 'sha256': SHA256},
        'callers': {hex(PERP_VISITOR): ['0x30bd65b', '0x30be31e'],
                    hex(SPOT_VALUE): ['0x320935d', '0x3209966']},
        'decoder': hex(DECODER),
        'fixmap': {'map_visitor': hex(MAP_VISITOR), 'key_reader': hex(KEY_READER),
                   'key_type_name': 'Date', 'value': hex(VALUE),
                   'repeated_key': 'duplicate key'},
        'fixarray': {'sequence_visitor': hex(SEQ_VISITOR), 'repeated_key': 'duplicate key'},
        'value': {
            'function': hex(VALUE),
            'fields': {
                '0': {'key': 'a', 'arm': hex(ARM_A), 'seen_flag': 'rsp+0x90',
                      'kept_at': 'rsp+0xa0', 'reader_slot': hex(INT_SLOT),
                      'duplicate_block': hex(DUP_A)},
                '1': {'key': 'c', 'arm': hex(ARM_C), 'seen_flag': 'rsp+0x88',
                      'kept_at': 'rsp+0x98', 'reader_slot': hex(INT_SLOT),
                      'duplicate_block': hex(DUP_C)},
                '2': {'key': '(any other key)', 'skip': hex(SKIP)},
            },
            'missing_field': 'set to 0, not an error',
        },
        'same_layout_as': {'pr': '#6319', 'decoder': '0x18d4f40',
                           'matches': ['key type name Date', 'keys a then c',
                                       'integer values', 'missing field is 0']},
        'strings': strings(data),
        'branches': jumps,
        'slot_calls': slots,
        'holders_checked': holders(data),
        'links': {'perp_visitor': '#6582', 'spot_value': '#6596', 'first_d': '#6319'},
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
    print(f"pins={result['pins']} fields={len(result['value']['fields'])} "
          f"holders={result['holders_checked']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
