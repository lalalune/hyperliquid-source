#!/usr/bin/env python3
"""Node #115: the shared S decoder 0x31c32d0 reads {s, r}, like the first S decoder.

Open PRs #6582 and #6596 showed that the second perp per-user value visitor
0x30bcb40 (arm 4) and the spot per-user value 0x3208ad0 (field 2) both read
field `S` through 0x31c32d0. Open PR #6239 showed that the first per-user value
reads `S` through 0x1adf620, which accepts only the one-byte keys `s` and `r`.
This tool checks what 0x31c32d0 reads and compares it with 0x1adf620.

1. 0x31c32d0 has four direct calls: 0x30bd615 and 0x30be296 in 0x30bcb40,
   0x32093fb and 0x3209aa0 in 0x3208ad0.
2. The first marker is compared with 0x90 and 0xa0: a fixmap goes to the map
   path, a fixarray to the sequence path 0x31c3aac. There is no "struct X with
   N elements" record in the function.
3. The map path reads each key inline. Only a key of length 1 is matched: `s`
   is field 0, `r` is field 1, any other key is field 2 and is skipped through
   0x31d5e50 (third argument 1). There are no long key names.
4. Fields 0 and 1 are read through slot 0x64e2580 (the integer read slot of
   field `r` in #6239). `s` is kept at rsp+0xa0 with seen flag rsp+0x90; `r` at
   rsp+0x98 with seen flag rsp+0x88. Both flags start at 0.
5. A repeated `s` or `r` reports its one-byte name (0x793170, 0x793504) with
   the template `duplicate field `...`` (0x43351a).
6. At the end, a field whose seen flag is still 0 is set to 0 (two `cmove`
   from a zeroed register). No field is required.
7. 0x1adf620 has the same unwind extent length as 0x31c32d0, and the same
   bytes at the key compares, the seen-flag setup, the value stores and the
   default block, at the same offsets. Its two value reads at the same offsets
   also go through slot 0x64e2580. So the shared S decoder has the S layout of
   #6239: keys `s` then `r`, integer values, 0 defaults.

The tool only compares fixed bytes at fixed addresses, branch and call
targets, RIP-relative references, function extents from .eh_frame_hdr, and
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
PACKET = ROOT / 'research/work-items/RE-008-shared-s-decoder-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

PERP_VISITOR = 0x30bcb40
SPOT_VALUE = 0x3208ad0
DECODER = 0x31c32d0
FIRST_S = 0x1adf620
SEQ_PATH = 0x31c3aac
SKIP = 0x31d5e50
DUP_S = 0x31c4238
DUP_R = 0x31c4244
NAME_S = 0x793170
NAME_R = 0x793504
DUP_FIELD = 0x43351a
INT_SLOT = 0x64e2580

PINS = {   # address -> (bytes, meaning)
    0x31c332a: ('3c90', 'first marker compared with 0x90 (fixmap below)'),
    0x31c3337: ('3ca0', 'first marker compared with 0xa0 (fixarray below)'),
    0x31c3404: ('48c784249000000000000000', 'seen flag of s starts at 0'),
    0x31c3410: ('48c784248800000000000000', 'seen flag of r starts at 0'),
    0x31c3424: ('ba01000000', 'skip an unknown key'),
    0x31c3886: ('4883fa01', 'only a key of length 1 is matched'),
    0x31c3893: ('3c72', "key byte compared with 'r'"),
    0x31c3898: ('3c73', "key byte compared with 's'"),
    0x31c37f2: ('3c72', "borrowed key byte compared with 'r'"),
    0x31c37fb: ('3c73', "borrowed key byte compared with 's'"),
    0x31c38a0: ('4883bc249000000001', 'field s arm: tests seen flag rsp+0x90'),
    0x31c3504: ('4883bc248800000001', 'field r arm: tests seen flag rsp+0x88'),
    0x31c3a41: ('48898c24a0000000', 'field s: value kept at rsp+0xa0'),
    0x31c3a49: ('b8010000004889842490000000', 'field s: seen flag set to 1'),
    0x31c3a92: ('48898c2498000000', 'field r: value kept at rsp+0x98'),
    0x31c3a9a: ('b8010000004889842488000000', 'field r: seen flag set to 1'),
    0x31c4253: ('48c744244801000000', 'duplicate name length 1'),
    0x31c3fcc: ('31c0f684249000000001488b8c24a0000000480f44c8',
                'end: s is 0 when not seen'),
    0x31c3fe2: ('f684248800000001488b942498000000480f44d0',
                'end: r is 0 when not seen'),
}

# call / jump site -> (opcode bytes, instruction length, target)
JUMPS = {
    0x30bd615: ('e8', 5, DECODER),
    0x30be296: ('e8', 5, DECODER),
    0x32093fb: ('e8', 5, DECODER),
    0x3209aa0: ('e8', 5, DECODER),
    0x31c333f: ('e9', 5, SEQ_PATH),
    0x31c3429: ('e8', 5, SKIP),
    0x31c38a9: ('0f84', 6, DUP_S),
    0x31c350d: ('0f84', 6, DUP_R),
}
# indirect call site through INT_SLOT -> field
SLOT_CALLS = {0x31c3a2a: 's', 0x31c3a7b: 'r'}
# lea site -> (target, string)
STRINGS = {
    0x31c423b: (NAME_S, b's'),
    0x31c4247: (NAME_R, b'r'),
    0x31c4271: (DUP_FIELD, b'\x11duplicate field `'),
}
# Same bytes at the same offset in DECODER and FIRST_S (non-relative bytes only).
TWIN = {
    0x134: 24,   # seen flags start at 0
    0x522: 8,    # key compare 'r' / 's'
    0x52b: 5,
    0x5c3: 7,    # key compare after length-1 check
    0x5d0: 9,    # field s arm
    0x234: 9,    # field r arm
    0x771: 21,   # field s store
    0x7c2: 21,   # field r store
    0xcfc: 42,   # defaults
}
TWIN_SLOT_OFFSETS = (0x75a, 0x7ab)


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


def extents(data):
    _, entries = unwind_index(data)
    starts = [e['start'] for e in entries]
    out = {}
    for func in (DECODER, FIRST_S):
        i = bisect.bisect_left(starts, func)
        if i == len(starts) or starts[i] != func:
            raise ValueError(f'no unwind entry starts at {func:#x}')
        out[func] = entries[i]['next_index_upper_bound'] - func
    return entries, starts, out


def twin(data):
    _, _, size = extents(data)
    if size[DECODER] != size[FIRST_S]:
        raise ValueError('decoder extents differ from the first S decoder')
    for off, n in TWIN.items():
        if read_va(data, DECODER + off, n) != read_va(data, FIRST_S + off, n):
            raise ValueError(f'bytes at offset {off:#x} differ from the first S decoder')
    for off in TWIN_SLOT_OFFSETS:
        slot_call(data, FIRST_S + off)
        if DECODER + off not in SLOT_CALLS:
            raise ValueError(f'offset {off:#x} is not a value read in the decoder')
    return {'extent': hex(size[DECODER]), 'offsets': [hex(o) for o in sorted(TWIN)],
            'slot_offsets': [hex(o) for o in TWIN_SLOT_OFFSETS]}


def holders(data):
    entries, starts, _ = extents(data)
    sites = {}
    for site in (0x30bd615, 0x30be296):
        sites[site] = PERP_VISITOR
    for site in (0x32093fb, 0x3209aa0):
        sites[site] = SPOT_VALUE
    for va in list(PINS) + [s for s in JUMPS if DECODER <= s < 0x31c4600] + \
              list(STRINGS) + list(SLOT_CALLS):
        sites[va] = DECODER
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
        'callers': {hex(PERP_VISITOR): ['0x30bd615', '0x30be296'],
                    hex(SPOT_VALUE): ['0x32093fb', '0x3209aa0']},
        'decoder': hex(DECODER),
        'shape': {'fixmap': 'inline struct visitor', 'fixarray': hex(SEQ_PATH),
                  'struct_name_record': None},
        'fields': {
            '0': {'key': 's', 'seen_flag': 'rsp+0x90', 'kept_at': 'rsp+0xa0',
                  'reader_slot': hex(INT_SLOT), 'duplicate_block': hex(DUP_S)},
            '1': {'key': 'r', 'seen_flag': 'rsp+0x88', 'kept_at': 'rsp+0x98',
                  'reader_slot': hex(INT_SLOT), 'duplicate_block': hex(DUP_R)},
            '2': {'key': '(any other key)', 'skip': hex(SKIP)},
        },
        'key_length': 'only 1-byte keys are matched; no long names',
        'missing_field': 'set to 0, not an error',
        'same_layout_as': {'pr': '#6239', 'decoder': hex(FIRST_S), 'check': twin(data)},
        'strings': strings(data),
        'branches': jumps,
        'slot_calls': slots,
        'holders_checked': holders(data),
        'links': {'perp_visitor': '#6582', 'spot_value': '#6596', 'shared_d': '#6598',
                  'first_s': '#6239'},
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
    print(f"pins={result['pins']} fields={len(result['fields'])} "
          f"holders={result['holders_checked']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
