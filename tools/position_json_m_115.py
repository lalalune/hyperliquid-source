#!/usr/bin/env python3
"""Node #115 position field M in the JSON reader: 0 is rejected and missing M is 20.

Open PR #6577 found that the per-user value has a pretty JSON writer and a
JSON reader 0x402e7c0 whose field matcher 0x4455890 gives the position keys
the same indices as the MessagePack decoder (#6453). Open PR #6456 found
that the MessagePack decoder rejects an M of 0 and reads a missing M as 20.
This tool checks the same two rules in the JSON reader:

1. After the matcher, 0x402e7c0 jumps through table 0x7c01c0 by field
   index. Index 2 (M) goes to 0x402eb63. That arm treats a stored 0 as
   "not seen" (`cmp dword [rsp+0x50],0`) and reports a second M as a
   duplicate field with the name `M`.
2. After `:`, the arm calls the M value reader 0x3ef32a0 and keeps the
   4-byte result at rsp+0x50. The sequence form reads its third element
   with the same function.
3. 0x3ef32a0 parses a JSON number with 0x3ef2440. A positive or negative
   integer passes only in the range 1..0xffffffff (the same range test as
   the MessagePack u64 and i64 arms). Any other integer, 0 included, goes
   to slot 0x64e0910 with Unexpected tag 1 (unsigned) or 2 (signed); any
   other number goes to slot 0x64e0900 with tag 3. Both calls pass the
   expected vtable 0x646c050. Its format entry (0x646c068) is relocated
   to 0x38dbaa0, which writes `a nonzero u32`. The MessagePack decoder in
   #6456 uses the same vtable.
4. At the end of the map, a 0 (not seen) M becomes 0x14 (20). The sequence
   form also starts M at 0x14. The result stores M at +0x38.

The tool only compares fixed bytes at fixed addresses, jump-table entries,
branch and call targets, relocation values and strings. The captured binary
is not executed. objdump and readelf are not started. Addresses are ELF
virtual addresses.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-position-json-m-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

READER = 0x402e7c0
MATCHER = 0x4455890
FIELD_TABLE = 0x7c01c0
FIELD_ARMS = (0x402ea75, 0x402ec1b, 0x402eb63, 0x402ebbd, 0x402eaec, 0x402ec73)
M_ARM = 0x402eb63
M_READ = 0x3ef32a0
NUMBER = 0x3ef2440
INVALID_VALUE_SLOT = 0x64e0910
INVALID_TYPE_SLOT = 0x64e0900
EXPECTED_VTABLE = 0x646c050
EXPECTED_FMT_SLOT = 0x646c068
EXPECTED_FMT = 0x38dbaa0
M_DEFAULT = 0x14

PINS = {   # address -> (bytes, meaning)
    0x402ea4b: ('488d7c2430e83b6e4200807c2430010f84330400000fb6442431488d0d541779fc'
                '486304814801c8ffe0',
                'reader: call matcher 0x4455890; jump by field index through 0x7c01c0'),
    0x402eb63: ('837c2450000f856e060000',
                'M arm: 0 means not seen; else duplicate field'),
    0x402ecec: ('4883fe3a0f85ab0400004885c00f84470500004989442428488d7c24084c89e6e8'
                '8f45ecff837c2408010f8488fbffff8b44240c89442450e9a7fcffff',
                'M arm after ":": call 0x3ef32a0; tag 1 is an error; keep u32 at rsp+0x50'),
    0x402eeb3: ('b9140000008b54242c0f44d18954242c448b6424504585e4440f44e1',
                'end of map: M 0 (not seen) -> 0x14'),
    0x402ef42: ('b91400000041bc14000000',
                'sequence form: M starts as 0x14'),
    0x402ef75: ('488b742430488d7c2408e81c43ecff837c2408010f84c9000000448b64240c',
                'sequence form: element read with 0x3ef32a0'),
    0x402f0be: ('44896338',
                'result: M stored at +0x38'),
    0x3ef3343: ('e8f8f0ffff488b4c24284883f9037541488b442430',
                'M read: parse number with 0x3ef2440; kind 3 passes an error'),
    0x3ef3394: ('488b44243083f901742783f902754748b900000000ffffffff488d140848ffc148'
                '39ca73224889442418c644241002eb6248b900000000ffffffff488d140848ffc1'
                '4839ca724289430431c089034883c4385b415ec3',
                'M read: unsigned and signed pass only 1..0xffffffff; signed failure is tag 2'),
    0x3ef33ea: ('4889442418c644241003488d15558c5702488d7c2410488d74240fff15f5d45e02',
                'M read: other number is tag 3, expected vtable 0x646c050, slot 0x64e0900'),
    0x3ef341d: ('4889442418c644241001488d15228c5702488d7c2410488d74240fff15d2d45e02',
                'M read: unsigned failure is tag 1, expected vtable 0x646c050, slot 0x64e0910'),
    0x38dbaa0: ('488b3e488b4608488b4018488d35fb9606fdba0d000000ffe0',
                'expected text: a nonzero u32 (13)'),
}

# call / jump site -> (opcode bytes, instruction length, target)
JUMPS = {0x402ea50: ('e8', 5, MATCHER), 0x402eb68: ('0f85', 6, 0x402f1dc),
         0x402ed0c: ('e8', 5, M_READ), 0x402ef7f: ('e8', 5, M_READ),
         0x3ef3343: ('e8', 5, NUMBER)}
# rip-relative call site -> slot
SLOT_CALLS = {0x3ef3405: INVALID_TYPE_SLOT, 0x3ef3438: INVALID_VALUE_SLOT}
RELOCATED = {INVALID_VALUE_SLOT: 0x5c54c30, INVALID_TYPE_SLOT: 0x5c54bd0,
             EXPECTED_FMT_SLOT: EXPECTED_FMT}
# lea site -> (address, length, text or None for a non-string target)
LEAS = {0x402f1dc: (0x7c26e9, 1, 'M'), 0x38dbaab: (0x9451ad, 13, 'a nonzero u32'),
        0x3ef33f4: (EXPECTED_VTABLE, 0, None), 0x3ef3427: (EXPECTED_VTABLE, 0, None)}
# Second matcher 0x4455970 (caller 0x32d3c90): the same key code, a different ok tag.
SECOND = {'leverage_compare': (0x44558d8, 0x44559b8, 13),
          'szi_compare': (0x44558f0, 0x44559d0, 21),
          'entry_ntl_compare': (0x445590e, 0x44559ee, 26),
          'ok_tag': {0x44558d4: 'c60000', 0x44559b4: 'c60009'}}


def read_va(data, va, size):
    hits = [s for s in sections(data)
            if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(hits) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = hits[0]['offset'] + va - hits[0]['address']
    return data[off:off + size]


def rel_target(data, va, length):
    width = 1 if length == 2 else 4
    fmt = '<b' if width == 1 else '<i'
    return va + length + struct.unpack(fmt, read_va(data, va + length - width, width))[0]


def relative_relocations(data):
    rel = {}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise ValueError(f"relocation section {sec['name']} is truncated")
        for va, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if info & 0xffffffff == 8:
                rel[va] = addend
    return rel


def pin_check(data):
    for va, (want, meaning) in PINS.items():
        raw = bytes.fromhex(want)
        if read_va(data, va, len(raw)) != raw:
            raise ValueError(f'instruction bytes changed at {va:#x} ({meaning})')


def field_table(data):
    arms = tuple(FIELD_TABLE + struct.unpack('<i', read_va(data, FIELD_TABLE + 4 * i, 4))[0]
                 for i in range(len(FIELD_ARMS)))
    if arms != FIELD_ARMS:
        raise ValueError('field table 0x7c01c0 changed')
    if arms[2] != M_ARM:
        raise ValueError('field index 2 (M) does not go to the M arm')
    return {str(i): hex(a) for i, a in enumerate(arms)}


def jumps(data):
    out = {}
    for site, (op, length, target) in JUMPS.items():
        if read_va(data, site, len(op) // 2) != bytes.fromhex(op) or rel_target(data, site, length) != target:
            raise ValueError(f'branch at {site:#x} is not to {target:#x}')
        out[hex(site)] = hex(target)
    return out


def slots(data):
    rel = relative_relocations(data)
    out = {}
    for site, slot in SLOT_CALLS.items():
        raw = read_va(data, site, 6)
        if raw[:2] != b'\xff\x15' or site + 6 + struct.unpack('<i', raw[2:])[0] != slot:
            raise ValueError(f'call at {site:#x} is not through slot {slot:#x}')
        out[hex(site)] = hex(slot)
    for slot, target in RELOCATED.items():
        if rel.get(slot) != target:
            raise ValueError(f'slot {slot:#x} is not relocated to {target:#x}')
        out[hex(slot)] = hex(target)
    return out


def leas(data):
    out = {}
    for site, (addr, length, text) in LEAS.items():
        if read_va(data, site + 1, 1) != b'\x8d' or rel_target(data, site, 7) != addr:
            raise ValueError(f'lea at {site:#x} is not to {addr:#x}')
        if text is not None and read_va(data, addr, length) != text.encode():
            raise ValueError(f'string at {addr:#x} is not {text!r}')
        out[hex(site)] = {'address': hex(addr), 'text': text}
    return out


def second_matcher(data):
    out = {}
    for name, value in SECOND.items():
        if name == 'ok_tag':
            for site, raw in value.items():
                if read_va(data, site, 3) != bytes.fromhex(raw):
                    raise ValueError(f'ok tag changed at {site:#x}')
            continue
        first, second, length = value
        if read_va(data, first, length) != read_va(data, second, length):
            raise ValueError(f'{name}: the two matchers differ')
        out[name] = 'same bytes'
    out['ok_tag'] = {'0x4455890': 0, '0x4455970': 9}
    return out


RANGE = bytes.fromhex('48b900000000ffffffff488d140848ffc14839ca')
# kind -> (range test site, branch site, branch opcode, branch length, target, meaning)
RANGE_TESTS = {1: (0x3ef33c5, 0x3ef33d9, '72', 2, 0x3ef341d, 'below the range -> tag 1 error'),
               2: (0x3ef33a3, 0x3ef33b7, '73', 2, 0x3ef33db, 'in the range -> keep the u32')}
KIND_TESTS = {0x3ef3399: ('83f901', 0x3ef339c, '74', 2, 0x3ef33c5),
              0x3ef339e: ('83f902', 0x3ef33a1, '75', 2, 0x3ef33ea)}


def m_read_range(data):
    out = {}
    for site, (cmp, br, op, length, target) in KIND_TESTS.items():
        if read_va(data, site, 3) != bytes.fromhex(cmp) or read_va(data, br, 1) != bytes.fromhex(op) \
                or rel_target(data, br, length) != target:
            raise ValueError(f'number kind test changed at {site:#x}')
    for kind, (site, br, op, length, target, meaning) in RANGE_TESTS.items():
        if read_va(data, site, len(RANGE)) != RANGE:
            raise ValueError(f'kind {kind}: range test changed at {site:#x}')
        if read_va(data, br, 1) != bytes.fromhex(op) or rel_target(data, br, length) != target:
            raise ValueError(f'kind {kind}: range branch at {br:#x} changed')
        out[str(kind)] = meaning
    return out


def bind(data):
    pin_check(data)
    return {
        'target': {'path': RELATIVE, 'sha256': SHA256},
        'reader': hex(READER),
        'field_table': field_table(data),
        'm_arm': {'arm': hex(M_ARM), 'not_seen': 0, 'duplicate_name': 'M',
                  'value_read': hex(M_READ), 'default': M_DEFAULT, 'stored_at': '+0x38'},
        'm_read': {'number_parse': hex(NUMBER), 'accepts': '1..0xffffffff',
                   'range_tests': m_read_range(data),
                   'rejects': {'integer outside 1..0xffffffff (0 included)':
                               'slot 0x64e0910, Unexpected tag 1 or 2',
                               'other number': 'slot 0x64e0900, Unexpected tag 3'},
                   'expected': 'vtable 0x646c050 -> 0x38dbaa0 writes "a nonzero u32"'},
        'branches': jumps(data),
        'slots': slots(data),
        'leas': leas(data),
        'second_matcher': second_matcher(data),
        'same_as_msgpack': {'not_seen': 0, 'default': M_DEFAULT,
                            'expected_vtable': hex(EXPECTED_VTABLE), 'range': '1..0xffffffff'},
        'links': {'json_writer_reader': '#6577', 'msgpack_m_rules': '#6456'},
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
    print(f"pins={result['pins']} m_arm={result['m_arm']['arm']} "
          f"default={result['m_arm']['default']:#x} accepts={result['m_read']['accepts']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
