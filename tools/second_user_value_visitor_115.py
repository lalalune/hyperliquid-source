#!/usr/bin/env python3
"""Node #115 function 0x30bcb40: a second visitor of the per-user value.

Open PR #6581 found that 0x30bcb40 holds both direct calls to 0x3184540, a
second decoder of the per-user `p` value, and left 0x30bcb40 unmapped. This
tool checks:

1. 0x30bcb40 reads each key through slot 0x64dfca8. For a 1-byte key it
   subtracts 0x44 ('D'), bounds the result to 0x31 and jumps through table
   0x6857e0. A second path (0x30bd16f) does the same through table
   0x685718. In both tables `u` gives index 0 (`xor eax,eax`), `p` 1, `D` 2,
   `l` 3, `S` 4 and `r` 5 (`mov al,k`). Every other character, and every key
   that is not 1 byte long, gives 6.
2. The index selects an arm through table 0x6858a8:
   0 u: `call 0x2f6b730` with the 4-byte name `Ntli`, result tag 9;
   1 p: `call 0x3184540` (0x30bd552) after a not-seen check;
   2 D: `call 0x3215260`;
   3 l: `call 0x2f6fa30` with the 4-byte name `Time`, result tag 9;
   4 S: `call 0x31c32d0`, result tag 9;
   5 r: `call [0x64e2580]`;
   6 other: `call 0x31d5e50` (skip), result tag 9.
3. A repeated key goes to a `duplicate field` error that names the key:
   `p`, `D`, `r`, `u`, `l` or `S`.
4. The key order and names are those of the per-user value visitor 0x1a212f0
   in #6239 (u 0, p 1, D 2, l 3, S 4, r 5), and the `r` arm uses the same
   integer slot 0x64e2580. So 0x30bcb40 is a second visitor of the same
   per-user value, built for the tag-9 result type of #6580 and #6581.
5. The second call to 0x3184540 (0x30be015) is also in 0x30bcb40. It is
   counted, not mapped. 0x30bcb40 has one direct caller, 0x3314f4e in
   0x3314a40, which is counted, not mapped.

The tool only compares fixed bytes at fixed addresses, jump-table entries,
branch and call targets, RIP-relative slot and string references, function
starts from .eh_frame_hdr, a count of direct `call rel32` instructions in
.text, and strings. The captured binary is not executed. objdump and readelf
are not started. Addresses are ELF virtual addresses.
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
PACKET = ROOT / 'research/work-items/RE-008-second-user-value-visitor-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

VISITOR = 0x30bcb40
P_DECODER = 0x3184540
UPPER = 0x3314a40
KEY_TABLES = (0x6857e0, 0x685718)
KEY_BASE, KEY_SPAN = 0x44, 0x32
FIELD_TABLE = 0x6858a8
OTHER = 6
NAMES = ('u', 'p', 'D', 'l', 'S', 'r')

PINS = {   # address -> (bytes, meaning)
    0x30bd0fb: ('ff15a72b420383bc24f0000000017546b0064183fc010f8500040000410fb60f83c1bc'
                '83f931488b7c24080f87f0030000488d15ad865cfd48630c8a4801d1ffe1',
                'key via slot 0x64dfca8; default index 6; 1-byte key - 0x44 through 0x6857e0'),
    0x30bd51c: ('0fb6c0488d0d82835cfd486304814801c8ffe0',
                'index in al through field table 0x6858a8'),
    0x30bce79: ('b904000000488dbc24f00000004c89f6488d1508d239fde89be8eaff0fb68424f0000000'
                '4883f809488b7c24080f85d6150000',
                'u arm: name Ntli (4), call 0x2f6b730, tag 9'),
    0x30bd52f: ('48b801000000000000804839c50f85ca1500004889c5488dbc24f00000004c89f631d2'
                'e8e96f0c00',
                'p arm: not-seen check, call 0x3184540'),
    0x30bd636: ('48b8010000000000008048394424500f8557150000410fb65624488dbc24f00000004c89'
                'f6e8007c1500',
                'D arm: not-seen check, call 0x3215260'),
    0x30bd6b8: ('b904000000488dbc24f00000004c89f6488d15a9c839fde85c23ebff0fb68424f0000000'
                '4883f809488b7c24080f85060f0000',
                'l arm: name Time (4), call 0x2f6fa30, tag 9'),
    0x30bd5f9: ('4883bc2478010000010f84ed170000488dbc24f00000004c89f631d2e8b65c10000fb684'
                '24f00000004883f809488b7c24080f8430f7ffff',
                'S arm: seen check, call 0x31c32d0, tag 9'),
    0x30bd789: ('0fb6d10fb6c8488dbc24f00000004c89f6ff15e04d4203',
                'r arm: call through slot 0x64e2580'),
    0x30bd5cc: ('488dbc24f00000004c89f6ba01000000e86f88110080bc24f000000009488b7c24080f84'
                '9af7ffff',
                'other key: call 0x31d5e50, tag 9'),
}

# call / jump site -> (opcode bytes, instruction length, target)
JUMPS = {0x30bce90: ('e8', 5, 0x2f6b730), 0x30bd552: ('e8', 5, P_DECODER),
         0x30bd65b: ('e8', 5, 0x3215260), 0x30bd6cf: ('e8', 5, 0x2f6fa30),
         0x30bd615: ('e8', 5, 0x31c32d0), 0x30bd5dc: ('e8', 5, 0x31d5e50),
         0x30be015: ('e8', 5, P_DECODER)}
# indirect call site -> slot
SLOTS = {0x30bd0fb: 0x64dfca8, 0x30bd79a: 0x64e2580}
# lea site -> (address, length, text)
LEAS = {0x30bce89: (0x45a098, 4, 'Ntli'), 0x30bd6c8: (0x459f78, 4, 'Time'),
        0x30beb81: (0x43351a, 18, '\x11duplicate field `'),
        0x30beb47: (0x7939dc, 1, 'p'), 0x30bebdd: (0x794ccb, 1, 'D'),
        0x30bec6e: (0x793504, 1, 'r'), 0x30bed04: (0x7936ed, 1, 'u'),
        0x30bed9a: (0x7932e9, 1, 'l'), 0x30bee30: (0x7948ff, 1, 'S')}
# field index -> arm start (from FIELD_TABLE)
ARMS = {0: 0x30bce6a, 1: 0x30bd52f, 2: 0x30bd636, 3: 0x30bd6aa,
        4: 0x30bd5f9, 5: 0x30bd70e, 6: 0x30bd5cc}
# call site -> function that holds it (from .eh_frame_hdr)
HOLDERS = {0x30bd0fb: VISITOR, 0x30bd552: VISITOR, 0x30be015: VISITOR,
           0x30bd79a: VISITOR, 0x3314f4e: UPPER}
# function -> its direct `call rel32` sites in .text
CALLERS = {P_DECODER: (0x30bd552, 0x30be015), VISITOR: (0x3314f4e,)}


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


def table_entry(data, table, index):
    return table + struct.unpack('<i', read_va(data, table + 4 * index, 4))[0]


def pin_check(data):
    for va, (want, meaning) in PINS.items():
        raw = bytes.fromhex(want)
        if read_va(data, va, len(raw)) != raw:
            raise ValueError(f'instruction bytes changed at {va:#x} ({meaning})')


def key_index(data, target):
    """Index an entry of a key table selects: `xor eax,eax` -> 0, `mov al,k` -> k,
    any other first instruction -> the default index 6 already in al."""
    head = read_va(data, target, 2)
    if head == b'\x31\xc0':
        return 0
    if head[0] == 0xb0:
        return head[1]
    return OTHER


def key_tables(data):
    out = {}
    for table in KEY_TABLES:
        found = {}
        for i in range(KEY_SPAN):
            k = key_index(data, table_entry(data, table, i))
            if k != OTHER:
                found[chr(KEY_BASE + i)] = k
        want = {name: i for i, name in enumerate(NAMES)}
        if found != want:
            raise ValueError(f'key table {table:#x} gives {found}, not {want}')
        out[hex(table)] = found
    return out


def field_table(data):
    out = {}
    for index, arm in ARMS.items():
        got = table_entry(data, FIELD_TABLE, index)
        if got != arm:
            raise ValueError(f'field table {FIELD_TABLE:#x} entry {index} is {got:#x}, not {arm:#x}')
        out[str(index)] = hex(arm)
    return out


def jumps(data):
    out = {}
    for site, (op, length, target) in JUMPS.items():
        if read_va(data, site, len(op) // 2) != bytes.fromhex(op) or rel_target(data, site, length) != target:
            raise ValueError(f'branch at {site:#x} is not to {target:#x}')
        out[hex(site)] = hex(target)
    return out


def slots(data):
    out = {}
    for site, slot in SLOTS.items():
        if read_va(data, site, 2) != b'\xff\x15' or rel_target(data, site, 6) != slot:
            raise ValueError(f'indirect call at {site:#x} is not through {slot:#x}')
        out[hex(site)] = hex(slot)
    return out


def leas(data):
    out = {}
    for site, (addr, length, text) in LEAS.items():
        if read_va(data, site + 1, 1) != b'\x8d' or rel_target(data, site, 7) != addr:
            raise ValueError(f'lea at {site:#x} is not to {addr:#x}')
        if read_va(data, addr, length) != text.encode():
            raise ValueError(f'string at {addr:#x} is not {text!r}')
        out[hex(site)] = {'address': hex(addr), 'text': text}
    return out


def holders(data):
    _, entries = unwind_index(data)
    starts = [e['start'] for e in entries]
    out = {}
    for site, func in HOLDERS.items():
        i = bisect.bisect_right(starts, site) - 1
        if i < 0 or starts[i] != func or not site < entries[i]['next_index_upper_bound']:
            raise ValueError(f'call site {site:#x} is not in function {func:#x}')
        out[hex(site)] = hex(func)
    return out


def callers(data):
    text = [s for s in sections(data) if s['name'] == '.text' and s['type'] != 8]
    if len(text) != 1:
        raise ValueError('expected one .text section')
    sec = text[0]
    body = data[sec['offset']:sec['offset'] + sec['size']]
    base = sec['address']
    found = {f: [] for f in CALLERS}
    pos = body.find(b'\xe8')
    while 0 <= pos <= len(body) - 5:
        target = base + pos + 5 + struct.unpack_from('<i', body, pos + 1)[0]
        if target in found:
            found[target].append(base + pos)
        pos = body.find(b'\xe8', pos + 1)
    out = {}
    for func, want in CALLERS.items():
        if tuple(found[func]) != want:
            raise ValueError(f'direct callers of {func:#x} are '
                             f'{[hex(x) for x in found[func]]}, not {[hex(x) for x in want]}')
        out[hex(func)] = [hex(x) for x in want]
    return out


def bind(data):
    pin_check(data)
    return {
        'target': {'path': RELATIVE, 'sha256': SHA256},
        'visitor': hex(VISITOR),
        'keys': key_tables(data),
        'other_key_index': OTHER,
        'field_table': {'address': hex(FIELD_TABLE), 'arms': field_table(data)},
        'fields': {'0': {'key': 'u', 'reader': '0x2f6b730', 'name': 'Ntli'},
                   '1': {'key': 'p', 'reader': hex(P_DECODER)},
                   '2': {'key': 'D', 'reader': '0x3215260'},
                   '3': {'key': 'l', 'reader': '0x2f6fa30', 'name': 'Time'},
                   '4': {'key': 'S', 'reader': '0x31c32d0'},
                   '5': {'key': 'r', 'reader_slot': '0x64e2580'},
                   '6': {'key': None, 'reader': '0x31d5e50', 'note': 'skip'}},
        'ok_tag': 9,
        'branches': jumps(data),
        'slots': slots(data),
        'leas': leas(data),
        'holders': holders(data),
        'direct_callers': callers(data),
        'upper_boundary': {'function': hex(UPPER), 'mapped': False},
        'links': {'second_p_decoder': '#6581', 'first_user_value_visitor': '#6239'},
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
    print(f"pins={result['pins']} visitor={result['visitor']} "
          f"keys={result['keys']['0x6857e0']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
