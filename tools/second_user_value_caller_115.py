#!/usr/bin/env python3
"""Node #115: the path above the second per-user value visitor 0x30bcb40.

Open PR #6582 found that 0x30bcb40 is a second visitor of the per-user value
{u, p, D, l, S, r} and that its only direct caller is 0x3314f4e in 0x3314a40.
This tool checks the functions above it, one direct call at a time:

1. 0x3314a40 reads a tuple of two elements: element 0 through 0x32e36c0 with
   length 0x14 (20), element 1 through 0x30bcb40. A wrong length reports
   `invalid length` with the expected text `a tuple of size 2`.
2. 0x470e6c0, its only direct caller, reads a sequence of those tuples. It caps
   the first allocation at 0x1c71 entries of 0x98 bytes, then for each element
   calls 0x3314a40, 0x4717440 and 0x3ecd9a0.
3. 0x3216f80, the only direct caller of 0x470e6c0, sends a MessagePack array
   (0x90..0x9f) to 0x470e6c0 and a map (0x80..0x8f) to 0x45dd2b0. 0x45dd2b0
   reports `invalid type` with Unexpected tag 0xb (map) and the expected text
   `a sequenced map`. So the field is a map written as a sequence of
   (key, value) pairs; a MessagePack map is refused.
4. 0x32daf90 calls 0x3216f80 for field 0. Its key matcher 0x4458570 gives
   user_to_state 0, users_with_positions 1,
   check_all_users_for_liquidatables 2, asset_to_oi and asset_to_oi_szi 3,
   open_order_tracker 4, ar 5 and any other key 6.
5. 0x3274e70 calls 0x32daf90 for field 1. Its key matcher 0x445d0d0 gives
   user_states 1, and 0x13 (19) for any other key.

So the second visitor reads the values of user_states.user_to_state, the same
field path as the first chain in #6577 (user_states -> user_to_state). The
caller of 0x3274e70 (0x389a09e in 0x3899fe0) is counted, not mapped.

The tool only compares fixed bytes at fixed addresses, jump-table entries,
branch and call targets, RIP-relative references, one relocation, function
starts from .eh_frame_hdr, a count of direct `call rel32` instructions in
.text, and strings. Key names are spelled from the `cmp byte [rsi+k],c`
instructions of each matcher arm. The captured binary is not executed.
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
PACKET = ROOT / 'research/work-items/RE-008-second-user-value-caller-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

VISITOR = 0x30bcb40      # second per-user value visitor (#6582)
TUPLE = 0x3314a40
SEQUENCE = 0x470e6c0
SEQ_MAP = 0x3216f80
MAP_ERROR = 0x45dd2b0
USER_STATES = 0x32daf90
CLEARINGHOUSE = 0x3274e70
UPPER = 0x3899fe0

PINS = {   # address -> (bytes, meaning)
    0x3314a9a: ('3c90730a240f4189c0e99b0000003ca0730a240f4189c0e909010000',
                'tuple reader: fixmap -> 0x3314b43, fixarray -> 0x3314bbf'),
    0x3314c26: ('48c78424c000000014000000488dbc24a0010000488d9424b00000004889b424f8000000'
                'b901000000e86ceafcff0fb68424a00100003c090f85e9010000',
                'tuple element 0: length 0x14, call 0x32e36c0, tag 9'),
    0x3314f26: ('83fd010f843d0700000f29842440020000448854240544884c2406488dbc24a0010000'
                '4c89c631d2e8ed7bdaff',
                'tuple element 1: one element only -> 0x331566c; call 0x30bcb40'),
    0x3315637: ('488d7c2440488d0d5de91403488d54240731f6',
                'invalid length 0, expected 0x6463fa0'),
    0x331566c: ('488d7c2440488d0d28e91403488d542407be01000000e809a8c6ff',
                'invalid length 1, expected 0x6463fa0, call 0x2f7fe90'),
    0x38db60b: ('488d357e4decfcba11000000ffe0',
                'expected text 0x7a0390, length 0x11'),
    0x470e6d6: ('448b76084181fe711c0000bb711c0000',
                'first capacity min(len, 0x1c71)'),
    0x470e728: ('4c69fb980000004c89ffff15480ddd01',
                'allocation capacity * 0x98'),
    0x470e7f0: ('41ffce488b44245844897008488dbc2438020000488b74246031d2e83062c0fe',
                'per element: call 0x3314a40'),
    0x470e9c6: ('488b7c2448488b742450488d942490000000e8638a00004889ac24f0000000488dbc24'
                '38020000488d7424104889c2488d4c24704c8d8424f0000000e899ef7bff',
                'per element: call 0x4717440, then 0x3ecd9a0'),
    0x3216fd7: ('3c90730a240f4189c0e99b0000003ca0730a240f4189c0e929010000',
                'sequenced map: fixmap -> 0x3217080, fixarray -> 0x321711c'),
    0x32170ae: ('488dbc2498000000488db42408010000e8ed613c01',
                'map form: call 0x45dd2b0'),
    0x3217159: ('488dbc2498000000488db42408010000e852754f01',
                'array form: call 0x470e6c0'),
    0x45dd2b8: ('c64424380b',
                'Unexpected tag 0xb (map)'),
    0x46dd93b: ('488d35aa0d10fcba0f000000ffe0',
                'expected text 0x7de6ec, length 0xf'),
    0x32db9c0: ('e8abcb170180bc247001000009753e0fb6842471010000888424f1000000c68424f0000000'
                '09',
                'user_states visitor: key matcher 0x4458570, tag 9'),
    0x32db31a: ('0fb68424f1000000488d0d178a44fd486304814801c8ffe0',
                'user_states visitor: field index through table 0x723d40'),
    0x32db332: ('48b800000000000000804939c70f85ba2300004989c7488dbc24700100004c89f631d2'
                'e826bcf3ff',
                'field 0 arm: not-seen check, call 0x3216f80'),
    0x327614f: ('e87c6f1e0180bc246005000009753e0fb6842461050000888424b1030000c68424b003'
                '000009',
                'clearinghouse visitor: key matcher 0x445d0d0, tag 9'),
    0x3275237: ('0fb68424b1030000488d0d3a1049fd486304814801c8ffe0',
                'clearinghouse visitor: field index through table 0x706280'),
    0x3275984: ('48b8000000000000008048398424080d00000f8539310000488dbc24600500004c89f6'
                '31d2e8e2550600',
                'field 1 arm: not-seen check, call 0x32daf90'),
    0x445dd6a: ('b113884801c60009c3',
                '0x445d0d0: any other key 0x13, tag 9'),
    0x44585a6: ('884801c60009c3',
                '0x4458570: store index, tag 9'),
    0x44588c0: ('31c9884801c60009c3',
                '0x4458570: user_to_state index 0, tag 9'),
    0x44589cf: ('b106884801c60009c3',
                '0x4458570: any other key 6, tag 9'),
}

# call / jump site -> (opcode bytes, instruction length, target)
JUMPS = {0x3314c4f: ('e8', 5, 0x32e36c0), 0x3314f4e: ('e8', 5, VISITOR),
         0x3314f29: ('0f84', 6, 0x331566c), 0x3315682: ('e8', 5, 0x2f7fe90),
         0x3314a9c: ('73', 2, 0x3314aa8), 0x3314aa3: ('e9', 5, 0x3314b43),
         0x3314ab1: ('e9', 5, 0x3314bbf),
         0x470e80b: ('e8', 5, TUPLE), 0x470e9d8: ('e8', 5, 0x4717440),
         0x470ea02: ('e8', 5, 0x3ecd9a0),
         0x3216fe0: ('e9', 5, 0x3217080), 0x3216fee: ('e9', 5, 0x321711c),
         0x32170be: ('e8', 5, MAP_ERROR), 0x3217169: ('e8', 5, SEQUENCE),
         0x45dd30f: ('e8', 5, 0x3046740),
         0x32db9c0: ('e8', 5, 0x4458570), 0x32db355: ('e8', 5, SEQ_MAP),
         0x327614f: ('e8', 5, 0x445d0d0), 0x32759a9: ('e8', 5, USER_STATES)}
# lea site -> (address, text or None for a pointer-only reference)
LEAS = {0x331563c: (0x6463fa0, None), 0x3315671: (0x6463fa0, None),
        0x38db60b: (0x7a0390, 'a tuple of size 2'),
        0x45dd2cb: (0x64906f0, None),
        0x45dd303: (0x44f07a, '\x0einvalid type: '),
        0x46dd93b: (0x7de6ec, 'a sequenced map')}
# relocated pointer -> target (expected-text formatter)
RELOCS = {0x6463fb8: 0x38db600, 0x6490708: 0x46dd930}
# (table, index) -> target
TABLES = {(0x723d40, 0): 0x32db332, (0x706280, 1): 0x3275984}
# key matcher arms: (matcher, length table, length base, name, arm start, arm end, index)
KEYS = (
    (0x445d0d0, 0x7ce814, 3, 'user_states', 0x445da33, 0x445daa7, 1),
    (0x4458570, 0x7ce2c0, 2, 'user_to_state', 0x445883f, 0x44588c9, 0),
    (0x4458570, 0x7ce2c0, 2, 'users_with_positions', 0x44585ad, 0x445867b, 1),
    (0x4458570, 0x7ce2c0, 2, 'check_all_users_for_liquidatables', 0x44586ef, 0x445883f, 2),
    (0x4458570, 0x7ce2c0, 2, 'asset_to_oi', 0x445867b, 0x44586ef, 3),
    (0x4458570, 0x7ce2c0, 2, 'asset_to_oi_szi', 0x44588c9, 0x445895e, 3),
    (0x4458570, 0x7ce2c0, 2, 'open_order_tracker', 0x445895e, 0x44589cf, 4),
    (0x4458570, 0x7ce2c0, 2, 'ar', 0x4458591, 0x44585ad, 5),
)
# call site -> function that holds it (from .eh_frame_hdr)
HOLDERS = {0x3314f4e: TUPLE, 0x3314c4f: TUPLE, 0x470e80b: SEQUENCE,
           0x3217169: SEQ_MAP, 0x32170be: SEQ_MAP, 0x32db355: USER_STATES,
           0x32db1a9: USER_STATES, 0x32759a9: CLEARINGHOUSE,
           0x32766c6: CLEARINGHOUSE, 0x389a09e: UPPER}
# function -> its direct `call rel32` sites in .text
CALLERS = {VISITOR: (0x3314f4e,), TUPLE: (0x470e80b,), SEQUENCE: (0x3217169,),
           SEQ_MAP: (0x32db1a9, 0x32db355), USER_STATES: (0x32759a9, 0x32766c6),
           CLEARINGHOUSE: (0x389a09e,)}


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


def jumps(data):
    out = {}
    for site, (op, length, target) in JUMPS.items():
        if read_va(data, site, len(op) // 2) != bytes.fromhex(op) or rel_target(data, site, length) != target:
            raise ValueError(f'branch at {site:#x} is not to {target:#x}')
        out[hex(site)] = hex(target)
    return out


def leas(data):
    out = {}
    for site, (addr, text) in LEAS.items():
        if read_va(data, site, 3)[1:2] != b'\x8d' or rel_target(data, site, 7) != addr:
            raise ValueError(f'lea at {site:#x} is not to {addr:#x}')
        if text is not None and read_va(data, addr, len(text)) != text.encode():
            raise ValueError(f'string at {addr:#x} is not {text!r}')
        out[hex(site)] = {'address': hex(addr), 'text': text}
    return out


def relocations(data):
    secs = [s for s in sections(data) if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(secs) != 1 or secs[0]['size'] % 24:
        raise ValueError('unsupported dynamic relocation section')
    body = data[secs[0]['offset']:secs[0]['offset'] + secs[0]['size']]
    found = {}
    for off, info, addend in struct.iter_unpack('<QQq', body):
        if off in RELOCS:
            if off in found or info != 8:
                raise ValueError(f'ambiguous or non-relative relocation at {off:#x}')
            found[off] = addend
    out = {}
    for off, target in RELOCS.items():
        if found.get(off) != target:
            raise ValueError(f'relocation at {off:#x} is not to {target:#x}')
        out[hex(off)] = hex(target)
    return out


def tables(data):
    out = {}
    for (table, index), target in TABLES.items():
        got = table_entry(data, table, index)
        if got != target:
            raise ValueError(f'table {table:#x} entry {index} is {got:#x}, not {target:#x}')
        out[f'{table:#x}[{index}]'] = hex(target)
    return out


def spell(data, start, end):
    """Key name and index from one matcher arm: `cmp byte [rsi],c` (80 3e c),
    `cmp byte [rsi+k],c` (80 7e k c); index from `mov cl,i` (b1 i) or
    `xor ecx,ecx` (31 c9)."""
    body = read_va(data, start, end - start)
    chars, index, i = {}, None, 0
    while i < len(body):
        if body[i:i + 2] == b'\x80\x3e':
            chars[0] = body[i + 2]
            i += 3
        elif body[i:i + 2] == b'\x80\x7e':
            chars[body[i + 2]] = body[i + 3]
            i += 4
        elif body[i] == 0xb1:
            index = body[i + 1]
            i += 2
        elif body[i:i + 2] == b'\x31\xc9':
            index = 0
            i += 2
        else:
            i += 1
    if not chars or sorted(chars) != list(range(len(chars))):
        raise ValueError(f'arm {start:#x} does not compare a whole key')
    return bytes(chars[k] for k in range(len(chars))).decode(), index


def keys(data):
    out = {}
    for matcher, table, base, name, start, end, index in KEYS:
        if table_entry(data, table, len(name) - base) != start:
            raise ValueError(f'length table {table:#x} does not send length {len(name)} to {start:#x}')
        got, got_index = spell(data, start, end)
        if got != name:
            raise ValueError(f'arm {start:#x} matches {got!r}, not {name!r}')
        if got_index != index:
            raise ValueError(f'arm {start:#x} gives index {got_index}, not {index}')
        out.setdefault(hex(matcher), {})[name] = index
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
        'chain': [
            {'function': hex(CLEARINGHOUSE), 'key': 'user_states', 'index': 1,
             'calls': hex(USER_STATES)},
            {'function': hex(USER_STATES), 'key': 'user_to_state', 'index': 0,
             'calls': hex(SEQ_MAP)},
            {'function': hex(SEQ_MAP), 'array_form': hex(SEQUENCE),
             'map_form': hex(MAP_ERROR), 'map_form_error': 'a sequenced map'},
            {'function': hex(SEQUENCE), 'element': hex(TUPLE),
             'first_capacity_cap': hex(0x1c71), 'entry_bytes': hex(0x98)},
            {'function': hex(TUPLE), 'expected': 'a tuple of size 2',
             'element_0': {'reader': '0x32e36c0', 'length': hex(0x14)},
             'element_1': {'reader': hex(VISITOR)}},
        ],
        'keys': keys(data),
        'other_key_index': {'0x445d0d0': hex(0x13), '0x4458570': 6},
        'tables': tables(data),
        'branches': jumps(data),
        'leas': leas(data),
        'relocations': relocations(data),
        'holders': holders(data),
        'direct_callers': callers(data),
        'upper_boundary': {'function': hex(UPPER), 'call_site': '0x389a09e', 'mapped': False},
        'links': {'second_user_value_visitor': '#6582', 'first_chain': '#6577'},
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
    print(f"pins={result['pins']} path=user_states.user_to_state "
          f"keys={result['keys']['0x4458570']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
