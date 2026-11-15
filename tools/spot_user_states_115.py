#!/usr/bin/env python3
"""Node #115: SpotClearinghouse field `user_states` is a sequenced map of a
20-byte key to a three-field value {b, D, S}.

Open PR #6594 showed that arm 1 (`user_states`) of the SpotClearinghouse
visitor 0x31b5450 calls 0x31541c0 at 0x31b62de. Open PR #6584 showed that the
perp Clearinghouse field `user_states` is read by 0x32daf90, a visitor for
`struct UserStates with 6 elements` whose field `user_to_state` is a sequenced
map. This tool checks what 0x31541c0 reads:

1. A fixmap marker (below 0x90) goes to 0x45dffb0. That function builds an
   `invalid type` error (tag 0xb) through visitor table 0x6490a30. The table
   slot 0x6490a48 is relocated to 0x46dd930, which writes the 15-byte text
   `a sequenced map`. A fixarray marker (0x90..0x9f) goes to 0x46fa510.
2. 0x46fa510 caps its first allocation at 0x2762 entries of 0x70 bytes and
   reads each element through 0x32a82b0.
3. 0x32a82b0 reads one pair from an array: an empty array is an error, the
   key is read through 0x32e36c0 with length 0x14 (the same key reader as
   #6584 and #6591), an array with only one element is an error, and the value
   is read through 0x3208ad0.
4. 0x3208ad0 reads each key through slot 0x64dfca8 and matches it inline:
   `b` is field 0, `D` is field 1, `S` is field 2, any other key is 3. It jumps
   through table 0x6e6eb4. Arm 0 calls 0x31a73f0, arm 1 calls 0x3215260, arm 2
   calls 0x31c32d0, and arm 3 calls the skip reader 0x31d5e50. A repeated key
   reports the one-byte name with the template `duplicate field `...``.
   0x3215260 and 0x31c32d0 are the same D and S decoders that the second
   per-user value visitor 0x30bcb40 calls (#6582).
5. 0x3208ad0 has no load of the template `missing field `...`` (0x4325c4).

The tool only compares fixed bytes at fixed addresses, jump-table entries,
branch and call targets, RIP-relative references, relocations, function
starts from .eh_frame_hdr, and strings. The captured binary is not executed.
objdump and readelf are not started. Addresses are ELF virtual addresses.
"""
import argparse
import bisect
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections, unwind_index

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-spot-user-states-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

SCL = 0x31b5450
SCL_CALL = 0x31b62de
DECODER = 0x31541c0
MAP_REFUSAL = 0x45dffb0
VISITOR_TABLE = 0x6490a30
EXPECTING_SLOT = 0x6490a48
EXPECTING = 0x46dd930
EXPECTED_TEXT = 0x7de6ec
SEQUENCE = 0x46fa510
PAIR = 0x32a82b0
KEY_READER = 0x32e36c0
VALUE = 0x3208ad0
KEY_SLOT = 0x64dfca8
KEY_CALL = 0x3208fb8
FIELD_TABLE = 0x6e6eb4
DUP_TEMPLATE = 0x43351a
MISSING_TEMPLATE = 0x4325c4
PERP_USER_STATES = 0x32daf90
PERP_RECORD = 0x64645c0
PERP_RECORD_LEA = 0x32dbf0f
PERP_TEXT = b'struct UserStates with 6 elements'

PINS = {   # address -> (bytes, meaning)
    0x3154217: ('3c90730a', 'first marker compared with 0x90 (fixmap below)'),
    0x3154225: ('3ca0730a', 'first marker compared with 0xa0 (fixarray below)'),
    0x45dffb8: ('c64424380b', 'map refusal: invalid-type tag 0xb'),
    0x46dd942: ('ba0f000000', 'expected text length 15'),
    0x46fa52a: ('4181fe62270000', 'sequence: first allocation capped at 0x2762'),
    0x46fa578: ('4c6bfb70', 'sequence: entry size 0x70'),
    0x32a845c: ('85ed0f84', 'pair: empty array test'),
    0x32a8496: ('48c784241001000014000000', 'pair: key length 0x14'),
    0x32a879b: ('83fd010f84', 'pair: one-element array test'),
    0x3208fca: ('83fd01', 'value: key length compared with 1'),
    0x3208fd8: ('83f944', "value: key byte compared with 'D'"),
    0x3208fe1: ('83f953', "value: key byte compared with 'S'"),
    0x3208fea: ('83f962', "value: key byte compared with 'b'"),
    0x3208ff3: ('31c0', "value: 'b' is field 0"),
    0x320930e: ('b001', "value: 'D' is field 1"),
    0x32092f5: ('b002', "value: 'S' is field 2"),
    0x3208fc8: ('b003', 'value: other key is field 3'),
}
# index -> (arm, decoder call site, decoder)
ARMS = {
    0: (0x3208d46, 0x3208d6b, 0x31a73f0),
    1: (0x3209338, 0x320935d, 0x3215260),
    2: (0x32093df, 0x32093fb, 0x31c32d0),
    3: (0x32093b4, 0x32093c4, 0x31d5e50),
}
# index -> (key, duplicate branch site, opcode, duplicate block, name lea, template lea)
DUPLICATES = {
    0: ('b', 0x3208d55, '0f85', 0x320a551, 0x320a588, 0x320a5b9),
    1: ('D', 0x3209347, '0f85', 0x320a4c8, 0x320a4ff, 0x320a530),
    2: ('S', 0x32093e8, '0f84', 0x320a43f, 0x320a476, 0x320a4a7),
}
# call / jump site -> (opcode bytes, instruction length, target)
JUMPS = {
    SCL_CALL: ('e8', 5, DECODER),
    0x31542fe: ('e8', 5, MAP_REFUSAL),
    0x31543a9: ('e8', 5, SEQUENCE),
    0x46fa65b: ('e8', 5, PAIR),
    0x32a84bf: ('e8', 5, KEY_READER),
    0x32a87c3: ('e8', 5, VALUE),
    0x3208fdb: ('0f84', 6, 0x320930e),
    0x3208fe4: ('0f84', 6, 0x32092f5),
    0x3208fed: ('0f85', 6, 0x3209325),
}
HOLDER = {DECODER: (0x3154217, 0x3154225, 0x31542fe, 0x31543a9),
          MAP_REFUSAL: (0x45dffb8, 0x45dffcb), EXPECTING: (0x46dd93b, 0x46dd942),
          SEQUENCE: (0x46fa52a, 0x46fa578, 0x46fa65b),
          PAIR: (0x32a845c, 0x32a8496, 0x32a84bf, 0x32a879b, 0x32a87c3),
          SCL: (SCL_CALL,), PERP_USER_STATES: (PERP_RECORD_LEA,)}


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


def lea(data, site, target=None):
    if read_va(data, site, 3)[1:2] != b'\x8d':
        raise ValueError(f'no lea at {site:#x}')
    got = rel_target(data, site, 7)
    if target is not None and got != target:
        raise ValueError(f'lea at {site:#x} is not to {target:#x}')
    return got


def text(data, va, want):
    if read_va(data, va, len(want)) != want:
        raise ValueError(f'string at {va:#x} is not {want!r}')


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


def map_refusal(data):
    lea(data, 0x45dffcb, VISITOR_TABLE)
    if relocation(data, EXPECTING_SLOT) != EXPECTING:
        raise ValueError(f'slot {EXPECTING_SLOT:#x} is not relocated to {EXPECTING:#x}')
    lea(data, 0x46dd93b, EXPECTED_TEXT)
    text(data, EXPECTED_TEXT, b'a sequenced map')
    return {'function': hex(MAP_REFUSAL), 'tag': 11, 'visitor_table': hex(VISITOR_TABLE),
            'expecting': hex(EXPECTING), 'expected': 'a sequenced map'}


def key_read(data):
    if read_va(data, KEY_CALL, 2) != b'\xff\x15' or rel_target(data, KEY_CALL, 6) != KEY_SLOT:
        raise ValueError(f'call at {KEY_CALL:#x} is not through slot {KEY_SLOT:#x}')
    return {'site': hex(KEY_CALL), 'slot': hex(KEY_SLOT), 'relocated_to': hex(relocation(data, KEY_SLOT))}


def table_entry(data, index):
    return FIELD_TABLE + struct.unpack('<i', read_va(data, FIELD_TABLE + 4 * index, 4))[0]


def fields(data):
    text(data, DUP_TEMPLATE, b'\x11duplicate field `')
    lea(data, 0x3208ff8, FIELD_TABLE)
    out = {}
    for index, (arm, csite, decoder) in ARMS.items():
        if table_entry(data, index) != arm:
            raise ValueError(f'field table entry {index} is not {arm:#x}')
        jump(data, csite, 'e8', 5, decoder)
        out[str(index)] = {'arm': hex(arm), 'decoder': hex(decoder)}
        if index in DUPLICATES:
            key, dsite, op, block, nlea, tlea = DUPLICATES[index]
            jump(data, dsite, op, 6, block)
            text(data, lea(data, nlea), key.encode())
            if read_va(data, nlea + 12, 9) != bytes.fromhex('48c744247801000000'):
                raise ValueError(f'duplicate block {block:#x} does not store length 1')
            lea(data, tlea, DUP_TEMPLATE)
            out[str(index)].update({'key': key, 'duplicate_block': hex(block)})
        else:
            out[str(index)]['key'] = '(any other key)'
    return out


def no_missing(data):
    _, entries = unwind_index(data)
    starts = [e['start'] for e in entries]
    i = bisect.bisect_left(starts, VALUE)
    if starts[i] != VALUE:
        raise ValueError(f'{VALUE:#x} is not a function start')
    code = read_va(data, VALUE, entries[i]['next_index_upper_bound'] - VALUE)
    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', code):
        site = VALUE + m.start()
        if site + 7 + struct.unpack('<i', code[m.start() + 3:m.start() + 7])[0] == MISSING_TEMPLATE:
            raise ValueError(f'missing-field template loaded at {site:#x}')
    return {'function': hex(VALUE), 'missing_template_loads': 0}


def perp_side(data):
    lea(data, PERP_RECORD_LEA, PERP_RECORD)
    target = relocation(data, PERP_RECORD)
    if struct.unpack('<Q', read_va(data, PERP_RECORD + 8, 8))[0] != len(PERP_TEXT):
        raise ValueError(f'record {PERP_RECORD:#x} has the wrong length')
    text(data, target, PERP_TEXT)
    return {'function': hex(PERP_USER_STATES), 'struct_name': PERP_TEXT.decode(), 'link': '#6584'}


def holders(data):
    _, entries = unwind_index(data)
    starts = [e['start'] for e in entries]
    sites = {}
    for func, vas in HOLDER.items():
        for va in vas:
            sites[va] = func
    for va in list(PINS)[9:] + [KEY_CALL] + [s for s in JUMPS if s >= 0x3208000 and s < 0x320b000]:
        sites[va] = VALUE
    for arm, csite, _ in ARMS.values():
        sites[arm] = sites[csite] = VALUE
    for _, dsite, _, block, nlea, tlea in DUPLICATES.values():
        for va in (dsite, block, nlea, tlea):
            sites[va] = VALUE
    for site, func in sites.items():
        i = bisect.bisect_right(starts, site) - 1
        if i < 0 or starts[i] != func or not site < entries[i]['next_index_upper_bound']:
            raise ValueError(f'site {site:#x} is not in function {func:#x}')
    return len(sites)


def bind(data):
    pin_check(data)
    jumps = {hex(s): jump(data, s, *v) for s, v in JUMPS.items()}
    return {
        'target': {'path': RELATIVE, 'sha256': SHA256},
        'spot_clearinghouse': {'index': 1, 'key': 'user_states', 'visitor': hex(SCL),
                               'call': hex(SCL_CALL)},
        'decoder': hex(DECODER),
        'fixmap': map_refusal(data),
        'fixarray': {'sequence': hex(SEQUENCE), 'first_allocation_cap': 0x2762,
                     'entry_size': 0x70, 'element': hex(PAIR)},
        'pair': {'function': hex(PAIR), 'key_reader': hex(KEY_READER), 'key_length': 20,
                 'value': hex(VALUE), 'empty_array': 'error', 'one_element': 'error'},
        'value': {'key_read': key_read(data), 'field_table': hex(FIELD_TABLE),
                  'fields': fields(data), 'missing_field_errors': no_missing(data)},
        'perp_user_states': perp_side(data),
        'branches': jumps,
        'holders_checked': holders(data),
        'links': {'spot_clearinghouse': '#6594', 'perp_user_states': '#6584',
                  'second_per_user_visitor': '#6582'},
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
