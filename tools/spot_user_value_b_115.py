#!/usr/bin/env python3
"""Node #115: field `b` of the spot per-user value is a map from a `Token`
key to a three-field value {t, h, e}.

Open PR #6596 showed that the spot per-user value {b, D, S} reads field `b`
through 0x31a73f0 (call at 0x3208d6b). This tool checks what 0x31a73f0 reads:

1. A fixmap marker (below 0x90) goes to the map visitor 0x3747e60 (call at
   0x31a7525). A fixarray marker (0x90..0x9f) goes to the sequence visitor
   0x378dbb0 (call at 0x31a75d3).
2. The map visitor reads each key through 0x2f48380 with the 5-byte type name
   `Token` and each value through 0x3077410. A repeated key gives the 13-byte
   text `duplicate key`. The sequence visitor reads each element through
   0x32d1140 and loads the same text.
3. 0x3077410 reads each one-byte key and matches it inline: `t` is field 0,
   `h` is field 1, `e` is field 2, any other key is 3. It jumps through table
   0x6701e4. Fields 0 and 1 are read through 0x2f782f0 with the 3-byte type
   name `Wei`. Field 2 is read through 0x2f53f30 with the 14-byte type name
   `UsdcBigSpotNtl`. Any other key goes to 0x30775cf.
4. A repeated key reports its one-byte name (`t`, `h` or `e`, length 1) with
   the template `duplicate field `...``.
5. At the end, each field whose seen flag is still 0 is set to 0 (three
   `cmove` from a zeroed register). No field is required.

The tool only compares fixed bytes at fixed addresses, jump-table entries,
branch and call targets, RIP-relative references, function starts from
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
PACKET = ROOT / 'research/work-items/RE-008-spot-user-value-b-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

SPOT_VALUE = 0x3208ad0
SPOT_VALUE_CALL = 0x3208d6b
DECODER = 0x31a73f0
MAP_VISITOR = 0x3747e60
SEQ_VISITOR = 0x378dbb0
KEY_READER = 0x2f48380
VALUE = 0x3077410
ELEMENT = 0x32d1140
WEI_READER = 0x2f782f0
NTL_READER = 0x2f53f30
OTHER_ARM = 0x30775cf
FIELD_TABLE = 0x6701e4
DUP_KEY = 0x79dce8
DUP_FIELD = 0x43351a
TOKEN = 0x7c8235
WEI = 0x7cab5e
NTL = 0x7db4bf

PINS = {   # address -> (bytes, meaning)
    0x31a7445: ('3c90', 'first marker compared with 0x90 (fixmap below)'),
    0x31a7453: ('3ca0', 'first marker compared with 0xa0 (fixarray below)'),
    0x3747f04: ('b905000000', 'map key: type name length 5'),
    0x3747f22: ('3c09', 'map key: result tag 9 is success'),
    0x3747f37: ('31d2', 'map value: second argument 0'),
    0x3748078: ('ba0d000000', 'duplicate key text length 13'),
    0x3077972: ('b003', 'value: other key is field 3'),
    0x3077974: ('4183ff01', 'value: key length compared with 1'),
    0x3077982: ('83f965', "value: key byte compared with 'e'"),
    0x307798e: ('83f968', "value: key byte compared with 'h'"),
    0x3077991: ('ba00000000', "value: 't' is field 0"),
    0x30779a4: ('83f974', "value: key byte compared with 't'"),
    0x3077bc8: ('b001', "value: 'h' is field 1"),
    0x3077bec: ('b002', "value: 'e' is field 2"),
    0x30776c4: ('b903000000', "field t: type name length 3"),
    0x3077c20: ('b903000000', "field h: type name length 3"),
    0x3077c71: ('b90e000000', "field e: type name length 14"),
    0x30776ec: ('48898424200100', 'field t: value kept at rsp+0x120'),
    0x3078572: ('48c744244801000000', 'duplicate name length 1'),
    0x30782c7: ('31c0f68424b800000001488b8c2420010000480f44c8', 'end: t is 0 when not seen'),
    0x30782dd: ('f68424c000000001488bbc2418010000480f44f8', 'end: h is 0 when not seen'),
    0x30782f1: ('f68424c800000001488b942410010000480f44d0', 'end: e is 0 when not seen'),
}
# call / jump site -> (opcode bytes, instruction length, target)
JUMPS = {
    SPOT_VALUE_CALL: ('e8', 5, DECODER),
    0x31a7525: ('e8', 5, MAP_VISITOR),
    0x31a75d3: ('e8', 5, SEQ_VISITOR),
    0x3747f18: ('e8', 5, KEY_READER),
    0x3747f39: ('e8', 5, VALUE),
    0x378dc58: ('e8', 5, ELEMENT),
    0x3077988: ('0f84', 6, 0x3077bec),
    0x307799e: ('0f84', 6, 0x3077bc8),
    0x30776d6: ('e8', 5, WEI_READER),
    0x3077c32: ('e8', 5, WEI_READER),
    0x3077c83: ('e8', 5, NTL_READER),
}
# index -> (key, arm, seen-flag test, duplicate branch, duplicate block, name lea)
FIELDS = {
    0: ('t', 0x30776b5, 'b8', 0x30776be, 0x307854b, 0x307854e),
    1: ('h', 0x3077c11, 'c0', 0x3077c1a, 0x3078557, 0x307855a),
    2: ('e', 0x3077c62, 'c8', 0x3077c6b, 0x3078563, 0x3078566),
}
# lea site -> (target, string)
STRINGS = {
    0x3747f11: (TOKEN, b'Token'),
    0x3748071: (DUP_KEY, b'duplicate key'),
    0x378dd59: (DUP_KEY, b'duplicate key'),
    0x30776cf: (WEI, b'Wei'),
    0x3077c2b: (WEI, b'Wei'),
    0x3077c7c: (NTL, b'UsdcBigSpotNtl'),
    0x3078590: (DUP_FIELD, b'\x11duplicate field `'),
}
HOLDER = {
    SPOT_VALUE: (SPOT_VALUE_CALL,),
    DECODER: (0x31a7445, 0x31a7453, 0x31a7525, 0x31a75d3),
    MAP_VISITOR: (0x3747f04, 0x3747f11, 0x3747f18, 0x3747f22, 0x3747f37, 0x3747f39,
                  0x3748071, 0x3748078),
    SEQ_VISITOR: (0x378dc58, 0x378dd59),
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


def strings(data):
    out = {}
    for site, (target, want) in STRINGS.items():
        lea(data, site, target)
        text(data, target, want)
        out[hex(site)] = want.decode().lstrip('\x11')
    return out


def table_entry(data, index):
    return FIELD_TABLE + struct.unpack('<i', read_va(data, FIELD_TABLE + 4 * index, 4))[0]


def fields(data):
    lea(data, 0x30779b8, FIELD_TABLE)
    out = {}
    for index, (key, arm, flag, dsite, block, nlea) in FIELDS.items():
        if table_entry(data, index) != arm:
            raise ValueError(f'field table entry {index} is not {arm:#x}')
        want = bytes.fromhex('4883bc24' + flag + '00000001')
        if read_va(data, arm, len(want)) != want:
            raise ValueError(f'arm {arm:#x} does not test seen flag rsp+0x{flag}')
        jump(data, dsite, '0f84', 6, block)
        text(data, lea(data, nlea), key.encode())
        out[str(index)] = {'key': key, 'arm': hex(arm), 'seen_flag': f'rsp+0x{flag}',
                           'duplicate_block': hex(block)}
    if table_entry(data, 3) != OTHER_ARM:
        raise ValueError(f'field table entry 3 is not {OTHER_ARM:#x}')
    out['3'] = {'key': '(any other key)', 'arm': hex(OTHER_ARM)}
    out['0']['reader'] = out['1']['reader'] = {'function': hex(WEI_READER), 'type_name': 'Wei'}
    out['2']['reader'] = {'function': hex(NTL_READER), 'type_name': 'UsdcBigSpotNtl'}
    return out


def holders(data):
    _, entries = unwind_index(data)
    starts = [e['start'] for e in entries]
    sites = {}
    for func, vas in HOLDER.items():
        for va in vas:
            sites[va] = func
    for va in [v for v in PINS if VALUE <= v < 0x3079000] + \
              [s for s in JUMPS if VALUE <= s < 0x3079000] + \
              [s for s in STRINGS if VALUE <= s < 0x3079000] + [0x30779b8]:
        sites[va] = VALUE
    for _, arm, _, dsite, block, nlea in FIELDS.values():
        for va in (arm, dsite, block, nlea):
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
        'spot_value': {'index': 0, 'key': 'b', 'function': hex(SPOT_VALUE),
                       'call': hex(SPOT_VALUE_CALL)},
        'decoder': hex(DECODER),
        'fixmap': {'map_visitor': hex(MAP_VISITOR), 'key_reader': hex(KEY_READER),
                   'key_type_name': 'Token', 'value': hex(VALUE),
                   'repeated_key': 'duplicate key'},
        'fixarray': {'sequence_visitor': hex(SEQ_VISITOR), 'element': hex(ELEMENT)},
        'value': {'function': hex(VALUE), 'field_table': hex(FIELD_TABLE),
                  'fields': fields(data), 'missing_field': 'set to 0, not an error'},
        'strings': strings(data),
        'branches': jumps,
        'holders_checked': holders(data),
        'links': {'spot_user_states': '#6596'},
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
