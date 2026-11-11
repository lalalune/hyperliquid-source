#!/usr/bin/env python3
"""Node #115: Locus field 7 (`uaR`) is a map from a 20-byte user key to a sequence.

Open PR #6589 showed that arm 7 (`uaR`) of the Locus MessagePack visitor
0x332c430 calls 0x32da770, and did not map that decoder. This tool checks
what 0x32da770 reads, one level down:

1. 0x32da770 sends a fixmap marker (0x80-0x8f) to the map visitor 0x37351a0
   and a fixarray marker (0x90-0x9f) to the array visitor 0x377b070. Its
   marker jump table 0x723224 sends map16/map32 (0xde, 0xdf) to the same map
   path and array16/array32 (0xdc, 0xdd) to the same array path.
2. The map visitor 0x37351a0 reads each key through 0x2f660a0 with the
   4-byte type name `User`, then each value through 0x329edf0. It loads the
   text `duplicate key`.
3. The key reader 0x2f660a0 stores the length 0x14 (20 bytes) and calls
   0x32e36c0. That is the same 20-byte key reader that 0x3314a40 calls for
   `user_states.user_to_state` (#6584).
4. The array visitor 0x377b070 reads each element through 0x3168ee0 and
   also loads `duplicate key`.
5. The value reader 0x329edf0 sends a fixmap marker to 0x3848e30 and a
   fixarray marker to a loop that reads each item through 0x2f3c470 and adds
   it through 0x3710120.
6. 0x3848e30 is a refusal: it stores the unexpected-type tag 0xb (map),
   passes the expectation record 0x646c990 and the text `invalid type: `,
   and calls 0x3046740. The record's function (relocated slot 0x646c9a8 ->
   0x38db620) writes the 10-byte text `a sequence`.

So `uaR` is a map whose key is a 20-byte user key read by the same reader as
user_to_state, and whose value is a sequence of items. The item decoder
0x2f3c470 and the collector 0x3710120 are listed by address only.

The tool only compares fixed bytes at fixed addresses, jump-table entries,
branch and call targets, RIP-relative references, relocations, function
starts from .eh_frame_hdr, and strings. The captured binary is not
executed. objdump and readelf are not started. Addresses are ELF virtual
addresses.
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
PACKET = ROOT / 'research/work-items/RE-008-locus-uar-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

UAR = 0x32da770
MAP_VISITOR = 0x37351a0
ARRAY_VISITOR = 0x377b070
KEY_READER = 0x2f660a0
KEY_BYTES = 0x32e36c0
VALUE = 0x329edf0
ELEMENT = 0x3168ee0
ITEM = 0x2f3c470
COLLECT = 0x3710120
REFUSE = 0x3848e30
MARKER_TABLE = 0x723224
EXPECT_RECORD = 0x646c990
EXPECT_SLOT = 0x646c9a8
EXPECT_FN = 0x38db620

PINS = {   # address -> (bytes, meaning)
    0x332d06d: ('0c00004c89fee8f8d6faff', 'Locus arm 7 (uaR): call 0x32da770 (#6589)'),
    0x32da7c5: ('3c90730a240f4189c0e99b0000003ca0730a240f4189c0e93b010000',
                'uaR: fixmap -> map path 0x32da86e, fixarray -> array path 0x32da91c'),
    0x32da89b: ('488d7c2428488d742450e8f6a84500', 'uaR map path: call 0x37351a0'),
    0x32da949: ('488d7c2428488d742450e818074a00', 'uaR array path: call 0x377b070'),
    0x373526c: ('896808b904000000488d7c2428488bb42488000000488d15644ed2fce8130e83ff',
                'map visitor: type name length 4, lea `User`, call 0x2f660a0'),
    0x37352c5: ('488d7c2428488bb4248800000031d2e8179bb6ff', 'map visitor: value through 0x329edf0'),
    0x2f660f5: ('48c744245014000000488d7c2460488d542440b901000000e8aed53700',
                'key reader: length 0x14, call 0x32e36c0'),
    0x3314c4f: ('e86ceafcff', 'user_to_state pair reader 0x3314a40: call 0x32e36c0 (#6584)'),
    0x377b14b: ('4c89fe31d2e88bdd9eff', 'array visitor: element through 0x3168ee0'),
    0x329ee4a: ('3c907309240f89c7e9950000003ca07309240f89c7e9fd000000',
                'value: fixmap -> 0x329eeec, fixarray -> 0x329ef61'),
    0x329ef0d: ('4889e7488db424a8000000e8139f5a00', 'value map path: call 0x3848e30'),
    0x329efca: ('488d7c24704889e6e849114700', 'value array loop: add item through 0x3710120'),
    0x329efe2: ('4889e74989f4e883d4c9ff', 'value array loop: item through 0x2f3c470'),
    0x3848e38: ('c64424380b', 'refusal: unexpected type tag 0xb (map)'),
    0x38db62b: ('488d35974decfcba0a000000', 'expectation: lea `a sequence`, length 10'),
}
# call / jump site -> (opcode bytes, instruction length, target)
JUMPS = {
    0x332d073: ('e8', 5, UAR),
    0x32da7ce: ('e9', 5, 0x32da86e),
    0x32da7dc: ('e9', 5, 0x32da91c),
    0x32da8a5: ('e8', 5, MAP_VISITOR),
    0x32da953: ('e8', 5, ARRAY_VISITOR),
    0x3735288: ('e8', 5, KEY_READER),
    0x37352d4: ('e8', 5, VALUE),
    0x2f6610d: ('e8', 5, KEY_BYTES),
    0x3314c4f: ('e8', 5, KEY_BYTES),
    0x377b150: ('e8', 5, ELEMENT),
    0x329ee52: ('e9', 5, 0x329eeec),
    0x329ee5f: ('e9', 5, 0x329ef61),
    0x329ef18: ('e8', 5, REFUSE),
    0x329efd2: ('e8', 5, COLLECT),
    0x329efe8: ('e8', 5, ITEM),
    0x3848e8b: ('e8', 5, 0x3046740),
}
# marker byte -> uaR arm in table 0x723224
MARKERS = {0xdc: 0x32daa93, 0xdd: 0x32daa49, 0xde: 0x32da9d5, 0xdf: 0x32daa06}
# arm -> (bytes, jump site, target): each wide arm ends in a jmp to the map or array path
WIDE = {
    0x32daa93: ('488b4610488b4e18', 0x32daabb, 0x32da920, 'array16'),
    0x32daa49: ('488b4610488b4e18', 0x32daa6b, 0x32da920, 'array32'),
    0x32da9d5: ('488b4610488b4e18', 0x32daa01, 0x32da872, 'map16'),
    0x32daa06: ('488b4610488b4e18', 0x32daa2c, 0x32da872, 'map32'),
}
# lea site -> (address, text or None)
LEAS = {
    0x3735281: (0x45a0ec, 'User'),
    0x37355cb: (0x79dce8, 'duplicate key'),
    0x377b340: (0x79dce8, 'duplicate key'),
    0x3848e47: (EXPECT_RECORD, None),
    0x3848e7f: (0x44f07a, '\x0einvalid type: '),
    0x38db62b: (0x7a03c9, 'a sequence'),
}
RELOCS = {EXPECT_SLOT: EXPECT_FN}
# site -> function that holds it (from .eh_frame_hdr)
HOLDERS = {
    0x32da8a5: UAR, 0x32da953: UAR, 0x3735288: MAP_VISITOR, 0x37352d4: MAP_VISITOR,
    0x37355cb: MAP_VISITOR, 0x2f6610d: KEY_READER, 0x377b150: ARRAY_VISITOR,
    0x377b340: ARRAY_VISITOR, 0x329ef18: VALUE, 0x329efd2: VALUE, 0x329efe8: VALUE,
    0x3848e8b: REFUSE, 0x38db62b: EXPECT_FN, 0x3314c4f: 0x3314a40, 0x332d073: 0x332c430,
}


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


def branch(data, site, op, length, target):
    if read_va(data, site, len(op) // 2) != bytes.fromhex(op) or rel_target(data, site, length) != target:
        raise ValueError(f'branch at {site:#x} is not to {target:#x}')


def jumps(data):
    out = {}
    for site, (op, length, target) in JUMPS.items():
        branch(data, site, op, length, target)
        out[hex(site)] = hex(target)
    return out


def markers(data):
    out = {}
    for marker, arm in MARKERS.items():
        got = table_entry(data, MARKER_TABLE, marker)
        if got != arm:
            raise ValueError(f'table {MARKER_TABLE:#x} marker {marker:#x} is {got:#x}, not {arm:#x}')
        raw, site, target, kind = WIDE[arm]
        if read_va(data, arm, len(raw) // 2) != bytes.fromhex(raw):
            raise ValueError(f'instruction bytes changed at {arm:#x} ({kind} arm)')
        branch(data, site, 'e9', 5, target)
        out[hex(marker)] = {'arm': hex(arm), 'kind': kind, 'joins': hex(target)}
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
    if EXPECT_SLOT - EXPECT_RECORD != 0x18:
        raise ValueError('expectation slot is not the first method of the record')
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
        'locus_field': {'index': 7, 'key': 'uaR', 'decoder': hex(UAR)},
        'uar': {
            'map_visitor': hex(MAP_VISITOR), 'array_visitor': hex(ARRAY_VISITOR),
            'wide_markers': markers(data),
            'key': {'reader': hex(KEY_READER), 'type_name': 'User', 'length': 20,
                    'bytes_reader': hex(KEY_BYTES),
                    'same_reader_as': 'user_states.user_to_state pair reader 0x3314a40 (#6584)'},
            'value': {'reader': hex(VALUE), 'map_form': 'refused: expected a sequence',
                      'item_decoder': hex(ITEM), 'collector': hex(COLLECT)},
            'array_element': hex(ELEMENT),
            'duplicate_key_text': True,
        },
        'branches': jumps(data),
        'leas': leas(data),
        'relocations': relocations(data),
        'holders': holders(data),
        'item_decoder_mapped': False,
        'meaning_of_uaR_name': 'not proven',
        'links': {'locus_arms': '#6589', 'user_key_reader': '#6584'},
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
    print(f"pins={result['pins']} branches={len(result['branches'])} "
          f"key={result['uar']['key']['type_name']!r} value={result['uar']['value']['map_form']!r}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
