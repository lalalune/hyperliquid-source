#!/usr/bin/env python3
"""Node #115 per-user value: the D field decoder 0x18d4f40 and its item decoder.

Open PR #6239 found that the per-user value map visitor 0x1a212f0 calls
0x18d4f40 for key D (index 2) and keeps the result at output +0x28, with item
size 0x18. It left open the D keys. This tool checks:

1. 0x18d4f40 sends a MessagePack map (fixmap, map16 0xde, map32 0xdf) to
   0x27a95f0 and an array (fixarray, array16 0xdc, array32 0xdd) to 0x28197a0.
2. D is a map, not a struct: each map key is read by 0x17e3120 with the
   4-byte name `Date`, and each value by 0x1be12b0. The array form reads
   (Date, value) pairs through 0x1bd5ae0, which calls the same two decoders.
   Entries are 0x18 bytes: key dword at +0x0, value at +0x8.
3. Both forms end in 0x2dac950, which sorts the entries by key, rejects two
   equal adjacent keys (`duplicate key`, tag 0x8000000000000001) and keeps
   up to 0x40 entries in the (cap, ptr, 0, len) form; above 0x40 it builds a
   second form (tag 0x8000000000000000).
4. The value decoder 0x1be12b0 is a struct with two fields: key `a` (index 0)
   and key `c` (index 1); any other key is skipped. Both are integers read
   through slot 0x64e2580. A missing field is 0. Output: a at +0x8, c at
   +0x10 of the result, so entry +0x8 and +0x10.
5. No long key name: the value decoder only matches one-byte keys (length-1
   guards on the string and byte paths), has no 16-byte `pcmpeqb` compare,
   and its only key-name strings are the two one-byte names `a` and `c` used
   for `duplicate field`. The D, map and array functions load no key name
   other than `Date`.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections, unwind_index

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-user-value-d-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

D_DECODER = 0x18d4f40
MAP_VISITOR = 0x27a95f0
SEQ_VISITOR = 0x28197a0
SEQ_ELEMENT = 0x1bd5ae0
KEY_DECODER = 0x17e3120
VALUE_DECODER = 0x1be12b0
COLLECTOR = 0x2dac950
FUNCTIONS = (D_DECODER, MAP_VISITOR, SEQ_VISITOR, SEQ_ELEMENT, VALUE_DECODER, COLLECTOR)

PINS = {
    # D decoder: fixmap (0x80..0x8f) -> 0x18d503e, fixarray (0x90..0x9f) -> 0x18d50ec
    0x18d4f8e: '41b1e03cdf77463c90730a240f4189c0e99b0000003ca0730a240f4189c0e93b010000',
    # map path: depth guard, then call 0x27a95f0
    0x18d503e: ('410fb6d80fb746226685c00f845b06000066ffc8668946220f84a80400004989ff4989f6'
                '4889742450895c2458488d7c2428488d742450e87645ed00'),
    # array path: depth guard, then call 0x28197a0
    0x18d50ec: ('410fb6d80fb746226685c00f84ba05000066ffc8668946220f84fa0300004989ff4989f6'
                '4889742450895c2458488d7c2428488d742450e87846f400'),
    # map16 / map32 length reads join the map path; array16 / array32 join the array path
    0x18d51ce: '0fb7dae96cfeffff',
    0x18d51fc: 'e941feffff',
    0x18d5288: '0fb7dae960feffff',
    0x18d523b: 'e9b0feffff',
    # map visitor: preallocate min(len, 0xaaaa) entries of 0x18 bytes
    0x27a9601: '8b6e0881fdaaaa0000bbaaaa00000f42dd85ed48897c24480f843e0100004989f68d04dd000000004c8d3c404c89ff',
    # map visitor: store key dword at entry+0x0 and 16-byte value at entry+0x8
    0x27a9660: '488b4424184b8d0c64891cc80f284424700f1144c80849ffc44c89642420',
    # map visitor: key through 0x17e3120 with name `Date`, value through 0x1be12b0
    0x27a9687: '41896e08b9040000004c89ef4c89fe488d153309cbfde87e9a03ff0fb64424283c0975408b5c242c4c89ef4c89fe31d2e8f47b43ff',
    0x27a9796: '488d7c2428488d742450e8ab316000',
    0x27a97ae: '48b801000000000000804839442428',
    0x27a97ea: '488d3563dce4fdba0d000000e8354311ff',
    # array visitor: element through 0x1bd5ae0; key dword +0x0, 20 bytes +0x4
    0x2819849: 'e892c23bff',
    0x2819810: '488b4424084b8d0c64891cc80f284424400f1144c8048b5424508954c814',
    0x28198bd: '488d742460e889305900',
    0x281996d: '488d35e0daddfdba0d000000e8b2410aff',
    # array element: same key decoder with `Date`, same value decoder
    0x1bd5c7b: '488d154e4388fe488d7c2430b9040000004889f3e88cd4c0ff',
    0x1bd5cbd: 'e8eeb50000',
    # collector: sort, adjacent equal keys -> 0x8000000000000001, <= 0x40 entries -> first form
    0x2dac973: '4983fc020f8301010000',
    0x2dac999: '8b113b5118488d491875ec48b8000000000000008048ffc0',
    0x2dac9db: '4983fc40763c',
    0x2daca07: 'e8e44d60ff48b800000000000000804889442430',
    0x2daca1d: '48c7442420000000004c8964242848894424104c89742418488d7c241031f6e83f8b72ff',
    0x2daca7e: '4983fc15731a488d4c2410ba010000004c89f74c89e6e807ed91ff',
    0x2dacaa9: 'ff15f9ba7303',
    # value decoder: string key, length-1 guard, `c` -> 1, `a` -> 0, other -> 2
    0x1be17af: ('833c2401750ab0024183ff017411eb29b00248837c241001751f488b6c24080fb645003c630f94c1'
                'b20228ca3c610fb6c2b9000000000f44c1'),
    # value decoder: byte key, length-1 guard, same compare
    0x1be1866: '4883fa010f858efbffff0fb6003c630f94c13c610f8561010000',
    # value decoder: index 0 -> a arm 0x1be1880, index 1 -> c arm 0x1be14e4, other -> skip
    0x1be14d0: '84c00f84a80300000fb6c083f8010f851affffff',
    0x1be1880: '4883bc249000000001',
    # a: integer through slot 0x64e2580 -> [rsp+0xa0], seen [rsp+0x90]
    0x1be1a0a: 'ff15700b90040fb60424488b4c24083c090f850e06000048898c24a0000000b8010000004889842490000000',
    # c: integer through slot 0x64e2580 -> [rsp+0x98], seen [rsp+0x88]
    0x1be1a5b: 'ff151f0b90040fb60424488b4c24083c090f85bd05000048898c2498000000b8010000004889842488000000',
    # end of map: a, c default 0
    0x1be1fac: '31c0f684249000000001488b8c24a0000000480f44c8f684248800000001488b942498000000480f44d04889d0',
    # result: tag 9 at +0x0, a at +0x8, c at +0x10
    0x1be1c71: '31c948898c24b000000048898424b8000000c68424a800000009',
    0x1be1ca2: '0f108424a80000000f108c24b8000000',
    0x1be1f2a: '0f114b100f1103',
    # duplicate field: a (seen 0x90) names 0x5c95b6, c (seen 0x88) names 0x5c9254, length 1
    0x1be2218: '4989f7488d0594739efeeb0a4989f7488d0526709efe488944244048c744244801000000',
    # array form: first element -> a, second -> c, missing -> 0
    0x1be1ab8: 'e8f33ccb000fb604243c090f85900400004c8b7c240883fd010f855c040000',
    0x1be1d52: '4531ff31c04c897c24484889442450',
    0x1be1f39: 'e87238cb000fb604243c09751383fd020f8512010000488b442408',
}

MARKER_TABLE, MARKER_LEA = 0x4bdc60, 0x18d4fc4
MARKERS = {   # marker byte -> (table arm, path it joins)
    0xde: (0x18d51a5, 'map'), 0xdf: (0x18d51d6, 'map'),
    0xdc: (0x18d5263, 'array'), 0xdd: (0x18d5219, 'array'),
}
PATHS = {'map': 0x18d5042, 'array': 0x18d50f0}
JOINS = {0x18d51d1: 'map', 0x18d51fc: 'map', 0x18d528b: 'array', 0x18d523b: 'array'}
CALLS = {   # call site -> target
    0x18d5075: MAP_VISITOR, 0x18d5123: SEQ_VISITOR,
    0x27a969d: KEY_DECODER, 0x27a96b7: VALUE_DECODER, 0x27a97a0: COLLECTOR,
    0x2819849: SEQ_ELEMENT, 0x28198c2: COLLECTOR,
    0x1bd5c8f: KEY_DECODER, 0x1bd5cbd: VALUE_DECODER,
}
SLOT_CALLS = {0x1be1a0a: (0x64e2580, 'a'), 0x1be1a5b: (0x64e2580, 'c')}
STRINGS = {   # lea site -> (address, length, text)
    0x27a9696: (0x459fd0, 4, 'Date'), 0x1bd5c7b: (0x459fd0, 4, 'Date'),
    0x27a97ea: (0x5f7454, 13, 'duplicate key'), 0x281996d: (0x5f7454, 13, 'duplicate key'),
    0x1be221b: (0x5c95b6, 1, 'a'), 0x1be2227: (0x5c9254, 1, 'c'),
}
# Every RIP-relative lea in each function, by target. Jump tables and error
# objects are listed; only `Date`, `duplicate key`, `a` and `c` are text.
LEA_TARGETS = {
    D_DECODER: {0x4bdc60: 1, 0x4bdfe4: 1, 0x641ccb0: 2, 0x641f9f8: 2, 0x641f9b0: 2,
                0x641f9c8: 2, 0x641fa10: 1, 0x641f9e0: 1},
    MAP_VISITOR: {0x459fd0: 1, 0x5f7454: 1},
    SEQ_VISITOR: {0x5f7454: 1},
    VALUE_DECODER: {0x5a9d54: 1, 0x5aa0d8: 1, 0x5aa120: 1, 0x641ccb0: 5, 0x641f9c8: 3,
                    0x641f9f8: 3, 0x641f9b0: 3, 0x641fa10: 1, 0x5c95b6: 1, 0x5c9254: 1,
                    0x24a7c50: 1, 0x43351a: 1},
    COLLECTOR: {},
}
# `cmp al, imm8` with a printable byte in the value decoder: only the two key sites.
KEY_COMPARES = {0x1be17d2: 'c', 0x1be17db: 'a', 0x1be1873: 'c', 0x1be1878: 'a'}
LENGTH_GUARDS = {0x1be17b7: 'string key length 1', 0x1be17c1: 'string key length 1',
                 0x1be1866: 'byte key length 1'}
SORT_LIMIT, SMALL_LIMIT = 0x15, 0x40


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return data[off:off + size]


def rel32(data, va, length):
    return va + length + struct.unpack('<i', read_va(data, va + length - 4, 4))[0]


def extents(data):
    _, entries = unwind_index(data)
    starts = {e['start']: e['next_index_upper_bound'] for e in entries}
    out = {}
    for fn in FUNCTIONS + (KEY_DECODER,):
        if fn not in starts:
            raise ValueError(f'no unwind entry at {fn:#x}')
        out[fn] = starts[fn]
    return out


def pin_check(data):
    for va, want in PINS.items():
        raw = bytes.fromhex(want)
        if read_va(data, va, len(raw)) != raw:
            raise ValueError(f'instruction bytes changed at {va:#x}')


def owner(ext, va):
    hits = [fn for fn, end in ext.items() if fn <= va < end]
    if len(hits) != 1:
        raise ValueError(f'{va:#x} is outside the mapped functions')
    return hits[0]


def markers(data):
    if rel32(data, MARKER_LEA, 7) != MARKER_TABLE:
        raise ValueError('marker table lea moved')
    out = {}
    for byte, (arm, path) in MARKERS.items():
        got = MARKER_TABLE + struct.unpack('<i', read_va(data, MARKER_TABLE + 4 * byte, 4))[0]
        if got != arm:
            raise ValueError(f'marker {byte:#x} goes to {got:#x}, not {arm:#x}')
        out[hex(byte)] = {'arm': hex(arm), 'path': path}
    for site, path in JOINS.items():
        if read_va(data, site, 1) != b'\xe9' or rel32(data, site, 5) != PATHS[path]:
            raise ValueError(f'jump at {site:#x} does not join the {path} path')
    return out


def calls(data, ext):
    out = {}
    for site, target in CALLS.items():
        if read_va(data, site, 1) != b'\xe8' or rel32(data, site, 5) != target:
            raise ValueError(f'call at {site:#x} is not to {target:#x}')
        out[hex(site)] = {'in': hex(owner(ext, site)), 'target': hex(target)}
    for site, (slot, field) in SLOT_CALLS.items():
        if read_va(data, site, 2) != b'\xff\x15' or rel32(data, site, 6) != slot:
            raise ValueError(f'slot call at {site:#x} is not through {slot:#x}')
        out[hex(site)] = {'in': hex(owner(ext, site)), 'slot': hex(slot), 'field': field}
    return out


def strings(data):
    out = {}
    for site, (addr, length, text) in STRINGS.items():
        if read_va(data, site + 1, 1) != b'\x8d' or rel32(data, site, 7) != addr:
            raise ValueError(f'lea at {site:#x} is not to {addr:#x}')
        got = read_va(data, addr, length).decode('ascii', 'replace')
        if got != text:
            raise ValueError(f'string at {addr:#x} is {got!r}, not {text!r}')
        out[hex(site)] = {'address': hex(addr), 'length': length, 'text': text}
    return out


def lea_census(data, ext, fn):
    code = read_va(data, fn, ext[fn] - fn)
    found = {}
    for i in range(len(code) - 6):
        if code[i] in (0x48, 0x4c) and code[i + 1] == 0x8d and (code[i + 2] & 0xc7) == 5:
            target = fn + i + 7 + struct.unpack_from('<i', code, i + 3)[0]
            found[target] = found.get(target, 0) + 1
    return found


def key_names(data, ext):
    """No key name other than the listed strings; one-byte key compares only."""
    for fn, want in LEA_TARGETS.items():
        got = lea_census(data, ext, fn)
        if got != want:
            raise ValueError(f'lea targets in {fn:#x} changed: {sorted(map(hex, got))}')
    pcmpeqb = {}
    for fn in FUNCTIONS:
        code = read_va(data, fn, ext[fn] - fn)
        pcmpeqb[hex(fn)] = sum(1 for i in range(len(code) - 3) if code[i:i + 4] == b'\x66\x0f\x74\x05')
        if pcmpeqb[hex(fn)]:
            raise ValueError(f'{fn:#x} has a 16-byte constant compare')
    code = read_va(data, VALUE_DECODER, ext[VALUE_DECODER] - VALUE_DECODER)
    letters = {VALUE_DECODER + i: chr(code[i + 1]) for i in range(len(code) - 1)
               if code[i] == 0x3c and 0x41 <= code[i + 1] <= 0x7a and chr(code[i + 1]).isalpha()}
    if letters != KEY_COMPARES:
        raise ValueError(f'value decoder letter compares changed: {letters}')
    guards = {0x1be17b7: read_va(data, 0x1be17b7, 4) == bytes.fromhex('4183ff01'),
              0x1be17c1: read_va(data, 0x1be17c1, 6) == bytes.fromhex('48837c241001'),
              0x1be1866: read_va(data, 0x1be1866, 4) == bytes.fromhex('4883fa01')}
    if not all(guards.values()):
        raise ValueError('value decoder length-1 guard changed')
    return {
        'value_decoder_key_index': {'a': 0, 'c': 1, 'other': 2},
        'key_compares': {hex(k): v for k, v in KEY_COMPARES.items()},
        'length_guards': {hex(k): v for k, v in LENGTH_GUARDS.items()},
        'pcmpeqb_rip_sites': pcmpeqb,
        'lea_targets': {hex(fn): {hex(t): n for t, n in sorted(w.items())} for fn, w in LEA_TARGETS.items()},
        'long_key_names': [],
    }


def disp32(data, va, prefix):
    raw = read_va(data, va, len(prefix) + 4)
    if raw[:len(prefix)] != prefix:
        raise ValueError(f'instruction at {va:#x} changed')
    return struct.unpack_from('<I', raw, len(prefix))[0]


def entry_layout(data):
    # map: mov [rax+rcx*8],ebx ; movups [rax+rcx*8+disp8],xmm0 ; stride lea rcx,[r12+r12*2] (x8)
    map_value = read_va(data, 0x27a9671, 5)
    seq_value = read_va(data, 0x2819821, 5)
    seq_tail = read_va(data, 0x281982a, 4)
    if map_value[:4] != bytes.fromhex('0f1144c8') or seq_value[:4] != bytes.fromhex('0f1144c8'):
        raise ValueError('entry value store changed')
    if seq_tail[:3] != bytes.fromhex('8954c8'):
        raise ValueError('array entry tail store changed')
    for site in (0x27a9665, 0x2819815):
        if read_va(data, site, 4) != bytes.fromhex('4b8d0c64'):
            raise ValueError(f'entry stride at {site:#x} changed')
    if read_va(data, 0x27a9669, 3) != bytes.fromhex('891cc8') or read_va(data, 0x2819819, 3) != bytes.fromhex('891cc8'):
        raise ValueError('entry key store changed')
    map_off, seq_off, tail_off = map_value[4], seq_value[4], seq_tail[3]
    if map_off != 0x8 or seq_off != 0x4 or tail_off != 0x14:
        raise ValueError(f'entry offsets changed: {map_off:#x} {seq_off:#x} {tail_off:#x}')
    # value result: a -> [rsp+0xb0], c -> [rsp+0xb8], copied from [rsp+0xa8] to rbx+0x0
    a_slot = disp32(data, 0x1be1c73, b'\x48\x89\x8c\x24')
    c_slot = disp32(data, 0x1be1c7b, b'\x48\x89\x84\x24')
    base = disp32(data, 0x1be1ca2, b'\x0f\x10\x84\x24')
    if (a_slot - base, c_slot - base) != (0x8, 0x10):
        raise ValueError('value field offsets changed')
    # map visitor keeps the value at [rsp+0x30..0x40] (result + 8) and stores it at entry + 8
    if read_va(data, 0x27a96c5, 5) != bytes.fromhex('0f10442430'):
        raise ValueError('map visitor value copy changed')
    return {
        'entry_size': '0x18',
        'map_form': {'key': '+0x0 (dword)', 'value': hex(map_off), 'a': hex(map_off), 'c': hex(map_off + 8)},
        'array_form': {'key': '+0x0 (dword)', 'rest': f'{seq_off:#x}..0x18 (20 bytes, value at +0x8)'},
        'value_result': {'tag': '+0x0 (9 = ok)', 'a': hex(a_slot - base), 'c': hex(c_slot - base)},
        'defaults_when_missing': {'a': 0, 'c': 0},
        'prealloc_cap': '0xaaaa',
    }


def collector(data):
    sort_limit = read_va(data, 0x2daca81, 1)[0]
    small_limit = read_va(data, 0x2dac9de, 1)[0]
    if (sort_limit, small_limit) != (SORT_LIMIT, SMALL_LIMIT):
        raise ValueError('collector limits changed')
    if read_va(data, 0x2dac999, 5) != bytes.fromhex('8b113b5118'):
        raise ValueError('duplicate key compare changed')
    dup_tag = struct.unpack('<Q', read_va(data, 0x2dac9a6, 8))[0] + 1
    big_tag = struct.unpack('<Q', read_va(data, 0x2daca0e, 8))[0]
    check_tag = struct.unpack('<Q', read_va(data, 0x27a97b0, 8))[0]
    if dup_tag != check_tag or dup_tag != 0x8000000000000001 or big_tag != 0x8000000000000000:
        raise ValueError('collector tags changed')
    return {
        'function': hex(COLLECTOR),
        'sort': f'insertion sort below {SORT_LIMIT:#x} entries (0x26cb7a0), else slot 0x64e85a8',
        'duplicate_key': {'compare': 'dword key at entry+0x0 with entry+0x18', 'tag': hex(dup_tag),
                          'message': 'duplicate key'},
        'small_form_max_entries': hex(SMALL_LIMIT),
        'small_form': '(cap, ptr, 0, len) through 0x24d5580',
        'large_form': 'tag 0x8000000000000000, then 24 bytes from 0x23b17f0',
    }


def bind(data):
    pin_check(data)
    ext = extents(data)
    return {
        'target': {'path': RELATIVE, 'sha256': SHA256},
        'functions': {hex(k): hex(v) for k, v in sorted(ext.items())},
        'markers': markers(data),
        'calls': calls(data, ext),
        'strings': strings(data),
        'entry': entry_layout(data),
        'collector': collector(data),
        'keys': key_names(data, ext),
        'link_6239': {'visitor_call': '0x1a22158', 'decoder': hex(D_DECODER),
                      'output_offset': '0x28', 'item_size': '0x18'},
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
    print(f"pins={result['pins']} calls={len(result['calls'])} "
          f"value_keys={sorted(result['keys']['value_decoder_key_index'])} long_names={result['keys']['long_key_names']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
