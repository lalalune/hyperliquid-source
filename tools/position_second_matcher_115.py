#!/usr/bin/env python3
"""Node #115 second position key matcher 0x4455970: a second MessagePack position decoder.

Open PR #6579 found that 0x4455970 has the same key compares as the JSON
position matcher 0x4455890 and only a different success tag (9, not 0),
and named its one caller 0x32d3c90 without mapping it. This tool checks:

1. The two matchers are the same 0xd4 bytes except two jump-table lea
   displacements and six success-tag bytes (`mov byte [rax],0` vs
   `mov byte [rax],9`). The two pairs of jump tables (11 and 0x27 entries)
   send each key length and first byte to the same function offset.
2. 0x32d3c90 reads MessagePack markers (fixmap 0x80, fixarray 0x90,
   fixstr 0xa0, other markers from 0xc0). For a map key it calls the
   slot 0x64dfca8 on the key bytes. Result tag 1 sends the key to
   0x2fc4d70; any other result sends it to 0x4455970. Every callee result
   in this function is tested with `cmp al,9`, so 9 is the success tag of
   this decoder's result type.
3. After the key, the function jumps through table 0x722690 by field
   index: 0 s (Szi decoder, name `Szi`), 1 l, 2 M, 3 f, 4 e (name `Ntl`),
   5 skip the value. These are the indices of the MessagePack decoder in
   #6453 and the JSON reader in #6579.
4. The M arm reports a second M as a duplicate field named `M`. It reads
   the value with 0x4483100, which passes the name `MarginTableId` (13)
   to 0x2f6e330. That function reads the integer through slot 0x64e25d8.
   The slot is relocated to 0x34861d0, the integer read that #6456 found
   for the first MessagePack decoder (it rejects 0 as `a nonzero u32`).
5. At the end of the map, an M of 0 (not seen) becomes 0x14 (20), and an
   l that was not seen becomes tag 0 with 0x14.
6. 0x32d3c90 has two direct callers. One, 0x372f3ae, first reads a key
   through 0x2f48380 with the name `Perp`.

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
PACKET = ROOT / 'research/work-items/RE-008-position-second-matcher-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

DECODER = 0x32d3c90
JSON_MATCHER = 0x4455890
SECOND_MATCHER = 0x4455970
MATCHER_SIZE = 0xd4
TABLE_LEAS = {0x10: 11, 0x2f: 0x27}   # matcher offset of a jump-table lea -> entries
OK_TAGS = 6
BYTES_MATCHER = 0x2fc4d70
FIELD_TABLE = 0x722690
FIELD_ARMS = (0x32d3f65, 0x32d4097, 0x32d4007, 0x32d4036, 0x32d3fb6, 0x32d3e80)
FIELD_NAMES = ('s', 'l', 'M', 'f', 'e', 'other')
M_ARM = 0x32d4007
M_READ = 0x4483100
M_NEWTYPE = 0x2f6e330
INT_SLOT = 0x64e25d8
INT_READ = 0x34861d0
KEY_SLOT = 0x64dfca8
KEY_SLOT_TARGET = 0x16815e0
M_DEFAULT = 0x14

PINS = {   # address -> (bytes, meaning)
    0x32d42fc: ('ff15a6b9200383bc24b00000000175244889e74889ee4c89e2e8560acfff803c2409'
                '752d0fb644240188442451c644245009eb5c488bb424b8000000488b9424c0000000'
                '4c89ed4c89efe825161801',
                'key: slot 0x64dfca8; tag 1 -> 0x2fc4d70, else -> 0x4455970'),
    0x32d3f44: ('ff158e0721030fb64424503c090f851f0a00000fb6442451496304844c01e0ffe0',
                'after the key: tag 9 is success; jump by field index through r12'),
    0x32d438f: ('4c8d25fae244fd', 'r12 = field table 0x722690'),
    0x32d3f65: ('4883bc24d8000000010f843c1100004c89f6b9030000004c89ef488d15da4b4ffd'
                'e8459ac9ff',
                's arm: duplicate check; value read with name Szi (3)'),
    0x32d3fb6: ('4883bc24e0000000010f84f41000004c89f6b9030000004c89ef488d15e47450fd'
                'e86413c9ff',
                'e arm: duplicate check; value read with name Ntl (3)'),
    0x32d4007: ('837c2448000f85b91000004c89f64c89efe8e3f01a010fb604243c090f85950e0000'
                '8b44240489442448e964feffff',
                'M arm: 0 means not seen; read with 0x4483100; keep u32 at rsp+0x48'),
    0x32d4c4f: ('b914000000448b9c24ec000000440f44d90f44e8448b7424484585f6440f44f1',
                'end of map: l not seen -> tag 0 with 0x14; M 0 (not seen) -> 0x14'),
    0x32d3e80: ('4c89ef4c89f6ba01000000e8c01ff0ff803c2409',
                'index 5: skip one value'),
    0x4483100: ('488d1518f434fcb90d000000e91fb2aefe',
                'M read: name MarginTableId (13), jump to 0x2f6e330'),
    0x2f6e45d: ('ff15754157030fb604248b4c24043c09750f894b04c60309',
                'M newtype: integer read through slot 0x64e25d8; keep u32 on tag 9'),
    0x318125f: ('488dbc24c00000004889de31d2e81f2a1500', 'caller 1: call 0x32d3c90'),
    0x372f384: ('488d1545add2fce8f08f81ff0fb64424503c090f854c0100004c8b642458'
                '488d7c2450488b74244831d2e8dd48baff',
                'caller 2: key read with name Perp, then call 0x32d3c90'),
}

# call / jump site -> (opcode bytes, instruction length, target)
JUMPS = {0x32d4315: ('e8', 5, BYTES_MATCHER), 0x32d4346: ('e8', 5, SECOND_MATCHER),
         0x32d3f6e: ('0f84', 6, 0x32d50b0), 0x32d3fbf: ('0f84', 6, 0x32d50b9),
         0x32d400c: ('0f85', 6, 0x32d50cb), 0x32d403f: ('0f84', 6, 0x32d50c2),
         0x32d409f: ('0f85', 6, 0x32d50d4),
         0x32d4018: ('e8', 5, M_READ), 0x32d3f86: ('e8', 5, 0x2f6d9d0),
         0x32d3fd7: ('e8', 5, 0x2f65340), 0x32d3e8b: ('e8', 5, 0x31d5e50),
         0x448310c: ('e9', 5, M_NEWTYPE),
         0x318126c: ('e8', 5, DECODER), 0x372f3ae: ('e8', 5, DECODER),
         0x372f38b: ('e8', 5, 0x2f48380)}
# rip-relative call site -> slot
SLOT_CALLS = {0x32d42fc: KEY_SLOT, 0x2f6e45d: INT_SLOT}
RELOCATED = {INT_SLOT: INT_READ, KEY_SLOT: KEY_SLOT_TARGET}
# lea site -> (address, length, text or None for a non-string target)
LEAS = {0x32d438f: (FIELD_TABLE, 0, None),
        0x32d3f7f: (0x7c8b60, 3, 'Szi'), 0x32d3fd0: (0x7db4bb, 3, 'Ntl'),
        0x4483100: (0x7d251f, 13, 'MarginTableId'), 0x372f384: (0x45a0d0, 4, 'Perp'),
        0x32d50b0: (0x793170, 1, 's'), 0x32d50b9: (0x79367a, 1, 'e'),
        0x32d50c2: (0x7932e4, 1, 'f'), 0x32d50cb: (0x793e6c, 1, 'M'),
        0x32d50d4: (0x7932e9, 1, 'l')}


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


def table_arms(data, func, lea_offset, count):
    table = rel_target(data, func + lea_offset, 7)
    return tuple(table + struct.unpack('<i', read_va(data, table + 4 * i, 4))[0] - func
                 for i in range(count))


def matchers(data):
    first = read_va(data, JSON_MATCHER, MATCHER_SIZE)
    second = read_va(data, SECOND_MATCHER, MATCHER_SIZE)
    diff = [i for i in range(MATCHER_SIZE) if first[i] != second[i]]
    tags = []
    for i in diff:
        if any(off + 3 <= i < off + 7 for off in TABLE_LEAS):
            continue
        if first[i - 2:i + 1] != b'\xc6\x00\x00' or second[i - 2:i + 1] != b'\xc6\x00\x09':
            raise ValueError(f'matchers differ at {JSON_MATCHER + i:#x} outside the ok tag')
        tags.append(i)
    if len(tags) != OK_TAGS:
        raise ValueError(f'matchers have {len(tags)} ok tag differences, not {OK_TAGS}')
    tables = {}
    for off, count in TABLE_LEAS.items():
        a = table_arms(data, JSON_MATCHER, off, count)
        if a != table_arms(data, SECOND_MATCHER, off, count):
            raise ValueError(f'jump table at matcher +{off:#x} sends a key to a different place')
        tables[hex(off)] = count
    return {'size': hex(MATCHER_SIZE), 'ok_tag_bytes': len(tags), 'same_jump_tables': tables,
            'json_ok_tag': 0, 'second_ok_tag': 9}


def field_table(data):
    arms = tuple(FIELD_TABLE + struct.unpack('<i', read_va(data, FIELD_TABLE + 4 * i, 4))[0]
                 for i in range(len(FIELD_ARMS)))
    if arms != FIELD_ARMS:
        raise ValueError('field table 0x722690 changed')
    return {str(i): {'field': FIELD_NAMES[i], 'arm': hex(a)} for i, a in enumerate(arms)}


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


def bind(data):
    pin_check(data)
    return {
        'target': {'path': RELATIVE, 'sha256': SHA256},
        'decoder': hex(DECODER),
        'format': 'MessagePack markers 0x80 fixmap, 0x90 fixarray, 0xa0 fixstr, 0xc0..',
        'matchers': matchers(data),
        'key_path': {'slot': hex(KEY_SLOT), 'tag_1': hex(BYTES_MATCHER),
                     'otherwise': hex(SECOND_MATCHER)},
        'field_table': field_table(data),
        'm_arm': {'arm': hex(M_ARM), 'not_seen': 0, 'duplicate_name': 'M',
                  'value_read': hex(M_READ), 'newtype': hex(M_NEWTYPE),
                  'name': 'MarginTableId', 'integer_slot': hex(INT_SLOT),
                  'integer_read': hex(INT_READ), 'default': M_DEFAULT},
        'l_default': {'tag': 0, 'leverage': M_DEFAULT},
        'callers': {'0x318126c': 'call only', '0x372f3ae': 'after key read 0x2f48380 (Perp)'},
        'branches': jumps(data),
        'slots': slots(data),
        'leas': leas(data),
        'links': {'json_m_rules_and_second_matcher': '#6579', 'msgpack_m_rules': '#6456',
                  'msgpack_long_keys': '#6453'},
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
    print(f"pins={result['pins']} decoder={result['decoder']} "
          f"m_default={result['m_arm']['default']:#x} integer_read={result['m_arm']['integer_read']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
