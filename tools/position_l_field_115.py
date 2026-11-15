#!/usr/bin/env python3
"""Bind the node #115 per-user position field `l` to the enum Leverage (108th stage).

Continues the p.p item packet (open PR #6224), which found that the pretty
JSON item writer writes field `l` (+0x0, dword tag at +0x0, payload at +0x4)
with 0x420a0d0 and skips it when the tag is 0 and the payload is 0x14. This
tool binds:

1. the JSON writer 0x420a0d0 and its MessagePack twin 0x4209b80: tag 1
   writes {"I": {"l": u32 +0x4, "u": i64 +0x8}}, any other tag writes
   {"C": u32 +0x4};
2. the only code references to the keys "I" and "u": these two writers;
3. the only callers: 0x448afdc (in the JSON item writer 0x448ae20) and
   0x448ab8f (in 0x448aa30);
4. the four-entry name lists at 0x6483c28 (l, leverage, raw_usd, u) and
   0x6483c68 (C, Cross, I, Isolated), each passed with length 4 to an error
   path, and the three users of the "enum Leverage" message.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import (RELATIVE, SHA256, TARGET, direct_calls, fixed, frame,
                                 read_va, relative_relocations, render, rip_target, text)

PACKET = ROOT / 'research/work-items/RE-008-position-l-field-115'

JSON_WRITER, PACK_WRITER = 0x420a0d0, 0x4209b80
JSON_ITEM, PACK_ITEM = 0x448ae20, 0x448aa30
U32_JSON, I64_JSON, U32_FMT = 0x4648d30, 0x41d5380, 0x46ef430
KEY_JSON, VARIANT_JSON = 0x4713ba0, 0x46708b0
KEY_PACK, U32_PACK, I64_PACK = 0x41c6110, 0x3d517e0, 0x3d50670
FIELD_NAMES, VARIANT_NAMES = 0x6483c28, 0x6483c68

STRINGS = {
    0x7c8413: b'l', 0x7c8414: b'raw_usd', 0x7c841b: b'u', 0x7c841c: b'enum Leverage',
    0x7c842c: b'C', 0x7c84ce: b'Cross', 0x7c84d3: b'I', 0x458f18: b'leverage', 0x459480: b'Isolated',
    0x7d0946: b'l',
}
FIXED = {
    # JSON writer 0x420a0d0
    0x420a0e1: '4c8d7704',              # lea r14, [rdi+4]              (payload)
    0x420a0e5: '833f01',                # cmp dword [rdi], 1            (tag)
    0x420a0e8: '756a',                  # jne 0x420a154                 (C path)
    0x420a12b: '48893c24',              # mov [rsp], rdi
    0x420a197: '4c89742408',            # mov [rsp+8], r14              (C path)
    0x420a236: '4c8b3c24',              # mov r15, [rsp]                (I path)
    0x420a252: 'ba01000000',            # mov edx, 1                    ("I" length)
    0x420a2fd: '498d4f04',              # lea rcx, [r15+4]              (l)
    0x420a36a: '498b7708',              # mov rsi, [r15+8]              (u)
    0x420a499: '488b442408',            # mov rax, [rsp+8]
    0x420a49e: '8b38',                  # mov edi, [rax]                (C value)
    # MessagePack writer 0x4209b80
    0x4209b8e: '4989f7',                # mov r15, rsi
    0x4209b9e: '833e01',                # cmp dword [rsi], 1
    0x4209ba1: '7570',                  # jne 0x4209c13                 (C path)
    0x4209c4e: '418b5704',              # mov edx, [r15+4]              (C value)
    0x4209cca: '418b5704',              # mov edx, [r15+4]              (l)
    0x4209d07: '498b5708',              # mov rdx, [r15+8]              (u)
    # callers
    0x448afd6: '4889df',                # mov rdi, rbx                  (item value +0x0)
    # name-list users: list length 4
    0x420ab71: 'b904000000',
    0x41fe7d5: '41b804000000',
    0x41fe8a3: '41b804000000',
    0x3f7aac5: 'b904000000',
    0x3fb7bd3: 'b904000000',
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x420a24b, b'\x48\x8d\x35', 7, 0x7c84d3),
    (0x420a25a, b'\xe8', 5, VARIANT_JSON),
    (0x420a2ec, b'\x48\x8d\x35', 7, 0x7c8413),
    (0x420a301, b'\xe8', 5, U32_JSON),
    (0x420a31a, b'\x48\x8d\x35', 7, 0x7c841b),
    (0x420a32b, b'\xe8', 5, KEY_JSON),
    (0x420a372, b'\xe8', 5, I64_JSON),
    (0x420a440, b'\x48\x8d\x35', 7, 0x7c842c),
    (0x420a44f, b'\xe8', 5, VARIANT_JSON),
    (0x420a4a8, b'\xe8', 5, U32_FMT),
    (0x4209bc4, b'\x48\x8d\x35', 7, 0x7c84d3),
    (0x4209c30, b'\x48\x8d\x35', 7, 0x7c842c),
    (0x4209c5a, b'\xe8', 5, U32_PACK),
    (0x4209cb0, b'\x48\x8d\x35', 7, 0x7c8413),
    (0x4209cd6, b'\xe8', 5, U32_PACK),
    (0x4209ced, b'\x48\x8d\x35', 7, 0x7c841b),
    (0x4209d13, b'\xe8', 5, I64_PACK),
    (0x448afdc, b'\xe8', 5, JSON_WRITER),
    (0x448ab66, b'\x48\x8d\x35', 7, 0x7d0946),
    (0x448ab75, b'\xe8', 5, KEY_PACK),
    (0x448ab8f, b'\xe8', 5, PACK_WRITER),
    (0x420ab65, b'\x48\x8d\x15', 7, FIELD_NAMES),
    (0x41fe7c9, b'\x48\x8d\x0d', 7, VARIANT_NAMES),
    (0x41fe89c, b'\x48\x8d\x0d', 7, VARIANT_NAMES),
    (0x3f7aabe, b'\x48\x8d\x15', 7, VARIANT_NAMES),
    (0x3fb7bcc, b'\x48\x8d\x15', 7, VARIANT_NAMES),
    (0x25eb59b, b'\x48\x8d\x35', 7, 0x7c841c),
    (0x422922b, b'\x48\x8d\x35', 7, 0x7c841c),
    (0x5b097db, b'\x48\x8d\x35', 7, 0x7c841c),
)
NAME_LISTS = {
    FIELD_NAMES: ('l', 'leverage', 'raw_usd', 'u'),
    VARIANT_NAMES: ('C', 'Cross', 'I', 'Isolated'),
}
KEY_STRINGS = {'I': 0x7c84d3, 'C': 0x7c842c, 'l': 0x7c8413, 'u': 0x7c841b, 'enum Leverage': 0x7c841c,
               'field list': FIELD_NAMES, 'variant list': VARIANT_NAMES}
LEA = re.compile(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]')


def lea_census(data, fdes, targets):
    base, code = text(data)
    out = {t: [] for t in targets}
    for m in LEA.finditer(code):
        i = m.start()
        if i + 7 > len(code):
            continue
        tgt = base + i + 7 + struct.unpack_from('<i', code, i + 3)[0]
        if tgt in out:
            out[tgt].append(base + i)
    return {t: sorted({hex(frame(fdes, va)) for va in v}) for t, v in out.items()}


def name_list(data, rel, va, count):
    names = []
    for k in range(count):
        slot = va + 16 * k
        ptr = rel.get(slot)
        length = struct.unpack('<Q', read_va(data, slot + 8, 8))[0]
        if ptr is None:
            raise ValueError(f'name list entry at {slot:#x} changed')
        names.append(read_va(data, ptr, length).decode())
    return tuple(names)


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    for va, expect in STRINGS.items():
        if read_va(data, va, len(expect)) != expect:
            raise ValueError(f'string at {va:#x} changed')
    rel = relative_relocations(data)
    lists = {va: name_list(data, rel, va, 4) for va in NAME_LISTS}
    if lists != NAME_LISTS:
        raise ValueError('name lists changed')

    callers = {w: [(hex(c), hex(frame(fdes, c))) for c in direct_calls(data, w)]
               for w in (JSON_WRITER, PACK_WRITER)}
    if callers != {JSON_WRITER: [('0x448afdc', hex(JSON_ITEM))], PACK_WRITER: [('0x448ab8f', hex(PACK_ITEM))]}:
        raise ValueError('writer call census changed')
    refs = lea_census(data, fdes, KEY_STRINGS.values())
    census = {name: refs[va] for name, va in KEY_STRINGS.items()}
    writers = [hex(PACK_WRITER), hex(JSON_WRITER)]
    if census['I'] != writers or census['u'] != writers:
        raise ValueError('key reference census changed')
    if census['enum Leverage'] != ['0x25eb590', '0x4229220', '0x5b097d0']:
        raise ValueError('expecting message census changed')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'field': 'p.p value field l (+0x0, from #6224)',
        'callers': {hex(w): [{'call': c, 'function': f} for c, f in v] for w, v in callers.items()},
        'layout': {
            '+0x0': 'u32 tag (cmp dword [rdi], 1)',
            '+0x4': 'u32 (both variants)',
            '+0x8': 'i64 (tag 1 only)',
        },
        'json_writer': {
            'function': hex(JSON_WRITER),
            'tag_1': '{"I": {"l": u32 +0x4 via %s, "u": i64 +0x8 via %s}}' % (hex(U32_JSON), hex(I64_JSON)),
            'other_tag': '{"C": u32 +0x4 via %s}' % hex(U32_FMT),
            'variant_writer': hex(VARIANT_JSON),
        },
        'msgpack_writer': {
            'function': hex(PACK_WRITER),
            'key_writer': hex(KEY_PACK),
            'tag_1': '"I" {"l": u32 +0x4 via %s, "u": +0x8 via %s}' % (hex(U32_PACK), hex(I64_PACK)),
            'other_tag': '"C" u32 +0x4 via %s' % hex(U32_PACK),
        },
        'name_lists': {hex(va): list(v) for va, v in lists.items()},
        'reference_census': census,
        'default_skip': 'tag 0 and payload 0x14 (#6224) = {"C": 20}',
        'gates_changed': False,
    }


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    data = binary.read_bytes()
    _, fdes, _ = fde_extents(data)
    result = bind(data, fdes)
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
    print('leverage lists=%s callers=%s' % (result['name_lists'], result['callers']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
