#!/usr/bin/env python3
"""Bind the node #115 per-user p.p and D item layouts.

Continues #6223. The per-user value 0x3beac00 has two sequences whose items
were not mapped: p.p (0x48-byte items, written by 0x4634470) and D (0x18-byte
items, written by 0x45fa240). This tool binds, from the bytes:

1. both item writers write each item as a JSON pair [key, value];
2. p.p: key = u64 at item+0 (0x37be790), value = struct at item+8
   (0x448ae20) with fields s, l, M, f, e;
3. the f struct (0x448b410): a (+0x0), o (+0x8), c (+0x10), each i64;
4. D: key = item+0 written as a quoted string through Display 0x44dbf10,
   which jumps through the date slot 0x64e1158; value = struct at item+8
   (0x3674da0) with fields a (+0x0) and c (+0x8), each u64;
5. the integer writers: 0x37be790 and 0x4301950 (u64, 20-digit buffer),
   0x46ef430 (u32, 10-digit buffer), 0x41d5380 (i64, from #6223).

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-user-state-items-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

PP_ITEMS = 0x4634470
PP_VALUE = 0x448ae20
F_STRUCT = 0x448b410
D_ITEMS = 0x45fa240
D_KEY = 0x46f3a10
D_VALUE = 0x3674da0
I64_WRITER = 0x41d5380
U64_KEY = 0x37be790
U64_E = 0x4301950
U32_M = 0x46ef430

# (lea rsi va, name address, name byte)
NAMES = {
    0x448af18: (0x7d082f, b's'),
    0x448af87: (0x7d0946, b'l'),
    0x448afff: (0x7d13c1, b'M'),
    0x448b06d: (0x7d13cd, b'f'),
    0x448b0f3: (0x7d0bd9, b'e'),
    0x448b4c5: (0x7d098e, b'a'),
    0x448b52e: (0x7d0929, b'o'),
    0x448b59a: (0x7d0c8d, b'c'),
    0x3674e0e: (0x79d2d7, b'a'),
    0x3674f4b: (0x79d2d8, b'c'),
}
# direct calls: (call va, target)
CALLS = {
    0x4664aab: PP_ITEMS,     # p.p sequence -> item writer (#6223)
    0x464d19b: D_ITEMS,      # D sequence -> item writer (#6223)
    0x4634781: U64_KEY,      # p.p key
    0x463482d: PP_VALUE,     # p.p value
    0x448af6f: I64_WRITER,   # s
    0x448afdc: 0x420a0d0,    # l
    0x448b010: 0x4648d30,    # M
    0x4648d7f: U32_M,        # M value
    0x448b0c3: F_STRUCT,     # f
    0x448b107: 0x4649110,    # e
    0x4649160: U64_E,        # e value
    0x448b51b: I64_WRITER,   # f.a
    0x448b587: I64_WRITER,   # f.o
    0x448b5ef: I64_WRITER,   # f.c
    0x45fa54d: D_KEY,        # D key
    0x45fa60d: D_VALUE,      # D value
    0x3674e20: 0x465f980,    # D value a (u64 writer, #6223)
    0x3674f5d: 0x465f980,    # D value c
}
# rip-relative references: (va, prefix, length, target)
RIP = (
    (0x37be7c0, b'\x4c\x8d\x05', 7, 0x7a1643),   # digit table
    (0x46f3a79, b'\x48\x8d\x05', 7, 0x44dbf10),  # D key Display
    (0x46f3a9b, b'\xff\x15', 6, 0x64df6f0),      # core::fmt::write slot
    (0x44dbf19, b'\xff\x25', 6, 0x64e1158),      # date writer slot
)
FIXED = {
    # p.p item writer 0x4634470
    0x46344c8: '48b9398ee3388ee3388e',  # movabs rcx,0x8e38e38e38e38e39   /9
    0x463451d: 'c604305b',              # '['
    0x46345a5: '488d4848',              # lea rcx,[rax+0x48]             next item
    0x46345ae: '488d5008',              # lea rdx,[rax+0x8]              value
    0x46345d3: '4889442458',            # [rsp+0x58] = item
    0x46345e0: '4889542460',            # [rsp+0x60] = item+8
    0x4634775: '498b3c24',              # rdi = serializer
    0x4634779: '488b442458',            # rax = item
    0x463477e: '488b30',                # rsi = [item]                   key u64
    0x4634820: '488b7c2460',            # rdi = item+8                   value
    0x46348f2: '42c604385d',            # ']'
    # p.p value 0x448ae20
    0x448ae31: '8b4f04',                # ecx = dword [+0x4]             l
    0x448ae34: '83f114',                # xor ecx,0x14
    0x448ae39: '0b0f',                  # or ecx, dword [+0x0]
    0x448ae3f: '488b4f20',              # f +0x20
    0x448ae43: '480b4f18',              # f +0x18
    0x448ae59: '4c8b7310',              # s +0x10
    0x448ae5d: '448b4338',              # M +0x38 (dword)
    0x448ae61: '488b5328',              # f +0x28
    0x448ae65: '488b4b30',              # e +0x30
    0x448ae82: '4183f814',              # cmp r8d,0x14                   M default
    0x448aed2: 'c604017b',              # '{'
    0x448affb: '488d4b38',              # lea rcx,[rbx+0x38]             M
    0x448b08e: '488d7b18',              # lea rdi,[rbx+0x18]             f
    0x448b0ef: '4883c330',              # add rbx,0x30                   e
    # f struct 0x448b410
    0x448b42f: '4c8b27',                # a = [+0x0]
    0x448b432: '488b4f08',              # o = [+0x8]
    0x448b436: '488b4710',              # c = [+0x10]
    # l writer head
    0x420a0e5: '833f01',                # cmp dword [rdi],0x1            tag
    # M and e value loads
    0x4648d76: '8b3b',                  # mov edi,dword [rbx]            u32
    0x4649156: '488b3b',                # mov rdi,qword [rbx]            u64
    # D item writer 0x45fa240
    0x45fa375: '488d4818',              # lea rcx,[rax+0x18]             next item
    0x45fa37e: '488d5008',              # lea rdx,[rax+0x8]
    0x45fa3a3: '4889442460',            # [rsp+0x60] = item
    0x45fa3b0: '4889542458',            # [rsp+0x58] = item+8
    0x45fa540: '488b7c2460',            # rdi = item                     key
    0x45fa600: '488b7c2458',            # rdi = item+8                   value
    0x46f3ab5: 'c6043022',              # closing '"' of the key
    # D value 0x3674da0
    0x3674dbf: '4c8b2f',                # a = [+0x0]
    0x3674dc2: '4c8b7f08',              # c = [+0x8]
    0x3674de7: 'c604017b',              # '{'
    0x3674f47: '4883c308',              # add rbx,0x8                    c
    # integer writers
    0x37be79e: '41bc14000000',          # 20-digit buffer
    0x37be7a4: '4881fe10270000',        # cmp rsi,0x2710
    0x4301951: 'b814000000',            # 20-digit buffer
    0x4301968: '49b84b598638d6c56d34',  # movabs r8,0x346dc5d63886594b
    0x46ef431: 'b80a000000',            # 10-digit buffer
    0x46ef447: 'ba5917b7d1',            # mov edx,0xd1b71759
}


def read_va(data, va, size):
    hits = [s for s in sections(data)
            if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(hits) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = hits[0]['offset'] + va - hits[0]['address']
    return data[off:off + size]


def rip_target(data, va, prefix, length):
    raw = read_va(data, va, length)
    if raw[:len(prefix)] != prefix:
        raise ValueError(f'instruction at {va:#x} changed')
    return va + length + struct.unpack_from('<i', raw, len(prefix))[0]


def bind(data):
    for va, expect in FIXED.items():
        if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
            raise ValueError(f'instruction at {va:#x} changed')
    for va, (target, name) in NAMES.items():
        if rip_target(data, va, b'\x48\x8d\x35', 7) != target:
            raise ValueError(f'name load at {va:#x} changed')
        if read_va(data, target, 1) != name:
            raise ValueError(f'field name at {target:#x} changed')
    for va, target in CALLS.items():
        if rip_target(data, va, b'\xe8', 5) != target:
            raise ValueError(f'call at {va:#x} changed')
    for va, prefix, length, target in RIP:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    for va in (U64_KEY, U64_E, U32_M):
        if b'\xf7\xd9' in read_va(data, va, 0x20):
            raise ValueError(f'unsigned formatter {va:#x} gained a negate')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'p_p_item': {
            'writer': hex(PP_ITEMS),
            'size': '0x48',
            'shape': '[key, value]',
            'key': {'offset': '+0x0', 'type': 'u64', 'writer': hex(U64_KEY)},
            'value': {'offset': '+0x8', 'writer': hex(PP_VALUE)},
        },
        'p_p_value_fields': {
            's': {'offset': '+0x10', 'type': 'i64', 'writer': hex(I64_WRITER), 'skip': 'value == 0'},
            'l': {'offset': '+0x0', 'type': 'tagged (dword tag +0x0, payload +0x4)', 'writer': '0x420a0d0',
                  'skip': 'dword +0x0 == 0 and dword +0x4 == 0x14'},
            'M': {'offset': '+0x38', 'type': 'u32', 'writer': '0x4648d30 -> ' + hex(U32_M), 'skip': 'value == 0x14'},
            'f': {'offset': '+0x18', 'type': 'struct {a, o, c}', 'writer': hex(F_STRUCT),
                  'skip': '+0x18, +0x20 and +0x28 all 0'},
            'e': {'offset': '+0x30', 'type': 'u64', 'writer': '0x4649110 -> ' + hex(U64_E), 'skip': 'value == 0'},
        },
        'f_fields': {
            'a': {'offset': '+0x0', 'type': 'i64', 'skip': 'value == 0'},
            'o': {'offset': '+0x8', 'type': 'i64', 'skip': 'value == 0'},
            'c': {'offset': '+0x10', 'type': 'i64', 'skip': 'value == 0'},
        },
        'd_item': {
            'writer': hex(D_ITEMS),
            'size': '0x18',
            'shape': '[key, value]',
            'key': {'offset': '+0x0', 'type': 'quoted string from Display 0x44dbf10 (date slot 0x64e1158)',
                    'writer': hex(D_KEY)},
            'value': {'offset': '+0x8', 'writer': hex(D_VALUE)},
        },
        'd_value_fields': {
            'a': {'offset': '+0x0', 'type': 'u64', 'writer': '0x465f980', 'skip': 'value == 0'},
            'c': {'offset': '+0x8', 'type': 'u64', 'writer': '0x465f980', 'skip': 'value == 0'},
        },
        'integer_writers': {
            hex(U64_KEY): 'unsigned 20-digit (u64)',
            hex(U64_E): 'unsigned 20-digit (u64)',
            hex(U32_M): 'unsigned 10-digit (u32)',
            hex(I64_WRITER): 'signed (i64), from #6223',
        },
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
    print('p_p_value=' + ','.join(result['p_p_value_fields'])
          + ' d_value=' + ','.join(result['d_value_fields']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
