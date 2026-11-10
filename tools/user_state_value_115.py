#!/usr/bin/env python3
"""Bind the node #115 per-user state value written for each user_to_state entry.

Continues #6221. Clearinghouse.user_states.user_to_state writes each entry as a
[key, value] pair, and the value goes through the pretty JSON serializer
0x3beac00. This tool binds, from the bytes:

1. the six fields 0x3beac00 writes, each skipped when it holds its default:
   u (+0x48) i64, p (+0x0) struct, D (+0x28) sequence, l (+0x68) date-time,
   S (+0x50) struct, r (+0x60) u64;
2. the p struct (0x4206910): p (+0x0) a two-slice sequence of 0x48-byte items
   and n (+0x20) u64;
3. the D sequence (0x464d090): a two-slice sequence of 0x18-byte items;
4. the S struct (0x36752b0): s (+0x0) u64 and r (+0x8) u64;
5. the integer writers: 0x41d5380 negates negative inputs (signed), 0x46ef580
   does not (unsigned);
6. the l writer: core::fmt::write with Display 0x46dd720, which calls the date
   slot 0x64e1158 and then writes 'T'.

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
PACKET = ROOT / 'research/work-items/RE-008-user-state-value-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

VALUE = 0x3beac00
P_STRUCT = 0x4206910
D_SEQ = 0x464d090
S_STRUCT = 0x36752b0
I64_WRITER = 0x41d5380
U64_FORMAT = 0x46ef580
L_WRITER = 0x4592eb0
L_DISPLAY = 0x46dd720

# (va, name bytes) for each field-name load: lea rsi,[rip+d] then mov edx,1
NAMES = {
    0x3bead84: (0x7ba759, b'u'),
    0x3beae25: (0x7b9bbb, b'p'),
    0x3beaec0: (0x7bad69, b'D'),
    0x3beaf05: (0x7b9af7, b'l'),
    0x3beaf93: (0x7bad6a, b'S'),
    0x3beb013: (0x7b9b44, b'r'),
    0x42069fe: (0x7c828e, b'p'),
    0x4206a37: (0x7c89f4, b'n'),
    0x367531e: (0x79cc47, b's'),
    0x367545b: (0x79c5d3, b'r'),
}
# direct calls: (call va, target)
CALLS = {
    0x3beaddf: I64_WRITER,   # u
    0x3beae7e: P_STRUCT,     # p
    0x3beaed4: D_SEQ,        # D
    0x3beaf6f: L_WRITER,     # l
    0x3beafe9: S_STRUCT,     # S
    0x3beb027: 0x465f980,    # r
    0x4206a12: 0x46649a0,    # p.p
    0x4206a4b: 0x4648c20,    # p.n
    0x4648c70: U64_FORMAT,   # p.n value
    0x465f9d0: U64_FORMAT,   # r value
    0x3675330: 0x465f980,    # S.s
    0x367546d: 0x4654de0,    # S.r
    0x4654e2f: U64_FORMAT,   # S.r value
    0x4664aab: 0x4634470,    # p.p sequence
    0x464d19b: 0x45fa240,    # D sequence
}
# rip-relative loads: (va, prefix, length, target)
RIP = (
    (0x4592f05, b'\x48\x8d\x05', 7, L_DISPLAY),
    (0x4592f27, b'\xff\x15', 6, 0x64df6f0),
    (0x46dd733, b'\xff\x15', 6, 0x64e1158),
)
FIXED = {
    0x3beac14: '488b4748',          # mov rax,[rdi+0x48]         u
    0x3bead75: '4885ff',            # test rdi,rdi               skip u when 0
    0x3beac5b: '498d7d28',          # lea rdi,[r13+0x28]         D
    0x3beac88: 'b91a40f600',        # mov ecx,0xf6401a           l default date
    0x3beac9f: '490b4d50',          # or rcx,[r13+0x50]          S non-zero
    0x3beacc2: '498b4d60',          # mov rcx,[r13+0x60]         r
    0x3beaf26: '498d5d68',          # lea rbx,[r13+0x68]         l
    0x3beafb4: '498d7d50',          # lea rdi,[r13+0x50]         S
    0x3beb00f: '4983c560',          # add r13,0x60               r
    0x41d5391: '48f7d9',            # neg rcx                    signed
    0x41d5394: '480f48ce',          # cmovs rcx,rsi
    0x46ef580: '53b814000000',      # push rbx; mov eax,0x14     unsigned, no neg
    0x4206a33: '4883c320',          # add rbx,0x20               p.n
    0x4664a54: '488d0cc9',          # lea rcx,[rcx+rcx*8]        0x48 items
    0x4664a58: '488d3cca',          # lea rdi,[rdx+rcx*8]
    0x464d144: '488d0c49',          # lea rcx,[rcx+rcx*2]        0x18 items
    0x464d148: '488d3cca',          # lea rdi,[rdx+rcx*8]
    0x3675457: '4883c308',          # add rbx,0x8                S.r
    0x46dd744: 'be54000000',        # mov esi,'T'
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
    if b'\xf7' in read_va(data, U64_FORMAT, 0x10):
        raise ValueError('unsigned formatter gained a negate')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'value_serializer': hex(VALUE),
        'fields': {
            'u': {'offset': '+0x48', 'type': 'i64', 'writer': hex(I64_WRITER), 'skip': 'value == 0'},
            'p': {'offset': '+0x0', 'type': 'struct {p, n}', 'writer': hex(P_STRUCT), 'skip': 'p.p empty and n == 0'},
            'D': {'offset': '+0x28', 'type': 'two-slice sequence of 0x18-byte items', 'writer': hex(D_SEQ), 'skip': 'empty'},
            'l': {'offset': '+0x68', 'type': 'date-time (date, then T, then time)', 'writer': hex(L_WRITER), 'skip': 'date 0xf6401a and +0x6c == 0 and +0x70 == 0'},
            'S': {'offset': '+0x50', 'type': 'struct {s: u64 +0x0, r: u64 +0x8}', 'writer': hex(S_STRUCT), 'skip': 'both words 0'},
            'r': {'offset': '+0x60', 'type': 'u64', 'writer': '0x465f980', 'skip': 'value == 0'},
        },
        'p_struct': {
            'p': {'offset': '+0x0', 'type': 'two-slice sequence of 0x48-byte items', 'writer': '0x46649a0 -> 0x4634470'},
            'n': {'offset': '+0x20', 'type': 'u64', 'writer': '0x4648c20 -> 0x46ef580'},
        },
        'integer_writers': {
            hex(I64_WRITER): 'signed: neg rcx / cmovs at 0x41d5391',
            hex(U64_FORMAT): 'unsigned: no neg in the first 0x10 bytes',
        },
        'l_display': hex(L_DISPLAY) + ': date slot 0x64e1158, then mov esi,0x54 (T)',
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
    print('fields=' + ','.join(result['fields']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
