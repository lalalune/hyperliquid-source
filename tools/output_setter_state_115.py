#!/usr/bin/env python3
"""Bind where node #115 keeps the boxed output-setter result (15th stage).

The 14th stage found that 0x548ce30 places the 0xb70-byte output-setter result
at +0x7c0 of a new 0x4e38-byte allocation (the box) and returns it to
0x5a6bfb0 at 0x5a6c0af. This tool binds what 0x5a6bfb0 does with the box:

1. it reads box +0x28 and stores it in a new 0x18-byte {1, 1, value} block;
2. it builds a 0x470-byte value with the box at +0x450, that block at +0x458,
   the constant 0xf6401a at +0x460 and zero bytes at +0x468..+0x46d, and
   passes the box-holding value to 0x5a08720, which reloads the box from
   +0x450 and tests box +0x28 % 10000 == 0 (multiply 0xd288ce703afb7e91,
   ror 4, unsigned compare below 0x68db8bac710cc);
3. it passes the 0x470-byte value with the 16-byte name "fast_abci_engine"
   and Location 0x64b89d0 (node/src/node.rs:608:9) to 0x567bd50, which copies
   it to +0x6b0 of a 0xb28-byte result (tag qword 0 at +0x6a8) and stores
   1_000_000_000 at +0x128; the box pointer is therefore at result +0xb00;
4. it copies that result to +0x10 of a 0xb38-byte {1, 1, ...} allocation
   (box pointer at +0xb10) and calls 0x4f1b280 on allocation +0x140 with the
   11-byte name "fast_height" and Location 0x64b89e8 (node/src/node.rs:623:40).

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
PACKET = ROOT / 'research/work-items/RE-008-output-setter-state-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

ENGINE_NAME = (0x4519a0, b'fast_abci_engine')
HEIGHT_NAME = (0x93afb9, b'fast_height')
SOURCE = (0x44aca3, b'node/src/node.rs')
LOCATIONS = {0x64b89d0: (608, 9), 0x64b89e8: (623, 40)}
MAGIC, LIMIT = 0xd288ce703afb7e91, 0x68db8bac710cc

FIXED = {
    # 0x548ce30: box allocation, returned in rax
    0x548d82f: 'bf384e0000',                  # mov edi, 0x4e38
    0x548d847: 'ba384e0000',                  # mov edx, 0x4e38
    0x548d84f: '4989c6',                      # mov r14, rax
    0x548d868: '4c89f0',                      # mov rax, r14
    # 0x5a6bfb0: box +0x28 into a {1, 1, value} block
    0x5a6c0af: '4989c6',                      # mov r14, rax              (box)
    0x5a6c0b2: '4c8b7828',                    # mov r15, [rax+0x28]
    0x5a6c0b6: 'bf18000000',                  # mov edi, 0x18
    0x5a6c0cd: '48c70001000000',              # mov qword [rax], 1
    0x5a6c0d4: '48c7400801000000',            # mov qword [rax+8], 1
    0x5a6c0dc: '4c897810',                    # mov [rax+0x10], r15
    # the 0x470-byte value at rsp+0x1240
    0x5a6c10a: '4c89b42490160000',            # mov [rsp+0x1690], r14     (+0x450 box)
    0x5a6c11a: '4c89a42498160000',            # mov [rsp+0x1698], r12     (+0x458 block)
    0x5a6c122: '4c8db42440120000',            # lea r14, [rsp+0x1240]
    0x5a6c132: 'ba50040000',                  # mov edx, 0x450
    0x5a6c140: '48c78424a01600001a40f600',    # mov qword [rsp+0x16a0], 0xf6401a (+0x460)
    0x5a6c112: 'c68424ac16000000',            # mov byte [rsp+0x16ac], 0  (+0x46c)
    0x5a6c14c: 'c78424a816000000000000',      # mov dword [rsp+0x16a8], 0 (+0x468)
    0x5a6c157: 'c68424ad16000000',            # mov byte [rsp+0x16ad], 0  (+0x46d)
    0x5a6c1c4: '488db42440120000',            # lea rsi, [rsp+0x1240]
    0x5a6c1cc: 'ba70040000',                  # mov edx, 0x470
    0x5a6c214: 'b910000000',                  # mov ecx, 16               (name length)
    # 0x567bd50: tag 0 + value at +0x6a8, 1e9 at +0x128
    0x567bd70: '48c784242006000000000000',    # mov qword [rsp+0x620], 0
    0x567bd7c: '488dbc2428060000',            # lea rdi, [rsp+0x628]
    0x567bd84: 'ba70040000',                  # mov edx, 0x470
    0x567c0c7: '498dbda8060000',              # lea rdi, [r13+0x6a8]
    0x567c0ce: '488db42420060000',            # lea rsi, [rsp+0x620]
    0x567c0dd: 'ba78040000',                  # mov edx, 0x478
    0x567c165: '41c78528010000' + '00ca9a3b', # mov dword [r13+0x128], 1000000000
    # 0x5a6bfb0: {1, 1, result} allocation and fast_height
    0x5a6c2be: '48c784244012000001000000', # mov qword [rsp+0x1240], 1
    0x5a6c2ca: '48c784244812000001000000', # mov qword [rsp+0x1248], 1
    0x5a6c2de: 'ba280b0000',                  # mov edx, 0xb28
    0x5a6c2ec: 'bf380b0000',                  # mov edi, 0xb38
    0x5a6c331: '48c78424501200000b000000',    # mov qword [rsp+0x1250], 11
    0x5a6c34c: '4881c740010000',              # add rdi, 0x140
    # 0x5a08720: box reload and % 10000 test
    0x5a08737: '488bb650040000',              # mov rsi, [rsi+0x450]
    0x5a0873e: '4c8b7e28',                    # mov r15, [rsi+0x28]
    0x5a0874c: '490fafc7',                    # imul rax, r15
    0x5a08750: '48c1c804',                    # ror rax, 4
    0x5a0875e: '4839c8',                      # cmp rax, rcx
    0x5a08761: '7222',                        # jb 0x5a08785
}
IMMEDIATES = {0x5a08742: (b'\x48\xb8', MAGIC), 0x5a08754: (b'\x48\xb9', LIMIT)}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x548d834, b'\xff\x15', 6, 0x64df480),       # allocator slot
    (0x548d852, b'\xff\x15', 6, 0x64df508),       # memcpy slot
    (0x5a6c0aa, b'\xe8', 5, 0x548ce30),
    (0x5a6c16a, b'\xe8', 5, 0x5a08720),
    (0x5a6c1ea, b'\x48\x8d\x05', 7, 0x64b89d0),
    (0x5a6c1f5, b'\x48\x8d\x15', 7, ENGINE_NAME[0]),
    (0x5a6c21c, b'\xe8', 5, 0x567bd50),
    (0x5a6c322, b'\x48\x8d\x05', 7, HEIGHT_NAME[0]),
    (0x5a6c353, b'\x4c\x8d\x05', 7, 0x64b89e8),
    (0x5a6c364, b'\xe8', 5, 0x4f1b280),
)


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return data[off:off + size]


def rip_target(data, va, prefix, length):
    raw = read_va(data, va, length)
    if raw[:len(prefix)] != prefix:
        raise ValueError(f'instruction at {va:#x} changed')
    return va + length + struct.unpack_from('<i', raw, len(prefix))[0]


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


def location(data, rel, va):
    if rel.get(va) != SOURCE[0]:
        raise ValueError(f'Location {va:#x} file pointer changed')
    length, line, col = struct.unpack('<QII', read_va(data, va + 8, 16))
    if length != len(SOURCE[1]):
        raise ValueError(f'Location {va:#x} file length changed')
    return line, col


def divisor(magic, limit):
    """x * magic rotated right by 4 is below limit exactly when x % (16 * inverse) == 0."""
    odd = pow(magic, -1, 1 << 64)
    n = odd << 4
    if limit != (2**64 - 1) // n + 1:
        raise ValueError('divisibility limit changed')
    return n


def divisible(x):
    v = (x * MAGIC) & (2**64 - 1)
    v = ((v >> 4) | (v << 60)) & (2**64 - 1)
    return v < LIMIT


def bind(data):
    for va, expect in FIXED.items():
        if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
            raise ValueError(f'instruction at {va:#x} changed')
    for va, (prefix, value) in IMMEDIATES.items():
        if read_va(data, va, 10) != prefix + struct.pack('<Q', value):
            raise ValueError(f'immediate at {va:#x} changed')
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    for va, text in (ENGINE_NAME, HEIGHT_NAME, SOURCE):
        if read_va(data, va, len(text)) != text:
            raise ValueError(f'string at {va:#x} changed')
    rel = relative_relocations(data)
    locs = {va: location(data, rel, va) for va in LOCATIONS}
    if locs != LOCATIONS:
        raise ValueError('Location line or column changed')
    n = divisor(MAGIC, LIMIT)
    samples = {x: divisible(x) for x in (0, 1, 5000, 9999, 10000, 20000, 123450000, 123456789)}
    if any(v != (x % n == 0) for x, v in samples.items()):
        raise ValueError('divisibility predicate disagrees')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'box': {
            'allocation': '0x548ce30 allocates 0x4e38 bytes (0x548d82f) and returns the pointer (0x548d868)',
            'setter_result_at': '+0x7c0 (stage 14); setter +0xae0/+0xb18 at box +0x12a0/+0x12d8',
            'height_block': '0x5a6c0b2 reads box +0x28 into a new 0x18-byte {1, 1, value} block',
        },
        'engine_value': {
            'size': '0x470',
            'fields': {'+0x450': 'box', '+0x458': '{1, 1, box+0x28} block', '+0x460': hex(0xf6401a),
                       '+0x468': 'dword 0', '+0x46c': 'byte 0', '+0x46d': 'byte 0'},
            'check': '0x5a08720 reloads the box from +0x450 (0x5a08737) and tests box +0x28 %% %d == 0' % n,
            'divisibility_samples': {str(k): v for k, v in samples.items()},
        },
        'runner': {
            'builder': '0x567bd50',
            'name': '%s %r (ecx = %d)' % (hex(ENGINE_NAME[0]), ENGINE_NAME[1].decode(), len(ENGINE_NAME[1])),
            'location': '%s %s:%d:%d' % ((hex(0x64b89d0), SOURCE[1].decode()) + locs[0x64b89d0]),
            'layout': 'result 0xb28 bytes: tag qword 0 at +0x6a8, engine value at +0x6b0, '
                      '1000000000 at +0x128; box pointer at +0xb00',
        },
        'shared': {
            'allocation': '0xb38 bytes: {1, 1} then the runner at +0x10; box pointer at +0xb10',
            'fast_height': '0x4f1b280 on allocation +0x140 with %s %r and %s %s:%d:%d'
                           % ((hex(HEIGHT_NAME[0]), HEIGHT_NAME[1].decode(), hex(0x64b89e8), SOURCE[1].decode())
                              + locs[0x64b89e8]),
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
    print(result['engine_value']['check'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
