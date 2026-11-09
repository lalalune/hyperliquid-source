#!/usr/bin/env python3
"""Bind where node #115's output-flag struct comes from and what setter byte +0x18 does (13th stage).

Continues #5883 (the flag reader 0x564d390) and #5892 (the two pollers build
the setter 0x51cf360 argument with +0x18 = 0 and the flags shifted by one).
This tool binds:

1. the subcommand matcher: after matching `run-non-validator` the reader
   (slot 0x64ebcb8 -> 0x564d390) writes its struct to enum +0x8 and the tag
   is 2; after matching `run-validator` the same reader writes enum +0x8 and
   the tag is 3;
2. the parent future 0x2ae41e0: it copies its +0x10..+0x50 to +0xc0..+0x100,
   switches on the qword at +0xc0 (tag 2 -> table case 0, tag 3 -> case 1),
   and in both cases copies +0xc8..+0xf0 (0x28 bytes) to the poller future
   +0x0..+0x28 at +0x220, stores a mode byte (2 or 1) at future +0x28, and
   calls the poller 0x2aeaef0;
3. setter byte +0x18: copied to [rsp+0x13] at 0x51cf387 and tested only at
   0x51d0856; when set, two 0x38-byte values are built (empty Vec, f64 15.0)
   and copied to output +0xae0 and +0xb18; when clear both get the tag rbp+1.
   #5892 shows both setter callers pass 0, so the set branch is not taken on
   those paths.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-output-flags-origin-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

READER, READER_SLOT = 0x564d390, 0x64ebcb8
SETTER, SETTER_SLOT = 0x51cf360, 0x64e7428
PARENT, POLLER = 0x2ae41e0, 0x2aeaef0
JUMP_TABLE = 0x60411c
NON_VALIDATOR = (0x454460, b'run-non-validato', 0x453cb0, b'r')
FIFTEEN = 0x402e000000000000

FIXED = {
    # matcher: run-non-validator -> reader -> tag 2
    0x56550a2: 'f30f6f00',                  # movdqu xmm0, [rax]
    0x56550a6: '0fb64010',                  # movzx eax, byte [rax+0x10]
    0x56550c6: '3dffff0000',                # cmp eax, 0xffff
    0x56550da: '488d7b08',                  # lea rdi, [rbx+8]
    0x56550e4: '48c70302000000',            # mov qword [rbx], 2
    # matcher: run-validator -> reader -> tag 3
    0x5654e03: '48b972756e2d76616c69',      # movabs rcx, 'run-vali'
    0x5654e0d: '483308',                    # xor rcx, [rax]
    0x5654e10: '48ba616c696461746f72',      # movabs rdx, 'alidator'
    0x5654e1a: '48335005',                  # xor rdx, [rax+5]
    0x56551e5: '488d7b08',                  # lea rdi, [rbx+8]
    0x56551ef: '48c70303000000',            # mov qword [rbx], 3
    # parent: +0x10..+0x50 -> +0xc0..+0x100
    0x2ae4548: '0f104310',                  # movups xmm0, [rbx+0x10]
    0x2ae454c: '0f104b20',
    0x2ae4550: '0f105330',
    0x2ae4554: '0f105b40',
    0x2ae4558: '0f119bf0000000',            # -> +0xf0
    0x2ae455f: '0f1193e0000000',            # -> +0xe0
    0x2ae4566: '0f118bd0000000',            # -> +0xd0
    0x2ae456d: '0f1183c0000000',            # -> +0xc0
    # parent: switch on +0xc0 (tag - 2, else case 12)
    0x2ae4586: '488d83c0000000',            # lea rax, [rbx+0xc0]
    0x2ae458d: '488b00',                    # mov rax, [rax]
    0x2ae4593: '4883e902',                  # sub rcx, 2
    0x2ae4597: 'ba0c000000',                # mov edx, 12
    0x2ae459c: '480f43d1',                  # cmovae rdx, rcx
    0x2ae45ae: '48631491',                  # movsxd rdx, [rcx+rdx*4]
    0x2ae45b5: 'ffe2',                      # jmp rdx
    # case 0 (tag 2): payload +0xc8..+0xf0 -> future +0x220.., mode 2, call poller
    0x2ae45da: '0f1083c8000000',
    0x2ae45e1: '0f118320020000',
    0x2ae45e8: '0f1083d8000000',
    0x2ae45ef: '0f118330020000',
    0x2ae45f6: '488b8be8000000',
    0x2ae45fd: '48898b40020000',
    0x2ae4604: 'c6834802000002',            # mov byte [rbx+0x248], 2
    0x2ae461d: '4c8db320020000',            # lea r14, [rbx+0x220]
    0x2ae4624: '4c89f7',                    # mov rdi, r14
    # case 1 (tag 3): same copy, mode 1
    0x2ae543f: '0f1083c8000000',
    0x2ae5446: '0f118320020000',
    0x2ae544d: '0f1083d8000000',
    0x2ae5454: '0f118330020000',
    0x2ae545b: '488b8be8000000',
    0x2ae5462: '48898b40020000',
    0x2ae5469: 'c6834802000001',            # mov byte [rbx+0x248], 1
    0x2ae5482: '4c8db320020000',
    0x2ae5489: '4c89f7',
    # setter byte +0x18
    0x51cf383: '0fb64618',                  # movzx eax, byte [rsi+0x18]
    0x51cf387: '88442413',                  # mov [rsp+0x13], al
    0x51d0856: '807c241300',                # cmp byte [rsp+0x13], 0
    0x51d085b: '745f',                      # je 0x51d08bc
    0x51d085d: '48c784242002000008000000',  # mov qword [rsp+0x220], 8
    0x51d0874: '48b8000000000000' + '2e40',  # movabs rax, 15.0
    0x51d087e: '4889842438020000',          # mov [rsp+0x238], rax
    0x51d0891: '48c784245802000008000000',  # mov qword [rsp+0x258], 8
    0x51d08a5: '4889842470020000',          # mov [rsp+0x270], rax
    0x51d08b8: '31c0',                      # xor eax, eax  (set: tag 0)
    0x51d08bc: '488d4501',                  # lea rax, [rbp+1] (clear)
    0x51d08c5: '4889842418020000',          # mov [rsp+0x218], rax
    0x51d08cd: '4889842450020000',          # mov [rsp+0x250], rax
    0x51d09e3: '0f10842418020000',          # movups xmm0, [rsp+0x218]
    0x51d09eb: '410f1187e00a0000',          # movups [r15+0xae0], xmm0
    0x51d0a31: '0f10842450020000',          # movups xmm0, [rsp+0x250]
    0x51d0a59: '410f1187180b0000',          # movups [r15+0xb18], xmm0
}
CALLS = (
    # (va, prefix, length, target)
    (0x56550de, b'\xff\x15', 6, READER_SLOT),
    (0x56551e9, b'\xff\x15', 6, READER_SLOT),
    (0x56550ae, b'\x66\x0f\x74\x05', 8, NON_VALIDATOR[0]),
    (0x56550b6, b'\x66\x0f\x74\x0d', 8, NON_VALIDATOR[2]),
    (0x5654e21, b'\x0f\x84', 6, 0x56551d8),
    (0x56551d8, b'\x48\x8b\x76\x10', 0, None),
    (0x2ae45a7, b'\x48\x8d\x0d', 7, JUMP_TABLE),
    (0x2ae4627, b'\xe8', 5, POLLER),
    (0x2ae548c, b'\xe8', 5, POLLER),
)


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return data[off:off + size]


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def target(data, va, prefix, length):
    raw = read_va(data, va, max(length, len(prefix)))
    if raw[:len(prefix)] != prefix:
        raise ValueError(f'instruction at {va:#x} changed')
    if not length:
        return None
    return va + length + struct.unpack_from('<i', raw, len(prefix))[0]


def relative(data, slot):
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        for va, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if va == slot and info & 0xffffffff == 8:
                return addend
    raise ValueError(f'no relative relocation at {slot:#x}')


def jump_case(data, index):
    return JUMP_TABLE + struct.unpack('<i', read_va(data, JUMP_TABLE + 4 * index, 4))[0]


def frame(fdes, va):
    hits = [f for f in fdes if f['start'] <= va < f['end']]
    if len(hits) != 1:
        raise ValueError(f'{va:#x} is not in exactly one FDE')
    return hits[0]['start'], hits[0]['end']


def rsp13_accesses(data, lo, hi):
    """Byte census: ModRM/SIB [rsp+0x13] with disp8 inside the setter FDE."""
    code = read_va(data, lo, hi - lo)
    return [lo + m.start() for m in re.finditer(rb'[\x44\x4c\x54\x5c\x64\x6c\x74\x7c]\x24\x13', code)]


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, want in CALLS:
        if target(data, va, prefix, length) != want:
            raise ValueError(f'reference at {va:#x} changed')
    if relative(data, READER_SLOT) != READER or relative(data, SETTER_SLOT) != SETTER:
        raise ValueError('slot relocation changed')
    if read_va(data, NON_VALIDATOR[0], 16) != NON_VALIDATOR[1] or read_va(data, NON_VALIDATOR[2], 1) != NON_VALIDATOR[3]:
        raise ValueError('subcommand name changed')
    words = (read_va(data, 0x5654e05, 8) + read_va(data, 0x5654e12, 8)[3:]).decode()
    if words != 'run-validator':
        raise ValueError('run-validator constant changed')
    cases = {2: jump_case(data, 0), 3: jump_case(data, 1)}
    if cases != {2: 0x2ae45b7, 3: 0x2ae5421}:
        raise ValueError('parent dispatch changed')
    for case, first in ((0x2ae45b7, 0x2ae45da), (0x2ae5421, 0x2ae543f)):
        if frame(fdes, case) != frame(fdes, first) or frame(fdes, case)[0] != PARENT:
            raise ValueError('case outside the parent future')
    if struct.unpack('<Q', read_va(data, 0x51d0876, 8))[0] != FIFTEEN:
        raise ValueError('constant changed')
    setter = frame(fdes, SETTER)
    accesses = rsp13_accesses(data, *setter)
    if accesses != [0x51cf388, 0x51d0857]:  # ModRM byte of 0x51cf387 and 0x51d0856
        raise ValueError('setter byte +0x18 access census changed')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'subcommands': {
            'run-non-validator': 'match at %s (16 bytes %s + %s); reader slot %s -> %s writes enum +0x8; tag 2 at %s'
                                 % (hex(0x56550a2), hex(NON_VALIDATOR[0]), hex(NON_VALIDATOR[2]), hex(READER_SLOT),
                                    hex(READER), hex(0x56550e4)),
            'run-validator': 'match at %s (%r at +0, +5); reader writes enum +0x8; tag 3 at %s'
                             % (hex(0x5654e03), words, hex(0x56551ef)),
        },
        'parent_future': {
            'fn': hex(PARENT),
            'copy': '+0x10..+0x50 -> +0xc0..+0x100 (%s)' % hex(0x2ae4548),
            'switch': 'qword +0xc0 minus 2 indexes table %s, else case 12' % hex(JUMP_TABLE),
            'cases': {str(k): hex(v) for k, v in cases.items()},
            'poller_argument': 'both cases copy +0xc8..+0xf0 (0x28 bytes) to future +0x220..+0x248 '
                               'and call %s with rdi = +0x220' % hex(POLLER),
            'mode_byte_future_plus_0x28': {'tag 2': 2, 'tag 3': 1},
        },
        'setter_plus_0x18': {
            'copy': hex(0x51cf387) + ' mov [rsp+0x13], al',
            'test': hex(0x51d0856) + ' cmp byte [rsp+0x13], 0',
            'rsp13_accesses_in_setter_fde': [hex(v) for v in accesses],
            'set': 'two 0x38-byte values: qword 0 (tag), 8 (dangling ptr), 0, 0, f64 15.0, dword 0',
            'clear': 'both tags = rbp + 1 (%s)' % hex(0x51d08bc),
            'stored': ['output +0xae0 (%s)' % hex(0x51d09eb), 'output +0xb18 (%s)' % hex(0x51d0a59)],
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
    print('cases=%s' % result['parent_future']['cases'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
