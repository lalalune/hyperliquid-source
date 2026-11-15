#!/usr/bin/env python3
"""Bind the node #115 blp mode call 0x5609fb0, the blp side predicate and the move_token pair (stage 99).

Continues #6210 (stage 98), which found that 0x55817e0 calls 0x5609fb0 with
r8d = 3, then the slot 0x64e7180 predicate on Locus blp, then 0x5609fb0 with
r8d = 0, and ends in 0x5580d10. This tool binds:

1. the three 0x5609fb0 / predicate call sites in 0x55817e0 and their mode
   and side arguments;
2. 0x5609fb0 keeps the mode in ebp, passes it in edi to 0x57cbe30 (an
   eight-arm switch, jump table 0x9351f4; modes 0 and 3 return the mode at
   once, the other arms walk tables) and in ecx to 0x55a03c0 (which passes
   it on to 0x55a07e0); 0x5609fb0 returns tag 0x1a2 when 0x55a03c0 returns
   0x11, else tag 0xf1 with byte 0xc;
3. in 0x55a07e0 the mode is read only as (mode & 1) << 4: an offset of 0 or
   0x10 into 0x20/0x28-byte entries. So mode 3 selects the second 16-byte
   half and mode 0 the first;
4. the predicate 0x369b360 (only target of slot 0x64e7180): it looks the
   20-byte key up in the map at blp +0x88 (memcmp length 0x14), then the
   u64 argument in the value's inner map, and returns true when the entry's
   word at +0x8 + ((ecx ^ 1) << 4) is 0 or no entry exists. The 0x55817e0
   call passes ecx = 0, so it tests the second half;
5. 0x5580d10 adds 1 to Locus ctr (+0xab0, saturating) on entry; when its r8
   equals the first stack argument and r8 is 0 or r9 equals the second, it
   returns tag 0x1a2 with 0 at once; otherwise it calls 0x54df920 with
   r8d = 1 (failure formats 'move_token to_spot: ') and then with r8d = 0
   (failure formats 'move_token from_spot: ').

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import (RELATIVE, TARGET, direct_calls, fixed, frame, read_va,
                                 relative_relocations, rip_target)

PACKET = ROOT / 'research/work-items/RE-008-blp-mode-call-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

CALLER = 0x55817e0
MODE_CALL = 0x5609fb0
MODE_SWITCH = 0x57cbe30
MODE_TABLE = 0x9351f4
INNER = 0x55a03c0
SIDE_USER = 0x55a07e0
PREDICATE = 0x369b360
PREDICATE_SLOT = 0x64e7180
MOVE = 0x5580d10
MOVE_LEG = 0x54df920
TO_SPOT = (0x432bcb, b'\x14move_token to_spot: ')
FROM_SPOT = (0x438c95, b'\x16move_token from_spot: ')
MODE_ARMS = {0: 0x57cbfeb, 1: 0x57cbe4b, 2: 0x57cbf16, 3: 0x57cbfe6}

FIXED = {
    # 0x55817e0: first mode call (mode 3)
    0x558193d: '41b803000000',          # mov r8d, 3
    0x5581943: '4531c9',                # xor r9d, r9d
    # predicate on Locus blp with ecx = 0
    0x55819e1: '498dbf70060000',        # lea rdi, [r15+0x670]   (Locus blp)
    0x55819e8: '4889da',                # mov rdx, rbx
    0x55819eb: '31c9',                  # xor ecx, ecx
    0x55819f3: '84c0',                  # test al, al
    # second mode call (mode 0)
    0x5581a31: '4531c0',                # xor r8d, r8d
    0x5581a34: '4531c9',                # xor r9d, r9d
    # 0x5609fb0: mode kept and passed on
    0x5609fc4: '4489c5',                # mov ebp, r8d
    0x5609ff2: '4489c7',                # mov edi, r8d
    0x560a11b: '400fb6cd',              # movzx ecx, bpl
    0x560a137: '3c11',                  # cmp al, 0x11
    0x560a139: '750b',                  # jne error
    0x560a13f: '66c703a201',            # mov word [rbx], 0x1a2
    0x560a146: '66c703f100',            # mov word [rbx], 0xf1
    0x560a14b: 'c643020c',              # mov byte [rbx+2], 0xc
    # 0x57cbe30: switch on the mode byte
    0x57cbe37: '400fb6c7',              # movzx eax, dil
    0x57cbe42: '48631481',              # movsxd rdx, [rcx+rax*4]
    0x57cbe46: '4801ca',                # add rdx, rcx
    0x57cbfe6: 'b803000000',            # mov eax, 3   (mode 3 arm)
    0x57cbfeb: 'e9f3000000',            # jmp return   (mode 0 arm)
    # 0x55a03c0: mode passed on to 0x55a07e0
    0x55a03d8: '884c240e',              # mov [rsp+0xe], cl
    0x55a04f1: '0fb64c240e',            # movzx ecx, byte [rsp+0xe]
    # 0x55a07e0: mode read as (mode & 1) << 4
    0x55a07f9: '894c240c',              # mov [rsp+0xc], ecx
    0x55a0e5c: '0fb64c240c',            # movzx ecx, byte [rsp+0xc]
    0x55a0e61: '83e101',                # and ecx, 1
    0x55a0e64: 'c1e104',                # shl ecx, 4
    0x55a0e67: '488b6c0108',            # mov rbp, [rcx+rax+8]
    0x55a0f3c: '0fb64c240c',
    0x55a0f41: '83e101',
    0x55a0f44: 'c1e104',
    0x55a0f47: '488b2c01',              # mov rbp, [rcx+rax]
    # 0x369b360: key lookup and side test
    0x369b36e: '894c2404',              # mov [rsp+4], ecx
    0x369b37b: '488b9f88000000',        # mov rbx, [rdi+0x88]   (blp +0x88 map)
    0x369b3f9: 'ba14000000',            # mov edx, 0x14         (memcmp length)
    0x369b5c9: '8b442404',              # mov eax, [rsp+4]   (ecx argument)
    0x369b5cd: '3401',                  # xor al, 1
    0x369b5cf: '0fb6c0',
    0x369b5d2: 'c1e004',                # shl eax, 4
    0x369b5d5: '48837c010800',          # cmp qword [rcx+rax+8], 0
    0x369b5db: '0f94c0',                # sete al
    # 0x5580d10: ctr increment, early exit, two legs
    0x5580d24: '4d89c7',                # mov r15, r8
    0x5580d32: '488b86b00a0000',        # mov rax, [rsi+0xab0]   (Locus ctr)
    0x5580d39: '48ffc0',
    0x5580d43: '490f44c6',              # cmove rax, r14 (-1)
    0x5580d47: '488986b00a0000',
    0x5580d7e: '4c3bbc24b0010000',      # cmp r15, [rsp+0x1b0]   (stack arg 0)
    0x5580d86: '7517',
    0x5580d88: '4d85ff',                # test r15, r15
    0x5580d8b: '0f84da050000',          # je early exit
    0x5580d91: '483bac24b8010000',      # cmp rbp, [rsp+0x1b8]   (stack arg 1)
    0x5580d99: '0f84cc050000',          # je early exit
    0x55812a9: '41b801000000',          # mov r8d, 1
    0x55812cf: '0f8503010000',          # jne -> to_spot message block
    0x558134a: '4531c0',                # xor r8d, r8d
    0x558135f: '0f8532010000',          # jne -> from_spot message block
    0x558136b: '49c7450800000000',      # early exit: [r13+8] = 0
    0x5581373: '6641c74500a201',        # [r13] = 0x1a2
}
CALLS = (
    (0x5581946, MODE_CALL), (0x5581a37, MODE_CALL), (0x5609ff5, MODE_SWITCH),
    (0x560a132, INNER), (0x55a0504, SIDE_USER), (0x55812c0, MOVE_LEG), (0x5581350, MOVE_LEG),
)
REFERENCES = (
    (0x55819ed, b'\xff\x15', 6, PREDICATE_SLOT),
    (0x57cbe3b, b'\x48\x8d\x0d', 7, MODE_TABLE),
    (0x5581455, b'\x48\x8d\x35', 7, TO_SPOT[0]),
    (0x558152a, b'\x48\x8d\x35', 7, FROM_SPOT[0]),
)


def call_target(data, va):
    raw = read_va(data, va, 5)
    if raw[0] != 0xe8:
        raise ValueError(f'call at {va:#x} changed')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def table_arm(data, mode):
    return MODE_TABLE + struct.unpack_from('<i', read_va(data, MODE_TABLE + 4 * mode, 4))[0]


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, target in CALLS:
        if call_target(data, va) != target:
            raise ValueError(f'call at {va:#x} changed')
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    if relative_relocations(data).get(PREDICATE_SLOT) != PREDICATE:
        raise ValueError('predicate slot relocation changed')
    for va, text_bytes in (TO_SPOT, FROM_SPOT):
        if read_va(data, va, len(text_bytes)) != text_bytes:
            raise ValueError(f'string at {va:#x} changed')
    arms = {mode: table_arm(data, mode) for mode in MODE_ARMS}
    if arms != MODE_ARMS:
        raise ValueError('mode switch arms changed')
    for fn, va in ((CALLER, 0x5581946), (MODE_CALL, 0x5609ff5), (INNER, 0x55a0504),
                   (SIDE_USER, 0x55a0e5c), (PREDICATE, 0x369b5d5), (MOVE, 0x55812c0)):
        if frame(fdes, va) != fn:
            raise ValueError(f'{va:#x} left {fn:#x}')
    mode_calls = direct_calls(data, MODE_CALL)
    move_calls = direct_calls(data, MOVE)

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'caller_0x55817e0': {
            'mode_3_call': hex(0x5581946) + ' r8d=3 r9d=0',
            'predicate_call': hex(0x55819ed) + ' slot %s -> %s, rdi=box+0x670 (Locus blp), ecx=0'
                              % (hex(PREDICATE_SLOT), hex(PREDICATE)),
            'mode_0_call': hex(0x5581a37) + ' r8d=0 r9d=0, only when the predicate returns true',
        },
        'mode_call_0x5609fb0': {
            'direct_calls': len(mode_calls),
            'mode_to_switch': hex(0x5609ff5) + ' edi=r8d -> %s (jump table %s)' % (hex(MODE_SWITCH), hex(MODE_TABLE)),
            'switch_arms': {str(k): hex(v) for k, v in arms.items()},
            'modes_0_and_3': 'return at once with eax = mode (0x57cbfeb / 0x57cbfe6 -> 0x57cc0e3)',
            'mode_to_inner': hex(0x560a11b) + ' ecx=bpl -> %s -> %s at %s' % (hex(INNER), hex(SIDE_USER), hex(0x55a0504)),
            'result': 'inner returns 0x11 -> tag 0x1a2, else tag 0xf1 byte 0xc',
        },
        'side_select_0x55a07e0': {
            'reads': [hex(0x55a0e5c), hex(0x55a0f3c)],
            'rule': 'offset = (mode & 1) << 4: mode 3 -> +0x10 (second half), mode 0 -> +0x0 (first half)',
        },
        'predicate_0x369b360': {
            'lookup': 'blp +0x88 map, 20-byte key (memcmp 0x14), then the u64 argument in the value inner map',
            'test': 'true when word at entry +0x8 + ((ecx ^ 1) << 4) == 0 or no entry',
            'on_this_path': 'ecx = 0 -> tests the second half (+0x18)',
        },
        'move_0x5580d10': {
            'direct_calls': len(move_calls),
            'ctr': hex(0x5580d32) + ' Locus ctr +0xab0 += 1 (saturating) on entry',
            'early_exit': 'r8 == stack arg 0 and (r8 == 0 or r9 == stack arg 1) -> tag 0x1a2, value 0',
            'legs': {
                'first': hex(0x55812c0) + ' %s r8d=1, failure -> %s %r' % (hex(MOVE_LEG), hex(TO_SPOT[0]), TO_SPOT[1][1:].decode()),
                'second': hex(0x5581350) + ' %s r8d=0, failure -> %s %r' % (hex(MOVE_LEG), hex(FROM_SPOT[0]), FROM_SPOT[1][1:].decode()),
            },
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
    print('mode calls=%d move calls=%d' % (result['mode_call_0x5609fb0']['direct_calls'],
                                           result['move_0x5580d10']['direct_calls']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
