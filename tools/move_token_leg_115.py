#!/usr/bin/env python3
"""Bind the node #115 move_token leg 0x54df920 and the 0x55817e0 early exit (stage 100).

Continues #6210 (stage 98) and #6212 (stage 99). Stage 99 found that
0x5580d10 calls 0x54df920 with r8d = 1 (failure formats 'move_token
to_spot: ') and then with r8d = 0 (failure formats 'move_token from_spot: '),
unless its r8 equals the first stack argument and r8 is 0 or r9 equals the
second. This tool binds:

1. the 0x54df920 arguments: rsi = box, rdx = clearinghouse index (checked
   against Locus cls length box +0x7d0; out of range -> the
   clearinghouses.rs:11:29 unwrap panic, error tag 0x156), rcx = a 20-byte key,
   r8 = leg (0, 1 or 2), r9 = amount (signed; negative -> the
   qtys/mod.rs:847:1 Result::unwrap panic);
2. the element is box +0x7c8 + index * 0x510; the leg reads its +0x58 word
   and looks the key up in Locus vlt (box +0xa18), testing the entry byte
   +0xb7;
3. amount * 100 overflow -> tag 0x106; amount <= 0 -> tag 0x1a2 with no move;
4. leg 1: a balance read (slot 0x64e5078 -> 0x446bdd0) below the amount ->
   tag 0x34; otherwise slot 0x64e7170 (0x447db40) and element +0x4a8 -=
   amount (signed overflow saturates and is recorded with the
   impl_ntl.rs:70:1 Location through the registry slot 0x64e4ea8);
5. leg 0: a check through slot 0x64e5af8 (0x3bf4b00) on Locus scl (box +0x80)
   must pass, then 0x3bfa910 (ecx = 1) and 0x4472ea0, and element +0x4a8 +=
   amount (signed, same overflow handling);
6. leg 2 takes its amount from slot 0x64e7160 (0x4479470) and debits like
   leg 1 without the balance check;
7. on the 0x5582180 -> 0x55817e0 -> 0x5580d10 path, 0x5582180 passes
   ecx = 0, 0x55817e0 keeps rcx in r12 and passes it as stack argument 0
   with r8d = 0, so 0x5580d10 returns tag 0x1a2 before either leg runs.

Labels such as debit, credit, balance and vault are inferences. The captured
binary is not executed. objdump and readelf are not started. Addresses are
ELF virtual addresses.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import (RELATIVE, TARGET, direct_calls, fixed, frame, read_va,
                                 relative_relocations, rip_target)

PACKET = ROOT / 'research/work-items/RE-008-move-token-leg-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

LEG = 0x54df920
MOVE = 0x5580d10
CALLER = 0x55817e0
OUTER = 0x5582180
SLOTS = {0x64e5078: 0x446bdd0, 0x64e7170: 0x447db40, 0x64e5af8: 0x3bf4b00,
         0x64e7160: 0x4479470, 0x64e64a0: 0x3bf4fa0, 0x64e4ea8: 0x4524e40}
LOCATIONS = {0x648b990: ('l1/src/dex_registry/clearinghouses.rs', 11, 29),
             0x648ba50: ('l1/src/qtys/impl_ntl.rs', 70, 1),
             0x64a9900: ('l1/src/qtys/mod.rs', 847, 1)}

FIXED = {
    0x54df94b: '483b96d0070000',        # cmp rdx, [rsi+0x7d0]       (cls length)
    0x54df972: '4c69f210050000',        # imul r14, rdx, 0x510
    0x54df979: '66c74424505601',        # error tag 0x156
    0x54df994: '4b8b443458',            # mov rax, [r12+r14+0x58]
    0x54df9b2: '498b9d180a0000',        # mov rbx, [r13+0xa18]       (Locus vlt)
    0x54dfb35: '4180bfb700000000',      # cmp byte [r15+0xb7], 0
    0x54dfb52: '4983ff02',              # cmp r15, 2                 (leg 2)
    0x54dfb74: 'ba02000000',            # mov edx, 2
    0x54dfba4: '4885c0',                # test rax, rax              (amount sign)
    0x54dfba7: '0f885c070000',          # js 0x54e0309               (unwrap panic)
    0x54dfbad: 'b964000000',            # mov ecx, 100
    0x54dfbb5: '48f7e1',                # mul rcx
    0x54dfbb8: '400f90c6',              # seto sil
    0x54dfbcd: '66bd0601',              # mov bp, 0x106              (overflow tag)
    0x54dfbe0: '4983ff01',              # cmp r15, 1                 (leg 1)
    0x54dfc05: '66bd3400',              # mov bp, 0x34               (short balance)
    0x54dfc09: '4839c8',                # cmp rax, rcx
    0x54dfc0c: '0f82c0000000',          # jb -> return
    0x54dfc14: '498dbd80000000',        # lea rdi, [r13+0x80]        (Locus scl)
    0x54dfc36: '66bda201',              # mov bp, 0x1a2
    0x54dfc3d: '490f4fc6',              # cmovg rax, r14
    0x54dfc41: '0f8e8b000000',          # jle -> return 0x1a2        (amount <= 0)
    0x54dfc85: 'f2410f598404e0040000',  # mulsd xmm0, [elem+0x4e0]
    0x54dfd28: '48b9ae47e17a14ae4701',  # movabs rcx, 0x147ae147ae147ae (i64::MAX / 100)
    0x54dfe69: '4983ff02',              # cmp r15, 2
    0x54dfe73: '4983ff01',              # cmp r15, 1
    0x54dfeb3: '4939c6',                # cmp r14, rax               (amount vs balance)
    0x54dfebb: '0f8e40020000',          # jle 0x54e0101              (leg 1 debit)
    0x54dfec1: '66c74424503400',        # tag 0x34
    0x54dff40: 'b901000000',            # mov ecx, 1
    0x54dff80: '498b86a8040000',        # mov rax, [r14+0x4a8]
    0x54dff8a: '4d01fe',                # add r14, r15               (leg 0 credit)
    0x54dff8d: '0f80ec020000',          # jo -> saturate
    0x54dff93: '4c89b1a8040000',        # mov [rcx+0x4a8], r14
    0x54e0088: '4c8bb2a8040000',        # mov r14, [rdx+0x4a8]
    0x54e0092: '4c29f8',                # sub rax, r15               (leg 2 debit)
    0x54e0095: '0f807a010000',          # jo -> saturate
    0x54e00a5: '488982a8040000',        # mov [rdx+0x4a8], rax
    0x54e011a: '498b97a8040000',        # mov rdx, [r15+0x4a8]
    0x54e0124: '4c29f0',                # sub rax, r14               (leg 1 debit)
    0x54e0127: '0f801e010000',          # jo -> saturate
    0x54e012d: '498987a8040000',        # mov [r15+0x4a8], rax
    0x54e00eb: '6641892e',              # mov [r14], bp              (result tag)
    0x54e0232: '4c0f40f0',              # cmovo r14, rax             (saturate)
    0x54e01a5: '48b94b598638d6c56d34',  # movabs rcx, 0x346dc5d63886594b (/10000)
    0x54e01b5: '48c1ea0b',              # shr rdx, 11
    0x54e01c0: '4801d0',                # add rax, rdx
    0x54e01ce: '49894618',              # mov [r14+0x18], rax
    # 0x5580d10 early exit
    0x5580d7e: '4c3bbc24b0010000',      # cmp r15, [rsp+0x1b0]       (stack arg 0)
    0x5580d88: '4d85ff',                # test r15, r15
    0x5580d91: '483bac24b8010000',      # cmp rbp, [rsp+0x1b8]       (stack arg 1)
    0x558136b: '49c7450800000000',      # [r13+8] = 0
    0x5581373: '6641c74500a201',        # [r13] = 0x1a2
    0x55812a9: '41b801000000',          # r8d = 1 before the first leg
    0x558134a: '4531c0',                # r8d = 0 before the second leg
    # 0x55817e0 -> 0x5580d10
    0x55817f4: '4989cc',                # mov r12, rcx
    0x5581bfe: '4c892424',              # mov [rsp], r12             (stack arg 0)
    0x5581bf9: '4c896c2408',            # mov [rsp+8], r13           (stack arg 1)
    0x5581c19: '4531c0',                # xor r8d, r8d
    # 0x5582180 -> 0x55817e0
    0x558310a: '31c9',                  # xor ecx, ecx
}
CALLS = ((0x55812c0, LEG), (0x5581350, LEG), (0x5581c1c, MOVE), (0x5583117, CALLER),
         (0x54dff4b, 0x3bfa910), (0x54dff78, 0x4472ea0), (0x54e00bf, 0x54e0ec0),
         (0x54e014a, 0x54e0ec0), (0x54dfecd, 0x5630000))
REFERENCES = (
    (0x54dfb79, b'\xff\x15', 6, 0x64e7160),
    (0x54dfbf1, b'\xff\x15', 6, 0x64e5078),
    (0x54dfc26, b'\xff\x15', 6, 0x64e64a0),
    (0x54dfead, b'\xff\x15', 6, 0x64e5078),
    (0x54dff0f, b'\xff\x15', 6, 0x64e5af8),
    (0x54e007d, b'\xff\x15', 6, 0x64e7170),
    (0x54e0114, b'\xff\x15', 6, 0x64e7170),
    (0x54e0238, b'\xff\x15', 6, 0x64e4ea8),
    (0x54e022b, b'\x48\x8d\x35', 7, 0x648ba50),
    (0x54e02f0, b'\x4c\x8d\x05', 7, 0x648b990),
    (0x54e0317, b'\x4c\x8d\x05', 7, 0x64a9900),
)


def call_target(data, va):
    raw = read_va(data, va, 5)
    if raw[0] != 0xe8:
        raise ValueError(f'call at {va:#x} changed')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def location(data, rel, va):
    length, line, col = struct.unpack('<QII', read_va(data, va + 8, 16))
    return read_va(data, rel[va], length).decode(), line, col


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, target in CALLS:
        if call_target(data, va) != target:
            raise ValueError(f'call at {va:#x} changed')
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in SLOTS.items():
        if rel.get(slot) != target:
            raise ValueError(f'slot {slot:#x} relocation changed')
    for va, expect in LOCATIONS.items():
        if location(data, rel, va) != expect:
            raise ValueError(f'Location {va:#x} changed')
    for fn, va in ((LEG, 0x54dfc36), (LEG, 0x54e012d), (MOVE, 0x5580d7e), (CALLER, 0x5581bfe),
                   (OUTER, 0x558310a)):
        if frame(fdes, va) != fn:
            raise ValueError(f'{va:#x} left {fn:#x}')
    if 0x346dc5d63886594b * 10000 >> 75 != 1:
        raise ValueError('divisor constant changed')
    leg_calls = direct_calls(data, LEG)

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'leg_0x54df920': {
            'direct_calls': len(leg_calls),
            'arguments': 'rsi box, rdx clearinghouse index, rcx 20-byte key, r8 leg (0/1/2), r9 signed amount',
            'index_check': hex(0x54df94b) + ' rdx < box +0x7d0 (Locus cls length), else %s:%d:%d unwrap panic, tag 0x156'
                           % LOCATIONS[0x648b990],
            'element': 'box +0x7c8 + index * 0x510; reads +0x58; key looked up in Locus vlt (box +0xa18), entry byte +0xb7',
            'negative_amount': hex(0x54dfba7) + ' js -> Result::unwrap panic at %s:%d:%d' % LOCATIONS[0x64a9900],
            'overflow_x100': hex(0x54dfbcd) + ' amount * 100 overflows -> tag 0x106',
            'non_positive': hex(0x54dfc41) + ' amount <= 0 -> tag 0x1a2, no move',
            'leg_1': 'balance slot 0x64e5078 -> 0x446bdd0 below amount -> tag 0x34; else slot 0x64e7170 -> 0x447db40, '
                     'element +0x4a8 -= amount (%s)' % hex(0x54e0124),
            'leg_0': 'slot 0x64e5af8 -> 0x3bf4b00 on Locus scl (box +0x80) must pass, then 0x3bfa910 (ecx 1), '
                     '0x4472ea0, element +0x4a8 += amount (%s)' % hex(0x54dff8a),
            'leg_2': 'amount from slot 0x64e7160 -> 0x4479470 (edx 2), then debit as leg 1 without the balance check',
            'overflow': 'signed overflow on +0x4a8 saturates (%s cmovo) and is recorded at %s:%d:%d via slot 0x64e4ea8'
                        % ((hex(0x54e0232),) + LOCATIONS[0x648ba50]),
        },
        'move_0x5580d10_legs': {
            'first': hex(0x55812c0) + ' r8d = 1 (failure: move_token to_spot)',
            'second': hex(0x5581350) + ' r8d = 0 (failure: move_token from_spot)',
            'early_exit': 'r8 == [rsp+0x1b0] (stack arg 0) and (r8 == 0 or r9 == [rsp+0x1b8]) -> [out] = 0x1a2, 0',
        },
        'path_0x5582180': {
            'outer': hex(0x558310a) + ' ecx = 0 before call ' + hex(0x5583117),
            'caller': hex(0x55817f4) + ' r12 = rcx; ' + hex(0x5581bfe) + ' stack arg 0 = r12; '
                      + hex(0x5581c19) + ' r8d = 0; call ' + hex(0x5581c1c),
            'result': 'r8 == arg 0 == 0 -> 0x5580d10 returns tag 0x1a2 before either leg; no token moves on this path',
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
    print('leg calls=%d' % result['leg_0x54df920']['direct_calls'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
