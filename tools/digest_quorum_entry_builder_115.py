#!/usr/bin/env python3
"""Bind the node #115 digest quorum entry builder 0x53779c0 (62nd stage).

Continues the digest quorum store packets (#6046, #6048). The extract loop
0x51515f0 calls 0x53779c0(out, store, height) once per removed height. This
tool binds:

1. the outer lookup: store +0x18 holds a second height-keyed map (B-tree when
   the first word is the 0x8000000000000000 niche, else a ring with buffer
   +0x20, head +0x28, length +0x30, capacity +0x18 and 0x50-byte elements);
   each value has an inner map at +0x0, a byte at +0x20 (non-zero gives None)
   and a 32-byte key at +0x21;
2. the inner lookup: that 32-byte key is looked up (memcmp length 0x20 through
   slot 0x64dfb50) in the inner map (B-tree keys at +0x2c0, length u16 +0x42a,
   children +0x430; ring elements 0x60 bytes with the value at +0x20); the
   value is two 0x20-byte collections;
3. the output: clone of collection one at +0x0, clone of collection two at
   +0x20, the 32-byte key at +0x40..+0x60; None is 0x8000000000000001; the
   extract loop skips a None result (0x5151ac4);
4. the store delay (store +0x88 = box +0x3e20 in layout A, +0x4990 in B):
   written at 0x539025b, 0x539b07b and 0x28d0cde from the f64 at +0x8 of the
   result of slot 0x64e6ae8 (0x421e630) when its tag is 0x1a2;
5. the insert's prune call 0x5376540(out, store, max(0, height - 50000), ...)
   at 0x5afa72f, and its second caller 0x5afacce.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import (RELATIVE, SHA256, TARGET, direct_calls, fixed, frame,
                                 read_va, relative_relocations)

PACKET = ROOT / 'research/work-items/RE-008-digest-quorum-entry-builder-115'

BUILDER = 0x53779c0
EXTRACT = 0x51515f0
INSERT = 0x5afa5d0
PRUNE = 0x5376540
DELAY_SLOT, DELAY_FN = 0x64e6ae8, 0x421e630

FIXED = {
    # outer map: niche test on store +0x18
    0x53779e9: '488b5e18',                    # mov rbx, [rsi+0x18]
    0x53779f0: '48f7d8',                      # neg rax
    0x53779f3: '0f817e000000',                # jno -> ring path
    0x5377a0a: '410fb7b77a030000',            # movzx esi, word [r15+0x37a] (node length)
    0x5377a38: '493b54cf10',                  # cmp rdx, [r15+rcx*8+0x10] (u64 height keys)
    0x5377a6d: '4d8bbccf80030000',            # mov r15, [r15+rcx*8+0x380] (child)
    # ring path: 0x50-byte elements, value at +0x8, flag byte at value +0x20
    0x5377aae: '488d0c92',                    # lea rcx, [rdx+rdx*4]
    0x5377ab2: '48c1e104',                    # shl rcx, 4
    0x5377aba: '4983c708',                    # add r15, 8
    0x5377abe: '41807f2000',                  # cmp byte [r15+0x20], 0
    0x5377ac3: '0f85e6000000',                # jne -> None
    # inner map: 32-byte keys
    0x5377afa: '488db0c0020000',              # lea rsi, [rax+0x2c0]
    0x5377b01: '440fb7a02a040000',            # movzx r12d, word [rax+0x42a]
    0x5377b39: 'ba20000000',                  # mov edx, 0x20 (memcmp length)
    0x5377b90: '488b84e830040000',            # mov rax, [rax+rbp*8+0x430] (child)
    0x5377bf4: '488d0c52',                    # lea rcx, [rdx+rdx*2]
    0x5377bf8: '48c1e105',                    # shl rcx, 5 (0x60-byte ring elements)
    0x5377c00: '4983c720',                    # add r15, 0x20 (value at +0x20)
    # None result
    0x5377c3b: '48b80000000000000080',        # movabs rax, 0x8000000000000000
    0x5377c45: '48ffc0',                      # inc rax
    # output: key at +0x40..+0x60, second collection at +0x20
    0x5377d6d: '410f1006',                    # movups xmm0, [r14]
    0x5377d71: '410f104e10',                  # movups xmm1, [r14+0x10]
    0x5377d76: '410f114c2450',                # movups [r12+0x50], xmm1
    0x5377d7c: '410f11442440',                # movups [r12+0x40], xmm0
    0x5377d82: '49895c2420',                  # mov [r12+0x20], rbx
    # extract loop: call and None test
    0x5151ab1: '488d7c2418',                  # lea rdi, [rsp+0x18]
    0x5151ab6: '488b542410',                  # mov rdx, [rsp+0x10]
    0x5151ac0: '498d4701',                    # lea rax, [r15+1]
    0x5151ac4: '4839442418',                  # cmp [rsp+0x18], rax
    # store cap and prune bound
    0x5afa20e: '482de8030000',                # sub rax, 1000
    0x5afa701: '4981ed50c30000',              # sub r13, 50000
    # delay writers
    0x5390252: 'f30f7e842438010000',          # movq xmm0, [rsp+0x138]
    0x539025b: '66410fd685203e0000',          # movq [r13+0x3e20], xmm0
    0x539b072: 'f30f7e842438010000',
    0x539b07b: '66410fd68590490000',          # movq [r13+0x4990], xmm0
    0x28d0cd5: 'f30f7e842438010000',
    0x28d0cde: '66410fd68424203e0000',        # movq [r12+0x3e20], xmm0
}
SLOT_CALLS = (  # (site, slot): call [rip+disp32]
    (0x5390239, DELAY_SLOT),
    (0x539b059, DELAY_SLOT),
    (0x28d0cbc, DELAY_SLOT),
)
OK_TAG_CHECKS = (0x5390247, 0x539b067, 0x28d0cca)   # cmp eax, 0x1a2


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for site, slot in SLOT_CALLS:
        raw = read_va(data, site, 6)
        if raw[:2] != b'\xff\x15' or site + 6 + struct.unpack_from('<i', raw, 2)[0] != slot:
            raise ValueError(f'slot call at {site:#x} changed')
    for va in OK_TAG_CHECKS:
        fixed(data, va, '3da2010000')
    if relative_relocations(data).get(DELAY_SLOT) != DELAY_FN:
        raise ValueError('delay slot relocation changed')

    builder_calls = direct_calls(data, BUILDER)
    prune_calls = direct_calls(data, PRUNE)
    if builder_calls != [0x5151abb, 0x57d4078] or frame(fdes, 0x5151abb) != EXTRACT:
        raise ValueError('builder call census changed')
    if prune_calls != [0x5afa72f, 0x5afacce] or frame(fdes, 0x5afa72f) != INSERT:
        raise ValueError('prune call census changed')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'builder': {
            'fn': hex(BUILDER),
            'calls': [hex(v) for v in builder_calls],
            'args': 'rdi out (0x60 bytes), rsi store, rdx height',
            'outer_map': 'store +0x18: B-tree (u64 keys at node +0x10, length u16 +0x37a, children +0x380) '
                         'or ring (+0x20 buffer, +0x28 head, +0x30 length, 0x50-byte elements, value at +0x8)',
            'outer_value': '+0x0 inner map, +0x20 byte (non-zero -> None), +0x21 32-byte key',
            'inner_map': 'B-tree (32-byte keys at +0x2c0, memcmp 0x20 via slot 0x64dfb50, length u16 +0x42a, '
                         'children +0x430) or ring (0x60-byte elements, value at +0x20)',
            'output': '+0x0 clone of collection one, +0x20 clone of collection two, +0x40..+0x60 the key',
            'none': '0x8000000000000001 (height missing, byte set, or key missing); extract loop skips it at '
                    + hex(0x5151ac4),
        },
        'quorum_entry': 'height (+0x0) followed by the 0x60-byte builder output: +0x48..+0x68 is the 32-byte key '
                        'stored with that height in store +0x18',
        'store_delay': {
            'field': 'store +0x88 (box +0x3e20 layout A, +0x4990 layout B)',
            'writers': [hex(0x539025b), hex(0x539b07b), hex(0x28d0cde)],
            'source': 'f64 at result +0x8 of slot %s -> %s when the result tag is 0x1a2'
                      % (hex(DELAY_SLOT), hex(DELAY_FN)),
        },
        'prune': {
            'fn': hex(PRUNE),
            'calls': [hex(v) for v in prune_calls],
            'insert_args': 'rsi store, rdx max(0, height - 50000) (sub r13, 0xc350 at 0x5afa701)',
        },
        'store_cap': 'max(0, store +0x78 - 1000) (sub rax, 0x3e8 at 0x5afa20e)',
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
    print('builder calls=%d prune calls=%d' % (len(result['builder']['calls']), len(result['prune']['calls'])))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
