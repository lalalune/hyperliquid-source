#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 container-pop-helper packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window is a container pop helper: given a struct pointer in rdi, it compares
the qwords at +0x8 and +0x10. On equality it pops one element off the stack at
[rdi+0x20] (reading the qword just below the top, moving the top down by 8,
decrementing the counter at +0x28 by 0x10, and storing a 0x200-tagged pair);
otherwise it steps the +0x8 pointer back by 0x20 and decrements the same
counter by 0x10. What the struct fields mean, and what the caller does with
the result, is not claimed anywhere.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x5178be0, 0x5178c37
PAD_END = 0x5178c40
MASK = (1 << 64) - 1
BODY = bytes.fromhex(
    'f30f1efa488b4708483b471074124883e82048836f281048894708c30f1f4000'
    '488b4720488d50f848895720488b50f848836f2810488d820002000066480f6e'
    'c266480f6ec84883e820660f6cc1488947080f114710c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
CIE2 = bytes.fromhex('1c00000000000000017a504c5200017810079b3d5848041b1b0c070890010000')
FDE = bytes.fromhex('10000000c4c8290000ae1f045700000000000000')
NEXT = bytes.fromhex(
    '54000000d8c829004cae1f040302000000460e108d02420e188c03410e20860441'
    '0e288305440e500325010a0e28440e20410e18420e10420e08440b5c0e584d0e604'
    '20e68420e704d0e50026a0e584d0e60470e58410e50')
CALLERS = [
    (0x508f300, 0x508f7ed, 0x62c7dc,
     '3c00000010c200000416d803ed040000044d498cff460e108d02420e188c03410'
     'e208604410e288305470e700345020a0e28440e20410e18420e10420e08490b',
     (0x508f33e, 'e89d980e00', '488dbf28020000'),
    ),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pop_rule(a, b, top, val):
    """Decoded pop-helper rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. All arithmetic wraps at 64 bits.
    Returns (new_q8, new_q10, new_q18, new_q20, counter_delta) where
    new_q10/new_q20 are None on the else path (field untouched).
    """
    a &= MASK
    b &= MASK
    top &= MASK
    val &= MASK
    if a == b:
        return ((val + 0x200 - 0x20) & MASK, val, (val + 0x200) & MASK,
                (top - 8) & MASK, -0x10)
    return ((a - 0x20) & MASK, None, None, None, -0x10)


def analyze(data):
    """Structural checks, separate from identity so corruption controls reach them."""
    secs = sections(data)
    by_name = {s['name']: s for s in secs}

    def read(va, size):
        matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
                   and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'Ambiguous or unmapped VA')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return data[off:off + size]

    body = read(START, END - START)
    require(body == BODY, 'Container-pop-helper instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    require(read(eh['address'] + 0x6205d0, len(CIE2)) == CIE2,
            'CIE at offset 0x6205d0 changed')
    for offset, raw, start, end in [
            (0x29c8c0, FDE, START, END),
            (0x29c8d4, NEXT, PAD_END, 0x5178e43)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: nine int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 9, 'Padding changed')
    require(PAD_END == 0x5178c40, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x5178be0. Every instruction
    # start is locked, so no call opcode can hide at an instruction start
    # (the 0xe8 byte inside `sub $0x20,%rax` is an operand byte, not an
    # opcode, and is locked as part of its instruction).
    fixed = [
        (0, 'f30f1efa', 'Endbr64 changed'),
        (4, '488b4708', 'First-pointer load changed'),
        (8, '483b4710', 'Pointer compare changed'),
        (12, '7412', 'Equality branch changed'),
        (14, '4883e820', 'Else-path step-back changed'),
        (18, '48836f2810', 'Else-path counter decrement changed'),
        (23, '48894708', 'Else-path pointer store changed'),
        (27, 'c3', 'Else-path return changed'),
        (28, '0f1f4000', 'Alignment padding changed'),
        (32, '488b4720', 'Stack-top load changed'),
        (36, '488d50f8', 'Popped-slot address changed'),
        (40, '48895720', 'Stack-top store changed'),
        (44, '488b50f8', 'Popped-value load changed'),
        (48, '48836f2810', 'Pop-path counter decrement changed'),
        (53, '488d8200020000', 'Tag-add changed'),
        (60, '66480f6ec2', 'Value-to-xmm0 changed'),
        (65, '66480f6ec8', 'Tagged-to-xmm1 changed'),
        (70, '4883e820', 'Tag-adjust changed'),
        (74, '660f6cc1', 'Pair-pack changed'),
        (78, '48894708', 'Pop-path pointer store changed'),
        (82, '0f114710', 'Pair store changed'),
        (86, 'c3', 'Pop-path return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # Branch target lands exactly on a retained instruction start.
    require(0x5178bec + 2 + 0x12 == 0x5178c00, 'Equality target changed')
    # Relocations: no record of any type in any .rela.* section names this window.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((sec['name'], address))
    require(naming == [], 'Relocation naming window changed')
    # Incoming calls: direct e8 call sites anywhere in .text.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    expected_sites = [s[0] for c in CALLERS for s in c[4:]]
    require(direct == expected_sites, 'Incoming direct calls changed')
    # Each caller sits inside its caller FDE range, with the retained FDE
    # record, call bytes, and call-path argument setup intact.
    for fde_start, fde_end, fde_off, fde_raw, *sites in CALLERS:
        record = read(eh['address'] + fde_off, len(bytes.fromhex(fde_raw)))
        require(record == bytes.fromhex(fde_raw), 'Caller FDE record changed')
        pc = eh['address'] + fde_off + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (fde_start, fde_end),
                'Caller FDE PC/range changed')
        for site, call_hex, setup_hex in sites:
            require(fde_start <= site < fde_end, 'Caller outside its FDE range')
            require(read(site, 5) == bytes.fromhex(call_hex), 'Caller call bytes changed')
            setup_len = len(bytes.fromhex(setup_hex))
            require(read(site - setup_len, setup_len) == bytes.fromhex(setup_hex),
                    'Caller setup changed')
            require(site + 5 + struct.unpack_from('<i', read(site, 5), 1)[0] == START,
                    'Caller call target changed')
    # Decoded-rule edges (restatement of the retained bytes, not execution).
    require(pop_rule(100, 100, 1000, 7) == (0x1e7, 7, 0x207, 992, -0x10),
            'Pop-path edge changed')
    require(pop_rule(100, 50, 1000, 7) == (68, None, None, None, -0x10),
            'Else-path edge changed')
    require(pop_rule(100, 100, 1000, 0) == (0x1e0, 0, 0x200, 992, -0x10),
            'Pop-zero-value edge changed')
    require(pop_rule(0x20, 0, 1000, 7) == (0, None, None, None, -0x10),
            'Else-path zero edge changed')
    require(pop_rule(100, 100, 1000, MASK) == (0x1df, MASK, 0x1ff, 992, -0x10),
            'Pop-wraparound edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'relocation_slots': [],
        'direct_callers': direct,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 '
                    'container-pop-helper evidence packet.')
    parser.add_argument('--binary', default=str(TARGET))
    parser.add_argument('--check', help='Compare with retained JSON; fail on drift')
    args = parser.parse_args()
    result = inspect(args.binary)
    if args.check:
        retained = json.loads(Path(args.check).read_text())
        require(retained['target_sha256'] == SHA256, 'Retained digest changed')
        require(retained['function']['start_va'] == hex(START), 'Retained start changed')
        require(retained['function']['end_va_exclusive'] == hex(END), 'Retained end changed')
        require(retained['function']['bytes'] == END - START, 'Retained size changed')
        require(retained['function']['sha256'] == result['body_sha256'],
                'Retained body hash changed')
        require(retained['function']['padding_bytes'] == 9, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation container-pop-helper evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
