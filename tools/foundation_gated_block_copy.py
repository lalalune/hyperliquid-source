#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 gated 48-byte block copy packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window copies one of two 48-byte source blocks to the destination, selected
by three gates: a flag byte, a signed index-range check, and a gate byte. What
the blocks, the fields, and the callers mean is not claimed anywhere.
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
START, END = 0x4ff8b30, 0x4ff8b9c
PAD_END = 0x4ff8ba0
BODY = bytes.fromhex(
    'f30f1efa4889f84584c0743c8b521483ea0139ca7f3280bea0010000007429'
    'f30f6f9e88010000f30f6fa698010000f30f6faea80100000f111f0f116710'
    '0f116f20c30f1f440000f30f6f8658010000f30f6f8e68010000f30f6f9678'
    '0100000f11000f1148100f115020c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
CALLER_CIE = bytes.fromhex('1c00000000000000017a504c5200017810079b3d5848041b1b0c070890010000')
FDE = bytes.fromhex('1000000058f72800bc7e08046c00000000000000')
NEXT = bytes.fromhex('100000006cf72800187f08047500000000000000')
CALLER_FDES = [
    (0x626a5c, bytes.fromhex(
        '3800000090640000b4a3cf039c05000004cf6e8cff450e108602430d06428f'
        '03458e04488d058c0683070346032ea00102e70a0c0708440b02b32e00'),
     0x5002330, 0x50028cc),
    (0x626ac0, bytes.fromhex(
        '54000000f464000050aacf038c18000004cb6e8cff450e108602430d06508f'
        '038e048d058c06830702e02e2003db032e0002ab2e2002cd0a0c0708450b02'
        '4f2e0003b90a2ea00102a92e000382032ea00102b12e00000000'),
     0x5002a30, 0x50042bc),
    (0x628588, bytes.fromhex(
        '54000000bc7f0000d862d1031220000004b35f8cff450e108602530d06508f'
        '038e048d058c06830703bb022e200347010a0c0708460b025e2e0003e1072e'
        'a00102c22e000335022e20027c2e0003fa052e207f2e00000000'),
     0x501fd80, 0x5021d92),
    (0x628608, bytes.fromhex(
        '3c0000003c800000088dd103de0a00000457608cff410e108602430d06428f'
        '03498e048d058c064b830703c6072ea0010350010a0c0708480b02452e0000'
        '0000'),
     0x5022830, 0x502330e),
    (0x62866c, bytes.fromhex(
        '38000000a08000000498d10317100000044b608cff410e108602430d06488f'
        '038e048d058c064b8307033e0c2ea0010364010a0c0708470b702e0000'),
     0x5023390, 0x50243a7),
    (0x6286cc, bytes.fromhex(
        '4800000000810000d4a8d103b61a00000434608cff410e108602430d06508f'
        '038e048d058c06830703420c0a0c07084a0b02e12e20026f2e00028c2e10028'
        '12e0003bb062ea00103e0012e00'),
     0x50244c0, 0x5025f76),
    (0x62873c, bytes.fromhex(
        '5400000070810000c4c4d103ee2700000459608cff410e108602430d06428f'
        '03518e048d058c0683070349070a0c0708410b03b2062e2003da032e00037e'
        '012e20672e00033a022e2002862e000381092ea00103f7012e00'),
     0x5026120, 0x502890e),
]
CALLERS = [0x50023f8, 0x5003a54, 0x5003e5b, 0x50207c7,
           0x5022eeb, 0x5023e9f, 0x50258f1, 0x5027fae]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def select_block(flag, field, bound, gate):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. Returns 'A' for the +0x188 block and
    'B' for the +0x158 block. The index arithmetic is signed 32-bit with
    wraparound, matching sub/cmov-free jg semantics on the retained bytes.
    """
    if flag == 0:
        return 'B'
    edx = (field - 1) & 0xffffffff
    if edx >= 0x80000000:
        edx -= 0x100000000
    if edx > bound:
        return 'B'
    if gate == 0:
        return 'B'
    return 'A'


def analyze(data):
    """Structural checks, separate from identity so corruption controls reach them."""
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
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
    require(body == BODY, 'Gated block copy window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    require(read(eh['address'] + 0x6205d0, len(CALLER_CIE)) == CALLER_CIE,
            'Caller CIE changed')

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    check_fde(0x28f754, FDE, START, END)
    check_fde(0x28f768, NEXT, PAD_END, 0x4ff8c15)
    for offset, raw, start, end in CALLER_FDES:
        check_fde(offset, raw, start, end)
    # Padding: four int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 4, 'FDE padding changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x4ff8b30.
    fixed = [
        (0x00, 'f30f1efa', 'Entry landing pad changed'),
        (0x04, '4889f8', 'Destination copy changed'),
        (0x07, '4584c0', 'Flag test changed'),
        (0x0a, '743c', 'Flag branch changed'),
        (0x0c, '8b5214', 'Index field load changed'),
        (0x0f, '83ea01', 'Index decrement changed'),
        (0x12, '39ca', 'Range compare changed'),
        (0x14, '7f32', 'Range branch changed'),
        (0x16, '80bea001000000', 'Gate byte compare changed'),
        (0x1d, '7429', 'Gate branch changed'),
        (0x1f, 'f30f6f9e88010000', 'Path A first block load changed'),
        (0x27, 'f30f6fa698010000', 'Path A second block load changed'),
        (0x2f, 'f30f6faea8010000', 'Path A third block load changed'),
        (0x37, '0f111f', 'Path A first block store changed'),
        (0x3a, '0f116710', 'Path A second block store changed'),
        (0x3e, '0f116f20', 'Path A third block store changed'),
        (0x42, 'c3', 'Path A return changed'),
        (0x43, '0f1f440000', 'Intra-body alignment padding changed'),
        (0x48, 'f30f6f8658010000', 'Path B first block load changed'),
        (0x50, 'f30f6f8e68010000', 'Path B second block load changed'),
        (0x58, 'f30f6f9678010000', 'Path B third block load changed'),
        (0x60, '0f1100', 'Path B first block store changed'),
        (0x63, '0f114810', 'Path B second block store changed'),
        (0x67, '0f115020', 'Path B third block store changed'),
        (0x6b, 'c3', 'Path B return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # Branch targets: all three conditional branches land on path B.
    for off, disp, target in [(0x0a, 0x3c, 0x4ff8b78),
                              (0x14, 0x32, 0x4ff8b78),
                              (0x1d, 0x29, 0x4ff8b78)]:
        require(body[off + 1] == disp, 'Branch displacement changed')
        require(START + off + 2 + disp == target, 'Branch target changed')
    # No call opcode at any instruction start inside the window.
    starts = {off for off, _, _ in fixed}
    for pos, byte in enumerate(body):
        if pos in starts:
            require(byte != 0xe8, 'Unexpected call opcode in window')
    # Relocations: no record in any .rela.* section names this window.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((sec['name'], address))
    require(naming == [], 'Unexpected relocation naming window')
    # Incoming calls: direct e8 call sites anywhere in .text, each with
    # call bytes (e8 + rel32) landing exactly on the window start.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == CALLERS, 'Unexpected incoming direct calls')
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    require(select_block(0, 5, 4, 1) == 'B', 'Flag-zero edge changed')
    require(select_block(1, 5, 3, 1) == 'B', 'Index-over edge changed')
    require(select_block(1, 5, 4, 0) == 'B', 'Gate-zero edge changed')
    require(select_block(1, 5, 4, 1) == 'A', 'All-gates-pass edge changed')
    require(select_block(1, 0, -1, 1) == 'A', 'Zero-field boundary changed')
    require(select_block(1, 5, 4, 0xff) == 'A', 'Gate nonzero edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'relocation_slots': [[name, hex(addr)] for name, addr in naming],
        'direct_callers': direct,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 '
                    'gated block copy evidence packet.')
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
        require(retained['function']['padding_bytes'] == 4, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation gated-block-copy evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
