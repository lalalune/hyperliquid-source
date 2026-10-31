#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 two-hop field load packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window is a two-hop field load with a -1 default: given a struct pointer
in rdi, it loads a pointer from [rdi+8]; if that pointer's own first qword
equals the pointer itself, it returns -1; otherwise it chains two more loads
([p+8], then [q+0x10]) and returns the qword at [r+0xcb8]. What the struct
fields mean, and what the caller does with the result, is not claimed
anywhere. The window reads as pair-load class (cf. packet #40), but its shape
is distinct: #40 loads two fields from the same base with no chaining and no
gate, while this window chains three dereferences and gates on a self-compare.
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
START, END = 0x5172e50, 0x5172e77
PAD_END = 0x5172e80
MASK = (1 << 64) - 1
BODY = bytes.fromhex(
    'f30f1efa488b470848c7c2ffffffff483b00740f488b4008488b4010488b90b80c'
    '00004889d0c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
CIE2 = bytes.fromhex('1c00000000000000017a504c5200017810079b3d5848041b1b0c070890010000')
FDE = bytes.fromhex('1000000010c5290024541f042700000000000000')
NEXT = bytes.fromhex(
    '4800000024c5290040541f041101000000460e108d02420e188c03410e20860441'
    '0e288305440e3002e80a0e28440e20410e18420e10420e08410b440e28440e20440'
    'e18420e10420e080000')
CALLERS = [
    (0x5152280, 0x51524a9, 0x6344bc,
     '44000000f03e0100a4c8e30329020000043b268cff460e108e02420e188d03420e'
     '208c04410e288605410e308306440e8001024d0a0e30440e28410e20420e18420e'
     '10420e08480b',
     (0x51523bc, 'e88f0a0200', '488ba8b80c0000'),
    ),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(mem, rdi):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. mem maps addresses to qwords; rdi is
    the struct pointer. Returns the value in rax at ret.
    """
    p = mem[rdi + 8] & MASK
    if p == (mem[p] & MASK):
        return MASK
    q = mem[p + 8] & MASK
    r = mem[q + 0x10] & MASK
    return mem[r + 0xcb8] & MASK


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
    require(body == BODY, 'Two-hop-field-load instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    require(read(eh['address'] + 0x6205d0, len(CIE2)) == CIE2,
            'CIE at offset 0x6205d0 changed')
    for offset, raw, start, end in [
            (0x29c50c, FDE, START, END),
            (0x29c520, NEXT, PAD_END, 0x5172f91)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: nine int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 9, 'Padding changed')
    require(PAD_END == 0x5172e80, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x5172e50.
    fixed = [
        (0, 'f30f1efa', 'Endbr64 changed'),
        (4, '488b4708', 'Pointer load changed'),
        (8, '48c7c2ffffffff', 'Default -1 changed'),
        (15, '483b00', 'Self-compare changed'),
        (18, '740f', 'Self-compare branch changed'),
        (20, '488b4008', 'First hop load changed'),
        (24, '488b4010', 'Second hop load changed'),
        (28, '488b90b80c0000', 'Deep field load changed'),
        (35, '4889d0', 'Result move changed'),
        (38, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # Branch target lands exactly on a retained instruction start.
    require(0x5172e62 + 2 + 0x0f == 0x5172e73, 'Self-compare target changed')
    # No call opcode inside the window: the locked body contains no e8 byte.
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
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
    # Caller-path argument setup one instruction further back: the caller
    # adds 0x8f0 to rdi before the final field load and call.
    require(read(0x51523ae, 7) == bytes.fromhex('4881c7f0080000'),
            'Caller base adjustment changed')
    # Decoded-rule edges (restatement of the retained bytes, not execution).
    # Struct at 0x1000 whose [rdi+8] points to itself: the self-compare fires.
    require(load({0x1008: 0x1000, 0x1000: 0x1000}, 0x1000) == MASK,
            'Self-compare edge changed')
    # Full chain: [rdi+8]=0x3000, [0x3000]=0x9999 (not self), [0x3008]=0x4000,
    # [0x4010]=0x5000, [0x5000+0xcb8]=42.
    mem = {0x2008: 0x3000, 0x3000: 0x9999, 0x3008: 0x4000, 0x4010: 0x5000,
           0x5000 + 0xcb8: 42}
    require(load(mem, 0x2000) == 42, 'Chain edge changed')
    # Chain reaching a zero deep field.
    mem0 = {0x2008: 0x3000, 0x3000: 0x0001, 0x3008: 0x4000, 0x4010: 0x5000,
            0x5000 + 0xcb8: 0}
    require(load(mem0, 0x2000) == 0, 'Zero deep-field edge changed')
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
                    'two-hop-field-load evidence packet.')
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
        print('Foundation two-hop-field-load evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
