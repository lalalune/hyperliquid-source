#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 conditional-sum init packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window stores zero into two struct fields, the sign-extended input into a
third, and a conditional sum into a fourth, returning 1. What the struct, the
fields, and the callers mean is not claimed anywhere.
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
START, END = 0x5475e80, 0x5475ead
PAD_END = 0x5475eb0
BODY = bytes.fromhex(
    'f30f1efa4863c248c70700000000488947184801f085d2480f45f048c7471000000000'
    'b80100000048897708c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
CIE2 = bytes.fromhex('1c00000000000000017a504c5200017810079b3d5848041b1b0c070890010000')
FDE = bytes.fromhex('1000000050e72b0014624d042d00000000000000')
NEXT = bytes.fromhex(
    '4800000064e72b0030624d04f111000000460e108f02420e188e03420e208d04450e288c05490e308606440e388307440ea001026c0a0e38410e30410e28420e20420e18420e10420e084a0b')
CALLER_FDES = [
    (0x62735c, bytes.fromhex(
        '38000000906d0000447fd0032511000004946a8cff450e108602430d06468f038e048d05458c06448307030d010a0c0708440b03f0062e107a2e0000'),
     0x50107c0, 0x50118e5),
    (0x657ddc, bytes.fromhex(
        '3800000010780300e4260904111000000479278bff450e108602430d06468f038e048d05458c06448307039f012e1003d5012e0002490a0c0708440b'),
     0x53cb9e0, 0x53cc9f1),
]
CALLERS = [0x5010b7f, 0x53cc23c]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sext32(value):
    """Sign-extend a raw 32-bit input, matching the retained movslq."""
    value &= 0xffffffff
    return value - 0x100000000 if value & 0x80000000 else value


def compute_init(edx_raw, rsi):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. `edx_raw` is the raw 32-bit input;
    `rsi` is the 64-bit addend. All arithmetic wraps at 64 bits, matching
    the retained add/cmovne semantics. Returns
    (field0, field8, field16, field24, eax).
    """
    mask = 0xffffffffffffffff
    extended = sext32(edx_raw) & mask
    field8 = (extended + rsi) & mask if edx_raw & 0xffffffff else rsi & mask
    return 0, field8, 0, extended, 1


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
    require(body == BODY, 'Conditional-sum init window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    require(read(eh['address'] + 0x6205d0, len(CIE2)) == CIE2,
            'CIE at offset 0x6205d0 changed')

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    check_fde(0x2be74c, FDE, START, END)
    check_fde(0x2be760, NEXT, PAD_END, 0x54770a1)
    for offset, raw, start, end in CALLER_FDES:
        check_fde(offset, raw, start, end)
    # Padding: three int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 3, 'FDE padding changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x5475e80.
    fixed = [
        (0x00, 'f30f1efa', 'Entry landing pad changed'),
        (0x04, '4863c2', 'Input sign extension changed'),
        (0x07, '48c70700000000', 'Field zero store changed'),
        (0x0e, '48894718', 'Extended input store changed'),
        (0x12, '4801f0', 'Addend add changed'),
        (0x15, '85d2', 'Zero input test changed'),
        (0x17, '480f45f0', 'Conditional move changed'),
        (0x1b, '48c7471000000000', 'Second field zero store changed'),
        (0x23, 'b801000000', 'Return constant changed'),
        (0x28, '48897708', 'Conditional sum store changed'),
        (0x2c, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
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
    require(compute_init(0, 0x1000) == (0, 0x1000, 0, 0, 1),
            'Zero input edge changed')
    require(compute_init(5, 0x1000) == (0, 0x1005, 0, 5, 1),
            'Positive input edge changed')
    require(compute_init(0xffffffff, 0x1000) == (0, 0xfff, 0, 0xffffffffffffffff, 1),
            'Negative input edge changed')
    require(compute_init(0x80000000, 0x1000)
            == (0, 0xffffffff80001000, 0, 0xffffffff80000000, 1),
            'Sign extension boundary edge changed')
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
                    'conditional-sum init evidence packet.')
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
        require(retained['function']['padding_bytes'] == 3, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation conditional-sum-init evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
