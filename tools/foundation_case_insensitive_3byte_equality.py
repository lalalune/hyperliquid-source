#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 case-insensitive 3-byte equality packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window returns 1 iff the length argument is exactly 3 and all three byte
pairs match after ASCII A-Z folding, else 0. What the strings hold, and what
the caller does with the result, is not claimed anywhere.
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
START, END = 0x151a4a0, 0x151a52f
PAD_END = 0x151a530
BODY = bytes.fromhex(
    '4883fe03' '0f8582000000'
    '0fb607' '8d48bf' '80f91a' '0f92c1' 'c0e105' '08c1'
    '0fb602' '8d70bf' '4080fe1a' '400f92c6' '40c0e605' '4008c6'
    '4038f1' '7557'
    '0fb64701' '8d48bf' '80f91a' '0f92c1' 'c0e105' '08c1'
    '0fb64201' '8d70bf' '4080fe1a' '400f92c6' '40c0e605' '4008c6'
    '4038f1' '752a'
    '0fb64702' '8d48bf' '80f91a' '0f92c1' 'c0e105' '08c1'
    '0fb64202' '8d50bf' '80fa1a' '0f92c2' 'c0e205' '08c2'
    '38d1' '0f94c0' 'c3' '31c0' 'c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000044a0100804582008f00000000000000')
NEXT = bytes.fromhex(
    '2c000000184a0100fc458200b902000000410e10420e18410e2083048e0386020395'
    '020e18420e10410e08410e200000')
CALLER_FDES = [
    (0x14b34, bytes.fromhex(
        '48000000384b0100ac508200a305000000410e10420e18420e20420e28420e30410'
        'e38410e4083078c068d058e048f0386020332050e38410e30420e28420e20420e184'
        '20e10410e08410e40'),
     0x151b100, 0x151b6a3),
]
CALLERS = [0x151b4f9, 0x151b527]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fold(byte):
    """ASCII A-Z fold, exactly as the retained bytes implement it.

    lea byte-0x41, cmp <= 0x1a unsigned, setb, shl 5, or: bytes in
    'A'..'Z' gain 0x20 (become lowercase); every other byte, including
    bytes below 0x41 (whose wrapped difference exceeds 0x1a unsigned),
    is unchanged. ASCII-only by construction; no locale or Unicode claim.
    """
    require(0 <= byte <= 0xff, 'Byte out of range')
    return (byte | 0x20) if 0x41 <= byte <= 0x5a else byte


def case_insensitive_3byte_equal(left, right):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary: the length must be exactly 3, and
    all three folded byte pairs must match, else 0.
    """
    require(len(left) == 3 and len(right) == 3, 'Edge inputs must be 3 bytes')
    return 1 if all(fold(a) == fold(b) for a, b in zip(left, right)) else 0


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
    require(body == BODY, 'Case-insensitive 3-byte equality window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    check_fde(0x14a00, FDE, START, END)
    check_fde(0x14a14, NEXT, PAD_END, 0x151a7e9)
    for offset, raw, start, end in CALLER_FDES:
        check_fde(offset, raw, start, end)
    # Padding: one int3 byte between the FDE end and the next FDE start,
    # and fourteen int3 bytes before the window (previous FDE ends 0x151a492).
    require(read(END, PAD_END - END) == b'\xcc' * 1, 'Padding changed')
    require(read(START - 14, 14) == b'\xcc' * 14, 'Leading padding changed')
    require(PAD_END == 0x151a530, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x151a4a0.
    fixed = [
        (0x00, '4883fe03', 'Length compare changed'),
        (0x04, '0f8582000000', 'Length-gate branch changed'),
        (0x0a, '0fb607', 'First left load changed'),
        (0x0d, '8d48bf', 'First left fold lea changed'),
        (0x10, '80f91a', 'First left fold compare changed'),
        (0x13, '0f92c1', 'First left fold setb changed'),
        (0x16, 'c0e105', 'First left fold shift changed'),
        (0x19, '08c1', 'First left fold or changed'),
        (0x1b, '0fb602', 'First right load changed'),
        (0x1e, '8d70bf', 'First right fold lea changed'),
        (0x21, '4080fe1a', 'First right fold compare changed'),
        (0x25, '400f92c6', 'First right fold setb changed'),
        (0x29, '40c0e605', 'First right fold shift changed'),
        (0x2d, '4008c6', 'First right fold or changed'),
        (0x30, '4038f1', 'First pair compare changed'),
        (0x33, '7557', 'First pair branch changed'),
        (0x35, '0fb64701', 'Second left load changed'),
        (0x39, '8d48bf', 'Second left fold lea changed'),
        (0x3c, '80f91a', 'Second left fold compare changed'),
        (0x3f, '0f92c1', 'Second left fold setb changed'),
        (0x42, 'c0e105', 'Second left fold shift changed'),
        (0x45, '08c1', 'Second left fold or changed'),
        (0x47, '0fb64201', 'Second right load changed'),
        (0x4b, '8d70bf', 'Second right fold lea changed'),
        (0x4e, '4080fe1a', 'Second right fold compare changed'),
        (0x52, '400f92c6', 'Second right fold setb changed'),
        (0x56, '40c0e605', 'Second right fold shift changed'),
        (0x5a, '4008c6', 'Second right fold or changed'),
        (0x5d, '4038f1', 'Second pair compare changed'),
        (0x60, '752a', 'Second pair branch changed'),
        (0x62, '0fb64702', 'Third left load changed'),
        (0x66, '8d48bf', 'Third left fold lea changed'),
        (0x69, '80f91a', 'Third left fold compare changed'),
        (0x6c, '0f92c1', 'Third left fold setb changed'),
        (0x6f, 'c0e105', 'Third left fold shift changed'),
        (0x72, '08c1', 'Third left fold or changed'),
        (0x74, '0fb64202', 'Third right load changed'),
        (0x78, '8d50bf', 'Third right fold lea changed'),
        (0x7b, '80fa1a', 'Third right fold compare changed'),
        (0x7e, '0f92c2', 'Third right fold setb changed'),
        (0x81, 'c0e205', 'Third right fold shift changed'),
        (0x84, '08c2', 'Third right fold or changed'),
        (0x86, '38d1', 'Third pair compare changed'),
        (0x88, '0f94c0', 'Success sete changed'),
        (0x8b, 'c3', 'Success return changed'),
        (0x8c, '31c0', 'Fail zeroing changed'),
        (0x8e, 'c3', 'Fail return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # No call opcode at any instruction start inside the window; the only
    # transfers are the two conditional early exits and the length gate.
    starts = {off for off, _, _ in fixed}
    for pos, byte in enumerate(body):
        if pos in starts:
            require(byte != 0xe8, 'Unexpected call opcode in window')
    # Relocations: no R_X86_64_RELATIVE record in any .rela.* section names
    # this window as addend.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((sec['name'], address))
    require(naming == [], 'Relocation slots naming window changed')
    # Incoming calls: direct e8 call sites anywhere in .text, each inside
    # the single caller FDE.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == CALLERS, 'Incoming direct callers changed')
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    require(fold(0x41) == 0x61, 'Fold A edge changed')
    require(fold(0x5a) == 0x7a, 'Fold Z edge changed')
    require(fold(0x40) == 0x40, 'Fold below-A edge changed')
    require(fold(0x5b) == 0x5b, 'Fold above-Z edge changed')
    require(fold(0x00) == 0x00, 'Fold zero edge changed')
    require(case_insensitive_3byte_equal(b'ABC', b'abc') == 1,
            'Full-fold match edge changed')
    require(case_insensitive_3byte_equal(b'AbC', b'aBc') == 1,
            'Mixed-case match edge changed')
    require(case_insensitive_3byte_equal(b'ABC', b'ABD') == 0,
            'Third-pair mismatch edge changed')
    require(case_insensitive_3byte_equal(b'ABX', b'aby') == 0,
            'Folded mismatch edge changed')
    require(case_insensitive_3byte_equal(b'A!C', b'a!c') == 1,
            'Non-alpha passthrough edge changed')
    require(case_insensitive_3byte_equal(b'@BC', b'`bc') == 0,
            'Fold-boundary mismatch edge changed')
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
                    'case-insensitive 3-byte equality evidence packet.')
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
        require(retained['function']['padding_bytes'] == 1, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation case-insensitive-3byte-equality evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
