#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 two-struct deep-field compare packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window is a two-struct deep-field compare: rdi and rsi each point at a
struct whose +8 field points at a second struct. It returns 1 in %al exactly
when [[rsi+8]+0x78] < [[rdi+8]+0x78] as unsigned qwords, else 0.
What the bytes mean, and what reads the result, is not claimed anywhere.
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
START, END = 0x51c0c00, 0x51c0c18
PAD_END = 0x51c0c20
CALL_SITE = 0x51e7377
BODY = bytes.fromhex('f30f1efa488b4708488b5608488b4078483942780f92c0c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000024ff2900c0f7230418000000')
NEXT = bytes.fromhex('1000000038ff2900ccf7230405000000')
CALLER_CIE = bytes.fromhex(
    '1c00000000000000017a504c5200017810079b3d5848041b1b0c070890010000')
CALLER_FDE = bytes.fromhex(
    '38000000689c01001cb3ec03aa0d00000494028cff450e108602430d06508f'
    '038e048d058c068307030d022e1002602e00027e0a0c0708450b000000')
CALL_BYTES = bytes.fromhex('e88498fdff')
CALL_SETUP = bytes.fromhex('4801d94801df')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse(first, second):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. Returns 1 exactly when the second
    struct's deep field is strictly below the first struct's, unsigned.
    """
    return 1 if second < first else 0


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
    require(body == BODY, 'Two-struct-deep-field-compare instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    for offset, raw, start, end in [
            (0x29ff20, FDE, START, END),
            (0x29ff34, NEXT, PAD_END, 0x51c0c25),
            (0x6205d0, CALLER_CIE, None, None),
            (0x63a234, CALLER_FDE, 0x51e6a70, 0x51e781a)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE/CIE record changed')
        if start is not None:
            pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
            extent = struct.unpack_from('<I', record, 12)[0]
            require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: eight int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 8, 'Padding changed')
    require(PAD_END == 0x51c0c20, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x51c0c00.
    fixed = [
        (0, 'f30f1efa', 'Entry endbr64 changed'),
        (4, '488b4708', 'First struct hop changed'),
        (8, '488b5608', 'Second struct hop changed'),
        (12, '488b4078', 'First deep field load changed'),
        (16, '48394278', 'Second deep field compare changed'),
        (20, '0f92c0', 'Unsigned setb changed'),
        (23, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # No call opcode inside the window.
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    # The single caller: call bytes and the two adds immediately before it.
    require(read(CALL_SITE, len(CALL_BYTES)) == CALL_BYTES,
            'Caller call bytes changed')
    require(read(CALL_SITE - 6, len(CALL_SETUP)) == CALL_SETUP,
            'Caller setup changed')
    # Relocations: no record of any type names this window as addend.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((sec['name'], address))
    require(naming == [], 'Unexpected naming relocation')
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
    require(direct == [CALL_SITE], 'Incoming direct calls changed')
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    require(parse(0, 0) == 0, 'Both-zero edge changed')
    require(parse(1, 0) == 1, 'Second-below edge changed')
    require(parse(0, 1) == 0, 'Second-above edge changed')
    require(parse(0xffffffffffffffff, 0xfffffffffffffffe) == 1,
            'Second-max-minus-one edge changed')
    require(parse(0, 0xffffffffffffffff) == 0, 'Second-max-first-zero edge changed')
    require(parse(0x8000000000000000, 0x7fffffffffffffff) == 1,
            'Unsigned-wrap edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'relocation_slots': [[name, hex(addr)] for name, addr in naming],
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
                    'two-struct deep-field compare evidence packet.')
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
        require(retained['function']['padding_bytes'] == 8, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation two-struct-deep-field-compare evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
