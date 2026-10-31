#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 three-field span sum packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window returns a span (one field minus another) plus a third field, all
64-bit wrapping. What the three fields mean, and what consumes the result,
is not claimed anywhere.
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
START, END = 0x5276b80, 0x5276b94
PAD_END = 0x5276ba0
BODY = bytes.fromhex('f30f1efa488b4770482b476048038780000000c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c0708')
FDE = bytes.fromhex('10000000688a2a00fccb2e0414000000')
NEXT = bytes.fromhex('100000007c8a2a0008cc2e041c000000')
SLOT = 0x575fc28
MASK = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def span_rule(end, start, third):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary: rax = [rdi+0x70] - [rdi+0x60] +
    [rdi+0x80], all 64-bit wrapping.
    """
    return ((end - start + third) & MASK)


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
    require(body == BODY, 'Three-field span sum window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    for offset, raw, start, end in [
            (0x2a8a64, FDE, START, END),
            (0x2a8a78, NEXT, PAD_END, 0x5276bbc)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: twelve int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 12, 'Padding changed')
    require(PAD_END == 0x5276ba0, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x5276b80.
    fixed = [
        (0x00, 'f30f1efa', 'Endbr64 entry changed'),
        (0x04, '488b4770', 'First field load changed'),
        (0x08, '482b4760', 'Span subtract changed'),
        (0x0c, '48038780000000', 'Third field add changed'),
        (0x13, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # No call opcode at any instruction start inside the window; there are no
    # branches at all, and every path falls through to ret.
    starts = {off for off, _, _ in fixed}
    for pos, byte in enumerate(body):
        if pos in starts:
            require(byte != 0xe8, 'Unexpected call opcode in window')
    # Relocations: exactly one R_X86_64_RELATIVE record in .rela.dyn names
    # this window as addend; no record in any other .rela.* section does.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((sec['name'], address))
    require(naming == [('.rela.dyn', SLOT)], 'Relocation slots naming window changed')
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
    require(direct == [], 'Unexpected incoming direct call')
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    require(span_rule(0, 0, 0) == 0, 'Zero fields edge changed')
    require(span_rule(7, 7, 11) == 11, 'Span-zero edge changed')
    require(span_rule(5, 9, 3) == MASK, 'Negative span edge changed')
    require(span_rule(MASK, 0, 1) == 0, 'Overflow edge changed')
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
                    'three-field span sum evidence packet.')
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
        require(retained['function']['padding_bytes'] == 12, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation three-field-span-sum evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
