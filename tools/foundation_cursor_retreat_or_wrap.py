#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 cursor retreat-or-wrap packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window steps a cursor back by one 8-byte element, or wraps it to the far
bound when it already equals the first bound. What the bounds mean, and what
the cursor walks over, is not claimed anywhere.
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
START, END = 0x52c6ea0, 0x52c6ec9
PAD_END = 0x52c6ed0
BODY = bytes.fromhex(
    'f30f1efa' '488b5710' '488b4720' '483b02' '740f'
    '4883e808' '48894720' 'c3'
    '660f1f440000' '488b4208' '48894720' 'c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000b0bc2a00d49c33042900000000000000')
NEXT = bytes.fromhex('10000000c4bc2a00f09c33040500000000000000')
SLOT = ('.rela.dyn', '0x57615c8')
MASK = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def retreat_or_wrap(cursor, first, second):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary: when the cursor equals the first
    bound it is replaced by the second bound, otherwise it steps back by
    8, wrapping modulo 2^64.
    """
    if cursor == first:
        return second
    return (cursor - 8) & MASK


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
    require(body == BODY, 'Cursor retreat-or-wrap window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    check_fde(0x2abcac, FDE, START, END)
    check_fde(0x2abcc0, NEXT, PAD_END, 0x52c6ed5)
    # Padding: seven int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 7, 'Padding changed')
    require(PAD_END == 0x52c6ed0, 'FDE stride end changed')
    # Preceding gap: five int3 bytes after the previous FDE ends.
    require(read(START - 5, 5) == b'\xcc' * 5, 'Preceding gap changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x52c6ea0.
    fixed = [
        (0x00, 'f30f1efa', 'Entry marker changed'),
        (0x04, '488b5710', 'Bounds pointer load changed'),
        (0x08, '488b4720', 'Cursor load changed'),
        (0x0c, '483b02', 'First-bound compare changed'),
        (0x0f, '740f', 'Wrap branch changed'),
        (0x11, '4883e808', 'Step-back subtract changed'),
        (0x15, '48894720', 'Step-back store changed'),
        (0x19, 'c3', 'Step-back return changed'),
        (0x1a, '660f1f440000', 'Inter-path alignment padding changed'),
        (0x20, '488b4208', 'Second-bound load changed'),
        (0x24, '48894720', 'Wrap store changed'),
        (0x28, 'c3', 'Wrap return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # The je at 0x0f must land exactly on the wrap path at 0x52c6ec0.
    rel8 = body[0x10] if body[0x10] < 0x80 else body[0x10] - 256
    require(START + 0x0f + 2 + rel8 == 0x52c6ec0,
            'Wrap branch target changed')
    # No call opcode at any instruction start inside the window; both paths
    # fall through to their own ret.
    starts = {off for off, _, _ in fixed}
    for pos, byte in enumerate(body):
        if pos in starts:
            require(byte != 0xe8, 'Unexpected call opcode in window')
    # Relocations: exactly one R_X86_64_RELATIVE record in .rela.dyn names
    # this window as addend.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append([sec['name'], hex(address)])
    require(naming == [[SLOT[0], SLOT[1]]], 'Relocation slots naming window changed')
    # Incoming calls: direct e8 call sites anywhere in .text; none may land
    # on this window.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == [], 'Incoming direct callers changed')
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    require(retreat_or_wrap(100, 100, 200) == 200, 'Wrap edge changed')
    require(retreat_or_wrap(108, 100, 200) == 100, 'Step-back edge changed')
    require(retreat_or_wrap(0, 100, 200) == (1 << 64) - 8, 'Wrapping edge changed')
    require(retreat_or_wrap(8, 0, 16) == 0, 'Step-to-bound edge changed')
    require(retreat_or_wrap(16, 16, 16) == 16, 'Equal-bounds edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'relocation_slots': [[name, addr] for name, addr in naming],
        'direct_callers': direct,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 '
                    'cursor retreat-or-wrap evidence packet.')
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
        require(retained['function']['padding_bytes'] == 7, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation cursor-retreat-or-wrap evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
