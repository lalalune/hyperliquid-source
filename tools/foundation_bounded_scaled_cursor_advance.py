#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 bounded scaled cursor advance packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window advances a cursor by a scaled, input-bounded amount and returns the
unadvanced remainder. What the struct fields mean, and what consumes the
result, is not claimed anywhere.
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
START, END = 0x4ea41e0, 0x4ea4216
PAD_END = 0x4ea4220
BODY = bytes.fromhex('4889f0488b4f08488b57184829ca48c1ea0348bea38b2ebae8a28b2e480faff24839f0480f42f0486bd6584801ca488957084829f0c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c0708')
FDE = bytes.fromhex('1000000080c827004464f40336000000')
NEXT = bytes.fromhex('1000000094c827007064f40349000000')
SLOT = 0x574faf8
FACTOR = 0x2e8ba2e8ba2e8ba3
MASK = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def advance_rule(input_value, cursor, end):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary: count = (end - cursor) >> 3, scaled =
    count * FACTOR (low 64 bits), taken = min(input, scaled) unsigned,
    new cursor = cursor + taken * 88, return input - taken, all wrapping.
    """
    count = ((end - cursor) & MASK) >> 3
    scaled = (count * FACTOR) & MASK
    taken = input_value if input_value < scaled else scaled
    new_cursor = (cursor + taken * 88) & MASK
    return taken, new_cursor, (input_value - taken) & MASK


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
    require(body == BODY, 'Bounded scaled cursor advance window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    for offset, raw, start, end in [
            (0x27c87c, FDE, START, END),
            (0x27c890, NEXT, PAD_END, 0x4ea4269)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: ten int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 10, 'Padding changed')
    require(PAD_END == 0x4ea4220, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x4ea41e0.
    fixed = [
        (0x00, '4889f0', 'Input preserve changed'),
        (0x03, '488b4f08', 'Cursor load changed'),
        (0x07, '488b5718', 'End load changed'),
        (0x0b, '4829ca', 'Span subtract changed'),
        (0x0e, '48c1ea03', 'Count shift changed'),
        (0x12, '48bea38b2ebae8a28b2e', 'Factor load changed'),
        (0x1c, '480faff2', 'Scaled multiply changed'),
        (0x20, '4839f0', 'Compare changed'),
        (0x23, '480f42f0', 'Conditional move changed'),
        (0x27, '486bd658', 'Advance multiply changed'),
        (0x2b, '4801ca', 'Cursor add changed'),
        (0x2e, '48895708', 'Cursor store changed'),
        (0x32, '4829f0', 'Remainder subtract changed'),
        (0x35, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # No call opcode at any instruction start inside the window; the only
    # conditional transfer is cmovb, and every path falls through to ret.
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
    require(advance_rule(0, 0, 0) == (0, 0, 0), 'Zero edge changed')
    require(advance_rule(100, 0, 88) == (1, 0x58, 99), 'Scaled-unit edge changed')
    require(advance_rule(10, 0, 40) == (10, 0x370, 0), 'Input-below-scaled edge changed')
    require(advance_rule(50, 16, 280) == (3, 0x118, 47), 'Partial advance edge changed')
    require(advance_rule((1 << 64) - 1, 0, 8) ==
            (0x2e8ba2e8ba2e8ba3, 8, 0xd1745d1745d1745c),
            'Input-dominates edge changed')
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
                    'bounded scaled cursor advance evidence packet.')
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
        require(retained['function']['padding_bytes'] == 10, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation bounded-scaled-cursor-advance evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
