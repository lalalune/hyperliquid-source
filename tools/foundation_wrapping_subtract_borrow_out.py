#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 four-limb wrapping subtract packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window subtracts one four-limb (256-bit) value from another with a borrow
chain, rewrites the minuend in place, copies the difference unconditionally to
a destination, and stores a borrow-out byte. What the 256-bit values hold, and
what the callers do with the result, is not claimed anywhere.
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
START, END = 0x32d8310, 0x32d8361
PAD_END = 0x32d8370
BODY = bytes.fromhex(
    '488b02' '482906'
    '488b4208' '48194608'
    '488b4210' '48194610'
    '488b4618' '0f92c1' '482b4218' '0f92c2' '80c1ff' '4883d800'
    '0f92c1' '08d1' '80e101'
    '48894618'
    '0f1006' '0f1107'
    '488b4610' '48894710'
    '488b4618' '48894718'
    '884f20' 'c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000d095100024d84e025100000000000000')
NEXT = bytes.fromhex('40000000e495100070d84e02d002000000410e10420e18420e20420e28420e30410e3883078c068d058e048f03860203bc020e30420e28420e20420e18420e10410e0800')
CALLER_FDES = [
    (0x107258, bytes.fromhex(
        '4c0000005c721000080a4b023605000000410e10420e18420e20420e28420e30410e38470e800483078c068d058e048f038602030b040e38410e30420e28420e20420e18420e10410e08410e80040000'),
     0x3299180, 0x32996b6),
]
CALLERS = [0x32994ed, 0x3299579]
MASK = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def wrapping_subtract(minuend, subtrahend):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary: the four difference limbs of
    minuend - subtrahend as unsigned 256-bit values, plus a borrow-out byte
    that is 1 iff the minuend is strictly smaller than the subtrahend.
    `minuend` and `subtrahend` are four unsigned 64-bit words in address order.
    """
    require(len(minuend) == 4 and len(subtrahend) == 4,
            'Operands must hold exactly four qwords')
    m = sum((x & MASK) << (64 * i) for i, x in enumerate(minuend))
    s = sum((x & MASK) << (64 * i) for i, x in enumerate(subtrahend))
    diff = (m - s) % (1 << 256)
    limbs = [(diff >> (64 * i)) & MASK for i in range(4)]
    return limbs, 1 if m < s else 0


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
    require(body == BODY, 'Four-limb wrapping subtract window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    check_fde(0x1095cc, FDE, START, END)
    check_fde(0x1095e0, NEXT, PAD_END, 0x32d8640)
    for offset, raw, start, end in CALLER_FDES:
        check_fde(offset, raw, start, end)
    # Padding: fifteen int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 15, 'Padding changed')
    require(PAD_END == 0x32d8370, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x32d8310.
    fixed = [
        (0x00, '488b02', 'First subtrahend load changed'),
        (0x03, '482906', 'Limb-0 subtract changed'),
        (0x06, '488b4208', 'Second subtrahend load changed'),
        (0x0a, '48194608', 'Limb-1 subtract-with-borrow changed'),
        (0x0e, '488b4210', 'Third subtrahend load changed'),
        (0x12, '48194610', 'Limb-2 subtract-with-borrow changed'),
        (0x16, '488b4618', 'Top minuend load changed'),
        (0x1a, '0f92c1', 'Limb-2 borrow capture changed'),
        (0x1d, '482b4218', 'Top subtract changed'),
        (0x21, '0f92c2', 'Top subtract borrow capture changed'),
        (0x24, '80c1ff', 'Borrow-in trick changed'),
        (0x27, '4883d800', 'Top subtract-with-borrow changed'),
        (0x2b, '0f92c1', 'Top borrow capture changed'),
        (0x2e, '08d1', 'Borrow-out OR changed'),
        (0x30, '80e101', 'Borrow-out mask changed'),
        (0x33, '48894618', 'Top difference store changed'),
        (0x37, '0f1006', 'Low copy load changed'),
        (0x3a, '0f1107', 'Low copy store changed'),
        (0x3d, '488b4610', 'Third difference load changed'),
        (0x41, '48894710', 'Third difference store changed'),
        (0x45, '488b4618', 'Top difference load changed'),
        (0x49, '48894718', 'Top difference store changed'),
        (0x4d, '884f20', 'Borrow-out store changed'),
        (0x50, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # No call opcode at any instruction start inside the window; every path
    # falls through to the single ret (the window is branchless).
    starts = {off for off, _, _ in fixed}
    for pos, byte in enumerate(body):
        if pos in starts:
            require(byte != 0xe8, 'Unexpected call opcode in window')
    # No branch opcodes at any instruction start inside the window.
    for off, _, _ in fixed:
        require(body[off] not in (0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
                                  0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d,
                                  0x7e, 0x7f, 0xeb, 0xe9),
                'Unexpected branch opcode in window')
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
    # its own caller FDE.
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
    require(wrapping_subtract([0, 0, 0, 0], [0, 0, 0, 0]) ==
            ([0, 0, 0, 0], 0), 'Zero edge changed')
    require(wrapping_subtract([1, 0, 0, 0], [0, 0, 0, 0]) ==
            ([1, 0, 0, 0], 0), 'No-borrow edge changed')
    require(wrapping_subtract([0, 0, 0, 0], [1, 0, 0, 0]) ==
            ([MASK, MASK, MASK, MASK], 1), 'Borrow edge changed')
    require(wrapping_subtract([0, 1, 0, 0], [1, 0, 0, 0]) ==
            ([MASK, 0, 0, 0], 0), 'Borrow-chain edge changed')
    require(wrapping_subtract([MASK, MASK, MASK, MASK], [1, 0, 0, 0]) ==
            ([MASK - 1, MASK, MASK, MASK], 0), 'Full-minus-one edge changed')
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
                    'four-limb wrapping subtract evidence packet.')
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
        require(retained['function']['padding_bytes'] == 15, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation wrapping-subtract-borrow-out evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
