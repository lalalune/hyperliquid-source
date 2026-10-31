#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 byte-swapped reversed 4-qword copy packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window copies four qwords from a source struct to a destination struct
with both the qword order and the byte order of each qword reversed. What the
structs hold, and what the callers do with the copy, is not claimed anywhere.
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
START, END = 0x5632d90, 0x5632dbb
PAD_END = 0x5632dc0
BODY = bytes.fromhex(
    '488b4618' '480fc8' '488907'
    '488b4610' '480fc8' '48894708'
    '488b4608' '480fc8' '48894710'
    '488b06' '480fc8' '48894718' 'c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000cc812d00a89667042b00000000000000')
NEXT = bytes.fromhex('18000000e0812d00c4966704bf000000004b0e10830202750e080000')
CALLER_FDES = [
    (0x2d88b4, bytes.fromhex(
        '40000000b8882d00ec4e6804df02000000420e108e02420e188d03420e208c04410e'
        '288605410e308306470e801502560a0e30410e28410e20420e18420e10420e08430b'),
     0x563ecc0, 0x563ef9f),
    (0x2d89e8, bytes.fromhex(
        '4c000000ec892d00186068047503000000420e108f02420e188e03420e208d04420e'
        '288c05410e308606410e3883074a0ee0030389020a0e38410e30410e28420e20420e'
        '18420e10420e08490b000000'),
     0x563ff20, 0x5640295),
]
CALLERS = [0x563ed52, 0x563ff6f]
MASK = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bswap64(value):
    return int.from_bytes((value & MASK).to_bytes(8, 'little'), 'big')


def bswap_reverse_copy(source):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary: the destination qword at offset 0x00
    is the byte-swapped source qword at offset 0x18, and so on in reverse
    order. `source` is four unsigned 64-bit words in address order.
    """
    require(len(source) == 4, 'Source must hold exactly four qwords')
    return [bswap64(source[3]), bswap64(source[2]),
            bswap64(source[1]), bswap64(source[0])]


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
    require(body == BODY, 'Byte-swapped reversed copy window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    check_fde(0x2d81c8, FDE, START, END)
    check_fde(0x2d81dc, NEXT, PAD_END, 0x5632e7f)
    for offset, raw, start, end in CALLER_FDES:
        check_fde(offset, raw, start, end)
    # Padding: five int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 5, 'Padding changed')
    require(PAD_END == 0x5632dc0, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x5632d90.
    fixed = [
        (0x00, '488b4618', 'First source load changed'),
        (0x04, '480fc8', 'First byte swap changed'),
        (0x07, '488907', 'First destination store changed'),
        (0x0a, '488b4610', 'Second source load changed'),
        (0x0e, '480fc8', 'Second byte swap changed'),
        (0x11, '48894708', 'Second destination store changed'),
        (0x15, '488b4608', 'Third source load changed'),
        (0x19, '480fc8', 'Third byte swap changed'),
        (0x1c, '48894710', 'Third destination store changed'),
        (0x20, '488b06', 'Fourth source load changed'),
        (0x23, '480fc8', 'Fourth byte swap changed'),
        (0x26, '48894718', 'Fourth destination store changed'),
        (0x2a, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # No call opcode at any instruction start inside the window; every path
    # falls through to the single ret.
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
    require(bswap_reverse_copy([0, 0, 0, 0]) == [0, 0, 0, 0], 'Zero edge changed')
    require(bswap_reverse_copy([1, 2, 3, 4]) ==
            [0x0400000000000000, 0x0300000000000000,
             0x0200000000000000, 0x0100000000000000],
            'Order-reversal edge changed')
    require(bswap_reverse_copy([0x00000000000000ff, 0, 0, 0]) ==
            [0, 0, 0, 0xff00000000000000], 'Single-byte edge changed')
    require(bswap_reverse_copy([0x0102030405060708, 0x1112131415161718,
                                0x2122232425262728, 0x3132333435363738]) ==
            [0x3837363534333231, 0x2827262524232221,
             0x1817161514131211, 0x0807060504030201],
            'Full-word edge changed')
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
                    'byte-swapped reversed 4-qword copy evidence packet.')
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
        require(retained['function']['padding_bytes'] == 5, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation bswap-reverse-copy evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
