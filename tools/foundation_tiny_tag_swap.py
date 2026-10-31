#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 tiny tag-swap packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window is a tiny tag-swap: rdi = base pointer, sil = input tag byte. It
stores one byte at [rdi+0x10] -- 0 when sil == 0, 2 when sil == 2, else 1 --
via xchg, and returns the byte previously stored there. What the tag means,
and what reads the stored byte, is not claimed anywhere.
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
START, END = 0x4f7fb20, 0x4f7fb38
PAD_END = 0x4f7fb40
BODY = bytes.fromhex('4080fe020f94c0fec031c94084f60fb6c00f44c1864710c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000c87528003c7001041800000000000000')
NEXT = bytes.fromhex(
    '50000000043434000cebc703c0010000046f8a8cff420e10420e18420e20410e28410e3083058c048e038f020315010e28410e20420e18420e10420e08420e3002660e28410e20420e18420e10420e08410e3000')
SLOTS = [
    '0x5664220', '0x566ec28', '0x567b650', '0x567bd40', '0x567ce38',
    '0x567e028', '0x567e988', '0x567ef98', '0x5680488', '0x5680c88',
    '0x5681aa8', '0x5683000', '0x5683cd8', '0x5684570', '0x5684a10',
    '0x5685860', '0x56c97a0', '0x56ca698', '0x56cab28', '0x56cb408',
    '0x56cbef0', '0x56cc050', '0x56cc140', '0x56cd2d0', '0x56ce500',
    '0x56ce988', '0x56cefb8', '0x56cf848', '0x56d0398', '0x56d04c8',
    '0x56d1500', '0x56d2468', '0x56d35d0', '0x56d59f8', '0x56d5b18',
    '0x574b088',
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse(old, sil):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. Returns (stored_byte, return_value).
    """
    if sil == 0:
        stored = 0
    elif sil == 2:
        stored = 2
    else:
        stored = 1
    return stored, old


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
    require(body == BODY, 'Tiny-tag-swap instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    for offset, raw, start, end in [
            (0x2875c4, FDE, START, END),
            (0x61fb14, NEXT, PAD_END, 0x4f7fd00)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: eight int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 8, 'Padding changed')
    require(PAD_END == 0x4f7fb40, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x4f7fb20.
    fixed = [
        (0, '4080fe02', 'Tag compare changed'),
        (4, '0f94c0', 'Tag-two set changed'),
        (7, 'fec0', 'Tag increment changed'),
        (9, '31c9', 'Zero register changed'),
        (11, '4084f6', 'Tag-zero test changed'),
        (14, '0fb6c0', 'Tag extend changed'),
        (17, '0f44c1', 'Tag-zero move changed'),
        (20, '864710', 'Tag exchange changed'),
        (23, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # No branches and no call opcode inside the window.
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    # Relocations: exactly the 36 R_X86_64_RELATIVE slots naming this window.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    require((info & 0xffffffff) == 8, 'Relocation type changed')
                    naming.append((sec['name'], address))
    require([hex(addr) for _, addr in naming] == SLOTS, 'Relocation slots changed')
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
    require(direct == [], 'Incoming direct calls changed')
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    require(parse(0x05, 0) == (0, 0x05), 'Tag-0 edge changed')
    require(parse(0x00, 0) == (0, 0x00), 'Tag-0 zero-old edge changed')
    require(parse(0x00, 2) == (2, 0x00), 'Tag-2 edge changed')
    require(parse(0xff, 2) == (2, 0xff), 'Tag-2 ff-old edge changed')
    require(parse(0x00, 1) == (1, 0x00), 'Else input-1 edge changed')
    require(parse(0xab, 3) == (1, 0xab), 'Else input-3 edge changed')
    require(parse(0x7f, 0x80) == (1, 0x7f), 'Else input-128 edge changed')
    require(parse(0x7f, 0xff) == (1, 0x7f), 'Else input-255 edge changed')
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
                    'tiny tag-swap evidence packet.')
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
        print('Foundation tiny-tag-swap evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
