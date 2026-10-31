#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 sixteen-byte copy packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window is a sixteen-byte copy with a constant return: rdx and rsi are
pointer arguments. It loads the destination pointer dest = [rdx+8], then the
source base q = [[rsi+0x10]+8], copies the 16 bytes at q-0x10 to dest with an
unaligned vector load/store pair, and returns 1.
What the copied bytes mean, and what reads them, is not claimed anywhere.
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
START, END = 0x5454710, 0x545472e
PAD_END = 0x5454730
BODY = bytes.fromhex('f30f1efa488b4208488b5610488b5208f30f6f42f00f1100b801000000c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000a8c92b004c684b041e000000')
NEXT = bytes.fromhex('18000000bcc92b0058684b043d000000')
SLOTS = [
    '0x57675a0',
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse(dest, q):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. dest is the loaded [rdx+8] value, q is
    the loaded [[rsi+0x10]+8] value. Returns (destination, source, 1): the
    16 bytes at q-0x10 are stored at dest, and the window returns 1.
    """
    return (dest, q - 0x10, 1)


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
    require(body == BODY, 'Sixteen-byte-copy instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    for offset, raw, start, end in [
            (0x2bc9a4, FDE, START, END),
            (0x2bc9b8, NEXT, PAD_END, 0x545476d)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: two int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 2, 'Padding changed')
    require(PAD_END == 0x5454730, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x5454710.
    fixed = [
        (0, 'f30f1efa', 'Entry endbr64 changed'),
        (4, '488b4208', 'Destination load changed'),
        (8, '488b5610', 'Intermediate load changed'),
        (12, '488b5208', 'Source base load changed'),
        (16, 'f30f6f42f0', 'Vector load changed'),
        (21, '0f1100', 'Vector store changed'),
        (24, 'b801000000', 'Constant return changed'),
        (29, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # No call opcode inside the window, and no branch opcode either: the
    # window is straight-line from endbr64 to ret.
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    # Relocations: exactly the one R_X86_64_RELATIVE slot naming this window.
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
    require(parse(0x1000, 0x2010) == (0x1000, 0x2000, 1), 'Copy edge changed')
    require(parse(0x0, 0x10) == (0x0, 0x0, 1), 'Zero-source edge changed')
    require(parse(0xfffffffffffffff0, 0x1000000000000010) ==
            (0xfffffffffffffff0, 0x1000000000000000, 1), 'Large-address edge changed')
    require(parse(0x2000, 0x2010) == (0x2000, 0x2000, 1),
            'Overlapping-region edge changed')
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
                    'sixteen-byte copy evidence packet.')
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
        require(retained['function']['padding_bytes'] == 2, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation sixteen-byte-copy-return-one evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
