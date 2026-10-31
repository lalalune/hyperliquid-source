#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 gated dword compare packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window is a gated dword compare: rdi = base pointer. It returns 0 when
the gate byte [rdi+0x228] is 0, and otherwise 1 exactly when
[rdi+0x114] < [rdi+0x110] as unsigned dwords.
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
START, END = 0x53b1080, 0x53b109f
PAD_END = 0x53b10a0
BRANCH_TARGET = 0x53b109e
BODY = bytes.fromhex('f30f1efa0fb6872802000084c0740f8b87100100003987140100000f92c0c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000dc572b0088a341041f000000')
NEXT = bytes.fromhex('10000000f0572b0094a3410413000000')
SLOTS = [
    '0x5764818',
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse(gate, low, high):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. Returns 0 when the gate byte is 0,
    else 1 exactly when high < low as unsigned dwords.
    """
    if gate == 0:
        return 0
    return 1 if high < low else 0


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
    require(body == BODY, 'Gated-dword-compare instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    for offset, raw, start, end in [
            (0x2b57d8, FDE, START, END),
            (0x2b57ec, NEXT, PAD_END, 0x53b10b3)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: one int3 byte between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 1, 'Padding changed')
    require(PAD_END == 0x53b10a0, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x53b1080.
    fixed = [
        (0, 'f30f1efa', 'Entry endbr64 changed'),
        (4, '0fb68728020000', 'Gate byte load changed'),
        (11, '84c0', 'Gate byte test changed'),
        (13, '740f', 'Gate branch changed'),
        (15, '8b8710010000', 'Low dword load changed'),
        (21, '398714010000', 'High dword compare changed'),
        (27, '0f92c0', 'Unsigned setb changed'),
        (30, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # The branch lands exactly on the ret: je at START+13 is 2 bytes, so
    # target = START+13+2+disp.
    disp = struct.unpack_from('<b', body, 14)[0]
    require(START + 13 + 2 + disp == BRANCH_TARGET, 'Branch target changed')
    # No call opcode inside the window.
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
    require(parse(0, 0x00, 0xffffffff) == 0, 'Gate-off edge changed')
    require(parse(1, 0x20, 0x10) == 1, 'High-below edge changed')
    require(parse(1, 0x10, 0x20) == 0, 'High-above edge changed')
    require(parse(1, 0x10, 0x10) == 0, 'Both-equal edge changed')
    require(parse(1, 0x00, 0xffffffff) == 0, 'High-max-low-zero edge changed')
    require(parse(1, 0x80000000, 0x7fffffff) == 1, 'Unsigned-wrap edge changed')
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
                    'gated dword compare evidence packet.')
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
        print('Foundation gated-dword-compare evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
