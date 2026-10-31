#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 gated two-field copy packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window is a gated two-field copy: rdi = base pointer, rsi = destination
pointer. It loads p = [rdi+0x2d8]; when p is null or the gate byte
[rdi+0xb8] is 0 it stores nothing, and otherwise stores [p+0x20] at
[rsi+0x10] and [p+0x60] at [rsi+0x18].
What the fields mean, and what reads the copied fields, is not claimed anywhere.
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
START, END = 0x53b1120, 0x53b114a
PAD_END = 0x53b1150
BRANCH_TARGET = 0x53b1149
BODY = bytes.fromhex('f30f1efa488b87d80200004885c0741980bfb8000000007410488b5020488b40604889561048894618c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000068582b009ca341042a000000')
NEXT = bytes.fromhex('100000007c582b00b8a341041e000000')
SLOTS = [
    '0x57648b0',
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse(p_is_null, gate, field20, field60):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. Returns None when nothing is stored
    (null pointer or gate byte clear), else the (field20, field60) pair in
    destination order: field20 lands at [rsi+0x10], field60 at [rsi+0x18].
    """
    if p_is_null or gate == 0:
        return None
    return (field20, field60)


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
    require(body == BODY, 'Gated-two-field-copy instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    for offset, raw, start, end in [
            (0x2b5864, FDE, START, END),
            (0x2b5878, NEXT, PAD_END, 0x53b116e)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: six int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 6, 'Padding changed')
    require(PAD_END == 0x53b1150, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x53b1120.
    fixed = [
        (0, 'f30f1efa', 'Entry endbr64 changed'),
        (4, '488b87d8020000', 'Pointer load changed'),
        (11, '4885c0', 'Pointer test changed'),
        (14, '7419', 'Null branch changed'),
        (16, '80bfb800000000', 'Gate byte compare changed'),
        (23, '7410', 'Gate branch changed'),
        (25, '488b5020', 'First field load changed'),
        (29, '488b4060', 'Second field load changed'),
        (33, '48895610', 'First field store changed'),
        (37, '48894618', 'Second field store changed'),
        (41, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # Both branches land exactly on the ret: je at START+14 is 2 bytes, so
    # target = START+14+2+disp; je at START+23 is 2 bytes, so
    # target = START+23+2+disp.
    disp_null = struct.unpack_from('<b', body, 15)[0]
    require(START + 14 + 2 + disp_null == BRANCH_TARGET, 'Null branch target changed')
    disp_gate = struct.unpack_from('<b', body, 24)[0]
    require(START + 23 + 2 + disp_gate == BRANCH_TARGET, 'Gate branch target changed')
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
    require(parse(True, 1, 0x11, 0x22) is None, 'Null-pointer edge changed')
    require(parse(False, 0, 0x11, 0x22) is None, 'Gate-clear edge changed')
    require(parse(False, 1, 0x11, 0x22) == (0x11, 0x22), 'Copy edge changed')
    require(parse(False, 1, 0x0, 0xffffffffffffffff) == (0x0, 0xffffffffffffffff),
            'Extreme-fields edge changed')
    require(parse(False, 0xff, 0x22, 0x11) == (0x22, 0x11),
            'Field-order edge changed')
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
                    'gated two-field copy evidence packet.')
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
        require(retained['function']['padding_bytes'] == 6, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation gated-two-field-copy evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
