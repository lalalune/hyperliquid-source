#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 slot-move packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window is a 16-byte slot move with a kind-gated restore and a tag byte 5:
the link field is always overwritten from a two-hop pointer load, the slot is
zeroed, and then the restore depends on the kind byte -- full 16-byte restore
iff kind <= 4, first-qword-only restore iff kind in [16..21], no restore
otherwise -- while the output byte is 5 on every path. What the kind values
mean, and what reads the slot or the tag, is not claimed anywhere.
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
START, END = 0x3290130, 0x3290192
PAD_END = 0x32901a0
BODY = bytes.fromhex(
    '4889f84c8b82d80000004531c948833900410f94c141c1e104420fb6740940'
    '4a8d14094883c230420f104409304a8b7c09304d8b80380200004e89440928'
    '0f57c9420f114c09308d4ef083f906730748893ac60005c383fe0477f70f11'
    '02c60005c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000e064100034874a026200000000000000')
NEXT = bytes.fromhex(
    '2c000000c8071a00a81d13027700000004b7d491ff420e10410e18410e208'
    '3038e027b0e18410e10420e08410e200000')
SLOTS = [
    '0x56e3b70', '0x56e3d80', '0x56e4230', '0x56e4380', '0x56e46e0',
    '0x56e4830', '0x56e4980', '0x56e4c20', '0x56e4d70', '0x56e4ec0',
    '0x56e5010', '0x56e5160', '0x56e52b0', '0x56e5550', '0x56e56a0',
    '0x56e57f0', '0x56e5940', '0x56e5d30', '0x56e5e80', '0x56e6120',
    '0x56e63c0', '0x56e6510', '0x56e6660', '0x56e67b0', '0x56e6900',
    '0x56e6a50', '0x56e6cf0', '0x56e6f90', '0x56e7230', '0x56e7380',
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse(kind, saved):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. ``saved`` is the 16-byte slot content
    before the window. Returns (restored_bytes_or_None, tag_byte).
    """
    if kind <= 4:
        restored = saved
    elif 16 <= kind <= 21:
        restored = saved[:8] + bytes(8)
    else:
        restored = bytes(16)
    return restored, 5


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
    require(body == BODY, 'Slot-move instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    for offset, raw, start, end in [
            (0x1064dc, FDE, START, END),
            (0x47ced8, NEXT, PAD_END, 0x3290217)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: fourteen int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 14, 'Padding changed')
    require(PAD_END == 0x32901a0, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x3290130.
    fixed = [
        (0, '4889f8', 'Output pointer save changed'),
        (3, '4c8b82d8000000', 'First pointer hop changed'),
        (10, '4531c9', 'Slot selector zero changed'),
        (13, '48833900', 'Slot selector compare changed'),
        (17, '410f94c1', 'Slot selector set changed'),
        (21, '41c1e104', 'Slot selector shift changed'),
        (25, '420fb6740940', 'Kind load changed'),
        (31, '4a8d1409', 'Slot base lea changed'),
        (35, '4883c230', 'Slot base add changed'),
        (39, '420f10440930', 'Slot save changed'),
        (45, '4a8b7c0930', 'First qword save changed'),
        (50, '4d8b8038020000', 'Second pointer hop changed'),
        (57, '4e89440928', 'Link field store changed'),
        (62, '0f57c9', 'Slot zero changed'),
        (65, '420f114c0930', 'Slot zero store changed'),
        (71, '8d4ef0', 'Kind minus 16 changed'),
        (74, '83f906', 'Kind band compare changed'),
        (77, '7307', 'First-qword band branch changed'),
        (79, '48893a', 'First-qword restore changed'),
        (82, 'c60005', 'Tag store changed'),
        (85, 'c3', 'Return changed'),
        (86, '83fe04', 'Full restore gate changed'),
        (89, '77f7', 'Tag-only branch changed'),
        (91, '0f1102', 'Full restore changed'),
        (94, 'c60005', 'Tag store changed'),
        (97, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # Branch targets, derived from the rel8 displacements.
    require(START + 0x4d + 2 + struct.unpack_from('<b', body, 0x4e)[0]
            == 0x3290186, 'First-qword band target changed')
    require(START + 0x59 + 2 + struct.unpack_from('<b', body, 0x5a)[0]
            == 0x3290182, 'Tag-only target changed')
    # No call opcode inside the window.
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    # Relocations: exactly the 30 R_X86_64_RELATIVE slots naming this window.
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
    saved = bytes(range(16))
    require(parse(0, saved) == (saved, 5), 'Kind-0 edge changed')
    require(parse(4, saved) == (saved, 5), 'Kind-4 edge changed')
    require(parse(5, saved) == (bytes(16), 5), 'Kind-5 edge changed')
    require(parse(15, saved) == (bytes(16), 5), 'Kind-15 edge changed')
    require(parse(16, saved) == (saved[:8] + bytes(8), 5), 'Kind-16 edge changed')
    require(parse(21, saved) == (saved[:8] + bytes(8), 5), 'Kind-21 edge changed')
    require(parse(22, saved) == (bytes(16), 5), 'Kind-22 edge changed')
    require(parse(255, saved) == (bytes(16), 5), 'Kind-255 edge changed')
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
                    'slot-move evidence packet.')
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
        require(retained['function']['padding_bytes'] == 14, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation slot-move-kind-gated-restore evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
