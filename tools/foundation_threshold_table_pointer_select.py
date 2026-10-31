#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 threshold table-pointer select packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window compares an unsigned index against 0x3f and returns either a
rip-relative table address or zero. What the table at that address holds,
and what consumes the returned pointer, is not claimed anywhere.
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
START, END = 0x54d76e0, 0x54d76f9
PAD_END = 0x54d7700
TABLE_ADDRESS = 0x576a6c0
BODY = bytes.fromhex(
    'f30f1efa4883f93fba00000000488d05cc2f2900480f47c2c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c0708')
FDE = bytes.fromhex('1000000060172c00644a53041900000000000000')
NEXT = bytes.fromhex('1000000074172c00704a53043300000000000000')
SLOT = 0x576a6a8


def require(condition, message):
    if not condition:
        raise ValueError(message)


def select_rule(index):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. cmova is the unsigned above test, so
    indices strictly above 0x3f select zero; indices at or below 0x3f keep
    the lea address. The lea target is the next instruction address plus
    the displacement: 0x54d76f4 + 0x292fcc = 0x576a6c0.
    """
    return 0 if index > 0x3f else TABLE_ADDRESS


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
    require(body == BODY, 'Threshold table-pointer select window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    for offset, raw, start, end in [
            (0x2c175c, FDE, START, END),
            (0x2c1770, NEXT, PAD_END, 0x54d7733)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: seven int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 7, 'Padding changed')
    require(PAD_END == 0x54d7700, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x54d76e0.
    fixed = [
        (0x00, 'f30f1efa', 'Endbr64 entry changed'),
        (0x04, '4883f93f', 'Threshold compare changed'),
        (0x08, 'ba00000000', 'Zero candidate load changed'),
        (0x0d, '488d05cc2f2900', 'Table address lea changed'),
        (0x14, '480f47c2', 'Unsigned-above select changed'),
        (0x18, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # Lea target, decoded from the locked displacement: the next instruction
    # address (0x54d76f4) plus 0x292fcc is 0x576a6c0.
    require(0x54d76f4 + 0x292fcc == TABLE_ADDRESS, 'Lea target changed')
    # No call opcode at any instruction start inside the window; cmova is the
    # only conditional transfer, and every path falls through to ret.
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
    require(select_rule(0x00) == TABLE_ADDRESS, 'Zero index edge changed')
    require(select_rule(0x3f) == TABLE_ADDRESS, 'Threshold boundary edge changed')
    require(select_rule(0x40) == 0, 'Above-threshold edge changed')
    require(select_rule(0xffffffffffffffff) == 0, 'Max index edge changed')
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
                    'threshold table-pointer select evidence packet.')
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
        print('Foundation threshold-table-pointer-select evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
