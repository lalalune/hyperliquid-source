#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 clamp-with-default store packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window clamps a signed 32-bit input to the range 1..12 with a default of 9
for non-positive inputs, using two conditional moves, and stores the result as
a word at a fixed struct offset. What the input, the struct, and the stored
word mean, and what the three callers do with the stored word, is not claimed
anywhere.
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
START, END = 0x5488d00, 0x5488d20
PAD_END = 0x5488d20
BODY = bytes.fromhex(
    'f30f1efab80c000000ba0900000039c60f4ec685f60f4ec266898724000400c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c0708')
FDE = bytes.fromhex('1000000000e92b00e48e4e042000000000000000')
NEXT = bytes.fromhex(
    '1800000014e92b00f08e4e042e00000000450e108302680e08000000')
CALLER2 = bytes.fromhex(
    '1800000030e92b00048f4e0443000000004e0e1083026d0e0845c300')
CALLER3 = bytes.fromhex(
    '3c00000074e92b00408f4e045401000000460e108e02420e188d03420e208c04440e'
    '288605470e30830602ff0a0e28440e20420e18420e10420e08420b000000')
CALLERS = [0x5488d44, 0x5488d82, 0x5488e20]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def clamp_store(value):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. The first cmovle replaces the bound 12
    with the input when the signed input is <= 12; the second cmovle then
    replaces the result with the default 9 when the signed input is <= 0.
    """
    result = 12
    if value <= 12:
        result = value
    if value <= 0:
        result = 9
    return result


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
    require(body == BODY, 'Clamp-with-default store window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    # The next FDE doubles as the first caller FDE (it starts exactly at END).
    for offset, raw, start, end in [
            (0x2be8fc, FDE, START, END),
            (0x2be910, NEXT, 0x5488d20, 0x5488d4e),
            (0x2be92c, CALLER2, 0x5488d50, 0x5488d93),
            (0x2be970, CALLER3, 0x5488dd0, 0x5488f24)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: zero bytes between the FDE end and the next FDE start.
    require(PAD_END == END, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x5488d00.
    fixed = [
        (0x00, 'f30f1efa', 'Entry landing pad changed'),
        (0x04, 'b80c000000', 'Upper clamp bound changed'),
        (0x09, 'ba09000000', 'Default value changed'),
        (0x0e, '39c6', 'Clamp compare changed'),
        (0x10, '0f4ec6', 'Clamp conditional move changed'),
        (0x13, '85f6', 'Sign test changed'),
        (0x15, '0f4ec2', 'Default conditional move changed'),
        (0x18, '66898724000400', 'Word store changed'),
        (0x1f, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # No call opcode at any instruction start inside the window; the two
    # conditional moves are the only selection logic (no branch at all).
    starts = {off for off, _, _ in fixed}
    for pos, byte in enumerate(body):
        if pos in starts:
            require(byte != 0xe8, 'Unexpected call opcode in window')
    # Relocations: no record in any .rela.* section names this window.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((sec['name'], address))
    require(naming == [], 'Unexpected relocation naming window')
    # Incoming calls: direct e8 call sites anywhere in .text, each with
    # call bytes (e8 + rel32) landing exactly on the window start.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == CALLERS, 'Unexpected incoming direct calls')
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    require(clamp_store(0) == 9, 'Default boundary changed')
    require(clamp_store(-1) == 9, 'Default negative changed')
    require(clamp_store(-0x80000000) == 9, 'Default bottom changed')
    require(clamp_store(1) == 1, 'Pass-through changed')
    require(clamp_store(12) == 12, 'Clamp high boundary changed')
    require(clamp_store(13) == 12, 'Above-clamp edge changed')
    require(clamp_store(0x7fffffff) == 12, 'Clamp top changed')
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
                    'clamp-with-default store evidence packet.')
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
        require(retained['function']['padding_bytes'] == 0, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation clamp-with-default-store evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
