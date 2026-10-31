#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 gated byte test packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window is a gated byte test: rdi = base pointer. When the qword field
[rdi+0xb0] is 0 it returns 0 without reading the gate byte; otherwise it
returns 1 exactly when the gate byte [rdi+0xb8] is 0, else 0.
What the fields mean, and what reads the returned byte, is not claimed anywhere.
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
START, END = 0x53d1f90, 0x53d1fab
PAD_END = 0x53d1fb0
BRANCH_TARGET = 0x53d1faa
BODY = bytes.fromhex('f30f1efa31c04883bfb000000000740a80bfb8000000000f94c0c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('100000004c692b0028a143041b000000')
NEXT = bytes.fromhex('1000000060692b0034a1430414000000')
SLOTS = [
    '0x5764f50',
    '0x5778c30',
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse(ptr_is_null, gate):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. Returns 0 when the pointer field is
    null, else 1 exactly when the gate byte is 0.
    """
    if ptr_is_null:
        return 0
    return 1 if gate == 0 else 0


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
    require(body == BODY, 'Gated-byte-test instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    for offset, raw, start, end in [
            (0x2b6948, FDE, START, END),
            (0x2b695c, NEXT, PAD_END, 0x53d1fc4)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: five int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 5, 'Padding changed')
    require(PAD_END == 0x53d1fb0, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x53d1f90.
    fixed = [
        (0, 'f30f1efa', 'Entry endbr64 changed'),
        (4, '31c0', 'Result zeroing changed'),
        (6, '4883bfb000000000', 'Pointer field compare changed'),
        (14, '740a', 'Null branch changed'),
        (16, '80bfb800000000', 'Gate byte compare changed'),
        (23, '0f94c0', 'Sete changed'),
        (26, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # The branch lands exactly on the ret: je at START+14 is 2 bytes, so
    # target = START+14+2+disp.
    disp_null = struct.unpack_from('<b', body, 15)[0]
    require(START + 14 + 2 + disp_null == BRANCH_TARGET, 'Null branch target changed')
    # No call opcode inside the window.
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    # Relocations: exactly the two R_X86_64_RELATIVE slots naming this window.
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
    require(parse(True, 0) == 0, 'Null-pointer edge changed')
    require(parse(True, 1) == 0, 'Null-pointer gate-nonzero edge changed')
    require(parse(False, 0) == 1, 'Gate-zero edge changed')
    require(parse(False, 1) == 0, 'Gate-nonzero edge changed')
    require(parse(False, 0xff) == 0, 'Gate-0xff edge changed')
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
                    'gated byte test evidence packet.')
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
        print('Foundation gated-byte-test evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
