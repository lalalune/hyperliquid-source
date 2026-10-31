#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 chain all-zero predicate packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window is a chain all-zero predicate: p = [rdi]; it returns 1 in eax
exactly when the flag byte [p+0x70] is clear and every node on the chain
starting at [p+0x48], linked by [node], has [node+0x10] == 0, else 0.
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
START, END = 0x51a5d60, 0x51a5da8
PAD_END = 0x51a5db0
CALL_SITE = 0x51fd9e5
BODY = bytes.fromhex(
    'f30f1efa488b070fb6507084d27529488b40484885c07510eb26660f1f440000'
    '488b004885c07418488378100074f189d0c3660f1f44000031d289d0c30f1f00'
    'ba0100000089d0c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000034f42900105422044800000000000000')
NEXT = bytes.fromhex(
    '5c00000048f429004c5422045901000000460e108d02440e188c03410e2086044'
    '10e288305440e3002a70a0e28440e20410e18420e10420e08480b02430a0e2841'
    '0e20440e18420e10420e08440b610a0e28410e20440e18420e10420e08460b')
CALLER_CIE = bytes.fromhex(
    '1c00000000000000017a504c5200017810079b3d5848041b1b0c070890010000')
CALLER_FDE = bytes.fromhex(
    '5000000088a901004c10ee03dd110000042b018cff460e108f02420e188e0342'
    '0e208d04420e288c05410e308606410e388307470ec00403190b0a0e38410e30'
    '410e28420e20420e18420e10420e08480b000000')
CALL_BYTES = bytes.fromhex('e87683faff')
CALL_SETUP = bytes.fromhex('488b4010488b38')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse(flag, fields):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. Returns 1 exactly when the flag byte
    is clear and every visited chain node's +0x10 field is zero (an empty
    chain counts as all-zero).
    """
    if flag != 0:
        return 0
    return 1 if all(f == 0 for f in fields) else 0


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
    require(body == BODY, 'Chain-all-zero-predicate instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    for offset, raw, start, end in [
            (0x29f430, FDE, START, END),
            (0x29f444, NEXT, PAD_END, 0x51a5f09),
            (0x6205d0, CALLER_CIE, None, None),
            (0x63af54, CALLER_FDE, 0x51fd4c0, 0x51fe69d)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE/CIE record changed')
        if start is not None:
            pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
            extent = struct.unpack_from('<I', record, 12)[0]
            require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: eight int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 8, 'Padding changed')
    require(PAD_END == 0x51a5db0, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x51a5d60.
    fixed = [
        (0x00, 'f30f1efa', 'Entry endbr64 changed'),
        (0x04, '488b07', 'Struct hop changed'),
        (0x07, '0fb65070', 'Flag byte load changed'),
        (0x0b, '84d2', 'Flag test changed'),
        (0x0d, '7529', 'Flag branch changed'),
        (0x0f, '488b4048', 'Chain head load changed'),
        (0x13, '4885c0', 'Chain head test changed'),
        (0x16, '7510', 'Chain head branch changed'),
        (0x18, 'eb26', 'Empty chain jump changed'),
        (0x1a, '660f1f440000', 'Loop alignment nop changed'),
        (0x20, '488b00', 'Chain link load changed'),
        (0x23, '4885c0', 'Chain link test changed'),
        (0x26, '7418', 'Chain end branch changed'),
        (0x28, '4883781000', 'Node field compare changed'),
        (0x2d, '74f1', 'Loop back branch changed'),
        (0x2f, '89d0', 'Zero return move changed'),
        (0x31, 'c3', 'Zero return changed'),
        (0x32, '660f1f440000', 'Flag path alignment nop changed'),
        (0x38, '31d2', 'Flag path zero changed'),
        (0x3a, '89d0', 'Flag path return move changed'),
        (0x3c, 'c3', 'Flag path return changed'),
        (0x3d, '0f1f00', 'One path alignment nop changed'),
        (0x40, 'ba01000000', 'One return constant changed'),
        (0x45, '89d0', 'One return move changed'),
        (0x47, 'c3', 'One return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # Branch targets, decoded from the retained displacements.
    require(0x0f + 0x29 == 0x38, 'Flag branch target changed')
    require(0x18 + 0x10 == 0x28, 'Chain head branch target changed')
    require(0x1a + 0x26 == 0x40, 'Empty chain jump target changed')
    require(0x28 + 0x18 == 0x40, 'Chain end branch target changed')
    require(0x2f - 0x0f == 0x20, 'Loop back branch target changed')
    # No call opcode inside the window.
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    # The single caller: call bytes and the two loads immediately before it.
    require(read(CALL_SITE, len(CALL_BYTES)) == CALL_BYTES,
            'Caller call bytes changed')
    require(read(CALL_SITE - 7, len(CALL_SETUP)) == CALL_SETUP,
            'Caller setup changed')
    # Relocations: no record of any type names this window as addend.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((sec['name'], address))
    require(naming == [], 'Unexpected naming relocation')
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
    require(direct == [CALL_SITE], 'Incoming direct calls changed')
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    require(parse(0, []) == 1, 'Empty chain edge changed')
    require(parse(0, [0]) == 1, 'Single zero node edge changed')
    require(parse(0, [0, 0, 0]) == 1, 'All zero chain edge changed')
    require(parse(0, [1]) == 0, 'Single nonzero node edge changed')
    require(parse(0, [0, 5, 0]) == 0, 'Middle nonzero node edge changed')
    require(parse(0, [0, 0, 0xffffffffffffffff]) == 0,
            'Last nonzero node edge changed')
    require(parse(1, []) == 0, 'Flag set empty chain edge changed')
    require(parse(0x80, [0, 0]) == 0, 'Flag nonzero all zero edge changed')
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
                    'chain all-zero predicate evidence packet.')
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
        print('Foundation chain-all-zero-predicate evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
