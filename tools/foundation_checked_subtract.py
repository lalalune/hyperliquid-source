#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 checked-subtract evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window subtracts a 256-bit subtrahend from a 256-bit minuend in place and
reports success only when no borrow escapes the top word; on success it also
copies the 32-byte difference to out+8 and stores 1 at out, and on failure it
stores 0 at out and leaves out+8 untouched. The minuend operand is modified
in place regardless of success. The meaning of the 256-bit values is not
claimed anywhere.
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
START, END = 0x2760a10, 0x2760a67
PAD_END = 0x2760a70
BODY = bytes.fromhex(
    '488b06482902488b460848194208488b4610481942104c8b42180f92c0488b7618'
    '4d89c14929f104ff4983d9000f92c131c04c894a184939f0721884c975140f1002'
    '0f104a100f114f180f114708b801000000488907c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000d40c0a0020e89d015700000000000000')
NEXT_FDE = bytes.fromhex(
    '50000000d835130068f86601a6100000048bf892ff410e10420e18420e20420e284'
    '20e30410e38470ed00e83078c068d058e048f038602038d0e0e38410e30420e28420'
    'e20420e18420e10410e08410ed00e0000')
CALLERS = [0x2760924, 0x276095c, 0x2760998]
MASK = (1 << 256) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def build(minuend, subtrahend):
    """Decoded subtract rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. Inputs are 32-byte little-endian
    values. The return is (flag, out_bytes_or_None, minuend_after_bytes):
    the minuend operand is rewritten with the raw difference in both cases,
    exactly as the window stores word 3 before its borrow checks.
    """
    require(isinstance(minuend, (bytes, bytearray)) and len(minuend) == 32,
            'Minuend must be exactly 32 bytes')
    require(isinstance(subtrahend, (bytes, bytearray)) and len(subtrahend) == 32,
            'Subtrahend must be exactly 32 bytes')
    m = int.from_bytes(minuend, 'little')
    s = int.from_bytes(subtrahend, 'little')
    diff = (m - s) & MASK
    borrow = m < s
    flag = 0 if borrow else 1
    out = diff.to_bytes(32, 'little') if flag == 1 else None
    return flag, out, diff.to_bytes(32, 'little')


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
    require(body == BODY, 'Checked-subtract instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in [(0xa0cd0, FDE, START, END),
                                    (0x40fce8, NEXT_FDE, PAD_END, 0x2761b16)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: nine int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 9, 'Padding changed')
    require(PAD_END == 0x2760a70, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x2760a10.
    require(body[0:3] == bytes.fromhex('488b06'), 'First load changed')
    require(body[3:6] == bytes.fromhex('482902'), 'Word-0 subtract changed')
    require(body[6:10] == bytes.fromhex('488b4608'), 'Word-1 load changed')
    require(body[10:14] == bytes.fromhex('48194208'), 'Word-1 borrow changed')
    require(body[14:18] == bytes.fromhex('488b4610'), 'Word-2 load changed')
    require(body[18:22] == bytes.fromhex('48194210'), 'Word-2 borrow changed')
    require(body[22:26] == bytes.fromhex('4c8b4218'), 'Top-word load changed')
    require(body[26:29] == bytes.fromhex('0f92c0'), 'Borrow capture changed')
    require(body[29:33] == bytes.fromhex('488b7618'), 'Top subtrahend load changed')
    require(body[33:36] == bytes.fromhex('4d89c1'), 'Top-word copy changed')
    require(body[36:39] == bytes.fromhex('4929f1'), 'Top-word subtract changed')
    require(body[39:41] == bytes.fromhex('04ff'), 'Borrow-in trick changed')
    require(body[41:45] == bytes.fromhex('4983d900'), 'Borrow-in apply changed')
    require(body[45:48] == bytes.fromhex('0f92c1'), 'Borrow-out capture changed')
    require(body[48:50] == bytes.fromhex('31c0'), 'Default flag changed')
    require(body[50:54] == bytes.fromhex('4c894a18'), 'Top-word store changed')
    require(body[54:57] == bytes.fromhex('4939f0'), 'Top-word compare changed')
    require(body[57:59] == bytes.fromhex('7218'), 'Below branch changed')
    require(body[59:61] == bytes.fromhex('84c9'), 'Borrow-out test changed')
    require(body[61:63] == bytes.fromhex('7514'), 'Borrow branch changed')
    require(body[63:66] == bytes.fromhex('0f1002'), 'Result load changed')
    require(body[66:70] == bytes.fromhex('0f104a10'), 'High result load changed')
    require(body[70:74] == bytes.fromhex('0f114f18'), 'High result store changed')
    require(body[74:78] == bytes.fromhex('0f114708'), 'Low result store changed')
    require(body[78:83] == bytes.fromhex('b801000000'), 'Success flag changed')
    require(body[83:86] == bytes.fromhex('488907'), 'Flag store changed')
    require(body[86] == 0xc3, 'Return changed')
    # Branch targets: both failure branches land on the flag store at +79.
    require(0x2760a10 + 57 + 2 + 0x18 == 0x2760a10 + 83,
            'Below branch target changed')
    require(0x2760a10 + 61 + 2 + 0x14 == 0x2760a10 + 83,
            'Borrow branch target changed')
    # No calls inside the window: the locked body contains no e8 byte at all.
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    # Relocations: no record of any type in .rela.dyn names this window.
    relsec = by_name['.rela.dyn']
    require(relsec['size'] % 24 == 0, 'Truncated RELA section')
    raw = read(relsec['address'], relsec['size'])
    naming = []
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        if addend == START:
            naming.append(address)
    require(naming == [], 'Relocation naming window changed')
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
    require(direct == CALLERS, 'Incoming direct calls changed')
    # Decoded-rule edges (restatement of the retained bytes, not execution).
    require(build(b'\x00' * 32, b'\x00' * 32) ==
            (1, b'\x00' * 32, b'\x00' * 32), 'Zero-minus-zero edge changed')
    require(build(b'\x00' * 32, b'\x01' + b'\x00' * 31) ==
            (0, None, b'\xff' * 32), 'Borrow edge changed')
    require(build(b'\xff' * 32, b'\x01' + b'\x00' * 31) ==
            (1, b'\xfe' + b'\xff' * 31, b'\xfe' + b'\xff' * 31),
            'Max-minus-one edge changed')
    # Low words borrow but the top word covers it: success, not failure.
    m = (1 << 192).to_bytes(32, 'little')
    s = (1).to_bytes(32, 'little')
    require(build(m, s) ==
            (1, ((1 << 192) - 1).to_bytes(32, 'little'),
             ((1 << 192) - 1).to_bytes(32, 'little')),
            'Covered-borrow edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'relocation_slots': [],
        'direct_callers': direct,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 checked-subtract '
                    'evidence packet.')
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
        require(retained['function']['padding_bytes'] == 9, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation checked-subtract evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
