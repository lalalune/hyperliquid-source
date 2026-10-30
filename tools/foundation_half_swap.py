#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 lane-reversal evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window writes 32 output bytes: each of the eight 32-bit input lanes is
byte-reversed in place. The meaning of the input and output bytes is not
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
START, END = 0x56544a0, 0x56544f0
BODY = bytes.fromhex(
    'f30f1efa4c8b064c8b4e084c8b5610490fc84c8b5e18490fc944894704490fca'
    '44894f0c490fcb4489571449c1e82044895f1c49c1e92044890749c1ea204489'
    '4f0849c1eb204489571044895f18f3c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000084af2d00008069045000000000000000')
NEXT_FDE = bytes.fromhex('1000000098af2d003c8069041900000000000000')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def build(inp):
    """Decoded lane-reversal rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. The return is the 32 output
    bytes. Each 32-bit lane is byte-reversed in place; lanes do not move.
    """
    require(isinstance(inp, (bytes, bytearray)) and len(inp) == 32,
            'Input must be exactly 32 bytes')
    out = bytearray(32)
    for w in range(4):
        out[w * 8:w * 8 + 4] = inp[w * 8:w * 8 + 4][::-1]
        out[w * 8 + 4:w * 8 + 8] = inp[w * 8 + 4:w * 8 + 8][::-1]
    return bytes(out)


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
    require(body == BODY, 'Lane-reversal instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in [(0x2daf80, FDE, START, END),
                                    (0x2daf94, NEXT_FDE, 0x56544f0, 0x5654509)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Zero padding: the next FDE starts exactly at the FDE end.
    require(END == 0x56544f0, 'FDE end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x56544a0.
    require(body[0:4] == bytes.fromhex('f30f1efa'), 'Entry changed')
    require(body[4:7] == bytes.fromhex('4c8b06'), 'Word 0 load changed')
    require(body[7:11] == bytes.fromhex('4c8b4e08'), 'Word 1 load changed')
    require(body[11:15] == bytes.fromhex('4c8b5610'), 'Word 2 load changed')
    require(body[15:18] == bytes.fromhex('490fc8'), 'Word 0 bswap changed')
    require(body[18:22] == bytes.fromhex('4c8b5e18'), 'Word 3 load changed')
    require(body[22:25] == bytes.fromhex('490fc9'), 'Word 1 bswap changed')
    require(body[25:29] == bytes.fromhex('44894704'), 'Word 0 low store changed')
    require(body[29:32] == bytes.fromhex('490fca'), 'Word 2 bswap changed')
    require(body[32:36] == bytes.fromhex('44894f0c'), 'Word 1 low store changed')
    require(body[36:39] == bytes.fromhex('490fcb'), 'Word 3 bswap changed')
    require(body[39:43] == bytes.fromhex('44895714'), 'Word 2 low store changed')
    require(body[43:47] == bytes.fromhex('49c1e820'), 'Word 0 shift changed')
    require(body[47:51] == bytes.fromhex('44895f1c'), 'Word 3 low store changed')
    require(body[51:55] == bytes.fromhex('49c1e920'), 'Word 1 shift changed')
    require(body[55:58] == bytes.fromhex('448907'), 'Word 0 high store changed')
    require(body[58:62] == bytes.fromhex('49c1ea20'), 'Word 2 shift changed')
    require(body[62:66] == bytes.fromhex('44894f08'), 'Word 1 high store changed')
    require(body[66:70] == bytes.fromhex('49c1eb20'), 'Word 3 shift changed')
    require(body[70:74] == bytes.fromhex('44895710'), 'Word 2 high store changed')
    require(body[74:78] == bytes.fromhex('44895f18'), 'Word 3 high store changed')
    require(body[78:80] == bytes.fromhex('f3c3'), 'Return changed')
    # No calls inside the window: none of the locked instruction starts is a
    # call opcode. (A blanket byte scan cannot be used here: 0xe8 legitimately
    # appears as the ModRM byte of the four shr instructions, e.g. 49 c1 e8 20;
    # the fixed-offset locks above pin every instruction boundary, so checking
    # the start bytes is exact.)
    starts = (0, 4, 7, 11, 15, 18, 22, 25, 29, 32, 36, 39, 43, 47, 51, 55, 58,
              62, 66, 70, 74, 78)
    require(all(body[i] != 0xe8 for i in starts),
            'Unexpected call opcode in window')
    # Relocations: no record of any type names this window as addend.
    relsec = by_name['.rela.dyn']
    require(relsec['size'] % 24 == 0, 'Truncated RELA section')
    raw = read(relsec['address'], relsec['size'])
    naming = []
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        if addend == START:
            naming.append(address)
    require(naming == [], 'Relocation naming window changed')
    # Incoming calls: no direct e8 call anywhere in .text.
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
    # Decoded-rule edges (restatement of the retained bytes, not execution).
    require(build(b'\x00' * 32) == b'\x00' * 32,
            'All-zero edge changed')
    require(build(bytes(range(1, 33))) ==
            bytes.fromhex('04030201080706050c0b0a09100f0e0d1413121118171615'
                          '1c1b1a19201f1e1d'),
            'Sequential edge changed')
    require(build(b'\xff' * 32) == b'\xff' * 32,
            'All-0xff edge changed')
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
        description='Verify a digest-bound, static node #94 lane-reversal '
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
        require(retained['function']['padding_bytes'] == 0, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] == [],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation half-swap evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
