#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 tagged-copy evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window writes a 40-byte value: an 8-byte tag at out+0 and the 32 input
bytes at out+8, and returns the out pointer. The tag's meaning and the copied
bytes' meaning are not claimed anywhere.
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
START, END = 0x22155a0, 0x22155c0
BODY = bytes.fromhex(
    '4889f80f10060f104e100f114f180f11470848b9140000000000008048890fc3')
TAG = 0x8000000000000014
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000d0730500b4cc4d012000000000000000')
NEXT_FDE = bytes.fromhex(
    '38000000e4730500c0cc4d019902000000420e10420e18420e20410e28440e408'
    '3058c048e038f020374020e28410e20420e18420e10420e08410e40')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def build(inp):
    """Decoded copy rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. The return is the 40 output
    bytes.
    """
    require(isinstance(inp, (bytes, bytearray)) and len(inp) == 32,
            'Input must be exactly 32 bytes')
    return struct.pack('<Q', TAG) + bytes(inp)


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
    require(body == BODY, 'Tagged-copy instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in [(0x573cc, FDE, START, END),
                                    (0x573e0, NEXT_FDE, 0x22155c0, 0x2215859)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Zero padding: the next FDE starts exactly at the FDE end.
    require(END == 0x22155c0, 'FDE end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x22155a0.
    require(body[0:3] == bytes.fromhex('4889f8'), 'Out-pointer return changed')
    require(body[3:6] == bytes.fromhex('0f1006'), 'First load changed')
    require(body[6:10] == bytes.fromhex('0f104e10'), 'Second load changed')
    require(body[10:14] == bytes.fromhex('0f114f18'), 'Second store changed')
    require(body[14:18] == bytes.fromhex('0f114708'), 'First store changed')
    require(body[18:28] == bytes.fromhex('48b91400000000000080'),
            'Tag load changed')
    require(struct.unpack_from('<Q', body, 20)[0] == TAG,
            'Tag constant changed')
    require(body[28:31] == bytes.fromhex('48890f'), 'Tag store changed')
    require(body[31] == 0xc3, 'Return changed')
    # No calls inside the window: none of the locked instruction starts is a
    # call opcode, and the full locked body contains no e8 call opcode at an
    # instruction boundary (the fixed-offset locks above pin every boundary).
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
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
    require(build(b'\x00' * 32) == struct.pack('<Q', TAG) + b'\x00' * 32,
            'All-zero edge changed')
    require(build(bytes(range(32))) == struct.pack('<Q', TAG) + bytes(range(32)),
            'Sequential edge changed')
    require(build(b'\xff' * 32) == struct.pack('<Q', TAG) + b'\xff' * 32,
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
        description='Verify a digest-bound, static node #94 tagged-copy '
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
        print('Foundation tagged-copy evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
