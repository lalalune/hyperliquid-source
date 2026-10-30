#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 chunk-equality evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window loads one 16-byte chunk, compares it against a 16-byte constant in
.rodata, and returns rdi+0x38 on a full match, else 0. The meaning of the
chunk, of the constant, and of the returned pointer offset is not claimed
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
START, END = 0x14b52b0, 0x14b52d1
PAD_END = 0x14b52e0
BODY = bytes.fromhex(
    'f30f6f06660f74054430d5fe660fd7c8488d573831c081f9ffff0000480f44c2c3')
PAD = b'\xcc' * 15
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('100000008cde0000085f7c002100000000000000')
NEXT_FDE = bytes.fromhex('10000000a0de0000245f7c002100000000000000')
CONSTANT_VA = 0x208300
CONSTANT = bytes.fromhex('f86e515c5a0d0918c20ac95e03583e31')
# One R_X86_64_RELATIVE slot names this window as addend. The file stores 0
# in the .data.rel.ro slot; the loader writes the window address at load time.
SLOTS = [0x566e618]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decide(chunk):
    """Decoded equality rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. The return is 'base+0x38' when
    the 16-byte chunk equals the constant, else 'zero'.
    """
    require(isinstance(chunk, (bytes, bytearray)) and len(chunk) == 16,
            'Chunk must be exactly 16 bytes')
    return 'base+0x38' if bytes(chunk) == CONSTANT else 'zero'


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
    require(body == BODY, 'Chunk-equality instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in [(0xde88, FDE, START, END),
                                    (0xde9c, NEXT_FDE, 0x14b52e0, 0x14b5301)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x14b52b0.
    require(body[0:4] == bytes.fromhex('f30f6f06'), 'Chunk load changed')
    require(body[4:12] == bytes.fromhex('660f74054430d5fe'),
            'Compare opcode/displacement changed')
    require(0x14b52bc + struct.unpack_from('<i', body, 8)[0] == CONSTANT_VA,
            'Compare target changed')
    require(body[12:16] == bytes.fromhex('660fd7c8'), 'Mask move changed')
    require(body[16:20] == bytes.fromhex('488d5738'), 'Base-plus-0x38 changed')
    require(body[20:22] == bytes.fromhex('31c0'), 'Zero return changed')
    require(body[22:28] == bytes.fromhex('81f9ffff0000'),
            'Full-mask compare changed')
    require(body[28:32] == bytes.fromhex('480f44c2'), 'Select changed')
    require(body[32] == 0xc3, 'Return changed')
    # The constant lives in .rodata and equals the retained bytes.
    const_secs = [s for s in secs if s['address'] <= CONSTANT_VA
                  < s['address'] + s['size']]
    require(len(const_secs) == 1 and const_secs[0]['name'] == '.rodata',
            'Constant section changed')
    require(read(CONSTANT_VA, 16) == CONSTANT, 'Constant changed')
    # No calls inside the window: none of the locked instruction starts is a
    # call opcode, and the full locked body contains no e8 call opcode at an
    # instruction boundary (the fixed-offset locks above pin every boundary).
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    # Relocations: exactly one RELATIVE slot names this window; the file
    # stores 0 in the .data.rel.ro slot, applied only at load time.
    relsec = by_name['.rela.dyn']
    require(relsec['size'] % 24 == 0, 'Truncated RELA section')
    rels = {}
    raw = read(relsec['address'], relsec['size'])
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        require(address not in rels, 'Duplicate relocation address')
        rels[address] = (info, addend)
    window_slots = [a for a, (info, addend) in rels.items()
                    if info == 8 and addend == START]
    require(window_slots == SLOTS, 'Relocation slots naming window changed')
    for slot in SLOTS:
        slot_secs = [s for s in secs if s['address'] <= slot
                     < s['address'] + s['size']]
        require(len(slot_secs) == 1 and slot_secs[0]['name'] == '.data.rel.ro',
                'Relocation slot section changed')
        require(struct.unpack_from('<Q', read(slot, 8), 0)[0] == 0,
                'Relocation slot file value changed')
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
    require(decide(CONSTANT) == 'base+0x38', 'Exact-match edge changed')
    changed = bytearray(CONSTANT)
    changed[0] ^= 0x01
    require(decide(changed) == 'zero', 'First-byte-diff edge changed')
    changed = bytearray(CONSTANT)
    changed[15] ^= 0x80
    require(decide(changed) == 'zero', 'Last-byte-diff edge changed')
    require(decide(bytes(16)) == 'zero', 'All-zero edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'relocation_slots': [hex(a) for a in SLOTS],
        'direct_callers': direct,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 chunk-equality '
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
        require(retained['incoming_pattern_scan']['e8_candidates'] == [],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation chunk-equality evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
