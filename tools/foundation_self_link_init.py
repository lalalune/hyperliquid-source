#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 self-link init packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window is a self-link init: rdi = base pointer. It zeroes the qword field
[rdi+8], stores rdi+0x10 into [rdi] (so the head pointer points at the node's
own +0x10 slot), zeroes the byte at [rdi+0x10], and returns rdi.
What the fields mean, and what consumes the initialized node, is not claimed
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
START, END = 0x4f91ee0, 0x4f91efb
PAD_END = 0x4f91f00
BODY = bytes.fromhex('f30f1efa488d571048c74708000000004889f8488917c6471000c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000080982800447102041b000000')
NEXT = bytes.fromhex('2000000094982800507102040c010000')
SLOTS = [
    '0x575c6d8', '0x575c990', '0x575cef8', '0x575d1b0', '0x575d550',
    '0x575d630', '0x575da30', '0x575dc28', '0x575de20', '0x575e098',
    '0x575e4b0', '0x575e8c0', '0x575eac0', '0x575ebd0', '0x575ef00',
    '0x575f1c8', '0x575f4c8', '0x575ffb8', '0x5760270', '0x5760628',
    '0x5760e50', '0x5761110', '0x57613d0', '0x5761628', '0x57619a8',
    '0x5761d58', '0x5761dd8', '0x5761f28', '0x5762050', '0x5762258',
    '0x57622d8', '0x57627e0', '0x5763710', '0x5763a80', '0x5763b40',
    '0x5763c00', '0x5763cc0', '0x5763d80', '0x5763e40', '0x5763f00',
    '0x5764160', '0x5764238', '0x5765c58', '0x5765d78', '0x5765e98',
    '0x5766208', '0x57662d8', '0x57663a8', '0x57665d0', '0x5766a40',
    '0x5766e08', '0x5767018', '0x5767340', '0x5767448', '0x5767520',
    '0x5767610', '0x5767700', '0x57677f8', '0x57678e8', '0x57679e0',
    '0x5767ca8', '0x5768000', '0x5768178', '0x5768250', '0x5768338',
    '0x5777b20',
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def init(base):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. Returns (stores, return_value) where
    stores maps a field offset to the stored value.
    """
    stores = {0: base + 0x10, 8: 0, 0x10: 0}
    return stores, base


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
    require(body == BODY, 'Self-link-init instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    for offset, raw, start, end in [
            (0x28987c, FDE, START, END),
            (0x289890, NEXT, PAD_END, 0x4f9200c)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: five int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 5, 'Padding changed')
    require(PAD_END == 0x4f91f00, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x4f91ee0.
    fixed = [
        (0, 'f30f1efa', 'Entry endbr64 changed'),
        (4, '488d5710', 'Self-pointer lea changed'),
        (8, '48c7470800000000', 'Link qword zeroing changed'),
        (16, '4889f8', 'Return register move changed'),
        (19, '488917', 'Head pointer store changed'),
        (22, 'c6471000', 'Link byte zeroing changed'),
        (26, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # No call opcode and no branch opcode inside the window.
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    require(all(b not in body for b in
                [b'\x74', b'\x75', b'\xeb', b'\xe9']),
            'Unexpected branch opcode in window')
    # Relocations: exactly the 66 R_X86_64_RELATIVE slots naming this window.
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
    stores, ret = init(0x1000)
    require(stores == {0: 0x1010, 8: 0, 0x10: 0}, 'Init stores changed')
    require(ret == 0x1000, 'Return value changed')
    stores2, ret2 = init(0x7f0000000000)
    require(stores2[0] == 0x7f0000000010, 'Self-pointer edge changed')
    require(ret2 == 0x7f0000000000, 'High-address return edge changed')
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
                    'self-link init evidence packet.')
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
        print('Foundation self-link-init evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
