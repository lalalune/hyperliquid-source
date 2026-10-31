#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 multi-path pointer-arithmetic
triple packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window returns a (rax, rdx) pair selected by two byte tests:
if byte [rdi+0x240] == 1, the pair is the stored ([rdi+0x308], [rdi+0x310]);
otherwise rax is a computed cursor ([rdi+0xa0] + adjusted span) and rdx is
[rdi+0x300]. What the fields mean, and what consumes the pair, is not claimed
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
START, END = 0x50fa260, 0x50fa2b2
PAD_END = 0x50fa2c0
BODY = bytes.fromhex(
    'f30f1efa80bf4002000001743380bfd800000000488b97a8000000488b87a0000000'
    '7414488b8f000300004829ca4801d04889cac30f1f004883ea08ebe66690488b8f10'
    '030000488b87080300004889cac3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c0708')
FDE = bytes.fromhex('100000002c802900180d180452000000')
NEXT = bytes.fromhex(
    '4c00000040802900640d18049d01000000460e108e02480e188d03420e208c04410e28'
    '8605480e30830602f30a0e28410e20420e18420e10420e08450b02540a0e28410e2042'
    '0e18420e10420e08450b')
SLOTS = ['0x575ad00']
MASK = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def triple(fields):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. ``fields`` maps a field offset to its
    value; returns (rax, rdx) with 64-bit wrapping, matching the hardware.
    """
    if fields[0x240] == 1:
        return fields[0x308], fields[0x310]
    span = fields[0xa8]
    if fields[0xd8] == 0:
        span = (span - 8) & MASK
    cursor = (fields[0xa0] + span - fields[0x300]) & MASK
    return cursor, fields[0x300]


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
    require(body == BODY, 'Multi-path pointer-arithmetic window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    for offset, raw, start, end in [
            (0x298028, FDE, START, END),
            (0x29803c, NEXT, PAD_END, 0x50fa45d)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: fourteen int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 14, 'Padding changed')
    require(PAD_END == 0x50fa2c0, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x50fa260.
    fixed = [
        (0, 'f30f1efa', 'Entry endbr64 changed'),
        (4, '80bf4002000001', 'Flag byte compare changed'),
        (11, '7433', 'Stored-pair branch changed'),
        (13, '80bfd800000000', 'Adjust byte compare changed'),
        (20, '488b97a8000000', 'Span load changed'),
        (27, '488b87a0000000', 'Base load changed'),
        (34, '7414', 'Adjust branch changed'),
        (36, '488b8f00030000', 'Limit load changed'),
        (43, '4829ca', 'Limit subtract changed'),
        (46, '4801d0', 'Cursor add changed'),
        (49, '4889ca', 'Limit return move changed'),
        (52, 'c3', 'Computed-path return changed'),
        (53, '0f1f00', 'Intra-body nopl changed'),
        (56, '4883ea08', 'Span adjust changed'),
        (60, 'ebe6', 'Shared-tail join changed'),
        (62, '6690', 'Intra-body xchg changed'),
        (64, '488b8f10030000', 'Stored limit load changed'),
        (71, '488b8708030000', 'Stored base load changed'),
        (78, '4889ca', 'Stored return move changed'),
        (81, 'c3', 'Stored-path return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # Branch targets, decoded from the locked displacements.
    require(0x50fa26b + 2 + 0x33 == 0x50fa2a0, 'Stored-pair branch target changed')
    require(0x50fa282 + 2 + 0x14 == 0x50fa298, 'Adjust branch target changed')
    require(0x50fa29c + 2 - 26 == 0x50fa284, 'Shared-tail join target changed')
    # No call opcode inside the window; the two je branches and the one jmp
    # join are the only control transfers (no loop: the join target falls
    # through to ret with no cycle back).
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    # Relocations: exactly the one R_X86_64_RELATIVE slot naming this window.
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
    stored = triple({0x240: 1, 0x308: 0x5000, 0x310: 0x6000,
                     0xa0: 0, 0xa8: 0, 0xd8: 0, 0x300: 0})
    require(stored == (0x5000, 0x6000), 'Stored-pair path changed')
    computed = triple({0x240: 0, 0xa0: 0x1000, 0xa8: 0x100, 0xd8: 0,
                       0x300: 0x40, 0x308: 0, 0x310: 0})
    require(computed == (0x1000 + 0x100 - 8 - 0x40, 0x40),
            'Computed path with adjust changed')
    no_adjust = triple({0x240: 0, 0xa0: 0x1000, 0xa8: 0x100, 0xd8: 5,
                        0x300: 0x40, 0x308: 0, 0x310: 0})
    require(no_adjust == (0x1000 + 0x100 - 0x40, 0x40),
            'Computed path without adjust changed')
    flag_other = triple({0x240: 2, 0xa0: 0x1000, 0xa8: 0x100, 0xd8: 0,
                         0x300: 0x40, 0x308: 0x5000, 0x310: 0x6000})
    require(flag_other == (0x1000 + 0x100 - 8 - 0x40, 0x40),
            'Non-one flag must take the computed path')
    wrapped = triple({0x240: 0, 0xa0: 0x10, 0xa8: 0x8, 0xd8: 0,
                      0x300: 0x40, 0x308: 0, 0x310: 0})
    require(wrapped == ((0x10 + 0 - 0x40) & MASK, 0x40),
            'Wrapping cursor edge changed')
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
                    'multi-path pointer-arithmetic triple evidence packet.')
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
        print('Foundation multi-path-pointer-arithmetic-triple evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
