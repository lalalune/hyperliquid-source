#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 conditional 16-byte restore packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window selects a 16-byte block by a null test on a leading qword, saves
and zeroes the block, overwrites one neighboring qword from a two-hop load,
then conditionally restores the saved block (first qword only, all 16 bytes,
or nothing) based on a byte at block offset +0x40, and always stores the
byte 5 at the pointer the window was entered with. What the block, the
fields, and the restored values mean, and what consumes them, is not claimed
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
START, END = 0x4e6cf10, 0x4e6cf72
PAD_END = 0x4e6cf80
BODY = bytes.fromhex(
    '4889f84c8b82d80000004531c948833900410f94c141c1e104420fb67409404a8d14'
    '094883c230420f104409304a8b7c09304d8b80380200004e894409280f57c9420f11'
    '4c09308d4ef083f906730748893ac60005c383fe0477f70f1102c60005c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c0708')
FDE = bytes.fromhex('10000000c08827003431f1036200000000000000')
NEXT = bytes.fromhex(
    '1c000000d48827009031f1035400000000410e10440e608302024d0e10410e08')
SLOT = 0x574bcf8
MASK = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def restore_path(byte):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. The first test is (byte - 0x10) as an
    unsigned 32-bit value compared against 7, so bytes 0x10..0x16 take the
    qword-restore path; bytes below 0x10 wrap to huge values and fall to
    the second test, where bytes <= 4 take the full 16-byte restore and
    bytes 5..0x0f restore nothing; bytes above 0x16 also reach the second
    test and, being above 4, restore nothing.
    """
    if ((byte - 0x10) & 0xffffffff) < 7:
        return 'qword'
    if byte <= 4:
        return 'full'
    return 'none'


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
    require(body == BODY, 'Conditional 16-byte restore window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    for offset, raw, start, end in [
            (0x2788bc, FDE, START, END),
            (0x2788d0, NEXT, PAD_END, 0x4e6cfd4)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: fourteen int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 14, 'Padding changed')
    require(PAD_END == 0x4e6cf80, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x4e6cf10.
    fixed = [
        (0x00, '4889f8', 'Entry pointer save changed'),
        (0x03, '4c8b82d8000000', 'Two-hop base load changed'),
        (0x0a, '4531c9', 'Offset selector zeroing changed'),
        (0x0d, '48833900', 'Leading qword null test changed'),
        (0x11, '410f94c1', 'Null-test set changed'),
        (0x15, '41c1e104', 'Offset shift changed'),
        (0x19, '420fb6740940', 'Gate byte load changed'),
        (0x1f, '4a8d1409', 'Block base computation changed'),
        (0x23, '4883c230', 'Block address adjustment changed'),
        (0x27, '420f10440930', 'Block save changed'),
        (0x2d, '4a8b7c0930', 'First qword save changed'),
        (0x32, '4d8b8038020000', 'Two-hop value load changed'),
        (0x39, '4e89440928', 'Neighbor qword store changed'),
        (0x3e, '0f57c9', 'Zero vector preparation changed'),
        (0x41, '420f114c0930', 'Block zeroing store changed'),
        (0x47, '8d4ef0', 'Gate byte minus sixteen changed'),
        (0x4a, '83f906', 'Qword-path threshold compare changed'),
        (0x4d, '7307', 'Qword-path branch changed'),
        (0x4f, '48893a', 'Qword restore store changed'),
        (0x52, 'c60005', 'First byte-five store changed'),
        (0x55, 'c3', 'Qword-path return changed'),
        (0x56, '83fe04', 'Full-path threshold compare changed'),
        (0x59, '77f7', 'Full-path branch changed'),
        (0x5b, '0f1102', 'Full restore store changed'),
        (0x5e, 'c60005', 'Second byte-five store changed'),
        (0x61, 'c3', 'Full-path return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # Branch targets, decoded from the locked displacements.
    require(0x4e6cf5f + 0x07 == 0x4e6cf66, 'Qword-path branch target changed')
    require(0x4e6cf6b - 9 == 0x4e6cf62, 'Full-path branch target changed')
    # No call opcode at any instruction start inside the window; the two
    # conditional branches are the only control transfers (no loop: every
    # path falls through to ret).
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
    require(restore_path(0x10) == 'qword', 'Qword low boundary changed')
    require(restore_path(0x16) == 'qword', 'Qword high boundary changed')
    require(restore_path(0x17) == 'none', 'Above-qword edge changed')
    require(restore_path(0x0f) == 'none', 'Below-qword edge changed')
    require(restore_path(0x00) == 'full', 'Full low boundary changed')
    require(restore_path(0x04) == 'full', 'Full high boundary changed')
    require(restore_path(0x05) == 'none', 'Above-full edge changed')
    require(restore_path(0xff) == 'none', 'Top byte edge changed')
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
                    'conditional 16-byte restore evidence packet.')
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
        print('Foundation conditional-sixteen-byte-restore evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
