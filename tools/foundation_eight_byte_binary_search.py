#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 eight-byte binary search packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window walks a table of 8-byte entries with a sar midpoint loop and
returns an index: the first entry whose key is >= the search key (unsigned),
the insertion point when every probed key is smaller, count - 1 when the key
is >= the struct limit, and 0 for an empty span on the search path. What the
table, the limit, and the callers mean is not claimed anywhere.
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
START, END = 0x52ca970, 0x52ca9e3
PAD_END = 0x52ca9f0
BODY = bytes.fromhex(
    'f30f1efa4c8b07488b4f084c29c14889c848c1f8034889c2483b7718720a4883e801c3'
    '0f1f4400004885c97e434c89c04889d148d1f9488d3cc848393773214829ca488d4708'
    '4883ea014885d27fe14c29c048c1f803c3660f1f8400000000004885c974ea4889ca'
    'ebc6660f1f44000031c0c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000f0c12a0064d233047300000000000000')
NEXT = bytes.fromhex('1000000004c22a00d0d233045c00000000000000')
CALLER_FDES = [
    (0x2ac250, bytes.fromhex(
        '2800000054c22a0090d333048300000000450e1086024b0e188303470e2002500a0e'
        '18410e10410e08470b00'),
     0x52cab00, 0x52cab83),
]
CALLERS = [0x52cab17]
MASK = 0xffffffffffffffff


def require(condition, message):
    if not condition:
        raise ValueError(message)


def binary_search(entries, limit, key):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. `entries` is the table of unsigned
    64-bit keys in address order, `limit` is the struct's [rdi+0x18] bound,
    `key` is rsi. All comparisons are unsigned; all arithmetic wraps at
    64 bits. Returns the 64-bit rax result.
    """
    entries = [e & MASK for e in entries]
    limit &= MASK
    key &= MASK
    count = len(entries)
    if key >= limit:
        return (count - 1) & MASK
    span = count * 8
    if span <= 0:
        return 0
    lo = 0
    while True:
        mid = count >> 1
        probe = lo + mid
        if entries[probe] >= key:
            if mid == 0:
                return probe
            count = mid
        else:
            count = count - mid - 1
            lo = probe + 1
            if count <= 0:
                return lo


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
    require(body == BODY, 'Eight-byte binary search window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    check_fde(0x2ac1ec, FDE, START, END)
    check_fde(0x2ac200, NEXT, PAD_END, 0x52caa4c)
    for offset, raw, start, end in CALLER_FDES:
        check_fde(offset, raw, start, end)
    # Padding: thirteen int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 13, 'FDE padding changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x52ca970.
    fixed = [
        (0x00, 'f30f1efa', 'Entry endbr64 changed'),
        (0x04, '4c8b07', 'Table lo load changed'),
        (0x07, '488b4f08', 'Table hi load changed'),
        (0x0b, '4c29c1', 'Span subtract changed'),
        (0x0e, '4889c8', 'Span copy changed'),
        (0x11, '48c1f803', 'Count shift changed'),
        (0x15, '4889c2', 'Count copy changed'),
        (0x18, '483b7718', 'Limit compare changed'),
        (0x1c, '720a', 'Limit branch changed'),
        (0x1e, '4883e801', 'Count minus one changed'),
        (0x22, 'c3', 'Shortcut return changed'),
        (0x23, '0f1f440000', 'Shortcut padding changed'),
        (0x28, '4885c9', 'Span test changed'),
        (0x2b, '7e43', 'Empty-span branch changed'),
        (0x2d, '4c89c0', 'Loop lo load changed'),
        (0x30, '4889d1', 'Loop count load changed'),
        (0x33, '48d1f9', 'Midpoint shift changed'),
        (0x36, '488d3cc8', 'Probe address changed'),
        (0x3a, '483937', 'Entry compare changed'),
        (0x3d, '7321', 'Found-ge branch changed'),
        (0x3f, '4829ca', 'Count shrink changed'),
        (0x42, '488d4708', 'Lo advance changed'),
        (0x46, '4883ea01', 'Count decrement changed'),
        (0x4a, '4885d2', 'Count test changed'),
        (0x4d, '7fe1', 'Loop branch changed'),
        (0x4f, '4c29c0', 'Index subtract changed'),
        (0x52, '48c1f803', 'Index shift changed'),
        (0x56, 'c3', 'Loop return changed'),
        (0x57, '660f1f840000000000', 'Return padding changed'),
        (0x60, '4885c9', 'Mid test changed'),
        (0x63, '74ea', 'Mid-zero branch changed'),
        (0x65, '4889ca', 'Count narrow changed'),
        (0x68, 'ebc6', 'Narrow jump changed'),
        (0x6a, '660f1f440000', 'Fallback padding changed'),
        (0x70, '31c0', 'Empty return zero changed'),
        (0x72, 'c3', 'Empty return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # Branch targets, decoded from the retained displacements.
    require(0x1e + 0x0a == 0x28, 'Limit branch target changed')
    require(0x2d + 0x43 == 0x70, 'Empty-span branch target changed')
    require(0x3f + 0x21 == 0x60, 'Found-ge branch target changed')
    require(0x4f - 0x1f == 0x30, 'Loop branch target changed')
    require(0x65 - 0x16 == 0x4f, 'Mid-zero branch target changed')
    require(0x6a - 0x3a == 0x30, 'Narrow jump target changed')
    # No call opcode at any instruction start inside the window.
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
    require(binary_search([10, 20, 30], 30, 20) == 1, 'Exact middle edge changed')
    require(binary_search([10, 20, 30], 30, 25) == 2, 'Between keys edge changed')
    require(binary_search([10, 20, 30], 30, 5) == 0, 'Below all edge changed')
    require(binary_search([10, 20, 30], 30, 31) == 2, 'Above limit edge changed')
    require(binary_search([10, 20, 30], 30, 30) == 2, 'At limit edge changed')
    require(binary_search([10, 20, 30], 100, 50) == 3, 'Past end edge changed')
    require(binary_search([], 5, 3) == 0, 'Empty span edge changed')
    require(binary_search([], 0, 0) == MASK, 'Empty span at limit edge changed')
    require(binary_search([7], 10, 7) == 0, 'Single entry exact edge changed')
    require(binary_search([7], 10, 8) == 1, 'Single entry past edge changed')
    require(binary_search([1 << 63], (1 << 64) - 1, 1) == 0,
            'Unsigned compare edge changed')
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
                    'eight-byte binary search evidence packet.')
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
        require(retained['function']['padding_bytes'] == 13, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation eight-byte-binary-search evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
