#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 byte-indexed flag-OR evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window has no calls: it zero-extends a byte argument, loads one u32 entry
from a table, and ORs that entry into a struct field. The meaning of the
field, of the table, and of any single-bit entry is not claimed anywhere.
Only the first 20 table entries are locked as flag entries; entries at index
20 and above are multi-bit values in the target, so no flag interpretation
is claimed for them.
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
START, END = 0x15625e0, 0x15625f5
PAD_END = 0x1562600
BODY = bytes.fromhex('400fb6c6488d0d01f1cefe8b04810987a0010000c3')
PAD = b'\xcc' * 11
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('100000001c7e0100a89286001500000000000000')
NEXT_FDE = bytes.fromhex('10000000307e0100b49286008b00000000000000')
TABLE_VA = 0x2516ec
# First 20 u32 entries: a permutation of single bits 0..19, in this order:
# indices 0-7 -> bits 0-7, index 8 -> bit 9, index 9 -> bit 11,
# indices 10-17 -> bits 12-19, index 18 -> bit 8, index 19 -> bit 10.
TABLE = struct.pack('<20I',
    0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80,  # indices 0-7
    0x200, 0x800,                                # indices 8-9
    0x1000, 0x2000, 0x4000, 0x8000,              # indices 10-13
    0x10000, 0x20000, 0x40000, 0x80000,          # indices 14-17
    0x100, 0x400)                                # indices 18-19
TABLE_ENTRY_20 = bytes.fromhex('6c4a3101')
# R_X86_64_RELATIVE slots whose addend names this window. The file stores 0
# in .data.rel.ro slots; the loader writes the window address at load time.
SLOTS = [0x5672668, 0x5673070, 0x5673830, 0x5673958]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def flag_or(index, field):
    """Decoded formula of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. The index is the zero-extended
    byte argument (movzbl); only indices 0..19 are locked table entries here.
    """
    require(0 <= index < 20, 'Index outside the locked flag table')
    mask = struct.unpack_from('<I', TABLE, index * 4)[0]
    return field | mask


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
    require(body == BODY, 'Flag-OR instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in [(0x17e18, FDE, START, END),
                                    (0x17e2c, NEXT_FDE, 0x1562600, 0x156268b)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x15625e0.
    require(body[0:4] == bytes.fromhex('400fb6c6'), 'Byte-index load changed')
    require(body[4:11] == bytes.fromhex('488d0d01f1cefe'), 'Table address changed')
    require(0x15625eb + struct.unpack_from('<i', body, 7)[0] == TABLE_VA,
            'Table address target changed')
    require(body[11:14] == bytes.fromhex('8b0481'), 'Table entry load changed')
    require(body[14:20] == bytes.fromhex('0987a0010000'), 'Field OR changed')
    require(body[20] == 0xc3, 'Return changed')
    # Table: exactly the first 20 u32 entries, a permutation of bits 0..19.
    table = read(TABLE_VA, 80)
    require(table == TABLE, 'Flag table changed')
    entries = struct.unpack_from('<20I', table, 0)
    require(sorted(entries) == [1 << b for b in range(20)],
            'Flag table is not a permutation of bits 0..19')
    require(read(TABLE_VA + 80, 4) == TABLE_ENTRY_20, 'Table boundary changed')
    require(bin(struct.unpack_from('<I', TABLE_ENTRY_20, 0)[0]).count('1') > 1,
            'Table entry 20 unexpectedly a single-bit mask')
    # Relocations: exactly four RELATIVE slots name this window; the file
    # stores 0 in .data.rel.ro slots, applied only at load time.
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
    # Decoded-formula edges (restatement of the retained bytes, not execution).
    require(flag_or(0, 0) == 1, 'Index-0 edge changed')
    require(flag_or(7, 0xff) == 0xff, 'Index-7 already-set edge changed')
    require(flag_or(8, 0) == 0x200, 'Index-8 edge changed')
    require(flag_or(18, 0) == 0x100, 'Index-18 edge changed')
    require(flag_or(19, 0) == 0x400, 'Index-19 edge changed')
    require(flag_or(0, 0x200) == 0x201, 'OR-accumulate edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'table_sha256': hashlib.sha256(table).hexdigest(),
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
        description='Verify a digest-bound, static node #94 byte-indexed '
                    'flag-OR evidence packet.')
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
        require(retained['function']['table_sha256'] == result['table_sha256'],
                'Retained table hash changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] == [],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation flag-OR evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
