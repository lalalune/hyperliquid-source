#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 binary-search-16 packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window is a lower-bound binary search over 16-byte entries: given a struct
pointer in rdi (table bounds at +0xad8/+0xae0) and a key in rsi, it returns a
pointer to the first entry whose double-dereferenced key is >= the key
(unsigned), or the table end when every probed key is smaller. What the struct
fields mean, and whether the actual table is sorted, is not claimed anywhere.
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
START, END = 0x51cb570, 0x51cb5da
PAD_END = 0x51cb5e0
MASK = (1 << 64) - 1
BODY = bytes.fromhex(
    'f30f1efa4c8b87d80a0000488b87e00a00004c29c04889c248c1fa044885c07e320f1f80000000004889d148d1f94889c848c1e0044c01c0488b38488b3f483937731d4829ca4c8d40104883ea014885d27fd54c89c0c3660f1f8400000000004885c974ee4889caebbe')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
CIE2 = bytes.fromhex('1c00000000000000017a504c5200017810079b3d5848041b1b0c070890010000')
FDE = bytes.fromhex('1000000074112a00e08e24046a00000000000000')
NEXT = bytes.fromhex('1000000088112a003c8f24040c00000000000000')
CALLERS = [
    (0x51a5db0, 0x51a5f09, 0x29f444,
     '5c00000048f429004c5422045901000000460e108d02440e188c03410e208604410e288305440e3002a70a0e28440e20410e18420e10420e08480b02430a0e28410e20440e18420e10420e08440b610a0e28410e20440e18420e10420e08460b',
     (0x51a5dce, 'e89d570200', '488b7d184c8dad00010000'),
    ),
    (0x51a9d80, 0x51aa0c9, 0x6382dc,
     '44000000107d01008405e9034903000004950b8cff460e108e02420e188d03420e208c04480e288605440e3083064a0ea00202980a0e30410e28410e20420e18420e10420e08480b',
     (0x51a9e52, 'e819170200', '4889de4c89ef'),
    ),
    (0x51aa570, 0x51ab46c, 0x638324,
     '50000000587d01002c0de903fc0e000004670b8cff460e108f02420e188e03420e208d04450e288c05480e308606440e388307470eb007035c010a0e38410e30410e28420e20420e18420e10420e08480b000000',
     (0x51aa70a, 'e8610e0200', '4889de4c89f7'),
    ),
    (0x51ab640, 0x51ac66f, 0x638378,
     '50000000ac7d0100a81de9032f100000046b0b8cff460e108f02420e188e03420e208d04420e288c05410e308606440e3883074a0e80020306080a0e38410e30410e28420e20420e18420e10420e08450b000000',
     (0x51ab681, 'e8eafe0100', '48898424b800000031c0'),
    ),
    (0x51afff0, 0x51b0cb5, 0x6387b8,
     '50000000ec8101001863e903c50c0000040e0a8cff460e108f02420e188e03420e208d04420e288c05410e308606410e3883074a0ec0060387040a0e38410e30410e28420e20420e18420e10420e08470b000000',
     (0x51b0165, 'e806b40100', '4c89f64c89ef'),
    ),
    (0x51b2620, 0x51b38d2, 0x63880c,
     '5000000040820100f488e903b212000004450a8cff460e108f02440e188e03420e208d04420e288c05410e308606410e3883074a0e90020309040a0e38410e30410e28420e20420e18420e10420e08410b000000',
     (0x51b2902, 'e8698c0100', '0f82420d000031f6'),
    ),
    (0x51d02d0, 0x51d056a, 0x6394fc,
     '38000000308f0100b458eb039a0200000493088cff450e108602430d06488f038e048d058c064b8307029b0a0c07084a0b0392012e304f2e00000000',
     (0x51d03a5, 'e8c6b1ffff', '4889de48899d58ffffff'),
    ),
    (0x51d0a20, 0x51d0ab0, 0x2a1758,
     '280000005c172a00a8dd24049000000000410e108602410e188303440e40024c0a0e18430e10410e084a0b00',
     (0x51d0a43, 'e828abffff', '488d7b404889ee'),
    ),
    (0x51d0ab0, 0x51d1002, 0x2a1784,
     '4c00000088172a000cde24045205000000460e108f02420e188e03420e208d04420e288c05410e308606440e3883074e0e90010329030a0e38410e30410e28420e20420e18420e10420e08460b000000',
     (0x51d0bba, 'e8b1a9ffff', '4c89e74c89fe'),
     (0x51d0be1, 'e88aa9ffff', '4c89e74c89fe'),
     (0x51d0c08, 'e863a9ffff', '4c89e74c89fe'),
     (0x51d0c3e, 'e82da9ffff', '4c89e74c89fe'),
     (0x51d0ce2, 'e889a8ffff', '4c89e74c89ee'),
    ),
    (0x51ded50, 0x51dfbb9, 0x639e8c,
     '54000000c0980100a439ec03690e0000046f048cff460e108f02420e188e03420e208d04420e288c05410e308606410e388307470eb8204c0ec0210365060a0e38410e30410e28420e20420e18420e10420e08480b000000',
     (0x51dee26, 'e845c7feff', '48895c246048899c2498000000'),
    ),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def to_signed(value):
    value &= MASK
    return value - (1 << 64) if value >= (1 << 63) else value


def lower_bound(mem_entry, mem_key, lo, hi, rsi):
    """Decoded lower-bound rule of the window, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. mem_entry maps an entry address to the
    address of its key cell; mem_key maps a key-cell address to the key
    value. lo/hi are byte addresses (the window's table bounds). The
    span/count arithmetic below follows the bytes exactly, including the
    truncated-count probe for a positive span that is not a multiple of 16.
    Returns the entry address of the first key >= rsi (unsigned), or the
    table-end entry address.
    """
    span_signed = to_signed((hi - lo) & MASK)
    count = span_signed >> 4
    if span_signed <= 0:
        return lo
    while True:
        mid = count >> 1
        entry = (lo + mid * 16) & MASK
        key = mem_key[mem_entry[entry]]
        if key >= rsi:
            if mid == 0:
                return lo
            count = mid
            continue
        lo = (entry + 16) & MASK
        count = count - mid - 1
        if count <= 0:
            return lo


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
    require(body == BODY, 'Binary-search instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    require(read(eh['address'] + 0x6205d0, len(CIE2)) == CIE2,
            'CIE at offset 0x6205d0 changed')
    for offset, raw, start, end in [
            (0x2a1170, FDE, START, END),
            (0x2a1184, NEXT, PAD_END, 0x51cb5ec)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: six int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 6, 'Padding changed')
    require(PAD_END == 0x51cb5e0, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x51cb570.
    fixed = [
        (0, 'f30f1efa', 'Endbr64 changed'),
        (4, '4c8b87d80a0000', 'Table-lo load changed'),
        (11, '488b87e00a0000', 'Table-hi load changed'),
        (18, '4c29c0', 'Span subtract changed'),
        (21, '4889c2', 'Span copy changed'),
        (24, '48c1fa04', 'Entry-count shift changed'),
        (28, '4885c0', 'Span test changed'),
        (31, '7e32', 'Non-positive-span branch changed'),
        (33, '0f1f8000000000', 'Loop alignment nop changed'),
        (40, '4889d1', 'Count copy changed'),
        (43, '48d1f9', 'Midpoint shift changed'),
        (46, '4889c8', 'Midpoint copy changed'),
        (49, '48c1e004', 'Midpoint scale changed'),
        (53, '4c01c0', 'Midpoint entry add changed'),
        (56, '488b38', 'Entry pointer load changed'),
        (59, '488b3f', 'Key-cell load changed'),
        (62, '483937', 'Key compare changed'),
        (65, '731d', 'Greater-or-equal branch changed'),
        (67, '4829ca', 'Upper-half count subtract changed'),
        (70, '4c8d4010', 'Upper-half lo advance changed'),
        (74, '4883ea01', 'Upper-half count decrement changed'),
        (78, '4885d2', 'Remaining-count test changed'),
        (81, '7fd5', 'Loop-continue branch changed'),
        (83, '4c89c0', 'Return-lo move changed'),
        (86, 'c3', 'Return changed'),
        (87, '660f1f840000000000', 'Return alignment nop changed'),
        (96, '4885c9', 'Midpoint-zero test changed'),
        (99, '74ee', 'Midpoint-zero branch changed'),
        (101, '4889ca', 'Lower-half count move changed'),
        (104, 'ebbe', 'Lower-half loop jump changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # Branch targets land exactly on retained instruction starts.
    require(0x51cb58f + 2 + 0x32 == 0x51cb5c3, 'Non-positive-span target changed')
    require(0x51cb5b1 + 2 + 0x1d == 0x51cb5d0, 'Greater-or-equal target changed')
    require(0x51cb5c1 + 2 - 0x2b == 0x51cb598, 'Loop-continue target changed')
    require(0x51cb5d3 + 2 - 0x12 == 0x51cb5c3, 'Midpoint-zero target changed')
    require(0x51cb5d8 + 2 - 0x42 == 0x51cb598, 'Lower-half loop target changed')
    # No call opcode inside the window: the locked body contains no e8 byte.
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    # Relocations: no record of any type in any .rela.* section names this window.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((sec['name'], address))
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
    expected_sites = [s[0] for c in CALLERS for s in c[4:]]
    require(direct == expected_sites, 'Incoming direct calls changed')
    # Each caller sits inside its caller FDE range, with the retained FDE
    # record, call bytes, and call-path argument setup intact.
    for fde_start, fde_end, fde_off, fde_raw, *sites in CALLERS:
        record = read(eh['address'] + fde_off, len(bytes.fromhex(fde_raw)))
        require(record == bytes.fromhex(fde_raw), 'Caller FDE record changed')
        pc = eh['address'] + fde_off + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (fde_start, fde_end),
                'Caller FDE PC/range changed')
        for site, call_hex, setup_hex in sites:
            require(fde_start <= site < fde_end, 'Caller outside its FDE range')
            require(read(site, 5) == bytes.fromhex(call_hex), 'Caller call bytes changed')
            setup_len = len(bytes.fromhex(setup_hex))
            require(read(site - setup_len, setup_len) == bytes.fromhex(setup_hex),
                    'Caller setup changed')
            require(site + 5 + struct.unpack_from('<i', read(site, 5), 1)[0] == START,
                    'Caller call target changed')
    # Decoded-rule edges (restatement of the retained bytes, not execution).
    # Synthetic tables: entries at 0x2000 + i*16, entry i points at key cell i.
    def run(keys_list, rsi, span_bytes=None):
        base = 0x2000
        entries = {base + i * 16: 0x1000 + i * 8 for i in range(len(keys_list))}
        keys = {0x1000 + i * 8: k for i, k in enumerate(keys_list)}
        hi = base + (len(keys_list) * 16 if span_bytes is None else span_bytes)
        return lower_bound(entries, keys, base, hi, rsi) - base
    require(run([10, 20, 30], 20) == 16, 'Exact middle key edge changed')
    require(run([10, 20, 30], 25) == 32, 'Between keys edge changed')
    require(run([10, 20, 30], 5) == 0, 'Below all keys edge changed')
    require(run([10, 20, 30], 10) == 0, 'Exact first key edge changed')
    require(run([10, 20, 30], 30) == 32, 'Exact last key edge changed')
    require(run([10, 20, 30], 31) == 48, 'Above all keys edge changed')
    require(run([7], 7) == 0, 'Single entry ge edge changed')
    require(run([7], 8) == 16, 'Single entry lt edge changed')
    require(run([], 1) == 0, 'Empty span edge changed')
    require(run([1 << 63], 1) == 0, 'Unsigned compare edge changed')
    require(run([7], 7, span_bytes=8) == 0, 'Short span ge edge changed')
    require(run([7], 8, span_bytes=8) == 16, 'Short span lt edge changed')
    require(run([7], 1, span_bytes=-16) == 0, 'Negative span edge changed')
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
        description='Verify a digest-bound, static node #94 '
                    'binary-search-16 evidence packet.')
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
        require(retained['function']['padding_bytes'] == 6, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation binary-search-16 evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
