#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 index-clamp-stride packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window reads four qwords from a struct (base at +0x8, two values at +0x0
and +0x10, a count at +0x18), computes three 80-byte-stride indices with a
clamping branch, and stores base plus each scaled index (plus the bare base)
to the four output slots. What the struct fields mean is not claimed anywhere.
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
START, END = 0x2517660, 0x25176d2
PAD_END = 0x25176e0
MASK = (1 << 64) - 1
BODY = bytes.fromhex(
    '4889f84c8b46184d85c0742b488b16488b4e1031ff4839d1480f43fa4829f94989d1'
    '4929c94c89c74c29cf77104901c831ff4c89c2eb0631c931d231ff488b7608488d0c89'
    '48c1e1044801f1488d149248c1e2044801f2488d3cbf48c1e7044801f748890848895008'
    '4889701048897818c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000645a0800e0067b017200000000000000')
NEXT_SECTION_ORDER = bytes.fromhex(
    '38000000785a08000c0c7b016500000000420e10420e18420e20410e28410e3083058c'
    '048e038f02700e28410e20420e18420e10420e08410e300000')
NEXT_ADDR_ORDER = bytes.fromhex(
    '3c000000c0a11000f0f84401250200000473c593ff420e10420e18410e2083048e038f'
    '02037b010e18420e10420e08410e20570e18420e10420e08450e200000')
CALLERS = [
    (0x22807d0, 0x228177d, 0x5a058,
     '4c0000005ca0050058525401ad0f000000410e10420e18420e20420e28420e30410e38470ed00983078c068d058e048f038602034d0c0e38410e30420e28420e20420e18420e10410e08410ed0090000',
     0x228149e, 'e8bd612900', '4c89e7488b742468'),
    (0x2281780, 0x2282801, 0x5a0a8,
     '4c000000aca00500b86154018110000000410e10420e18420e20420e28420e30410e38470ee00983078c068d058e048f03860203440e0e38410e30420e28420e20420e18420e10410e08410ee0090000',
     0x2282484, 'e8d7512900', '4c89ff488b742470'),
    (0x2285500, 0x2285fb3, 0x3ba018,
     '5000000008d90d00c89f1e01b30a0000048f3b94ff410e10420e18420e20420e28420e30410e38470ef00283078c068d058e048f0386020340060e38410e30420e28420e20420e18420e10410e08410ef0020000',
     0x2285c23, 'e8381a2900', '488d7320488d7c2440'),
    (0x2285fc0, 0x2286a73, 0x3ba06c,
     '500000005cd90d0034aa1e01b30a000004a73b94ff410e10420e18420e20420e28420e30410e38470ef00283078c068d058e048f0386020340060e38410e30420e28420e20420e18420e10410e08410ef0020000',
     0x22866e3, 'e8780f2900', '488d7320488d7c2440'),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def compute(base, a, b, n):
    """Decoded index-clamp-stride rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. All arithmetic wraps at 64 bits,
    matching the unsigned sub/ja/cmovae semantics of the bytes. Inputs are
    the struct fields (base at +0x8, A at +0x0, B at +0x10, N at +0x18);
    the return is the three computed indices (i0, i1, i2), and the stored
    outputs are base + i*80 for i0/i1/i2 plus the bare base in slot 2.
    """
    if n == 0:
        return (0, 0, 0)
    lo = a if b >= a else 0
    i0 = (b - lo) & MASK
    r9 = (a - i0) & MASK
    i2 = (n - r9) & MASK
    if i2 > r9:
        return (i0, a, i2)
    return (i0, (n + i0) & MASK, 0)


def outputs(base, a, b, n):
    i0, i1, i2 = compute(base, a, b, n)
    return ((base + i0 * 80) & MASK, (base + i1 * 80) & MASK, base,
            (base + i2 * 80) & MASK)


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
    require(body == BODY, 'Index-clamp-stride instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in [
            (0x85a60, FDE, START, END),
            (0x85a74, NEXT_SECTION_ORDER, 0x2517ba0, 0x2517c05),
            (0x3e68d0, NEXT_ADDR_ORDER, PAD_END, 0x2517905)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: fourteen int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 14, 'Padding changed')
    require(PAD_END == 0x25176e0, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x2517660.
    fixed = [
        (0, '4889f8', 'Output pointer move changed'),
        (3, '4c8b4618', 'Count load changed'),
        (7, '4d85c0', 'Count test changed'),
        (10, '742b', 'Zero-count branch changed'),
        (12, '488b16', 'First value load changed'),
        (15, '488b4e10', 'Second value load changed'),
        (19, '31ff', 'Low select clear changed'),
        (21, '4839d1', 'Value compare changed'),
        (24, '480f43fa', 'Unsigned select changed'),
        (28, '4829f9', 'First index subtract changed'),
        (31, '4989d1', 'Remainder move changed'),
        (34, '4929c9', 'Remainder subtract changed'),
        (37, '4c89c7', 'Count move changed'),
        (40, '4c29cf', 'Third index subtract changed'),
        (43, '7710', 'Unsigned above branch changed'),
        (45, '4901c8', 'Count adjust changed'),
        (48, '31ff', 'Third index clear changed'),
        (50, '4c89c2', 'Second index move changed'),
        (53, 'eb06', 'Store-phase jump changed'),
        (55, '31c9', 'Zero-count first clear changed'),
        (57, '31d2', 'Zero-count second clear changed'),
        (59, '31ff', 'Zero-count third clear changed'),
        (61, '488b7608', 'Base load changed'),
        (65, '488d0c89', 'First stride lea changed'),
        (69, '48c1e104', 'First stride shift changed'),
        (73, '4801f1', 'First stride add changed'),
        (76, '488d1492', 'Second stride lea changed'),
        (80, '48c1e204', 'Second stride shift changed'),
        (84, '4801f2', 'Second stride add changed'),
        (87, '488d3cbf', 'Third stride lea changed'),
        (91, '48c1e704', 'Third stride shift changed'),
        (95, '4801f7', 'Third stride add changed'),
        (98, '488908', 'First store changed'),
        (101, '48895008', 'Second store changed'),
        (105, '48897010', 'Base store changed'),
        (109, '48897818', 'Third store changed'),
        (113, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # Branch targets land exactly on retained instruction starts.
    require(0x251766a + 2 + 0x2b == 0x2517697, 'Zero-count target changed')
    require(0x251768b + 2 + 0x10 == 0x251769d, 'Above target changed')
    require(0x2517695 + 2 + 0x06 == 0x251769d, 'Store-phase target changed')
    # Each stride is *5 then <<4, i.e. *80, for all three indices.
    require(body[65:69] == bytes.fromhex('488d0c89')
            and body[76:80] == bytes.fromhex('488d1492')
            and body[87:91] == bytes.fromhex('488d3cbf'), 'Stride lea changed')
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
    require(direct == [c[4] for c in CALLERS], 'Incoming direct calls changed')
    # Each caller sits inside its caller FDE range, with the retained FDE
    # record, call bytes, and call-path argument setup intact.
    for fde_start, fde_end, fde_off, fde_raw, site, call_hex, setup_hex in CALLERS:
        record = read(eh['address'] + fde_off, len(bytes.fromhex(fde_raw)))
        require(record == bytes.fromhex(fde_raw), 'Caller FDE record changed')
        pc = eh['address'] + fde_off + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (fde_start, fde_end),
                'Caller FDE PC/range changed')
        require(fde_start <= site < fde_end, 'Caller outside its FDE range')
        require(read(site, 5) == bytes.fromhex(call_hex), 'Caller call bytes changed')
        setup_len = len(bytes.fromhex(setup_hex))
        require(read(site - setup_len, setup_len) == bytes.fromhex(setup_hex),
                'Caller setup changed')
        require(site + 5 + struct.unpack_from('<i', read(site, 5), 1)[0] == START,
                'Caller call target changed')
    # Decoded-rule edges (restatement of the retained bytes, not execution).
    require(compute(0, 10, 25, 100) == (15, 115, 0), 'Above-range edge changed')
    require(compute(0, 10, 5, 100) == (5, 10, 95), 'Below-range edge changed')
    require(compute(0, 10, 5, 3) == (5, 10, (1 << 64) - 2), 'Wrap edge changed')
    require(compute(0, 10, 25, 5) == (15, 20, 0), 'Clamp edge changed')
    require(compute(0, 10, 5, 10) == (5, 15, 0), 'Equality edge changed')
    require(compute(0, 10, 10, 7) == (0, 10, (1 << 64) - 3), 'Equal-values edge changed')
    require(compute(0, 0, 0, 5) == (0, 0, 5), 'Zero-values edge changed')
    require(compute(0, 10, 25, 0) == (0, 0, 0), 'Zero-count edge changed')
    require(outputs(0x1000, 10, 25, 100) == (0x1000 + 15 * 80, 0x1000 + 115 * 80,
                                            0x1000, 0x1000),
            'Output store edge changed')
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
                    'index-clamp-stride evidence packet.')
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
        print('Foundation index-clamp-stride evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
