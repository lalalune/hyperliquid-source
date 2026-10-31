#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 unwindless SWAR popcount64 packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window counts the set bits of its 64-bit input with the classic
shift-mask-add SWAR sequence and returns the count masked to 0x7f. What the
count is used for, and which source-level function this might be, is not
claimed anywhere.

UNWINDLESS: no FDE record covers this window. The checker therefore locks the
two bracketing FDE records (PREV ends exactly where the leading int3 run
starts, NEXT starts exactly where the trailing int3 run ends) and scans every
.eh_frame record to prove no FDE pc/range contains the window start.
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
START, END = 0x5660010, 0x5660072
LEAD_START, NEXT_START = 0x5660004, 0x5660080
BODY = bytes.fromhex(
    '4889f848d1e848b955555555555555554821c14829cf4889f848c1e80248b933'
    '333333333333334821c84821f94801c14889c848c1e8044801c848b90f0f0f0f'
    '0f0f0f0f4821c14889c848c1e82001c889c1c1e91001c189c8c1e80801c883e0'
    '7fc3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
PREV = bytes.fromhex('14000000d0c62d0094236a04840000000000000000000000')
NEXT = bytes.fromhex('14000000e8c62d007c246a04120000000000000000000000')
CALLER_FDES = [
    (0x28ac50, bytes.fromhex(
        '1400000054ac2800202a03041500000000480e104c0e0800'),
     0x4f9eb90, 0x4f9eba5),
    (0x6231ac, bytes.fromhex(
        '54000000e02b000074e9ca03b90f000004af7f8cff460e108f02420e188e03420e208d04420e288c05410e308606410e388307470eb820490e902103a60d0a0e38410e30410e28420e20420e18420e10420e08410b000000'),
     0x4fb3040, 0x4fb3ff9),
    (0x2b2ba0, bytes.fromhex(
        '74000000a42b2b00d0f33c041207000000460e108f02420e188e03420e208d04420e288c05410e308606410e388307470eb0010355010eb801600ec001570eb801410eb0010346010a0e38410e30410e28420e20420e18420e10420e08410b02e90a0e38410e30410e28420e20420e18420e10420e08420b'),
     0x5363490, 0x5363ba2),
    (0x2c0638, bytes.fromhex(
        '640000003c062c00b8b452047107000000460e108f02420e188e03450e208d04420e288c05410e308606440e388307470ee0010378060a0e38410e30410e28420e20420e18420e10420e08410b02b80a0e38450e30440e28420e20420e18420e10420e08450b0000'),
     0x54cd010, 0x54cd781),
    (0x2c06a0, bytes.fromhex(
        '4c000000a4062c00d0bb52047206000000460e108f02450e188e03420e208d04420e288c05410e308606410e3883074a0ef0010340050a0e38440e30410e28420e20420e18420e10420e08480b000000'),
     0x54cd790, 0x54cde02),
    (0x2c9ae0, bytes.fromhex(
        '4c000000e49a2c0000a55704af0c000000460e108f024c0e188e034c0e208d04450e288c05450e308606440e388307440ea0010362040a0e38410e30410e28420e20420e18420e10420e08440b000000'),
     0x5525500, 0x55261af),
]
CALLERS = [0x4f9eb9b, 0x4fb39f9, 0x5363531, 0x5363699, 0x5363814,
           0x54cd36e, 0x54cda13,
           0x5525942, 0x5525a7c, 0x5525b28, 0x5525b4e, 0x5525b74,
           0x5525b9a, 0x5525bc0, 0x5525be6, 0x5525c1e, 0x5525c2c,
           0x5525c3a, 0x5525c48, 0x5525c56, 0x5525c64, 0x5525c72,
           0x5525c80, 0x5525cee, 0x5526151]
# Caller FDE range per call site, in CALLERS order: C1, C2, C3 x3, C4, C5,
# then C6 x18.
SITE_FDES = ([(0x4f9eb90, 0x4f9eba5), (0x4fb3040, 0x4fb3ff9)]
             + [(0x5363490, 0x5363ba2)] * 3
             + [(0x54cd010, 0x54cd781), (0x54cd790, 0x54cde02)]
             + [(0x5525500, 0x55261af)] * 18)
MASK = (1 << 64) - 1
MASK32 = (1 << 32) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def swar_popcount(x):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. Each step follows the bytes literally,
    including the 32-bit fold at the end (add %ecx,%eax and friends operate
    on 32-bit registers).
    """
    x &= MASK
    rax = (x >> 1) & MASK
    rcx = 0x5555555555555555 & rax
    rdi = (x - rcx) & MASK
    rax = (rdi >> 2) & MASK
    rcx = 0x3333333333333333
    rax &= rcx
    rcx &= rdi
    rcx = (rcx + rax) & MASK
    rax = (rcx >> 4) & MASK
    rax = (rax + rcx) & MASK
    rcx = 0xf0f0f0f0f0f0f0f & rax
    rax = (rcx >> 0x20) & MASK
    eax = (rax + rcx) & MASK32
    ecx = eax
    ecx = (ecx >> 0x10) & MASK32
    ecx = (ecx + eax) & MASK32
    eax = ecx
    eax = (eax >> 0x08) & MASK32
    eax = (eax + ecx) & MASK32
    return eax & 0x7f


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
    require(body == BODY, 'Unwindless popcount window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    # Bracketing FDEs: PREV ends where the leading int3 run starts, NEXT
    # starts where the trailing int3 run ends. Neither covers the window.
    check_fde(0x2dc6cc, PREV, 0x565ff80, LEAD_START)
    check_fde(0x2dc6e4, NEXT, NEXT_START, 0x5660092)
    for offset, raw, start, end in CALLER_FDES:
        check_fde(offset, raw, start, end)
    # Int3 runs: 12 leading, 14 trailing; the gap totals 124 bytes.
    require(read(LEAD_START, START - LEAD_START) == b'\xcc' * 12,
            'Leading int3 run changed')
    require(read(END, NEXT_START - END) == b'\xcc' * 14,
            'Trailing int3 run changed')
    require(NEXT_START - LEAD_START == 124, 'Gap extent changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the window start 0x5660010.
    fixed = [
        (0x00, '4889f8', 'Input copy changed'),
        (0x03, '48d1e8', 'First shift changed'),
        (0x06, '48b95555555555555555', '0x5555 mask load changed'),
        (0x10, '4821c1', 'First mask changed'),
        (0x13, '4829cf', 'First subtract changed'),
        (0x16, '4889f8', 'Second input copy changed'),
        (0x19, '48c1e802', 'Second shift changed'),
        (0x1d, '48b93333333333333333', '0x3333 mask load changed'),
        (0x27, '4821c8', 'Second mask changed'),
        (0x2a, '4821f9', 'Second mask-and changed'),
        (0x2d, '4801c1', 'First add changed'),
        (0x30, '4889c8', 'Third input copy changed'),
        (0x33, '48c1e804', 'Third shift changed'),
        (0x37, '4801c8', 'Second add changed'),
        (0x3a, '48b90f0f0f0f0f0f0f0f', '0xf0f0 mask load changed'),
        (0x44, '4821c1', 'Third mask changed'),
        (0x47, '4889c8', 'Fourth input copy changed'),
        (0x4a, '48c1e820', 'Fold shift changed'),
        (0x4e, '01c8', 'Fold add changed'),
        (0x50, '89c1', 'Fold copy changed'),
        (0x52, 'c1e910', 'Fold 16-bit shift changed'),
        (0x55, '01c1', 'Fold 16-bit add changed'),
        (0x57, '89c8', 'Fold 8-bit copy changed'),
        (0x59, 'c1e808', 'Fold 8-bit shift changed'),
        (0x5c, '01c8', 'Fold 8-bit add changed'),
        (0x5e, '83e07f', 'Result mask changed'),
        (0x61, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # No call opcode at any instruction start inside the window; every path
    # falls through to the single ret.
    starts = {off for off, _, _ in fixed}
    for pos, byte in enumerate(body):
        if pos in starts:
            require(byte != 0xe8, 'Unexpected call opcode in window')
    # UNWINDLESS PROOF: walk every .eh_frame record (length-prefixed; a
    # zero CIE pointer marks a CIE, anything else is an FDE whose initial
    # location is a pcrel sdata4 at record offset 8 and whose range is the
    # u32 at offset 12). No FDE pc/range may contain the window start, and
    # the bracketing FDEs must be exactly PREV and NEXT.
    eh_raw = read(eh['address'], eh['size'])
    ranges = []
    off = 0
    while off + 4 <= len(eh_raw):
        length = struct.unpack_from('<I', eh_raw, off)[0]
        if length == 0:
            break
        require(off + 4 + length <= len(eh_raw), 'Truncated .eh_frame record')
        cie_pointer = struct.unpack_from('<I', eh_raw, off + 4)[0]
        if cie_pointer != 0:
            pc = eh['address'] + off + 8 + struct.unpack_from(
                '<i', eh_raw, off + 8)[0]
            extent = struct.unpack_from('<I', eh_raw, off + 12)[0]
            ranges.append((pc, pc + extent))
        off += 4 + length
    require(not any(lo <= START < hi for lo, hi in ranges),
            'An FDE covers the window')
    below = max((lo, hi) for lo, hi in ranges if lo <= START)
    above = min((lo, hi) for lo, hi in ranges if lo > START)
    require(below == (0x565ff80, LEAD_START), 'Bracketing FDE below changed')
    require(above == (NEXT_START, 0x5660092), 'Bracketing FDE above changed')
    # Relocations: no R_X86_64_RELATIVE record in any .rela.* section names
    # this window as addend.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for o in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, o)
                if addend == START:
                    naming.append((sec['name'], address))
    require(naming == [], 'Relocation slots naming window changed')
    # Incoming calls: direct e8 call sites anywhere in .text, each inside
    # its own caller FDE.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == CALLERS, 'Incoming direct callers changed')
    for site, (lo, hi) in zip(direct, SITE_FDES):
        require(lo <= site < hi, 'Call site outside its caller FDE')
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    for value, expected in [
            (0, 0),
            (1, 1),
            (0x8000000000000000, 1),
            (0x5555555555555555, 32),
            (0xaaaaaaaaaaaaaaaa, 32),
            (0xffffffffffffffff, 64),
            (0x123456789abcdef0, bin(0x123456789abcdef0).count('1')),
            (0xf0f0f0f0f0f0f0f0, 32)]:
        require(swar_popcount(value) == expected, 'Popcount edge changed')
        require(swar_popcount(value) == bin(value).count('1'),
                'SWAR sequence disagrees with bit count')
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
                    'unwindless popcount evidence packet.')
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
        require(retained['function']['leading_padding_bytes'] == 12,
                'Retained leading padding changed')
        require(retained['function']['trailing_padding_bytes'] == 14,
                'Retained trailing padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation unwindless-popcount evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
