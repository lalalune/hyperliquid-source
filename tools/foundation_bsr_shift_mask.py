#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 bsr-derived shift-mask packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window takes one 64-bit input, derives a bit index with bsr from twice the
input minus one, extracts a two-bit masked field with a shift-and-mask, and
returns the masked field plus four times the clamped bit index minus 0x17.
What the input, the masked field, and the callers mean is not claimed anywhere.
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
START, END = 0x54b4390, 0x54b43d2
PAD_END = 0x54b43e0
BODY = bytes.fromhex(
    '488d443fffb9070000004889fa48c7c7ffffffff480fbdf041b80600000039ce0f43ce'
    '4883ea0183e90348d3e74821d748d3ef83e7034439c6410f42f08d44b7e9c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000ccf82b00a83551044200000000000000')
NEXT = bytes.fromhex(
    '18000000e0f82b00e43551044500000000410e10830202430e080000')
CALLER_FDES = [
    (0x2bfecc, bytes.fromhex(
        '64000000d0fe2b0034425204271f000000460e108f02420e188e03420e208d04420e288c'
        '05410e308606440e3883074a0e800202470a0e38440e30410e28420e20420e18420e10420'
        'e08490b032e030a0e38440e30410e28420e20420e18420e10420e08450b0000'),
     0x54c5620, 0x54c7547),
    (0x2bff34, bytes.fromhex(
        '4c00000038ff2b00fc6052045517000000460e108f02420e188e03450e208d04450e288c'
        '05440e308606410e388307470ec001038e010a0e38410e30410e28420e20420e18420e104'
        '20e084a0b000000'),
     0x54c7550, 0x54c8ca5),
]
CALLERS = [0x54c6268, 0x54c85d5]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def compute_shift_mask(rdi):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. `rdi` is the 64-bit input. The doubled
    value 2*rdi-1 is always odd, so the bsr input is never zero and the
    rule is defined for every 64-bit input. Returns the 32-bit eax result.
    """
    mask = 0xffffffffffffffff
    x = rdi & mask
    doubled = (2 * x - 1) & mask
    bsr = doubled.bit_length() - 1
    shift = max(7, bsr) - 3
    masked = ((((x - 1) & mask) & ((-1 << shift) & mask)) >> shift) & 3
    clamped = bsr if bsr >= 6 else 6
    return (masked + 4 * clamped - 0x17) & 0xffffffff


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
    require(body == BODY, 'Bsr shift-mask window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    check_fde(0x2bf8c8, FDE, START, END)
    check_fde(0x2bf8dc, NEXT, PAD_END, 0x54b4425)
    for offset, raw, start, end in CALLER_FDES:
        check_fde(offset, raw, start, end)
    # Padding: fourteen int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 14, 'FDE padding changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x54b4390.
    fixed = [
        (0x00, '488d443fff', 'Doubled-minus-one lea changed'),
        (0x05, 'b907000000', 'Shift floor constant changed'),
        (0x0a, '4889fa', 'Input copy changed'),
        (0x0d, '48c7c7ffffffff', 'All-ones mask load changed'),
        (0x14, '480fbdf0', 'Bit-scan changed'),
        (0x18, '41b806000000', 'Index floor constant changed'),
        (0x1e, '39ce', 'Shift floor compare changed'),
        (0x20, '0f43ce', 'Shift floor select changed'),
        (0x23, '4883ea01', 'Input-minus-one changed'),
        (0x27, '83e903', 'Shift decrement changed'),
        (0x2a, '48d3e7', 'Mask shift left changed'),
        (0x2d, '4821d7', 'Mask apply changed'),
        (0x30, '48d3ef', 'Mask shift right changed'),
        (0x33, '83e703', 'Two-bit mask changed'),
        (0x36, '4439c6', 'Index floor compare changed'),
        (0x39, '410f42f0', 'Index floor select changed'),
        (0x3d, '8d44b7e9', 'Result lea changed'),
        (0x41, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
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
    require(compute_shift_mask(0) == 232, 'Zero input edge changed')
    require(compute_shift_mask(1) == 1, 'One input edge changed')
    require(compute_shift_mask(32) == 2, 'Clamp boundary edge changed')
    require(compute_shift_mask(33) == 3, 'Clamp release edge changed')
    require(compute_shift_mask(65) == 5, 'Shift step edge changed')
    require(compute_shift_mask(1 << 63) == 232, 'Top-bit input edge changed')
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
                    'bsr-derived shift-mask evidence packet.')
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
        print('Foundation bsr-shift-mask evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
