#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 byte/dword-gate packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window is a byte/dword gate: given a struct pointer in rdi, it returns the
flag byte at +0x15 when that byte is nonzero and the count dword at +0x10 is
positive (signed); otherwise it returns 1 iff dword [rdi+0x4] <= dword
[rdi+0x10] (signed), else 0. What the struct fields mean, and what the
callers do with the result, is not claimed anywhere.
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
START, END = 0x5172c70, 0x5172c8a
PAD_END = 0x5172c90
MASK = (1 << 64) - 1
BODY = bytes.fromhex(
    'f30f1efa0fb647158b571084c0740485d27f063957040f9ec0c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
CIE2 = bytes.fromhex('1c00000000000000017a504c5200017810079b3d5848041b1b0c070890010000')
FDE = bytes.fromhex('1000000064c42900f0521f041a00000000000000')
NEXT = bytes.fromhex('1000000078c42900fc521f042500000000000000')
CALLERS = [
    (0x503a7f0, 0x503ab70, 0x6297dc,
     '6400000010920000f4fad203800300000483578cff460e108d02420e188c03440e208604410e2883054e0e30700a0e28410e20410e18420e10420e08470b0302010a0e28410e20410e18420e10420e08480b03cc010a0e284b0e20410e18420e10420e08450b0000',
     (0x503a9b7, 'e8b4821300', '488dbdf0080000'),
    ),
    (0x5047bd0, 0x50493b4, 0x629df4,
     '3c00000028980000bcc8d303e4170000042b568cff450e108602430d06428f03458e04478d058c0644830703a3070a0c0708430b03400e2e1002e52e00000000',
     (0x5047fde, 'e88dac1200', '498dbc24f0080000'),
    ),
    (0x514ae30, 0x514ae58, 0x29a274,
     '1800000078a229009cf61c042800000000450e108302620e08000000',
     (0x514ae46, 'e8257e0200', '4881c7f0080000'),
    ),
]
# The address-order next window (0x5172c90) ends with a tail jump into this
# window; locked as bytes, not as a call.
NEIGHBOR_JMP = 0x5172cb0
NEIGHBOR_JMP_BYTES = 'e9bbffffff'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def to_signed32(value):
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value >= (1 << 31) else value


def gate(byte, count, d4, d10):
    """Decoded gate rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. All comparisons are signed 32-bit; the
    flag byte is zero-extended by movzbl.
    """
    byte &= 0xFF
    count = to_signed32(count)
    d4 = to_signed32(d4)
    d10 = to_signed32(d10)
    if byte != 0 and count > 0:
        return byte
    return 1 if d4 <= d10 else 0


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
    require(body == BODY, 'Byte/dword-gate instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    require(read(eh['address'] + 0x6205d0, len(CIE2)) == CIE2,
            'CIE at offset 0x6205d0 changed')
    for offset, raw, start, end in [
            (0x29c460, FDE, START, END),
            (0x29c474, NEXT, PAD_END, 0x5172cb5)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: six int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 6, 'Padding changed')
    require(PAD_END == 0x5172c90, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x5172c70.
    fixed = [
        (0, 'f30f1efa', 'Endbr64 changed'),
        (4, '0fb64715', 'Flag-byte load changed'),
        (8, '8b5710', 'Count-dword load changed'),
        (11, '84c0', 'Flag-byte test changed'),
        (13, '7404', 'Flag-zero branch changed'),
        (15, '85d2', 'Count test changed'),
        (17, '7f06', 'Count-positive branch changed'),
        (19, '395704', 'Dword compare changed'),
        (22, '0f9ec0', 'Setle changed'),
        (25, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # Branch targets land exactly on retained instruction starts.
    require(0x5172c7d + 2 + 0x04 == 0x5172c83, 'Flag-zero target changed')
    require(0x5172c81 + 2 + 0x06 == 0x5172c89, 'Count-positive target changed')
    # No call opcode inside the window: the locked body contains no e8 byte.
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    # Neighbor tail jump: the next window ends with jmp 0x5172c70.
    jmp = read(NEIGHBOR_JMP, 5)
    require(jmp == bytes.fromhex(NEIGHBOR_JMP_BYTES), 'Neighbor jump changed')
    require(NEIGHBOR_JMP + 5 + struct.unpack_from('<i', jmp, 1)[0] == START,
            'Neighbor jump target changed')
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
    require(gate(5, 3, 0, 0) == 5, 'Short-circuit edge changed')
    require(gate(5, 0, 1, 3) == 1, 'Zero-count fallback edge changed')
    require(gate(5, -1, 1, 3) == 1, 'Negative-count fallback edge changed')
    require(gate(0, 3, 1, 3) == 1, 'Zero-byte less edge changed')
    require(gate(0, 3, 5, 3) == 0, 'Zero-byte greater edge changed')
    require(gate(0, 3, 3, 3) == 1, 'Zero-byte equal edge changed')
    require(gate(0xFF, 1, 9, 9) == 255, 'Full-byte edge changed')
    require(gate(0, 1, -1, 0) == 1, 'Signed dword edge changed')
    require(gate(0, 1, 0, -1) == 0, 'Signed dword reverse edge changed')
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
                    'byte/dword-gate evidence packet.')
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
        print('Foundation byte/dword-gate evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
