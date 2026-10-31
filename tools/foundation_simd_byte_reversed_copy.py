#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 SIMD struct-copy packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window copies a 16-byte + 4-byte header verbatim, then two byte-reversed
16-byte fields, for a 0x34-byte output. What the fields MEAN is not claimed
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
START, END = 0x3818d40, 0x3818dc4
PAD_END = 0x3818dd0
BODY = bytes.fromhex(
    '4889f8' '8b4e30' '894f10' '0f104620' '0f1107'
    'f30f6f4610' '660fefc9' '660f6fd0' '660f60d1' '660f70d24e'
    'f20f70d21b' 'f30f70d21b' '660f68c1' '660f70c04e' 'f20f70c01b'
    'f30f70c01b' '660f67c2' 'f30f7f4714'
    'f30f6f06' '660f6fd0' '660f60d1' '660f70d24e' 'f20f70d21b'
    'f30f70d21b' '660f68c1' '660f70c04e' 'f20f70c01b' 'f30f70c01b'
    '660f67c2' 'f30f7f4724' 'c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
PREV = bytes.fromhex('10000000fc561800d8209b024e00000000000000')
FDE = bytes.fromhex('100000001057180014219b028400000000000000')
NEXT = bytes.fromhex(
    '440000002457180090219b029800000000410e10420e18420e20420e28420e30410e38440e7083078c068d058e048f038602027f0e38410e30420e28420e20420e18420e10410e08')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def reverse16(field):
    """The window's SSE reversal sequence, as a word-level model.

    punpcklbw/punpckhbw against zero widen the 16 input bytes to 16-bit
    words; pshufd 0x4e swaps the 32-bit lanes; pshuflw/pshufhw 0x1b reverse
    the 16-bit words inside each 64-bit half; packuswb packs the words back
    to bytes. The net effect is an exact byte reversal, verified here by
    construction, not by running the captured binary.
    """
    require(len(field) == 16, 'Reversal model needs exactly 16 bytes')
    lo = list(field[:8])
    hi = list(field[8:])

    def pshufd_4e(w):
        d = [w[0:2], w[2:4], w[4:6], w[6:8]]
        return d[2] + d[3] + d[0] + d[1]

    def pshuflw_1b(w):
        return [w[3], w[2], w[1], w[0]] + w[4:]

    def pshufhw_1b(w):
        return w[:4] + [w[7], w[6], w[5], w[4]]

    lo = pshufhw_1b(pshuflw_1b(pshufd_4e(lo)))
    hi = pshufhw_1b(pshuflw_1b(pshufd_4e(hi)))
    # packuswb %xmm2,%xmm0: dest words first, then source words.
    return bytes(hi + lo)


def simd_copy(src):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. src is the 0x34-byte source record
    at [rsi]; the result is the 0x34-byte record written at [rdi].
    """
    require(len(src) == 0x34, 'Copy model needs a 0x34-byte source record')
    out = bytearray(0x34)
    out[0x00:0x10] = src[0x20:0x30]
    out[0x10:0x14] = src[0x30:0x34]
    out[0x14:0x24] = reverse16(src[0x10:0x20])
    out[0x24:0x34] = reverse16(src[0x00:0x10])
    return bytes(out)


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
    require(body == BODY, 'SIMD struct-copy window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    check_fde(0x1856f8, PREV, 0x3818cf0, 0x3818d3e)
    check_fde(0x18570c, FDE, START, END)
    check_fde(0x185720, NEXT, PAD_END, 0x3818e68)
    # Padding: twelve int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 12, 'Padding changed')
    require(PAD_END == 0x3818dd0, 'FDE stride end changed')
    # Preceding gap: two int3 bytes after the previous FDE ends.
    require(read(START - 2, 2) == b'\xcc' * 2, 'Preceding gap changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x3818d40.
    fixed = [
        (0x00, '4889f8', 'Out-pointer save changed'),
        (0x03, '8b4e30', 'Header dword load changed'),
        (0x06, '894f10', 'Header dword store changed'),
        (0x09, '0f104620', 'Verbatim 16-byte load changed'),
        (0x0d, '0f1107', 'Verbatim 16-byte store changed'),
        (0x10, 'f30f6f4610', 'First reversed-field load changed'),
        (0x15, '660fefc9', 'Zero register setup changed'),
        (0x19, '660f6fd0', 'First low-half copy changed'),
        (0x1d, '660f60d1', 'First low unpack changed'),
        (0x21, '660f70d24e', 'First low lane shuffle changed'),
        (0x26, 'f20f70d21b', 'First low word shuffle changed'),
        (0x2b, 'f30f70d21b', 'First low high-half word shuffle changed'),
        (0x30, '660f68c1', 'First high unpack changed'),
        (0x34, '660f70c04e', 'First high lane shuffle changed'),
        (0x39, 'f20f70c01b', 'First high low word shuffle changed'),
        (0x3e, 'f30f70c01b', 'First high high-half word shuffle changed'),
        (0x43, '660f67c2', 'First pack changed'),
        (0x47, 'f30f7f4714', 'First reversed-field store changed'),
        (0x4c, 'f30f6f06', 'Second reversed-field load changed'),
        (0x50, '660f6fd0', 'Second low-half copy changed'),
        (0x54, '660f60d1', 'Second low unpack changed'),
        (0x58, '660f70d24e', 'Second low lane shuffle changed'),
        (0x5d, 'f20f70d21b', 'Second low word shuffle changed'),
        (0x62, 'f30f70d21b', 'Second low high-half word shuffle changed'),
        (0x67, '660f68c1', 'Second high unpack changed'),
        (0x6b, '660f70c04e', 'Second high lane shuffle changed'),
        (0x70, 'f20f70c01b', 'Second high low word shuffle changed'),
        (0x75, 'f30f70c01b', 'Second high high-half word shuffle changed'),
        (0x7a, '660f67c2', 'Second pack changed'),
        (0x7e, 'f30f7f4724', 'Second reversed-field store changed'),
        (0x83, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # No call opcode at any instruction start inside the window; the single
    # ret is the only exit.
    starts = {off for off, _, _ in fixed}
    for pos, byte in enumerate(body):
        if pos in starts:
            require(byte != 0xe8, 'Unexpected call opcode in window')
    # Relocations: exactly one R_X86_64_RELATIVE record names this window
    # as addend — slot 0x5775570, reported as a slot list only.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append([sec['name'], hex(address)])
    require(naming == [['.rela.dyn', '0x5775570']],
            'Relocation slots naming window changed')
    # Incoming calls: direct e8 call sites anywhere in .text landing on
    # this window; exactly zero — explicitly not a complete xref census.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == [], 'Incoming direct callers changed')
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    # The reversal sequence is an exact byte reversal (word-level model).
    require(reverse16(bytes(range(16))) == bytes(range(15, -1, -1)),
            'Reversal model edge changed')
    require(reverse16(bytes(16)) == bytes(16), 'Zero-field edge changed')
    # Full copy: sequential source bytes expose every field's placement.
    src = bytes(range(0x34))
    out = simd_copy(src)
    require(out[0x00:0x10] == src[0x20:0x30], 'Verbatim header edge changed')
    require(out[0x10:0x14] == src[0x30:0x34], 'Header dword edge changed')
    require(out[0x14:0x24] == src[0x10:0x20][::-1],
            'First reversed-field edge changed')
    require(out[0x24:0x34] == src[0x00:0x10][::-1],
            'Second reversed-field edge changed')
    # Distinct marker bytes per field: a field's reversal cannot be confused
    # with another field's verbatim copy.
    src = bytes([0xa0 + i for i in range(0x34)])
    out = simd_copy(src)
    require(out[0x14] == src[0x1f] and out[0x23] == src[0x10],
            'First reversed-field marker edge changed')
    require(out[0x24] == src[0x0f] and out[0x33] == src[0x00],
            'Second reversed-field marker edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'relocation_slots': naming,
        'direct_callers': direct,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 '
                    'SIMD struct-copy evidence packet.')
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
        require(retained['function']['padding_bytes'] == 12, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation SIMD-byte-reversed-copy evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
