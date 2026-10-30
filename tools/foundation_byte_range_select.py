#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 byte-range-select evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window takes (edi, esi) and returns one 32-bit value: edi unchanged when
the low byte of edi lies in [0xc0, 0xe0); otherwise esi, transformed in three
byte classes (b <= 0x8f, b == 0x90, b == 0xa0) and unchanged otherwise. What
either argument means is not claimed anywhere.
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
START, END = 0x359be70, 0x359bebe
PAD_END = 0x359bec0
BODY = bytes.fromhex(
    '89f80fb6c88d9140ffffff83fa207301c381f98f0000007e1b81f9900000007422'
    '81f9a000000075084080e61f4080cea089f0c385c974f94080e60f4080ce8089f0'
    'c34080e60f4080ce9089f0c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000dc1f1500788976024e00000000000000')
NEXT_FDE = bytes.fromhex(
    '3c000000f01f1500b48976029f00000000420e10420e18420e20420e28410e3083068c'
    '058d048e038f0202770e28420e20420e18420e10420e08410e30000000')
CALLERS = [
    0x31ed745,
    0x31ed78d,
    0x31f0bc5,
    0x31f0c03,
    0x31fbcf1,
    0x31fe4fe,
    0x32010bb,
    0x320166b,
    0x32017a3,
    0x3201e57,
    0x32389ac,
    0x3238a30,
    0x3238d15,
    0x32459fd,
    0x3246092,
    0x327dcfd,
    0x327e626,
    0x327e847,
    0x328050c,
    0x3280b05,
    0x3300118,
    0x33010a8,
    0x3301360,
    0x3301b22,
    0x3301c5d,
    0x332f3de,
    0x332f8da,
    0x333dafe,
    0x333ddbc,
    0x3343b81,
    0x33440e3,
    0x3347291,
    0x33477fa,
    0x3348a11,
    0x3348eaa,
    0x334915c,
    0x33494a4,
    0x334ba7f,
    0x334bd66,
    0x336e2a1,
    0x336e6d9,
    0x33df717,
    0x33df8a9,
    0x342c630,
    0x342c6c5,
    0x342cd72,
    0x342ce22,
    0x342d919,
    0x342dd5e,
    0x342f688,
    0x342f8e1,
    0x3500f97,
    0x359821d,
    0x35984cd,
    0x3598654,
    0x3598aec,
    0x3598d1d,
    0x3598e6d,
    0x359913c,
    0x359949e,
    0x3599ab8,
    0x373a14a,
    0x373a1b8,
    0x373a222,
    0x374a5be,
    0x374a870,
    0x374ad7e,
    0x374b02d,
    0x375433c,
    0x3754e63,
    0x37553de,
    0x375578a,
    0x37558de,
    0x375db70,
    0x375df12,
    0x3796a62,
    0x3796bd6,
    0x3937886,
    0x3937b6b,
    0x39382cc,
    0x39385a0,
    0x39389cc,
    0x3938c9b,
    0x39390dd,
    0x3939e42,
    0x393a122,
    0x393a3dd,
    0x393ab5c,
    0x393ae2d,
    0x393b872,
    0x393be2d,
    0x393c273,
    0x393c582,
    0x393c83d,
    0x393cc9b,
    0x393d3db,
    0x393d843,
    0x39483ae,
    0x3948991,
    0x3948f5a,
    0x39797b9,
    0x3979ba7,
    0x397b9e0,
    0x397f761,
    0x3990a23,
    0x3991957,
    0x3991bf6,
    0x3a09ed2,
    0x3a0a3c6,
    0x3a0b36d,
    0x3c9abd8,
    0x3c9e20c,
    0x3ca0627
]
CALLER_FDES = [(0x31ed6b0, 0x31ed886), (0x31f0b40, 0x31f0c88)]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def select(edi, esi):
    """Decoded select rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. Only the low byte of edi is read;
    transform cases modify only the low byte of esi.
    """
    b = edi & 0xFF
    if 0xC0 <= b < 0xE0:
        return edi & 0xFFFFFFFF
    if b == 0:
        return esi & 0xFFFFFFFF
    if b <= 0x8F:
        return (esi & 0xFFFFFF00) | ((esi & 0x0F) | 0x80)
    if b == 0x90:
        return (esi & 0xFFFFFF00) | ((esi & 0x0F) | 0x90)
    if b == 0xA0:
        return (esi & 0xFFFFFF00) | ((esi & 0x1F) | 0xA0)
    return esi & 0xFFFFFFFF


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
    require(body == BODY, 'Byte-range-select instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in [(0x151fd8, FDE, START, END),
                                    (0x151fec, NEXT_FDE, PAD_END, 0x359bf5f)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: two int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 2, 'Padding changed')
    require(PAD_END == 0x359bec0, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x359be70.
    require(body[0:2] == bytes.fromhex('89f8'), 'edi-to-eax move changed')
    require(body[2:5] == bytes.fromhex('0fb6c8'), 'Byte zero-extend changed')
    require(body[5:11] == bytes.fromhex('8d9140ffffff'), 'Range lea changed')
    require(body[11:14] == bytes.fromhex('83fa20'), 'Range compare changed')
    require(body[14:16] == bytes.fromhex('7301'), 'Out-of-range branch changed')
    require(body[16] == 0xc3, 'In-range return changed')
    require(body[17:23] == bytes.fromhex('81f98f000000'), '0x8f compare changed')
    require(body[23:25] == bytes.fromhex('7e1b'), 'Low-byte branch changed')
    require(body[25:31] == bytes.fromhex('81f990000000'), '0x90 compare changed')
    require(body[31:33] == bytes.fromhex('7422'), '0x90 branch changed')
    require(body[33:39] == bytes.fromhex('81f9a0000000'), '0xa0 compare changed')
    require(body[39:41] == bytes.fromhex('7508'), '0xa0 branch changed')
    require(body[41:45] == bytes.fromhex('4080e61f'), '0x1f mask changed')
    require(body[45:49] == bytes.fromhex('4080cea0'), '0xa0 or changed')
    require(body[49:51] == bytes.fromhex('89f0'), 'esi-to-eax move changed')
    require(body[51] == 0xc3, '0xa0 return changed')
    require(body[52:54] == bytes.fromhex('85c9'), 'Zero test changed')
    require(body[54:56] == bytes.fromhex('74f9'), 'Zero branch changed')
    require(body[56:60] == bytes.fromhex('4080e60f'), '0x0f mask changed')
    require(body[60:64] == bytes.fromhex('4080ce80'), '0x80 or changed')
    require(body[64:66] == bytes.fromhex('89f0'), 'Low-byte return move changed')
    require(body[66] == 0xc3, 'Low-byte return changed')
    require(body[67:71] == bytes.fromhex('4080e60f'), '0x90-path mask changed')
    require(body[71:75] == bytes.fromhex('4080ce90'), '0x90 or changed')
    require(body[75:77] == bytes.fromhex('89f0'), '0x90 return move changed')
    require(body[77] == 0xc3, '0x90 return changed')
    # Branch targets resolve inside the window (relative arithmetic).
    require(START + 16 + struct.unpack_from('<b', body, 15)[0] == 0x359be81,
            'jae target changed')
    require(START + 25 + struct.unpack_from('<b', body, 24)[0] == 0x359bea4,
            'jle target changed')
    require(START + 33 + struct.unpack_from('<b', body, 32)[0] == 0x359beb3,
            'je target changed')
    require(START + 41 + struct.unpack_from('<b', body, 40)[0] == 0x359bea1,
            'jne target changed')
    require(START + 56 + struct.unpack_from('<b', body, 55)[0] == 0x359bea1,
            'zero-branch target changed')
    # Range constants: lea subtracts 0xc0, compare is against 0x20.
    require(struct.unpack_from('<i', body, 7)[0] == -0xC0, 'Range base changed')
    require(body[13] == 0x20, 'Range width changed')
    # No calls inside the window: the locked body contains no e8 byte at all.
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    # Relocations: no record of any type in .rela.dyn names this window.
    relsec = by_name['.rela.dyn']
    require(relsec['size'] % 24 == 0, 'Truncated RELA section')
    raw = read(relsec['address'], relsec['size'])
    naming = []
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        if addend == START:
            naming.append(address)
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
    require(direct == CALLERS, 'Incoming direct calls changed')
    # Each retained caller site sits inside its caller FDE range.
    for site, (lo, hi) in zip([CALLERS[0], CALLERS[1], CALLERS[2]],
                              [CALLER_FDES[0], CALLER_FDES[0], CALLER_FDES[1]]):
        require(lo <= site < hi, 'Caller outside its FDE range')
    # Decoded-rule edges (restatement of the retained bytes, not execution).
    require(select(0xAABBCCDF, 0x12345678) == 0xAABBCCDF, 'In-range edge changed')
    require(select(0x000000C0, 0x12345678) == 0x000000C0, 'Range-low edge changed')
    require(select(0x00000000, 0x12345678) == 0x12345678, 'Byte-zero edge changed')
    require(select(0x00000041, 0x12345678) == 0x12345688, 'Mid-byte edge changed')
    require(select(0x0000008F, 0x12345678) == 0x12345688, 'Byte-8f edge changed')
    require(select(0x00000090, 0x12345678) == 0x12345698, 'Byte-90 edge changed')
    require(select(0x000000A0, 0x12345678) == 0x123456B8, 'Byte-a0 edge changed')
    require(select(0x00000091, 0x12345678) == 0x12345678, 'Byte-91 edge changed')
    require(select(0x000000BF, 0x12345678) == 0x12345678, 'Byte-bf edge changed')
    require(select(0x000000E0, 0x12345678) == 0x12345678, 'Byte-e0 edge changed')
    require(select(0x000000FF, 0x12345678) == 0x12345678, 'Byte-ff edge changed')
    require(select(0x00000041, 0xDEADBEEF) == 0xDEADBE8F,
            'Upper-bytes edge changed')
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
        description='Verify a digest-bound, static node #94 byte-range-select '
                    'evidence packet.')
    parser.add_argument('--binary', default=str(TARGET))
    parser.add_argument('--check', help='Compare with retained JSON; fail on drift')
    args = parser.parse_args()
    result = inspect(args.binary)
    if args.check:
        retained = json.loads(Path(args.check).read_text())
        require(retained['target_sha256'] == SHA256, 'Retained digest changed')
        require(retained['function']['window'] == [hex(START), hex(END)],
                'Retained window changed')
        require(retained['function']['window_bytes'] == END - START,
                'Retained size changed')
        require(retained['function']['padding_bytes'] == 2, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['direct_call_sites'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['direct_call_count'] ==
                len(result['direct_callers']), 'Retained caller count changed')
        print('Foundation byte-range-select evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
