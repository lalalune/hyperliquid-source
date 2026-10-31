#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 multi-limb multiply-accumulate packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window folds the high limb of a five-qword, 52-bit-limb integer into its
low limbs: the high bits of the high limb are multiplied by a constant and
added into limb 0, carries propagate through limbs 1-3, and the low 48 bits
of the high limb are added into the final high limb. What the integer
represents, and what the callers do with the result, is not claimed anywhere.
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
START, END = 0x56327f0, 0x563286b
PAD_END = 0x5632870
BODY = bytes.fromhex(
    '488b5720' '4889f8' '49b8ffffffffffff0000' '48b9d103000001000000'
    '48beffffffffffff0f00' '4921d0' '48c1ea30' '480fafd1' '480317'
    '4989d1' '4821f2' '49c1e934' '4c034f08' '488910' '4c89cf' '4921f1'
    '48c1ef34' '48037810' '4c894808' '4889f9' '4821f7' '48c1e934'
    '48034818' '48897810' '4821ce' '48c1e934' '4c01c1' '48897018'
    '48894820' 'c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000044812d00909167047b00000000000000')
NEXT = bytes.fromhex(
    '2000000058812d00fc91670405010000004b0e108602580e18830302d10e10440e080000')
CALLER_FDES = [
    (0x2d87fc, bytes.fromhex(
        '6400000000882d00141668040c05000000420e108f02420e188e03420e208d04420e'
        '288c05440e308606410e3883074a0ea00402b20a0e38410e30410e28420e20420e184'
        '20e10420e08450b031a040a0e38470e30410e28420e20420e18420e10420e08450b0000'),
     0x563b330, 0x563b83c),
    (0x2d8864, bytes.fromhex(
        '4c00000068882d00bc1a68047534000000420e108f02420e188e03420e208d04420e'
        '288c05410e308606410e388307470ee00d03f51d0a0e38410e30410e28420e20420e'
        '18420e10420e08480b000000'),
     0x563b840, 0x563ecb5),
    (0x2d89e8, bytes.fromhex(
        '4c000000ec892d00186068047503000000420e108f02420e188e03420e208d04420e'
        '288c05410e308606410e3883074a0ee0030389020a0e38410e30410e28420e20420e'
        '18420e10420e08490b000000'),
     0x563ff20, 0x5640295),
]
CALLERS = [0x563b803, 0x563bc5f, 0x5640242]
MASK = (1 << 64) - 1
MASK52 = (1 << 52) - 1
MASK48 = (1 << 48) - 1
CONST = 0x1000003d1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def multiply_accumulate(limbs):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary: limbs are 52-bit, stored in place at
    [rdi+0x00..0x20]. The high limb's top bits are multiplied by CONST and
    folded into limb 0; carries propagate through limbs 1-3; the high
    limb's low 48 bits are added into the final high limb.
    """
    require(len(limbs) == 5, 'Input must hold exactly five limbs')
    limbs = [x & MASK for x in limbs]
    high = limbs[4]
    low48 = high & MASK48
    prod = (((high >> 48) * CONST) & MASK) + limbs[0]
    prod &= MASK
    out = [0] * 5
    out[0] = prod & MASK52
    carry = prod >> 52
    for i in (1, 2, 3):
        total = carry + limbs[i]
        out[i] = total & MASK52
        carry = total >> 52
    out[4] = (carry + low48) & MASK
    return out


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
    require(body == BODY, 'Multi-limb multiply-accumulate window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    check_fde(0x2d8140, FDE, START, END)
    check_fde(0x2d8154, NEXT, PAD_END, 0x5632975)
    for offset, raw, start, end in CALLER_FDES:
        check_fde(offset, raw, start, end)
    # Padding: five int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 5, 'Padding changed')
    require(PAD_END == 0x5632870, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x56327f0.
    fixed = [
        (0x00, '488b5720', 'High limb load changed'),
        (0x04, '4889f8', 'Base copy changed'),
        (0x07, '49b8ffffffffffff0000', '48-bit mask load changed'),
        (0x11, '48b9d103000001000000', 'Constant load changed'),
        (0x1b, '48beffffffffffff0f00', '52-bit mask load changed'),
        (0x25, '4921d0', 'Low-48 mask changed'),
        (0x28, '48c1ea30', 'High-bit shift changed'),
        (0x2c, '480fafd1', 'Constant multiply changed'),
        (0x30, '480317', 'Limb 0 add changed'),
        (0x33, '4989d1', 'Product copy changed'),
        (0x36, '4821f2', 'Limb 0 mask changed'),
        (0x39, '49c1e934', 'First carry shift changed'),
        (0x3d, '4c034f08', 'Limb 1 add changed'),
        (0x41, '488910', 'Limb 0 store changed'),
        (0x44, '4c89cf', 'Carry copy changed'),
        (0x47, '4921f1', 'Limb 1 mask changed'),
        (0x4a, '48c1ef34', 'Second carry shift changed'),
        (0x4e, '48037810', 'Limb 2 add changed'),
        (0x52, '4c894808', 'Limb 1 store changed'),
        (0x56, '4889f9', 'Carry copy changed'),
        (0x59, '4821f7', 'Limb 2 mask changed'),
        (0x5c, '48c1e934', 'Third carry shift changed'),
        (0x60, '48034818', 'Limb 3 add changed'),
        (0x64, '48897810', 'Limb 2 store changed'),
        (0x68, '4821ce', 'Limb 3 mask changed'),
        (0x6b, '48c1e934', 'Final carry shift changed'),
        (0x6f, '4c01c1', 'Low-48 add changed'),
        (0x72, '48897018', 'Limb 3 store changed'),
        (0x76, '48894820', 'High limb store changed'),
        (0x7a, 'c3', 'Return changed'),
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
    # Relocations: no R_X86_64_RELATIVE record in any .rela.* section names
    # this window as addend.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
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
    # Each call site lies inside its caller FDE's range.
    ranges = [(s, e) for _, _, s, e in CALLER_FDES]
    for site, (lo, hi) in zip(direct, ranges):
        require(lo <= site < hi, 'Call site outside its caller FDE')
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    require(multiply_accumulate([0, 0, 0, 0, 0]) == [0, 0, 0, 0, 0],
            'Zero edge changed')
    require(multiply_accumulate([0, 0, 0, 0, 1 << 48]) ==
            [0x1000003d1, 0, 0, 0, 0], 'High-bit fold edge changed')
    require(multiply_accumulate([0, 0, 0, 0, 1]) == [0, 0, 0, 0, 1],
            'Low-48 passthrough edge changed')
    require(multiply_accumulate([0, 0, 0, 0, 1 << 49]) ==
            [0x2000007a2, 0, 0, 0, 0], 'Doubled fold edge changed')
    require(multiply_accumulate([MASK52, MASK52, MASK52, MASK52, 1 << 48]) ==
            [0x1000003d0, 0, 0, 0, 1], 'Full carry chain edge changed')
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
                    'multi-limb multiply-accumulate evidence packet.')
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
        require(retained['function']['padding_bytes'] == 5, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation multi-limb-multiply-accumulate evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
