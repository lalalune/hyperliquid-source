#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 indexed qword swap packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window computes two element pointers from two base structs through a
threshold-split table base (field +0x108 for indices <= 0x1f, field +0x110
for indices > 0x1f) and swaps the qwords at those two pointers. What the
structs, indices, and swapped values mean, and what consumes the swap, is not
claimed anywhere.
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
START, END = 0x4fa90a0, 0x4fa9109
PAD_END = 0x4fa9110
BODY = bytes.fromhex(
    '4883f91f763a488b8210010000488d84c800ffffff4883fe1f7636488b9710010000'
    '488d94f200ffffff488b30488b0a488932488908c3660f1f840000000000488b82080'
    '10000488d04c84883fe1f77ca488b9708010000488d14f2488b30488b0a4889324889'
    '08c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c0708')
FDE = bytes.fromhex('10000000a8bb2800dcbf03046900000000000000')
NEXT = bytes.fromhex(
    '30000000bcbb280038c003049200000000410e108602440e188303440e2002420a0e'
    '18470e10410e08450b6f0e18490e10410e08')
CALLER = bytes.fromhex(
    '4c00000098c22800dce303040f07000000420e108f02420e188e03450e208d04420e2'
    '88c05410e308606410e388307470ee001031d060a0e38410e30410e28420e20420e18'
    '420e10420e08410b000000')
CALLERS = [0x4fabc77, 0x4fac161, 0x4fac199, 0x4fac1da]
CALL_BYTES = {
    0x4fabc77: 'e824d4ffff',
    0x4fac161: 'e83acfffff',
    0x4fac199: 'e802cfffff',
    0x4fac1da: 'e8c1ceffff',
}
MASK = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def element_pointer(low, high, idx):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. The threshold test is unsigned
    (jbe/ja), so indices <= 0x1f take the low base and indices > 0x1f take
    the high base with (idx - 0x20) * 8.
    """
    if idx <= 0x1f:
        return (low + idx * 8) & MASK
    return (high + (idx - 0x20) * 8) & MASK


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
    require(body == BODY, 'Indexed qword swap window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    for offset, raw, start, end in [
            (0x28bba4, FDE, START, END),
            (0x28bbb8, NEXT, PAD_END, 0x4fa91a2),
            (0x28c294, CALLER, 0x4fabb90, 0x4fac29f)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: seven int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 7, 'Padding changed')
    require(PAD_END == 0x4fa9110, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x4fa90a0.
    fixed = [
        (0, '4883f91f', 'First index compare changed'),
        (4, '763a', 'Low-first-index branch changed'),
        (6, '488b8210010000', 'High first table base load changed'),
        (13, '488d84c800ffffff', 'High first pointer computation changed'),
        (21, '4883fe1f', 'Second index compare changed'),
        (25, '7636', 'Low-second-index branch changed'),
        (27, '488b9710010000', 'High second table base load changed'),
        (34, '488d94f200ffffff', 'High second pointer computation changed'),
        (42, '488b30', 'First value load changed'),
        (45, '488b0a', 'Second value load changed'),
        (48, '488932', 'First swap store changed'),
        (51, '488908', 'Second swap store changed'),
        (54, 'c3', 'High-path return changed'),
        (55, '660f1f840000000000', 'Intra-body nopw changed'),
        (64, '488b8208010000', 'Low first table base load changed'),
        (71, '488d04c8', 'Low first pointer computation changed'),
        (75, '4883fe1f', 'Low-path second index compare changed'),
        (79, '77ca', 'High-second-index branch changed'),
        (81, '488b9708010000', 'Low second table base load changed'),
        (88, '488d14f2', 'Low second pointer computation changed'),
        (92, '488b30', 'Low-path first value load changed'),
        (95, '488b0a', 'Low-path second value load changed'),
        (98, '488932', 'Low-path first swap store changed'),
        (101, '488908', 'Low-path second swap store changed'),
        (104, 'c3', 'Low-path return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # Branch targets, decoded from the locked displacements.
    require(0x4fa90a4 + 2 + 0x3a == 0x4fa90e0, 'Low-first-index branch target changed')
    require(0x4fa90b9 + 2 + 0x36 == 0x4fa90f1, 'Low-second-index branch target changed')
    require(0x4fa90ef + 2 - 54 == 0x4fa90bb, 'High-second-index branch target changed')
    # No call opcode inside the window; the three conditional branches are
    # the only control transfers (no loop: every path falls through to ret).
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    # Relocations: no record of any type in any .rela.* section names this
    # window as addend.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((sec['name'], address))
    require(naming == [], 'Unexpected relocation naming this window')
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
    # All four call sites sit in the single caller FDE; lock their call bytes.
    for site, raw in CALL_BYTES.items():
        require(read(site, 5) == bytes.fromhex(raw), 'Caller call bytes changed')
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    require(element_pointer(0x1000, 0x2000, 3) == 0x1018, 'Low index edge changed')
    require(element_pointer(0x1000, 0x2000, 0x1f) == 0x10f8, 'Low boundary changed')
    require(element_pointer(0x1000, 0x2000, 0x20) == 0x2000, 'High boundary changed')
    require(element_pointer(0x1000, 0x2000, 0x25) == 0x2028, 'High index edge changed')
    require(element_pointer(0x3000, 0x4000, 5) == 0x3028, 'Second low edge changed')
    require(element_pointer(0x3000, 0x4000, 0x20) == 0x4000, 'Second high boundary changed')
    require(element_pointer(0xfffffffffffffff8, 0x2000, 3) == 0x10,
            'Wrapping low edge changed')
    require(element_pointer(0x1000, 0xfffffffffffffff8, 0x20) == 0xfffffffffffffff8,
            'Wrapping high edge changed')
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
                    'indexed qword swap evidence packet.')
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
        require(retained['function']['padding_bytes'] == 7, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation indexed-qword-swap evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
