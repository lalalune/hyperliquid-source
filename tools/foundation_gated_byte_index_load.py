#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 gated bounded byte-index load packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window returns one byte selected by an enable byte, a sentinel byte, a
signed range check, and a clamped cursor offset. What the bytes, the fields,
and the callers mean is not claimed anywhere.
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
START, END = 0x4ff8ac0, 0x4ff8b28
PAD_END = 0x4ff8b30
BODY = bytes.fromhex(
    'f30f1efa31c04584c0745c0fb686540100003cff740a8b7f1483ef0139d77e47'
    '488bbed0010000488b86c80100004839c7742d85d2741c29ca4829c783c20183'
    'ef0139fa0f4fd74863ca4801c185d2480f4fc10fb600c3660f1f840000000000'
    '0fb68653010000c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
CALLER_CIE = bytes.fromhex('1c00000000000000017a504c5200017810079b3d5848041b1b0c070890010000')
FDE = bytes.fromhex('1000000044f72800607e08046800000000000000')
NEXT = bytes.fromhex('1000000058f72800bc7e08046c00000000000000')
CALLER_FDES = [
    (0x626a5c, bytes.fromhex(
        '3800000090640000b4a3cf039c05000004cf6e8cff450e108602430d06428f'
        '03458e04488d058c0683070346032ea00102e70a0c0708440b02b32e00'),
     0x5002330, 0x50028cc),
    (0x626ac0, bytes.fromhex(
        '54000000f464000050aacf038c18000004cb6e8cff450e108602430d06508f'
        '038e048d058c06830702e02e2003db032e0002ab2e2002cd0a0c0708450b02'
        '4f2e0003b90a2ea00102a92e000382032ea00102b12e00000000'),
     0x5002a30, 0x50042bc),
    (0x28fdc4, bytes.fromhex(
        '18000000c8fd28008c3b09043100000000450e108302680e08000000'),
     0x5004e70, 0x5004ea1),
    (0x628588, bytes.fromhex(
        '54000000bc7f0000d862d1031220000004b35f8cff450e108602530d06508f'
        '038e048d058c06830703bb022e200347010a0c0708460b025e2e0003e1072e'
        'a00102c22e000335022e20027c2e0003fa052e207f2e00000000'),
     0x501fd80, 0x5021d92),
    (0x628608, bytes.fromhex(
        '3c0000003c800000088dd103de0a00000457608cff410e108602430d06428f'
        '03498e048d058c064b830703c6072ea0010350010a0c0708480b02452e0000'
        '0000'),
     0x5022830, 0x502330e),
    (0x62866c, bytes.fromhex(
        '38000000a08000000498d10317100000044b608cff410e108602430d06488f'
        '038e048d058c064b8307033e0c2ea0010364010a0c0708470b702e0000'),
     0x5023390, 0x50243a7),
    (0x6286cc, bytes.fromhex(
        '4800000000810000d4a8d103b61a00000434608cff410e108602430d06508f'
        '038e048d058c06830703420c0a0c07084a0b02e12e20026f2e00028c2e10028'
        '12e0003bb062ea00103e0012e00'),
     0x50244c0, 0x5025f76),
    (0x62873c, bytes.fromhex(
        '5400000070810000c4c4d103ee2700000459608cff410e108602430d06428f'
        '03518e048d058c0683070349070a0c0708410b03b2062e2003da032e00037e'
        '012e20672e00033a022e2002862e000381092ea00103f7012e00'),
     0x5026120, 0x502890e),
]
CALLERS = [0x5002807, 0x5003a71, 0x5003e76, 0x5004e91, 0x50207ec,
           0x5022f05, 0x5023ebe, 0x5025915, 0x5027fcc]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def select_byte(enable, sentinel, field, index, subtrahend, cursor, base,
                fallback, table):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. `table` maps byte addresses to byte
    values; `fallback` is byte [rsi + 0x153]. All comparisons are signed
    32-bit with wraparound, matching the retained jle/cmovg semantics.
    """
    def s32(v):
        v &= 0xffffffff
        return v - 0x100000000 if v >= 0x80000000 else v
    if enable == 0:
        return 0
    if sentinel == 0xff:
        pass
    else:
        if s32(field - 1) <= s32(index):
            return 0
    if cursor == base:
        return fallback
    if index == 0:
        return table[base]
    edx = s32(s32(index) - s32(subtrahend) + 1)
    edi = s32(s32(cursor) - s32(base) - 1)
    if edx > edi:
        edx = edi
    if edx > 0:
        return table[base + edx]
    return table[base]


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
    require(body == BODY, 'Gated byte-index load window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    require(read(eh['address'] + 0x6205d0, len(CALLER_CIE)) == CALLER_CIE,
            'Caller CIE changed')

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    check_fde(0x28f740, FDE, START, END)
    check_fde(0x28f754, NEXT, PAD_END, 0x4ff8b9c)
    for offset, raw, start, end in CALLER_FDES:
        check_fde(offset, raw, start, end)
    # Padding: eight int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 8, 'FDE padding changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x4ff8ac0.
    fixed = [
        (0x00, 'f30f1efa', 'Entry landing pad changed'),
        (0x04, '31c0', 'Zero accumulator changed'),
        (0x06, '4584c0', 'Enable test changed'),
        (0x09, '745c', 'Enable branch changed'),
        (0x0b, '0fb68654010000', 'Sentinel byte load changed'),
        (0x12, '3cff', 'Sentinel compare changed'),
        (0x14, '740a', 'Sentinel branch changed'),
        (0x16, '8b7f14', 'Index field load changed'),
        (0x19, '83ef01', 'Index decrement changed'),
        (0x1c, '39d7', 'Range compare changed'),
        (0x1e, '7e47', 'Range branch changed'),
        (0x20, '488bbed0010000', 'Cursor load changed'),
        (0x27, '488b86c8010000', 'Base load changed'),
        (0x2e, '4839c7', 'Cursor-base compare changed'),
        (0x31, '742d', 'Cursor-base branch changed'),
        (0x33, '85d2', 'Index zero test changed'),
        (0x35, '741c', 'Index zero branch changed'),
        (0x37, '29ca', 'Index subtract changed'),
        (0x39, '4829c7', 'Cursor-base subtract changed'),
        (0x3c, '83c201', 'Index increment changed'),
        (0x3f, '83ef01', 'Span decrement changed'),
        (0x42, '39fa', 'Clamp compare changed'),
        (0x44, '0f4fd7', 'Clamp move changed'),
        (0x47, '4863ca', 'Offset sign extend changed'),
        (0x4a, '4801c1', 'Offset add changed'),
        (0x4d, '85d2', 'Offset sign test changed'),
        (0x4f, '480f4fc1', 'Offset select changed'),
        (0x53, '0fb600', 'Result byte load changed'),
        (0x56, 'c3', 'Main return changed'),
        (0x57, '660f1f840000000000', 'Intra-body alignment padding changed'),
        (0x60, '0fb68653010000', 'Fallback byte load changed'),
        (0x67, 'c3', 'Fallback return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # Branch targets: all five conditional branches land inside the window.
    for off, disp, target in [(0x09, 0x5c, 0x4ff8b27),
                              (0x14, 0x0a, 0x4ff8ae0),
                              (0x1e, 0x47, 0x4ff8b27),
                              (0x31, 0x2d, 0x4ff8b20),
                              (0x35, 0x1c, 0x4ff8b13)]:
        require(body[off + 1] == disp, 'Branch displacement changed')
        require(START + off + 2 + disp == target, 'Branch target changed')
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
    table = {0x1000 + i: i & 0xff for i in range(256)}
    require(select_byte(0, 0x00, 5, 3, 0, 0x1010, 0x1000, 0x77, table) == 0,
            'Enable-zero edge changed')
    require(select_byte(1, 0x00, 5, 4, 0, 0x1010, 0x1000, 0x77, table) == 0,
            'Index-over edge changed')
    require(select_byte(1, 0x00, 5, 3, 0, 0x1010, 0x1000, 0x77, table) == 0x04,
            'Range-pass clamped edge changed')
    require(select_byte(1, 0xff, 5, 99, 0, 0x1010, 0x1000, 0x77, table) == 0x0f,
            'Sentinel-bypass edge changed')
    require(select_byte(1, 0x00, 5, 3, 0, 0x1000, 0x1000, 0x77, table) == 0x77,
            'Cursor-base fallback edge changed')
    require(select_byte(1, 0x00, 5, 0, 0, 0x1010, 0x1000, 0x77, table) == 0x00,
            'Zero-index edge changed')
    require(select_byte(1, 0x00, 5, 3, 90, 0x1010, 0x1000, 0x77, table) == 0x00,
            'Negative-offset edge changed')
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
                    'gated byte-index load evidence packet.')
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
        require(retained['function']['padding_bytes'] == 8, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation gated-byte-index-load evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
