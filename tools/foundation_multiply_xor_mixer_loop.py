#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 multiply-xor mixer loop packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window is a two-stream multiply-xor fold over a length-like input: with
rdi = base pointer, rsi = length, rdx = seed B, rcx = seed A, r8 = xor key,
it folds 16-byte chunks from the front (advancing) and from the back
(retreating) with two unsigned 64x64->128 multiplies per step, and returns
the xor of the two accumulators. What the buffer holds, and what the caller
does with the result, is not claimed anywhere. The window is heavier than
the usual single-gate bar (a loop with 128-bit multiplies), and it is bound
only because its rule locks exactly from its own bytes and was re-verified
against an independent byte-level emulator over 5,062 cases with zero
mismatches (see the work-item README and evidence.json).
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
START, END = 0x16488e0, 0x1648946
PAD_END = 0x1648950
MASK = (1 << 64) - 1
BODY = bytes.fromhex(
    '4989c94889d149bbf0ffffffffffff7f4921f3744a83e60f4801fe0f1f440000'
    '4a8d041e4839c773364c334f084a8b441ef84c31c049f7e14989c248330f4a8b44'
    '1ef04c31c04989d148f7e14889d14831c14d31d14883c7104983c3f075c14931c9'
    '4c89c8c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000f80b0200cc6794006600000000000000')
NEXT = bytes.fromhex('140000000c0c0200286894004900000000440e3002440e08')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def mix(buf, base, n, seed_b, seed_a, key):
    """Decoded rule, for edge and vector checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. buf covers [base, base + L_eff) where
    L_eff = n & 0x7fffffffffffffff; reads outside that range raise, which
    the loop conditions provably never do for a well-formed call.
    """
    def memq(addr):
        off = addr - base
        require(0 <= off and off + 8 <= len(buf), 'Rule read outside buffer')
        return int.from_bytes(buf[off:off + 8], 'little')

    a, b = seed_a & MASK, seed_b & MASK
    r11 = n & 0x7ffffffffffffff0
    if r11 == 0:
        return (a ^ b) & MASK
    base2 = (base + (n & 0xf)) & MASK
    p = base
    while True:
        bound = (base2 + r11) & MASK
        if p >= bound:
            break
        a ^= memq(p + 8)
        t1 = memq(bound - 8) ^ (key & MASK)
        prod1 = t1 * a
        lo1, hi1 = prod1 & MASK, (prod1 >> 64) & MASK
        b ^= memq(p)
        t2 = memq(bound - 16) ^ (key & MASK)
        a = hi1
        prod2 = t2 * b
        lo2, hi2 = prod2 & MASK, (prod2 >> 64) & MASK
        b = hi2 ^ lo2
        a ^= lo1
        p = (p + 16) & MASK
        r11 = (r11 - 16) & MASK
        if r11 == 0:
            break
    return (a ^ b) & MASK


def qwords(*values):
    return b''.join(struct.pack('<Q', v & MASK) for v in values)


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
    require(body == BODY, 'Multiply-xor-mixer-loop instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    for offset, raw, start, end in [
            (0x20bf4, FDE, START, END),
            (0x20c08, NEXT, PAD_END, 0x1648999)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: ten int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 10, 'Padding changed')
    require(PAD_END == 0x1648950, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x16488e0.
    fixed = [
        (0, '4989c9', 'Seed A move changed'),
        (3, '4889d1', 'Seed B move changed'),
        (6, '49bbf0ffffffffffff7f', 'Loop-bound mask changed'),
        (16, '4921f3', 'Loop-bound and changed'),
        (19, '744a', 'Zero-bound branch changed'),
        (21, '83e60f', 'Low-nibble and changed'),
        (24, '4801fe', 'Base-plus-nibble add changed'),
        (27, '0f1f440000', 'Alignment nop changed'),
        (32, '4a8d041e', 'Bound lea changed'),
        (36, '4839c7', 'Meeting compare changed'),
        (39, '7336', 'Meeting branch changed'),
        (41, '4c334f08', 'Forward high xor changed'),
        (45, '4a8b441ef8', 'Backward high load changed'),
        (50, '4c31c0', 'First key xor changed'),
        (53, '49f7e1', 'First multiply changed'),
        (56, '4989c2', 'First low save changed'),
        (59, '48330f', 'Forward low xor changed'),
        (62, '4a8b441ef0', 'Backward low load changed'),
        (67, '4c31c0', 'Second key xor changed'),
        (70, '4989d1', 'First high move changed'),
        (73, '48f7e1', 'Second multiply changed'),
        (76, '4889d1', 'Second high move changed'),
        (79, '4831c1', 'Second fold xor changed'),
        (82, '4d31d1', 'First fold xor changed'),
        (85, '4883c710', 'Forward step changed'),
        (89, '4983c3f0', 'Backward step changed'),
        (93, '75c1', 'Loop branch changed'),
        (95, '4931c9', 'Final fold xor changed'),
        (98, '4c89c8', 'Result move changed'),
        (101, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # Branch targets land exactly on retained instruction starts.
    require(0x16488f3 + 2 + 0x4a == 0x164893f, 'Zero-bound target changed')
    require(0x1648907 + 2 + 0x36 == 0x164893f, 'Meeting target changed')
    require(0x164893d + 2 - 0x3f == 0x1648900, 'Loop target changed')
    # No call opcode inside the window: the locked body contains no e8 byte.
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    # Relocations: exactly one record of any type in any .rela.* section
    # names this window: one R_X86_64_RELATIVE slot, reported as a slot list.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((sec['name'], address))
    require(naming == [('.rela.dyn', 0x57709e8)], 'Relocation slot changed')
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
    require(direct == [], 'Incoming direct calls changed')
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    # Zero/short length: the bound is zero, so the seeds just xor.
    require(mix(b'', 0x1000, 0, 0x2222, 0x1111, 0) == 0x3333,
            'Zero-length edge changed')
    require(mix(bytes(5), 0x1000, 5, 0x2222, 0x1111, 0) == 0x3333,
            'Short-length edge changed')
    # One step, n=16, mem=[1, 2], key=0, A=3, B=5 -> 6 (hand trace in README).
    require(mix(qwords(1, 2), 0x1000, 16, 5, 3, 0) == 6,
            'Single-step edge changed')
    # One step over the far chunk, n=32, mem=[1, 2, 3, 4], key=0, A=3, B=5 -> 8.
    require(mix(qwords(1, 2, 3, 4), 0x1000, 32, 5, 3, 0) == 8,
            'Far-chunk edge changed')
    # Two steps with overlap, n=48, mem=[1, 2, 3, 4, 5, 6], key=0, A=3, B=5 -> 77.
    require(mix(qwords(1, 2, 3, 4, 5, 6), 0x1000, 48, 5, 3, 0) == 77,
            'Two-step edge changed')
    # High-part fold, n=16, mem=[0, 3], key=0, A=all-ones, B=0 -> 0xFFF...F6.
    require(mix(qwords(0, 3), 0x1000, 16, 0, MASK, 0) == MASK - 9,
            'High-part edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'relocation_slots': [[name, hex(addr)] for name, addr in naming],
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
                    'multiply-xor mixer-loop evidence packet.')
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
        require(retained['function']['padding_bytes'] == 10, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        # Replay the emulator-generated vectors against the decoded rule.
        for vec in retained['reverification']['vectors']:
            buf = bytes.fromhex(vec['buffer_hex'])
            got = mix(buf, 0x100000, vec['length'], int(vec['seedB'], 16),
                      int(vec['seedA'], 16), int(vec['key'], 16))
            require(got == int(vec['expected'], 16), 'Vector replay changed')
        print('Foundation multiply-xor-mixer-loop evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
