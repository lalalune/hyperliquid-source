#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 pointer-sum gate packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window returns rdi+rsi when either argument is zero, and rdi+rsi-0xc
when both are nonzero. Both tests are full 64-bit tests, and both return
paths load rax with a lea, so the return value is fully determined.

This window is bound ALONE. No census of similar windows is claimed.
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
START, END = 0x521cc40, 0x521cc5d
BODY = bytes.fromhex(
    'f30f1efa4885ff740f488d4437f44885f67405c30f1f4000488d0437c3')
STRIDE_END = 0x521cc5e
PADDING = bytes.fromhex('cc')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# Both CIEs use zR-family encodings where initial_location is a 4-byte
# signed PC-relative value; range is a 4-byte unsigned value. The window
# CIE lives at section offset 0x0; the next/caller CIE lives at 0x6205d0
# ("zPLR": P encoding 0x9b, L encoding 0x1b, R encoding 0x1b, i.e. pcrel
# sdata4 for initial_location, which is what the checker decodes).
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000064412a00c07529041d00000000000000')
NEXT_CIE = bytes.fromhex(
    '1c00000000000000017a504c5200017810079b3d5848041b1b0c070890010000')
NEXT_FDE = bytes.fromhex(
    '20000000fcc3010076edef03380000000428f48bff0e9001830786068c058d'
    '048e038f02')
CALLERS = [
    # (call site, call bytes, (caller FDE start, caller FDE end),
    #  caller FDE section offset, caller FDE raw bytes)
    (0x50ef0f7, bytes.fromhex('e844db1200'), (0x50ee960, 0x50efe8d),
     0x630430, bytes.fromhex(
         '4c00000064fe000010d0dd032d15000004ed3c8cff450e108602430d06468f'
         '038e048d05458c06448307037d0b0a0c0708440b0359012e30029b2e0002dd'
         '2e4002852e0003b0022e20028e2e00000000')),
    (0x50f0b9b, bytes.fromhex('e8a0c01200'), (0x50f03a0, 0x50f16a2),
     0x63050c, bytes.fromhex(
         '3800000040ff000074e9dd030213000004f93c8cff450e108602430d06468f'
         '038e048d05458c0644830703bf080a0c07084a0b039b032e10027e2e00')),
    (0x50f2bda, bytes.fromhex('e861a01200'), (0x50f18a0, 0x50f3a3a),
     0x63056c, bytes.fromhex(
         '60000000a0ff000014fedd039a210000044a3d8cff450e108602430d06428f'
         '03518e048d058c0683070343010a0c0708420b03e5032e1003c7022e0003e9'
         '022e40024a2e0003200a2e10025e2e0002eb2e30028e2e0003ff042e40029b'
         '2e000305032e20')),
]
MASK64 = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pointer_sum(rdi, rsi):
    """Decoded rule of the window, for edge checks only.

    A restatement of the retained bytes, not execution: the first je skips
    the subtract-0xc lea when rdi is zero, and the second je skips the
    fall-through ret (whose rax already holds rdi+rsi-0xc) when rsi is
    zero, landing on the sum lea. Both leas wrap mod 2^64.
    """
    if rdi == 0 or rsi == 0:
        return (rdi + rsi) & MASK64
    return (rdi + rsi - 0xc) & MASK64


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
    require(body == BODY, 'Pointer-sum instruction window changed')
    require(read(END, STRIDE_END - END) == PADDING,
            'Stride padding changed')
    eh = by_name['.eh_frame']

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    check_fde(0x2a4160, FDE, START, END)
    require(read(eh['address'] + 0x6205d0, len(NEXT_CIE)) == NEXT_CIE,
            'Next/caller CIE changed')
    check_fde(0x63c9c8, NEXT_FDE, STRIDE_END, 0x521cc96)
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x521cc40.
    require(body[0:4] == bytes.fromhex('f30f1efa'), 'Endbr64 changed')
    require(body[4:7] == bytes.fromhex('4885ff'), 'First zero test changed')
    require(body[7:9] == bytes.fromhex('740f'), 'First branch changed')
    require(struct.unpack_from('<b', body, 8)[0] == 0x0f,
            'First branch displacement changed')
    require(START + 9 + 0x0f == 0x521cc58, 'First branch lands off sum lea')
    require(body[9:14] == bytes.fromhex('488d4437f4'),
            'Subtract lea changed')
    require(struct.unpack_from('<b', body, 13)[0] == -0xc,
            'Subtract constant changed')
    require(body[14:17] == bytes.fromhex('4885f6'),
            'Second zero test changed')
    require(body[17:19] == bytes.fromhex('7405'), 'Second branch changed')
    require(struct.unpack_from('<b', body, 18)[0] == 0x05,
            'Second branch displacement changed')
    require(START + 19 + 0x05 == 0x521cc58,
            'Second branch lands off sum lea')
    require(body[19:20] == bytes.fromhex('c3'), 'First return changed')
    require(body[20:24] == bytes.fromhex('0f1f4000'),
            'Intra-body nopl changed')
    require(body[24:28] == bytes.fromhex('488d0437'), 'Sum lea changed')
    require(body[28:29] == bytes.fromhex('c3'), 'Second return changed')
    # Data edge: no relocation record of any type in any .rela.* section
    # names this window as addend (full-section scan).
    naming = []
    for name, sec in by_name.items():
        if name.startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((address, info & 0xffffffff))
    require(naming == [], 'Naming relocation changed')
    # Incoming calls: exactly three direct e8 calls in .text. This is a
    # byte-pattern scan, explicitly not a complete xref census. The sites
    # were confirmed as instruction starts by linear disassembly from their
    # caller FDE starts with GNU objdump; the checker pins the call bytes,
    # the rel32 targets, caller-FDE containment, and caller FDE records.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == [c[0] for c in CALLERS], 'Incoming direct calls changed')
    for site, call_bytes, (fde_start, fde_end), fde_off, fde_raw in CALLERS:
        require(read(site, 5) == call_bytes, 'Caller call bytes changed')
        rel = struct.unpack_from('<i', call_bytes, 1)[0]
        require(site + 5 + rel == START, 'Caller call target changed')
        require(fde_start <= site < fde_end, 'Caller FDE containment changed')
        check_fde(fde_off, fde_raw, fde_start, fde_end)
    # Decoded-rule edges (restatement of the retained bytes, not execution).
    require(pointer_sum(0, 0) == 0, 'Zero-zero edge changed')
    require(pointer_sum(0, 0x1000) == 0x1000, 'Zero-first edge changed')
    require(pointer_sum(0x1000, 0) == 0x1000, 'Zero-second edge changed')
    require(pointer_sum(0x1000, 0x20) == 0x1014, 'Both-nonzero edge changed')
    require(pointer_sum(0x10, 0x4) == 0x8, 'Small-sum edge changed')
    require(pointer_sum(1, 1) == (2 - 0xc) & MASK64,
            'Wrapping edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'call_sites': direct,
        'naming': naming,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 '
                    'pointer-sum gate evidence packet.')
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
        require(retained['function']['padding_bytes'] == 1, 'Retained padding changed')
        require(retained['function']['padding_stride_end'] == hex(STRIDE_END),
                'Retained stride end changed')
        require([int(s, 16) for s in retained['incoming_pattern_scan']['e8_candidates']]
                == result['call_sites'], 'Retained call sites changed')
        require(retained['naming_relocation'] is None, 'Retained naming changed')
    print('Foundation pointer-sum evidence reproduces exactly.')


if __name__ == '__main__':
    main()
