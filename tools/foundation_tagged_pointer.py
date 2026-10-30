#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 tagged-pointer decision-tree packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window reads one qword field and returns one of four (rax, rdx) pairs
selected by three magic constants. The meaning of the field, of the constants,
and of the two data pointers is not claimed anywhere.
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
START, END = 0x15d65b0, 0x15d65f3
PAD_END = 0x15d6600
BODY = bytes.fromhex(
    '488b0f48ba02000000000000804839d1731a4889f84889ca48f7da7012'
    '48ba01000000000000804839d1750f31c0c34883c008488d15be050a04'
    'c3488d152e060a04c3')
PAD = b'\xcc' * 13
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000064d8010030788d004300000000000000')
NEXT_FDE = bytes.fromhex('1000000078d801006c788d000300000000000000')
# One R_X86_64_RELATIVE slot names this window as addend. The file stores 0
# in the .data.rel.ro slot; the loader writes the window address at load time.
SLOTS = [0x5678ee8]
PTR_ZERO_TAG = 0x5676c20
PTR_NEG_TAG = 0x5676ba8


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decide(v):
    """Decoded decision tree of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. The first element is what rax
    holds on return: 'zero' for xor eax,eax, 'base' for rdi, 'base+8' for
    rdi+8. The second element is what rdx holds on return.
    """
    require(0 <= v < 1 << 64, 'Value outside the u64 field domain')
    if v >= 0x8000000000000002:
        return ('zero', 0x8000000000000002)
    if v == 0x8000000000000000:
        return ('base+8', PTR_NEG_TAG)
    if v == 0x8000000000000001:
        return ('zero', 0x8000000000000001)
    return ('base', PTR_ZERO_TAG)


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
    require(body == BODY, 'Tagged-pointer instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in [(0x1d860, FDE, START, END),
                                    (0x1d874, NEXT_FDE, 0x15d6600, 0x15d6603)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x15d65b0.
    require(body[0:3] == bytes.fromhex('488b0f'), 'Field load changed')
    require(body[3:13] == bytes.fromhex('48ba0200000000000080'),
            'High-tag constant changed')
    require(body[13:16] == bytes.fromhex('4839d1'), 'High-tag compare changed')
    require(body[16:18] == bytes.fromhex('731a'), 'High-tag branch changed')
    require(0x15d65c2 + struct.unpack_from('<b', body, 17)[0] == 0x15d65dc,
            'High-tag branch target changed')
    require(body[18:21] == bytes.fromhex('4889f8'), 'Base move changed')
    require(body[21:24] == bytes.fromhex('4889ca'), 'Value copy changed')
    require(body[24:27] == bytes.fromhex('48f7da'), 'Negate changed')
    require(body[27:29] == bytes.fromhex('7012'), 'Overflow branch changed')
    require(0x15d65cd + struct.unpack_from('<b', body, 28)[0] == 0x15d65df,
            'Overflow branch target changed')
    require(body[29:39] == bytes.fromhex('48ba0100000000000080'),
            'Unit-tag constant changed')
    require(body[39:42] == bytes.fromhex('4839d1'), 'Unit-tag compare changed')
    require(body[42:44] == bytes.fromhex('750f'), 'Unit-tag branch changed')
    require(0x15d65dc + struct.unpack_from('<b', body, 43)[0] == 0x15d65eb,
            'Unit-tag branch target changed')
    require(body[44:46] == bytes.fromhex('31c0'), 'Zero return changed')
    require(body[46] == 0xc3, 'Zero-path return changed')
    require(body[47:51] == bytes.fromhex('4883c008'), 'Base-plus-8 changed')
    require(body[51:58] == bytes.fromhex('488d15be050a04'),
            'Neg-tag pointer load changed')
    require(0x15d65ea + struct.unpack_from('<i', body, 54)[0] == PTR_NEG_TAG,
            'Neg-tag pointer target changed')
    require(body[58] == 0xc3, 'Neg-path return changed')
    require(body[59:66] == bytes.fromhex('488d152e060a04'),
            'Zero-tag pointer load changed')
    require(0x15d65f2 + struct.unpack_from('<i', body, 62)[0] == PTR_ZERO_TAG,
            'Zero-tag pointer target changed')
    require(body[66] == 0xc3, 'Base-path return changed')
    # No calls inside the window: none of the locked instruction starts is a
    # call opcode, and the full locked body contains no e8 call opcode at an
    # instruction boundary (the fixed-offset locks above pin every boundary).
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    # Relocations: exactly one RELATIVE slot names this window; the file
    # stores 0 in the .data.rel.ro slot, applied only at load time.
    relsec = by_name['.rela.dyn']
    require(relsec['size'] % 24 == 0, 'Truncated RELA section')
    rels = {}
    raw = read(relsec['address'], relsec['size'])
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        require(address not in rels, 'Duplicate relocation address')
        rels[address] = (info, addend)
    window_slots = [a for a, (info, addend) in rels.items()
                    if info == 8 and addend == START]
    require(window_slots == SLOTS, 'Relocation slots naming window changed')
    for slot in SLOTS:
        slot_secs = [s for s in secs if s['address'] <= slot
                     < s['address'] + s['size']]
        require(len(slot_secs) == 1 and slot_secs[0]['name'] == '.data.rel.ro',
                'Relocation slot section changed')
        require(struct.unpack_from('<Q', read(slot, 8), 0)[0] == 0,
                'Relocation slot file value changed')
    # The two lea targets live in .data.rel.ro; their file values are 0 and
    # their meanings are not claimed.
    for ptr in (PTR_NEG_TAG, PTR_ZERO_TAG):
        ptr_secs = [s for s in secs if s['address'] <= ptr
                    < s['address'] + s['size']]
        require(len(ptr_secs) == 1 and ptr_secs[0]['name'] == '.data.rel.ro',
                'Pointer target section changed')
        require(struct.unpack_from('<Q', read(ptr, 8), 0)[0] == 0,
                'Pointer target file value changed')
    # Incoming calls: no direct e8 call anywhere in .text.
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
    # Decoded-tree edges (restatement of the retained bytes, not execution).
    require(decide(0) == ('base', PTR_ZERO_TAG), 'Zero edge changed')
    require(decide(2) == ('base', PTR_ZERO_TAG), 'Small-value edge changed')
    require(decide(0x7fffffffffffffff) == ('base', PTR_ZERO_TAG),
            'Max-positive edge changed')
    require(decide(0x8000000000000000) == ('base+8', PTR_NEG_TAG),
            'Neg-overflow edge changed')
    require(decide(0x8000000000000001) == ('zero', 0x8000000000000001),
            'Unit-tag edge changed')
    require(decide(0x8000000000000002) == ('zero', 0x8000000000000002),
            'High-tag edge changed')
    require(decide(0xffffffffffffffff) == ('zero', 0x8000000000000002),
            'Max-value edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'relocation_slots': [hex(a) for a in SLOTS],
        'direct_callers': direct,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 tagged-pointer '
                    'decision-tree evidence packet.')
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
        require(retained['incoming_pattern_scan']['e8_candidates'] == [],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation tagged-pointer evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
