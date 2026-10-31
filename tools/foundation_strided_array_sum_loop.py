#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 strided-array sum loop packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window sums count = 1 << [rdi+0x68] qwords at base + i*0xce40 + index*8,
i = 0..count-1, in a do-while loop. What the table holds, and what the callers
do with the sum, is not claimed anywhere.
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
START, END = 0x52cfe00, 0x52cfe4d
PAD_END = 0x52cfe4e
BODY = bytes.fromhex(
    'f30f1efa' '89f6' '4531c0' '31d2' '4531c9' '48c1e603' '41ba01000000'
    '0f1f840000000000' '488b4760' '4883c201' '4c01c0' '4981c040ce0000'
    '4801f0' '488b00' '4901c1' '4c89d0' '8b4f68' '48d3e0' '4839c2' '72d7'
    '4c89c8' 'c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000098cc2a004c1c34044d00000000000000')
NEXT = bytes.fromhex('1c00000074b60200ee2cfa03100000000453688bff0e20830486038c02000000')
CALLER_FDES = [
    (0x64bc10, bytes.fromhex(
        '2c00000044b60200302dfa03420000000477688bff460e108c02450e188603430e208304640a0e18410e10420e08410b'),
     0x52cfe60, 0x52cfea2),
    (0x64bd94, bytes.fromhex(
        '70000000c8b702002c2ffa03a50200000456678bff460e108f02420e188e03420e208d04450e288c05410e308606440e388307470e800302780e88034a0e9003640e8803410e800302650e8803490e9003770e8803410e800302d40a0e38440e30410e28420e20420e18420e10420e08410b0000'),
     0x52d01e0, 0x52d0485),
    (0x64c26c, bytes.fromhex(
        '50000000a0bc02007482fa03e50500000489698bff460e108f02420e188e03420e208d04420e288c05410e308606410e388307470ee0010368030a0e38410e30410e28420e20420e18420e10420e08490b000000'),
     0x52d5a00, 0x52d5fe5),
]
CALLERS = [0x52cfe7e, 0x52d0265, 0x52d5b03]
STRIDE_PATTERN = bytes.fromhex('4981c040ce0000')
MASK = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def element_count(field_value):
    """Shift amount is the low 6 bits of the field (cl, hardware-masked)."""
    return 1 << (field_value & 0x3f)


def strided_sum(base, index, field_value, read_qword):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary: sum of element_count(field_value)
    qwords at base + i*0xce40 + index*8, i = 0..count-1. The loop always
    executes at least once (count >= 1, do-while shape). `read_qword`
    maps an address to one unsigned 64-bit word; counts here are small
    by construction of the edge checks.
    """
    count = element_count(field_value)
    require(count <= (1 << 20), 'Edge-check count too large to iterate')
    total = 0
    for i in range(count):
        total = (total + read_qword(base + i * 0xce40 + index * 8)) & MASK
    return total


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
    require(body == BODY, 'Strided-array sum loop window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    check_fde(0x2acc94, FDE, START, END)
    check_fde(0x64bc40, NEXT, PAD_END, 0x52cfe5e)
    for offset, raw, start, end in CALLER_FDES:
        check_fde(offset, raw, start, end)
    # Padding: one int3 byte between the FDE end and the next FDE start,
    # and three int3 bytes before the window (previous FDE ends 0x52cfdfd).
    require(read(END, PAD_END - END) == b'\xcc' * 1, 'Padding changed')
    require(read(START - 3, 3) == b'\xcc' * 3, 'Leading padding changed')
    require(PAD_END == 0x52cfe4e, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x52cfe00.
    fixed = [
        (0x00, 'f30f1efa', 'Entry endbr64 changed'),
        (0x04, '89f6', 'Index zero-extension changed'),
        (0x06, '4531c0', 'Stride cursor init changed'),
        (0x09, '31d2', 'Counter init changed'),
        (0x0b, '4531c9', 'Sum init changed'),
        (0x0e, '48c1e603', 'Index-times-8 changed'),
        (0x12, '41ba01000000', 'Shift-one init changed'),
        (0x18, '0f1f840000000000', 'Loop alignment nop changed'),
        (0x20, '488b4760', 'Base load changed'),
        (0x24, '4883c201', 'Counter increment changed'),
        (0x28, '4c01c0', 'Cursor add changed'),
        (0x2b, '4981c040ce0000', 'Stride add changed'),
        (0x32, '4801f0', 'Index add changed'),
        (0x35, '488b00', 'Element load changed'),
        (0x38, '4901c1', 'Sum add changed'),
        (0x3b, '4c89d0', 'Shift-one move changed'),
        (0x3e, '8b4f68', 'Count field load changed'),
        (0x41, '48d3e0', 'Count shift changed'),
        (0x44, '4839c2', 'Loop compare changed'),
        (0x47, '72d7', 'Loop branch changed'),
        (0x49, '4c89c8', 'Return move changed'),
        (0x4c, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # No call opcode at any instruction start inside the window; the only
    # transfer is the backward conditional loop branch.
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
    # Stride uniqueness: the 0xce40-stride add occurs exactly once in .text.
    stride_hits = []
    pos = 0
    while (pos := code.find(STRIDE_PATTERN, pos)) >= 0:
        stride_hits.append(text['address'] + pos)
        pos += 1
    require(stride_hits == [0x52cfe2b], 'Stride pattern uniqueness changed')
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    mem = {0x1000: 5, 0x1000 + 0xce40: 7, 0x1000 + 2 * 0xce40: 11,
           0x1008: 3, 0x1008 + 0xce40: 4}
    require(element_count(0) == 1, 'Zero count edge changed')
    require(element_count(1) == 2, 'Count-one edge changed')
    require(element_count(0x3f) == (1 << 63), 'Count-mask edge changed')
    require(element_count(0x40) == 1, 'Count-wrap edge changed')
    require(strided_sum(0x1000, 0, 0, mem.__getitem__) == 5,
            'Single-element edge changed')
    require(strided_sum(0x1000, 0, 1, mem.__getitem__) == 12,
            'Two-element edge changed')
    require(strided_sum(0x1000, 0, 2, lambda a: mem.get(a, 0)) == 23,
            'Four-element edge changed')
    require(strided_sum(0x1000, 1, 1, mem.__getitem__) == 7,
            'Index-offset edge changed')
    require(strided_sum(0x1000, 0, 1,
                        lambda a: (1 << 64) - 1 if a == 0x1000 else 2) == 1,
            'Wrapping edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'relocation_slots': [[name, hex(addr)] for name, addr in naming],
        'direct_callers': direct,
        'stride_hits': stride_hits,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 '
                    'strided-array sum loop evidence packet.')
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
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation strided-array-sum-loop evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
