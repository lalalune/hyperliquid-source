#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 empty-guarded indexed-load packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.

The window at 0x4fec800 (35 bytes) takes rdi = a container and rsi = an index.
It reads the begin pointer at [rdi + 0x988] and compares it with the end
pointer at [rdi + 0x990]. When the two are equal (an empty container) it
returns 0 (rax = 0). Otherwise it scales the index by the 16-byte element
stride (shl $0x4) and returns the first qword of that element,
[begin + 16*index]. The index is never re-checked against the element count;
the only guard is emptiness. A 0 result is therefore ambiguous: it is produced
both by an empty container and by a non-empty element whose stored first qword
is 0. No source-level type is claimed for the container, the begin/end field
pair, or the element.
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
START, END = 0x4fec800, 0x4fec823
PAD_END = 0x4fec830
BODY = bytes.fromhex(
    'f30f1efa488b8788090000483b8790090000740c48c1e604488b0430c30f1f0031c0c3')
PAD = b'\xcc' * 13
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000050f0280094c2070423000000')
NEXT_FDE = bytes.fromhex('1000000064f02800b0c2070414000000')
BEGIN_OFFSET = 0x988
END_OFFSET = 0x990
ELEMENT_STRIDE = 0x10
# One direct e8 caller inside .text; no tail jumps, no RELATIVE record names
# this window as its addend.
DIRECT_CALLERS = [0x4fb2546]
MASK64 = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def element_offset(index):
    """Byte offset the window loads for a given index: 16 * index."""
    require(index >= 0, 'Index outside the non-negative domain')
    return ELEMENT_STRIDE * index


def indexed_load(empty, element_value=0):
    """Decoded rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. ``empty`` is begin == end;
    ``element_value`` is the u64 the loaded element holds in its first qword
    when the container is non-empty. Returns 0 for the empty path (xor at
    0x4fec820) and the element's first qword otherwise (load at 0x4fec818).
    """
    if empty:
        return 0
    require(0 <= element_value <= MASK64, 'Element value outside the u64 domain')
    return element_value & MASK64


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
    require(body == BODY, 'Indexed-load instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in [(0x28f04c, FDE, START, END),
                                    (0x28f060, NEXT_FDE, 0x4fec830, 0x4fec844)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x4fec800.
    require(body[0:4] == bytes.fromhex('f30f1efa'), 'endbr64 changed')
    require(body[4:7] == bytes.fromhex('488b87'), 'begin-load opcode changed')
    require(struct.unpack_from('<I', body, 7)[0] == BEGIN_OFFSET,
            'begin field offset changed')
    require(body[11:14] == bytes.fromhex('483b87'), 'end-compare opcode changed')
    require(struct.unpack_from('<I', body, 14)[0] == END_OFFSET,
            'end field offset changed')
    require(body[18] == 0x74, 'Empty-guard branch opcode changed')
    require(START + 0x12 + 2 + struct.unpack_from('<b', body, 19)[0] == 0x4fec820,
            'Empty-guard branch target changed')
    require(body[20:23] == bytes.fromhex('48c1e6'), 'Index-scale opcode changed')
    require(body[23] == ELEMENT_STRIDE.bit_length() - 1, 'Index-scale shift changed')
    require(body[24:28] == bytes.fromhex('488b0430'), 'Scaled element load changed')
    require(body[28] == 0xc3, 'Non-empty ret changed')
    require(body[29:32] == bytes.fromhex('0f1f00'), 'Alignment nopl changed')
    require(body[32:34] == bytes.fromhex('31c0'), 'Empty-path xor changed')
    require(body[34] == 0xc3, 'Empty ret changed')
    # No calls inside the window: the fixed-offset locks above pin every
    # instruction boundary, and no e8 byte appears at any of them.
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    require(b'\xff' not in body, 'Unexpected indirect branch in window')
    # Incoming calls: one direct e8 call in .text, no e9 tail jump.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == DIRECT_CALLERS, 'Incoming direct calls changed')
    tail = []
    pos = 0
    while (pos := code.find(b'\xe9', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            tail.append(text['address'] + pos)
        pos += 1
    require(tail == [], 'Incoming tail jumps changed')
    # Relocations: no RELATIVE record names this window as its addend.
    relsec = by_name['.rela.dyn']
    require(relsec['size'] % 24 == 0, 'Truncated RELA section')
    raw = read(relsec['address'], relsec['size'])
    window_slots = []
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        if info == 8 and addend == START:
            window_slots.append(address)
    require(window_slots == [], 'Relocation slots naming window changed')
    # Decoded-rule edges (restatement of the retained bytes, not execution).
    require(indexed_load(True) == 0, 'Empty edge changed')
    require(indexed_load(True, 0x1234) == 0, 'Empty-with-value edge changed')
    require(indexed_load(False, 0x1234) == 0x1234, 'Non-empty edge changed')
    require(indexed_load(False, 0) == 0, 'Zero-element edge changed')
    require(indexed_load(False, MASK64) == MASK64, 'u64-max element edge changed')
    require(element_offset(0) == 0, 'Index-0 offset changed')
    require(element_offset(1) == 0x10, 'Index-1 offset changed')
    require(element_offset(5) == 0x50, 'Index-5 offset changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'begin_offset': hex(BEGIN_OFFSET),
        'end_offset': hex(END_OFFSET),
        'element_stride': ELEMENT_STRIDE,
        'direct_callers': [hex(c) for c in direct],
        'relocation_slots_naming_window': window_slots,
        'text_byte_count': len(code),
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 empty-guarded '
                    'indexed-load evidence packet.')
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
        require(retained['behavior']['begin_offset'] == result['begin_offset'],
                'Retained begin offset changed')
        require(retained['behavior']['end_offset'] == result['end_offset'],
                'Retained end offset changed')
        require(retained['behavior']['element_stride'] == result['element_stride'],
                'Retained element stride changed')
        require(retained['incoming_pattern_scan']['direct_callers'] ==
                result['direct_callers'], 'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots_naming_window'],
                'Retained window slots changed')
        require(retained['incoming_pattern_scan']['byte_count'] ==
                result['text_byte_count'], 'Retained scan size changed')
        print('Foundation empty-guarded indexed-load evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
