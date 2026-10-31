#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 field-walk shift evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window has no outgoing calls: it walks two pointers from rdi, subtracts
two 64-bit fields loaded from the same base, arithmetic-shifts the difference
right by 4, stores the result through rsi, and returns 1. The fields' meaning,
the pointers' provenance, and any caller behavior are not claimed anywhere.

No scout correction was needed: every scouted element verified exactly (FDE
range, 42-byte body, all nine instructions, zero direct callers, no naming
relocation). The scout shorthand is made precise here: the subtraction is of
two loaded values (both read from the same walked base), the store destination
is (rsi), and the shift is arithmetic (sar), not logical.

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
START, END = 0x514ab20, 0x514ab4a
BODY = bytes.fromhex(
    'f30f1efa488b8788070000488b5030488b82200b0000482b82180b000048c1f804'
    '488906b801000000c3')
PADDING = bytes.fromhex('cccccccccccc')
STRIDE_END = 0x514ab50
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
# The CIE and FDE encodings are zR: initial_location is a 4-byte signed
# PC-relative value under the CIE's zR encoding; range is a 4-byte unsigned
# value.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000b4a0290050f51c042a00000000000000')
NEXT_FDE = bytes.fromhex('10000000c8a029006cf51c041400000000000000')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def store_value(field_b20, field_b18):
    """Decoded rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. The subtraction wraps modulo
    2^64, and sar shifts the signed 64-bit difference right by 4, so a
    negative difference sign-extends (e.g. a difference of -16 stores -1).
    The window always returns 1, regardless of the stored value.
    """
    diff = (field_b20 - field_b18) % (1 << 64)
    signed = diff - (1 << 64) if diff >= (1 << 63) else diff
    return (signed >> 4) % (1 << 64)


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
    require(body == BODY, 'Field-walk-shift instruction window changed')
    require(read(END, STRIDE_END - END) == PADDING, 'Stride padding changed')
    eh = by_name['.eh_frame']

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    check_fde(0x29a0b0, FDE, START, END)
    check_fde(0x29a0c4, NEXT_FDE, STRIDE_END, 0x514ab64)
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x514ab20.
    require(body[0:4] == bytes.fromhex('f30f1efa'), 'Endbr64 changed')
    require(body[4:11] == bytes.fromhex('488b8788070000'),
            'First pointer load changed')
    require(struct.unpack_from('<i', body, 7)[0] == 0x788,
            'First pointer displacement changed')
    require(body[11:15] == bytes.fromhex('488b5030'),
            'Second pointer load changed')
    require(body[14] == 0x30, 'Second pointer displacement changed')
    require(body[15:22] == bytes.fromhex('488b82200b0000'),
            'First field load changed')
    require(struct.unpack_from('<i', body, 18)[0] == 0xb20,
            'First field offset changed')
    require(body[22:29] == bytes.fromhex('482b82180b0000'),
            'Field subtraction changed')
    require(struct.unpack_from('<i', body, 25)[0] == 0xb18,
            'Second field offset changed')
    require(body[29:33] == bytes.fromhex('48c1f804'), 'Shift changed')
    require(body[32] == 0x04, 'Shift amount changed')
    require(body[33:36] == bytes.fromhex('488906'), 'Store changed')
    require(body[36:41] == bytes.fromhex('b801000000'),
            'Return immediate changed')
    require(body[41:42] == bytes.fromhex('c3'), 'Return changed')
    # Data edge: no relocation record in any .rela.* section names this
    # window as addend (full-section scan).
    naming = []
    for name, sec in by_name.items():
        if name.startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((address, info & 0xffffffff))
    require(naming == [], 'Naming relocation changed')
    # Incoming calls: zero direct e8 calls in .text. This is a byte-pattern
    # scan, explicitly not a complete xref census.
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
    # Decoded-rule edges (restatement of the retained bytes, not execution).
    require(store_value(0x100, 0x0) == 0x10, 'Positive edge changed')
    require(store_value(0x0, 0x10) == (1 << 64) - 1, 'Negative edge changed')
    require(store_value(0x0, 0x0) == 0, 'Zero edge changed')
    require(store_value(0x1, 0x0) == 0, 'Sub-shift edge changed')
    require(store_value(0xFFFFFFFFFFFFFFFF, 0x0) == (1 << 64) - 1,
            'Minus-one edge changed')
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
        description='Verify a digest-bound, static node #94 field-walk-shift '
                    'evidence packet.')
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
        require(retained['incoming_pattern_scan']['e8_candidates']
                == [hex(v) for v in result['call_sites']], 'Retained callers changed')
        require(retained['naming_relocation']['slot'] is None,
                'Retained naming slot changed')
        print('Foundation field-walk-shift evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
