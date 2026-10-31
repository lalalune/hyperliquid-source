#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 flag-gated span advance packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window rewrites one span field only when a flag byte is clear and two
bounds checks pass. What the struct fields mean, and what consumes the
result, is not claimed anywhere.
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
START, END = 0x5293e00, 0x5293e47
PAD_END = 0x5293e50
BODY = bytes.fromhex(
    'f30f1efa' '807e2800' '753c' '8b12' '4c8b06' '488b4e20'
    '488d04d500000000' '4829d0' '48c1e004' '480307' '498d3c08'
    '488b5028' '488b7018' '4c8d0c32' '4939f9' '730c' '4939d0' '7207'
    '4801f1' '48894818' 'c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000849b2a00608d30044700000000000000')
NEXT = bytes.fromhex('10000000989b2a009c8d30042300000000000000')
GATE_PREFIX = bytes.fromhex('f30f1efa807e2800')
MASK = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def span_rule(flag_set, idx, struct_base, base, offset, span_start, span_len):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary: when the flag byte is set, nothing
    changes; otherwise elem = struct_base + idx * 112 and cursor =
    base + offset (all wrapping). The field is rewritten to
    offset + span_len only when span_start + span_len < cursor (unsigned,
    wrapping sum) AND span_start >= base (unsigned); otherwise nothing
    changes. Returns (new_field_value, changed).
    """
    if flag_set:
        return span_len, False
    cursor = (base + offset) & MASK
    if ((span_start + span_len) & MASK) >= cursor:
        return span_len, False
    if span_start < base:
        return span_len, False
    return (offset + span_len) & MASK, True


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
    require(body == BODY, 'Flag-gated span advance window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    for offset, raw, start, end in [
            (0x2a9b80, FDE, START, END),
            (0x2a9b94, NEXT, PAD_END, 0x5293e73)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: nine int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 9, 'Padding changed')
    require(PAD_END == 0x5293e50, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x5293e00.
    fixed = [
        (0x00, 'f30f1efa', 'Entry endbr64 changed'),
        (0x04, '807e2800', 'Flag gate compare changed'),
        (0x08, '753c', 'Flag gate jump changed'),
        (0x0a, '8b12', 'Index load changed'),
        (0x0c, '4c8b06', 'Base load changed'),
        (0x0f, '488b4e20', 'Offset load changed'),
        (0x13, '488d04d500000000', 'Index times eight changed'),
        (0x1b, '4829d0', 'Index times seven changed'),
        (0x1e, '48c1e004', 'Index times 112 shift changed'),
        (0x22, '480307', 'Element address add changed'),
        (0x25, '498d3c08', 'Cursor add changed'),
        (0x29, '488b5028', 'Span start load changed'),
        (0x2d, '488b7018', 'Span length load changed'),
        (0x31, '4c8d0c32', 'Span end add changed'),
        (0x35, '4939f9', 'Span end compare changed'),
        (0x38, '730c', 'Span end jump changed'),
        (0x3a, '4939d0', 'Span start compare changed'),
        (0x3d, '7207', 'Span start jump changed'),
        (0x3f, '4801f1', 'Field value add changed'),
        (0x42, '48894818', 'Field store changed'),
        (0x46, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # No call opcode at any instruction start inside the window; every
    # conditional transfer targets the single ret.
    starts = {off for off, _, _ in fixed}
    for pos, byte in enumerate(body):
        if pos in starts:
            require(byte != 0xe8, 'Unexpected call opcode in window')
    # Relocations: no R_X86_64_RELATIVE record in any .rela.* section
    # names this window as addend.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((sec['name'], address))
    require(naming == [], 'Relocation slots naming window changed')
    # Incoming calls: direct e8 call sites anywhere in .text, plus the
    # gate-prefix uniqueness check (endbr64 + cmpb $0, 0x28(%rsi)).
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == [], 'Unexpected incoming direct call')
    gate_hits = []
    pos = 0
    while (pos := code.find(GATE_PREFIX, pos)) >= 0:
        gate_hits.append(text['address'] + pos)
        pos += 1
    require(gate_hits == [START], 'Gate prefix is no longer unique to this window')
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    require(span_rule(True, 0, 0, 0x1000, 0x200, 0x1000, 0x100) ==
            (0x100, False), 'Flag-set edge changed')
    require(span_rule(False, 0, 0, 0x1000, 0x200, 0x1000, 0x100) ==
            (0x300, True), 'Write edge changed')
    require(span_rule(False, 0, 0, 0x1000, 0x200, 0x1000, 0x200) ==
            (0x200, False), 'Sum-equals-cursor edge changed')
    require(span_rule(False, 0, 0, 0x1000, 0x200, 0x1000, 0x300) ==
            (0x300, False), 'Sum-above-cursor edge changed')
    require(span_rule(False, 0, 0, 0x1000, 0x200, 0x800, 0x100) ==
            (0x100, False), 'Start-below-base edge changed')
    require(span_rule(False, 0, 0, 0x1000, 0x200, (1 << 64) - 0x10, 0x20) ==
            (0x220, True), 'Wrapping-sum edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'relocation_slots': [[name, hex(addr)] for name, addr in naming],
        'direct_callers': direct,
        'gate_prefix_hits': [hex(h) for h in gate_hits],
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 '
                    'flag-gated span advance evidence packet.')
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
        require(retained['function']['padding_bytes'] == 9, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        require(retained['gate_prefix_uniqueness'] ==
                result['gate_prefix_hits'], 'Retained gate prefix hits changed')
        print('Foundation flag-gated-span-advance evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
