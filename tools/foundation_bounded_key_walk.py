#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 bounded key-walk packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window walks a node chain while the next node's +0xe6 word does not exceed
the current node's +0xe4 word, counting steps, and stores a three-qword triple
whose exact contents differ per path (see bounded_key_walk). What the nodes,
words, or key MEAN is not claimed anywhere.
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
START, END = 0x1b26100, 0x1b2616a
PAD_END = 0x1b26170
BODY = bytes.fromhex(
    '4889f8' '488b16' '488b4e08' '488b7610' '0fb7bae6000000' '4839fe' '7316'
    '4889d7' '488938' '48894808' '48897010' 'c3'
    '0f1f8000000000'
    '488b3a' '4885ff' '7422' '48ffc1' '0fb7b2e4000000' '4889fa'
    '663bb7e6000000' '73e2' '488938' '48894808' '48897010' 'c3'
    '48895008' '48894810' '48c70000000000' 'c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000070e502007466e1006a00000000000000')
NEXT = bytes.fromhex('1000000084e50200d066e100ca00000000000000')
CALLER = bytes.fromhex(
    '50000000bceb1000c49f4a01bd0300000433a593ff410e10420e18420e20420e28420e30410e3847'
    '0ed00183078c068d058e048f0386020347030e38410e30420e28420e20420e18420e10410e08410ed0010000')
CALLER_START, CALLER_END = 0x25767b0, 0x2576b6d
CALL_SITE = 0x2576999


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bounded_key_walk(nodes, start, index, key):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. nodes maps a node id to
    (next_or_None, word_at_0xe4, word_at_0xe6); all words are unsigned
    16-bit values, matching the zero-extending movzwl loads. The stored
    triple's third field DIFFERS per path, and that difference is the
    point: path 1 stores the input key, but the walk loop's movzwl
    clobbers rsi, so path 2 stores the previous node's +0xe4 gate word
    instead, and path 3 stores the last index. A scout note describing
    all three paths as storing "(node, steps, key)" is wrong for paths
    2 and 3; this model encodes the bytes, not the note.
    """
    node, idx = start, index
    if key < nodes[node][2]:
        return (node, idx, key)
    while True:
        nxt = nodes[node][0]
        if nxt is None:
            return (0, node, idx)
        idx += 1
        gate = nodes[node][1]
        node = nxt
        if nodes[node][2] <= gate:
            continue
        return (node, idx, gate)


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
    require(body == BODY, 'Bounded key-walk window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    check_fde(0x2e56c, FDE, START, END)
    check_fde(0x2e580, NEXT, PAD_END, 0x1b2623a)
    check_fde(0x3eb2cc, CALLER, CALLER_START, CALLER_END)
    # Padding: six int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 6, 'Padding changed')
    require(PAD_END == 0x1b26170, 'FDE stride end changed')
    # Preceding gap: eight int3 bytes after the previous FDE ends.
    require(read(START - 8, 8) == b'\xcc' * 8, 'Preceding gap changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x1b26100.
    fixed = [
        (0x00, '4889f8', 'Out-pointer save changed'),
        (0x03, '488b16', 'First-node load changed'),
        (0x06, '488b4e08', 'Index load changed'),
        (0x0a, '488b7610', 'Key load changed'),
        (0x0e, '0fb7bae6000000', 'First gate-word load changed'),
        (0x15, '4839fe', 'Path-1 gate compare changed'),
        (0x18, '7316', 'Path-1 walk branch changed'),
        (0x1a, '4889d7', 'Path-1 node move changed'),
        (0x1d, '488938', 'Path-1 node store changed'),
        (0x20, '48894808', 'Path-1 index store changed'),
        (0x24, '48897010', 'Path-1 key store changed'),
        (0x28, 'c3', 'Path-1 return changed'),
        (0x29, '0f1f8000000000', 'Inter-path alignment padding changed'),
        (0x30, '488b3a', 'Next-node load changed'),
        (0x33, '4885ff', 'Exhaustion test changed'),
        (0x36, '7422', 'Exhaustion branch changed'),
        (0x38, '48ffc1', 'Step increment changed'),
        (0x3b, '0fb7b2e4000000', 'Gate-word load changed'),
        (0x42, '4889fa', 'Node advance changed'),
        (0x45, '663bb7e6000000', 'Walk gate compare changed'),
        (0x4c, '73e2', 'Walk branch changed'),
        (0x4e, '488938', 'Path-2 node store changed'),
        (0x51, '48894808', 'Path-2 index store changed'),
        (0x55, '48897010', 'Path-2 gate-word store changed'),
        (0x59, 'c3', 'Path-2 return changed'),
        (0x5a, '48895008', 'Exhausted node store changed'),
        (0x5e, '48894810', 'Exhausted index store changed'),
        (0x62, '48c70000000000', 'Exhausted zero store changed'),
        (0x69, 'c3', 'Exhausted return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # Branch targets: jae at 0x18 lands on the walk loop; je at 0x36 lands
    # on the exhausted path; jae at 0x4c loops back to the walk loop.
    def rel8(pos):
        b = body[pos]
        return b if b < 0x80 else b - 256
    require(START + 0x18 + 2 + rel8(0x19) == 0x1b26130,
            'Path-1 branch target changed')
    require(START + 0x36 + 2 + rel8(0x37) == 0x1b2615a,
            'Exhaustion branch target changed')
    require(START + 0x4c + 2 + rel8(0x4d) == 0x1b26130,
            'Walk branch target changed')
    # No call opcode at any instruction start inside the window; all three
    # paths fall through to their own ret.
    starts = {off for off, _, _ in fixed}
    for pos, byte in enumerate(body):
        if pos in starts:
            require(byte != 0xe8, 'Unexpected call opcode in window')
    # Relocations: no R_X86_64_RELATIVE record names this window as addend.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append([sec['name'], hex(address)])
    require(naming == [], 'Relocation slots naming window changed')
    # Incoming calls: direct e8 call sites anywhere in .text landing on
    # this window; exactly one, inside the retained caller FDE.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == [CALL_SITE], 'Incoming direct callers changed')
    require(CALLER_START <= CALL_SITE < CALLER_END,
            'Call site outside caller FDE')
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    # Path 1: key below the first gate word stores (node, index, key).
    require(bounded_key_walk({'a': (None, 10, 5)}, 'a', 3, 4) == ('a', 3, 4),
            'Path-1 edge changed')
    # Path 2: the walk stops when the next gate word exceeds the current
    # gate word, and the stored third field is the GATE WORD (10), not the
    # input key (5) — the loop's movzwl clobbered rsi.
    require(bounded_key_walk({'a': ('b', 10, 5), 'b': (None, 7, 20)},
                             'a', 3, 5) == ('b', 4, 10),
            'Path-2 edge changed')
    # Path 3: an exhausted chain stores (0, last node, last index).
    require(bounded_key_walk({'a': (None, 10, 5)}, 'a', 3, 9) == (0, 'a', 3),
            'Exhausted edge changed')
    # Multi-step walk: two gates pass, then the chain ends.
    require(bounded_key_walk({'a': ('b', 10, 9), 'b': ('c', 30, 8),
                              'c': (None, 1, 25)}, 'a', 0, 9) == (0, 'c', 2),
            'Multi-step edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'relocation_slots': naming,
        'direct_callers': direct,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 '
                    'bounded key-walk evidence packet.')
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
        require(retained['function']['padding_bytes'] == 6, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation bounded-key-walk evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
