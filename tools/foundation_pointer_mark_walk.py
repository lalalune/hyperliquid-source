#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 pointer-mark walk packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window walks, per entry, a [entry+0x8f8] chain, overwriting [node+0xcc8]
with a mark value while the field still equals the 0x00ffffffffffffff mask.
What the fields mean, and what the callers do with the walk, is not claimed
anywhere.
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
START, END = 0x50e69f0, 0x50e6a82
PAD_END = 0x50e6a90
MASK = 0x00ffffffffffffff
M64 = 0xffffffffffffffff
BODY = bytes.fromhex(
    'f30f1efa488b47684989f3488bb8080100004c8b4e504c8b56584d29ca49c1fa03'
    '4c0316746b4983e9404531c048beffffffffffffff00660f1f8400000000004c89c8'
    '4983f8077708498b43484a8d04c0488b00488b88f8080000488b014839c87514eb1f'
    '0f1f00488b004889bac80c00004839c8740d488b50104839b2c80c000074e44983c0'
    '014983c1084d39c275afc3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000f47d2900e0d616049200000000000000')
NEXT = bytes.fromhex('10000000087e29006cd716042400000000000000')
CIE2 = bytes.fromhex('1c00000000000000017a504c5200017810079b3d5848041b1b0c070890010000')
CALLER_FDES = [
    # (eh_frame offset, raw, start, end)
    (0x629b64,
     bytes.fromhex('50000000989500004c59d3031d1500000409568cff460e108f02450e188e03420e208d04420e288c05410e308606410e388307470e800d033b0b0a0e38410e30410e28420e20420e18420e10420e08430b000000'),
     0x50409d0, 0x5041eed),
    (0x630268,
     bytes.fromhex('380000009cfc000028a8dd03270a0000043d3d8cff450e108602430d06448f038e04488d058c06830702bd2e1002be2e000307040a0c07084a0b0000'),
     0x50ebfb0, 0x50ec9d7),
    (0x6302c8,
     bytes.fromhex('50000000fcfc0000a8b2dd037309000004303d8cff460e108f02420e188e03420e208d04420e288c05410e308606440e3883074a0e90050367060a0e38440e30410e28420e20420e18420e10420e08410b000000'),
     0x50eca90, 0x50ed403),
    (0x630340,
     bytes.fromhex('5000000074fd000050bcdd03f008000004fb3c8cff460e108f02420e188e03490e208d04420e288c05440e308606410e3883074a0e900503c8050a0e38440e30410e28420e20420e18420e10420e08410b000000'),
     0x50ed4b0, 0x50edda0),
]
CALLERS = [
    # (call site, call bytes, setup bytes immediately before the call)
    (0x5041978, bytes.fromhex('e873500a00'), bytes.fromhex('4c8da424b0010000')),
    (0x50ec3cb, bytes.fromhex('e820a6ffff'), bytes.fromhex('4c8dbdc0feffff')),
    (0x50ecf60, bytes.fromhex('e88b9affff'), bytes.fromhex('4c8dbc2440010000')),
    (0x50edac8, bytes.fromhex('e8238fffff'), bytes.fromhex('4c89f6')),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def walk(mem, rdi_in, rsi):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. Mutates and returns the memory dict.
    """
    m = dict(mem)
    mark = m[m[rdi_in + 0x68] + 0x108]
    diff = (m[rsi + 0x58] - m[rsi + 0x50]) & M64
    signed = diff - (1 << 64) if diff & (1 << 63) else diff
    n = (m[rsi] + (signed >> 3)) & M64
    if n == 0:
        return m
    r9 = (m[rsi + 0x50] - 0x40) & M64
    i = 0
    while i != n:
        if i <= 7:
            slot = (m[rsi + 0x48] + 8 * i) & M64
        else:
            slot = r9
        entry = m[slot]
        rcx = m[entry + 0x8f8]
        cur = m[rcx]
        if cur != rcx:
            while True:
                node = m[cur + 0x10]
                if m[node + 0xcc8] != MASK:
                    break
                cur = m[cur]
                m[node + 0xcc8] = mark
                if cur == rcx:
                    break
        i += 1
        r9 = (r9 + 8) & M64
    return m


def layout(entries):
    """Build a synthetic memory for walk() edge checks.

    entries: list of per-entry chain shapes; each shape is 'empty' or a list
    of per-link node marks ('mask' or 'other'). The outer count is len(entries)
    via s0 = min(8, len) plus a second-array count for the rest.
    """
    mem = {}
    base = 0x100000000
    s = base
    a_arr = base + 0x100
    b_arr = base + 0x200
    mid = base + 0x400
    rdi_obj = base + 0x600
    mem[rdi_obj + 0x68] = mid
    mem[mid + 0x108] = 0x4242424242424242
    n = len(entries)
    s0 = min(8, n)
    bcount = n - s0
    mem[s] = s0
    mem[s + 0x48] = a_arr
    mem[s + 0x50] = b_arr
    mem[s + 0x58] = b_arr + 8 * bcount
    nxt = base + 0x1000
    nodes = []
    for i, shape in enumerate(entries):
        entry = nxt
        nxt += 0x1000
        if i < 8:
            mem[a_arr + 8 * i] = entry
        else:
            mem[b_arr + 8 * (i - 8)] = entry
        head = nxt
        nxt += 0x100
        mem[entry + 0x8f8] = head
        if shape == 'empty':
            mem[head] = head
            continue
        prev = head
        for mk in shape:
            link = nxt
            nxt += 0x100
            node = nxt
            nxt += 0x1000
            nodes.append(node)
            mem[prev] = link
            mem[link + 0x10] = node
            mem[node + 0xcc8] = MASK if mk == 'mask' else 0x1111
            prev = link
        mem[prev] = head
    return mem, rdi_obj, s, nodes


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
    require(body == BODY, 'Pointer-mark-walk instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    require(read(eh['address'] + 0x6205d0, len(CIE2)) == CIE2,
            'Caller CIE changed')
    for offset, raw, start, end in [(0x297df0, FDE, START, END),
                                    (0x297e04, NEXT, PAD_END, 0x50e6ab4)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    for offset, raw, start, end in CALLER_FDES:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'Caller FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'Caller FDE PC/range changed')
    # Padding: fourteen int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 14, 'Padding changed')
    require(PAD_END == 0x50e6a90, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x50e69f0.
    fixed = [
        (0, 'f30f1efa', 'Entry endbr64 changed'),
        (4, '488b4768', 'Mark-base load changed'),
        (11, '488bb808010000', 'Mark-value load changed'),
        (18, '4c8b4e50', 'Second-array begin load changed'),
        (29, '49c1fa03', 'Count shift changed'),
        (0x24, '746b', 'Count-zero branch changed'),
        (0x2d, '48beffffffffffffff00', 'Mask movabs changed'),
        (0x37, '660f1f840000000000', 'Loop-head nopw changed'),
        (0x40, '4c89c8', 'Entry-address select changed'),
        (0x43, '4983f807', 'Eight-entry gate changed'),
        (0x47, '7708', 'Array-select branch changed'),
        (0x51, '488b00', 'Entry load changed'),
        (0x54, '488b88f8080000', 'Head load changed'),
        (0x5e, '4839c8', 'Head self-compare changed'),
        (0x61, '7514', 'Walk-entry branch changed'),
        (0x65, '0f1f00', 'Mark-step nopl changed'),
        (0x6b, '4889bac80c0000', 'Mark store changed'),
        (0x77, '488b5010', 'Node load changed'),
        (0x7b, '4839b2c80c0000', 'Mask compare changed'),
        (0x82, '74e4', 'Mark-step branch changed'),
        (0x84, '4983c001', 'Counter increment changed'),
        (0x8c, '4d39c2', 'Loop-end compare changed'),
        (0x8f, '75af', 'Loop-back branch changed'),
        (0x91, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # No call opcode byte anywhere inside the window.
    require(b'\xe8' not in body, 'Unexpected call opcode byte in window')
    # Caller call bytes and setups at fixed sites.
    for site, call_bytes, setup in CALLERS:
        require(read(site, 5) == call_bytes, 'Caller call bytes changed')
        require(read(site - len(setup), len(setup)) == setup,
                'Caller setup changed')
    # Relocations: no record of any type names this window as addend.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((sec['name'], address))
    require(naming == [], 'Unexpected naming relocation')
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
    require(direct == [c[0] for c in CALLERS], 'Incoming direct calls changed')
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    mem, rdi_obj, s, _ = layout([])
    require(walk(mem, rdi_obj, s) == mem, 'Zero-count edge changed')
    mem, rdi_obj, s, _ = layout(['empty'])
    require(walk(mem, rdi_obj, s) == mem, 'Empty-head edge changed')
    mem, rdi_obj, s, nodes = layout([['mask']])
    out = walk(mem, rdi_obj, s)
    require(out[nodes[0] + 0xcc8] == 0x4242424242424242, 'Mask-node edge changed')
    mem, rdi_obj, s, nodes = layout([['other']])
    out = walk(mem, rdi_obj, s)
    require(out[nodes[0] + 0xcc8] == 0x1111, 'Non-mask edge changed')
    mem, rdi_obj, s, nodes = layout([['mask', 'other']])
    out = walk(mem, rdi_obj, s)
    require(out[nodes[0] + 0xcc8] == 0x4242424242424242
            and out[nodes[1] + 0xcc8] == 0x1111, 'Mask-then-other edge changed')
    mem, rdi_obj, s, nodes = layout([['mask']] * 9)
    out = walk(mem, rdi_obj, s)
    require(len(nodes) == 9
            and all(out[n + 0xcc8] == 0x4242424242424242 for n in nodes),
            'Nine-entry boundary edge changed')
    # Self-loop link: a link whose +0x00 points to itself marks its mask
    # node once, then stops on the revisit (field no longer equals the mask).
    base = 0x100000000
    mem = {}
    mem[base + 0x600 + 0x68] = base + 0x400
    mem[base + 0x400 + 0x108] = 0x4242424242424242
    mem[base] = 1
    mem[base + 0x48] = base + 0x100
    mem[base + 0x50] = base + 0x200
    mem[base + 0x58] = base + 0x200
    mem[base + 0x100] = base + 0x800
    mem[base + 0x800 + 0x8f8] = base + 0x1000
    mem[base + 0x1000] = base + 0x1200
    mem[base + 0x1200] = base + 0x1200
    mem[base + 0x1200 + 0x10] = base + 0x1400
    mem[base + 0x1400 + 0xcc8] = MASK
    out = walk(mem, base + 0x600, base)
    require(out[base + 0x1400 + 0xcc8] == 0x4242424242424242,
            'Self-loop edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'relocation_slots': [],
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
                    'pointer-mark walk evidence packet.')
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
        require(retained['function']['padding_bytes'] == 14, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation pointer-mark-walk evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
