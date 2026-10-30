#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 twin take-helper evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.

The two windows share one skeleton (load [rdi] -> rax, load [rax] -> rbx,
zero [rax]; rbx == 0 takes a panic path; byte [rsi+4] == 1 takes a drop path;
otherwise the vtable first slot *(rbx) is called and the value is copied out).
They differ only in the copy: 0x14519c0 copies 0x268 bytes through the memcpy
slot 0x576dfe0, while 0x1451bf0 copies 0x38 bytes inline: 0x30 bytes with three
movups plus an 8-byte tail move. (An early scout note counted only the movups
portion as 0x30; the retained bytes show the tail move extends the copy to
0x38, and the checker locks the full 0x38.)

FDE extents: [0x14519c0, 0x1451a19) is 89 bytes, and seven int3 padding bytes
follow it to the 96-byte unwind-index stride ending at 0x1451a20; the stride
is not the FDE extent. [0x1451bf0, 0x1451c50) is 96 bytes with no padding:
the next FDE starts exactly at 0x1451c50.
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
TARGET_BYTES = 91774280
W1_START, W1_FDE_END, W1_INDEX_END = 0x14519c0, 0x1451a19, 0x1451a20
W2_START, W2_FDE_END = 0x1451bf0, 0x1451c50
W1_BODY = bytes.fromhex(
    '4156534881ec68020000488b07488b1848c700000000004885db742a807e04017431'
    '4989e64c89f7ff13ba680200004889df4c89f6ff15e5c531044881c4680200005b415e'
    'c3488d3dfb8d2104ff155dca3104ff154fce3104')
W1_PADDING = b'\xcc' * 7
W2_BODY = bytes.fromhex(
    '534883ec40488b07488b1848c700000000004885db7436807e0401743d488d7c2408ff'
    '13488b442438488943300f104424080f104c24180f105424280f1153200f114b100f110'
    '34883c4405bc3488d3dc48b2104ff1526c83104ff1518cc3104')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
W1_FDE = bytes.fromhex(
    '28000000d8ad0000cc5676005900000000420e10410e18470e800583038e02780e18410e'
    '10420e08410e8005')
W2_FDE = bytes.fromhex(
    '2000000028ae0000ac5876006000000000410e10440e50830202460e10410e08410e5000')


def require(condition, message):
    if not condition:
        raise ValueError(message)


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

    body1 = read(W1_START, W1_FDE_END - W1_START)
    require(body1 == W1_BODY, 'Take-memcpy instruction window changed')
    require(read(W1_FDE_END, W1_INDEX_END - W1_FDE_END) == W1_PADDING,
            'Take-memcpy FDE padding changed')
    body2 = read(W2_START, W2_FDE_END - W2_START)
    require(body2 == W2_BODY, 'Take-inline instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'], len(CIE)) == CIE, 'CIE changed')

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    check_fde(0xadd4, W1_FDE, W1_START, W1_FDE_END)
    check_fde(0xae24, W2_FDE, W2_START, W2_FDE_END)
    # The next FDE starts exactly at the take-inline FDE end: zero padding.
    next_record = read(eh['address'] + 0x2eeb8c, 0x50)
    next_pc = eh['address'] + 0x2eeb8c + 8 + struct.unpack_from('<i', next_record, 8)[0]
    next_extent = struct.unpack_from('<I', next_record, 12)[0]
    require((next_pc, next_pc + next_extent) == (0x1451c50, 0x1451dad),
            'Following FDE PC/range changed')

    relsec = by_name['.rela.dyn']
    require(relsec['size'] % 24 == 0, 'Truncated RELA section')
    rels = {}
    raw = read(relsec['address'], relsec['size'])
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        require(address not in rels, 'Duplicate relocation address')
        rels[address] = (info, addend)

    def relative(address, expected):
        require(rels.get(address) == (8, expected), 'Relative relocation changed')
        require(read(address, 8) == b'\0' * 8, 'Unexpected pre-relocation pointer')

    relative(0x576e470, 0x157a9f0)
    relative(0x576e868, 0x4eeb4c0)
    relative(0x566a7f8, W1_START)
    relative(0x566a7d0, W2_START)
    relative(0x566a808, 0x1f87cf)
    # The memcpy slot is a GLOB_DAT import (symbol 6, type 6), not RELATIVE.
    require(rels.get(0x576dfe0) == ((6 << 32) | 6, 0), 'Memcpy slot relocation changed')
    require(read(0x576dfe0, 8) == b'\0' * 8, 'Unexpected pre-relocation pointer')

    def call_slot(va, expected):
        inst = read(va, 6)
        require(inst[:2] == b'\xff\x15', 'Indirect call opcode changed')
        require(va + 6 + struct.unpack_from('<i', inst, 2)[0] == expected,
                'Indirect call slot changed')

    call_slot(0x14519f5, 0x576dfe0)
    call_slot(0x1451a0d, 0x576e470)
    call_slot(0x1451a13, 0x576e868)
    call_slot(0x1451c44, 0x576e470)
    call_slot(0x1451c4a, 0x576e868)

    def lea_target(va, expected):
        inst = read(va, 7)
        require(inst[:3] == bytes.fromhex('488d3d'), 'LEA opcode changed')
        require(va + 7 + struct.unpack_from('<i', inst, 3)[0] == expected,
                'LEA target changed')

    lea_target(0x1451a06, 0x566a808)
    lea_target(0x1451c3d, 0x566a808)

    # Shared skeleton bytes in both bodies: load [rdi], load [rax], zero
    # [rax], test rbx, and the [rsi+4] == 1 comparison. Offsets differ
    # because the memcpy window pushes two registers and the inline window
    # pushes one; each tuple is (body, load, deref, zero, test, flag).
    for body, load, deref, zero, test, flag in (
            (body1, 10, 13, 16, 23, 28), (body2, 5, 8, 11, 18, 23)):
        require(body[load:load + 3] == bytes.fromhex('488b07'), 'Take load changed')
        require(body[deref:deref + 3] == bytes.fromhex('488b18'),
                'Take dereference changed')
        require(body[zero:zero + 7] == bytes.fromhex('48c70000000000'),
                'Take zeroing changed')
        require(body[test:test + 3] == bytes.fromhex('4885db'), 'Take null test changed')
        require(body[flag:flag + 4] == bytes.fromhex('807e0401'),
                'Take flag comparison changed')
    # Branch targets: je to the panic arm, je to the drop arm. Each je is
    # two bytes; the displacement sits in the second byte.
    require(body1[27] == 0x2a and W1_START + 28 + body1[27] == 0x1451a06,
            'Take-memcpy null branch changed')
    require(body1[33] == 0x31 and W1_START + 34 + body1[33] == 0x1451a13,
            'Take-memcpy flag branch changed')
    require(body2[22] == 0x36 and W2_START + 23 + body2[22] == 0x1451c3d,
            'Take-inline null branch changed')
    require(body2[28] == 0x3d and W2_START + 29 + body2[28] == 0x1451c4a,
            'Take-inline flag branch changed')
    # Copy logic: memcpy window reserves 0x268 bytes and passes 0x268 in edx;
    # inline window reserves 0x40 bytes and copies 0x30 bytes with movups.
    require(body1[3:10] == bytes.fromhex('4881ec68020000'), 'Memcpy stack reserve changed')
    require(body1[42:47] == bytes.fromhex('ba68020000'), 'Memcpy length changed')
    require(body2[1:5] == bytes.fromhex('4883ec40'), 'Inline stack reserve changed')
    require(body2[36:41] == bytes.fromhex('488b442438'), 'Inline tail load changed')
    require(body2[41:45] == bytes.fromhex('48894330'), 'Inline tail store changed')
    require(body2[45:50] == bytes.fromhex('0f10442408'), 'Inline movups 0 changed')
    require(body2[50:55] == bytes.fromhex('0f104c2418'), 'Inline movups 1 changed')
    require(body2[55:60] == bytes.fromhex('0f10542428'), 'Inline movups 2 changed')
    require(body2[60:64] == bytes.fromhex('0f115320'), 'Inline movups store 2 changed')
    require(body2[64:68] == bytes.fromhex('0f114b10'), 'Inline movups store 1 changed')
    require(body2[68:71] == bytes.fromhex('0f1103'), 'Inline movups store 0 changed')

    # Incoming-call scan through the windows' own slots. This byte-pattern
    # scan is explicitly NOT a complete xref census: the windows may be
    # reached through data pointers, and the scan covers .text only.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    indirect, direct = [], []
    for opcode in (b'\xff\x15', b'\xff\x25', b'\xe8'):
        pos = 0
        while (pos := code.find(opcode, pos)) >= 0:
            if opcode == b'\xe8':
                length, disp_off = 5, pos + 1
            else:
                length, disp_off = 6, pos + 2
            if pos + length <= len(code):
                disp = struct.unpack_from('<i', code, disp_off)[0]
                target = text['address'] + pos + length + disp
                if opcode == b'\xe8':
                    if target in (W1_START, W2_START):
                        direct.append(hex(text['address'] + pos))
                elif target in (0x566a7f8, 0x566a7d0):
                    indirect.append(hex(text['address'] + pos))
            pos += 1
    require(indirect == [] and direct == [], 'Incoming call scan changed')
    return {
        'target': {'artifact': 'node #94', 'bytes': TARGET_BYTES, 'sha256': SHA256},
        'windows': [
            {'label': 'take-memcpy', 'start': hex(W1_START),
             'fde_end': hex(W1_FDE_END), 'fde_bytes': W1_FDE_END - W1_START,
             'index_stride_end': hex(W1_INDEX_END),
             'index_stride_bytes': W1_INDEX_END - W1_START, 'padding_bytes': 7,
             'stack_bytes': 0x268, 'copy': {'method': 'memcpy-slot', 'bytes': 0x268}},
            {'label': 'take-inline', 'start': hex(W2_START),
             'fde_end': hex(W2_FDE_END), 'fde_bytes': W2_FDE_END - W2_START,
             'index_stride_end': hex(W2_FDE_END),
             'index_stride_bytes': W2_FDE_END - W2_START, 'padding_bytes': 0,
             'stack_bytes': 0x40,
             'copy': {'method': 'inline-movups-plus-tail', 'bytes': 0x38,
                      'movups_bytes': 0x30, 'tail_bytes': 8}},
        ],
        'slots': {
            'panic': {'slot': '0x576e470', 'target': '0x157a9f0'},
            'drop': {'slot': '0x576e868', 'target': '0x4eeb4c0'},
            'memcpy': {'slot': '0x576dfe0', 'relocation': 'GLOB_DAT'},
            'panic_argument': {'slot': '0x566a808', 'relocated_value': '0x1f87cf'},
            'window_slots': {'take-memcpy': '0x566a7f8', 'take-inline': '0x566a7d0'},
        },
        'incoming_scan': {'indirect': indirect, 'direct': direct,
                          'note': 'byte-pattern scan of .text only, not a complete xref census'},
    }


def inspect(target):
    data = target.read_bytes()
    require(len(data) == TARGET_BYTES, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', metavar='EVIDENCE')
    args = parser.parse_args()
    if not args.check:
        parser.error('--check is required')
    result = inspect(TARGET)
    retained = json.loads(Path(args.check).read_text())
    if result != retained:
        raise SystemExit('Evidence mismatch')
    print('Foundation twin-take evidence reproduces exactly.')


if __name__ == '__main__':
    main()
