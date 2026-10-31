#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 keyed multiply-xor mixer packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window is a keyed multiply-xor mixer: rdi points at one qword, rsi at a
20-byte input block, and a GOT slot points at a 16-byte key table (k0 at +0,
k1 at +8; both runtime values, never claimed as constants). It returns
lo(T * k0) ^ hi(T * k0), where T folds the hi/lo halves of two unsigned
128-bit products and the constant 0x14.
What the bytes mean, and what reads the result, is not claimed anywhere.
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
START, END = 0x399c600, 0x399c646
PAD_END = 0x399c650
KEYPTR = 0x576e3e0
BODY = bytes.fromhex('488b0dd91ddd014c8b09488b460c4c31c84c8b16488b56084833510848f7e24889c14989d0488b46044c31c84c331749f7e24931d04831c84c31c04883f01449f7e14831d0c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000030331900b47db2024600000000000000')
NEXT = bytes.fromhex('1800000044331900f07db2024501000000440e500340010e08000000')
CALLER1 = bytes.fromhex('240100000c5e1a00749414026a140000')
CALLER2 = bytes.fromhex('24010000345f1a00bca714026a140000')
CALLERS = [
    # (FDE record offset, record head, FDE range, call site, call bytes)
    (0x48251c, CALLER1, 0x32aceb0, 0x32ae31a, 0x32ad5f3, 'e808f06e00'),
    (0x482644, CALLER2, 0x32ae320, 0x32af78a, 0x32aea63, 'e898db6e00'),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse(v_rdi, block, k0, k1):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. All four input loads are 64-bit qwords
    at rsi+0, +4, +8, +12 (a 20-byte span, not a 16-byte block); both
    multiplies are unsigned 64x64->128.
    """
    mask = (1 << 64) - 1

    def qword(off):
        return struct.unpack_from('<Q', block, off)[0]

    lo1, hi1 = divmod((qword(12) ^ k0) * (qword(8) ^ k1), 1 << 64)
    lo2, hi2 = divmod((qword(4) ^ k0) * (qword(0) ^ v_rdi), 1 << 64)
    folded = lo1 ^ lo2 ^ hi1 ^ hi2 ^ 0x14
    lo3, hi3 = divmod(folded * k0, 1 << 64)
    return (lo3 ^ hi3) & mask


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
    require(body == BODY, 'Keyed-multiply-xor-mixer instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    for offset, raw, start, end in [
            (0x19332c, FDE, START, END),
            (0x193340, NEXT, PAD_END, 0x399c795)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: ten int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 10, 'Padding changed')
    require(PAD_END == 0x399c650, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x399c600.
    fixed = [
        (0, '488b0dd91ddd01', 'Key-table pointer load changed'),
        (7, '4c8b09', 'First key load changed'),
        (10, '488b460c', 'High input qword load changed'),
        (14, '4c31c8', 'First key xor changed'),
        (17, '4c8b16', 'Base input qword load changed'),
        (20, '488b5608', 'Middle input qword load changed'),
        (24, '48335108', 'Second key xor changed'),
        (28, '48f7e2', 'First 128-bit multiply changed'),
        (31, '4889c1', 'First low half save changed'),
        (34, '4989d0', 'First high half save changed'),
        (37, '488b4604', 'Low-mid input qword load changed'),
        (41, '4c31c8', 'Second key xor changed'),
        (44, '4c3317', 'Base value xor changed'),
        (47, '49f7e2', 'Second 128-bit multiply changed'),
        (50, '4931d0', 'Second high half fold changed'),
        (53, '4831c8', 'First low half fold changed'),
        (56, '4c31c0', 'High halves fold changed'),
        (59, '4883f014', 'Constant 0x14 fold changed'),
        (63, '49f7e1', 'Final key multiply changed'),
        (66, '4831d0', 'Final hi/lo fold changed'),
        (69, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # The key-table pointer load is rip-relative and resolves into .got.
    disp = struct.unpack_from('<i', body, 3)[0]
    require(START + 7 + disp == KEYPTR, 'Key-table pointer target changed')
    got = by_name['.got']
    require(got['address'] <= KEYPTR < got['address'] + got['size'],
            'Key-table pointer not in .got')
    # No call opcode inside the window.
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    # Relocations: no record of any type names this window as addend.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((sec['name'], address))
    require(naming == [], 'Unexpected naming relocation for window')
    # Caller FDE records and call sites: two direct e8 sites, both locked.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    for offset, raw, fstart, fend, site, call_bytes in CALLERS:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'Caller FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (fstart, fend), 'Caller FDE PC/range changed')
        at = site - text['address']
        require(code[at:at + 5] == bytes.fromhex(call_bytes),
                'Caller call bytes changed')
        rel = struct.unpack_from('<i', code, at + 1)[0]
        require(text['address'] + at + 5 + rel == START, 'Caller target changed')
    # Incoming calls: direct e8 call sites anywhere in .text.
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == [0x32ad5f3, 0x32aea63], 'Incoming direct calls changed')
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    require(parse(0, bytes(20), 0, 0) == 0, 'Zero edge changed')
    require(parse(0, bytes(20), 1, 0) == 0x14, 'Unit-key edge changed')
    require(parse(0, bytes(20), 0, 0xffffffffffffffff) == 0, 'Zero-k0 edge changed')
    # Emulator vectors recorded in evidence.json (Capstone-decode sweep output).
    return body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', default=str(TARGET))
    parser.add_argument('--check', required=True)
    args = parser.parse_args()
    data = Path(args.binary).read_bytes()
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    body = analyze(data)
    evidence = json.loads(Path(args.check).read_text())
    require(evidence['target_sha256'] == SHA256, 'Evidence digest changed')
    require(evidence['function']['start_va'] == hex(START), 'Evidence start changed')
    require(evidence['function']['end_va_exclusive'] == hex(END), 'Evidence end changed')
    require(evidence['function']['bytes'] == END - START, 'Evidence size changed')
    require(evidence['function']['padding_bytes'] == PAD_END - END,
            'Evidence padding changed')
    require(evidence['function']['sha256'] == hashlib.sha256(body).hexdigest(),
            'Evidence body hash changed')
    for vector in evidence['emulator_vectors']:
        got = parse(int(vector['rdi_qword'], 16),
                    bytes.fromhex(vector['input_block_hex']),
                    int(vector['k0'], 16), int(vector['k1'], 16))
        require(got == int(vector['result'], 16), 'Emulator vector changed')
    print('Foundation keyed-multiply-xor-mixer evidence reproduces exactly.')


if __name__ == '__main__':
    main()
