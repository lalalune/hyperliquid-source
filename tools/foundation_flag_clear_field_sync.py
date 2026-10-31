#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 flag-clear plus field-sync packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window is a flag-clear plus field sync: given a struct pointer in rdi, it
clears the qword at [rdi] when nonzero, then copies [rdi+0x50] into [rdi+0x58]
when the two differ. What the struct fields mean, and what the callers do with
the result, is not claimed anywhere. The two effects read as unrelated
housekeeping; the packet binds the window only because both lock exactly from
its own bytes, not because they are shown to belong to one operation.
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
START, END = 0x5172fa0, 0x5172fc0
PAD_END = 0x5172fc0
MASK = (1 << 64) - 1
BODY = bytes.fromhex(
    'f30f1efa48833f00740748c70700000000488b4750483b4758740448894758c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
CIE2 = bytes.fromhex('1c00000000000000017a504c5200017810079b3d5848041b1b0c070890010000')
FDE = bytes.fromhex('1000000070c5290014551f0420000000')
NEXT = bytes.fromhex(
    '38000000605d010074b7e503dc07000004e7168cff450e108602430d06498f038e048d058c0683070306032e20035a020a0c0708470b02aa')
CALLERS = [
    (0x5173ffc, 0x517402b, 0x636418,
     '200000004c5e0100c4c6e5032f000000045e168cff0ec001830786068c058d04',
     (0x5174001, 'e89aefffff', '488d7c2410'),
    ),
    (0x517620e, 0x5176342, 0x636574,
     '20000000a85f01007ae7e5033401000004b0158cff0c0610830786028c068d05',
     (0x5176259, 'e842cdffff', '488bbdf0fcffff'),
    ),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sync(flag, a50, a58):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. Returns (flag_out, a58_out, rax_at_ret):
    the flag qword is cleared when nonzero; [rdi+0x58] is set to [rdi+0x50]
    when the two differ; rax at ret always holds the loaded [rdi+0x50].
    """
    flag &= MASK
    a50 &= MASK
    a58 &= MASK
    if flag != 0:
        flag = 0
    if a50 != a58:
        a58 = a50
    return flag, a58, a50


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
    require(body == BODY, 'Flag-clear-field-sync instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    require(read(eh['address'] + 0x6205d0, len(CIE2)) == CIE2,
            'CIE at offset 0x6205d0 changed')
    for offset, raw, start, end in [
            (0x29c56c, FDE, START, END),
            (0x63632c, NEXT, PAD_END, 0x517379c)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: zero int3 bytes — the next FDE starts exactly at the FDE end,
    # which the NEXT record lock above already pins (PC 0x5172fc0 == END).
    require(PAD_END == END, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x5172fa0.
    fixed = [
        (0, 'f30f1efa', 'Endbr64 changed'),
        (4, '48833f00', 'Flag-qword compare changed'),
        (8, '7407', 'Flag-zero branch changed'),
        (10, '48c70700000000', 'Flag-clear store changed'),
        (17, '488b4750', 'Field load changed'),
        (21, '483b4758', 'Field compare changed'),
        (25, '7404', 'Field-equal branch changed'),
        (27, '48894758', 'Field sync store changed'),
        (31, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # Branch targets land exactly on retained instruction starts.
    require(0x5172fa8 + 2 + 0x07 == 0x5172fb1, 'Flag-zero target changed')
    require(0x5172fb9 + 2 + 0x04 == 0x5172fbf, 'Field-equal target changed')
    # No call opcode inside the window: the locked body contains no e8 byte.
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    # Relocations: no record of any type in any .rela.* section names this window.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((sec['name'], address))
    require(naming == [], 'Relocation naming window changed')
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
    expected_sites = [s[0] for c in CALLERS for s in c[4:]]
    require(direct == expected_sites, 'Incoming direct calls changed')
    # Each caller sits inside its caller FDE range, with the retained FDE
    # record, call bytes, and call-path argument setup intact.
    for fde_start, fde_end, fde_off, fde_raw, *sites in CALLERS:
        record = read(eh['address'] + fde_off, len(bytes.fromhex(fde_raw)))
        require(record == bytes.fromhex(fde_raw), 'Caller FDE record changed')
        pc = eh['address'] + fde_off + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (fde_start, fde_end),
                'Caller FDE PC/range changed')
        for site, call_hex, setup_hex in sites:
            require(fde_start <= site < fde_end, 'Caller outside its FDE range')
            require(read(site, 5) == bytes.fromhex(call_hex), 'Caller call bytes changed')
            setup_len = len(bytes.fromhex(setup_hex))
            require(read(site - setup_len, setup_len) == bytes.fromhex(setup_hex),
                    'Caller setup changed')
            require(site + 5 + struct.unpack_from('<i', read(site, 5), 1)[0] == START,
                    'Caller call target changed')
    # Decoded-rule edges (restatement of the retained bytes, not execution).
    require(sync(0, 5, 5) == (0, 5, 5), 'No-op edge changed')
    require(sync(7, 5, 5) == (0, 5, 5), 'Flag-only edge changed')
    require(sync(7, 5, 3) == (0, 5, 5), 'Both-effects edge changed')
    require(sync(0, 5, 3) == (0, 5, 5), 'Sync-only edge changed')
    require(sync(0xFFFFFFFFFFFFFFFF, 0, 0) == (0, 0, 0), 'All-ones flag edge changed')
    require(sync(3, 0, 9) == (0, 0, 0), 'Zero-to-nonzero sync edge changed')
    require(sync(0, 9, 0) == (0, 9, 9), 'Nonzero-to-zero sync edge changed')
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
                    'flag-clear-field-sync evidence packet.')
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
        require(retained['function']['padding_bytes'] == 0, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation flag-clear-field-sync evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
