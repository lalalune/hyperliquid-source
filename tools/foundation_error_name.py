#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 error-name evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window reads one byte, selects one of two .rodata pointers by a zero test,
and computes a length as 3*(byte^1)+14. Only bytes 0 and 1 land exactly on a
name boundary; for byte >= 1 the slice starts at "invalid length" and runs
into the following concatenated name bytes. No meaning of the byte, the
names, or the returned pointer/length pair is claimed anywhere.
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
START, END = 0x14b4e20, 0x14b4e48
PAD_END = 0x14b4e50
BODY = bytes.fromhex(
    '0fb60f4889c84883f001488d14404883c20e488d356a71d6fe488d055271d6fe'
    '4885c9480f45c6c3')
PAD = b'\xcc' * 8
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000e4db0000205d7c002800000000000000')
NEXT_FDE = bytes.fromhex('40000000f8db00003c5d7c002501000000420e10')
NAME0_VA = 0x21bf92
NAME1_VA = 0x21bfa3
NAME0 = b'invalid character'
NAME1 = b'invalid length'
TAIL_VA = 0x21bfb1
TAIL = b'SystemTimeErrorUtf8Errorvalid_up'
# One R_X86_64_RELATIVE slot names this window as addend. The file stores 0
# in the .data.rel.ro slot; the loader writes the window address at load time.
SLOTS = [0x566de38]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def select(byte):
    """Decoded selection rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. The return is (pointer, length).
    """
    require(isinstance(byte, int) and 0 <= byte <= 255,
            'Byte must be an unsigned byte')
    pointer = NAME0_VA if byte == 0 else NAME1_VA
    return pointer, 3 * (byte ^ 1) + 14


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
    require(body == BODY, 'Error-name instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in [(0xdbe0, FDE, START, END),
                                    (0xdbf4, NEXT_FDE, 0x14b4e50, 0x14b4f75)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x14b4e20.
    require(body[0:3] == bytes.fromhex('0fb60f'), 'Byte load changed')
    require(body[3:6] == bytes.fromhex('4889c8'), 'Byte copy changed')
    require(body[6:10] == bytes.fromhex('4883f001'), 'Xor-one changed')
    require(body[10:14] == bytes.fromhex('488d1440'), 'Times-three changed')
    require(body[14:18] == bytes.fromhex('4883c20e'), 'Plus-fourteen changed')
    require(body[18:25] == bytes.fromhex('488d356a71d6fe'),
            'Second-pointer load changed')
    require(0x14b4e39 + struct.unpack_from('<i', body, 21)[0] == NAME1_VA,
            'Second-pointer target changed')
    require(body[25:32] == bytes.fromhex('488d055271d6fe'),
            'First-pointer load changed')
    require(0x14b4e40 + struct.unpack_from('<i', body, 28)[0] == NAME0_VA,
            'First-pointer target changed')
    require(body[32:35] == bytes.fromhex('4885c9'), 'Zero test changed')
    require(body[35:39] == bytes.fromhex('480f45c6'), 'Select changed')
    require(body[39] == 0xc3, 'Return changed')
    # The names live in .rodata and equal the retained bytes.
    name_secs = [s for s in secs if s['address'] <= NAME0_VA
                 < s['address'] + s['size']]
    require(len(name_secs) == 1 and name_secs[0]['name'] == '.rodata',
            'Name section changed')
    require(read(NAME0_VA, len(NAME0)) == NAME0, 'First name changed')
    require(read(NAME1_VA, len(NAME1)) == NAME1, 'Second name changed')
    require(read(TAIL_VA, len(TAIL)) == TAIL, 'Following name bytes changed')
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
    # Decoded-rule edges (restatement of the retained bytes, not execution).
    require(select(0) == (NAME0_VA, 17), 'Byte-0 edge changed')
    require(select(1) == (NAME1_VA, 14), 'Byte-1 edge changed')
    require(select(2) == (NAME1_VA, 23), 'Byte-2 edge changed')
    require(select(3) == (NAME1_VA, 20), 'Byte-3 edge changed')
    require(select(4) == (NAME1_VA, 29), 'Byte-4 edge changed')
    require(select(255) == (NAME1_VA, 776), 'Byte-255 edge changed')
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
        description='Verify a digest-bound, static node #94 error-name '
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
        require(retained['incoming_pattern_scan']['e8_candidates'] == [],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation error-name evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
