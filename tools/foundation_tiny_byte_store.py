#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 tiny-byte-store evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window has no outgoing calls: it reads one byte, writes one byte, and
returns. The meaning of the two stored values 0x5a/0x57, of the field offsets,
and of the ten RELATIVE slots naming this window is not claimed anywhere.
Those ten slots are a pointer table (one function pointer per table entry at
offset 0x30), not a single naming relocation, and nothing about the table's
purpose is claimed.
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
START, END = 0x24f13b0, 0x24f13c9
PAD_END = 0x24f13d0
BODY = bytes.fromhex('31c080bff2010000000f94c08d044083c0578887f3010000c3')
PAD = b'\xcc' * 7
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('100000003c2f080058cf78011900000000000000')
NEXT_FDE_OFFSET = 0x3e2070
NEXT_START = 0x24f13d0
# Ten R_X86_64_RELATIVE slots in .data.rel.ro naming this window as addend.
RELATIVE_SLOTS = [
    0x56a8f30, 0x56a9730, 0x56aa730, 0x56aaf30, 0x56abf30,
    0x56af730, 0x56b3f30, 0x56b4f30, 0x56b5730, 0x56b6730,
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def store(byte):
    """Decoded formula of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. A zero input byte stores 0x5a;
    any nonzero input byte stores 0x57; the same value is returned in eax.
    """
    return 0x5a if byte == 0 else 0x57


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
    require(body == BODY, 'Tiny-byte-store instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    record = read(eh['address'] + 0x82f38, len(FDE))
    require(record == FDE, 'FDE record changed')
    pc = eh['address'] + 0x82f38 + 8 + struct.unpack_from('<i', record, 8)[0]
    extent = struct.unpack_from('<I', record, 12)[0]
    require((pc, pc + extent) == (START, END), 'FDE PC/range changed')
    # The next FDE starts exactly at the stride end; its PC is locked here
    # (its full record is retained in frames.txt, not re-decoded).
    require(read(eh['address'] + NEXT_FDE_OFFSET, 4) == bytes.fromhex('50000000'),
            'Next FDE record changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x24f13b0.
    require(body[0:2] == bytes.fromhex('31c0'), 'Clear changed')
    require(body[2:9] == bytes.fromhex('80bff201000000'),
            'Input-byte compare changed')
    require(body[9:12] == bytes.fromhex('0f94c0'), 'Set-equal changed')
    require(body[12:15] == bytes.fromhex('8d0440'), 'Times-three changed')
    require(body[15:18] == bytes.fromhex('83c057'), 'Add-0x57 changed')
    require(body[18:24] == bytes.fromhex('8887f3010000'), 'Store changed')
    require(body[24:25] == bytes.fromhex('c3'), 'Return changed')
    # Data edge: exactly ten R_X86_64_RELATIVE slots in .data.rel.ro name
    # this window as addend, and no other relocation record of any type in
    # any .rela.* section does. The ten slots are a pointer table, not a
    # single naming relocation; the table's purpose is not claimed.
    naming = []
    for relname in ('.rela.dyn', '.rela.plt'):
        relsec = by_name[relname]
        require(relsec['size'] % 24 == 0, 'Truncated RELA section')
        raw = read(relsec['address'], relsec['size'])
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if addend == START:
                require(info & 0xffffffff == 8, 'Non-RELATIVE slot names window')
                naming.append(address)
    require(naming == RELATIVE_SLOTS, 'Pointer-table slots changed')
    data_rel_ro = by_name['.data.rel.ro']
    require(all(data_rel_ro['address'] <= s
                < data_rel_ro['address'] + data_rel_ro['size']
                for s in RELATIVE_SLOTS), 'Pointer-table slot outside .data.rel.ro')
    # Incoming calls: zero direct e8 calls, no indirect slot calls.
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
    # Decoded-formula edges (restatement of the retained bytes, not execution).
    require(store(0x00) == 0x5a, 'Zero edge changed')
    require(store(0x01) == 0x57, 'One edge changed')
    require(store(0xff) == 0x57, 'Max edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'relative_slots': RELATIVE_SLOTS,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 tiny-byte-store '
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
        require(retained['data_edge']['relative_slots_naming_window']
                == [hex(s) for s in RELATIVE_SLOTS], 'Retained slots changed')
        print('Foundation tiny-byte-store evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
