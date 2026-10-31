#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 byte-indexed dual-load evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window reads one byte, uses it as an index into two qword tables, and
returns one table entry in rax with the other in rdx. Table A lives in
.rodata and its file entries are readable; table B lives in .data.rel.ro,
its file entries are all zero, and 127 R_X86_64_RELATIVE relocations fill
its slots at load time, so table B's runtime contents are NOT claimed
anywhere. The meaning of the tables, of the index byte, and of the single
naming relocation is not claimed anywhere.
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
START, END = 0x4e48600, 0x4e4861d
PAD_END = 0x4e48620
BODY = bytes.fromhex('0fb607c1e003488d0deb8d97fb488b1408488d0d78169000488b0408c3')
PAD = b'\xcc' * 3
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000f04a2700f425ef031d000000')
FDE_OFFSET = 0x274aec
NEXT_FDE_OFFSET = 0x274b00
NEXT_START = 0x4e48620
TABLE_A = 0x7c13f8
TABLE_A_FIRST12 = (8, 9, 3, 9, 14, 9, 14, 10, 8, 11, 6, 6)
TABLE_B = 0x5749c90
TABLE_B_RELOC_COUNT = 127
NAMING_SLOT = 0x57494c0


def require(condition, message):
    if not condition:
        raise ValueError(message)


def dual_load(index, table_a, table_b):
    """Decoded formula of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. The index byte is zero-extended
    (movzbl), scaled by 8 (shl 3), and used to load one qword from each
    table: rdx = tableA[index], rax = tableB[index].
    """
    return table_a[index], table_b[index]


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
    require(body == BODY, 'Dual-load instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    record = read(eh['address'] + FDE_OFFSET, len(FDE))
    require(record == FDE, 'FDE record changed')
    pc = eh['address'] + FDE_OFFSET + 8 + struct.unpack_from('<i', record, 8)[0]
    extent = struct.unpack_from('<I', record, 12)[0]
    require((pc, pc + extent) == (START, END), 'FDE PC/range changed')
    # The next FDE starts exactly at the stride end; its PC/range are locked
    # here (its full record is retained in frames.txt, not re-decoded).
    nxt = read(eh['address'] + NEXT_FDE_OFFSET, len(FDE))
    npc = eh['address'] + NEXT_FDE_OFFSET + 8 + struct.unpack_from('<i', nxt, 8)[0]
    nextent = struct.unpack_from('<I', nxt, 12)[0]
    require((npc, npc + nextent) == (NEXT_START, 0x4e48824),
            'Next FDE PC/range changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x4e48600.
    require(body[0:3] == bytes.fromhex('0fb607'), 'Index-byte load changed')
    require(body[3:6] == bytes.fromhex('c1e003'), 'Scale-by-8 changed')
    require(body[6:13] == bytes.fromhex('488d0deb8d97fb'),
            'Table-A lea changed')
    require(body[13:17] == bytes.fromhex('488b1408'), 'Table-A load changed')
    require(body[17:24] == bytes.fromhex('488d0d78169000'),
            'Table-B lea changed')
    require(body[24:28] == bytes.fromhex('488b0408'), 'Table-B load changed')
    require(body[28:29] == bytes.fromhex('c3'), 'Return changed')
    # Table A: .rodata entries are file-readable; lock the first twelve.
    rodata = by_name['.rodata']
    require(rodata['address'] <= TABLE_A
            < rodata['address'] + rodata['size'], 'Table A outside .rodata')
    a_raw = read(TABLE_A, 12 * 8)
    require(struct.unpack('<12q', a_raw) == TABLE_A_FIRST12,
            'Table-A head changed')
    # Table B: file entries are all zero; 127 RELATIVE relocations land in
    # its 256-entry range, so runtime contents are load-time values and are
    # not claimed. Lock the zeros and the relocation count, not contents.
    data_rel_ro = by_name['.data.rel.ro']
    require(data_rel_ro['address'] <= TABLE_B
            < data_rel_ro['address'] + data_rel_ro['size'],
            'Table B outside .data.rel.ro')
    require(read(TABLE_B, 8 * 8) == b'\x00' * 64,
            'Table-B file head not zero')
    # Data edge: exactly one relocation record of any type in any .rela.*
    # section names this window as addend: a RELATIVE slot at 0x57494c0.
    # It is a single naming slot, not a pointer table; its meaning is not
    # claimed. Separately count RELATIVE relocations into the table-B range.
    naming = []
    table_b_relocs = 0
    for relname in ('.rela.dyn', '.rela.plt'):
        relsec = by_name[relname]
        require(relsec['size'] % 24 == 0, 'Truncated RELA section')
        raw = read(relsec['address'], relsec['size'])
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if addend == START:
                require(info & 0xffffffff == 8, 'Non-RELATIVE slot names window')
                naming.append(address)
            if (info & 0xffffffff == 8
                    and TABLE_B <= address < TABLE_B + 256 * 8):
                table_b_relocs += 1
    require(naming == [NAMING_SLOT], 'Naming slots changed')
    require(data_rel_ro['address'] <= NAMING_SLOT
            < data_rel_ro['address'] + data_rel_ro['size'],
            'Naming slot outside .data.rel.ro')
    require(table_b_relocs == TABLE_B_RELOC_COUNT, 'Table-B reloc count changed')
    # Incoming calls: zero direct e8 calls.
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
    require(dual_load(0, TABLE_A_FIRST12, [0] * 12) == (8, 0),
            'Index-0 edge changed')
    require(dual_load(5, TABLE_A_FIRST12, [0] * 12) == (9, 0),
            'Index-5 edge changed')
    require(dual_load(11, TABLE_A_FIRST12, [0] * 12) == (6, 0),
            'Index-11 edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'naming_slot': NAMING_SLOT,
        'table_b_relocs': table_b_relocs,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 byte-indexed '
                    'dual-load evidence packet.')
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
                == [hex(NAMING_SLOT)], 'Retained naming slot changed')
        require(retained['data_edge']['table_b_relative_reloc_count']
                == TABLE_B_RELOC_COUNT, 'Retained table-B reloc count changed')
        print('Foundation byte-indexed-dual-load evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
