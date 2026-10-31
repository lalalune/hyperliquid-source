#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 tag-dispatched-store evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window stores one of three things selected by a tag in edx (a global
pointer, rsi, or 16 bytes from [rsi]), or stores nothing for any other tag,
and always returns 0. What the destination, the source, and the global pointer
mean is not claimed anywhere.
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
START, END = 0x5057700, 0x505773d
PAD_END = 0x5057740
BODY = bytes.fromhex(
    'f30f1efa85d2742883fa01750b48893731c0c30f1f44000083fa0275f3'
    'f30f6f060f1107ebea662e0f1f840000000000488d05691b700048890731c0c3')
PAD = b'\xcc' * 3
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000ac30290038310e043d00000000000000')
FDE_OFFSET = 0x2930a8
NEXT_FDE_OFFSET = 0x2930bc
NEXT_START, NEXT_END = 0x5057740, 0x505774e
GLOBAL = 0x57592a0


def require(condition, message):
    if not condition:
        raise ValueError(message)


def store(tag):
    """Decoded dispatch of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. Tag 0 stores the global pointer,
    tag 1 stores rsi, tag 2 copies 16 bytes from [rsi]; any other tag stores
    nothing. Every path returns 0.
    """
    if tag == 0:
        return ('global', GLOBAL)
    if tag == 1:
        return ('rsi',)
    if tag == 2:
        return ('copy16',)
    return ('none',)


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
    require(body == BODY, 'Tag-dispatched-store instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    record = read(eh['address'] + FDE_OFFSET, len(FDE))
    require(record == FDE, 'FDE record changed')
    pc = eh['address'] + FDE_OFFSET + 8 + struct.unpack_from('<i', record, 8)[0]
    extent = struct.unpack_from('<I', record, 12)[0]
    require((pc, pc + extent) == (START, END), 'FDE PC/range changed')
    # The next FDE starts exactly at the stride end; decode and lock its
    # PC/range (its full record is retained in frames.txt, not re-decoded).
    nrec = read(eh['address'] + NEXT_FDE_OFFSET, 20)
    npc = eh['address'] + NEXT_FDE_OFFSET + 8 + struct.unpack_from('<i', nrec, 8)[0]
    nextent = struct.unpack_from('<I', nrec, 12)[0]
    require((npc, npc + nextent) == (NEXT_START, NEXT_END),
            'Next FDE PC/range changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x5057700.
    require(body[0:4] == bytes.fromhex('f30f1efa'), 'endbr64 changed')
    require(body[4:6] == bytes.fromhex('85d2'), 'Tag-zero test changed')
    require(body[6:8] == bytes.fromhex('7428'), 'Jump-to-global-path changed')
    require(body[8:11] == bytes.fromhex('83fa01'), 'Tag-one compare changed')
    require(body[11:13] == bytes.fromhex('750b'), 'Jump-to-tag-two changed')
    require(body[13:16] == bytes.fromhex('488937'), 'Store-rsi changed')
    require(body[16:18] == bytes.fromhex('31c0'), 'Return-zero changed')
    require(body[18:19] == bytes.fromhex('c3'), 'Return changed')
    require(body[19:24] == bytes.fromhex('0f1f440000'),
            'Five-byte alignment nop changed')
    require(body[24:27] == bytes.fromhex('83fa02'), 'Tag-two compare changed')
    require(body[27:29] == bytes.fromhex('75f3'), 'Jump-to-return changed')
    require(body[29:33] == bytes.fromhex('f30f6f06'), 'Sixteen-byte load changed')
    require(body[33:36] == bytes.fromhex('0f1107'), 'Sixteen-byte store changed')
    require(body[36:38] == bytes.fromhex('ebea'), 'Jump-to-return changed')
    require(body[38:48] == bytes.fromhex('662e0f1f840000000000'),
            'Ten-byte alignment nop changed')
    require(body[48:55] == bytes.fromhex('488d05691b7000'),
            'Global-pointer lea changed')
    lea_target = START + 55 + struct.unpack_from('<i', body, 51)[0]
    require(lea_target == GLOBAL, 'Global-pointer target changed')
    require(body[55:58] == bytes.fromhex('488907'), 'Store-global changed')
    require(body[58:60] == bytes.fromhex('31c0'), 'Return-zero changed')
    require(body[60:61] == bytes.fromhex('c3'), 'Return changed')
    # Data edge: the lea target lies in .data.rel.ro, and no relocation
    # record of any type in any .rela.* section names this window as addend
    # (full-section scan: 80,022 .rela.dyn + 278 .rela.plt entries).
    data_rel_ro = by_name['.data.rel.ro']
    require(data_rel_ro['address'] <= GLOBAL
            < data_rel_ro['address'] + data_rel_ro['size'],
            'Global pointer outside .data.rel.ro')
    naming = []
    for relname in ('.rela.dyn', '.rela.plt'):
        relsec = by_name[relname]
        require(relsec['size'] % 24 == 0, 'Truncated RELA section')
        raw = read(relsec['address'], relsec['size'])
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if addend == START:
                naming.append(address)
    require(naming == [], 'Naming relocation appeared')
    # Incoming calls: zero direct e8 calls (byte-pattern scan over .text).
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
    require(store(0) == ('global', GLOBAL), 'Tag-0 edge changed')
    require(store(1) == ('rsi',), 'Tag-1 edge changed')
    require(store(2) == ('copy16',), 'Tag-2 edge changed')
    require(store(3) == ('none',), 'Tag-3 edge changed')
    require(store(0xffffffff) == ('none',), 'Tag-max edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'global': GLOBAL,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 tag-dispatched-store '
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
        require(retained['function']['sha256'] ==
                '20b9c0991fb3c0cb30339df21612ac6562033a4a3fee606306fff618eedc775b',
                'Retained body hash mismatch')
        require(retained['incoming_pattern_scan']['e8_candidates'] == [],
                'Retained callers changed')
        require(retained['data_edge']['relative_slots_naming_window'] == [],
                'Retained slots changed')
        require(retained['data_edge']['global_pointer_va'] == hex(GLOBAL),
                'Retained global changed')
        print('Foundation tag-dispatched-store evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
