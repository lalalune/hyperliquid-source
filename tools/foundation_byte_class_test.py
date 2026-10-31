#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 byte-class test evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window takes one byte (in dil) and returns 1 exactly for five byte values
-- 0x0a, 0x0d, 0x23 ('"'), 0x3a (':'), 0x5c ('\\') -- and 0 otherwise. The set
is stated literally: it is an odd collection and is not rationalized into a
category. The meaning of the set, of the input byte, and of the caller is not
claimed anywhere.
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
START, END = 0x5430860, 0x54308a5
PAD_END = 0x54308b0
BODY = bytes.fromhex(
    'f30f1efa31c04080ff5c7f194080ff227f1e4080ff0a74084080ff0d0f94c0c3'
    'b801000000c3662e0f1f84000000000048b8010080000000000283ef23480fa3f8'
    '0f92c0c3')
PAD = b'\xcc' * 11
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000d8ad2b006c4549044500000000000000')
FDE_OFFSET = 0x2badd4
NEXT_FDE_OFFSET = 0x2bade8
NEXT_START = 0x54308b0
NEXT_END = 0x54308cc
CALLER = 0x54309be
CALLER_BYTES = bytes.fromhex('e89dfeffff')
CALLER_SETUP_MOVSBL = bytes.fromhex('440fbe7d00')
CALLER_SETUP_MOV = bytes.fromhex('4489ff')
CALLER_FDE_OFFSET = 0x65d378
CALLER_FDE_HEAD = bytes.fromhex('4c000000accd030068200f045e010000')
CALLER_START, CALLER_END = 0x5430900, 0x5430a5e
MASK = 0x200000000800001
MASK_BITS = (0, 23, 57)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def byte_class(byte, edi=None):
    """Decoded formula of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. The comparisons read dil as a
    signed 8-bit value: signed > 0x5c returns 0, signed > 0x22 takes the
    bit-test path, otherwise 0x0a and 0x0d return 1 and the rest return 0.
    The bit-test path computes (edi - 0x23) mod 64 over the full edi; the
    confirmed caller sign-extends the byte into edi, so for that caller the
    index is exactly byte - 0x23. With a zero-extended byte input the
    accepted bit-test bytes are 0x23, 0x3a, 0x5c.
    """
    signed = byte if byte < 0x80 else byte - 256
    if signed > 0x5c:
        return 0
    if signed > 0x22:
        index = ((byte if edi is None else edi) - 0x23) % 64
        return (MASK >> index) & 1
    if byte == 0x0a:
        return 1
    if byte == 0x0d:
        return 1
    return 0


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
    require(body == BODY, 'Byte-class instruction window changed')
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
    require((npc, npc + nextent) == (NEXT_START, NEXT_END),
            'Next FDE PC/range changed')
    # Caller FDE: lock its record head and computed PC/range. Its CIE differs
    # from the window's (augmentation data 27 ff 8a ff); only the FDE head
    # and PC/range are locked, not that CIE.
    chead = read(eh['address'] + CALLER_FDE_OFFSET, len(CALLER_FDE_HEAD))
    require(chead == CALLER_FDE_HEAD, 'Caller FDE record changed')
    cpc = (eh['address'] + CALLER_FDE_OFFSET + 8
           + struct.unpack_from('<i', chead, 8)[0])
    cent = struct.unpack_from('<I', chead, 12)[0]
    require((cpc, cpc + cent) == (CALLER_START, CALLER_END),
            'Caller FDE PC/range changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x5430860.
    require(body[0:4] == bytes.fromhex('f30f1efa'), 'endbr64 changed')
    require(body[4:6] == bytes.fromhex('31c0'), 'Zero changed')
    require(body[6:10] == bytes.fromhex('4080ff5c'), '0x5c compare changed')
    require(body[10:12] == bytes.fromhex('7f19'), 'High branch changed')
    require(body[12:16] == bytes.fromhex('4080ff22'), '0x22 compare changed')
    require(body[16:18] == bytes.fromhex('7f1e'), 'Bit-test branch changed')
    require(body[18:22] == bytes.fromhex('4080ff0a'), '0x0a compare changed')
    require(body[22:24] == bytes.fromhex('7408'), '0x0a branch changed')
    require(body[24:28] == bytes.fromhex('4080ff0d'), '0x0d compare changed')
    require(body[28:31] == bytes.fromhex('0f94c0'), 'sete changed')
    require(body[31:32] == bytes.fromhex('c3'), 'First return changed')
    require(body[32:37] == bytes.fromhex('b801000000'), 'One constant changed')
    require(body[37:38] == bytes.fromhex('c3'), 'Second return changed')
    require(body[38:48] == bytes.fromhex('662e0f1f840000000000'),
            'Alignment nopw changed')
    require(body[48:58] == bytes.fromhex('48b80100800000000002'),
            'Mask immediate changed')
    require(body[58:61] == bytes.fromhex('83ef23'), 'Index subtract changed')
    require(body[61:65] == bytes.fromhex('480fa3f8'), 'Bit test changed')
    require(body[65:68] == bytes.fromhex('0f92c0'), 'setb changed')
    require(body[68:69] == bytes.fromhex('c3'), 'Final return changed')
    # The mask immediate decodes to exactly bits 0, 23, 57.
    require([i for i in range(64) if MASK >> i & 1] == list(MASK_BITS),
            'Mask bits changed')
    # Caller call bytes and argument setup: the caller sign-extends the byte
    # from (%rbp) into r15d, moves it to edi, then calls the window.
    require(read(CALLER, 5) == CALLER_BYTES, 'Caller call bytes changed')
    require(read(0x54309b3, 5) == CALLER_SETUP_MOVSBL,
            'Caller movsbl setup changed')
    require(read(0x54309b8, 3) == CALLER_SETUP_MOV,
            'Caller mov-to-edi setup changed')
    # Data edge: no relocation record of any type in any .rela.* section
    # names this window as addend. The full-section scan counts are locked
    # so a truncated scan cannot pass silently.
    naming = []
    rela_counts = {}
    for relname in ('.rela.dyn', '.rela.plt'):
        relsec = by_name[relname]
        require(relsec['size'] % 24 == 0, 'Truncated RELA section')
        raw = read(relsec['address'], relsec['size'])
        rela_counts[relname] = len(raw) // 24
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if addend == START:
                naming.append(address)
    require(naming == [], 'Naming slots changed')
    require(rela_counts == {'.rela.dyn': 80022, '.rela.plt': 278},
            'RELA section counts changed')
    # Incoming calls: exactly one direct e8 call, the confirmed caller.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == [CALLER], 'Incoming direct calls changed')
    # Decoded-formula edges (restatement of the retained bytes, not execution).
    require(byte_class(0x0a) == 1, '0x0a edge changed')
    require(byte_class(0x0d) == 1, '0x0d edge changed')
    require(byte_class(0x23) == 1, '0x23 edge changed')
    require(byte_class(0x3a) == 1, '0x3a edge changed')
    require(byte_class(0x5c) == 1, '0x5c edge changed')
    require(byte_class(0x22) == 0, '0x22 edge changed')
    require(byte_class(0x24) == 0, '0x24 edge changed')
    require(byte_class(0x5d) == 0, '0x5d edge changed')
    require(byte_class(0x00) == 0, '0x00 edge changed')
    require(byte_class(0xff) == 0, '0xff edge changed')
    require(byte_class(0x80) == 0, '0x80 edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'caller': CALLER,
        'rela_counts': rela_counts,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 byte-class '
                    'test evidence packet.')
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
        require(retained['incoming_pattern_scan']['e8_candidates'] == [hex(CALLER)],
                'Retained callers changed')
        require(retained['data_edge']['relative_slots_naming_window'] == [],
                'Retained naming slots changed')
        print('Foundation byte-class-test evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
