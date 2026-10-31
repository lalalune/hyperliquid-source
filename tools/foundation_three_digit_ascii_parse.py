#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 three-digit ASCII parse packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window is a strict 3-character ASCII decimal parse: rdi = base pointer,
rsi = length. The length must be exactly 3; the value is
(b0 - '0') * 100 + (b1 - '0') * 10 + (b2 - '0'), where the tens term is
truncated to a byte after the *10 (harmless on the valid path, since the
tens term is at most 90). The gate is subtle and locked exactly: the first
byte must be '1'..'9' -- a leading '0' is rejected, so a 0 return
unambiguously means invalid (valid inputs give 100..999). What the parsed
number means, and what the caller does with it, is not claimed anywhere.
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
START, END = 0x1683670, 0x16836c5
PAD_END = 0x16836d0
CALLER_START, CALLER_END = 0x1682220, 0x1682735
CALL_SITE = 0x1682606
BODY = bytes.fromhex(
    '4883fe0375300fb60f0fb6470104d00fb6570280c2d08d71c64080fef7400f92c6'
    '3c0a400f93c780fa0a410f93c04108f84108f0740331c0c30fb6d280c1d00fb6c9'
    '6bc9640fb6c001c08d04800fb6c001c801d0c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000084802004cd997005500000000000000')
NEXT = bytes.fromhex(
    '50000000043004009c2a6800e9030000041bac94ff410e10420e18420e20420e284'
    '20e30410e38470e800683078c068d058e048f03860203db020e38410e30420e284'
    '20e20420e18420e10410e08410e8006000038000000')
CALLER_FDE = bytes.fromhex(
    '50000000982c04005819680015050000048fad94ff410e10420e18420e20420e284'
    '20e30410e38440e800183078c068d058e048f038602037f040e38410e30420e284'
    '20e20420e18420e10410e08410e800100003c000000')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse(buf, n):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. buf covers the input bytes; reads
    outside the supplied buffer raise, which the length gate provably never
    does for a well-formed call (n == 3 reads exactly 3 bytes).
    """
    if n != 3:
        return 0
    require(len(buf) >= 3, 'Rule read outside buffer')
    b0, b1, b2 = buf[0], buf[1], buf[2]
    # Validity flags, exactly as computed: sil is 1 iff b0 is NOT in
    # '1'..'9' (the (b0 - 0x3a) mod 256 < 0xf7 check); dil/r8b are 1 iff
    # the biased digit is >= 10 (not a digit).
    sil = 1 if ((b0 - 0x3a) & 0xff) < 0xf7 else 0
    dil = 1 if ((b1 - 0x30) & 0xff) >= 10 else 0
    r8b = 1 if ((b2 - 0x30) & 0xff) >= 10 else 0
    if (dil | r8b | sil) != 0:
        return 0
    # Compute path: biased digits, tens term byte-truncated after *10.
    b2p = (b2 - 0x30) & 0xff
    b0p = (b0 - 0x30) & 0xff
    b1p = (b1 - 0x30) & 0xff
    hundreds = (b0p * 100) & 0xffffffff
    tens = ((b1p * 10) & 0xff)
    return (hundreds + tens + b2p) & 0xffffffff


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
    require(body == BODY, 'Three-digit-ASCII-parse instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    for offset, raw, start, end in [
            (0x24804, FDE, START, END),
            (0x31f714, NEXT, PAD_END, 0x1683ab9),
            (0x31f3a8, CALLER_FDE, CALLER_START, CALLER_END)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: eleven int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 11, 'Padding changed')
    require(PAD_END == 0x16836d0, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x1683670.
    fixed = [
        (0, '4883fe03', 'Length compare changed'),
        (4, '7530', 'Length branch changed'),
        (6, '0fb60f', 'First byte load changed'),
        (9, '0fb64701', 'Second byte load changed'),
        (13, '04d0', 'Second byte bias changed'),
        (15, '0fb65702', 'Third byte load changed'),
        (19, '80c2d0', 'Third byte bias changed'),
        (22, '8d71c6', 'First byte gate lea changed'),
        (25, '4080fef7', 'First byte gate compare changed'),
        (29, '400f92c6', 'First byte gate setb changed'),
        (33, '3c0a', 'Second byte gate compare changed'),
        (35, '400f93c7', 'Second byte gate setae changed'),
        (39, '80fa0a', 'Third byte gate compare changed'),
        (42, '410f93c0', 'Third byte gate setae changed'),
        (46, '4108f8', 'Gate or changed'),
        (49, '4108f0', 'Gate or changed'),
        (52, '7403', 'Compute branch changed'),
        (54, '31c0', 'Invalid zero changed'),
        (56, 'c3', 'Invalid return changed'),
        (57, '0fb6d2', 'Third digit extend changed'),
        (60, '80c1d0', 'First digit bias changed'),
        (63, '0fb6c9', 'First digit extend changed'),
        (66, '6bc964', 'Hundreds multiply changed'),
        (69, '0fb6c0', 'Second digit extend changed'),
        (72, '01c0', 'Tens double changed'),
        (74, '8d0480', 'Tens times five changed'),
        (77, '0fb6c0', 'Tens truncation changed'),
        (80, '01c8', 'Hundreds add changed'),
        (82, '01d0', 'Ones add changed'),
        (84, 'c3', 'Valid return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # Branch targets land exactly on retained instruction starts.
    require(0x1683674 + 2 + 0x30 == 0x16836a6, 'Length branch target changed')
    require(0x16836a4 + 2 + 0x03 == 0x16836a9, 'Compute branch target changed')
    # No call opcode inside the window: the locked body contains no e8 byte.
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    # Relocations: no record of any type in any .rela.* section names
    # this window as addend.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((sec['name'], address))
    require(naming == [], 'Relocation slot changed')
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
    require(direct == [CALL_SITE], 'Incoming direct calls changed')
    # Caller call bytes and setup, locked from the caller FDE's linear stream:
    # mov 0x8(%rdi),%edi; mov 0x10(%r15),%rsi; call 0x1683670.
    require(read(0x16825ff, 12) == bytes.fromhex('8b7f08498b7710e865100000'),
            'Caller call bytes or setup changed')
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    require(parse(b'', 0) == 0, 'Zero-length edge changed')
    require(parse(b'12', 2) == 0, 'Short-length edge changed')
    require(parse(b'1234', 4) == 0, 'Long-length edge changed')
    require(parse(b'123', 3) == 123, 'Valid parse edge changed')
    require(parse(b'100', 3) == 100, 'Lowest valid edge changed')
    require(parse(b'999', 3) == 999, 'Highest valid edge changed')
    require(parse(b'012', 3) == 0, 'Leading zero edge changed')
    require(parse(b'12a', 3) == 0, 'Non-digit ones edge changed')
    require(parse(b'1:3', 3) == 0, 'Non-digit tens edge changed')
    require(parse(b':23', 3) == 0, 'Colon first byte edge changed')
    require(parse(b' 23', 3) == 0, 'Space first byte edge changed')
    require(parse(b'523', 3) == 523, 'Mid-range edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'relocation_slots': [[name, hex(addr)] for name, addr in naming],
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
                    'three-digit ASCII parse evidence packet.')
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
        require(retained['function']['padding_bytes'] == 11, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation three-digit-ascii-parse evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
