#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 bit-writer drain packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window drains a buffered bit accumulator: counter dword [rdi+0x1734],
accumulator word [rdi+0x1730], output buffer pointer [rdi+0x10], write
position qword [rdi+0x28]. Counter == 16 flushes both accumulator bytes and
resets; any other counter above 7 (8..15 in the valid 0..16 range) emits one
byte, subtracts 8, and shifts the accumulator right by 8; counter <= 7 emits
nothing. The branches route exactly that way: the ==16 path and the <=7 path
are the only special cases, so a counter above 16 would take the same
one-byte path -- the model below restates the branches, not a range
assumption. What the bits mean, and what any caller does with the output,
is not claimed anywhere.
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
START, END = 0x5494050, 0x54940d8
PAD_END = 0x54940e0
BODY = bytes.fromhex(
    'f30f1efa8b873417000083f810743183f8077e29488b47280fb78f30170000'
    '488b5710488d700148897728880c0283af341700000866c1af3017000008'
    'c36690488b47280fb78f30170000488b5710488d700148897728880c0248'
    '8b47280fb68f31170000488b5710488d700148897728880c0231c0668987'
    '30170000c7873417000000000000c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000acf22b0088384f048800000000000000')
NEXT = bytes.fromhex('10000000c0f22b0004394f044201000000000000')
CALLER_FDES = [
    (0x2beb2c, 0x5489a10, 0x548a2ef, bytes.fromhex(
        '4800000030eb2b00c4994e04df08000000460e108f02420e188e03420e208'
        'd04420e288c05410e308606410e388307470e700304050a0e38440e30410'
        'e28420e20420e18420e10420e084a0b')),
    (0x2beb78, 0x548a2f0, 0x548a894, bytes.fromhex(
        '7c0000007ceb2b0058a24e04a405000000460e108f02420e188e03420e208'
        'd04420e288c05410e308606410e388307470e500343020a0e38430e30410'
        'e28420e20420e18420e10420e08440b034d020a0e38410e30440e28420e204'
        '20e18420e10420e08410b02660a0e38410e30410e28420e20420e18420e104'
        '20e08410b00')),
    (0x2bebf8, 0x548a8a0, 0x548b03b, bytes.fromhex(
        '7c000000fceb2b0088a74e049b07000000460e108f02420e188e03420e208'
        'd04450e288c05410e308606410e388307470e4003b6020a0e38410e30410'
        'e28420e20420e18420e10420e08480b0389030a0e38410e30440e28420e204'
        '20e18420e10420e08410b0316010e38410e30440e28420e20420e18420e104'
        '20e08000000')),
    (0x2bed68, 0x548b640, 0x548cebc, bytes.fromhex(
        '600000006ced2b00b8b34e047c180000004f0e108f02420e188e03420e208'
        'd04420e288c05410e308606440e388307440e50690a0e38410e30410e284'
        '20e20420e18420e10420e08470b03e8170e08c3c6cccdcecf460e508307860'
        '68c058d048e038f02')),
]
# All 26 direct e8 call sites, each locked as (site, 5 call bytes).
CALL_SITES = [
    (0x5489b22, 'e829a50000'), (0x5489c7f, 'e8cca30000'),
    (0x548a06c, 'e8df9f0000'), (0x548a4ec, 'e85f9b0000'),
    (0x548a77b, 'e8d0980000'), (0x548a7f0, 'e85b980000'),
    (0x548ab07, 'e844950000'), (0x548ad7f, 'e8cc920000'),
    (0x548aeac, 'e89f910000'), (0x548afd2, 'e879900000'),
    (0x548b819, 'e832880000'), (0x548b8f8, 'e853870000'),
    (0x548ba92, 'e8b9850000'), (0x548bb43, 'e808850000'),
    (0x548bbe9, 'e862840000'), (0x548bc6c, 'e8df830000'),
    (0x548bdea, 'e861820000'), (0x548c00d, 'e83e800000'),
    (0x548c2c3, 'e8887d0000'), (0x548c542, 'e8097b0000'),
    (0x548c63b, 'e8107a0000'), (0x548c767, 'e8e4780000'),
    (0x548c86f, 'e8dc770000'), (0x548cc65, 'e8e6730000'),
    (0x548cd16, 'e835730000'), (0x548cdd2, 'e879720000'),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def drain(counter, acc, pos):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. Returns (emitted bytes, new counter,
    new accumulator word, new position). The branch structure is restated
    exactly: ==16 flushes, signed <=7 emits nothing, everything else takes
    the one-byte path.
    """
    acc &= 0xffff
    if counter == 16:
        return (bytes([acc & 0xff, (acc >> 8) & 0xff]), 0, 0, pos + 2)
    if counter <= 7:
        return (b'', counter, acc, pos)
    return (bytes([acc & 0xff]), counter - 8, (acc >> 8) & 0xffff, pos + 1)


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
    require(body == BODY, 'Bit-writer-drain instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    for offset, raw, start, end in [(0x2bf2a8, FDE, START, END),
                                    (0x2bf2bc, NEXT, PAD_END, 0x5494222)] + [
            (off, raw, s, e) for off, s, e, raw in CALLER_FDES]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: eight int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 8, 'Padding changed')
    require(PAD_END == 0x54940e0, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x5494050.
    fixed = [
        (0, 'f30f1efa', 'endbr64 changed'),
        (4, '8b8734170000', 'Counter load changed'),
        (10, '83f810', 'Flush compare changed'),
        (13, '7431', 'Flush branch changed'),
        (15, '83f807', 'No-emit compare changed'),
        (18, '7e29', 'No-emit branch changed'),
        (20, '488b4728', 'One-byte position load changed'),
        (24, '0fb78f30170000', 'One-byte accumulator load changed'),
        (31, '488b5710', 'One-byte buffer load changed'),
        (35, '488d7001', 'One-byte position increment changed'),
        (39, '48897728', 'One-byte position store changed'),
        (43, '880c02', 'One-byte emit changed'),
        (46, '83af3417000008', 'Counter decrement changed'),
        (53, '66c1af3017000008', 'Accumulator shift changed'),
        (61, 'c3', 'One-byte return changed'),
        (62, '6690', 'Intra-FDE alignment nop changed'),
        (64, '488b4728', 'Flush position load changed'),
        (68, '0fb78f30170000', 'Flush accumulator load changed'),
        (75, '488b5710', 'Flush buffer load changed'),
        (79, '488d7001', 'Flush position increment changed'),
        (83, '48897728', 'Flush position store changed'),
        (87, '880c02', 'Flush low-byte emit changed'),
        (90, '488b4728', 'Flush position reload changed'),
        (94, '0fb68f31170000', 'Flush high-byte load changed'),
        (101, '488b5710', 'Flush buffer reload changed'),
        (105, '488d7001', 'Flush second increment changed'),
        (109, '48897728', 'Flush position store changed'),
        (113, '880c02', 'Flush high-byte emit changed'),
        (116, '31c0', 'Accumulator zero changed'),
        (118, '66898730170000', 'Accumulator clear changed'),
        (125, 'c7873417000000000000', 'Counter reset changed'),
        (135, 'c3', 'Flush return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # Branch targets land exactly on retained instruction starts.
    require(0x549405d + 2 + 0x31 == 0x5494090, 'Flush branch target changed')
    require(0x5494062 + 2 + 0x29 == 0x549408d, 'No-emit branch target changed')
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
    require(direct == [site for site, _ in CALL_SITES],
            'Incoming direct calls changed')
    # Caller call bytes, locked for all 26 sites.
    for site, raw in CALL_SITES:
        require(read(site, 5) == bytes.fromhex(raw),
                'Caller call bytes changed')
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    require(drain(16, 0xabcd, 5) == (bytes([0xcd, 0xab]), 0, 0, 7),
            'Flush edge changed')
    require(drain(16, 0x0000, 0) == (bytes([0, 0]), 0, 0, 2),
            'Flush zero edge changed')
    require(drain(8, 0x1234, 3) == (bytes([0x34]), 0, 0x12, 4),
            'One-byte low edge changed')
    require(drain(15, 0x00ff, 9) == (bytes([0xff]), 7, 0x00, 10),
            'One-byte high edge changed')
    require(drain(9, 0x8001, 0) == (bytes([0x01]), 1, 0x80, 1),
            'One-byte mid edge changed')
    require(drain(7, 0xffff, 4) == (b'', 7, 0xffff, 4),
            'No-emit boundary edge changed')
    require(drain(0, 0x1234, 4) == (b'', 0, 0x1234, 4),
            'No-emit zero edge changed')
    require(drain(-1, 0x1234, 4) == (b'', -1, 0x1234, 4),
            'No-emit negative edge changed')
    require(drain(17, 0x1234, 3) == (bytes([0x34]), 9, 0x12, 4),
            'Above-range same-path edge changed')
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
                    'bit-writer drain evidence packet.')
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
        require(retained['function']['padding_bytes'] == 8, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation bit-writer-drain evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
