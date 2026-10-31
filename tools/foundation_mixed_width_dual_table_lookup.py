#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 mixed-width dual-table-lookup packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window takes one byte argument and returns two values: rax is a pointer
resolved as the i32-table base plus a signed 32-bit table entry, and rdx is
the u64-table entry at the same index. What either table entry means is not
claimed anywhere.

This is the third dual-table lookup after packets #24 (0x299e280) and #63
(0x4e48600). Its individual justification is the mixed-width second table:
relative i32 entries resolved against the table base, where the earlier two
packets' second tables are plain u64/i32 value tables. No dual-table census
is claimed.
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
START, END = 0x29d7fc0, 0x29d7fde
PAD_END = 0x29d7fe0
U64_BASE, I32_BASE = 0x4024a0, 0x402728
BODY = bytes.fromhex(
    '488d05d9a4a2fd400fb6cf488b14c8488d3552a7a2fd4863048e4801f0c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000e8520c00bc17c3011e00000000000000')
NEXT_FDE = bytes.fromhex(
    '3c000000fc520c00f821c301ed01000000420e10420e18420e20420e28410e3083068c'
    '058d048e038f0203ce010e28420e20420e18420e10420e08410e300000')
CALLER = 0x29d81b4
CALLER_FDE = (0x29d7fe0, 0x29d8a0e)
CALL_BYTES = bytes.fromhex('e807feffff')
CALLER_SETUP = bytes.fromhex('8bbc1c08010000')
U64_FIRST8 = [6, 14, 15, 15, 13, 32, 28, 28]
I32_FIRST8 = [-3447, -3441, -3427, -3412, -3397, -2058120, -3384, -3356]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def lookup(u64_table, i32_table, index):
    """Decoded lookup rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. Inputs are the two table entry
    lists and a byte index; the return is (resolved_pointer, u64_entry),
    where resolved_pointer is the i32-table base plus the signed entry.
    """
    require(isinstance(index, int) and 0 <= index <= 0xFF,
            'Index must be a single byte')
    require(0 <= index < len(u64_table), 'Index outside u64 table sample')
    require(0 <= index < len(i32_table), 'Index outside i32 table sample')
    return I32_BASE + i32_table[index], u64_table[index]


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
    require(body == BODY, 'Mixed-width dual-table-lookup instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    # Note: the .eh_frame-order next record (0x29d8a10) is NOT the
    # address-order next FDE; the address-order next FDE is the caller FDE
    # at PAD_END (0x29d7fe0), checked separately via the caller range below.
    for offset, raw, start, end in [(0xc52e4, FDE, START, END),
                                    (0xc52f8, NEXT_FDE, 0x29d8a10, 0x29d8bfd)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: two int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 2, 'Padding changed')
    require(PAD_END == 0x29d7fe0, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x29d7fc0.
    require(body[0:7] == bytes.fromhex('488d05d9a4a2fd'),
            'u64-table lea changed')
    require(body[7:11] == bytes.fromhex('400fb6cf'), 'Index zero-extend changed')
    require(body[11:15] == bytes.fromhex('488b14c8'), 'u64 load changed')
    require(body[15:22] == bytes.fromhex('488d3552a7a2fd'),
            'i32-table lea changed')
    require(body[22:26] == bytes.fromhex('4863048e'), 'i32 load changed')
    require(body[26:29] == bytes.fromhex('4801f0'), 'Base add changed')
    require(body[29] == 0xc3, 'Return changed')
    # lea targets resolve to the two table bases (RIP-relative arithmetic).
    require(START + 7 + struct.unpack_from('<i', body, 3)[0] == U64_BASE,
            'u64-table target changed')
    require(START + 22 + struct.unpack_from('<i', body, 18)[0] == I32_BASE,
            'i32-table target changed')
    # No calls inside the window: the locked body contains no e8 byte at all.
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    # No branches inside the window: straight-line to ret.
    require(b'\x74' not in body and b'\x75' not in body and b'\xeb' not in body,
            'Unexpected branch opcode in window')
    # Table bases live in .rodata, and their first entries match retention.
    rodata = by_name['.rodata']
    require(rodata['address'] <= U64_BASE < rodata['address'] + rodata['size'],
            'u64 table outside .rodata')
    require(rodata['address'] <= I32_BASE < rodata['address'] + rodata['size'],
            'i32 table outside .rodata')
    u64 = [struct.unpack_from('<Q', read(U64_BASE + i * 8, 8))[0]
           for i in range(8)]
    i32 = [struct.unpack_from('<i', read(I32_BASE + i * 4, 4))[0]
           for i in range(8)]
    require(u64 == U64_FIRST8, 'u64 table head changed')
    require(i32 == I32_FIRST8, 'i32 table head changed')
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
    require(direct == [CALLER], 'Incoming direct calls changed')
    # The single caller sits inside its caller FDE range, with the retained
    # call bytes and the call-path argument setup (edi load) intact.
    require(CALLER_FDE[0] <= CALLER < CALLER_FDE[1],
            'Caller outside its FDE range')
    require(read(CALLER, 5) == CALL_BYTES, 'Caller call bytes changed')
    require(read(0x29d81ad, 7) == CALLER_SETUP, 'Caller setup changed')
    # Decoded-rule edges (restatement of the retained bytes, not execution).
    require(lookup(U64_FIRST8, I32_FIRST8, 0) == (0x4019b1, 6),
            'Index-0 edge changed')
    require(lookup(U64_FIRST8, I32_FIRST8, 1) == (0x4019b7, 14),
            'Index-1 edge changed')
    require(lookup(U64_FIRST8, I32_FIRST8, 3) == (0x4019d4, 15),
            'Index-3 edge changed')
    require(lookup(U64_FIRST8, I32_FIRST8, 5) == (0x20bfa0, 32),
            'Index-5 edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'relocation_slots': [],
        'direct_callers': direct,
        'u64_head': u64,
        'i32_head': i32,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 '
                    'mixed-width dual-table-lookup evidence packet.')
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
        require(retained['function']['padding_bytes'] == 2, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        require(retained['tables']['u64_first8'] == result['u64_head'],
                'Retained u64 head changed')
        require(retained['tables']['i32_first8'] == result['i32_head'],
                'Retained i32 head changed')
        print('Foundation mixed-width dual-table-lookup evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
