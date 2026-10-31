#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 divide-then-log2 bucket packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window divides its first argument by its second (unsigned div), then
buckets the quotient: q < 2 -> 0, else min(floor(log2(q)), 6), via a shift
ladder. What the bytes mean, and what reads the result, is not claimed
anywhere.
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
START, END = 0x4f9eb10, 0x4f9eb82
PAD_END = 0x4f9eb90
CALL_SITE = 0x4f9d240
BODY = bytes.fromhex(
    'f30f1efa31d24889f848f7f64889c148d1e9743c4889c248c1ea02743b4889c7'
    '48c1ef03743a4889c148c1e90474374889c748c1ef05743448c1e8060f95c00f'
    'b6c083c005c3662e0f1f84000000000031c0c30f1f440000b801000000c36690'
    'b802000000c3b803000000c3b804000000c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000040ac2800b42903047200000000000000')
NEXT = bytes.fromhex(
    '1400000054ac2800202a03041500000000480e104c0e0800')
CALLER_CIE = bytes.fromhex(
    '1c00000000000000017a504c5200017810079b3d5848041b1b0c070890010000')
CALLER_FDE = bytes.fromhex(
    '34000000cc12000068a1c9037304000004818c8cff450e108602430d06498f03'
    '8e048d058c068307026a0a0c0708450b02c42e1002602e00')
CALL_BYTES = bytes.fromhex('e8cb180000')
# Argument setup observed upstream of the call (rsi = 0x80000, rdi = r14),
# with stack stores intervening before the call; caller purpose not claimed.
CALL_ARGSETUP = bytes.fromhex('be000008004c89f7')
# The two movsd stores immediately before the call site.
CALL_TAIL = bytes.fromhex('f20f118d70fffffff20f114588')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse(dividend, divisor):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. Returns 0 when the unsigned quotient
    is below 2, else min(floor(log2(q)), 6). A zero divisor is excluded:
    the hardware div traps, so no return value exists for that input.
    """
    if divisor == 0:
        raise ValueError('divisor zero traps; no defined bucket')
    q = dividend // divisor
    if q < 2:
        return 0
    return min(q.bit_length() - 1, 6)


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
    require(body == BODY, 'Divide-then-log2-bucket instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    for offset, raw, start, end in [
            (0x28ac3c, FDE, START, END),
            (0x28ac50, NEXT, PAD_END, 0x4f9eba5),
            (0x6205d0, CALLER_CIE, None, None),
            (0x621898, CALLER_FDE, 0x4f9cf20, 0x4f9d393)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE/CIE record changed')
        if start is not None:
            pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
            extent = struct.unpack_from('<I', record, 12)[0]
            require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: fourteen int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 14, 'Padding changed')
    require(PAD_END == 0x4f9eb90, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x4f9eb10.
    fixed = [
        (0x00, 'f30f1efa', 'Entry endbr64 changed'),
        (0x04, '31d2', 'Div high word zeroing changed'),
        (0x06, '4889f8', 'Dividend move changed'),
        (0x09, '48f7f6', 'Unsigned divide changed'),
        (0x0c, '4889c1', 'Quotient to rcx changed'),
        (0x0f, '48d1e9', 'Shift by 1 changed'),
        (0x12, '743c', 'First bucket branch changed'),
        (0x14, '4889c2', 'Quotient to rdx changed'),
        (0x17, '48c1ea02', 'Shift by 2 changed'),
        (0x1b, '743b', 'Second bucket branch changed'),
        (0x1d, '4889c7', 'Quotient to rdi changed'),
        (0x20, '48c1ef03', 'Shift by 3 changed'),
        (0x24, '743a', 'Third bucket branch changed'),
        (0x26, '4889c1', 'Quotient to rcx changed'),
        (0x29, '48c1e904', 'Shift by 4 changed'),
        (0x2d, '7437', 'Fourth bucket branch changed'),
        (0x2f, '4889c7', 'Quotient to rdi changed'),
        (0x32, '48c1ef05', 'Shift by 5 changed'),
        (0x36, '7434', 'Fifth bucket branch changed'),
        (0x38, '48c1e806', 'Shift by 6 changed'),
        (0x3c, '0f95c0', 'Cap test changed'),
        (0x3f, '0fb6c0', 'Cap zero-extend changed'),
        (0x42, '83c005', 'Cap add changed'),
        (0x45, 'c3', 'Cap return changed'),
        (0x46, '662e0f1f840000000000', 'First return alignment nop changed'),
        (0x50, '31c0', 'Zero bucket constant changed'),
        (0x52, 'c3', 'Zero bucket return changed'),
        (0x53, '0f1f440000', 'One bucket alignment nop changed'),
        (0x58, 'b801000000', 'One bucket constant changed'),
        (0x5d, 'c3', 'One bucket return changed'),
        (0x5e, '6690', 'Two bucket alignment nop changed'),
        (0x60, 'b802000000', 'Two bucket constant changed'),
        (0x65, 'c3', 'Two bucket return changed'),
        (0x66, 'b803000000', 'Three bucket constant changed'),
        (0x6b, 'c3', 'Three bucket return changed'),
        (0x6c, 'b804000000', 'Four bucket constant changed'),
        (0x71, 'c3', 'Four bucket return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # Branch targets, decoded from the retained displacements.
    require(0x14 + 0x3c == 0x50, 'First bucket branch target changed')
    require(0x1d + 0x3b == 0x58, 'Second bucket branch target changed')
    require(0x26 + 0x3a == 0x60, 'Third bucket branch target changed')
    require(0x2f + 0x37 == 0x66, 'Fourth bucket branch target changed')
    require(0x38 + 0x34 == 0x6c, 'Fifth bucket branch target changed')
    # No call instruction inside the window. This must be checked at
    # instruction starts, not by substring: the shr $6 encoding at offset
    # 0x38 (48 c1 e8 06) contains an 0xe8 byte that is not a call opcode.
    starts = [off for off, _, _ in fixed]
    require(all(body[off] != 0xe8 for off in starts),
            'Unexpected call opcode in window')
    # The single caller: call bytes, upstream argument setup, and the two
    # stores immediately before the call.
    require(read(CALL_SITE, len(CALL_BYTES)) == CALL_BYTES,
            'Caller call bytes changed')
    require(read(0x4f9d21d, len(CALL_ARGSETUP)) == CALL_ARGSETUP,
            'Caller argument setup changed')
    require(read(CALL_SITE - 13, len(CALL_TAIL)) == CALL_TAIL,
            'Caller tail changed')
    # Relocations: no record of any type names this window as addend.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((sec['name'], address))
    require(naming == [], 'Unexpected naming relocation')
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
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    require(parse(0, 7) == 0, 'Zero quotient edge changed')
    require(parse(1, 1) == 0, 'Quotient one edge changed')
    require(parse(2, 1) == 1, 'Quotient two edge changed')
    require(parse(3, 1) == 1, 'Quotient three edge changed')
    require(parse(4, 1) == 2, 'Quotient four edge changed')
    require(parse(7, 1) == 2, 'Quotient seven edge changed')
    require(parse(8, 1) == 3, 'Quotient eight edge changed')
    require(parse(15, 1) == 3, 'Quotient fifteen edge changed')
    require(parse(16, 1) == 4, 'Quotient sixteen edge changed')
    require(parse(31, 1) == 4, 'Quotient thirty-one edge changed')
    require(parse(32, 1) == 5, 'Quotient thirty-two edge changed')
    require(parse(63, 1) == 5, 'Quotient sixty-three edge changed')
    require(parse(64, 1) == 6, 'Quotient sixty-four edge changed')
    require(parse(2 ** 63, 1) == 6, 'Huge quotient cap edge changed')
    require(parse(2 ** 64 - 1, 1) == 6, 'Max quotient cap edge changed')
    require(parse(100, 7) == 3, 'Division edge changed')
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
                    'divide-then-log2 bucket evidence packet.')
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
        require(retained['function']['padding_bytes'] == 14, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation divide-then-log2-bucket evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
