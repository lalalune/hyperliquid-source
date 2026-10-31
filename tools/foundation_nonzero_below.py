#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 256-bit nonzero-and-below evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window has no outgoing calls: it ORs four words of one operand, subtracts
four words of a second operand with a borrow chain, and returns 1 exactly when
the first operand is nonzero and below the second as unsigned 256-bit values.
The subtraction results live only in caller-saved registers and are never
stored; the operands' meaning and the callers' behavior are not claimed
anywhere.

This window is bound ALONE. No census of similar windows is claimed.
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
START, END = 0x565dd80, 0x565ddc5
PAD_END = 0x565dde0
BODY = bytes.fromhex(
    'f30f1efa488b074c8b4f084c8b57104c8b5f184989c04c09c84c09d04c09d8'
    '4c2b064c1b4e084c1b56104c1b5e184819f648c7c2010000004883f800480f'
    '45c24821f0f3c3')
PAD = bytes.fromhex(
    '9066662e0f1f84000000000066662e0f1f8400000000000f1f4000')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
# The CIE and FDE encodings are zR: initial_location is a 4-byte signed
# PC-relative value, range is a 4-byte unsigned value.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000038c32d002c056a044500000000000000')
NEXT_FDE = bytes.fromhex(
    '240000004cc32d0078056a048e00000000450e108602410e188303440e200278'
    'c345c6450e080000')
CALLERS = [
    (0x56508a6, 0x56507c0, 0x5650951),
    (0x5650c86, 0x5650ba0, 0x5650d31),
    (0x5651e5f, 0x5651e50, 0x5651eb8),
]
MASK64 = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def predicate(minuend, subtrahend):
    """256-bit nonzero-and-below rule, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. Words are in low-to-high order
    (word 0 is the first 8 bytes at the operand pointer). The borrow chain
    yields 1 exactly when minuend < subtrahend as unsigned 256-bit values;
    the OR chain yields 1 exactly when the minuend is nonzero.
    """
    require(len(minuend) == 4 and len(subtrahend) == 4, 'Need four words')
    nonzero = any(w != 0 for w in minuend)
    borrow = 0
    for i in range(4):
        diff = minuend[i] - subtrahend[i] - borrow
        borrow = 1 if diff < 0 else 0
    return 1 if (nonzero and borrow) else 0


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
    require(body == BODY, 'Nonzero-below instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    require(b'\xcc' not in PAD, 'Padding is not int3')
    eh = by_name['.eh_frame']

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    check_fde(0x2dc334, FDE, START, END)
    check_fde(0x2dc348, NEXT_FDE, PAD_END, 0x565de6e)
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x565dd80.
    require(body[0:4] == bytes.fromhex('f30f1efa'), 'Endbr64 changed')
    require(body[4:7] == bytes.fromhex('488b07'), 'Word-0 load changed')
    require(body[7:11] == bytes.fromhex('4c8b4f08'), 'Word-1 load changed')
    require(body[11:15] == bytes.fromhex('4c8b5710'), 'Word-2 load changed')
    require(body[15:19] == bytes.fromhex('4c8b5f18'), 'Word-3 load changed')
    require(body[19:22] == bytes.fromhex('4989c0'), 'Word-0 move changed')
    require(body[22:25] == bytes.fromhex('4c09c8'), 'OR word-1 changed')
    require(body[25:28] == bytes.fromhex('4c09d0'), 'OR word-2 changed')
    require(body[28:31] == bytes.fromhex('4c09d8'), 'OR word-3 changed')
    require(body[31:34] == bytes.fromhex('4c2b06'), 'SUB word-0 changed')
    require(body[34:38] == bytes.fromhex('4c1b4e08'), 'SBB word-1 changed')
    require(body[38:42] == bytes.fromhex('4c1b5610'), 'SBB word-2 changed')
    require(body[42:46] == bytes.fromhex('4c1b5e18'), 'SBB word-3 changed')
    require(body[46:49] == bytes.fromhex('4819f6'),
            'Borrow-mask sbb changed')
    require(body[49:56] == bytes.fromhex('48c7c201000000'),
            'Constant-one move changed')
    require(body[56:60] == bytes.fromhex('4883f800'), 'Zero compare changed')
    require(body[60:64] == bytes.fromhex('480f45c2'), 'CMOVNE changed')
    require(body[64:67] == bytes.fromhex('4821f0'), 'Borrow AND changed')
    require(body[67:69] == bytes.fromhex('f3c3'), 'Return changed')
    # No instruction in the window stores to memory: every locked instruction
    # above reads operands or writes registers only. In particular no call
    # opcode starts any locked instruction.
    starts = [0, 4, 7, 11, 15, 19, 22, 25, 28, 31, 34, 38, 42, 46, 49, 56,
              60, 64, 67]
    require(all(body[s] != 0xe8 for s in starts),
            'Unexpected call opcode at an instruction start')
    # Incoming calls: exactly three direct e8 call sites in .text, each
    # confirmed as an instruction start by linear disassembly from its
    # caller FDE start (see caller.objdump.txt). This byte-pattern scan is
    # explicitly not a complete xref census.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == [c[0] for c in CALLERS], 'Incoming direct calls changed')
    for site, fde_start, fde_end in CALLERS:
        require(fde_start <= site < fde_end, 'Caller site outside its FDE')
        require(code[site - text['address']] == 0xe8, 'Caller call byte changed')
        rel = struct.unpack_from('<i', code, site - text['address'] + 1)[0]
        require(site + 5 + rel == START, 'Caller call target changed')
    # Data edge: no relocation record of any type in any .rela.* section
    # names this window as addend (full-section scan).
    naming = []
    for s in secs:
        if not s['name'].startswith('.rela.'):
            continue
        require(s['size'] % 24 == 0, 'Truncated RELA section')
        raw = read(s['address'], s['size'])
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if addend == START:
                naming.append(address)
    require(naming == [], 'Naming-relocation slots changed')
    # Decoded-formula edges (restatement of the retained bytes, not execution).
    require(predicate((0, 0, 0, 0), (1, 0, 0, 0)) == 0, 'Zero edge changed')
    require(predicate((1, 0, 0, 0), (2, 0, 0, 0)) == 1, 'Below edge changed')
    require(predicate((2, 0, 0, 0), (2, 0, 0, 0)) == 0, 'Equal edge changed')
    require(predicate((2, 0, 0, 0), (1, 0, 0, 0)) == 0, 'Above edge changed')
    require(predicate((0, 0, 0, 1), (0, 0, 0, 1)) == 0, 'Top-word equal changed')
    require(predicate((1, 0, 0, 0), (MASK64, MASK64, MASK64, MASK64)) == 1,
            'Max-subtrahend edge changed')
    require(predicate((0, 1, 0, 0), (1, 1, 0, 0)) == 1,
            'High-word below edge changed')
    require(predicate((MASK64, MASK64, MASK64, MASK64),
                      (MASK64, MASK64, MASK64, MASK64)) == 0,
            'Max-equal edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'call_sites': [c[0] for c in CALLERS],
        'naming_slots': [],
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 nonzero-and-below '
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
        require([int(c['site'], 16) for c in retained['callers']] == result['call_sites'],
                'Retained callers changed')
        require(retained['naming_relocation']['slots'] == result['naming_slots'],
                'Retained naming slots changed')
        print('Foundation nonzero-below evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
