#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 two-argument tzcnt-gate packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window takes two unsigned arguments (rdi, rsi) and dispatches through one
of two GOT slots: slot A when (rsi < 0x11 and rsi <= rdi) or when tzcnt(rsi)
is 0, slot B otherwise. The two slot targets are real function prologues
(endbr64 + body); their bodies are not decoded and no callee contract is
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
START, END = 0x14bf180, 0x14bf1a7
PAD_END = 0x14bf1b0
BODY = bytes.fromhex(
    '4883fe110f92c04839fe0f96c184c87510f3480fbcf64885f67406ff25eff02a04'
    'ff2531ee2a04')
PAD = b'\xcc' * 9
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000a0e40000c4f77c002700000000000000')
NEXT_FDE = bytes.fromhex('10000000b4e40000e0f77c002100000000000000')
# Dispatch slots: GOT slots, RELATIVE relocations, file value 0, applied
# only at load time. Slot A is the joint first-gate/tzcnt-zero target.
SLOT_A, TARGET_A = 0x576dfd8, 0x54c06b0
SLOT_B, TARGET_B = 0x576e290, 0x54c2670
# One R_X86_64_RELATIVE record in .rela.dyn names this window as addend:
# a GOT slot, file value 0, applied only at load time. The window is
# referenced by a data pointer, not by a direct call.
WINDOW_SLOTS = [0x576fd50]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def tzcnt(value):
    """Trailing-zero count of a u64, with tzcnt(0) == 64 per the ISA."""
    require(0 <= value < 1 << 64, 'Value outside the u64 argument domain')
    if value == 0:
        return 64
    return (value & -value).bit_length() - 1


def dispatch(rdi, rsi):
    """Decoded dispatch rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. Returns 'A' for the slot-A jump
    at 0x14bf1a1 and 'B' for the slot-B jump at 0x14bf19b.
    """
    require(0 <= rdi < 1 << 64, 'First argument outside the u64 domain')
    require(0 <= rsi < 1 << 64, 'Second argument outside the u64 domain')
    if rsi < 0x11 and rsi <= rdi:
        return 'A'
    if tzcnt(rsi) == 0:
        return 'A'
    return 'B'


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
    require(body == BODY, 'Tzcnt-gate instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in [(0xe49c, FDE, START, END),
                                    (0xe4b0, NEXT_FDE, 0x14bf1b0, 0x14bf1d1)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x14bf180.
    require(body[0:4] == bytes.fromhex('4883fe11'), 'Threshold compare changed')
    require(body[4:7] == bytes.fromhex('0f92c0'), 'Set-below changed')
    require(body[7:10] == bytes.fromhex('4839fe'), 'Order compare changed')
    require(body[10:13] == bytes.fromhex('0f96c1'), 'Set-below-or-equal changed')
    require(body[13:15] == bytes.fromhex('84c8'), 'Gate AND changed')
    require(body[15:17] == bytes.fromhex('7510'), 'First-gate branch changed')
    require(0x14bf18f + 2 + struct.unpack_from('<b', body, 16)[0] == 0x14bf1a1,
            'First-gate branch target changed')
    require(body[17:22] == bytes.fromhex('f3480fbcf6'), 'Tzcnt changed')
    require(body[22:25] == bytes.fromhex('4885f6'), 'Tzcnt-zero test changed')
    require(body[25:27] == bytes.fromhex('7406'), 'Tzcnt-zero branch changed')
    require(0x14bf199 + 2 + struct.unpack_from('<b', body, 26)[0] == 0x14bf1a1,
            'Tzcnt-zero branch target changed')
    require(body[27:33] == bytes.fromhex('ff25eff02a04'), 'Slot-B jump changed')
    require(0x14bf1a1 + struct.unpack_from('<i', body, 29)[0] == SLOT_B,
            'Slot-B jump target changed')
    require(body[33:39] == bytes.fromhex('ff2531ee2a04'), 'Slot-A jump changed')
    require(0x14bf1a7 + struct.unpack_from('<i', body, 35)[0] == SLOT_A,
            'Slot-A jump target changed')
    # No calls inside the window: none of the locked instruction starts is a
    # call opcode, and the full locked body contains no e8 call opcode at an
    # instruction boundary (the fixed-offset locks above pin every boundary).
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    # Relocations: the two dispatch slots are RELATIVE relocations in .got
    # with the callee addresses as addends; the file stores 0 in both slots.
    # No RELATIVE record names this window itself as addend.
    relsec = by_name['.rela.dyn']
    require(relsec['size'] % 24 == 0, 'Truncated RELA section')
    rels = {}
    raw = read(relsec['address'], relsec['size'])
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        require(address not in rels, 'Duplicate relocation address')
        rels[address] = (info, addend)
    for slot, target in ((SLOT_A, TARGET_A), (SLOT_B, TARGET_B)):
        require(rels.get(slot) == (8, target), 'Dispatch slot relocation changed')
        slot_secs = [s for s in secs if s['address'] <= slot
                     < s['address'] + s['size']]
        require(len(slot_secs) == 1 and slot_secs[0]['name'] == '.got',
                'Dispatch slot section changed')
        require(struct.unpack_from('<Q', read(slot, 8), 0)[0] == 0,
                'Dispatch slot file value changed')
        target_secs = [s for s in secs if s['address'] <= target
                       < s['address'] + s['size']]
        require(len(target_secs) == 1 and target_secs[0]['name'] == '.text',
                'Dispatch target section changed')
        # Only the endbr64 prefix is locked; the callee bodies are not
        # decoded and no callee contract is claimed.
        require(read(target, 4) == bytes.fromhex('f30f1efa'),
                'Dispatch target prologue prefix changed')
    window_slots = [a for a, (info, addend) in rels.items()
                    if info == 8 and addend == START]
    require(window_slots == WINDOW_SLOTS, 'Relocation slots naming window changed')
    for slot in WINDOW_SLOTS:
        slot_secs = [s for s in secs if s['address'] <= slot
                     < s['address'] + s['size']]
        require(len(slot_secs) == 1 and slot_secs[0]['name'] == '.got',
                'Window slot section changed')
        require(struct.unpack_from('<Q', read(slot, 8), 0)[0] == 0,
                'Window slot file value changed')
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
    # Decoded-dispatch edges (restatement of the retained bytes, not execution).
    # rsi == 0 never reaches the tzcnt branch: the first gate already takes
    # it (0 < 0x11 and 0 <= rdi for every rdi).
    require(dispatch(0, 0) == 'A', 'Zero edge changed')
    require(dispatch(16, 16) == 'A', 'Threshold-equality edge changed')
    require(dispatch(15, 16) == 'B', 'Order-fail edge changed')
    require(dispatch(100, 17) == 'A', 'Odd-second-argument edge changed')
    require(dispatch(100, 18) == 'B', 'Even-second-argument edge changed')
    require(dispatch(5, 3) == 'A', 'Small first-gate edge changed')
    require(dispatch(0xffffffffffffffff, 0x8000000000000000) == 'B',
            'High-bit edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'dispatch_slots': {'A': hex(SLOT_A), 'B': hex(SLOT_B)},
        'dispatch_targets': {'A': hex(TARGET_A), 'B': hex(TARGET_B)},
        'relocation_slots_naming_window': [hex(a) for a in WINDOW_SLOTS],
        'direct_callers': direct,
        'text_byte_count': len(code),
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 two-argument '
                    'tzcnt-gate evidence packet.')
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
                result['relocation_slots_naming_window'],
                'Retained window slots changed')
        require(retained['incoming_pattern_scan']['byte_count'] ==
                result['text_byte_count'], 'Retained scan size changed')
        require(retained['behavior']['dispatch_slots'] ==
                result['dispatch_slots'], 'Retained dispatch slots changed')
        require(retained['behavior']['dispatch_targets'] ==
                result['dispatch_targets'], 'Retained dispatch targets changed')
        print('Foundation tzcnt-gate evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
