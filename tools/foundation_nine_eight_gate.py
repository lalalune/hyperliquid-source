#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 two-condition 9/8 gate evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window has no outgoing calls: it compares esi against 1 and edi against 4,
ANDs the two sete results, and returns 9 minus that bit. The compared values'
meaning, the constants' meaning beyond their file bytes, and the callers'
behavior beyond their argument setup are not claimed anywhere.

Correction, stated prominently: the build brief's draft instruction sequence
(mov $0x9 first, sete %cl, and %cl,%dil, ...) and its draft caller list
(0x516bd6d, 0x52c8d04) do NOT match the retained bytes. The verified sequence
is cmp/sete/xor/cmp/sete/and/mov/sub/ret, and the verified direct callers are
0x5154497 and 0x5154726, both inside FDE 0x5154460. The checker locks the
verified bytes, not the draft. The round-7 scout note's sequence and caller
list verified exactly.

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
START, END = 0x5229860, 0x522987c
PAD_END = 0x5229880
BODY = bytes.fromhex(
    'f30f1efa83fe010f94c031d283ff040f94c221c2b80900000029d0c3')
PAD = b'\xcc' * 4
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
# The CIE and FDE encodings are zR: initial_location is a 4-byte signed
# PC-relative value, range is a 4-byte unsigned value.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000e8482a005c3a2a041c00000000000000')
NEXT_FDE = bytes.fromhex('10000000fc482a00683a2a040b00000000000000')
CALLERS = [0x5154497, 0x5154726]
CALLER_FDE_START, CALLER_FDE_END = 0x5154460, 0x51547cd


def require(condition, message):
    if not condition:
        raise ValueError(message)


def gate_value(esi_low32, edi_low32):
    """Decoded rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. The comparisons are 32-bit
    (cmp $imm,%esi / cmp $imm,%edi), so only the low 32 bits of rsi and rdi
    matter: rsi = 0x100000001 has low 32 bits 1 and satisfies the first
    condition.
    """
    return 9 - (1 if (esi_low32 & 0xffffffff) == 1
                and (edi_low32 & 0xffffffff) == 4 else 0)


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
    require(body == BODY, 'Nine-eight-gate instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    check_fde(0x2a48e4, FDE, START, END)
    check_fde(0x2a48f8, NEXT_FDE, PAD_END, 0x522988b)
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x5229860.
    require(body[0:4] == bytes.fromhex('f30f1efa'), 'Endbr64 changed')
    require(body[4:7] == bytes.fromhex('83fe01'), 'First comparison changed')
    require(body[6] == 0x01, 'First constant changed')
    require(body[7:10] == bytes.fromhex('0f94c0'), 'First sete changed')
    require(body[10:12] == bytes.fromhex('31d2'), 'Zeroing changed')
    require(body[12:15] == bytes.fromhex('83ff04'), 'Second comparison changed')
    require(body[14] == 0x04, 'Second constant changed')
    require(body[15:18] == bytes.fromhex('0f94c2'), 'Second sete changed')
    require(body[18:20] == bytes.fromhex('21c2'), 'AND changed')
    require(body[20:25] == bytes.fromhex('b809000000'), 'Constant 9 changed')
    require(body[25:27] == bytes.fromhex('29d0'), 'Subtract changed')
    require(body[27:28] == bytes.fromhex('c3'), 'Return changed')
    # The mov $0x9,%eax zeroes the upper bits of eax, so the return value
    # is fully determined: 9 or 8. No low-byte-only caveat applies here,
    # unlike packets #27/#32.
    # Data edge: no relocation record of any type in any .rela.* section
    # names this window as addend.
    for name, sec in by_name.items():
        if name.startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                require(addend != START, 'Unexpected naming relocation')
    # Incoming calls: exactly two direct e8 calls in .text, both inside the
    # caller FDE 0x5154460..0x51547cd. This is a byte-pattern scan,
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
    require(direct == CALLERS, 'Incoming direct calls changed')
    for va in CALLERS:
        call = read(va, 5)
        rel = struct.unpack_from('<i', call, 1)[0]
        require(va + 5 + rel == START, 'Caller target changed')
    # Caller FDE PC/range, decoded by scanning .eh_frame records.
    eh_raw = read(eh['address'], eh['size'])
    found = None
    off = 0
    while off + 8 <= len(eh_raw):
        ln = struct.unpack_from('<I', eh_raw, off)[0]
        if ln == 0:
            break
        cie_id = struct.unpack_from('<I', eh_raw, off + 4)[0]
        if cie_id != 0 and ln >= 16:
            pc = eh['address'] + off + 8 + struct.unpack_from('<i', eh_raw, off + 8)[0]
            rng = struct.unpack_from('<I', eh_raw, off + 12)[0]
            if pc == CALLER_FDE_START:
                found = (pc, pc + rng)
                break
        off += 4 + ln
    require(found == (CALLER_FDE_START, CALLER_FDE_END),
            'Caller FDE PC/range changed')
    # Caller argument setup, verified from the retained caller disassembly:
    # the first call site is preceded by xor %esi,%esi (esi = 0, so the
    # first condition is false and the call returns 9 regardless of edi);
    # the second call site is immediately preceded by mov $0x1,%esi and
    # mov $0x4,%edi, so both conditions hold and the call returns 8.
    require(read(0x5154482, 2) == bytes.fromhex('31f6'),
            'First caller esi setup changed')
    require(read(0x5154716, 10) == bytes.fromhex('be01000000bf04000000'),
            'Second caller esi/edi setup changed')
    # Decoded-formula edges (restatement of the retained bytes, not execution).
    require(gate_value(1, 4) == 8, 'Both-true edge changed')
    require(gate_value(1, 5) == 9, 'Second-false edge changed')
    require(gate_value(0, 4) == 9, 'First-false edge changed')
    require(gate_value(0, 0) == 9, 'Both-false edge changed')
    require(gate_value(0x100000001, 0x100000004) == 8,
            'Low-32-bit edge changed')
    require(gate_value(0x100000002, 4) == 9, 'High-bits edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'call_sites': CALLERS,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 nine-eight-gate '
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
        require(retained['incoming_pattern_scan']['e8_candidates']
                == [hex(v) for v in CALLERS], 'Retained callers changed')
        print('Foundation nine-eight-gate evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
