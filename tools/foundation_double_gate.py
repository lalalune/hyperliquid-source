#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 double threshold gate evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window has no outgoing calls: it loads a double through a field pointer,
compares it against a .rodata constant with comisd, and sets the low byte of
the return value with setae. The compared value's meaning, the constant's
meaning beyond its file bytes, and the callers' behavior are not claimed
anywhere.

Precision caveat, stated prominently: the retained bytes show no instruction
zeroes eax before the setae, so only the LOW BYTE of the return value is the
gate bit; the upper bytes of rax are caller-state dependent and are not
determined by this window. The checker locks the low-byte rule, not a
full-width 0/1 return. This matches packet #27's low-byte-only precedent.

This window is bound ALONE. No census of similar windows is claimed.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import struct
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x5028a40, 0x5028a5b
PAD_END = 0x5028a60
BODY = bytes.fromhex(
    'f30f1efa488b86380f0000f20f1000660f2f05d91c1efb0f93c0c3')
PAD = b'\xcc' * 5
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
# The CIE and FDE encodings are zR: initial_location is a 4-byte signed
# PC-relative value, range is a 4-byte unsigned value.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000084132900a0610b041b00000000000000')
NEXT_FDE = bytes.fromhex('1000000098132900ac610b041700000000000000')
CONSTANT_VA = 0x20a730
CONSTANT_BYTES = bytes.fromhex('000000000000f03f')
SLOT = 0x5759108


def require(condition, message):
    if not condition:
        raise ValueError(message)


def gate_bit(value, threshold=1.0):
    """Low-byte rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. The comisd/setae pair is
    unsigned in the sense that NaN is unordered: comisd sets CF=1 on an
    unordered comparison, so setae is false for NaN.
    """
    if math.isnan(value):
        return 0
    return 1 if value >= threshold else 0


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
    require(body == BODY, 'Double-gate instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    check_fde(0x291380, FDE, START, END)
    check_fde(0x291394, NEXT_FDE, PAD_END, 0x5028a77)
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x5028a40.
    require(body[0:4] == bytes.fromhex('f30f1efa'), 'Endbr64 changed')
    require(body[4:11] == bytes.fromhex('488b86380f0000'),
            'Field-pointer load changed')
    require(struct.unpack_from('<i', body, 7)[0] == 0xf38,
            'Field offset changed')
    require(body[11:15] == bytes.fromhex('f20f1000'), 'Movsd changed')
    require(body[15:23] == bytes.fromhex('660f2f05d91c1efb'),
            'Comisd changed')
    require(START + 15 + 8 + struct.unpack_from('<i', body, 19)[0]
            == CONSTANT_VA, 'Constant target changed')
    require(body[23:26] == bytes.fromhex('0f93c0'), 'Setae changed')
    require(body[26:27] == bytes.fromhex('c3'), 'Return changed')
    # No zeroing instruction appears before the setae: the gate bit is the
    # low byte only, and the checker must not claim a full 0/1.
    require(b'\x31\xc0' not in body,
            'Unexpected zeroing instruction in window')
    # The compared constant is exactly 1.0 in .rodata.
    require(read(CONSTANT_VA, 8) == CONSTANT_BYTES, 'Constant bytes changed')
    require(struct.unpack('<d', CONSTANT_BYTES)[0] == 1.0,
            'Constant value changed')
    # Data edge: exactly one RELATIVE record names this window as addend,
    # at slot 0x5759108 in .data.rel.ro, with file value 0 (applied only
    # at load time). This is a data-pointer reference, not a direct call.
    relsec = by_name['.rela.dyn']
    require(relsec['size'] % 24 == 0, 'Truncated RELA section')
    raw = read(relsec['address'], relsec['size'])
    window_slots = []
    slot_entry = None
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        if addend == START:
            window_slots.append(address)
            slot_entry = (address, info, addend)
    require(window_slots == [SLOT], 'Naming-relocation slots changed')
    require(slot_entry is not None and (slot_entry[1] & 0xffffffff) == 8,
            'Naming-relocation type changed')
    drel = by_name['.data.rel.ro']
    require(drel['address'] <= SLOT < drel['address'] + drel['size'],
            'Naming slot outside .data.rel.ro')
    require(read(SLOT, 8) == b'\x00' * 8, 'Naming slot file value changed')
    # Incoming calls: zero direct e8 calls in .text. This is a byte-pattern
    # scan, explicitly not a complete xref census.
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
    require(gate_bit(1.0) == 1, 'At-threshold edge changed')
    require(gate_bit(0.9999999999999999) == 0, 'Just-below edge changed')
    require(gate_bit(2.5) == 1, 'Above-threshold edge changed')
    require(gate_bit(0.0) == 0, 'Zero edge changed')
    require(gate_bit(-1.0) == 0, 'Negative edge changed')
    require(gate_bit(float('nan')) == 0, 'NaN edge changed')
    require(gate_bit(float('inf')) == 1, 'Positive-infinity edge changed')
    require(gate_bit(float('-inf')) == 0, 'Negative-infinity edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'call_sites': [],
        'constant': 1.0,
        'slot': SLOT,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 double-gate '
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
        require(retained['incoming_pattern_scan']['e8_candidates'] == [],
                'Retained callers changed')
        print('Foundation double-gate evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
