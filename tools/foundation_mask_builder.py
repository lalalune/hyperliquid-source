#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 bitmask-builder evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window has no outgoing calls: one full-width compare, one conditional
jump, one shift, one subtract, one global store, then ret. The global's
runtime meaning is not claimed anywhere; the target slot lies in .data, so
its file value is locked, but that file value is not a runtime claim.

Shift-count masking is the packet's sharpest edge: x86-64 masks the shl count
to 6 bits, so inputs whose low byte is >= 64 store (1 << (low_byte & 63)) - 1.
The rdi == -1 special case is a full-width cmp against 0xffffffffffffffff,
not a low-byte test: an input such as 0x1ff (low byte 0xff, value not -1)
takes the shift path and stores 0x7fffffffffffffff, not -1. The checker locks
this distinction, and the unit tests assert it.

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
START, END = 0x5521d10, 0x5521d37
PAD_END = 0x5521d40
BODY = bytes.fromhex(
    'f30f1efa48c7c0ffffffff4883ffff740eb80100000089f948d3e04883e801'
    '488905da632600c3')
PAD = b'\xcc' * 9
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
# The CIE and FDE encodings are zR: initial_location is a 4-byte signed
# PC-relative value, range is a 4-byte unsigned value.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1400000080922c0074755704270000000000000000000000')
NEXT_FDE = bytes.fromhex('1000000098922c008c7557041e00000000000000')
CALLER_FDE = (
    0x2bfa24,
    bytes.fromhex(
        '3c00000028fa2b001c8c5104bd03000000420e108c02410e188603410e208304'
        '470ea0204c0ea0404c0ed0550314010a0e20430e18410e10420e08430b000000'),
    0x54b9b60, 0x54b9f1d)
CALL_SITE = (0x54b9c3f, bytes.fromhex('e8cc800600'))
GLOBAL_SLOT = 0x5788110
GLOBAL_FILE_VALUE = 0xffffffffffffffff


def require(condition, message):
    if not condition:
        raise ValueError(message)


def mask_value(value):
    """Store rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. The input is a 64-bit value;
    the shift count is the low byte masked to 6 bits, exactly as x86-64
    hardware masks shl counts.
    """
    value &= (1 << 64) - 1
    if value == (1 << 64) - 1:
        return (1 << 64) - 1
    return ((1 << (value & 0xff & 63)) - 1) & ((1 << 64) - 1)


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
    require(body == BODY, 'Mask-builder instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    check_fde(0x2c927c, FDE, START, END)
    check_fde(0x2c9294, NEXT_FDE, PAD_END, 0x5521d5e)
    check_fde(*CALLER_FDE[0:2], CALLER_FDE[2], CALLER_FDE[3])
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x5521d10.
    require(body[0:4] == bytes.fromhex('f30f1efa'), 'Endbr64 changed')
    require(body[4:11] == bytes.fromhex('48c7c0ffffffff'), 'Default -1 changed')
    require(body[11:15] == bytes.fromhex('4883ffff'), 'Minus-one compare changed')
    require(body[15:17] == bytes.fromhex('740e'), 'Conditional jump changed')
    require(START + 15 + 2 + body[16] == 0x5521d2f, 'Jump target changed')
    require(body[17:22] == bytes.fromhex('b801000000'), 'Shift base changed')
    require(body[22:24] == bytes.fromhex('89f9'), 'Count move changed')
    require(body[24:27] == bytes.fromhex('48d3e0'), 'Shift changed')
    require(body[27:31] == bytes.fromhex('4883e801'), 'Subtract changed')
    require(body[31:38] == bytes.fromhex('488905da632600'), 'Global store changed')
    require(START + 31 + 7 + struct.unpack_from('<i', body, 34)[0] == GLOBAL_SLOT,
            'Global slot changed')
    require(body[38:39] == bytes.fromhex('c3'), 'Return changed')
    # The store target lies in .data, not .bss: its file value is locked.
    data_sec = by_name['.data']
    require(data_sec['address'] <= GLOBAL_SLOT
            < data_sec['address'] + data_sec['size'], 'Global not in .data')
    stored = struct.unpack_from('<Q', read(GLOBAL_SLOT, 8))[0]
    require(stored == GLOBAL_FILE_VALUE, 'Global file value changed')
    # Caller call bytes and target come before the incoming scan, so a
    # mutated call site reports its own check rather than the scan's.
    site, raw = CALL_SITE
    call = read(site, 5)
    require(call == raw, 'Caller call bytes changed')
    require(site + 5 + struct.unpack_from('<i', call, 1)[0] == START,
            'Caller call target changed')
    # Incoming calls: exactly one direct e8 call, no indirect slot calls.
    # No relocation of any type maps a slot to this window.
    relsec = by_name['.rela.dyn']
    require(relsec['size'] % 24 == 0, 'Truncated RELA section')
    rels = {}
    raw = read(relsec['address'], relsec['size'])
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        require(address not in rels, 'Duplicate relocation address')
        rels[address] = (info, addend)
    window_slots = [a for a, (info, addend) in rels.items() if addend == START]
    require(window_slots == [], 'Unexpected slot maps to window')
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == [CALL_SITE[0]], 'Incoming direct calls changed')
    # Decoded-formula edges (restatement of the retained bytes, not execution).
    require(mask_value(0) == 0, 'Input-0 edge changed')
    require(mask_value(1) == 1, 'Input-1 edge changed')
    require(mask_value(63) == 0x7fffffffffffffff, 'Input-63 edge changed')
    require(mask_value(64) == 0, 'Input-64 masking edge changed')
    require(mask_value(65) == 1, 'Input-65 masking edge changed')
    require(mask_value(127) == 0x7fffffffffffffff, 'Input-127 masking edge changed')
    require(mask_value(255) == 0x7fffffffffffffff, 'Input-255 masking edge changed')
    require(mask_value((1 << 64) - 1) == (1 << 64) - 1, 'Minus-one edge changed')
    require(mask_value(0x1ff) == 0x7fffffffffffffff,
            'Low-byte-ff-but-not-minus-one edge changed')
    require(mask_value(0x1ff) != (1 << 64) - 1,
            'Shift path must not yield all ones for 0x1ff')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'call_sites': [CALL_SITE[0]],
        'mask_edges': {'input_0': 0, 'input_1': 1, 'input_63': 0x7fffffffffffffff,
                       'input_64': 0, 'input_65': 1,
                       'input_minus_1': (1 << 64) - 1},
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 mask-builder '
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
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(CALL_SITE[0])],
                'Retained callers changed')
        print('Foundation mask-builder evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
