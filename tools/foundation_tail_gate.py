#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 tail-gate evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window has no outgoing calls: one field load, one subtract, two unsigned
compares, two conditional jumps, one tail jump, one return. The tail target
is a shared callee that this packet names but does not decode.

The packet's sharpest edge is the v == 3 case: the scout note said "v > 2
returns 0x30 without jumping", but the retained bytes show v == 3 takes the
n == 1 path and tail-jumps with rdi+0x28, exactly like v < 2. Only v >= 4
returns 0x30 without jumping. The checker and unit tests lock the corrected
rule, and a test explicitly asserts the scout's v == 3 prediction fails.

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
START, END = 0x250ab00, 0x250ab32
PAD_END = 0x250ab40
BODY = bytes.fromhex(
    '488b07488d50fe4883f802b901000000480f43ca4883f901740bb830000000'
    '4885c97406c3b8280000004801c7e92edcffff')
PAD = b'\xcc' * 14
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
# The CIE and FDE encodings are zR: initial_location is a 4-byte signed
# PC-relative value, range is a 4-byte unsigned value.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000184f0800cc467a013200000000000000')
NEXT_FDE = bytes.fromhex(
    '480000002c4f0800f8467a017c00000000420e10420e18420e20420e28410e308'
    '3068c058d048e038f02025b0e28420e20420e18420e10420e08460e30410e28420'
    'e20420e18420e10420e08')
CALLER_FDE1 = (
    0x3e2958,
    bytes.fromhex(
        '5000000048621000987743018f120000044be893ff410e10420e18420e204'
        '20e28420e30410e38470ee01b83078c068d058e048f0386020388100e38410'
        'e30420e28420e20420e18420e10410e08410ee01b0000'),
    0x24fb610, 0x24fc89f)
CALLER_FDE2 = (
    0x3e29ac,
    bytes.fromhex(
        '500000009c621000d4894301b4140000046be893ff410e10420e18420e204'
        '20e28420e30410e38470ef01a83078c068d058e048f038602037b130e38410'
        'e30420e28420e20420e18420e10410e08410ef01a0000'),
    0x24fc8a0, 0x24fdd54)
CALL_SITES = (
    (0x24fc82b, bytes.fromhex('e8d0e20000')),
    (0x24fdce3, bytes.fromhex('e818ce0000')),
)
TAIL_TARGET = 0x2508760


def require(condition, message):
    if not condition:
        raise ValueError(message)


def gate_outcome(value):
    """Gate rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. The input is a 64-bit field
    value; the cmovae compare is unsigned. Returns ('jump', offset) for the
    tail-jump paths and ('return', 0x30) for the no-jump path.
    """
    value &= (1 << 64) - 1
    n = (value - 2) & ((1 << 64) - 1) if value >= 2 else 1
    if n == 1:
        return ('jump', 0x28)
    if n == 0:
        return ('jump', 0x30)
    return ('return', 0x30)


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
    require(body == BODY, 'Tail-gate instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    check_fde(0x84f14, FDE, START, END)
    check_fde(0x84f28, NEXT_FDE, PAD_END, 0x250abbc)
    check_fde(*CALLER_FDE1[0:2], CALLER_FDE1[2], CALLER_FDE1[3])
    check_fde(*CALLER_FDE2[0:2], CALLER_FDE2[2], CALLER_FDE2[3])
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x250ab00.
    require(body[0:3] == bytes.fromhex('488b07'), 'Field load changed')
    require(body[3:7] == bytes.fromhex('488d50fe'), 'Subtract changed')
    require(body[7:11] == bytes.fromhex('4883f802'), 'Threshold compare changed')
    require(body[11:16] == bytes.fromhex('b901000000'), 'Default n changed')
    require(body[16:20] == bytes.fromhex('480f43ca'), 'Conditional move changed')
    require(body[20:24] == bytes.fromhex('4883f901'), 'n compare changed')
    require(body[24:26] == bytes.fromhex('740b'), 'n == 1 jump changed')
    require(START + 24 + 2 + body[25] == 0x250ab25, 'n == 1 jump target changed')
    require(body[26:31] == bytes.fromhex('b830000000'), 'Return value changed')
    require(body[31:34] == bytes.fromhex('4885c9'), 'n zero test changed')
    require(body[34:36] == bytes.fromhex('7406'), 'n == 0 jump changed')
    require(START + 34 + 2 + body[35] == 0x250ab2a, 'n == 0 jump target changed')
    require(body[36:37] == bytes.fromhex('c3'), 'Return changed')
    require(body[37:42] == bytes.fromhex('b828000000'), 'Jump offset changed')
    require(body[42:45] == bytes.fromhex('4801c7'), 'Argument add changed')
    require(body[45:50] == bytes.fromhex('e92edcffff'), 'Tail jump changed')
    require(START + 45 + 5 + struct.unpack_from('<i', body, 46)[0] == TAIL_TARGET,
            'Tail jump target changed')
    # Caller call bytes and targets come before the incoming scan, so a
    # mutated call site reports its own check rather than the scan's.
    for site, raw in CALL_SITES:
        call = read(site, 5)
        require(call == raw, 'Caller call bytes changed')
        require(site + 5 + struct.unpack_from('<i', call, 1)[0] == START,
                'Caller call target changed')
    # Incoming calls: exactly two direct e8 calls, no indirect slot calls.
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
    require(direct == [site for site, _ in CALL_SITES],
            'Incoming direct calls changed')
    # Decoded-formula edges (restatement of the retained bytes, not execution).
    # The v == 3 edge is the scout correction: n == 1, so it tail-jumps
    # with +0x28, exactly like v < 2 — it does NOT return 0x30.
    require(gate_outcome(0) == ('jump', 0x28), 'Input-0 edge changed')
    require(gate_outcome(1) == ('jump', 0x28), 'Input-1 edge changed')
    require(gate_outcome(2) == ('jump', 0x30), 'Input-2 edge changed')
    require(gate_outcome(3) == ('jump', 0x28), 'Input-3 edge changed')
    require(gate_outcome(3) != ('return', 0x30),
            'Input-3 must tail-jump, not return')
    require(gate_outcome(4) == ('return', 0x30), 'Input-4 edge changed')
    require(gate_outcome(5) == ('return', 0x30), 'Input-5 edge changed')
    require(gate_outcome(0xffffffffffffffff) == ('return', 0x30),
            'Input-max edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'call_sites': [site for site, _ in CALL_SITES],
        'tail_target': TAIL_TARGET,
        'gate_edges': {'input_0': ('jump', 0x28), 'input_1': ('jump', 0x28),
                       'input_2': ('jump', 0x30), 'input_3': ('jump', 0x28),
                       'input_4': ('return', 0x30)},
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 tail-gate '
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
                [hex(site) for site, _ in CALL_SITES],
                'Retained callers changed')
        print('Foundation tail-gate evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
