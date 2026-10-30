#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 global range-membership evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window has no outgoing calls: it reads two .bss globals, combines two
unsigned setcc results with AND, and returns. The globals' runtime values and
meaning are not claimed anywhere, and .bss has no file bytes to lock.

Precision correction over the scout note: the scout described the window as
"return 1 iff lo <= rdi < hi, else 0". The retained bytes show no instruction
zeroes eax or ecx before the setcc/AND sequence, so only the LOW BYTE of the
return value is the membership bit; the upper bytes of rax are caller-state
dependent and are not determined by this window. All four callers consume the
result with test %al,%al, which is consistent with low-byte-only use. The
checker locks the low-byte rule, not a full-width 0/1 return.

This window is bound ALONE. The next FDE at 0x5520e20 is a two-pointer range
comparison using the same two globals; it is a related but separate window
and is never bound here, never as a pair.
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
START, END = 0x5520e00, 0x5520e1e
PAD_END = 0x5520e20
BODY = bytes.fromhex(
    'f30f1efa488b1515994700483b3d1e9947000f93c04839d70f92c121c8c3')
PAD = b'\xcc' * 2
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
# The CIE and FDE encodings are zR: initial_location is a 4-byte signed
# PC-relative value, range is a 4-byte unsigned value.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000078902c006c6857041e00000000000000')
NEXT_FDE = bytes.fromhex('100000008c902c00786857045100000000000000')
CALLER_FDES = [
    (0x2c7e30,
     bytes.fromhex('30000000347e2c0070f156043900000000450e108602470e188303470e204d0a0e18410e10410e08460b440e18470e10410e0800'),
     0x55184c0, 0x55184f9),
    (0x2c7e64,
     bytes.fromhex('30000000687e2c007cf156043900000000450e108602470e188303470e204d0a0e18410e10410e08460b440e18470e10410e0800'),
     0x5518500, 0x5518539),
    (0x2c7f74,
     bytes.fromhex('30000000787f2c008cf356043100000000450e108602440e188303470e204d0a0e18410e10410e08410b440e18470e10410e0800'),
     0x5518820, 0x5518851),
    (0x2c7fa8,
     bytes.fromhex('30000000ac7f2c0098f356043100000000450e108602440e188303470e204d0a0e18410e10410e08410b440e18470e10410e0800'),
     0x5518860, 0x5518891),
]
CALL_SITES = [
    (0x55184d3, bytes.fromhex('e828890000')),
    (0x5518513, bytes.fromhex('e8e8880000')),
    (0x5518830, bytes.fromhex('e8cb850000')),
    (0x5518870, bytes.fromhex('e88b850000')),
]
HI_SLOT, LO_SLOT = 0x599a720, 0x599a730


def require(condition, message):
    if not condition:
        raise ValueError(message)


def membership_bit(lo, hi, value):
    """Low-byte rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. Comparisons are unsigned.
    """
    return 1 if lo <= value < hi else 0


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
    require(body == BODY, 'Range-test instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    check_fde(0x2c9074, FDE, START, END)
    check_fde(0x2c9088, NEXT_FDE, PAD_END, 0x5520e71)
    for offset, raw, start, end in CALLER_FDES:
        check_fde(offset, raw, start, end)
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x5520e00.
    require(body[0:4] == bytes.fromhex('f30f1efa'), 'Endbr64 changed')
    require(body[4:11] == bytes.fromhex('488b1515994700'), 'Hi-global load changed')
    require(START + 4 + 7 + struct.unpack_from('<i', body, 7)[0] == HI_SLOT,
            'Hi-global slot changed')
    require(body[11:18] == bytes.fromhex('483b3d1e994700'), 'Lo-global compare changed')
    require(START + 11 + 7 + struct.unpack_from('<i', body, 14)[0] == LO_SLOT,
            'Lo-global slot changed')
    require(body[18:21] == bytes.fromhex('0f93c0'), 'Setae changed')
    require(body[21:24] == bytes.fromhex('4839d7'), 'Hi compare changed')
    require(body[24:27] == bytes.fromhex('0f92c1'), 'Setb changed')
    require(body[27:29] == bytes.fromhex('21c8'), 'AND changed')
    require(body[29:30] == bytes.fromhex('c3'), 'Return changed')
    # No zeroing instruction appears before the setcc pair: the membership
    # bit is the low byte only, and the checker must not claim a full 0/1.
    require(b'\x31\xc0' not in body and b'\x31\xc9' not in body,
            'Unexpected zeroing instruction in window')
    # Caller call bytes and targets come before the incoming scan, so a
    # mutated call site reports its own check rather than the scan's.
    for site, raw in CALL_SITES:
        call = read(site, 5)
        require(call == raw, 'Caller call bytes changed')
        require(site + 5 + struct.unpack_from('<i', call, 1)[0] == START,
                'Caller call target changed')
    # Incoming calls: exactly four direct e8 calls, no indirect slot calls.
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
    require(direct == [site for site, _ in CALL_SITES], 'Incoming direct calls changed')
    # Decoded-formula edges (restatement of the retained bytes, not execution).
    # Concrete global values are unknown; edges use symbolic lo/hi pairs.
    require(membership_bit(10, 20, 10) == 1, 'At-lo edge changed')
    require(membership_bit(10, 20, 19) == 1, 'Just-below-hi edge changed')
    require(membership_bit(10, 20, 20) == 0, 'At-hi edge changed')
    require(membership_bit(10, 20, 9) == 0, 'Below-lo edge changed')
    require(membership_bit(10, 20, 25) == 0, 'Above-hi edge changed')
    require(membership_bit(10, 10, 10) == 0, 'Degenerate lo==hi edge changed')
    require(membership_bit(20, 10, 15) == 0, 'Inverted-range edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'call_sites': [site for site, _ in CALL_SITES],
        'low_byte_edges': {'at_lo': 1, 'just_below_hi': 1, 'at_hi': 0,
                           'below_lo': 0, 'above_hi': 0},
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 range-test '
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
        print('Foundation range-test evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
