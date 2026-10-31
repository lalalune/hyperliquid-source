#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 conditional-reduction evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window has no outgoing calls: two mulqs build a 192-bit scalar product, a
sub/sbb chain subtracts it from a 192-bit out buffer, a borrow mask adds the
128-bit input back to the low two words on borrow, and the top word is
unconditionally overwritten with the scalar (or scalar - 1 on borrow) — the
computed top-word subtraction result is discarded, never stored. The inputs'
meaning, the add-back operand's role, and any caller behavior are not claimed
anywhere.

Scout correction, stated prominently: the round-7 scout note described this
window as "out(192-bit) -= scalar * in(128-bit)". That is imprecise for the
top word. The retained bytes show the top-word difference (out[2] - p2 -
borrow, computed in rax at body offset 0x32) is never stored: the only store
to out + 0x10 is rcx, the scalar adjusted by the borrow mask. The checker
locks the verified bytes, not the scout summary.

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
START, END = 0x565ee40, 0x565ee9b
PAD_END = 0x565eea0
BODY = bytes.fromhex(
    'f30f1efa4889d04889d148f7264989c04889c84989d148f766084901c14883d200'
    '4c8b174c8b5f08488b47104d29c24d19cb4819d04d19c04c01c14d89c14c2306'
    '4c234e084d01c24d11cb4c89174c895f0848894f104889c8f3c3')
PAD = bytes.fromhex('900f1f4000')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
# The CIE and FDE encodings are zR: initial_location is a 4-byte signed
# PC-relative value under the CIE's zR encoding; range is a 4-byte unsigned
# value.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('100000006cc42d00b8146a045b00000000000000')
NEXT_FDE = bytes.fromhex('1000000080c42d0004156a041a00000000000000')
CALLER_FDES = (
    (0x2d9f88,
     bytes.fromhex(
         '540000008c9f2d0058f468044802000000420e108f02420e188e03420e208d0'
         '4420e288c05410e308606410e388307480c0bb88001510d07470e909101030'
         'e020a0e38410e30410e28420e20420e18420e10420e08410b00'),
     0x564a900, 0x564ab48),
    (0x2da7f0,
     bytes.fromhex(
         '50000000f4a72d00d04669043702000000420e108f02420e188e03420e208d0'
         '4420e288c05410e308606410e388307470eb8204c0ea025030a020a0e38410'
         'e30410e28420e20420e18420e10420e08410b000000'),
     0x56503e0, 0x5650617),
)
CALL_SITES = (
    (0x564a9ae, bytes.fromhex('e88d440100')),
    (0x564a9e3, bytes.fromhex('e858440100')),
    (0x5650496, bytes.fromhex('e8a5e90000')),
    (0x56504d5, bytes.fromhex('e866e90000')),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def reduce_step(out0, out1, out2, in0, in1, scalar):
    """Decoded rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. Words are unsigned 64-bit. The
    product is the full 192-bit scalar * 128-bit input; the subtraction is
    192-bit; the add-back on borrow touches only the low two words; the top
    word stored is the scalar adjusted by the borrow mask, never the
    subtraction result.
    """
    mask64 = (1 << 64) - 1
    lo0 = (scalar * in0) & mask64
    hi0 = (scalar * in0) >> 64
    lo1 = (scalar * in1) & mask64
    hi1 = (scalar * in1) >> 64
    p1, carry = (hi0 + lo1) & mask64, 1 if hi0 + lo1 > mask64 else 0
    p2 = (hi1 + carry) & mask64
    out192 = out0 + (out1 << 64) + (out2 << 128)
    prod192 = scalar * (in0 + (in1 << 64))
    borrow = 1 if out192 < prod192 else 0
    d0 = (out0 - lo0) & mask64
    b0 = 1 if out0 < lo0 else 0
    d1 = (out1 - p1 - b0) & mask64
    add = mask64 if borrow else 0
    s0 = (d0 + (add & in0)) & mask64
    carry2 = 1 if d0 + (add & in0) > mask64 else 0
    s1 = (d1 + (add & in1) + carry2) & mask64
    s2 = (scalar + add) & mask64
    return (s0, s1, s2, s2)


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
    require(body == BODY, 'Conditional-reduction instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'Stride padding changed')
    eh = by_name['.eh_frame']

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    check_fde(0x2dc468, FDE, START, END)
    check_fde(0x2dc47c, NEXT_FDE, PAD_END, 0x565eeba)
    for offset, raw, start, end in CALLER_FDES:
        check_fde(offset, raw, start, end)
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x565ee40.
    require(body[0:4] == bytes.fromhex('f30f1efa'), 'Endbr64 changed')
    require(body[4:7] == bytes.fromhex('4889d0'), 'Scalar copy to rax changed')
    require(body[7:10] == bytes.fromhex('4889d1'), 'Scalar copy to rcx changed')
    require(body[10:13] == bytes.fromhex('48f726'), 'First mulq changed')
    require(body[13:16] == bytes.fromhex('4989c0'), 'Low product to r8 changed')
    require(body[16:19] == bytes.fromhex('4889c8'), 'Scalar reload changed')
    require(body[19:22] == bytes.fromhex('4989d1'), 'High product to r9 changed')
    require(body[22:26] == bytes.fromhex('48f76608'), 'Second mulq changed')
    require(body[25] == 0x08, 'Second mulq displacement changed')
    require(body[26:29] == bytes.fromhex('4901c1'), 'Middle product add changed')
    require(body[29:33] == bytes.fromhex('4883d200'), 'Product carry adc changed')
    require(body[33:36] == bytes.fromhex('4c8b17'), 'Out word 0 load changed')
    require(body[36:40] == bytes.fromhex('4c8b5f08'), 'Out word 1 load changed')
    require(body[39] == 0x08, 'Out word 1 displacement changed')
    require(body[40:44] == bytes.fromhex('488b4710'), 'Out word 2 load changed')
    require(body[43] == 0x10, 'Out word 2 displacement changed')
    require(body[44:47] == bytes.fromhex('4d29c2'), 'Word 0 sub changed')
    require(body[47:50] == bytes.fromhex('4d19cb'), 'Word 1 sbb changed')
    require(body[50:53] == bytes.fromhex('4819d0'), 'Word 2 sbb changed')
    require(body[53:56] == bytes.fromhex('4d19c0'), 'Borrow mask sbb changed')
    require(body[56:59] == bytes.fromhex('4c01c1'), 'Scalar adjust add changed')
    require(body[59:62] == bytes.fromhex('4d89c1'), 'Mask copy to r9 changed')
    require(body[62:65] == bytes.fromhex('4c2306'), 'Add-back word 0 and changed')
    require(body[65:69] == bytes.fromhex('4c234e08'), 'Add-back word 1 and changed')
    require(body[68] == 0x08, 'Add-back word 1 displacement changed')
    require(body[69:72] == bytes.fromhex('4d01c2'), 'Add-back word 0 add changed')
    require(body[72:75] == bytes.fromhex('4d11cb'), 'Add-back word 1 adc changed')
    require(body[75:78] == bytes.fromhex('4c8917'), 'Word 0 store changed')
    require(body[78:82] == bytes.fromhex('4c895f08'), 'Word 1 store changed')
    require(body[81] == 0x08, 'Word 1 store displacement changed')
    require(body[82:86] == bytes.fromhex('48894f10'), 'Top word store changed')
    require(body[85] == 0x10, 'Top word store displacement changed')
    require(body[86:89] == bytes.fromhex('4889c8'), 'Return copy changed')
    require(body[89:91] == bytes.fromhex('f3c3'), 'Return changed')
    # Data edge: no relocation record of any type in any .rela.* section
    # names this window as addend. Absence of a naming relocation does not
    # identify the window's provenance.
    naming = []
    for name, sec in by_name.items():
        if name.startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((address, info & 0xffffffff))
    require(naming == [], 'Naming relocation changed')
    # Incoming calls: exactly four direct e8 call sites in .text. This is a
    # byte-pattern scan, explicitly not a complete xref census.
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
    for site, call_bytes in CALL_SITES:
        require(read(site, 5) == call_bytes, 'Caller call bytes changed')
    # Decoded-formula edges (restatement of the retained bytes, not execution).
    # No-borrow: plain subtraction lows, top word is the scalar itself.
    require(reduce_step(100, 200, 300, 3, 0, 7) == (79, 200, 7, 7),
            'No-borrow edge changed')
    # Borrow with scalar 1: product equals the input, so out - product +
    # input restores the entry lows and the top word is scalar - 1 = 0.
    require(reduce_step(3, 4, 0, 5, 9, 1) == (3, 4, 0, 0),
            'Borrow scalar-1 edge changed')
    # Borrow with scalar 2: stored lows are (out - 2*in + in) mod 2^128,
    # top word is scalar - 1 = 1.
    require(reduce_step(3, 4, 0, 5, 9, 2) ==
            ((1 << 64) - 2, (1 << 64) - 6, 1, 1),
            'Borrow scalar-2 edge changed')
    # Borrow with out zero: out - product + input is zero when scalar is 1.
    require(reduce_step(0, 0, 0, 5, 9, 1) == (0, 0, 0, 0),
            'Borrow zero-out edge changed')
    # Top-word discard: with zero product the top word stored is the scalar
    # regardless of the entry top word (7 vs 9 give the same stored top word).
    require(reduce_step(3, 4, 7, 0, 0, 5)[2] ==
            reduce_step(3, 4, 9, 0, 0, 5)[2] == 5,
            'Top-word discard edge changed')
    # Scalar zero: product zero, no borrow, stored triple is the entry lows
    # with top word 0.
    require(reduce_step(11, 22, 33, 7, 8, 0) == (11, 22, 0, 0),
            'Zero-scalar edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'call_sites': direct,
        'naming_slot': None,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 conditional-'
                    'reduction evidence packet.')
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
                == [hex(v) for v in result['call_sites']], 'Retained callers changed')
        require(retained['naming_relocation']['slot'] is None,
                'Retained naming slot changed')
        print('Foundation conditional-reduction evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
