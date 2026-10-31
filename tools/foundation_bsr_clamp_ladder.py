#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 bsr clamp-ladder packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window computes a four-step min/max chain over a zero-defaulted value,
with bounds built from bit-scan-reverse results. The chain is stated literally:
when lo > hi the min-then-max order matters and the result is not a true clamp.

This window is bound ALONE. No census of similar windows is claimed, and the
immediately following FDE (0x556e9e0, same ladder shape, different inputs) is
explicitly NOT bound here.
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
START, END = 0x556e980, 0x556e9d8
BODY = bytes.fromhex(
    'f30f1efa89f889d78d56ff4189c80fbdd2b91f0000000fbdff0fbdf683f21f'
    '4429c183c60129d18d570239d60f47f285c0ba0b0000000f44c2ba0c000000'
    '39c80f47c139f00f42c639d00f47c2ba0500000039d00f42c2c3')
STRIDE_END = 0x556e9e0
PADDING = bytes.fromhex('cc' * 8)
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# The window CIE lives at section offset 0x0 ("zR": R encoding 0x1b, i.e.
# pcrel sdata4 for initial_location, which is what the checker decodes).
# The next FDE shares the same CIE.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000010112d0054c35b045800000000000000')
NEXT_FDE = bytes.fromhex('1000000024112d00a0c35b044700000000000000')
NEXT_START, NEXT_END = 0x556e9e0, 0x556ea27
MASK32 = (1 << 32) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _bsr32(value):
    """Bit-scan-reverse of a 32-bit value; undefined for zero, as on x86."""
    value &= MASK32
    if value == 0:
        raise ValueError('bsr of zero is architecturally undefined')
    return value.bit_length() - 1


def bsr_clamp_ladder(v, rsi, rdx, rcx):
    """Decoded rule of the window, for edge checks only.

    A restatement of the retained bytes, not execution. All operands are
    32-bit: bsr reads the low 32 bits of rsi, rdx, and (rsi - 1); rcx enters
    only as r8d; v enters as edi and the result leaves in eax. Comparisons
    are unsigned 32-bit (cmova/cmovb). The rule is defined only when the low
    32 bits of rsi, rdx, and (rsi - 1) are all nonzero -- equivalently
    low32(rsi) not in {0, 1} and low32(rdx) != 0 -- because bsr of zero is
    architecturally undefined and the bytes contain no zero guards.
    """
    v &= MASK32
    rsi &= MASK32
    rdx &= MASK32
    rcx &= MASK32
    hi = (_bsr32((rsi - 1) & MASK32) - rcx) & MASK32
    lo = min(_bsr32(rsi) + 1, _bsr32(rdx) + 2)
    result = 11 if v == 0 else v
    result = min(result, hi)
    result = max(result, lo)
    result = min(result, 12)
    result = max(result, 5)
    return result


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
    require(body == BODY, 'Bsr clamp-ladder instruction window changed')
    require(read(END, STRIDE_END - END) == PADDING,
            'Stride padding changed')
    eh = by_name['.eh_frame']

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    check_fde(0x2d110c, FDE, START, END)
    check_fde(0x2d1120, NEXT_FDE, NEXT_START, NEXT_END)
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x556e980.
    require(body[0:4] == bytes.fromhex('f30f1efa'), 'endbr64 changed')
    require(body[4:6] == bytes.fromhex('89f8'), 'Value move changed')
    require(body[6:8] == bytes.fromhex('89d7'), 'Third-arg move changed')
    require(body[8:11] == bytes.fromhex('8d56ff'), 'rsi-1 lea changed')
    require(body[11:14] == bytes.fromhex('4189c8'), 'Fourth-arg move changed')
    require(body[14:17] == bytes.fromhex('0fbdd2'), 'bsr(rsi-1) changed')
    require(body[17:22] == bytes.fromhex('b91f000000'), '31 constant changed')
    require(body[22:25] == bytes.fromhex('0fbdff'), 'bsr(rdx) changed')
    require(body[25:28] == bytes.fromhex('0fbdf6'), 'bsr(rsi) changed')
    require(body[28:31] == bytes.fromhex('83f21f'), 'xor 31 changed')
    # The xor trick: bsr values lie in 0..31, so 31 ^ bsr == 31 - bsr, and
    # (31 - rcx) - (31 - bsr(rsi-1)) == bsr(rsi-1) - rcx (mod 2^32).
    require(body[31:34] == bytes.fromhex('4429c1'), '31-rcx sub changed')
    require(body[34:37] == bytes.fromhex('83c601'), 'bsr(rsi)+1 changed')
    require(body[37:39] == bytes.fromhex('29d1'), 'hi sub changed')
    require(body[39:42] == bytes.fromhex('8d5702'), 'bsr(rdx)+2 lea changed')
    require(body[42:44] == bytes.fromhex('39d6'), 'lo compare changed')
    require(body[44:47] == bytes.fromhex('0f47f2'), 'lo min cmova changed')
    require(body[47:49] == bytes.fromhex('85c0'), 'Zero test changed')
    require(body[49:54] == bytes.fromhex('ba0b000000'), 'Zero default 11 changed')
    require(body[54:57] == bytes.fromhex('0f44c2'), 'Zero cmove changed')
    require(body[57:62] == bytes.fromhex('ba0c000000'), 'Clamp 12 changed')
    require(body[62:64] == bytes.fromhex('39c8'), 'hi compare changed')
    require(body[64:67] == bytes.fromhex('0f47c1'), 'hi min cmova changed')
    require(body[67:69] == bytes.fromhex('39f0'), 'lo compare changed')
    require(body[69:72] == bytes.fromhex('0f42c6'), 'lo max cmovb changed')
    require(body[72:74] == bytes.fromhex('39d0'), '12 compare changed')
    require(body[74:77] == bytes.fromhex('0f47c2'), '12 min cmova changed')
    require(body[77:82] == bytes.fromhex('ba05000000'), 'Clamp 5 changed')
    require(body[82:84] == bytes.fromhex('39d0'), '5 compare changed')
    require(body[84:87] == bytes.fromhex('0f42c2'), '5 max cmovb changed')
    require(body[87:88] == bytes.fromhex('c3'), 'Return changed')
    # Data edge: no relocation record of any type in any .rela.* section
    # names this window as addend (full-section scan).
    naming = []
    for name, sec in by_name.items():
        if name.startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((address, info & 0xffffffff))
    require(naming == [], 'Naming relocation changed')
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
    # Decoded-rule edges (restatement of the retained bytes, not execution).
    require(bsr_clamp_ladder(0, 2, 4, 0) == 5, 'Zero-default edge changed')
    require(bsr_clamp_ladder(20, 256, 256, 3) == 9, 'Mid-range edge changed')
    require(bsr_clamp_ladder(7, 8, 8, 0) == 5, 'Order-matters edge changed')
    require(bsr_clamp_ladder(100, 1 << 20, 2, 0) == 12, 'Upper-clamp edge changed')
    require(bsr_clamp_ladder(6, 16, 16, 1) == 5, 'Lower-clamp edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'call_sites': direct,
        'naming': naming,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 '
                    'bsr clamp-ladder evidence packet.')
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
        require(retained['function']['padding_bytes'] == 8, 'Retained padding changed')
        require(retained['function']['padding_stride_end'] == hex(STRIDE_END),
                'Retained stride end changed')
        require([int(s, 16) for s in retained['incoming_pattern_scan']['e8_candidates']]
                == result['call_sites'], 'Retained call sites changed')
        require(retained['naming_relocation'] is None, 'Retained naming changed')
    print('Foundation bsr clamp-ladder evidence reproduces exactly.')


if __name__ == '__main__':
    main()
