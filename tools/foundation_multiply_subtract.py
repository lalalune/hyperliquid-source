#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 multiply-subtract evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window has no outgoing calls: it saves the 64-bit scalar, multiplies it by
the 64-bit input word (low 64 bits of the product only, as imul r/m64
discards the high word), subtracts that product from the first output word,
stores the saved scalar to the second output word, and returns. The inputs'
meaning, the output words' meaning, and any caller behavior are not claimed
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
START, END = 0x565eea0, 0x565eeba
PAD_END = 0x565eec0
BODY = bytes.fromhex(
    'f30f1efa4889d0480faf164c8b174929d24c891748894708f3c3')
PAD = bytes.fromhex('900f1f440000')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
# The CIE and FDE encodings are zR: initial_location is a 4-byte signed
# PC-relative value under the CIE's zR encoding; range is a 4-byte unsigned
# value.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000080c42d0004156a041a00000000000000')
NEXT_FDE = bytes.fromhex(
    '4000000094c42d0010156a042901000000450e108602410e188303420e208c044'
    '20e288d05420e308e06420e388f07470ed00402facf44ce44cd44cc44c344c644'
    '0e0800')
CALLER_FDES = (
    (0x2d9f88,
     bytes.fromhex(
         '540000008c9f2d0058f468044802000000420e108f02420e188e03420e208d0'
         '4420e288c05410e308606410e388307480c0bb88001510d07470e909101030'
         'e020a0e38410e30410e28420e20420e18420e10420e08410b00'),
     0x564a900, 0x564ab48),
)
CALL_SITES = (
    (0x564a9fe, bytes.fromhex('e89d440100')),
    (0x564aa26, bytes.fromhex('e875440100')),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def multiply_subtract(out0, in0, scalar):
    """Decoded rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. Words are unsigned 64-bit. Only
    the low 64 bits of scalar * in0 survive (imul r/m64); the entry second
    output word is never read and is unconditionally overwritten with the
    scalar; the input's second word is never read.
    """
    mask64 = (1 << 64) - 1
    new0 = (out0 - (scalar * in0 & mask64)) & mask64
    return (new0, scalar)


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
    require(body == BODY, 'Multiply-subtract instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'Stride padding changed')
    eh = by_name['.eh_frame']

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    check_fde(0x2dc47c, FDE, START, END)
    check_fde(0x2dc490, NEXT_FDE, PAD_END, 0x565efe9)
    for offset, raw, start, end in CALLER_FDES:
        check_fde(offset, raw, start, end)
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x565eea0.
    require(body[0:4] == bytes.fromhex('f30f1efa'), 'Endbr64 changed')
    require(body[4:7] == bytes.fromhex('4889d0'), 'Scalar save to rax changed')
    require(body[7:11] == bytes.fromhex('480faf16'), 'Imul input word changed')
    require(body[11:14] == bytes.fromhex('4c8b17'), 'Out word 0 load changed')
    require(body[14:17] == bytes.fromhex('4929d2'), 'Product sub changed')
    require(body[17:20] == bytes.fromhex('4c8917'), 'Out word 0 store changed')
    require(body[20:24] == bytes.fromhex('48894708'), 'Scalar store changed')
    require(body[23] == 0x08, 'Scalar store displacement changed')
    require(body[24:26] == bytes.fromhex('f3c3'), 'Return changed')
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
    # Incoming calls: exactly two direct e8 call sites in .text. This is a
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
    # Plain multiply-subtract: 100 - 7*3 = 79, second word is the scalar.
    require(multiply_subtract(100, 3, 7) == (79, 7),
            'Plain edge changed')
    # Scalar zero: product zero, first word unchanged, second word zero.
    require(multiply_subtract(100, 3, 0) == (100, 0),
            'Zero-scalar edge changed')
    # Input zero: product zero regardless of scalar.
    require(multiply_subtract(100, 0, 7) == (100, 7),
            'Zero-input edge changed')
    # Wraparound: 5 - 7*3 wraps mod 2^64.
    require(multiply_subtract(5, 3, 7) == ((1 << 64) - 16, 7),
            'Wraparound edge changed')
    # High product discarded: scalar 2^64-1 times input 2 keeps only the low
    # word (2^64-2), so 0 - (2^64-2) wraps to 2.
    require(multiply_subtract(0, 2, (1 << 64) - 1) == (2, (1 << 64) - 1),
            'High-product discard edge changed')
    # Entry second output word is irrelevant: it is overwritten, never read.
    require(multiply_subtract(100, 3, 7)[1] == 7,
            'Second-word store edge changed')
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
        description='Verify a digest-bound, static node #94 multiply-'
                    'subtract evidence packet.')
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
        print('Foundation multiply-subtract evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
