#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 three-field tail-gate packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window returns (falls through to ret) unless the byte at +0x88, the byte
at +0x80, and the word at +0x60 are all exactly 3; when all three pass, rdi
advances by 0x68 and control leaves by a tail jump whose callee is named, not
decoded. No return value is set by this window on either path.

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
START, END = 0x473b120, 0x473b143
BODY = bytes.fromhex(
    '80bf8800000003751980bf8000000003751066837f600375094883c768'
    'e98e50ffffc3')
STRIDE_END = 0x473b150
PADDING = bytes.fromhex('cc' * 13)
TAIL_START, TAIL_END = 0x47301d0, 0x4730299
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# The window CIE lives at section offset 0x0 ("zR": R encoding 0x1b, i.e.
# pcrel sdata4 for initial_location, which is what the checker decodes).
# The next/caller/tail CIE lives at 0x2dc714 ("zPLR": P encoding 0x9b,
# L encoding 0x1b, R encoding 0x1b, same pcrel sdata4 layout).
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000547a2100b02184032300000000000000')
NEXT_CIE = bytes.fromhex(
    '1c00000000000000017a504c5200017810079b29ca7b041b1b0c070890010000')
NEXT_FDE = bytes.fromhex(
    '2c00000050912c00d0434b03aa00000004039d8eff420e10410e18410e2083038'
    'e0202420e18410e10420e08450e2000')
TAIL_FDE = bytes.fromhex(
    '500000001c6b2c0084ba4a03c900000004dfac8eff420e10420e18420e20410e'
    '28410e3083058c048e038f02510e28410e20420e18420e10420e08410e3002540'
    'e28410e20420e18420e10420e08460e30000000')
CALLERS = [
    # (call site, call bytes, (caller FDE start, caller FDE end),
    #  caller FDE section offset, caller FDE raw bytes)
    (0x47b6f24, bytes.fromhex('e8f741f8ff'), (0x47b4950, 0x47b6f8f),
     0x5b0264, bytes.fromhex(
         '54000000543b2d00cc3152033f2600000433988eff410e10420e18420e'
         '20420e28420e30410e38470eb8204f0ee02883078c068d058e048f0386'
         '020317220e38410e30420e28420e20420e18420e10410e08410ee0280000')),
]
MASK64 = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def three_field_tail_gate(byte_88, byte_80, word_60, rdi):
    """Decoded rule of the window, for edge checks only.

    A restatement of the retained bytes, not execution: the three jne
    instructions all land on the single ret; only the all-3 path reaches
    the add and the tail jump. The tail jump's destination is not modeled
    here beyond its locked rel32 target.
    """
    if byte_88 == 3 and byte_80 == 3 and word_60 == 3:
        return ('tail', (rdi + 0x68) & MASK64)
    return ('ret', rdi)


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
    require(body == BODY, 'Three-field tail-gate instruction window changed')
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
    check_fde(0x217a50, FDE, START, END)
    require(read(eh['address'] + 0x2dc714, len(NEXT_CIE)) == NEXT_CIE,
            'Next/caller/tail CIE changed')
    check_fde(0x5a5860, NEXT_FDE, STRIDE_END, 0x473b1fa)
    check_fde(0x5a322c, TAIL_FDE, TAIL_START, TAIL_END)
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x473b120. Note the window has
    # no endbr64: it opens directly with the first compare.
    require(body[0:7] == bytes.fromhex('80bf8800000003'),
            'First field compare changed')
    require(body[7:9] == bytes.fromhex('7519'), 'First branch changed')
    require(struct.unpack_from('<b', body, 8)[0] == 0x19,
            'First branch displacement changed')
    require(START + 9 + 0x19 == 0x473b142,
            'First branch lands off the ret')
    require(body[9:16] == bytes.fromhex('80bf8000000003'),
            'Second field compare changed')
    require(body[16:18] == bytes.fromhex('7510'), 'Second branch changed')
    require(struct.unpack_from('<b', body, 17)[0] == 0x10,
            'Second branch displacement changed')
    require(START + 18 + 0x10 == 0x473b142,
            'Second branch lands off the ret')
    require(body[18:23] == bytes.fromhex('66837f6003'),
            'Third field compare changed')
    require(body[23:25] == bytes.fromhex('7509'), 'Third branch changed')
    require(struct.unpack_from('<b', body, 24)[0] == 0x09,
            'Third branch displacement changed')
    require(START + 25 + 0x09 == 0x473b142,
            'Third branch lands off the ret')
    require(body[25:29] == bytes.fromhex('4883c768'), 'Tail-path add changed')
    require(body[29:34] == bytes.fromhex('e98e50ffff'), 'Tail jump changed')
    require(struct.unpack_from('<i', body, 30)[0] == -0xaf72,
            'Tail jump displacement changed')
    require(START + 34 + (-0xaf72) == TAIL_START,
            'Tail jump lands off the tail callee')
    require(body[34:35] == bytes.fromhex('c3'), 'Return changed')
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
    # Incoming calls: exactly one direct e8 call in .text. This is a
    # byte-pattern scan, explicitly not a complete xref census. The site
    # was confirmed as an instruction start by linear disassembly from its
    # caller FDE start with GNU objdump; the checker pins the call bytes,
    # the rel32 target, caller-FDE containment, and the caller FDE record.
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
    for site, call_bytes, (fde_start, fde_end), fde_off, fde_raw in CALLERS:
        require(read(site, 5) == call_bytes, 'Caller call bytes changed')
        rel = struct.unpack_from('<i', call_bytes, 1)[0]
        require(site + 5 + rel == START, 'Caller call target changed')
        require(fde_start <= site < fde_end, 'Caller FDE containment changed')
        check_fde(fde_off, fde_raw, fde_start, fde_end)
    # Decoded-rule edges (restatement of the retained bytes, not execution).
    require(three_field_tail_gate(3, 3, 3, 0x1000) == ('tail', 0x1068),
            'All-three edge changed')
    require(three_field_tail_gate(2, 3, 3, 0x1000) == ('ret', 0x1000),
            'First-field edge changed')
    require(three_field_tail_gate(3, 2, 3, 0x1000) == ('ret', 0x1000),
            'Second-field edge changed')
    require(three_field_tail_gate(3, 3, 2, 0x1000) == ('ret', 0x1000),
            'Third-field edge changed')
    require(three_field_tail_gate(3, 3, 0x103, 0x1000) == ('ret', 0x1000),
            'Third-field low-byte edge changed')
    require(three_field_tail_gate(0, 0, 0, 0x1000) == ('ret', 0x1000),
            'All-zero edge changed')
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
                    'three-field tail-gate evidence packet.')
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
        require(retained['function']['padding_bytes'] == 13, 'Retained padding changed')
        require(retained['function']['padding_stride_end'] == hex(STRIDE_END),
                'Retained stride end changed')
        require([int(s, 16) for s in retained['incoming_pattern_scan']['e8_candidates']]
                == result['call_sites'], 'Retained call sites changed')
        require(retained['naming_relocation'] is None, 'Retained naming changed')
    print('Foundation three-field tail-gate evidence reproduces exactly.')


if __name__ == '__main__':
    main()
