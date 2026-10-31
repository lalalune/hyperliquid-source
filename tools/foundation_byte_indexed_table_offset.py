#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 byte-indexed table offset packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window returns base + zero-extended table[edx] + 224 * selector-byte, with
the selector byte optionally stored through an out-param. What the base, the
table, the fields, and the callers mean is not claimed anywhere.
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
START, END = 0x54ccfb0, 0x54cd009
PAD_END = 0x54cd010
BODY = bytes.fromhex(
    'f30f1efa4889f04885ff742c4883bf9000000000742289d2440fb68417a1000000'
    '4a8d34c5000000004c29c648c1e605eb0d660f1f44000031f64531c089d24885c9'
    '7403448901488d0dc2cc2c00448b0c914c01c84801f0c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000028062c006cb452045900000000000000')
NEXT = bytes.fromhex(
    '640000003c062c00b8b452047107000000460e108f02420e188e03450e208d04420e'
    '288c05410e308606440e388307470ee0010378060a0e38410e30410e28420e20420'
    'e18420e10420e08410b02b80a0e38450e30440e28420e20420e18420e10420e08450b'
    '0000')
CALLER_FDES = [
    (0x2cf138, bytes.fromhex(
        '280000003cf12c00f8445a047c10000000450e108602460d06508f038e048d05'
        '8c068307026f0a0c0708460b'),
     0x5554b50, 0x5555bcc),
    (0x2cf164, bytes.fromhex(
        '2c00000068f12c004c555a044f0a000000450e108602430d06428f03458e04458'
        'd054c8c0683070316080a0c0708410b'),
     0x5555bd0, 0x555661f),
    (0x2cf364, bytes.fromhex(
        '4400000068f32c008c6c5a040701000000460e108f02420e188e03420e208d044'
        '20e288c05410e308606410e388307440e5002ea0e38410e30410e28420e20420'
        'e18420e10420e08'),
     0x5557510, 0x5557617),
]
CALLERS = [0x55557a3, 0x5556447, 0x555755c]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def compute_pointer(base, struct_is_null, field90, index, out_present,
                    selector_byte, table_entry):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. `index` is the already zero-extended
    32-bit index; `table_entry` is the raw 32-bit table value, zero-extended
    by the mov-into-r9d load (not sign-extended). All arithmetic wraps at
    64 bits, matching the retained add semantics.
    """
    if struct_is_null or field90 == 0:
        selector = 0
        term = 0
    else:
        selector = selector_byte & 0xff
        term = selector * 224
    out = selector if out_present else None
    rax = (base + (table_entry & 0xffffffff) + term) & 0xffffffffffffffff
    return rax, out


def analyze(data):
    """Structural checks, separate from identity so corruption controls reach them."""
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
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
    require(body == BODY, 'Byte-indexed table offset window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    check_fde(0x2c0624, FDE, START, END)
    check_fde(0x2c0638, NEXT, PAD_END, 0x54cd781)
    for offset, raw, start, end in CALLER_FDES:
        check_fde(offset, raw, start, end)
    # Padding: seven int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 7, 'FDE padding changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x54ccfb0.
    fixed = [
        (0x00, 'f30f1efa', 'Entry landing pad changed'),
        (0x04, '4889f0', 'Base preserve changed'),
        (0x07, '4885ff', 'Null struct test changed'),
        (0x0a, '742c', 'Null struct branch changed'),
        (0x0c, '4883bf9000000000', 'Presence field compare changed'),
        (0x14, '7422', 'Zero field branch changed'),
        (0x16, '89d2', 'Index zero extend changed'),
        (0x18, '440fb68417a1000000', 'Selector byte load changed'),
        (0x21, '4a8d34c500000000', 'Selector times eight changed'),
        (0x29, '4c29c6', 'Selector times seven changed'),
        (0x2c, '48c1e605', 'Selector shift changed'),
        (0x30, 'eb0d', 'Join jump changed'),
        (0x32, '660f1f440000', 'Intra-body alignment padding changed'),
        (0x38, '31f6', 'Zero index term changed'),
        (0x3a, '4531c0', 'Zero selector changed'),
        (0x3d, '89d2', 'Join index zero extend changed'),
        (0x3f, '4885c9', 'Out-param test changed'),
        (0x42, '7403', 'Out-param branch changed'),
        (0x44, '448901', 'Out-param store changed'),
        (0x47, '488d0dc2cc2c00', 'Table base load changed'),
        (0x4e, '448b0c91', 'Table entry load changed'),
        (0x52, '4c01c8', 'Table entry add changed'),
        (0x55, '4801f0', 'Index term add changed'),
        (0x58, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # Branch targets: all four branches land inside the window.
    for off, disp, target in [(0x0a, 0x2c, 0x54ccfe8),
                              (0x14, 0x22, 0x54ccfe8),
                              (0x30, 0x0d, 0x54ccfef),
                              (0x42, 0x03, 0x54ccff7)]:
        require(body[off + 1] == disp, 'Branch displacement changed')
        require(START + off + 2 + disp == target, 'Branch target changed')
    # No call opcode at any instruction start inside the window.
    starts = {off for off, _, _ in fixed}
    for pos, byte in enumerate(body):
        if pos in starts:
            require(byte != 0xe8, 'Unexpected call opcode in window')
    # Relocations: no record in any .rela.* section names this window.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((sec['name'], address))
    require(naming == [], 'Unexpected relocation naming window')
    # Incoming calls: direct e8 call sites anywhere in .text, each with
    # call bytes (e8 + rel32) landing exactly on the window start.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == CALLERS, 'Unexpected incoming direct calls')
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    require(compute_pointer(0x1000, True, 0, 3, True, 0x05, 0x40)
            == (0x1040, 0), 'Null-struct edge changed')
    require(compute_pointer(0x1000, False, 0, 3, True, 0x05, 0x40)
            == (0x1040, 0), 'Zero-field edge changed')
    require(compute_pointer(0x1000, False, 7, 3, True, 0x05, 0x40)
            == (0x14a0, 5), 'Normal selector edge changed')
    require(compute_pointer(0x1000, False, 7, 3, False, 0x05, 0x40)
            == (0x14a0, None), 'Null out-param edge changed')
    require(compute_pointer(0x1000, False, 7, 3, True, 0xff, 0x80000000)
            == (0x8000ef20, 0xff), 'Table zero-extension edge changed')
    require(compute_pointer(0x1000, False, 7, 3, True, 0x00, 0x40)
            == (0x1040, 0), 'Zero selector edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'relocation_slots': [[name, hex(addr)] for name, addr in naming],
        'direct_callers': direct,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 '
                    'byte-indexed table offset evidence packet.')
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
        require(retained['function']['padding_bytes'] == 7, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation byte-indexed-table-offset evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
