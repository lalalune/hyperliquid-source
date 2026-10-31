#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 two-field byte-gate packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window reads one byte from rdi+0x160; when that byte is zero it returns 0,
otherwise it returns the byte at rdi+0x189 XOR 1. Both bytes are loaded with
movzbl, so the return value is fully determined (rax is zero-extended, not a
setcc byte), and no low-byte-only caveat applies here, unlike packets #27
and #32.

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
START, END = 0x51384e0, 0x51384fa
BODY = bytes.fromhex(
    'f30f1efa0fb6876001000084c0740a0fb6878901000083f001c3')
STRIDE_END = 0x5138500
PADDING = bytes.fromhex('cccccccccccc')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# The window CIE and FDE encodings are zR: initial_location is a 4-byte
# signed PC-relative value under the CIE's zR encoding; range is a 4-byte
# unsigned value. The next FDE belongs to the same zR CIE; its raw bytes are
# locked and its range is the GNU-decoded value, not a hand re-derivation.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('100000008c98290038d71b041a000000')
NEXT_FDE = bytes.fromhex('10000000a098290044d71b0411000000')
NAMING_SLOT = 0x575af60


def require(condition, message):
    if not condition:
        raise ValueError(message)


def gate(gate_byte, value_byte):
    """Decoded rule of the window, for edge checks only.

    A restatement of the retained bytes, not execution: the je skips the
    second load and the xor when the gate byte is zero, so the ret returns
    the xor'd eax (zero from the first movzbl) in that path.
    """
    if gate_byte == 0:
        return 0
    return (value_byte ^ 1) & 0xff


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
    require(body == BODY, 'Two-field byte-gate instruction window changed')
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
    check_fde(0x299888, FDE, START, END)
    require(read(eh['address'] + 0x29989c, len(NEXT_FDE)) == NEXT_FDE,
            'Next FDE record changed')
    check_fde(0x29989c, NEXT_FDE, 0x5138500, 0x5138511)
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x51384e0.
    require(body[0:4] == bytes.fromhex('f30f1efa'), 'Endbr64 changed')
    require(body[4:11] == bytes.fromhex('0fb68760010000'),
            'Gate byte load changed')
    require(struct.unpack_from('<i', body, 7)[0] == 0x160,
            'Gate byte offset changed')
    require(body[11:13] == bytes.fromhex('84c0'), 'Gate test changed')
    require(body[13:15] == bytes.fromhex('740a'), 'Gate branch changed')
    require(struct.unpack_from('<b', body, 14)[0] == 0x0a,
            'Gate branch target changed')
    require(START + 15 + 0x0a == 0x51384f9, 'Gate branch lands off ret')
    require(body[15:22] == bytes.fromhex('0fb68789010000'),
            'Value byte load changed')
    require(struct.unpack_from('<i', body, 18)[0] == 0x189,
            'Value byte offset changed')
    require(body[22:25] == bytes.fromhex('83f001'), 'Xor changed')
    require(body[24] == 0x01, 'Xor constant changed')
    require(body[25:26] == bytes.fromhex('c3'), 'Return changed')
    # Data edge: exactly one relocation record of any type in any .rela.*
    # section names this window as addend: R_X86_64_RELATIVE (type 8) at
    # slot 0x575af60 in .data.rel.ro, file value 0 (applied only at load
    # time) — a data-pointer reference, not a direct call.
    naming = []
    for name, sec in by_name.items():
        if name.startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((address, info & 0xffffffff))
    require(naming == [(NAMING_SLOT, 8)], 'Naming relocation changed')
    require(read(NAMING_SLOT, 8) == bytes(8), 'Naming slot file value changed')
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
    require(gate(0, 0) == 0, 'Gate-zero edge changed')
    require(gate(0, 0xff) == 0, 'Gate-zero ignores value edge changed')
    require(gate(1, 0) == 1, 'Value-zero edge changed')
    require(gate(1, 1) == 0, 'Value-one edge changed')
    require(gate(1, 2) == 3, 'Value-two edge changed')
    require(gate(0xff, 0xff) == 0xfe, 'All-ones edge changed')
    require(gate(7, 0x80) == 0x81, 'High-bit edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'call_sites': direct,
        'naming_slot': NAMING_SLOT,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 '
                    'two-field byte-gate evidence packet.')
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
        require(retained['naming_relocation']['slot'] == hex(NAMING_SLOT),
                'Retained naming slot changed')
        require(retained['naming_relocation']['type'] == 'R_X86_64_RELATIVE',
                'Retained naming type changed')
        require(retained['naming_relocation']['file_value'] == '0x0',
                'Retained naming file value changed')
        print('Foundation two-field byte-gate evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
