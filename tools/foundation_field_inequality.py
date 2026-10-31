#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 field-inequality-gate evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window loads two 64-bit fields from the same base pointer in rdi, compares
them, and sets only the low byte of rax: 1 iff *(rdi+0x1458) differs from
*(rdi+0x1478), else 0. No instruction zeroes eax before the setne, so only the
low byte is the gate bit (the same low-byte-only precedent as packets #27
and #32). The window has no outgoing calls.

Stride attribution, stated exactly: the window FDE record carries no
augmentation data and therefore no LSDA, so the bytes after its ret cannot be
this FDE's landing pad. The 16 bytes after the ret are a separate FDE record
whose body is a landing-pad stub; it is locked as a separate record and left
unanalyzed, with no shared routine claimed. Ten int3 bytes follow it to the
next FDE. The checker locks the window body, the stub record, and the padding
separately; stride is not the FDE extent.

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
START, END = 0x5035a70, 0x5035a86
BODY = bytes.fromhex(
    'f30f1efa488b8758140000483987781400000f95c0c3')
STUB_START, STUB_END = 0x5035a86, 0x5035a96
STUB = bytes.fromhex('4889efe832f22f004889dfe87aa66200')
STRIDE_END = 0x5035aa0
PADDING = bytes.fromhex('cccccccccccccccccccc')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
# The window CIE and FDE encodings are zR: initial_location is a 4-byte
# signed PC-relative value under the CIE's zR encoding; range is a 4-byte
# unsigned value. The stub and next FDEs belong to a zPLR CIE; their raw
# bytes are locked and their ranges are the GNU-decoded values.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000f81b29005c290c041600000000000000')
STUB_FDE = bytes.fromhex(
    '1c000000d48d0000c6b1d2031000000004be598cff0e20830486038c02000000')
NEXT_FDE = bytes.fromhex(
    '30000000a08d000014b2d203bd00000004e4598cff460e108c02410e188603480e208304029e0a0e18410e10420e08410b000000')
CALLERS = [
    # (site, call bytes, caller FDE range)
    (0x4fbcd61, bytes.fromhex('e80a8d0700'), (0x4fbcca0, 0x4fbdbb0)),
    (0x5035b3b, bytes.fromhex('e830ffffff'), (0x5035aa0, 0x5035b5d)),
    (0x50562cb, bytes.fromhex('e8a0f7fdff'), (0x5055f00, 0x50566ed)),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def gate(field_a, field_b):
    """Decoded rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. Only the low byte is the gate
    bit: setne writes al, and nothing in the window zeroes the upper bytes
    of rax first.
    """
    return 1 if (field_a % (1 << 64)) != (field_b % (1 << 64)) else 0


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
    require(body == BODY, 'Field-inequality instruction window changed')
    require(read(STUB_START, STUB_END - STUB_START) == STUB,
            'Stride stub bytes changed')
    require(read(STUB_END, STRIDE_END - STUB_END) == PADDING,
            'Stride padding changed')
    eh = by_name['.eh_frame']

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    check_fde(0x291bf4, FDE, START, END)
    # The stub and next FDEs belong to a zPLR CIE whose initial_location
    # encoding does not re-derive by the zR hand formula used above; their
    # raw bytes are locked and their ranges are the GNU --dwarf=frames
    # decoded values, not hand re-derivations.
    require(read(eh['address'] + 0x6293a0, len(STUB_FDE)) == STUB_FDE,
            'Stub FDE record changed')
    require(read(eh['address'] + 0x62936c, len(NEXT_FDE)) == NEXT_FDE,
            'Next FDE record changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x5035a70.
    require(body[0:4] == bytes.fromhex('f30f1efa'), 'Endbr64 changed')
    require(body[4:11] == bytes.fromhex('488b8758140000'),
            'First field load changed')
    require(struct.unpack_from('<i', body, 7)[0] == 0x1458,
            'First field offset changed')
    require(body[11:18] == bytes.fromhex('48398778140000'),
            'Field compare changed')
    require(struct.unpack_from('<i', body, 14)[0] == 0x1478,
            'Second field offset changed')
    require(body[18:21] == bytes.fromhex('0f95c0'), 'Setne changed')
    require(body[21:22] == bytes.fromhex('c3'), 'Return changed')
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
    # Incoming calls: exactly three direct e8 calls in .text. This is a
    # byte-pattern scan, explicitly not a complete xref census. Each site
    # was confirmed as an instruction start by linear disassembly from its
    # caller FDE start with GNU objdump; the checker pins the call bytes,
    # the rel32 targets, and caller-FDE containment.
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
    for site, call_bytes, (fde_start, fde_end) in CALLERS:
        require(read(site, 5) == call_bytes, 'Caller call bytes changed')
        rel = struct.unpack_from('<i', call_bytes, 1)[0]
        require(site + 5 + rel == START, 'Caller call target changed')
        require(fde_start <= site < fde_end, 'Caller FDE containment changed')
    # Decoded-rule edges (restatement of the retained bytes, not execution).
    require(gate(123456789, 123456789) == 0, 'Equal edge changed')
    require(gate(1, 2) == 1, 'Unequal edge changed')
    require(gate(0, 1 << 63) == 1, 'High-bit-only edge changed')
    require(gate((1 << 64) - 1, (1 << 64) - 1) == 0, 'Max-equal edge changed')
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
                    'field-inequality-gate evidence packet.')
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
        require(retained['naming_relocation']['type'] is None,
                'Retained naming type changed')
        print('Foundation field-inequality evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
