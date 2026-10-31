#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 bsr-indexed table-lookup packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window reads two 64-bit fields from the same base pointer in rdi, picks
the first nonzero one, and returns the table entry at index bsr(field) plus
64 when the first field was the nonzero one, or 0 when both fields are zero.
No instruction zeroes anything before the final mov, and the return value is
fully determined (rax is loaded, not a setcc byte), so no low-byte-only
caveat applies here, unlike packets #27 and #32.

Precision note, not a scout correction: the scout summary described the bsr
tail as "rcx += esi; rsi = *(rdi + 0x1088 + rcx*8)". The retained bytes add
one instruction the summary elided: `mov %ecx,%edx` copies the index into
edx before the indexed load, so the load itself reads
`*(rdi + 0x1088 + rdx*8)`. Because the index is at most 127, the 32-bit copy
zero-extends to the same value, and the rule is unchanged; the checker locks
the mov instruction and the rdx-indexed load exactly as retained.

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
START, END = 0x55442e0, 0x554431b
BODY = bytes.fromhex(
    'f30f1efa488b87901400004885c07512488b878814000031f64885c075094889f0'
    'c3be40000000480fbdc801f189ca488bb4d7881000004889f0c3')
STRIDE_END = 0x5544320
PADDING = bytes.fromhex('cccccccccc')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# The window CIE and FDE encodings are zR: initial_location is a 4-byte
# signed PC-relative value under the CIE's zR encoding; range is a 4-byte
# unsigned value. The next FDE belongs to the same zR CIE; its raw bytes are
# locked and its range is the GNU-decoded value, not a hand re-derivation.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000ecd92c00d85359043b000000')
NEXT_FDE = bytes.fromhex('1000000000da2c00045459040c000000')
CALLERS = [
    # (site, call bytes, caller FDE range)
    (0x5522959, bytes.fromhex('e882190200'), (0x5522780, 0x5522d66)),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bsr(value):
    """Highest set bit index of a nonzero 64-bit value, for edge checks only.

    This is a Python restatement of the retained bsr instruction, not a run
    or emulation of the captured binary. Both window paths guard the value
    against zero before reaching bsr, so the undefined bsr(0) case is never
    taken by the retained bytes.
    """
    require(value != 0, 'bsr of zero is undefined in the retained bytes')
    return (value % (1 << 64)).bit_length() - 1


def lookup(field_high, field_low, table):
    """Decoded rule of the window, for edge checks only.

    field_high is *(rdi+0x1490), field_low is *(rdi+0x1488), and table is
    the 128-entry sequence starting at rdi+0x1088. Returns 0 when both
    fields are zero.
    """
    if field_high % (1 << 64) != 0:
        return table[bsr(field_high) + 64]
    if field_low % (1 << 64) != 0:
        return table[bsr(field_low)]
    return 0


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
    require(body == BODY, 'Bsr-lookup instruction window changed')
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
    check_fde(0x2cd9e8, FDE, START, END)
    require(read(eh['address'] + 0x2cd9fc, len(NEXT_FDE)) == NEXT_FDE,
            'Next FDE record changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x55442e0.
    require(body[0:4] == bytes.fromhex('f30f1efa'), 'Endbr64 changed')
    require(body[4:11] == bytes.fromhex('488b8790140000'),
            'First field load changed')
    require(struct.unpack_from('<i', body, 7)[0] == 0x1490,
            'First field offset changed')
    require(body[11:14] == bytes.fromhex('4885c0'), 'First test changed')
    require(body[14:16] == bytes.fromhex('7512'), 'First jump changed')
    require(struct.unpack_from('<b', body, 15)[0] == 0x12,
            'First jump target changed')
    require(body[16:23] == bytes.fromhex('488b8788140000'),
            'Second field load changed')
    require(struct.unpack_from('<i', body, 19)[0] == 0x1488,
            'Second field offset changed')
    require(body[23:25] == bytes.fromhex('31f6'), 'Index clear changed')
    require(body[25:28] == bytes.fromhex('4885c0'), 'Second test changed')
    require(body[28:30] == bytes.fromhex('7509'), 'Second jump changed')
    require(struct.unpack_from('<b', body, 29)[0] == 0x09,
            'Second jump target changed')
    require(body[30:33] == bytes.fromhex('4889f0'), 'Zero return changed')
    require(body[33:34] == bytes.fromhex('c3'), 'Zero return ret changed')
    require(body[34:39] == bytes.fromhex('be40000000'),
            'Index bias changed')
    require(struct.unpack_from('<i', body, 35)[0] == 0x40,
            'Index bias value changed')
    require(body[39:43] == bytes.fromhex('480fbdc8'), 'Bsr changed')
    require(body[43:45] == bytes.fromhex('01f1'), 'Index add changed')
    require(body[45:47] == bytes.fromhex('89ca'), 'Index copy changed')
    require(body[47:55] == bytes.fromhex('488bb4d788100000'),
            'Indexed table load changed')
    require(struct.unpack_from('<i', body, 51)[0] == 0x1088,
            'Table base offset changed')
    require(body[55:58] == bytes.fromhex('4889f0'), 'Table return changed')
    require(body[58:59] == bytes.fromhex('c3'), 'Table return ret changed')
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
    # the rel32 target, and caller-FDE containment.
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
    table = list(range(128))
    require(lookup(0, 0, table) == 0, 'Both-zero edge changed')
    require(lookup(1, 0, table) == 64, 'High-field bit-0 edge changed')
    require(lookup(0, 1, table) == 0, 'Low-field bit-0 edge changed')
    require(lookup(0, 2, table) == 1, 'Low-field bit-1 edge changed')
    require(lookup(1 << 63, 0, table) == 127, 'High-field top-bit edge changed')
    require(lookup(0, 1 << 63, table) == 63, 'Low-field top-bit edge changed')
    require(lookup(3, 1 << 63, table) == 65,
            'High-field precedence edge changed')
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
                    'bsr-lookup evidence packet.')
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
        print('Foundation bsr-lookup evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
