#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 global-clamp evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window loads one 64-bit global, clamps it through a shift and two
conditional moves, stores the result to a second global, then tail-jumps to a
shared callee with the store target plus eight as its argument. The callee is
named only, never decoded, following the packet #31 tail-gate precedent.

The stored value rule, restated from the retained bytes: the source global is
read as a signed 64-bit value g. When g < 0 the stored value is 0. Otherwise
v starts as 1 when g == 0 else g, v >>= 6, v becomes 1 when that shift yields
0, and v is capped at 0x400000. The tail argument is always the store target
plus eight, whatever g was.

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
START, END = 0x55539e0, 0x5553a36
BODY = bytes.fromhex(
    'f30f1efa488b35f54723004885f67840b801000000ba01000000b900004000'
    '480f4ef04889f748c1ef06480f44fa4839cf480f47f948893d7cc24500488d'
    '3d7dc24500e948c0fdff0f1f84000000000031ff31f6ebdf')
STRIDE_END = 0x5553a40
PADDING = bytes.fromhex('cccccccccccccccccccc')
SOURCE_GLOBAL = 0x57881e0
STORE_GLOBAL = 0x59afc98
TAIL_ARG = 0x59afca0
TAIL_TARGET = 0x552fa70
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# The window CIE and FDE encodings are zR: initial_location is a 4-byte
# signed PC-relative value under the CIE's zR encoding; range is a 4-byte
# unsigned value. The caller and tail FDEs belong to the same zR CIE; their
# raw bytes are locked and their ranges are the GNU-decoded values, not hand
# re-derivations.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000048ef2c007c355a045600000000000000')
NEXT_FDE = bytes.fromhex('100000005cef2c00c8355a041000000000000000')
CALLER_FDE = bytes.fromhex(
    '3c00000028fa2b001c8c5104bd03000000420e108c02410e188603410e2083'
    '04470ea0204c0ea0404c0ed0550314010a0e20430e18410e10420e08430b000'
    '000')
TAIL_FDE = bytes.fromhex('100000000cba2c00482b58041200000000000000')
CALLERS = [
    # (site, call bytes, caller FDE range)
    (0x54b9c6b, bytes.fromhex('e8709d0900'), (0x54b9b60, 0x54b9f1d)),
    (0x54b9cc9, bytes.fromhex('e8129d0900'), (0x54b9b60, 0x54b9f1d)),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def clamp(g):
    """Decoded store rule, for edge checks only.

    g is a signed 64-bit value. This is a Python restatement of the retained
    bytes, not a run or emulation of the captured binary. The negative path
    in the retained bytes zeroes rdi and jumps to the store; the
    non-negative path applies cmovle (g == 0 -> 1), shr 6, cmove
    (shifted 0 -> 1), and cmova (cap at 0x400000).
    """
    require(-(1 << 63) <= g < (1 << 63), 'g outside signed 64-bit range')
    if g < 0:
        return 0
    v = 1 if g == 0 else g
    v >>= 6
    if v == 0:
        v = 1
    if v > 0x400000:
        v = 0x400000
    return v


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

    def section_of(va):
        matches = [s for s in secs if s['address'] <= va < s['address'] + s['size']]
        require(len(matches) == 1, 'Ambiguous VA section')
        return matches[0]['name']

    body = read(START, END - START)
    require(body == BODY, 'Global-clamp instruction window changed')
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
    check_fde(0x2cef44, FDE, START, END)
    require(read(eh['address'] + 0x2cef58, len(NEXT_FDE)) == NEXT_FDE,
            'Next FDE record changed')
    check_fde(0x2bfa24, CALLER_FDE, 0x54b9b60, 0x54b9f1d)
    check_fde(0x2cba08, TAIL_FDE, TAIL_TARGET, 0x552fa82)
    # Globals live in the sections the scout notes claim: source in .data,
    # store target and tail argument in .bss (tail argument is store + 8).
    require(section_of(SOURCE_GLOBAL) == '.data', 'Source global section changed')
    require(section_of(STORE_GLOBAL) == '.bss', 'Store global section changed')
    require(TAIL_ARG == STORE_GLOBAL + 8, 'Tail argument relation changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x55539e0.
    require(body[0:4] == bytes.fromhex('f30f1efa'), 'Endbr64 changed')
    require(body[4:11] == bytes.fromhex('488b35f5472300'),
            'Source global load changed')
    require(struct.unpack_from('<i', body, 7)[0] == 0x2347f5,
            'Source load displacement changed')
    require(START + 11 + 0x2347f5 == SOURCE_GLOBAL,
            'Source global target changed')
    require(body[11:14] == bytes.fromhex('4885f6'), 'Sign test changed')
    require(body[14:16] == bytes.fromhex('7840'), 'Negative jump changed')
    require(struct.unpack_from('<b', body, 15)[0] == 0x40,
            'Negative jump target changed')
    require(START + 16 + 0x40 == 0x5553a30, 'Negative block target changed')
    require(body[16:21] == bytes.fromhex('b801000000'), 'One constant changed')
    require(body[21:26] == bytes.fromhex('ba01000000'), 'Floor constant changed')
    require(body[26:31] == bytes.fromhex('b900004000'), 'Cap constant changed')
    require(struct.unpack_from('<I', body, 27)[0] == 0x400000,
            'Cap value changed')
    require(body[31:35] == bytes.fromhex('480f4ef0'), 'Zero select changed')
    require(body[35:38] == bytes.fromhex('4889f7'), 'Value move changed')
    require(body[38:42] == bytes.fromhex('48c1ef06'), 'Shift changed')
    require(body[42:46] == bytes.fromhex('480f44fa'), 'Zero floor changed')
    require(body[46:49] == bytes.fromhex('4839cf'), 'Cap compare changed')
    require(body[49:53] == bytes.fromhex('480f47f9'), 'Cap select changed')
    require(body[53:60] == bytes.fromhex('48893d7cc24500'),
            'Store to global changed')
    require(struct.unpack_from('<i', body, 56)[0] == 0x45c27c,
            'Store displacement changed')
    require(START + 60 + 0x45c27c == STORE_GLOBAL,
            'Store global target changed')
    require(body[60:67] == bytes.fromhex('488d3d7dc24500'),
            'Tail argument lea changed')
    require(struct.unpack_from('<i', body, 63)[0] == 0x45c27d,
            'Tail argument displacement changed')
    require(START + 67 + 0x45c27d == TAIL_ARG,
            'Tail argument target changed')
    require(body[67:72] == bytes.fromhex('e948c0fdff'), 'Tail jump changed')
    require(struct.unpack_from('<i', body, 68)[0] == -0x23fb8,
            'Tail jump displacement changed')
    require(START + 72 + (-0x23fb8) == TAIL_TARGET,
            'Tail jump target changed')
    require(body[72:80] == bytes.fromhex('0f1f840000000000'),
            'Alignment padding inside body changed')
    require(body[80:82] == bytes.fromhex('31ff'), 'Negative zero changed')
    require(body[82:84] == bytes.fromhex('31f6'), 'Negative zero2 changed')
    require(body[84:86] == bytes.fromhex('ebdf'), 'Negative store jump changed')
    require(struct.unpack_from('<b', body, 85)[0] == -0x21,
            'Negative store jump target changed')
    require(START + 86 + (-0x21) == 0x5553a15, 'Negative store target changed')
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
    # Incoming calls: exactly two direct e8 calls in .text. This is a
    # byte-pattern scan, explicitly not a complete xref census. The sites
    # were confirmed as instruction starts by linear disassembly from their
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
    require(clamp(-1) == 0, 'Negative edge changed')
    require(clamp(-(1 << 63)) == 0, 'Most-negative edge changed')
    require(clamp(0) == 1, 'Zero edge changed')
    require(clamp(1) == 1, 'One edge changed')
    require(clamp(63) == 1, 'Shift-floor edge changed')
    require(clamp(64) == 1, 'Shift-one edge changed')
    require(clamp(127) == 1, 'Shift-one high edge changed')
    require(clamp(128) == 2, 'Shift-two edge changed')
    require(clamp(0x10000000) == 0x400000, 'Cap exact edge changed')
    require(clamp(0x10000040) == 0x400000, 'Cap overflow edge changed')
    require(clamp((1 << 63) - 1) == 0x400000, 'Max edge changed')
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
                    'global-clamp evidence packet.')
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
        print('Foundation global-clamp evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
