#!/usr/bin/env python3
"""Bind the node #115 simulate-panic stop checks and the writers of their fields (86th stage).

Continues #6090, which found that the begin functions 0x5483850 (layout A) and
0x5483f50 (layout B) panic with "explicit panic" at l1/src/simulate_panic.rs
when a byte (A +0x39b0, B +0x4520) is set, the new height equals a stored
height (A +0x39a8, B +0x4518) and box byte +0xb9a (B +0x170a) is not 3.
This tool binds:

1. every reference to the simulate_panic.rs Location 0x6492ef0 in .text: six
   panic sites with "explicit panic" (0x7db393, 14 bytes) in six functions:
   the two begin functions, the quorum-entry builders 0x54897e0 (A) and
   0x5486720 (B) from #6046, and 0x2bdf270 and 0x2c71eb0; three sites test
   bit 0 of the byte, three test the byte == 0;
2. every store to A +0x39a8/+0x39b0 and B +0x4518/+0x4520 through a non-stack
   base: the clone 0x55ea030 copies both fields (load 0x55f1ce3/0x55f1cf2,
   store 0x55f27c2/0x55f27d1), and three stores write the byte value 2
   (0x2addc04, 0x2cc1ced, 0x3c1296f); nothing stores to the B offsets;
3. box byte +0xb9a: one store in .text (0x2fc32ad in 0x2fc21d0); immediate
   compares of the byte are against 2 or 3 only.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import SHA256, RELATIVE, TARGET, fixed, frame, read_va, relative_relocations, rip_target, text

PACKET = ROOT / 'research/work-items/RE-008-simulate-panic-height-115'

LOCATION = 0x6492ef0
MESSAGE = 0x7db393
PANIC_SLOT = 0x64df730
STOP_A = (0x39a8, 0x39b0)
STOP_B = (0x4518, 0x4520)
SELECTOR = (0xb9a, 0x170a)

CHECK_FUNCTIONS = {
    0x5483850: 'begin A (#6090)',
    0x5483f50: 'begin B (#6090)',
    0x54897e0: 'quorum entries A (#6046)',
    0x5486720: 'quorum entries B (#6046)',
    0x2bdf270: 'layout A function 0x2bdf270',
    0x2c71eb0: 'layout A function 0x2c71eb0',
}

FIXED = {
    # begin A: bit 0 of +0x39b0, +0x39a8 == new height, +0xb9a != 3 -> panic
    0x5483903: '41f685b039000001', 0x548390b: '7417', 0x548390d: '493b95a8390000',
    0x5483916: '4180bd9a0b000003', 0x548391e: '0f85bb050000',
    # begin B: same with +0x4520 / +0x4518 / +0x170a
    0x5484003: '41f685204500000' + '1', 0x548400b: '7417', 0x548400d: '493b9518450000',
    0x5484016: '4180bd0a17000003', 0x548401e: '0f85db050000',
    # quorum entries A: byte == 0, then height compare
    0x548bfc9: '4180bc24b039000000', 0x548bfd2: '7407', 0x548bfdb: '498b8c24a8390000',
    0x548bfed: '4180bc249a0b000003', 0x548bff9: '0f858f040000',
    # quorum entries B
    0x5488ed4: '80bd2045000000', 0x5488edb: '7406', 0x5488ee3: '488b8d18450000',
    0x5488ef3: '80bd0a17000003', 0x5488efd: '0f8595040000',
    # 0x2bdf270: bit 0 test
    0x2bdf30d: 'f683b039000001', 0x2bdf317: '483bbba8390000', 0x2bdf325: '80bb9a0b000003',
    # 0x2c71eb0: byte == 0 test
    0x2c7444e: '4180beb039000000', 0x2c74456: '7526', 0x2c7445c: '4180be9a0b000003',
    0x2c74469: '493b96a8390000',
    # panic argument loads
    0x5483eed: 'be0e000000', 0x548460d: 'be0e000000', 0x548c495: 'be0e000000',
    0x548939f: 'be0e000000', 0x2bdf897: 'be0e000000', 0x2c74756: 'be0e000000',
    # clone copies both fields
    0x55f1ce3: '410fb687b0390000', 0x55f1cf2: '498b87a8390000',
    0x55f27c2: '498986a8390000', 0x55f27d1: '418886b0390000',
    # byte value 2 stores
    0x2addc04: 'c683b039000002', 0x2cc1ced: '41c686b039000002', 0x3c1296f: '41c68424b039000002',
    # the one store of +0xb9a
    0x2fc32a8: '0fb6442407', 0x2fc32ad: '88839a0b0000',
}
REFERENCES = (
    (0x5483edf, b'\x48\x8d\x3d', 7, MESSAGE), (0x5483ee6, b'\x48\x8d\x15', 7, LOCATION),
    (0x5483ef2, b'\xff\x15', 6, PANIC_SLOT),
    (0x54845ff, b'\x48\x8d\x3d', 7, MESSAGE), (0x5484606, b'\x48\x8d\x15', 7, LOCATION),
    (0x5484612, b'\xff\x15', 6, PANIC_SLOT),
    (0x548c48e, b'\x48\x8d\x15', 7, LOCATION), (0x548c49a, b'\x48\x8d\x3d', 7, MESSAGE),
    (0x548c4a1, b'\xff\x15', 6, PANIC_SLOT),
    (0x5489398, b'\x48\x8d\x15', 7, LOCATION), (0x54893a4, b'\x48\x8d\x3d', 7, MESSAGE),
    (0x2bdf889, b'\x48\x8d\x3d', 7, MESSAGE), (0x2bdf890, b'\x48\x8d\x15', 7, LOCATION),
    (0x2bdf89c, b'\xff\x15', 6, PANIC_SLOT),
    (0x2c7474f, b'\x48\x8d\x15', 7, LOCATION), (0x2c7475b, b'\x48\x8d\x3d', 7, MESSAGE),
    (0x2c74762, b'\xff\x15', 6, PANIC_SLOT),
)


def location_refs(data):
    """Every RIP-relative lea (48 8d /r, mod=00 rm=101) in .text that targets the Location."""
    base, code = text(data)
    out = []
    for m in re.finditer(rb'\x48\x8d', code):
        i = m.start()
        if i + 7 > len(code) or (code[i + 2] & 0xc7) != 0x05:
            continue
        if base + i + 7 + struct.unpack_from('<i', code, i + 3)[0] == LOCATION:
            out.append(base + i)
    return out


def field_stores(data, disp):
    """mov [base+disp32], r/imm (88/89/c6/c7, mod=10) with or without SIB, excluding rsp/rbp bases."""
    base, code = text(data)
    hits = set()
    needle = struct.pack('<I', disp)
    for m in re.finditer(re.escape(needle), code):
        d = m.start()
        for sib in (False, True):
            k = d - (3 if sib else 2)  # opcode index
            if k < 0:
                continue
            op, modrm = code[k], code[k + 1]
            if op not in (0x88, 0x89, 0xc6, 0xc7) or modrm >> 6 != 2:
                continue
            rex = code[k - 1] if k >= 1 and 0x40 <= code[k - 1] <= 0x4f else 0
            if sib:
                if modrm & 7 != 4:
                    continue
                b = (code[k + 2] & 7) | ((rex & 1) << 3)
            else:
                if modrm & 7 == 4:
                    continue
                b = (modrm & 7) | ((rex & 1) << 3)
            if b in (4, 5):  # rsp, rbp
                continue
            hits.add(base + (k - 1 if rex else k))
    return sorted(hits)


def immediate_compares(data, disp):
    """cmp byte [base+disp32], imm8 (80 /7, mod=10, no SIB or SIB), non-rsp base: immediate -> count."""
    base, code = text(data)
    counts = {}
    for m in re.finditer(re.escape(struct.pack('<I', disp)), code):
        d = m.start()
        for sib in (False, True):
            k = d - (3 if sib else 2)
            if k < 0 or code[k] != 0x80:
                continue
            modrm = code[k + 1]
            if modrm >> 6 != 2 or (modrm >> 3) & 7 != 7 or ((modrm & 7) == 4) != sib:
                continue
            rex = code[k - 1] if 0x40 <= code[k - 1] <= 0x4f else 0
            b = ((code[k + 2] if sib else modrm) & 7) | ((rex & 1) << 3)
            if b == 4:
                continue
            imm = code[d + 4]
            counts[imm] = counts.get(imm, 0) + 1
    return {hex(k): v for k, v in sorted(counts.items())}


def location(data, va):
    raw = read_va(data, va, 24)
    rel = relative_relocations(data)
    ptr = rel.get(va, struct.unpack_from('<Q', raw, 0)[0])
    length, line, col = struct.unpack_from('<QII', raw, 8)
    return read_va(data, ptr, length).decode(), line, col


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    if read_va(data, MESSAGE, 14) != b'explicit panic':
        raise ValueError('panic message changed')
    path, line, col = location(data, LOCATION)
    if (path, line, col) != ('l1/src/simulate_panic.rs', 10, 13):
        raise ValueError('Location changed')
    refs = location_refs(data)
    owners = sorted({frame(fdes, v) for v in refs})
    if len(refs) != 6 or owners != sorted(CHECK_FUNCTIONS):
        raise ValueError('Location reference census changed')
    stores = {hex(d): [hex(v) for v in field_stores(data, d)] for d in STOP_A + STOP_B + SELECTOR}
    expect = {'0x39a8': ['0x55f27c2'], '0x39b0': ['0x2addc04', '0x2cc1ced', '0x3c1296f', '0x55f27d1'],
              '0x4518': [], '0x4520': [], '0xb9a': ['0x2fc32ad'], '0x170a': []}
    if stores != expect:
        raise ValueError('store census changed')
    if frame(fdes, 0x55f27c2) != 0x55ea030 or frame(fdes, 0x2fc32ad) != 0x2fc21d0:
        raise ValueError('store owner changed')
    compares = {hex(d): immediate_compares(data, d) for d in SELECTOR}
    if set(compares['0xb9a']) != {'0x2', '0x3'} or set(compares['0x170a']) != {'0x2', '0x3'}:
        raise ValueError('selector compare census changed')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'panic': {'message': hex(MESSAGE) + ' "explicit panic" (14 bytes)',
                  'location': '%s %s:%d:%d' % (hex(LOCATION), path, line, col),
                  'slot': hex(PANIC_SLOT)},
        'check_sites': [
            {'function': hex(f), 'role': r, 'location_ref': hex(next(v for v in refs if frame(fdes, v) == f))}
            for f, r in sorted(CHECK_FUNCTIONS.items())],
        'byte_tests': {
            'bit0_set': ['0x5483903 (A +0x39b0)', '0x5484003 (B +0x4520)', '0x2bdf30d (A +0x39b0)'],
            'equals_zero': ['0x548bfc9 (A +0x39b0)', '0x5488ed4 (B +0x4520)', '0x2c7444e (A +0x39b0)'],
            'all_then': 'height == stored height (A +0x39a8 / B +0x4518) and selector byte != 3 -> panic',
        },
        'field_stores_non_stack': stores,
        'store_owners': {'0x55f27c2/0x55f27d1': '0x55ea030 (copies from loads 0x55f1ce3/0x55f1cf2)',
                         '0x2addc04': hex(frame(fdes, 0x2addc04)), '0x2cc1ced': hex(frame(fdes, 0x2cc1ced)),
                         '0x3c1296f': hex(frame(fdes, 0x3c1296f)), '0x2fc32ad': '0x2fc21d0'},
        'byte_value_2_stores': ['0x2addc04', '0x2cc1ced', '0x3c1296f'],
        'selector_immediate_compares': compares,
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    data = binary.read_bytes()
    _, fdes, _ = fde_extents(data)
    result = bind(data, fdes)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_bytes(render(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    expected = (PACKET / 'evidence.json').read_bytes() if args.check else None
    result = generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    print('check sites=%d stop-field stores=%s' % (len(result['check_sites']), result['field_stores_non_stack']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
