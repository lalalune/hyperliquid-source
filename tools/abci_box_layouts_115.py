#!/usr/bin/env python3
"""Bind the two node #115 abci box layouts that differ by a 0xb70-byte insertion (36th stage).

Continues #5970 (freeze setter 0x54c9b80, dispatcher case 31 of 0x5397b50) and
#6004 (visor_abci_state writers read the freeze height from box +0x10e8 in
three callers and from +0x1c58 in 0x5a08720). This tool binds:

1. a sibling freeze setter 0x54c9a90 whose bytes equal 0x54c9b80 except the
   box offsets: +0x10e8/+0x10f0 there, +0x1c58/+0x1c60 here (delta 0xb70);
   the sibling is called once, from dispatcher 0x538cd30 (0x538e830);
2. three function pairs of equal length, compared byte by byte. Every
   differing 4-byte field is classified as a box displacement that grows by
   exactly 0xb70, a RIP-relative or rel32 field that names the same absolute
   address, or a reference to a paired function / table:
   - steps 0x5a07ec0 / 0x5a08720 (0x85c bytes),
   - dispatchers 0x538cd30 / 0x5397b50 (0xae1d bytes),
   - freeze setters 0x54c9a90 / 0x54c9b80 (0xeb bytes);
3. the shifted displacements start at +0x7c0: no shifted field in the
   compared code is below +0x7c0, so the second layout carries 0xb70 extra
   bytes from +0x7c0 (inference: the 0xb70-byte output-setter result that
   #5908 places at +0x7c0 of the block).

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import direct_calls, read_va

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-abci-box-layouts-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SHIFT = 0xb70

PAIRS = {
    'freeze_setter': (0x54c9a90, 0x54c9b80, 0xeb),
    'step': (0x5a07ec0, 0x5a08720, 0x85c),
    'dispatcher': (0x538cd30, 0x5397b50, 0xae1d),
}


def _ranges(data):
    from elf_index import sections
    secs = {x['name']: x for x in sections(data)}
    return {n: (secs[n]['address'], secs[n]['address'] + secs[n]['size']) for n in ('.text', '.rodata')}


def classify(data, a0, b0, length, starts):
    """Classify every differing 4-byte field of two equal-length functions.

    A field at offset s is read as a signed 32-bit value in both copies.
    'field': value grows by SHIFT (a [reg+disp32] box displacement).
    'same': value differs by a0 - b0 (rel32 / RIP-relative field naming the
            same absolute address, assuming the field ends its instruction).
    'pair': a rel32 whose two targets are both FDE starts (paired functions).
    'table': a RIP-relative field whose two targets both fall in .rodata
             (each copy has its own jump table).
    'other': none of these (reported, never ignored).
    """
    A = read_va(data, a0, length)
    B = read_va(data, b0, length)
    ro = _ranges(data)['.rodata']
    out = {'field': [], 'same': [], 'pair': [], 'table': [], 'other': []}
    p = 0
    while p < length:
        if A[p] == B[p]:
            p += 1
            continue
        chosen = None
        for kind in ('field', 'same', 'pair', 'table'):
            for s in range(max(0, p - 3), p + 1):
                if s + 4 > length:
                    continue
                va = struct.unpack_from('<i', A, s)[0]
                vb = struct.unpack_from('<i', B, s)[0]
                if any(A[q] != B[q] for q in range(p, s + 4)) is False:
                    continue
                if kind == 'field' and vb - va == SHIFT:
                    chosen = (kind, s, va, vb)
                elif kind == 'same' and vb - va == a0 - b0:
                    chosen = (kind, s, va, vb)
                elif kind in ('pair', 'table'):
                    ta, tb = a0 + s + 4 + va, b0 + s + 4 + vb
                    if kind == 'pair' and ta in starts and tb in starts and ta != tb:
                        chosen = (kind, s, ta, tb)
                    if kind == 'table' and ro[0] <= ta < ro[1] and ro[0] <= tb < ro[1]:
                        chosen = (kind, s, ta, tb)
                if chosen:
                    break
            if chosen:
                break
        if chosen is None:
            out['other'].append(p)
            p += 1
            continue
        kind, s, x, y = chosen
        out[kind].append((s, x, y))
        p = s + 4
    return out


FIXED = {
    0x54c9af2: '48c786e810000001000000',    # mov qword [rsi+0x10e8], 1
    0x54c9afd: '488996f0100000',            # mov [rsi+0x10f0], rdx
    0x54c9be2: '48c786581c000001000000',    # mov qword [rsi+0x1c58], 1
    0x54c9bed: '488996601c0000',            # mov [rsi+0x1c60], rdx
    0x54c9ac7: '4881c150c30000',            # add rcx, 50000 (sibling)
    0x54c9bb7: '4881c150c30000',            # add rcx, 50000 (#5970 setter)
    # dispatcher 0x538cd30 / 0x5397b50: the two immediates that do not shift by 0xb70
    0x5395f86: '4881c39b0b0000',            # add rbx, 0xb9b
    0x5396821: '4881c59b0b0000',            # add rbp, 0xb9b
    0x53a0da6: '4881c3c0070000',            # add rbx, 0x7c0
    0x53a1641: '4881c5c0070000',            # add rbp, 0x7c0
    # 0x5a6bfb0: 0x42c8-byte box, 0xb70-byte setter result, then 0x548ce30
    0x5a6c05d: 'bfc8420000',                # mov edi, 0x42c8               (alloc)
    0x5a6c083: 'bac8420000',                # mov edx, 0x42c8               (memcpy)
    0x5a6c096: 'ba700b0000',                # mov edx, 0xb70                (memcpy)
    # 0x548ce30: setter result at image +0x7c0, 0x4e38-byte box, old box freed
    0x548d6f5: '488dbc24e0070000',          # lea rdi, [rsp+0x7e0]          (= rsp+0x20 + 0x7c0)
    0x548d6fd: 'ba700b0000',                # mov edx, 0xb70
    0x548d702: '4c89f6',                    # mov rsi, r14
    0x548d708: '488dbc2420170000',          # lea rdi, [rsp+0x1720]
    0x548d710: '488d742420',                # lea rsi, [rsp+0x20]
    0x548d715: 'ba00170000',                # mov edx, 0x1700
    0x548d82f: 'bf384e0000',                # mov edi, 0x4e38               (alloc)
    0x548d847: 'ba384e0000',                # mov edx, 0x4e38               (memcpy)
    0x548d858: 'bec8420000',                # mov esi, 0x42c8               (dealloc old box)
}
ALLOC_SLOT = 0x64df480
ALLOC_CALLS = (0x5a6c062, 0x548d834)
EXPECTED = {
    'freeze_setter': {'field': 5, 'same': 6, 'pair': 0, 'table': 0, 'other': 0},
    'step': {'field': 9, 'same': 64, 'pair': 3, 'table': 0, 'other': 0},
    'dispatcher': {'field': 175, 'same': 476, 'pair': 43, 'table': 6, 'other': 4},
}
DISPATCHER_OTHER = [0x9259, 0x925a, 0x9af4, 0x9af5]     # imm bytes of the two adds above


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va in ALLOC_CALLS:
        raw = read_va(data, va, 6)
        if raw[:2] != b'\xff\x15' or va + 6 + struct.unpack_from('<i', raw, 2)[0] != ALLOC_SLOT:
            raise ValueError(f'allocation call at {va:#x} changed')
    if 0x4e38 - 0x42c8 != SHIFT:
        raise ValueError('size arithmetic')
    starts = {f['start'] for f in fdes}
    ends = {f['start']: f['end'] for f in fdes}
    pairs = {}
    shifted = set()
    for name, (a0, b0, length) in PAIRS.items():
        for v in (a0, b0):
            if v not in starts or ends[v] - v != length:
                raise ValueError(f'{name}: FDE extent of {v:#x} changed')
        r = classify(data, a0, b0, length, starts)
        counts = {k: len(v) for k, v in r.items()}
        if counts != EXPECTED[name]:
            raise ValueError(f'{name}: classification changed {counts}')
        if name == 'dispatcher' and r['other'] != DISPATCHER_OTHER:
            raise ValueError('dispatcher: unexplained bytes changed')
        shifted |= {x for _, x, _ in r['field']}
        pairs[name] = {
            'a': hex(a0), 'b': hex(b0), 'length': hex(length), 'counts': counts,
            'shifted_box_offsets_a': sorted({hex(x) for _, x, _ in r['field']}, key=lambda s: int(s, 16)),
            'paired_functions': sorted({(hex(x), hex(y)) for _, x, y in r['pair']}),
            'paired_tables': [(hex(x), hex(y)) for _, x, y in r['table']],
        }
    if min(shifted) != 0x7c0:
        raise ValueError('lowest shifted offset changed')
    calls = {hex(t): [hex(v) for v in direct_calls(data, t)]
             for t in (0x54c9a90, 0x54c9b80, 0x5a07ec0, 0x5a08720, 0x548ce30)}
    if calls[hex(0x54c9a90)] != ['0x538e830'] or calls[hex(0x54c9b80)] != ['0x5399650']:
        raise ValueError('setter call census changed')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'shift': hex(SHIFT),
        'pairs': pairs,
        'shifted_offset_range_a': [hex(min(shifted)), hex(max(shifted))],
        'shifted_offsets_count': len(shifted),
        'direct_calls': calls,
        'box_sizes': {'a': '0x42c8 (alloc 0x5a6c05d)', 'b': '0x4e38 (alloc 0x548d82f)', 'difference': hex(SHIFT)},
        'conversion': '0x548ce30 copies the 0xb70-byte argument to image +0x7c0 (0x548d6f5) and frees the '
                      '0x42c8-byte box (0x548d858)',
        'dispatcher_exceptions': 'add reg, 0xb9b (0x538cd30) vs add reg, 0x7c0 (0x5397b50) at +0x9256, +0x9af1',
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
    print('shifted offsets %d, range %s' % (result['shifted_offsets_count'], result['shifted_offset_range_a']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
