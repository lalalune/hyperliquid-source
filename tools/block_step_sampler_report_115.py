#!/usr/bin/env python3
"""Bind the node #115 block-step sampler's post-walk collect and two observer fields (19th stage).

Continues #5934. After its per-item walk, sampler 0x5b2a130 calls 0x5b926e0
once when the local map holds at least 3 entries, and once more when it holds
at least 2 and a minute value is at least 6. This tool binds:

1. 0x5b926e0: a collect of 8-byte pointers into a new vector. Its input has
   two modes: tag 2 walks two contiguous runs of 0x20-byte elements; any other
   tag calls 0x51360a0, which counts down a remaining length at +0x40 and walks
   B-tree nodes (length u16 +0x13e, parent index u16 +0x13c, edges +0x140 and
   +0x148). The first capacity is max(4, hint + 1); growth goes through
   0x5963a10 (element size 8, align 8). An empty input gives (0, 8, 0). The
   function's only calls are 0x51360a0, 0x5963a10, the allocator, the
   allocation-failure handler, the free function and _Unwind_Resume;
2. the sampler's two call sites: each reads only the result's capacity and
   pointer, frees the buffer, and the next writes overwrite rsp+0x8..+0x48
   (0x5b2a6cb) before any later read: the collected vectors are never read;
3. observer +0x240 (dword) and +0x200 (qword): the record entry 0x1547530
   compares +0x240 with the first dword from the wall-clock call (slot
   0x64e0990 -> 0x1629690); on a change it zeroes +0x200..+0x218 and stores
   the new dword at +0x240 and the next qword at +0x244. Later it adds the
   count argument (r14 = rsi) to +0x200 and 1 to +0x208, both saturating.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import bisect
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-block-step-sampler-report-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

SAMPLER = 0x5b2a130
COLLECT = 0x5b926e0
BTREE_NEXT = 0x51360a0
GROW = 0x5963a10
RECORD = 0x1547530
CONSTRUCTOR = 0x1548bb0
CLOCK_SLOT, CLOCK = 0x64e0990, 0x1629690
ALLOC_SLOTS = {0x64df480: 'alloc', 0x64df498: 'alloc failure', 0x64df4a0: 'free'}
UNWIND_RESUME = 0x63f0a50

FIXED = {
    # collect 0x5b926e0: input modes and capacity
    0x5b926f4: '833e02',                # cmp dword [rsi], 2          (two-run mode)
    0x5b926f7: '7540',                  # jne 0x5b92739               (else B-tree next)
    0x5b92739: '4c89f7',                # mov rdi, r14
    0x5b9275f: '48c1e905',              # shr rcx, 5                  (0x20-byte elements)
    0x5b92770: '498b4640',              # mov rax, [r14+0x40]         (remaining length)
    0x5b92774: '48ffc0',                # inc rax                     (hint + 1)
    0x5b92782: '4883f905',              # cmp rcx, 5
    0x5b92786: 'bb04000000',            # mov ebx, 4                  (minimum capacity)
    0x5b927d7: '4c8938',                # mov [rax], r15              (first pointer)
    0x5b928ec: 'b908000000',            # mov ecx, 8                  (element size)
    0x5b928f1: '41b808000000',          # mov r8d, 8                  (alignment)
    0x5b92937: '49c7450000000000',      # mov qword [r13], 0          (empty: cap 0)
    0x5b9293f: '49c7450808000000',      # mov qword [r13+8], 8        (dangling ptr)
    0x5b92947: '49c7451000000000',      # mov qword [r13+0x10], 0     (len 0)
    # B-tree next 0x51360a0
    0x51360a1: '488b4740',              # mov rax, [rdi+0x40]         (remaining)
    0x51360a8: '7439',                  # je -> None
    0x51360aa: '48ffc8',                # dec rax
    0x51360ad: '48894740',              # mov [rdi+0x40], rax
    0x51360cb: '0fb7903e010000',        # movzx edx, word [rax+0x13e] (node length)
    0x51361af: '0fb7883c010000',        # movzx ecx, word [rax+0x13c] (parent index)
    0x5136110: '488b8040010000',        # mov rax, [rax+0x140]        (first edge)
    # sampler: both results freed unread
    0x5b2a51f: '488b742408',            # mov rsi, [rsp+8]            (cap)
    0x5b2a529: '488b7c2410',            # mov rdi, [rsp+0x10]         (ptr)
    0x5b2a52e: '48c1e603',              # shl rsi, 3
    0x5b2a667: '488b742408',
    0x5b2a671: '488b7c2410',
    0x5b2a676: '48c1e603',
    0x5b2a6cb: '48894c2408',            # mov [rsp+8], rcx            (overwrite)
    0x5b2a6d0: '4c89442410',            # mov [rsp+0x10], r8
    # record entry 0x1547530: date field +0x240, day sums +0x200/+0x208
    0x154754a: '4989f6',                # mov r14, rsi                (count argument)
    0x154755f: '8b3c24',                # mov edi, [rsp]              (clock dword)
    0x1547562: '39bb40020000',          # cmp [rbx+0x240], edi
    0x1547568: '7447',                  # je (same date: no reset)
    0x154756a: '0f57c0',                # xorps xmm0, xmm0
    0x154756d: '0f118300020000',        # movups [rbx+0x200], xmm0
    0x1547574: '48c7831002000000000000',  # mov qword [rbx+0x210], 0
    0x1547596: '89bb40020000',          # mov [rbx+0x240], edi
    0x154759c: '488b0424',              # mov rax, [rsp]
    0x15475a0: '48898344020000',        # mov [rbx+0x244], rax
    0x154770d: '488b8b00020000',        # mov rcx, [rbx+0x200]
    0x1547714: '4c01f1',                # add rcx, r14
    0x1547721: '480f42f2',              # cmovb rsi, rdx              (saturate)
    0x1547729: '4889b300020000',        # mov [rbx+0x200], rsi
    0x1547730: '488b8b08020000',        # mov rcx, [rbx+0x208]
    0x1547737: '48ffc1',                # inc rcx
    0x154773a: '480f44ca',              # cmove rcx, rdx              (saturate)
    0x154773e: '48898b08020000',        # mov [rbx+0x208], rcx
    # constructor 0x1548bb0
    0x1548d37: '4589ae40020000',        # mov [r14+0x240], r13d
    0x1548d3e: '660f57c0',              # xorpd xmm0, xmm0
    0x1548d42: '66410f118600020000',    # movupd [r14+0x200], xmm0
}
CALLS = {
    # (call va): target
    0x5b9273c: BTREE_NEXT,
    0x5b928a3: BTREE_NEXT,
    0x5b928fd: GROW,
    0x5b2a51a: COLLECT,
    0x5b2a662: COLLECT,
    0x5b2a534: 0x64df4a0,
    0x5b2a67c: 0x64df4a0,
    0x1547559: CLOCK_SLOT,
}


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return data[off:off + size]


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def call_target(data, va):
    raw = read_va(data, va, 6)
    if raw[0] == 0xe8:
        return va + 5 + struct.unpack_from('<i', raw, 1)[0]
    if raw[:2] == b'\xff\x15':
        return va + 6 + struct.unpack_from('<i', raw, 2)[0]
    raise ValueError(f'instruction at {va:#x} changed')


def relative_relocations(data):
    rel = {}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise ValueError(f"relocation section {sec['name']} is truncated")
        for va, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if info & 0xffffffff == 8:
                rel[va] = addend
    return rel


def frame_of(fdes, va):
    ordered = sorted(fdes, key=lambda f: f['start'])
    starts = [f['start'] for f in ordered]
    i = bisect.bisect_right(starts, va) - 1
    if i < 0 or not ordered[i]['start'] <= va < ordered[i]['end']:
        raise ValueError(f'{va:#x} has no FDE')
    return ordered[i]['start'], ordered[i]['end']


def call_census(data, fdes, lo, hi):
    """E8 calls to an FDE start or PLT stub, and every FF 15 rip-relative call, inside [lo, hi)."""
    starts = {f['start'] for f in fdes}
    plt = next(s for s in sections(data) if s['name'] == '.plt')
    code = read_va(data, lo, hi - lo)
    out = []
    for m in re.finditer(rb'\xe8|\xff\x15', code):
        i = m.start()
        va = lo + i
        if code[i] == 0xe8 and i + 5 <= len(code):
            target = va + 5 + struct.unpack_from('<i', code, i + 1)[0]
            if target in starts or plt['address'] <= target < plt['address'] + plt['size']:
                out.append((va, target))
        elif code[i:i + 2] == b'\xff\x15' and i + 6 <= len(code):
            out.append((va, va + 6 + struct.unpack_from('<i', code, i + 2)[0]))
    return out


def direct_calls(data, target):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    base, code = sec['address'], data[sec['offset']:sec['offset'] + sec['size']]
    return [base + m.start() for m in re.finditer(rb'\xe8', code)
            if m.start() + 5 <= len(code)
            and base + m.start() + 5 + struct.unpack_from('<i', code, m.start() + 1)[0] == target]


EXPECTED_CENSUS = {
    COLLECT: [(0x5b9273c, BTREE_NEXT), (0x5b927b7, 0x64df498), (0x5b927c5, 0x64df480),
              (0x5b928a3, BTREE_NEXT), (0x5b928fd, GROW), (0x5b92966, 0x64df498),
              (0x5b92984, 0x64df4a0), (0x5b9298d, UNWIND_RESUME)],
    BTREE_NEXT: [(0x513629f, 0x64df830), (0x51362ae, 0x64df830)],
    GROW: [(0x5963a21, 0x64df498), (0x5963a6f, 0x5963650), (0x5963a98, 0x64df498)],
}
SLOT_NAMES = {**ALLOC_SLOTS, 0x64df830: 'Option::unwrap panic slot (-> 0x1680c10)', UNWIND_RESUME: '_Unwind_Resume'}


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, target in CALLS.items():
        if call_target(data, va) != target:
            raise ValueError(f'call at {va:#x} changed')
    rel = relative_relocations(data)
    if rel.get(CLOCK_SLOT) != CLOCK or rel.get(0x64df830) != 0x1680c10:
        raise ValueError('slot relocation changed')

    census = {}
    for fn, expect in EXPECTED_CENSUS.items():
        lo, hi = frame_of(fdes, fn)
        if lo != fn:
            raise ValueError(f'{fn:#x} is not an FDE start')
        found = call_census(data, fdes, lo, hi)
        if found != expect:
            raise ValueError(f'call census of {fn:#x} changed')
        census[hex(fn)] = {'fde': [hex(lo), hex(hi)],
                           'calls': [[hex(v), SLOT_NAMES.get(t, hex(t))] for v, t in found]}
    collect_callers = direct_calls(data, COLLECT)
    next_callers = direct_calls(data, BTREE_NEXT)
    if collect_callers != [0x5b2a51a, 0x5b2a662]:
        raise ValueError('collect callers changed')
    if any(frame_of(fdes, v)[0] != SAMPLER for v in collect_callers):
        raise ValueError('collect callers left the sampler')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'collect': {
            'fn': hex(COLLECT),
            'direct_callers': [hex(v) for v in collect_callers],
            'input_modes': {
                'tag 2': 'two contiguous runs of 0x20-byte elements (+0x8..+0x20 begin/end pairs)',
                'other': 'B-tree next %s: remaining length +0x40, node length u16 +0x13e, parent index '
                         'u16 +0x13c, edges +0x140/+0x148' % hex(BTREE_NEXT),
            },
            'output': '8-byte pointers; first capacity max(4, hint + 1); growth via %s (size 8, align 8); '
                      'empty input -> (cap 0, ptr 8, len 0)' % hex(GROW),
            'btree_next_direct_callers': [hex(v) for v in next_callers],
            'call_census': census,
        },
        'sampler_results': {
            'sites': [hex(0x5b2a51a), hex(0x5b2a662)],
            'after_each': 'read cap [rsp+8] and ptr [rsp+0x10], free cap*8 bytes; len [rsp+0x18] not read',
            'overwrite': hex(0x5b2a6cb) + ' stores rsp+0x8..+0x48 before any later read',
        },
        'observer_fields': {
            '+0x240': 'dword compared with the first dword of the wall-clock call (slot %s -> %s) at %s; '
                      'on change: zero +0x200..+0x218, store dword at +0x240 and next qword at +0x244'
                      % (hex(CLOCK_SLOT), hex(CLOCK), hex(0x1547562)),
            '+0x200': 'qword: += count argument (r14 = rsi), saturating (%s)' % hex(0x1547729),
            '+0x208': 'qword: += 1, saturating (%s)' % hex(0x154773e),
            'constructor': '%s stores r13d at +0x240 and zero at +0x200..+0x210' % hex(CONSTRUCTOR),
        },
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
    print(f"collect_callers={len(result['collect']['direct_callers'])} "
          f"btree_next_callers={len(result['collect']['btree_next_direct_callers'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
