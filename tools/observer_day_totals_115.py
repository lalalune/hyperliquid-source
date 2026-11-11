#!/usr/bin/env python3
"""Bind where the node #115 observer's day totals go, and the first sampler's collect (20th stage).

Continues #5940, which found that observer +0x200 sums the count argument and
+0x208 counts record calls for the current UTC day (+0x240). This tool binds:

1. the day value sum +0x210: the record entry 0x1547530 converts the count
   argument (x50 when the flag +0x25c is 1) to f64, multiplies it by the
   value argument (mulsd at 0x15475fd), adds it to +0x210 (0x1547660) and
   stores the result at 0x1547758;
2. the window-record path: once the window holds at least 10 samples
   (0x1547f4b), it loads +0x210, rejects a non-finite sum, loads +0x200
   (0x1547f78), clamps a sum in (-1e-15, 0) to 0, skips the record when the
   day count is 0 or the sum is below -1e-15, divides the sum by the count
   converted to f64 (0x1547fdd) and rejects a non-finite quotient;
3. the count is stored at rsp+0x1c8 and the quotient at rsp+0x58, then
   copied to rsp+0x128 and rsp+0x130 (0x15487d8..0x15487ee). The record
   passed to the line writer is rsp+0xd8 (0x15489b0, #5854), so these are
   record +0x50 and +0x58, which the serializer 0x1548f40 writes as
   "total_n" (u64 helper) and "total_mean" (f64 helper);
4. +0x208 is read only by its own increment in this function;
5. the two other callers of the B-tree iterator 0x51360a0 are in 0x5b70cf0,
   a second collect of 8-byte pointers with the same two input modes as
   0x5b926e0. Its only direct callers are two sites in the first block-step
   sampler 0x5b298d0; each reads only the result's capacity and pointer and
   frees the buffer, as in #5940.

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
PACKET = ROOT / 'research/work-items/RE-008-observer-day-totals-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

RECORD = (0x1547530, 0x1548ba3)
SERIALIZER = 0x1548f40
LINE_WRITE = 0x14c3370
BTREE_NEXT = 0x51360a0
COLLECT_A = 0x5b926e0
COLLECT_B = 0x5b70cf0
SAMPLER_A = 0x5b298d0
SAMPLER_B = 0x5b2a130
FREE_SLOT = 0x64df4a0
EPSILON = 0x458fa0
FIELDS = ((0x466de5, b'total_n', 0x50), (0x466dec, b'total_mean', 0x58))

FIXED = {
    # day reset on a new UTC date
    0x1547562: '39bb40020000',              # cmp [rbx+0x240], edi
    0x154756d: '0f118300020000',            # movups [rbx+0x200], xmm0   (+0x200, +0x208)
    0x1547574: '48c7831002000000000000',    # mov qword [rbx+0x210], 0
    # count x50 and value product
    0x15475b1: '80bb5c02000001',            # cmp byte [rbx+0x25c], 1
    0x15475ba: 'b932000000',                # mov ecx, 50
    0x15475fd: 'f20f59e3',                  # mulsd xmm4, xmm3          (count * value)
    0x1547658: 'f20f108310020000',          # movsd xmm0, [rbx+0x210]
    0x1547660: 'f20f58c4',                  # addsd xmm0, xmm4
    0x1547758: 'f20f118b10020000',          # movsd [rbx+0x210], xmm1
    # +0x200 saturating add, +0x208 saturating increment
    0x154770d: '488b8b00020000',            # mov rcx, [rbx+0x200]
    0x1547714: '4c01f1',                    # add rcx, r14
    0x1547721: '480f42f2',                  # cmovb rsi, rdx           (u64::MAX)
    0x1547729: '4889b300020000',            # mov [rbx+0x200], rsi
    0x1547730: '488b8b08020000',            # mov rcx, [rbx+0x208]
    0x1547737: '48ffc1',                    # inc rcx
    0x154773a: '480f44ca',                  # cmove rcx, rdx
    0x154773e: '48898b08020000',            # mov [rbx+0x208], rcx
    # window record: at least 10 samples
    0x1547f47: '4c8b6358',                  # mov r12, [rbx+0x58]
    0x1547f4b: '4983fc0a',                  # cmp r12, 10
    0x1547f4f: '0f8202070000',              # jb 0x1548657             (no record)
    0x1547f55: 'f30f7e8b10020000',          # movq xmm1, [rbx+0x210]
    0x1547f72: '0f8fdf060000',              # jg 0x1548657             (non-finite sum)
    0x1547f78: '488b9300020000',            # mov rdx, [rbx+0x200]
    0x1547f93: '660f57c9',                  # xorpd xmm1, xmm1         (tiny negative -> 0)
    0x1547f97: '4885d2',                    # test rdx, rdx
    0x1547fa4: '0f94c0',                    # sete al                  (count 0)
    0x1547fab: '0f97c1',                    # seta cl                  (sum < 0)
    0x1547fb0: '0f85a1060000',              # jne 0x1548657
    0x1547fb6: '66480f6ec2',                # movq xmm0, rdx           (u64 -> f64)
    0x1547fdd: 'f20f5eca',                  # divsd xmm1, xmm2         (sum / count)
    0x1547ff6: '0f8f5b060000',              # jg 0x1548657             (non-finite mean)
    0x1547ffc: '48899424c8010000',          # mov [rsp+0x1c8], rdx
    0x1548004: 'f20f114c2458',              # movsd [rsp+0x58], xmm1
    # copies into the record (rsp+0xd8 + 0x50 / + 0x58)
    0x15487d8: '488b8424c8010000',          # mov rax, [rsp+0x1c8]
    0x15487e0: '4889842428010000',          # mov [rsp+0x128], rax
    0x15487e8: 'f20f10442458',              # movsd xmm0, [rsp+0x58]
    0x15487ee: 'f20f11842430010000',        # movsd [rsp+0x130], xmm0
    0x15489b0: '488d9424d8000000',          # lea rdx, [rsp+0xd8]      (record)
    # serializer: record +0x50 / +0x58 with their names
    0x1548fa8: '488d4b50',                  # lea rcx, [rbx+0x50]
    0x1548fb8: 'ba07000000',                # mov edx, 7
    0x1548fd6: '488d4b58',                  # lea rcx, [rbx+0x58]
    0x1548fe6: 'ba0a000000',                # mov edx, 10
    # first sampler: collect result freed unread (two sites)
    0x5b29cad: '488d7c2408',                # lea rdi, [rsp+0x8]       (result)
    0x5b29cbf: '488b742408',                # mov rsi, [rsp+0x8]       (capacity)
    0x5b29cc9: '488b7c2410',                # mov rdi, [rsp+0x10]      (pointer)
    0x5b29cce: '48c1e603',                  # shl rsi, 3
    0x5b29df5: '488d7c2408',                # lea rdi, [rsp+0x8]
    0x5b29e07: '488b742408',                # mov rsi, [rsp+0x8]
    0x5b29e11: '488b7c2410',                # mov rdi, [rsp+0x10]
    0x5b29e16: '48c1e603',                  # shl rsi, 3
    # second collect: two input modes, B-tree iterator, 8-byte growth
    0x5b70d04: '833e02',                    # cmp dword [rsi], 2
    0x5b70d96: 'bb04000000',                # mov ebx, 4               (minimum capacity)
    0x5b70efc: 'b908000000',                # mov ecx, 8
    0x5b70f01: '41b808000000',              # mov r8d, 8
}
CALLS = {
    # (call site va): target
    0x15489bb: LINE_WRITE,
    0x1548fbd: 0x159b710,       # u64 helper   (total_n)
    0x1548feb: 0x159c0f0,       # f64 helper   (total_mean)
    0x5b29cba: COLLECT_B,
    0x5b29cd4: FREE_SLOT,
    0x5b29e02: COLLECT_B,
    0x5b29e1c: FREE_SLOT,
    0x5b70d4c: BTREE_NEXT,
    0x5b70eb3: BTREE_NEXT,
    0x5b70f0d: 0x5963a10,       # grow
}
LEAS = {
    # (lea va): target
    0x1547f89: EPSILON,         # ucomisd xmm1, [rip -> -1e-15] (prefix 660f2e0d)
    0x1548fac: FIELDS[0][0],
    0x1548fda: FIELDS[1][0],
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


def rip_target(data, va):
    raw = read_va(data, va, 8)
    if raw[:3] == b'\x48\x8d\x35':
        return va + 7 + struct.unpack_from('<i', raw, 3)[0]
    if raw[:4] == b'\x66\x0f\x2e\x0d':
        return va + 8 + struct.unpack_from('<i', raw, 4)[0]
    raise ValueError(f'instruction at {va:#x} changed')


def frame_of(fdes, va):
    ordered = sorted(fdes, key=lambda f: f['start'])
    starts = [f['start'] for f in ordered]
    i = bisect.bisect_right(starts, va) - 1
    if i < 0 or not ordered[i]['start'] <= va < ordered[i]['end']:
        raise ValueError(f'{va:#x} has no FDE')
    return ordered[i]['start'], ordered[i]['end']


def direct_calls(data, target):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    base, code = sec['address'], data[sec['offset']:sec['offset'] + sec['size']]
    return [base + m.start() for m in re.finditer(rb'\xe8', code)
            if m.start() + 5 <= len(code)
            and base + m.start() + 5 + struct.unpack_from('<i', code, m.start() + 1)[0] == target]


def field_refs(data, lo, hi, disp):
    """Instructions in [lo, hi) with a [rbx+disp32] memory operand (ModRM mod=10, rm=rbx)."""
    code = read_va(data, lo, hi - lo)
    pattern = re.compile(rb'[\x83\x8b\x93\x9b\xa3\xab\xb3\xbb]' + re.escape(struct.pack('<i', disp)))
    return [lo + m.start() for m in pattern.finditer(code)]


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, target in CALLS.items():
        if call_target(data, va) != target:
            raise ValueError(f'call at {va:#x} changed')
    for va, target in LEAS.items():
        if rip_target(data, va) != target:
            raise ValueError(f'reference at {va:#x} changed')
    for va, name, _ in FIELDS:
        if read_va(data, va, len(name)) != name:
            raise ValueError('field name changed')
    epsilon = struct.unpack('<d', read_va(data, EPSILON, 8))[0]
    if epsilon != -1e-15:
        raise ValueError('epsilon changed')

    refs = {hex(d): [hex(v) for v in field_refs(data, *RECORD, d)] for d in (0x200, 0x208, 0x210, 0x218)}
    collect_b_callers = direct_calls(data, COLLECT_B)
    btree_callers = direct_calls(data, BTREE_NEXT)
    collect_a_callers = direct_calls(data, COLLECT_A)
    if {frame_of(fdes, v)[0] for v in collect_b_callers} != {SAMPLER_A}:
        raise ValueError('collect caller census changed')
    if {frame_of(fdes, v)[0] for v in btree_callers} != {COLLECT_A, COLLECT_B}:
        raise ValueError('iterator caller census changed')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'day_fields': {
            'reset': '0x1547562 date compare; 0x154756d zero +0x200,+0x208; 0x1547574 zero +0x210',
            '+0x200': 'saturating sum of the count argument (x50 when +0x25c == 1): 0x154770d..0x1547729',
            '+0x208': 'saturating record-call count: 0x1547730..0x154773e; no other read in the record entry',
            '+0x210': 'f64 sum: load 0x1547658, add count*value (mulsd 0x15475fd, addsd 0x1547660), '
                      'store 0x1547758 (the branchy range check between them is not mapped)',
            '+0x218': 'no [rbx+0x218] operand in the record entry',
            'record_entry_rbx_disp32_modrm_sites': refs,
        },
        'window_record': {
            'gate': '0x1547f4b window samples (+0x58) >= 10, else no record',
            'sum': '0x1547f55 load +0x210; 0x1547f72 skip when not finite',
            'count': '0x1547f78 load +0x200',
            'clamp': 'sum in (%r, 0) -> 0 (0x1547f93); count 0 or sum < 0 after that -> no record (0x1547fb0)'
                     % epsilon,
            'mean': '0x1547fdd sum / (f64)count; 0x1547ff6 skip when not finite',
            'to_record': {'count': '0x1547ffc rsp+0x1c8 -> 0x15487e0 rsp+0x128 = record +0x50',
                          'mean': '0x1548004 rsp+0x58 -> 0x15487ee rsp+0x130 = record +0x58',
                          'record': '0x15489b0 lea rdx, [rsp+0xd8]; 0x15489bb call %s' % hex(LINE_WRITE)},
        },
        'json_fields': {name.decode(): {'record_offset': hex(off), 'name_at': hex(va)}
                        for va, name, off in FIELDS},
        'first_sampler_collect': {
            'collect': hex(COLLECT_B),
            'callers': [hex(v) for v in collect_b_callers],
            'caller_function': hex(SAMPLER_A),
            'result': 'only capacity [rsp+0x8] and pointer [rsp+0x10] read, then freed (0x5b29cd4, 0x5b29e1c)',
            'input_modes': 'tag 2 at [rsi]: two runs of 0x20-byte elements; else B-tree iterator %s'
                           % hex(BTREE_NEXT),
            'capacity': 'max(4, hint + 1); grow 0x5963a10 with element size 8, align 8',
        },
        'iterator_callers': [hex(v) for v in btree_callers],
        'second_sampler_collect_callers': [hex(v) for v in collect_a_callers],
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
    print('total_n=+0x50 total_mean=+0x58 collect_b_callers=%d' % len(result['first_sampler_collect']['callers']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
