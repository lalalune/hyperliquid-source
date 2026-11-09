#!/usr/bin/env python3
"""Bind the node #115 observer's per-record value clamps and day/window sums (21st stage).

Continues #5946, which found that the record entry 0x1547530 adds count*value
to the day sum +0x210. This tool binds the code between the product
(mulsd at 0x15475fd) and the window sum store (0x1547898):

1. the count: when the flag +0x25c is 1 the count is multiplied by 50
   (mul at 0x15475c2); on overflow (jo) it becomes u64::MAX (0x1548a0b);
2. the product clamp: the product's bits are classified with the masks
   0x7fffffffffffffff, 0xfff0000000000000 and 0xfffffffffffff and the bound
   0x3ff; the product is kept when it is +-0 or positive finite, otherwise
   (negative, NaN, +-inf) it is replaced by 0.0;
3. the day sums: +0x210 = clamp(+0x210 + product), +0x200 = count added
   with u64 saturation, +0x208 = calls + 1 with u64 saturation; the sum
   clamp keeps +-0 and positive finite values, maps +inf to the constant at
   0x459090 (2^64 as f64), and maps anything else to 0.0;
4. the window: the raw value is pushed to the front of the ring at
   +0x40 (cap), +0x48 (buffer), +0x50 (head), +0x58 (len); the length is cut
   to the limit at +0x1f8; +0x88 = clamp(+0x88 + product), +0x78 = count
   added with u64 saturation, +0x80 = calls + 1 with u64 saturation;
5. the day reset (+0x240 differs from the record date) zeroes +0x200..+0x218
   and the ring head and length;
6. a census of disp32 [reg+0x208] and [reg+0x218] operands (not rsp-based)
   inside the 77 functions that call the record or constructor slot.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import bisect
import json
import math
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-observer-value-range-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

RECORD = 0x1547530
CONSTRUCTOR = 0x1548bb0
RECORD_SLOT = 0x64e1010
CONSTRUCTOR_SLOT = 0x64e1020
SATURATED = 0x459090
TWO_POW_64 = 0x43f0000000000000

FIXED = {
    # day reset
    0x1547562: '39bb40020000',            # cmp [rbx+0x240], edi        (record date)
    0x1547568: '7447',                    # je 0x15475b1                (same day)
    0x154756d: '0f118300020000',          # movups [rbx+0x200], 0       (+0x200, +0x208)
    0x1547574: '48c7831002000000000000',  # mov qword [rbx+0x210], 0
    0x1547586: '48c7435800000000',        # mov qword [rbx+0x58], 0     (ring len)
    0x154758e: '48c7435000000000',        # mov qword [rbx+0x50], 0     (ring head)
    # count x50, saturating
    0x15475b1: '80bb5c02000001',          # cmp byte [rbx+0x25c], 1
    0x15475ba: 'b932000000',              # mov ecx, 50
    0x15475c2: '48f7e1',                  # mul rcx
    0x15475cb: '0f803a140000',            # jo 0x1548a0b
    0x1548a0b: '49c7c6ffffffff',          # mov r14, -1                 (u64::MAX)
    0x1548a12: 'e9c5ebffff',              # jmp 0x15475dc
    0x15475fd: 'f20f59e3',                # mulsd xmm4, xmm3            (count * value)
    # product classification
    0x1547606: '49b8ffffffffffffff7f',    # movabs r8, 0x7fffffffffffffff
    0x1547616: '49bf000000000000f0ff',    # movabs r15, 0xfff0000000000000
    0x1547620: '4a8d1438',                # lea rdx, [rax+r15]
    0x1547624: '48c1ea35',                # shr rdx, 53
    0x154762c: '4885c9',                  # test rcx, rcx               (sign)
    0x154762f: '7974',                    # jns 0x15476a5
    0x1547634: '81faff030000',            # cmp edx, 0x3ff              (normal)
    0x154763c: '49bdffffffffffff0f00',    # movabs r13, 0xfffffffffffff
    0x154764a: '4c39e9',                  # cmp rcx, r13                (subnormal)
    0x154764f: '4885c0',                  # test rax, rax               (zero)
    0x1547652: '7404',                    # je 0x1547658                (keep +-0)
    0x1547654: '660f28e1',                # movapd xmm4, xmm1
    0x15476cb: '660f28c8',                # movapd xmm1, xmm0           (0.0 or kept)
    # day value sum
    0x1547658: 'f20f108310020000',        # movsd xmm0, [rbx+0x210]
    0x1547660: 'f20f58c4',                # addsd xmm0, xmm4
    0x1547705: 'f20f100d8319f1fe',        # movsd xmm1, [0x459090]      (2^64)
    0x1547745: '48b9000000000000f07f',    # movabs rcx, 0x7ff0000000000000
    0x154774f: '4839c8',                  # cmp rax, rcx                (+-inf)
    0x1547752: '7404',                    # je 0x1547758                (keep 2^64 or 0)
    0x1547754: '660f28c8',                # movapd xmm1, xmm0
    0x1547758: 'f20f118b10020000',        # movsd [rbx+0x210], xmm1
    # day count and calls, saturating
    0x154770d: '488b8b00020000',          # mov rcx, [rbx+0x200]
    0x1547714: '4c01f1',                  # add rcx, r14
    0x1547721: '480f42f2',                # cmovb rsi, rdx              (carry -> u64::MAX)
    0x1547729: '4889b300020000',          # mov [rbx+0x200], rsi
    0x1547730: '488b8b08020000',          # mov rcx, [rbx+0x208]
    0x1547737: '48ffc1',                  # inc rcx
    0x154773a: '480f44ca',                # cmove rcx, rdx              (wrap -> u64::MAX)
    0x154773e: '48898b08020000',          # mov [rbx+0x208], rcx
    # window ring push and sums
    0x15477b7: '48894350',                # mov [rbx+0x50], rax         (head)
    0x15477be: '48894b58',                # mov [rbx+0x58], rcx         (len + 1)
    0x15477c2: 'f20f111cc2',              # movsd [rdx+rax*8], xmm3     (raw value)
    0x15477c7: '4c396358',                # cmp [rbx+0x58], r12         (limit +0x1f8)
    0x15477cd: '4c896358',                # mov [rbx+0x58], r12
    0x15477d1: 'f20f58a388000000',        # addsd xmm4, [rbx+0x88]
    0x154784a: 'f20f10053e18f1fe',        # movsd xmm0, [0x459090]
    0x1547852: '4c037378',                # add r14, [rbx+0x78]
    0x1547860: '480f42d1',                # cmovb rdx, rcx
    0x1547868: '48895378',                # mov [rbx+0x78], rdx
    0x1547870: '488b9380000000',          # mov rdx, [rbx+0x80]
    0x1547877: '48ffc2',                  # inc rdx
    0x154787a: '480f44d1',                # cmove rdx, rcx
    0x154787e: '48899380000000',          # mov [rbx+0x80], rdx
    0x1547885: '48b9000000000000f07f',    # movabs rcx, 0x7ff0000000000000
    0x1547898: 'f20f118388000000',        # movsd [rbx+0x88], xmm0
    # constructor: +0x218 is the scaled first guard constant (#5865)
    0x1548dd2: 'f2410f118618020000',      # movsd [r14+0x218], xmm0
    # census spot checks
    0x15ed69c: '488dbb08020000',          # lea rdi, [rbx+0x208]
    0x15ed6a3: '80bb0002000000',          # cmp byte [rbx+0x200], 0
    0x422acd0: '488bb808020000',          # mov rdi, [rax+0x208]
    0x422acde: '488b9018020000',          # mov rdx, [rax+0x218]
    0x422acec: '48c7800802000000000000',  # mov qword [rax+0x208], 0
    0x422acf7: '48c7801002000008000000',  # mov qword [rax+0x210], 8
}
RIP_REFS = ((0x1547705, 4, 8, SATURATED), (0x154784a, 4, 8, SATURATED))


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return data[off:off + size]


def text(data):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    return sec['address'], data[sec['offset']:sec['offset'] + sec['size']]


def slot_calls(data, slot):
    base, code = text(data)
    return [base + m.start() for m in re.finditer(rb'\xff\x15', code)
            if base + m.start() + 6 + struct.unpack_from('<i', code, m.start() + 2)[0] == slot]


def framer(fdes):
    ordered = sorted(fdes, key=lambda f: f['start'])
    starts = [f['start'] for f in ordered]

    def frame(va):
        i = bisect.bisect_right(starts, va) - 1
        if i < 0 or not ordered[i]['start'] <= va < ordered[i]['end']:
            raise ValueError(f'{va:#x} has no FDE')
        return ordered[i]['start']
    return frame


def disp32_operands(data, disp):
    """[reg+disp32] ModRM operands (mod=10) whose base is not rsp; returns ModRM addresses."""
    base, code = text(data)
    out = []
    for m in re.finditer(re.escape(struct.pack('<i', disp)), code):
        i = m.start()
        if i >= 1 and code[i - 1] >> 6 == 2 and code[i - 1] & 7 != 4:
            out.append(base + i - 1)
        elif i >= 2 and code[i - 2] >> 6 == 2 and code[i - 2] & 7 == 4 and code[i - 1] & 7 != 4:
            out.append(base + i - 2)
    return out


def bits(x):
    return struct.unpack('<Q', struct.pack('<d', x))[0]


def keep_product(x):
    """Product clamp traced from 0x1547601..0x1547658: keep +-0 and positive finite, else 0.0."""
    b = bits(x)
    if b & 0x7fffffffffffffff == 0:
        return x
    return x if b >> 63 == 0 and math.isfinite(x) else 0.0


def clamp_sum(x):
    """Sum clamp traced from 0x1547664..0x1547758: +inf -> 2^64, negative/NaN/-inf -> 0.0."""
    if x == math.inf:
        return struct.unpack('<d', struct.pack('<Q', TWO_POW_64))[0]
    return keep_product(x)


def bind(data, fdes):
    for va, expect in FIXED.items():
        if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
            raise ValueError(f'instruction at {va:#x} changed')
    for va, prefix_len, length, target in RIP_REFS:
        raw = read_va(data, va, length)
        if va + length + struct.unpack_from('<i', raw, prefix_len)[0] != target:
            raise ValueError(f'reference at {va:#x} changed')
    if struct.unpack('<Q', read_va(data, SATURATED, 8))[0] != TWO_POW_64:
        raise ValueError('saturation constant changed')

    frame = framer(fdes)
    record_calls = slot_calls(data, RECORD_SLOT)
    ctor_calls = slot_calls(data, CONSTRUCTOR_SLOT)
    owners = {frame(v) for v in record_calls + ctor_calls} | {RECORD, CONSTRUCTOR}
    census = {}
    for disp in (0x208, 0x218):
        sites = disp32_operands(data, disp)
        census[hex(disp)] = {
            'text_wide_non_rsp': len(sites),
            'in_owner_functions': [[hex(v), hex(frame(v))] for v in sites if frame(v) in owners],
        }

    two64 = struct.unpack('<d', struct.pack('<Q', TWO_POW_64))[0]
    samples = {'1.5': 1.5, '0.0': 0.0, '-0.0': -0.0, '5e-324': 5e-324, '1e308': 1e308,
               '-2.0': -2.0, '-5e-324': -5e-324, 'inf': math.inf, '-inf': -math.inf, 'nan': math.nan}
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'count': {
            'x50': hex(0x15475b1) + ' flag +0x25c == 1 -> mul by 50 at ' + hex(0x15475c2),
            'overflow': hex(0x15475cb) + ' jo -> ' + hex(0x1548a0b) + ' count = u64::MAX',
        },
        'product_clamp': {
            'span': [hex(0x1547601), hex(0x1547658)],
            'masks': ['0x7fffffffffffffff', '0xfff0000000000000', '0xfffffffffffff', 'normal bound 0x3ff'],
            'rule': 'keep +-0 and positive finite; negative, NaN and +-inf become 0.0',
            'samples': {k: repr(keep_product(v)) for k, v in samples.items()},
        },
        'sum_clamp': {
            'saturation_constant': '%s = %s (%r)' % (hex(SATURATED), hex(TWO_POW_64), two64),
            'rule': 'keep +-0 and positive finite; +inf becomes 2^64; negative, NaN and -inf become 0.0',
            'samples': {k: repr(clamp_sum(v)) for k, v in samples.items()},
        },
        'day': {
            'reset': hex(0x1547562) + ' date +0x240 differs -> +0x200..+0x218 = 0, ring +0x50/+0x58 = 0',
            '+0x200': 'count, u64 saturating add (' + hex(0x1547721) + ')',
            '+0x208': 'calls + 1, u64 saturating (' + hex(0x154773a) + ')',
            '+0x210': 'clamp_sum(+0x210 + product) (' + hex(0x1547758) + ')',
        },
        'window': {
            'ring': '+0x40 cap, +0x48 buffer, +0x50 head, +0x58 len; raw value pushed at '
                    + hex(0x15477c2) + '; len cut to +0x1f8 at ' + hex(0x15477cd),
            '+0x78': 'count, u64 saturating add (' + hex(0x1547860) + ')',
            '+0x80': 'calls + 1, u64 saturating (' + hex(0x154787a) + ')',
            '+0x88': 'clamp_sum(+0x88 + product) (' + hex(0x1547898) + ')',
        },
        'plus_0x218_store': hex(0x1548dd2) + ' constructor movsd [r14+0x218] (scaled first guard constant, #5865)',
        'census': {
            'owner_functions': len(owners),
            'record_slot_calls': len(record_calls),
            'constructor_slot_calls': len(ctor_calls),
            'operands': census,
            'spot_checks': {
                hex(0x15ed69c): 'byte flag at +0x200 and a pointer at +0x208: not the observer layout',
                hex(0x422acd0): '+0x208..+0x220 read, then +0x208 = 0 and +0x210 = 8: not the observer layout',
            },
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
    c = result['census']['operands']
    print(f"owners={result['census']['owner_functions']} "
          f"plus208={len(c['0x208']['in_owner_functions'])} plus218={len(c['0x218']['in_owner_functions'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
