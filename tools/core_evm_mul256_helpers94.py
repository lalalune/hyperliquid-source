#!/usr/bin/env python3
"""RE-004: the two 256-bit multiply helpers behind the core-to-EVM scaling
loop in node #94 (static).

The #158 packet mapped the non-negative scaling loop at call-site level:
three handler copies (0x2715320, 0x4d0a6d0, 0x4d0bfa0) each call a
256-bit multiply helper and fold its overflow signal into the loop flag.
#158 left the helpers' inner schoolbook loops undecod­ed. This packet
maps those inner loops, and finds the two helpers do NOT agree on the
overflow signal:

    helper-1 0x27a1150 (copy-1): (out, a, b) with out 33 bytes; the
        overflow byte at out+0x20 is CONSERVATIVE, not exact. It fires
        whenever the outer (smaller-operand) loop runs a second
        iteration, whenever the b operand has a low zero limb, when
        carry propagates past the accumulator, or when r11 == 0 at
        multiply entry. In particular every multi-limb multiply reports
        overflow even when the product fits. Sound (flag 0 implies the
        product fits) but inexact (flag 1 does not imply overflow).
    helper-2 0x4de5500 (copies 2/3): (out, count, a, b) with the flag
        returned in al; the flag is EXACT. The difference is one
        trim: helper-2's a high-trim reduces the count to the true
        significant count, so the r11 < r12 test reduces exactly to
        true overflow; helper-1's a high-trim leaves the count at
        4 - a_skip, so the same test fires on the second outer
        iteration for any multi-limb input.

Both helpers return the product mod 2^256 correctly for every in-scope
input (the L2 window truncation only ever drops limbs that land at
out[4] or beyond, i.e. genuine overflow limbs). Helper-2 additionally
leaves out[0..shift] untouched, so its callers must zero the out
prefix; the copy-2/3 scaling handlers do (movdqa zero idiom directly
before the call, verified at 0x4d0abfb).

Consequence for #158's model, stated here as an inference from these
helpers' semantics, not as a re-verification of #158: copy-1's loop
folds helper-1's byte, so copy-1 takes the fallback whenever any
acc x base or base x base step is multi-limb -- the first such step
is the k=5 square (base = 10^32, two limbs), so copy-1's success path
covers d <= 31, not d <= 77. Copies 2/3 fold helper-2's exact al, so
their success path keeps #158's d <= 77. The three copies therefore
diverge for d in [32, 77]: copy-1 takes the #159 float fallback while
copies 2/3 return the exact power of ten.

This tool never executes the node and never calls a disassembler. It
verifies the target SHA-256, reads FDE bounds from the binary's own
unwind index via the repository shared ELF parser, checks anchor byte
strings at fixed virtual addresses (trim entries, outer heads, flag
paths, L1/L2 pair loops, imul tails, carry propagation, epilogues,
panic blocks, caller zeroing), verifies the GOT relocation for the
shared panic callee, re-derives the 14-site caller census by scanning
.text for E8 rel32 targets, transcribes the helper windows, and
computes the case table from faithful block-level models of both
helpers plus closed-form 256-bit arithmetic. It writes only to the
directory given by --out.

    python3 tools/core_evm_mul256_helpers94.py --out <dir>
    python3 tools/core_evm_mul256_helpers94.py --out <dir> --binary <path>

--allow-digest-mismatch is test-only: it lets the tamper controls prove
the anchor checks fail on their own, instead of failing at the digest
check. Production runs must never use it.

writes evidence.json, sites.tsv, loop_cases.tsv and windows.txt.
Only the Python standard library is used.
"""

import argparse
import csv
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import elf_index  # noqa: E402  (repository shared ELF section parser)

DEFAULT_BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
M64 = (1 << 64) - 1

H1 = 0x27A1150
H2 = 0x4DE5500
PANIC_CALLEE = 0x157A6F0
PANIC_GOT = 0x576E2E0

# Anchor byte strings, verified against the binary. Each entry is
# (virtual address, hex bytes). The tamper controls flip one byte of
# each anchor class and must make this tool fail.
ANCHORS = [
    # helper-1 prologue: pushes + sub rsp,0x58 + mov rcx,rdx
    (0x27A1150, "554157415641554154534883ec58"),
    # helper-1 accumulator zero + a[0] check + je
    (0x27A1161, "0f57c00f294424200f2944241048833e00741a"),
    # helper-1 outer head through cmp r11,r12; jae +0x30 -> L1 0x27a13e0
    (0x27A138F, "4889e848c1e8034939c3490f42c34883f8014989c64983d600488b314d39e37330"),
    # helper-1 flag path: mov dl,1; mov [rsp],rdx
    (0x27A13B9, "b20148891424"),
    # helper-1 L1 pair loop: mov rax,rsi; mul [r15+rdi*8]; mov r9,rdx; add rax,r8
    (0x27A1400, "4889f049f724ff4989d14c01"),
    # helper-1 L2 pair loop: mov rax,rsi; mul [r15+r12*8]; mov r9,rdx; add rax,r8
    (0x27A14D0, "4889f04bf724e74989d14c01"),
    # helper-1 imul tail: imul rsi,[r15+rdx*8]; add rsi,r8; add [r10+rdx*8],rsi
    (0x27A151B, "490faf34d74c01c6490134d2"),
    # helper-1 carry test + carry add
    (0x27A145E, "4d85c0"),
    (0x27A146A, "4f0104e2"),
    # helper-1 epilogue: mov rax,[rsp]; and al,1
    (0x27A156E, "488b04242401"),
    # helper-1 panic block: lea rcx,[0x56c23d0]; mov edi,1; xor esi,esi; xor edx,edx
    (0x27A1537, "488d0d920ef202bf0100000031f631d2"),
    # helper-1 panic call: call [rip+disp] -> GOT 0x576e2e0
    (0x27A1547, "ff1593cdfc02"),
    # helper-2 prologue: pushes + sub rsp,0x28
    (0x4DE5500, "554157415641554154534883ec28"),
    # helper-2 a[0] check + je + mov r9d,4 + xor eax,eax + mov r8b,1
    (0x4DE550E, "48833a00741841b90400000031c041b0"),
    # helper-2 outer head through cmp r11,r12; jae +0x2f -> L1 0x4de5770
    (0x4DE5720, "4c89ea48c1ea034939d3490f42d34883fa014989d64983d600488b394d39e3732f"),
    # helper-2 flag path: mov al,1
    (0x4DE574A, "b001"),
    # helper-2 L1 pair loop: mov rax,rdi; mul [r15+r14*8]; mov r9,rdx; add rax,r8
    (0x4DE57A0, "4889f84bf724f74989d14c01"),
    # helper-2 L2 pair loop: mov rax,rdi; mul [r15+rsi*8]; mov r9,rdx; add rax,r8
    (0x4DE5870, "4889f849f724f74989d14c01"),
    # helper-2 imul tail: imul rdi,[r15+rdx*8]; add rdi,r8; add [r10+rdx*8],rdi
    (0x4DE58BA, "490faf3cd74c01c749013cd2"),
    # helper-2 carry test + carry add
    (0x4DE57FE, "4d85c0"),
    (0x4DE580B, "4f0104e2"),
    # helper-2 epilogue: and al,1
    (0x4DE55FD, "2401"),
    # helper-2 panic block: lea rcx,[0x5746f10]; mov edi,1; xor esi,esi; xor edx,edx
    (0x4DE58D6, "488d0d33169600bf0100000031f631d2"),
    # helper-2 panic call: call [rip+disp] -> GOT 0x576e2e0
    (0x4DE58E6, "ff15f4899800"),
    # copy-2 caller zeroing before the acc call: movdqa [rsp+0x120],xmm2;
    # movdqa [rsp+0x110],xmm2 (out buffer zeroed before helper-2 call)
    (0x4D0ABD6, "660f7f942420010000660f7f942410010000"),
]

# Caller census, re-derived by the tool from an E8 scan (not trusted
# blindly: the tool recomputes it and fails on any difference).
# (call site, enclosing FDE start, enclosing FDE trilogy end, helper, role)
CENSUS = [
    (0x2715834, 0x2715320, 0x2716BC0, "helper-1", "scaling"),
    (0x271589B, 0x2715320, 0x2716BC0, "helper-1", "scaling"),
    (0x27159E0, 0x2715320, 0x2716BC0, "helper-1", "scaling"),
    (0x279D1FC, 0x279D0C0, 0x279D3E0, "helper-1", "other"),
    (0x279D2AB, 0x279D0C0, 0x279D3E0, "helper-1", "other"),
    (0x279D51A, 0x279D3E0, 0x279D5E0, "helper-1", "other"),
    (0x4C90193, 0x4C900A0, 0x4C901E0, "helper-2", "other"),
    (0x4C994FF, 0x4C99440, 0x4C995C0, "helper-2", "other"),
    (0x4D0ABFB, 0x4D0A6D0, 0x4D0BFA0, "helper-2", "scaling"),
    (0x4D0AC78, 0x4D0A6D0, 0x4D0BFA0, "helper-2", "scaling"),
    (0x4D0ADD6, 0x4D0A6D0, 0x4D0BFA0, "helper-2", "scaling"),
    (0x4D0C4CB, 0x4D0BFA0, 0x4D0D870, "helper-2", "scaling"),
    (0x4D0C548, 0x4D0BFA0, 0x4D0D870, "helper-2", "scaling"),
    (0x4D0C6A6, 0x4D0BFA0, 0x4D0D870, "helper-2", "scaling"),
]

# Case grid: (case_id, a limbs, b limbs, out_init for helper-2).
# Helper-1 always writes the full 33-byte out from its zeroed stack
# accumulator, so it has no out_init parameter.
CASES = [
    ("single_limb", [5, 0, 0, 0], [7, 0, 0, 0], [0, 0, 0, 0]),
    ("b_low_zero", [5, 0, 0, 0], [0, 7, 0, 0], [0, 0, 0, 0]),
    ("a_zero", [0, 0, 0, 0], [1, 2, 3, 4], [0, 0, 0, 0]),
    ("b_zero", [1, 2, 3, 4], [0, 0, 0, 0], [0, 0, 0, 0]),
    ("one_times_one", [1, 0, 0, 0], [1, 0, 0, 0], [0, 0, 0, 0]),
    ("max_times_two", [M64, M64, M64, M64], [2, 0, 0, 0], [0, 0, 0, 0]),
    ("limb_max_squared", [M64, 0, 0, 0], [M64, 0, 0, 0], [0, 0, 0, 0]),
    ("two_limb_fit", [1, 2, 0, 0], [3, 4, 0, 0], [0, 0, 0, 0]),
    ("single_limb_pair", [2, 0, 0, 0], [3, 0, 0, 0], [0, 0, 0, 0]),
    ("square_1p64", [1, 1, 0, 0], [1, 1, 0, 0], [0, 0, 0, 0]),
    ("four_limb_overflow", [1, 2, 3, 4], [5, 6, 7, 8], [0, 0, 0, 0]),
    ("pow10_32_square", [9632337040368467968, 5421010862427, 0, 0],
     [9632337040368467968, 5421010862427, 0, 0], [0, 0, 0, 0]),
    ("one_times_pow10_32", [1, 0, 0, 0],
     [9632337040368467968, 5421010862427, 0, 0], [0, 0, 0, 0]),
    ("both_low_zero", [0, 5, 0, 0], [0, 7, 0, 0], [0, 0, 0, 0]),
    ("top_limb_product", [0, 0, 5, 0], [0, 0, 7, 0], [0, 0, 0, 0]),
    ("pow2_128_squared", [0, 0, 1, 0], [0, 0, 1, 0], [0, 0, 0, 0]),
    ("pow2_128_times_pow2_127", [0, 0, 1, 0], [0, 0x8000000000000000, 0, 0],
     [0, 0, 0, 0]),
    ("internal_zero_fit", [1, 0, 0, 0], [1, 0, 1, 0], [0, 0, 0, 0]),
    ("max_single_limb_pair", [M64, M64, 0, 0], [1, 1, 0, 0], [0, 0, 0, 0]),
    ("prefix_untouched", [0, 5, 0, 0], [7, 0, 0, 0], [99, 0, 0, 0]),
    ("prefix_untouched2", [0, 5, 0, 0], [7, 0, 0, 0], [7, 8, 9, 10]),
]


class Panic(Exception):
    pass


def sim_helper1(a_limbs, b_limbs):
    """Faithful block-level model of 0x27a1150. Returns (out, flag_byte)."""
    a = list(a_limbs)
    b = list(b_limbs)
    acc = [0, 0, 0, 0]
    # a low-trim: r15 = 4 - a_skip; r10 = acc + a_skip
    a_skip = 0
    while a_skip < 4 and a[a_skip] == 0:
        a_skip += 1
    if a_skip == 4:
        return (acc, 0)  # a == 0: variant B, dl == 1 -> epilogue al = 0
    a_idx = a_skip
    acc_idx = a_skip
    r15 = 4 - a_skip
    # a high-trim: sets dl only, never reduces r15 (the helper-1 asymmetry)
    dl = 0 if any(v != 0 for v in a) else 1
    # b low-trim: r11 = r15 - b_skip; acc_idx += b_skip
    b_skip = 0
    while b_skip < 4 and b[b_skip] == 0:
        b_skip += 1
    if b_skip == 4:
        # b == 0: the b high-trim loop exits with rbx == 1. If r11 is
        # also 0 the multiply entry short-circuits to flag 1; if r11
        # wraps (a_skip + b_skip > 4) the real code reads past the b
        # array, which is out of scope (see limitations).
        b_idx = 4
        acc_idx += 4
        r11 = r15 - 4
        if r11 < 0:
            raise ValueError("b == 0 with a low skip is out of scope")
        b_sig = 1
    else:
        b_idx = b_skip
        acc_idx += b_skip
        r11 = r15 - b_skip
        if r11 < 0:
            raise ValueError("a_skip + b_skip > 4 is out of scope")
        trimmed_b = b[b_idx:]
        b_sig = 0
        for i, v in enumerate(trimmed_b):
            if v != 0:
                b_sig = i + 1
    if dl & 1:
        return (acc, 0)
    if r11 == 0:
        return (acc, 1)
    rax = r15
    rbx = b_sig
    if rbx <= rax:
        r12 = rax
        inner_ptr, inner_is_a = a_idx, True
        outer_ptr, outer_count = b_idx, rbx
    else:
        r12 = rbx
        inner_ptr, inner_is_a = b_idx, False
        outer_ptr, outer_count = a_idx, rax
    outer_end = outer_ptr + outer_count
    rbx_max = max(rax, rbx)
    r13 = rbx_max & ~1
    flag = 0
    cur_outer, cur_acc, cur_r11, cur_rbp = outer_ptr, acc_idx, r11, r11
    while True:
        rax2 = cur_rbp if cur_rbp < cur_r11 else cur_r11
        r14b = rax2 + (1 if rax2 == 0 else 0)
        outer_limb = (b[cur_outer] if inner_is_a else a[cur_outer]) \
            if cur_outer < 4 else 0
        if cur_r11 >= r12:
            # L1: full-width pair loop + odd tail + carry propagation
            r8 = 0
            rdi = 0
            inner = inner_ptr
            while rdi < r13:
                for off in (0, 1):
                    idx = inner + rdi + off
                    limb = (a[idx] if inner_is_a else b[idx]) if idx < 4 else 0
                    prod = outer_limb * limb
                    s = (prod & M64) + r8
                    r8 = (prod >> 64) + (1 if s > M64 else 0)
                    s &= M64
                    pos = cur_acc + rdi + off
                    if 0 <= pos < 4:
                        ns = acc[pos] + s
                        r8 += 1 if ns > M64 else 0
                        acc[pos] = ns & M64
                rdi += 2
            if rbx_max & 1:
                idx = inner + rdi
                limb = (a[idx] if inner_is_a else b[idx]) if idx < 4 else 0
                prod = outer_limb * limb
                s = (prod & M64) + r8
                r8 = (prod >> 64) + (1 if s > M64 else 0)
                s &= M64
                pos = cur_acc + rdi
                if 0 <= pos < 4:
                    ns = acc[pos] + s
                    r8 += 1 if ns > M64 else 0
                    acc[pos] = ns & M64
            if r8 != 0:
                al = 1
                if cur_r11 != r12:
                    pos = cur_acc + r12
                    c = r8
                    p = pos
                    while c != 0 and p < 4:
                        ns = acc[p] + c
                        c = 1 if ns > M64 else 0
                        acc[p] = ns & M64
                        p += 1
                    al = 0 if c == 0 else 1
                flag |= al
        else:
            # flag path: flag = 1, then L2 windowed loop + imul tail
            if cur_r11 == 0:
                return (acc, 1)
            flag |= 1
            if cur_acc == acc_idx + r11:
                # r10 == acc_end: skip inner loop, advance only
                pass
            else:
                r8 = 0
                win = rax2 & ~1
                rdi = 0
                inner = inner_ptr
                while rdi < win:
                    for off in (0, 1):
                        idx = inner + rdi + off
                        limb = (a[idx] if inner_is_a else b[idx]) if idx < 4 else 0
                        prod = outer_limb * limb
                        s = (prod & M64) + r8
                        r8 = (prod >> 64) + (1 if s > M64 else 0)
                        s &= M64
                        pos = cur_acc + rdi + off
                        if 0 <= pos < 4:
                            ns = acc[pos] + s
                            r8 += 1 if ns > M64 else 0
                            acc[pos] = ns & M64
                    rdi += 2
                if r14b & 1:
                    idx = inner + rdi
                    limb = (a[idx] if inner_is_a else b[idx]) if idx < 4 else 0
                    s = ((outer_limb * limb) & M64) + r8
                    s &= M64
                    pos = cur_acc + rdi
                    if 0 <= pos < 4:
                        ns = acc[pos] + s
                        acc[pos] = ns & M64
        cur_outer += 1
        cur_r11 -= 1
        cur_acc += 1
        cur_rbp -= 1
        if cur_outer == outer_end:
            break
        if cur_r11 == 0:
            raise Panic("r11==0 with outer limbs remaining")
    return (acc, flag & 1)


def sim_helper2(out_init, count, a_limbs, b_limbs):
    """Faithful block-level model of 0x4de5500. Returns (out, al)."""
    out = list(out_init)
    a = list(a_limbs)
    b = list(b_limbs)
    a_skip = 0
    while a_skip < 4 and a[a_skip] == 0:
        a_skip += 1
    if a_skip == 4:
        return (out, 0)  # a == 0: return 0, out untouched
    a_idx = a_skip
    out_idx = a_skip
    count2 = count - a_skip
    trimmed_a = a[a_idx:]
    a_sig = 0
    for i, v in enumerate(trimmed_a):
        if v != 0:
            a_sig = i + 1
    b_skip = 0
    while b_skip < 4 and b[b_skip] == 0:
        b_skip += 1
    if b_skip == 4:
        return (out, 0)  # b == 0: return 0, out untouched
    b_idx = b_skip
    out_idx += b_skip
    r11 = count2 - b_skip
    if r11 < 0:
        raise ValueError("a_skip + b_skip > 4 is out of scope")
    trimmed_b = b[b_idx:]
    b_sig = 0
    for i, v in enumerate(trimmed_b):
        if v != 0:
            b_sig = i + 1
    if r11 == 0:
        return (out, 1)
    rax, rbx = a_sig, b_sig
    if rbx <= rax:
        r12 = rax
        inner_ptr, inner_is_a = a_idx, True
        outer_ptr, outer_count = b_idx, rbx
    else:
        r12 = rbx
        inner_ptr, inner_is_a = b_idx, False
        outer_ptr, outer_count = a_idx, rax
    outer_end = outer_ptr + outer_count
    acc_end = out_idx + r11
    rbx_max = max(rax, rbx)
    rbp = rbx_max & ~1
    al = 0
    cur_outer, cur_out, cur_r11, cur_rbp = outer_ptr, out_idx, r11, r11
    while True:
        rdx2 = cur_rbp if cur_rbp < cur_r11 else cur_r11
        r14 = rdx2 + (1 if rdx2 == 0 else 0)
        outer_limb = (b[cur_outer] if inner_is_a else a[cur_outer]) \
            if cur_outer < 4 else 0
        if cur_r11 >= r12:
            r8 = 0
            rdi = 0
            inner = inner_ptr
            while rdi < rbp:
                for off in (0, 1):
                    idx = inner + rdi + off
                    limb = (a[idx] if inner_is_a else b[idx]) if idx < 4 else 0
                    prod = outer_limb * limb
                    s = (prod & M64) + r8
                    r8 = (prod >> 64) + (1 if s > M64 else 0)
                    s &= M64
                    pos = cur_out + rdi + off
                    if 0 <= pos < 4:
                        ns = out[pos] + s
                        r8 += 1 if ns > M64 else 0
                        out[pos] = ns & M64
                rdi += 2
            if rbx_max & 1:
                idx = inner + rdi
                limb = (a[idx] if inner_is_a else b[idx]) if idx < 4 else 0
                prod = outer_limb * limb
                s = (prod & M64) + r8
                r8 = (prod >> 64) + (1 if s > M64 else 0)
                s &= M64
                pos = cur_out + rdi
                if 0 <= pos < 4:
                    ns = out[pos] + s
                    r8 += 1 if ns > M64 else 0
                    out[pos] = ns & M64
            sil = 0
            if r8 != 0:
                sil = 1
                if cur_r11 != r12:
                    c = r8
                    p = cur_out + r12
                    while c != 0 and p < 4:
                        ns = out[p] + c
                        c = 1 if ns > M64 else 0
                        out[p] = ns & M64
                        p += 1
                    sil = 0 if c == 0 else 1
            al |= sil
        else:
            if cur_r11 == 0:
                return (out, 1)
            al = 1
            if cur_out != acc_end:
                r8 = 0
                win = r14 & 0x1FFFFFFFFFFFFFFE
                rdi = 0
                inner = inner_ptr
                while rdi < win:
                    for off in (0, 1):
                        idx = inner + rdi + off
                        limb = (a[idx] if inner_is_a else b[idx]) if idx < 4 else 0
                        prod = outer_limb * limb
                        s = (prod & M64) + r8
                        r8 = (prod >> 64) + (1 if s > M64 else 0)
                        s &= M64
                        pos = cur_out + rdi + off
                        if 0 <= pos < 4:
                            ns = out[pos] + s
                            r8 += 1 if ns > M64 else 0
                            out[pos] = ns & M64
                    rdi += 2
                if r14 & 1:
                    idx = inner + rdi
                    limb = (a[idx] if inner_is_a else b[idx]) if idx < 4 else 0
                    s = ((outer_limb * limb) & M64) + r8
                    s &= M64
                    pos = cur_out + rdi
                    if 0 <= pos < 4:
                        ns = out[pos] + s
                        out[pos] = ns & M64
        cur_outer += 1
        cur_r11 -= 1
        cur_out += 1
        cur_rbp -= 1
        if cur_outer == outer_end:
            break
        if cur_r11 == 0:
            raise Panic("r11==0 with outer limbs remaining")
    return (out, al & 1)


def closed(a, b):
    A = sum(v << (64 * i) for i, v in enumerate(a))
    B = sum(v << (64 * i) for i, v in enumerate(b))
    P = A * B
    return ([(P >> (64 * i)) & M64 for i in range(4)], 1 if P >= (1 << 256) else 0)


def va_to_offset(sections, va):
    for s in sections:
        if s["type"] == 8:
            continue
        if s["address"] <= va < s["address"] + s["size"]:
            return s["offset"] + (va - s["address"])
    raise ValueError(f"VA {va:#x} has no file mapping")


def read_bytes(data, sections, va, length):
    off = va_to_offset(sections, va)
    return data[off:off + length]


def check_anchor(data, sections, va, hex_bytes):
    want = bytes.fromhex(hex_bytes)
    got = read_bytes(data, sections, va, len(want))
    if got != want:
        raise ValueError(f"anchor mismatch at {va:#x}: got {got.hex()}, want {hex_bytes}")


def check_call_target(data, sections, call_va, want_got):
    raw = read_bytes(data, sections, call_va, 6)
    if raw[0] != 0xFF or raw[1] != 0x15:
        raise ValueError(f"not an indirect call at {call_va:#x}: {raw.hex()}")
    disp = struct.unpack_from("<i", raw, 2)[0]
    got = call_va + 6 + disp
    if got != want_got:
        raise ValueError(f"call at {call_va:#x} targets GOT {got:#x}, want {want_got:#x}")


def check_relocation(data, sections, got_va, want_addend):
    rela = next(s for s in sections if s["name"] == ".rela.dyn")
    for i in range(rela["size"] // 24):
        off, info, add = struct.unpack_from("<QQq", data, rela["offset"] + i * 24)
        if off == got_va:
            if (info & 0xFFFFFFFF) != 8 or add != want_addend:
                raise ValueError(f"relocation at {got_va:#x}: type {info & 0xffffffff}, addend {add:#x}")
            return
    raise ValueError(f"no relocation for GOT {got_va:#x}")


def derive_census(data, sections, entries):
    text = next(s for s in sections if s["name"] == ".text")
    base, off, size = text["address"], text["offset"], text["size"]
    starts = [e["start"] for e in entries]
    import bisect
    found = {}
    for target in (H1, H2):
        sites = []
        for i in range(size - 5):
            if data[off + i] == 0xE8:
                rel = struct.unpack_from("<i", data, off + i + 1)[0]
                if base + i + 5 + rel == target:
                    sites.append(base + i)
        found[target] = sites
    rows = []
    for site, fde_start, fde_end, helper, role in CENSUS:
        target = H1 if helper == "helper-1" else H2
        if site not in found[target]:
            raise ValueError(f"census site {site:#x} not found by E8 scan")
        j = bisect.bisect_right(starts, site) - 1
        e = entries[j]
        if e["start"] != fde_start or e["next_index_upper_bound"] != fde_end:
            raise ValueError(f"enclosing FDE mismatch for {site:#x}")
        rows.append((site, fde_start, fde_end, helper, role))
    for target in (H1, H2):
        want = sorted(s for s, _, _, h, _ in CENSUS if (H1 if h == "helper-1" else H2) == target)
        if sorted(found[target]) != want:
            raise ValueError(f"E8 scan found extra/missing sites for {target:#x}")
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    p.add_argument("--allow-digest-mismatch", action="store_true")
    args = p.parse_args()
    data = args.binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256 and not args.allow_digest_mismatch:
        raise ValueError(f"node digest mismatch: {digest}")
    sections, entries = elf_index.unwind_index(data)
    starts = {e["start"]: e for e in entries}
    for addr, label in ((H1, "helper-1"), (H2, "helper-2"), (PANIC_CALLEE, "panic callee")):
        if addr not in starts:
            raise ValueError(f"{label} {addr:#x} is not an unwind start")
    fde = {addr: (starts[addr]["start"], starts[addr]["next_index_upper_bound"])
           for addr in (H1, H2, PANIC_CALLEE)}
    for va, hex_bytes in ANCHORS:
        check_anchor(data, sections, va, hex_bytes)
    check_call_target(data, sections, 0x27A1547, PANIC_GOT)
    check_call_target(data, sections, 0x4DE58E6, PANIC_GOT)
    check_relocation(data, sections, PANIC_GOT, PANIC_CALLEE)
    census = derive_census(data, sections, entries)
    # windows: full helper bodies (trilogy bounds) + panic callee + caller zeroing
    windows = []
    for label, start, end in (
            ("helper-1", H1, fde[H1][1]),
            ("helper-2", H2, fde[H2][1]),
            ("panic-callee", PANIC_CALLEE, fde[PANIC_CALLEE][1]),
            ("caller-zeroing-copy2-acc", 0x4D0ABD6, 0x4D0ABFB)):
        blob = read_bytes(data, sections, start, end - start)
        windows.append((label, start, end, blob))
    # case table
    case_rows = []
    for case_id, a, b, out_init in CASES:
        h1_val, h1_flag = sim_helper1(a, b)
        h2_val, h2_flag = sim_helper2(out_init, 4, a, b)
        c_val, c_flag = closed(a, b)
        case_rows.append({
            "case": case_id,
            "a": ",".join(str(v) for v in a),
            "b": ",".join(str(v) for v in b),
            "out_init": ",".join(str(v) for v in out_init),
            "closed_value": ",".join(str(v) for v in c_val),
            "closed_overflow": c_flag,
            "helper1_value": ",".join(str(v) for v in h1_val),
            "helper1_flag": h1_flag,
            "helper1_value_ok": 1 if h1_val == c_val else 0,
            "helper2_value": ",".join(str(v) for v in h2_val),
            "helper2_flag": h2_flag,
            "helper2_value_ok": 1 if h2_val == c_val else 0,
            "helper1_flag_exact": 1 if h1_flag == c_flag else 0,
            "helper2_flag_exact": 1 if h2_flag == c_flag else 0,
            "flags_agree": 1 if h1_flag == h2_flag else 0,
        })
    # evidence
    evidence = {
        "target": "node #94",
        "sha256": SHA256,
        "worktree_baseline": "2993e46",
        "helpers": {
            "helper-1": {
                "address": hex(H1),
                "fde_readelf": "0x27a1150..0x27a162f",
                "fde_trilogy_end": hex(fde[H1][1]),
                "length_trilogy": fde[H1][1] - H1,
                "sha256": hashlib.sha256(read_bytes(data, sections, H1, fde[H1][1] - H1)).hexdigest(),
                "signature": "(out: *mut u8[33], a: *const u64[4], b: *const u64[4])",
                "overflow_signal": "byte at out+0x20, conservative (see README)",
                "panic_call": "0x27a1547 call [GOT 0x576e2e0]",
            },
            "helper-2": {
                "address": hex(H2),
                "fde_readelf": "0x4de5500..0x4de59ca",
                "fde_trilogy_end": hex(fde[H2][1]),
                "length_trilogy": fde[H2][1] - H2,
                "sha256": hashlib.sha256(read_bytes(data, sections, H2, fde[H2][1] - H2)).hexdigest(),
                "signature": "(out: *mut u64, count: u64, a: *const u64, b: *const u64) -> al",
                "overflow_signal": "al return, exact (see README)",
                "panic_call": "0x4de58e6 call [GOT 0x576e2e0]",
            },
        },
        "panic_callee": {
            "address": hex(PANIC_CALLEE),
            "fde_readelf": "0x157a6f0..0x157a7b8",
            "fde_trilogy_end": hex(fde[PANIC_CALLEE][1]),
            "length_trilogy": fde[PANIC_CALLEE][1] - PANIC_CALLEE,
            "sha256": hashlib.sha256(read_bytes(data, sections, PANIC_CALLEE, fde[PANIC_CALLEE][1] - PANIC_CALLEE)).hexdigest(),
            "got_slot": hex(PANIC_GOT),
            "relocation": "R_X86_64_RELATIVE -> 0x157a6f0",
            "panic_string_va": "0x1f8cd2",
            "panic_string": "range start index ... out of range for slice of length ...",
            "terminal_args": "edi=1, esi=0, edx=0, rcx=0x56c23d0 (helper-1) / rcx=0x5746f10 (helper-2)",
            "note": "the callee's range check fails for the constant args, so both blocks are terminal panic paths; the exact role of the rcx struct is unresolved",
        },
        "caller_census": {
            "helper-1_sites": 6,
            "helper-2_sites": 8,
            "total": 14,
            "method": "E8 rel32 scan of .text, enclosing FDE from the unwind index",
        },
        "anchors": [{"va": hex(va), "hex": hx} for va, hx in ANCHORS],
        "case_counts": {
            "cases": len(case_rows),
            "helper1_value_ok": sum(r["helper1_value_ok"] for r in case_rows),
            "helper2_value_ok": sum(r["helper2_value_ok"] for r in case_rows),
            "helper1_flag_exact": sum(r["helper1_flag_exact"] for r in case_rows),
            "helper2_flag_exact": sum(r["helper2_flag_exact"] for r in case_rows),
            "flags_agree": sum(r["flags_agree"] for r in case_rows),
        },
        "limitations": "FDE bounds are unwind-described ranges, not validated function boundaries. The block models are faithful translations of the disassembly, not executions of the node binary. Inputs with a_skip + b_skip >= 4 are out of scope: they write past the 4-limb accumulator/out window and are never produced by the scaling handlers.",
    }
    out_dir = args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    with (out_dir / "sites.tsv").open("w", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(["call_site", "enclosing_fde_start", "enclosing_fde_end", "helper", "role"])
        for site, fs, fe, helper, role in census:
            writer.writerow([hex(site), hex(fs), hex(fe), helper, role])
    with (out_dir / "loop_cases.tsv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(case_rows[0].keys()),
                                delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(case_rows)
    with (out_dir / "windows.txt").open("w") as handle:
        for label, start, end, blob in windows:
            handle.write(f"{label} {hex(start)}..{hex(end)} {blob.hex()}\n")
    print(f"wrote {len(case_rows)} cases, {len(census)} sites, {len(windows)} windows to {out_dir}")


if __name__ == "__main__":
    main()
