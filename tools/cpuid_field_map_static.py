#!/usr/bin/env python3
"""Complete the node #115 A/B field map of the refresh helper 0x5cadd50.

PR #2474 (RE-002 xcr0-composition) attributed every A/B field the XCR0
terms drive and explicitly left the field-by-field CPUID attribution of
the always-on early compositions of R12 and R15 unclaimed; the merged
RE-002 cache-publication packet owns the suffix equations and likewise
leaves the prefix feature values unproved.  This tool closes that gap:
it attributes every remaining bit of the composed words A (= R12) and
B (= R15), measured at the selection entry 0x5cae35e, to its CPUID leaf,
subleaf and source bit, so the map is complete for A and B and therefore,
through the cited publication equations, for C0-C2.

Method.  Owner bodies and 223 sites are byte-pinned and the objdump
export is required to start exactly at each pin.  A per-bit provenance
fixpoint over the helper's control-flow graph tracks, for every register
bit and every named stack slot, the set of input bits the bit's value
can depend on (value provenance) and the set of input bits that selected
it through a conditional move (condition provenance); conditional-move
conditions are merged only where the two arms' value provenance for that
bit differs, and flag results materialised by sete are value provenance.
CPUID sites inject fresh per-bit atoms for the leaf/subleaf pinned by
the site's immediate setup; the single call site injects the XCR0 result
per PR #2398.  At the selection entry the union of both provenances,
minus the constant marker, must equal the recorded support of every bit
(bit 25 is asserted by subset: its compare condition may mention only
leaf 7.0 EBX).  Write-site and slot censuses are re-derived from the
export and asserted.  Three byte-level corrections to PR #2474 fall out
of the pins and are recorded under corrections_to_pr_2474.  No captured
code is executed.
"""
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import ROOT  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402
from foundation_millis import decode_export  # noqa: E402


def read(data, va, n):
    matches = [s for s in sections(data)
               if s["type"] != 8 and s["address"] <= va and va + n <= s["address"] + s["size"]]
    if len(matches) != 1:
        raise ValueError("expected one file-backed mapping")
    s = matches[0]
    o = s["offset"] + va - s["address"]
    return o, bytes(data[o:o + n])


def sha256(data):
    return hashlib.sha256(data).hexdigest()

WORK_ITEM = ROOT / "research/work-items/RE-002-node115-cpuid-field-map"
TARGET = ROOT / "artifacts/node/115/hl-node"
HELPER = (0x5CADD50, 0x5CAE3DA)
XCR0_LEAF = (0x5CAE3E0, 0x5CAE3ED)
OWNERS = {
    "refresh_helper": (*HELPER, "f4cc818ee02b994599bfc53910323d3edf8420d0b404c2e5060faab72524c349"),
    "xcr0_leaf": (*XCR0_LEAF, "f347a1395ba474e85f6c71330ca7f30e1d067cc6af42548744b6310ae2dbf0be"),
}
SELECTION_ENTRY = 0x5CAE35E
CALL_SITE = 0x5CAE04C
CONST = ("const",)
CALL = ("call",)
EMPTY = frozenset()
SITE_LEAVES = {
    0x5CADD68: (0, 0), 0x5CADD94: (1, 0), 0x5CADDB6: (7, 0), 0x5CADDD0: (7, 1),
    0x5CADE25: (0x80000000, 0), 0x5CADE3C: (0x80000001, 0), 0x5CADFB9: (0x19, 0),
    0x5CAE091: (0xD, 1), 0x5CAE2C5: (0x1E, 1), 0x5CAE33A: (0x24, 0),
}


def C(leaf, sub, reg, bit):
    return ("cpuid", leaf, sub, reg, bit)


def X(bit):
    return ("xcr0", bit)


def fmt(atom):
    if atom == CONST:
        return "const"
    if atom == CALL:
        return "call:unknown"
    if atom[0] == "cpuid":
        _, leaf, sub, reg, bit = atom
        ls = str(leaf) if leaf < 16 else hex(leaf)
        return f"cpuid leaf {ls} subleaf {sub} {reg} bit {bit}"
    if atom[0] == "xcr0":
        return f"xcr0 bit {atom[1]}"
    return repr(atom)


EARLY = "early composition (this packet)"
CITED = "pr #2474 (cited)"
FALL = "gated by xcr0 bits 1,2 fall-through (pr #2474 stage 3a)"
EXTRA = ("gated by (xcr0 & 0xe0) == 0xe0 and cpuid leaf 1 ecx bits 12,29 "
         "both set (extra block, pr #2474 stage 4b)")
SHARED = "gated by xcr0 bits 17,18 both set (shared block, pr #2474 stage 4c)"

# (bit, driver, mechanism, support atoms, origin)
FIELD_MAP_A = [
    (0, "cpuid leaf 1 ecx bit 25",
     "the (leaf 1 ecx << 38 | leaf 1 edx) word built in r8 at 0x5cade8c..0x5cade96 is masked with 0x2000000000000010 at 0x5cadefd and or-ed into r12 through r10 at 0x5cadf80; mask bit 0 keeps r8 bit 0",
     (C(1, 0, "ecx", 25),), EARLY),
    (1, "cpuid leaf 1 ecx bit 1",
     "the leaf 1 ecx scatter built at 0x5cade46..0x5cade7b (and ecx,0x202 keeps ecx bits 1 and 9) is or-ed into r12 at 0x5cadf56",
     (C(1, 0, "ecx", 1),), EARLY),
    (2, "cpuid leaf 1 ecx bit 30",
     "esi (leaf 1 ecx) is shifted right 0x1c and masked with 4 at 0x5cadf29/0x5cadf2c and or-ed into r12 through r10 at 0x5cadf80",
     (C(1, 0, "ecx", 30),), EARLY),
    (3, "cpuid leaf 7 subleaf 0 ebx bit 18",
     "r13d (leaf 7.0 ebx) is shifted right 0xf and masked with 8 at 0x5cadf59..0x5cadf62 and or-ed into r12",
     (C(7, 0, "ebx", 18),), EARLY),
    (4, "cpuid leaf 1 edx bit 4",
     "bit 4 of the 0x2000000000000010 mask over the (leaf 1 ecx << 38 | leaf 1 edx) word keeps leaf 1 edx bit 4; or-ed into r12 at 0x5cadf80",
     (C(1, 0, "edx", 4),), EARLY),
    (5, "cpuid leaf 1 edx bit 23",
     "esi is reloaded with r12d (leaf 1 edx) at 0x5cadf32, shifted right 0x12 and masked with 0x20, and or-ed into r12 through r10",
     (C(1, 0, "edx", 23),), EARLY),
    (6, "cpuid leaf 1 edx bit 25",
     "the r12 seed (leaf 1 edx, loaded at 0x5cadd99) is shifted right 0x13 and masked with 0xc0 at 0x5cadf4b/0x5cadf4f; only seed bits 25 and 26 survive, at positions 6 and 7",
     (C(1, 0, "edx", 25),), EARLY),
    (7, "cpuid leaf 1 edx bit 26",
     "the r12 seed (leaf 1 edx) shifted right 0x13 and masked with 0xc0 at 0x5cadf4b/0x5cadf4f",
     (C(1, 0, "edx", 26),), EARLY),
    (8, "cpuid leaf 1 ecx bit 0",
     "the leaf 1 ecx scatter (and eax,1 at 0x5cade4a, shl eax,8 at 0x5cade4d) is or-ed into r12 at 0x5cadf56",
     (C(1, 0, "ecx", 0),), EARLY),
    (9, "cpuid leaf 1 ecx bit 9",
     "the leaf 1 ecx scatter (and ecx,0x202 at 0x5cade52) is or-ed into r12 at 0x5cadf56",
     (C(1, 0, "ecx", 9),), EARLY),
    (10, "cpuid leaf 1 ecx bit 19",
     "leaf 1 ecx is shifted right 9 and masked with 0x400 at 0x5cade68..0x5cade73 and or-ed into r12 through the scatter at 0x5cadf56",
     (C(1, 0, "ecx", 19),), EARLY),
    (11, "cpuid leaf 1 ecx bit 20",
     "leaf 1 ecx is shifted right 9 and masked with 0x800 at 0x5cade68..0x5cade7b and or-ed into r12 at 0x5cadf56",
     (C(1, 0, "ecx", 20),), EARLY),
    (12, "cpuid leaf 0x80000001 ecx bit 6 (vendor block: amd/hygon only)",
     "in the vendor block (compare at 0x5cadfdf..0x5cae014), edi (leaf 0x80000001 ecx) is masked with 0x40 and shifted left 6 at 0x5cae016..0x5cae01b and or-ed into r12 through rcx at 0x5cae036",
     (C(0x80000001, 0, "ecx", 6),), EARLY),
    (13, "cpuid leaf 7 subleaf 0 ebx bit 29",
     "r13d is shifted right 0x10 and masked with 0x2000 at 0x5cadf65..0x5cadf70 and or-ed into r12",
     (C(7, 0, "ebx", 29),), EARLY),
    (14, "cpuid leaf 1 ecx bit 28, " + FALL,
     "ebx (leaf 1 ecx) is shifted right 0xe and masked with 0x4000 at 0x5cae0db/0x5cae0de; the term is or-ed into r12 through rbx/rdx/r9 in the fall-through composition and the pre-branch word is restored through rcx at 0x5cae14f (pr #2474 stage 5 (e))",
     (C(1, 0, "ecx", 28),), CITED),
    (15, "cpuid leaf 7 subleaf 0 ebx bit 5, " + FALL,
     "edx = (r13d & 0x20) << 0xa at 0x5cae0e7..0x5cae0f0; or-ed into r12 in the fall-through composition (pr #2474 stage 5 (e))",
     (C(7, 0, "ebx", 5),), CITED),
    (16, "cpuid leaf 7 subleaf 1 eax bit 0 ([rbp-0x38] slot), " + FALL,
     "r12d is reloaded with esi (leaf 7.1 eax, reloaded from the slot at 0x5cae0bd), masked with 7 and shifted left 0x10 at 0x5cae13b..0x5cae142 (pr #2474 stage 5 (e))",
     (C(7, 1, "eax", 0),), CITED),
    (17, "cpuid leaf 7 subleaf 1 eax bit 1 ([rbp-0x38] slot), " + FALL,
     "the same masked reload at 0x5cae13b..0x5cae142; slot bit 1 lands at position 17",
     (C(7, 1, "eax", 1),), CITED),
    (18, "cpuid leaf 7 subleaf 1 eax bit 2 ([rbp-0x38] slot), " + FALL,
     "the same masked reload at 0x5cae13b..0x5cae142; slot bit 2 lands at position 18",
     (C(7, 1, "eax", 2),), CITED),
    (19, "cpuid leaf 7 subleaf 0 ebx bit 16, " + EXTRA,
     "eax = r13d & 0x10000 at 0x5cae165..0x5cae168; lea eax,[rdx+rax*8] at 0x5cae179 combines it with the bit-24 term; the sum is or-ed into r12 at 0x5cae1c0 and carried through rax into the rebuilt word at 0x5cae239 (pr #2474 stage 5 (e))",
     (C(7, 0, "ebx", 16),), CITED),
    (20, "cpuid leaf 7 subleaf 0 ebx bit 28, " + EXTRA,
     "eax = (r13d >> 8) & 0x100000 at 0x5cae1a5..0x5cae1ab; or-ed into r12 at 0x5cae1c0 and carried through rax (pr #2474 stage 5 (e))",
     (C(7, 0, "ebx", 28),), CITED),
    (21, "cpuid leaf 7 subleaf 0 ebx bit 27, " + EXTRA,
     "edx = (r13d >> 6) & 0x200000 at 0x5cae197..0x5cae19d; or-ed into r12 at 0x5cae1c0 and carried through rax (pr #2474 stage 5 (e))",
     (C(7, 0, "ebx", 27),), CITED),
    (22, "cpuid leaf 7 subleaf 0 ebx bit 26, " + EXTRA,
     "eax = (r13d >> 4) & 0x400000 at 0x5cae18a..0x5cae190; or-ed into r12 at 0x5cae1c0 and carried through rax (pr #2474 stage 5 (e))",
     (C(7, 0, "ebx", 26),), CITED),
    (23, "cpuid leaf 7 subleaf 0 ebx bit 30, " + EXTRA,
     "edx = (r13d >> 7) & 0x800000 at 0x5cae1b2..0x5cae1b8; or-ed into r12 at 0x5cae1c0 and carried through rax into the rebuilt word at 0x5cae239. pr #2474's extra-block list (ebx bits 16, 28, 27, 26, 17, 21) does not include this bit; the pin at 0x5cae1b2..0x5cae1b8 attributes it here",
     (C(7, 0, "ebx", 30),), "extra block (this packet)"),
    (24, "cpuid leaf 7 subleaf 0 ebx bit 17, " + EXTRA,
     "edx = (r13d << 7) & 0x1000000 at 0x5cae16d..0x5cae173; combined by the lea at 0x5cae179 and or-ed into r12 at 0x5cae1c0 (pr #2474 stage 5 (e))",
     (C(7, 0, "ebx", 17),), CITED),
    (25, "the constant 1, selected by cpuid leaf 7 subleaf 0 ebx bit 31, " + EXTRA,
     "rax := r12 at 0x5cae1c3; or rax,0x2000000 at 0x5cae1c6 sets bit 25 in the copy; cmp r13,rcx at 0x5cae1cc compares leaf 7.0 ebx against rcx = 0x80000000 (ecx loaded at 0x5cae160, after the saved composed word in rcx was consumed by the restore at 0x5cae14f and ecx overwritten); cmovb rax,r12 at 0x5cae1cf restores the unset copy exactly when ebx < 0x80000000, so bit 25 is set exactly when ebx bit 31 is set. pr #2474 describes the compare as against the saved composed word in rcx; the pins at 0x5cae14f and 0x5cae160 show the constant is the operand at the compare",
     (C(7, 0, "ebx", 31),), "pr #2474 (cited), compare operand corrected by this packet"),
    (26, "cpuid leaf 7 subleaf 0 ebx bit 21, " + EXTRA,
     "edx = (r13d << 5) & 0x4000000 at 0x5cae17c..0x5cae182; or-ed into r12 at 0x5cae1c0 and carried through rax (pr #2474 stage 5 (e))",
     (C(7, 0, "ebx", 21),), CITED),
    (27, "cpuid leaf 7 subleaf 0 ecx bit 1 ([rbp-0x58] slot), " + EXTRA,
     "edx = (r11d & 2) << 0x1a at 0x5cae1d7..0x5cae1dd, with r11 the [rbp-0x58] reload at 0x5cae1d3; or-ed into r12 at 0x5cae22d (pr #2474 stage 5 (e))",
     (C(7, 0, "ecx", 1),), CITED),
    (28, "cpuid leaf 7 subleaf 0 ecx bit 14 ([rbp-0x58] slot), " + EXTRA,
     "r11d is shifted left 0xe and masked with 0x10000000 at 0x5cae1eb/0x5cae1ef; or-ed into r12 at 0x5cae22d (pr #2474 stage 5 (e))",
     (C(7, 0, "ecx", 14),), CITED),
    (29, "cpuid leaf 7 subleaf 0 ecx bit 6 ([rbp-0x58] slot), " + EXTRA,
     "ecx = (r11d & 0x40) << 0x17 at 0x5cae1e0..0x5cae1e9; or-ed into r12 at 0x5cae22a (pr #2474 stage 5 (e))",
     (C(7, 0, "ecx", 6),), CITED),
    (30, "cpuid leaf 7 subleaf 0 ecx bit 8",
     "the r15 seed (leaf 7.0 ecx << 22, built at 0x5cadeba..0x5cadebd) is masked with 0x40000000 at 0x5cadec1..0x5cadec4 — seed bit 30 is leaf 7.0 ecx bit 8 — and or-ed into r12 through r9 at 0x5cadf83",
     (C(7, 0, "ecx", 8),), EARLY),
    (31, "cpuid leaf 7 subleaf 0 ecx bit 9",
     "the r15 seed is masked with 0x80000000 at 0x5cadedc..0x5cadee6 — seed bit 31 is leaf 7.0 ecx bit 9 — and or-ed into r12 through r9 at 0x5cadf83",
     (C(7, 0, "ecx", 9),), EARLY),
    (32, "cpuid leaf 7 subleaf 0 ecx bit 10",
     "the constant 0x100000000 is and-ed with the r15 seed at 0x5cadee9..0x5cadefa — seed bit 32 is leaf 7.0 ecx bit 10 — and or-ed into r12 through r9 at 0x5cadf83",
     (C(7, 0, "ecx", 10),), EARLY),
    (33, "cpuid leaf 7 subleaf 0 ecx bit 11 ([rbp-0x58] slot via [rbp-0x68]), " + EXTRA,
     "r12 is reloaded with [rbp-0x68] (the seed word stored at 0x5cadef3) and masked with 0x600000000 at 0x5cae223/0x5cae227; seed bit 33 is leaf 7.0 ecx bit 11 (pr #2474 stage 5 (e))",
     (C(7, 0, "ecx", 11),), CITED),
    (34, "cpuid leaf 7 subleaf 0 ecx bit 12 ([rbp-0x58] slot via [rbp-0x68]), " + EXTRA,
     "the same reload and mask at 0x5cae223/0x5cae227; seed bit 34 is leaf 7.0 ecx bit 12 (pr #2474 stage 5 (e))",
     (C(7, 0, "ecx", 12),), CITED),
    (35, "cpuid leaf 7 subleaf 1 eax bit 5 ([rbp-0x38] slot, in rsi), " + EXTRA,
     "esi is masked with 0x20 and shifted left 0x1e at 0x5cae212/0x5cae215; or-ed into r12 at 0x5cae236 (pr #2474 stage 5 (e))",
     (C(7, 1, "eax", 5),), CITED),
    (36, "cpuid leaf 7 subleaf 0 edx bit 8 ([rbp-0x50] slot), " + EXTRA,
     "edx = (r8d & 0x100) << 0x1c at 0x5cae1fa..0x5cae203, with r8 the [rbp-0x50] reload at 0x5cae1f6; or-ed into r12 at 0x5cae230 (pr #2474 stage 5 (e))",
     (C(7, 0, "edx", 8),), CITED),
    (37, "cpuid leaf 7 subleaf 0 edx bit 23 ([rbp-0x50] slot), " + EXTRA,
     "r8d is masked with 0x800000 and shifted left 0xe at 0x5cae207/0x5cae20e; or-ed into r12 at 0x5cae233 (pr #2474 stage 5 (e))",
     (C(7, 0, "edx", 23),), CITED),
    (38, "cpuid leaf 7 subleaf 1 eax bit 23 ([rbp-0x38] slot), " + FALL,
     "edx = (esi & 0x800000) << 0xf at 0x5cae101..0x5cae109, with esi reloaded from the slot at 0x5cae0bd; or-ed into r12 in the fall-through composition (pr #2474 stage 5 (e))",
     (C(7, 1, "eax", 23),), CITED),
    (39, "cpuid leaf 7 subleaf 1 edx bit 5 ([rbp-0x60] slot), " + FALL,
     "r10d = (ebx & 0x20) << 0x22 at 0x5cae11f..0x5cae126, with rbx the [rbp-0x60] reload at 0x5cae110; or-ed into r12 at 0x5cae14c (pr #2474 stage 5 (e))",
     (C(7, 1, "edx", 5),), CITED),
    (40, "cpuid leaf 7 subleaf 1 eax bit 4 ([rbp-0x38] slot), " + FALL,
     "r9d = (esi & 0x10) << 0x24 at 0x5cae0f3..0x5cae0fe; or-ed into r12 through rdx at 0x5cae146 (pr #2474 stage 5 (e))",
     (C(7, 1, "eax", 4),), CITED),
    (41, "cpuid leaf 7 subleaf 1 edx bit 10 ([rbp-0x60] slot), " + FALL,
     "r11d = (ebx & 0x400) << 0x1f at 0x5cae12a..0x5cae138, with rbx the [rbp-0x60] reload at 0x5cae110; or-ed into r12 at 0x5cae14c (pr #2474 stage 5 (e))",
     (C(7, 1, "edx", 10),), CITED),
    (42, "cpuid leaf 7 subleaf 1 edx bit 4 ([rbp-0x60] slot), " + FALL,
     "r9d = (ebx & 0x10) << 0x26 at 0x5cae114..0x5cae11b, with rbx the [rbp-0x60] reload at 0x5cae110; or-ed into r12 at 0x5cae149 (pr #2474 stage 5 (e))",
     (C(7, 1, "edx", 4),), CITED),
    (43, "cpuid leaf 7 subleaf 0 edx bit 24 ([rbp-0x50] slot), " + SHARED,
     "eax = (edx & 0x3000000) << 0x13 at 0x5cae278..0x5cae27f covers bits 43 and 44; this bit is the 0x1000000 half, with edx the [rbp-0x50] reload at 0x5cae274 (pr #2474 stage 5 (d))",
     (C(7, 0, "edx", 24),), CITED),
    (44, "cpuid leaf 7 subleaf 0 edx bit 25 ([rbp-0x50] slot), " + SHARED + " — the only source",
     "eax = (edx & 0x3000000) << 0x13 at 0x5cae278..0x5cae27f; this bit is the 0x2000000 half (pr #2474 stage 5 (d)). pr #2474 also lists a fall-through leaf 1 ecx bit 12 driver for this bit; that term (and edx,0x1000 / shl rdx,0x2c at 0x5cae0d1/0x5cae0d7) lands at bit 56 — see bit 56",
     (C(7, 0, "edx", 25),), "pr #2474 (cited), second driver removed by this packet"),
    (45, "cpuid leaf 7 subleaf 0 edx bit 22 ([rbp-0x50] slot), " + SHARED,
     "edx is masked with 0x400000 and shifted left 0x17 at 0x5cae283/0x5cae289, with edx the [rbp-0x50] reload at 0x5cae274; or-ed into r12 through rcx at 0x5cae2af (pr #2474 stage 5 (d))",
     (C(7, 0, "edx", 22),), CITED),
    (46, "cpuid leaf 7 subleaf 1 eax bit 21 ([rbp-0x38] slot), " + SHARED,
     "ecx = (rcx & 0x200000) << 0x19 at 0x5cae294..0x5cae29a, with rcx the [rbp-0x38] reload at 0x5cae290; or-ed into r12 through rax at 0x5cae2af (pr #2474 stage 5 (d))",
     (C(7, 1, "eax", 21),), CITED),
    (47, "cpuid leaf 7 subleaf 1 edx bit 8 ([rbp-0x60] slot, reloaded into rbx on both arms), " + SHARED,
     "eax = (ebx & 0x100) << 0x27 at 0x5cae2a1..0x5cae2a8; or-ed into r12 at 0x5cae2af (pr #2474 stage 5 (d))",
     (C(7, 1, "edx", 8),), CITED),
    (48, "cpuid leaf 0x1e subleaf 1 eax bit 7, gated by xcr0 bits 17,18 and max leaf >= 0x1e",
     "in the leaf 0x1e block at 0x5cae2b8..0x5cae328 (pr #2474 stage 5 (d))",
     (C(0x1E, 1, "eax", 7),), CITED),
    (49, "cpuid leaf 0x1e subleaf 1 eax bit 4, gated by xcr0 bits 17,18 and max leaf >= 0x1e",
     "in the leaf 0x1e block at 0x5cae2b8..0x5cae328 (pr #2474 stage 5 (d))",
     (C(0x1E, 1, "eax", 4),), CITED),
    (50, "cpuid leaf 0x1e subleaf 1 eax bit 8, gated by xcr0 bits 17,18 and max leaf >= 0x1e",
     "in the leaf 0x1e block at 0x5cae2b8..0x5cae328 (pr #2474 stage 5 (d))",
     (C(0x1E, 1, "eax", 8),), CITED),
    (51, "cpuid leaf 0x1e subleaf 1 eax bit 6, gated by xcr0 bits 17,18 and max leaf >= 0x1e",
     "in the leaf 0x1e block at 0x5cae2b8..0x5cae328 (pr #2474 stage 5 (d))",
     (C(0x1E, 1, "eax", 6),), CITED),
    (52, "the constant 1, inserted exactly when xcr0 bit 19 and cpuid leaf 7 subleaf 1 edx bit 21 are both set",
     "sete cl on xcr0 bit 19 (test r14d,0x80000 at 0x5cae300) and sete dl on leaf 7.1 edx bit 21 (test ebx,0x200000 at 0x5cae30a, ebx the [rbp-0x60] reload) are or-ed at 0x5cae313; movabs r12,0x10000000000000 / or r12,rax / cmovne r12,rax at 0x5cae315..0x5cae324 inserts the constant exactly when the combined byte is nonzero, with rax the saved r12 from 0x5cae2fd (pr #2474 stage 5 (d))",
     (X(19), C(7, 1, "edx", 21)), CITED),
    (53, "the constant 1, set on both arms of the leaf 0x24 block (block gated by leaf 7.1 edx bit 19 at 0x5cae328, after the convergence at 0x5cae2f3)",
     "movabs rcx,0x60000000000000 at 0x5cae34d (bits 53 and 54) is the default word; cmove rcx,rax at 0x5cae357 substitutes movabs rax,0x20000000000000 (bit 53) when leaf 0x24 ebx bits 1..7 are all zero (test sil,0xfe at 0x5cae33f); bit 53 is in both words, so it is set whenever the block runs; or r12,rcx at 0x5cae35b",
     (), "leaf 0x24 block (this packet)"),
    (54, "the constant 1, set exactly when cpuid leaf 0x24 subleaf 0 ebx bits 1..7 are not all zero (same block as bit 53)",
     "bit 54 is in the default word 0x60000000000000 but not in the cmove substitute 0x20000000000000; the test sil,0xfe at 0x5cae33f tests leaf 0x24 ebx bits 1..7. pr #2474 names bits 57 and 58 for this block's reach; the pinned constant at 0x5cae34d is 0x60000000000000 (bits 53, 54)",
     tuple(C(0x24, 0, "ebx", i) for i in range(1, 8)), "leaf 0x24 block (this packet)"),
    (55, "cpuid leaf 1 ecx bit 29",
     "ebx (leaf 1 ecx) is masked with 0x20000000 and shifted left 0x1a at 0x5cadf18..0x5cadf26 and or-ed into r12 through r10 at 0x5cadf80",
     (C(1, 0, "ecx", 29),), EARLY),
    (56, "cpuid leaf 1 ecx bit 12, " + FALL,
     "edx = (ebx & 0x1000) << 0x2c at 0x5cae0d1/0x5cae0d7, with rbx leaf 1 ecx: bit 12 + 0x2c = bit 56; the term is or-ed into r12 through rbx/rdx/r9 in the fall-through composition. pr #2474 places this term at bit 44; the shift count in the pin at 0x5cae0d7 puts it at bit 56",
     (C(1, 0, "ecx", 12),), "this packet (term misplaced at bit 44 by pr #2474)"),
    (57, "cpuid leaf 7 subleaf 0 ebx bit 3",
     "r13d is masked with 8 and shifted left 0x36 at 0x5cadf73..0x5cadf7d and or-ed into r12. the leaf 0x24 block does not reach this bit (see bit 54)",
     (C(7, 0, "ebx", 3),), EARLY),
    (58, "cpuid leaf 7 subleaf 0 ebx bit 8",
     "r13d is masked with 0x100 and shifted left 0x32 at 0x5cadecb..0x5caded9 and or-ed into r12 through r9 at 0x5cadf83. the leaf 0x24 block does not reach this bit (see bit 54)",
     (C(7, 0, "ebx", 8),), EARLY),
    (59, "cpuid leaf 0x80000001 ecx bit 5",
     "edi (leaf 0x80000001 ecx, zero when the maximum extended leaf is 0) is masked with 0x20 and shifted left 0x36 at 0x5cadfd3..0x5cadfdc and or-ed into r12",
     (C(0x80000001, 0, "ecx", 5),), EARLY),
    (60, "cpuid leaf 0x80000001 ecx bit 21 (vendor block: amd/hygon only)",
     "in the vendor block, edi is masked with 0x200000 and shifted left 0x27 at 0x5cae01e..0x5cae02a and or-ed into r12 through rcx at 0x5cae036",
     (C(0x80000001, 0, "ecx", 21),), EARLY),
    (61, "cpuid leaf 1 ecx bit 23",
     "bit 61 of the 0x2000000000000010 mask over the (leaf 1 ecx << 38 | leaf 1 edx) word keeps leaf 1 ecx bit 23 (r8 bit 61 = ecx bit 23); or-ed into r12 at 0x5cadf80",
     (C(1, 0, "ecx", 23),), EARLY),
    (62, "cpuid leaf 1 edx bit 24",
     "ecx (leaf 1 edx) is masked with 0x1000000 and shifted left 0x26 at 0x5cadf3e..0x5cadf48 and or-ed into r12 through r10",
     (C(1, 0, "edx", 24),), EARLY),
    (63, "the constant 0x8000000000000000 (H), gated by xcr0 bits 1 and 2 both set (fall-through at 0x5cae061)",
     "the movabs/or at 0x5cae071/0x5cae07b or-s H into r12 (pr #2474 stages 3b/4); no xcr0 value bit is copied — the gate is control flow only, so the support is empty",
     (), CITED),
]

FIELD_MAP_B = [
    (0, "the constant 1, selected by cpuid leaf 0xd subleaf 1 eax bit 0, gated by xcr0 bits 1,2 and max leaf > 0xc",
     "rcx := r15 at 0x5cae096; or rcx,0x1 at 0x5cae099; test al,0x1 / cmove rcx,r15 at 0x5cae09d/0x5cae0a3 keeps the set bit exactly when leaf 0xd eax bit 0 is set; the composed word is stored to r15 at 0x5cae0ba, preserving the early bits 3..11 through rcx (pr #2474 stage 5 (e))",
     (C(0xD, 1, "eax", 0),), CITED),
    (1, "cpuid leaf 0xd subleaf 1 eax bit 3, gated by xcr0 bits 1,2 and max leaf > 0xc",
     "eax is masked with 8 and shifted right 2 at 0x5cae0ae/0x5cae0b1 and or-ed into the stored word at 0x5cae0b4 (pr #2474 stage 5 (e))",
     (C(0xD, 1, "eax", 3),), CITED),
    (2, "cpuid leaf 0xd subleaf 1 eax bit 1, gated by xcr0 bits 1,2 and max leaf > 0xc",
     "edx = eax & 2 at 0x5cae0a7..0x5cae0a9; add edx,edx at 0x5cae0ac moves bit 1 to position 2; or-ed into the stored word at 0x5cae0b4 (pr #2474 stage 5 (e))",
     (C(0xD, 1, "eax", 1),), CITED),
    (3, "cpuid leaf 1 ecx bit 13",
     "r8d = (esi >> 0xa) & 8 at 0x5cade5b..0x5cade62 (esi = leaf 1 ecx); the scatter word in rdx is the rebuild base loaded into r15 at 0x5cadf91",
     (C(1, 0, "ecx", 13),), EARLY),
    (4, "cpuid leaf 0x19 subleaf 0 ebx bit 0, gated by cpuid leaf 7 subleaf 0 ecx bit 23",
     "in the leaf 0x19 block (test r14d,0x800000 at 0x5cadfa6, r14 the [rbp-0x58] reload): eax = (ebx & 1) << 4 at 0x5cadfbe..0x5cadfc3; or-ed into r15 at 0x5cadfcc",
     (C(0x19, 0, "ebx", 0),), EARLY),
    (5, "cpuid leaf 0x19 subleaf 0 ebx bit 2, gated by cpuid leaf 7 subleaf 0 ecx bit 23",
     "in the leaf 0x19 block: esi = leaf 0x19 ebx & 4 at 0x5cadfc6; lea eax,[rax+rsi*8] at 0x5cadfc9 adds bit 2 at position 5; or-ed into r15 at 0x5cadfcc",
     (C(0x19, 0, "ebx", 2),), EARLY),
    (6, "cpuid leaf 7 subleaf 0 ebx bit 19",
     "r9d = (r13d >> 0xd) & 0x40 at 0x5cade99..0x5cadea4; part of the rebuild base in rdx loaded into r15 at 0x5cadf91",
     (C(7, 0, "ebx", 19),), EARLY),
    (7, "cpuid leaf 7 subleaf 0 ebx bit 11",
     "edx = (r13d & 0x800) >> 4 at 0x5cadea7..0x5cadeb3; part of the rebuild base in rdx",
     (C(7, 0, "ebx", 11),), EARLY),
    (8, "cpuid leaf 1 ecx bit 22",
     "edx = (esi & 0x400000) >> 0xe at 0x5cade7e..0x5cade89 (esi = leaf 1 ecx); part of the rebuild base in rdx",
     (C(1, 0, "ecx", 22),), EARLY),
    (9, "the constant 1, present exactly when cpuid leaf 7 subleaf 1 eax bit 31 is set",
     "the rebuild loads rax into r15 at 0x5cadf91 and or-s 0x200 at 0x5cadf94; cmove r15,rax at 0x5cadfa2 (test DWORD PTR [rbp-0x38],0x80000000 at 0x5cadf9b) removes the constant when leaf 7.1 eax bit 31 is clear",
     (C(7, 1, "eax", 31),), EARLY),
    (10, "cpuid leaf 7 subleaf 0 ebx bit 9",
     "lea eax,[rdx+rax*2] at 0x5cadf8e with rax = r13d & 0x200: bit 9 enters at position 10; the rebuild loads rax into r15 at 0x5cadf91",
     (C(7, 0, "ebx", 9),), EARLY),
    (11, "cpuid leaf 0x80000001 ecx bit 11 (vendor block: amd/hygon only)",
     "in the vendor block, edi (leaf 0x80000001 ecx) is masked with 0x800 at 0x5cae02d and or-ed into r15 at 0x5cae033",
     (C(0x80000001, 0, "ecx", 11),), EARLY),
]
for _bit in range(12, 64):
    FIELD_MAP_B.append((
        _bit, "no source on any path — always zero",
        "the per-bit provenance at the selection entry is empty: the rebuild base covers bits 3, 6, 7, 8 only, the rebuild adds bits 9 and 10, the leaf 0x19 block bits 4 and 5, the vendor block bit 11, and the leaf 0xd block preserves the early word through rcx while adding bits 0, 1, 2; the r15 write census (8 sites) has no other writer",
        (), "none — always zero"))


def field_map_records(entries, word):
    out = []
    for bit, driver, mechanism, support, origin in entries:
        out.append({
            "word": word,
            "bit": bit,
            "driver": driver,
            "mechanism": mechanism,
            "support": [fmt(a) for a in support],
            "origin": origin,
        })
    return out


CORRECTIONS = [
    {
        "subject": "leaf 0x24 block reach",
        "pr_2474_claim": "the leaf 0x24 OR reaches only bits 53, 57 and 58 (README stage 5 (d); pin name 'leaf 0x24 bit 57 and 58 constant' at 0x5cae34d)",
        "byte_verified": "the default word at 0x5cae34d is 0x60000000000000 (bits 53, 54) and the cmove substitute at 0x5cae343 is 0x20000000000000 (bit 53): the block reaches bits 53 and 54, with bit 54 conditional on leaf 0x24 ebx bits 1..7. a bits 57 and 58 come only from the early composition (leaf 7.0 ebx bits 3 and 8)",
    },
    {
        "subject": "fall-through leaf 1 ecx bit 12 landing bit",
        "pr_2474_claim": "a bit 44 driver (field_map C0 bit 44, second entry; README stage 5 (e))",
        "byte_verified": "and edx,0x1000 / shl rdx,0x2c at 0x5cae0d1/0x5cae0d7 lands the term at bit 56 (12 + 0x2c); a bit 44 has the single shared-block source leaf 7.0 edx bit 25",
    },
    {
        "subject": "bit 25 compare operand",
        "pr_2474_claim": "unsigned compare of leaf 7.0 ebx (r13) against the saved composed word (rcx) at 0x5cae1cc (field_map C0 bit 25)",
        "byte_verified": "ecx is loaded with the constant 0x80000000 at 0x5cae160, after the saved composed word in rcx was consumed by the restore or r12,rcx at 0x5cae14f; the compare at 0x5cae1cc therefore decides on leaf 7.0 ebx bit 31 alone, and bit 25 is that bit under the extra-block gate",
    },
]

PINS = [
    (0x5cadd61, bytes.fromhex("31c0"), 'xor eax,eax'),
    (0x5cadd63, bytes.fromhex("31c9"), 'xor ecx,ecx'),
    (0x5cadd65, bytes.fromhex("4889de"), 'mov rsi,rbx'),
    (0x5cadd68, bytes.fromhex("0fa2"), 'cpuid'),
    (0x5cadd6a, bytes.fromhex("4887f3"), 'xchg rbx,rsi'),
    (0x5cadd6d, bytes.fromhex("4531ed"), 'xor r13d,r13d'),
    (0x5cadd70, bytes.fromhex("48bf0000000000000080"), 'movabs rdi,0x8000000000000000'),
    (0x5cadd7a, bytes.fromhex("85c0"), 'test eax,eax'),
    (0x5cadd7e, bytes.fromhex("4189c2"), 'mov r10d,eax'),
    (0x5cadd81, bytes.fromhex("4189c8"), 'mov r8d,ecx'),
    (0x5cadd84, bytes.fromhex("4189d3"), 'mov r11d,edx'),
    (0x5cadd87, bytes.fromhex("4189f1"), 'mov r9d,esi'),
    (0x5cadd8a, bytes.fromhex("31c9"), 'xor ecx,ecx'),
    (0x5cadd8c, bytes.fromhex("b801000000"), 'mov eax,0x1'),
    (0x5cadd91, bytes.fromhex("4889de"), 'mov rsi,rbx'),
    (0x5cadd94, bytes.fromhex("0fa2"), 'cpuid'),
    (0x5cadd96, bytes.fromhex("4887f3"), 'xchg rbx,rsi'),
    (0x5cadd99, bytes.fromhex("4189d4"), 'mov r12d,edx'),
    (0x5cadd9c, bytes.fromhex("89ce"), 'mov esi,ecx'),
    (0x5cadd9e, bytes.fromhex("4183fa07"), 'cmp r10d,0x7'),
    (0x5cadda2, bytes.fromhex("448945d4"), 'mov DWORD PTR [rbp-0x2c],r8d'),
    (0x5cadda6, bytes.fromhex("448955c4"), 'mov DWORD PTR [rbp-0x3c],r10d'),
    (0x5caddac, bytes.fromhex("b807000000"), 'mov eax,0x7'),
    (0x5caddb1, bytes.fromhex("31c9"), 'xor ecx,ecx'),
    (0x5caddb3, bytes.fromhex("4989da"), 'mov r10,rbx'),
    (0x5caddb6, bytes.fromhex("0fa2"), 'cpuid'),
    (0x5caddb8, bytes.fromhex("4c87d3"), 'xchg rbx,r10'),
    (0x5caddbb, bytes.fromhex("89d7"), 'mov edi,edx'),
    (0x5caddbd, bytes.fromhex("4189c8"), 'mov r8d,ecx'),
    (0x5caddc0, bytes.fromhex("b807000000"), 'mov eax,0x7'),
    (0x5caddc5, bytes.fromhex("b901000000"), 'mov ecx,0x1'),
    (0x5caddca, bytes.fromhex("4c89db"), 'mov rbx,r11'),
    (0x5caddcd, bytes.fromhex("4989db"), 'mov r11,rbx'),
    (0x5caddd0, bytes.fromhex("0fa2"), 'cpuid'),
    (0x5caddd2, bytes.fromhex("4c87db"), 'xchg rbx,r11'),
    (0x5caddd5, bytes.fromhex("4989db"), 'mov r11,rbx'),
    (0x5caddd8, bytes.fromhex("4589d5"), 'mov r13d,r10d'),
    (0x5cadddb, bytes.fromhex("4489c1"), 'mov ecx,r8d'),
    (0x5caddeb, bytes.fromhex("89f8"), 'mov eax,edi'),
    (0x5caddde, bytes.fromhex("48894da8"), 'mov QWORD PTR [rbp-0x58],rcx'),
    (0x5cadde4, bytes.fromhex("488945c8"), 'mov QWORD PTR [rbp-0x38],rax'),
    (0x5cadde8, bytes.fromhex("4189d2"), 'mov r10d,edx'),
    (0x5cadded, bytes.fromhex("488945b0"), 'mov QWORD PTR [rbp-0x50],rax'),
    (0x5caddf3, bytes.fromhex("31d2"), 'xor edx,edx'),
    (0x5caddfa, bytes.fromhex("48c745a800000000"), 'mov QWORD PTR [rbp-0x58],0x0'),
    (0x5cade02, bytes.fromhex("48c745b000000000"), 'mov QWORD PTR [rbp-0x50],0x0'),
    (0x5cade0a, bytes.fromhex("48c745c800000000"), 'mov QWORD PTR [rbp-0x38],0x0'),
    (0x5cade12, bytes.fromhex("4531d2"), 'xor r10d,r10d'),
    (0x5cade15, bytes.fromhex("49c1e320"), 'shl r11,0x20'),
    (0x5cade19, bytes.fromhex("31ff"), 'xor edi,edi'),
    (0x5cade1b, bytes.fromhex("31c9"), 'xor ecx,ecx'),
    (0x5cade1d, bytes.fromhex("b800000080"), 'mov eax,0x80000000'),
    (0x5cade22, bytes.fromhex("4989d8"), 'mov r8,rbx'),
    (0x5cade25, bytes.fromhex("0fa2"), 'cpuid'),
    (0x5cade27, bytes.fromhex("4c87c3"), 'xchg rbx,r8'),
    (0x5cade2c, bytes.fromhex("4c8955a0"), 'mov QWORD PTR [rbp-0x60],r10'),
    (0x5cade30, bytes.fromhex("7411"), 'je 5cade43 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x9a5ed>'),
    (0x5cade32, bytes.fromhex("31c9"), 'xor ecx,ecx'),
    (0x5cade34, bytes.fromhex("b801000080"), 'mov eax,0x80000001'),
    (0x5cade39, bytes.fromhex("4889df"), 'mov rdi,rbx'),
    (0x5cade3c, bytes.fromhex("0fa2"), 'cpuid'),
    (0x5cade3e, bytes.fromhex("4887fb"), 'xchg rbx,rdi'),
    (0x5cade41, bytes.fromhex("89cf"), 'mov edi,ecx'),
    (0x5cade43, bytes.fromhex("4d09cb"), 'or r11,r9'),
    (0x5cade46, bytes.fromhex("89f3"), 'mov ebx,esi'),
    (0x5cade48, bytes.fromhex("89f0"), 'mov eax,esi'),
    (0x5cade4a, bytes.fromhex("83e001"), 'and eax,0x1'),
    (0x5cade4d, bytes.fromhex("c1e008"), 'shl eax,0x8'),
    (0x5cade50, bytes.fromhex("89d9"), 'mov ecx,ebx'),
    (0x5cade52, bytes.fromhex("81e102020000"), 'and ecx,0x202'),
    (0x5cade58, bytes.fromhex("4809c1"), 'or rcx,rax'),
    (0x5cade5b, bytes.fromhex("4189f0"), 'mov r8d,esi'),
    (0x5cade5e, bytes.fromhex("41c1e80a"), 'shr r8d,0xa'),
    (0x5cade62, bytes.fromhex("4183e008"), 'and r8d,0x8'),
    (0x5cade66, bytes.fromhex("89f0"), 'mov eax,esi'),
    (0x5cade68, bytes.fromhex("c1e809"), 'shr eax,0x9'),
    (0x5cade6b, bytes.fromhex("89c2"), 'mov edx,eax'),
    (0x5cade6d, bytes.fromhex("81e200040000"), 'and edx,0x400'),
    (0x5cade73, bytes.fromhex("4809ca"), 'or rdx,rcx'),
    (0x5cade76, bytes.fromhex("2500080000"), 'and eax,0x800'),
    (0x5cade7b, bytes.fromhex("4809d0"), 'or rax,rdx'),
    (0x5cade7e, bytes.fromhex("89f2"), 'mov edx,esi'),
    (0x5cade80, bytes.fromhex("81e200004000"), 'and edx,0x400000'),
    (0x5cade86, bytes.fromhex("c1ea0e"), 'shr edx,0xe'),
    (0x5cade89, bytes.fromhex("4409c2"), 'or edx,r8d'),
    (0x5cade8c, bytes.fromhex("4989d8"), 'mov r8,rbx'),
    (0x5cade8f, bytes.fromhex("49c1e026"), 'shl r8,0x26'),
    (0x5cade93, bytes.fromhex("4489e1"), 'mov ecx,r12d'),
    (0x5cade96, bytes.fromhex("4909c8"), 'or r8,rcx'),
    (0x5cade99, bytes.fromhex("4589e9"), 'mov r9d,r13d'),
    (0x5cade9c, bytes.fromhex("41c1e90d"), 'shr r9d,0xd'),
    (0x5cadea0, bytes.fromhex("4183e140"), 'and r9d,0x40'),
    (0x5cadea4, bytes.fromhex("4109d1"), 'or r9d,edx'),
    (0x5cadea7, bytes.fromhex("4489ea"), 'mov edx,r13d'),
    (0x5cadeaa, bytes.fromhex("81e200080000"), 'and edx,0x800'),
    (0x5cadeb0, bytes.fromhex("c1ea04"), 'shr edx,0x4'),
    (0x5cadeb3, bytes.fromhex("4409ca"), 'or edx,r9d'),
    (0x5cadeb6, bytes.fromhex("4c8b75a8"), 'mov r14,QWORD PTR [rbp-0x58]'),
    (0x5cadeba, bytes.fromhex("4d89f7"), 'mov r15,r14'),
    (0x5cadebd, bytes.fromhex("49c1e716"), 'shl r15,0x16'),
    (0x5cadec1, bytes.fromhex("4589fa"), 'mov r10d,r15d'),
    (0x5cadec4, bytes.fromhex("4181e200000040"), 'and r10d,0x40000000'),
    (0x5cadecb, bytes.fromhex("4589e9"), 'mov r9d,r13d'),
    (0x5cadece, bytes.fromhex("4181e100010000"), 'and r9d,0x100'),
    (0x5caded5, bytes.fromhex("49c1e132"), 'shl r9,0x32'),
    (0x5caded9, bytes.fromhex("4d09d1"), 'or r9,r10'),
    (0x5cadedc, bytes.fromhex("4589fa"), 'mov r10d,r15d'),
    (0x5cadedf, bytes.fromhex("4181e200000080"), 'and r10d,0x80000000'),
    (0x5cadee6, bytes.fromhex("4d09d1"), 'or r9,r10'),
    (0x5cadee9, bytes.fromhex("49ba0000000001000000"), 'movabs r10,0x100000000'),
    (0x5cadef3, bytes.fromhex("4c897d98"), 'mov QWORD PTR [rbp-0x68],r15'),
    (0x5cadef7, bytes.fromhex("4d21fa"), 'and r10,r15'),
    (0x5cadefa, bytes.fromhex("4d09d1"), 'or r9,r10'),
    (0x5cadefd, bytes.fromhex("49ba1000000000000020"), 'movabs r10,0x2000000000000010'),
    (0x5cadf07, bytes.fromhex("4d21c2"), 'and r10,r8'),
    (0x5cadf0a, bytes.fromhex("4189f0"), 'mov r8d,esi'),
    (0x5cadf0d, bytes.fromhex("41c1e819"), 'shr r8d,0x19'),
    (0x5cadf11, bytes.fromhex("4183e001"), 'and r8d,0x1'),
    (0x5cadf15, bytes.fromhex("4d09c2"), 'or r10,r8'),
    (0x5cadf18, bytes.fromhex("4189d8"), 'mov r8d,ebx'),
    (0x5cadf1b, bytes.fromhex("4181e000000020"), 'and r8d,0x20000000'),
    (0x5cadf22, bytes.fromhex("49c1e01a"), 'shl r8,0x1a'),
    (0x5cadf26, bytes.fromhex("4d09c2"), 'or r10,r8'),
    (0x5cadf29, bytes.fromhex("c1ee1c"), 'shr esi,0x1c'),
    (0x5cadf2c, bytes.fromhex("83e604"), 'and esi,0x4'),
    (0x5cadf2f, bytes.fromhex("4909f2"), 'or r10,rsi'),
    (0x5cadf32, bytes.fromhex("4489e6"), 'mov esi,r12d'),
    (0x5cadf35, bytes.fromhex("c1ee12"), 'shr esi,0x12'),
    (0x5cadf38, bytes.fromhex("83e620"), 'and esi,0x20'),
    (0x5cadf3b, bytes.fromhex("4909f2"), 'or r10,rsi'),
    (0x5cadf3e, bytes.fromhex("81e100000001"), 'and ecx,0x1000000'),
    (0x5cadf44, bytes.fromhex("48c1e126"), 'shl rcx,0x26'),
    (0x5cadf48, bytes.fromhex("4909ca"), 'or r10,rcx'),
    (0x5cadf4b, bytes.fromhex("41c1ec13"), 'shr r12d,0x13'),
    (0x5cadf4f, bytes.fromhex("4181e4c0000000"), 'and r12d,0xc0'),
    (0x5cadf56, bytes.fromhex("4909c4"), 'or r12,rax'),
    (0x5cadf59, bytes.fromhex("4489e8"), 'mov eax,r13d'),
    (0x5cadf5c, bytes.fromhex("c1e80f"), 'shr eax,0xf'),
    (0x5cadf5f, bytes.fromhex("83e008"), 'and eax,0x8'),
    (0x5cadf62, bytes.fromhex("4909c4"), 'or r12,rax'),
    (0x5cadf65, bytes.fromhex("4489e8"), 'mov eax,r13d'),
    (0x5cadf68, bytes.fromhex("c1e810"), 'shr eax,0x10'),
    (0x5cadf6b, bytes.fromhex("2500200000"), 'and eax,0x2000'),
    (0x5cadf70, bytes.fromhex("4909c4"), 'or r12,rax'),
    (0x5cadf73, bytes.fromhex("4489e8"), 'mov eax,r13d'),
    (0x5cadf76, bytes.fromhex("83e008"), 'and eax,0x8'),
    (0x5cadf79, bytes.fromhex("48c1e036"), 'shl rax,0x36'),
    (0x5cadf7d, bytes.fromhex("4909c4"), 'or r12,rax'),
    (0x5cadf80, bytes.fromhex("4d09d4"), 'or r12,r10'),
    (0x5cadf83, bytes.fromhex("4d09cc"), 'or r12,r9'),
    (0x5cadf86, bytes.fromhex("4489e8"), 'mov eax,r13d'),
    (0x5cadf89, bytes.fromhex("2500020000"), 'and eax,0x200'),
    (0x5cadf8e, bytes.fromhex("8d0442"), 'lea eax,[rdx+rax*2]'),
    (0x5cadf91, bytes.fromhex("4989c7"), 'mov r15,rax'),
    (0x5cadf94, bytes.fromhex("4981cf00020000"), 'or r15,0x200'),
    (0x5cadf9b, bytes.fromhex("f745c800000080"), 'test DWORD PTR [rbp-0x38],0x80000000'),
    (0x5cadfa2, bytes.fromhex("4c0f44f8"), 'cmove r15,rax'),
    (0x5cadfa6, bytes.fromhex("41f7c600008000"), 'test r14d,0x800000'),
    (0x5cadfaf, bytes.fromhex("b819000000"), 'mov eax,0x19'),
    (0x5cadfb4, bytes.fromhex("31c9"), 'xor ecx,ecx'),
    (0x5cadfb9, bytes.fromhex("0fa2"), 'cpuid'),
    (0x5cadfbe, bytes.fromhex("89f0"), 'mov eax,esi'),
    (0x5cadfc0, bytes.fromhex("83e001"), 'and eax,0x1'),
    (0x5cadfc3, bytes.fromhex("c1e004"), 'shl eax,0x4'),
    (0x5cadfc6, bytes.fromhex("83e604"), 'and esi,0x4'),
    (0x5cadfc9, bytes.fromhex("8d04f0"), 'lea eax,[rax+rsi*8]'),
    (0x5cadfcc, bytes.fromhex("4909c7"), 'or r15,rax'),
    (0x5cadfcf, bytes.fromhex("448b45d4"), 'mov r8d,DWORD PTR [rbp-0x2c]'),
    (0x5cadfd3, bytes.fromhex("89f8"), 'mov eax,edi'),
    (0x5cadfd5, bytes.fromhex("83e020"), 'and eax,0x20'),
    (0x5cadfd8, bytes.fromhex("48c1e036"), 'shl rax,0x36'),
    (0x5cadfdc, bytes.fromhex("4909c4"), 'or r12,rax'),
    (0x5cadfdf, bytes.fromhex("48b841757468656e7469"), 'movabs rax,0x69746e6568747541'),
    (0x5cadfe9, bytes.fromhex("4c31d8"), 'xor rax,r11'),
    (0x5cadfec, bytes.fromhex("4489c1"), 'mov ecx,r8d'),
    (0x5cadfef, bytes.fromhex("4881f163414d44"), 'xor rcx,0x444d4163'),
    (0x5cadff6, bytes.fromhex("4809c1"), 'or rcx,rax'),
    (0x5cadff9, bytes.fromhex("741b"), 'je 5cae016 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x9a41a>'),
    (0x5cadffb, bytes.fromhex("4489c0"), 'mov eax,r8d'),
    (0x5cadffe, bytes.fromhex("48b94879676f6e47656e"), 'movabs rcx,0x6e65476e6f677948'),
    (0x5cae008, bytes.fromhex("4c31d9"), 'xor rcx,r11'),
    (0x5cae00b, bytes.fromhex("483575696e65"), 'xor rax,0x656e6975'),
    (0x5cae011, bytes.fromhex("4809c8"), 'or rax,rcx'),
    (0x5cae016, bytes.fromhex("89f8"), 'mov eax,edi'),
    (0x5cae018, bytes.fromhex("83e040"), 'and eax,0x40'),
    (0x5cae01b, bytes.fromhex("c1e006"), 'shl eax,0x6'),
    (0x5cae01e, bytes.fromhex("89f9"), 'mov ecx,edi'),
    (0x5cae020, bytes.fromhex("81e100002000"), 'and ecx,0x200000'),
    (0x5cae026, bytes.fromhex("48c1e127"), 'shl rcx,0x27'),
    (0x5cae02a, bytes.fromhex("4809c1"), 'or rcx,rax'),
    (0x5cae02d, bytes.fromhex("81e700080000"), 'and edi,0x800'),
    (0x5cae033, bytes.fromhex("4909ff"), 'or r15,rdi'),
    (0x5cae036, bytes.fromhex("4909cc"), 'or r12,rcx'),
    (0x5cae039, bytes.fromhex("89d8"), 'mov eax,ebx'),
    (0x5cae03b, bytes.fromhex("f7d0"), 'not eax'),
    (0x5cae03d, bytes.fromhex("a90000000c"), 'test eax,0xc000000'),
    (0x5cae042, bytes.fromhex("0f8509020000"), 'jne 5cae251 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x9a1df>'),
    (0x5cae048, bytes.fromhex("4c895db8"), 'mov QWORD PTR [rbp-0x48],r11'),
    (0x5cae328, bytes.fromhex("f7c300000800"), 'test ebx,0x80000'),
    (0x5cae32e, bytes.fromhex("742e"), 'je 5cae35e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x9a0d2>'),
    (0x5cae330, bytes.fromhex("b824000000"), 'mov eax,0x24'),
    (0x5cae335, bytes.fromhex("31c9"), 'xor ecx,ecx'),
    (0x5cae337, bytes.fromhex("4889de"), 'mov rsi,rbx'),
    (0x5cae33a, bytes.fromhex("0fa2"), 'cpuid'),
    (0x5cae33c, bytes.fromhex("4887f3"), 'xchg rbx,rsi'),
    (0x5cae33f, bytes.fromhex("40f6c6fe"), 'test sil,0xfe'),
    (0x5cae343, bytes.fromhex("48b80000000000002000"), 'movabs rax,0x20000000000000'),
    (0x5cae34d, bytes.fromhex("48b90000000000006000"), 'movabs rcx,0x60000000000000'),
    (0x5cae357, bytes.fromhex("480f44c8"), 'cmove rcx,rax'),
    (0x5cae35b, bytes.fromhex("4909cc"), 'or r12,rcx'),
    (0x5cae35e, bytes.fromhex("48b847656e75696e6549"), 'movabs rax,0x49656e69756e6547'),
    (0x5cae368, bytes.fromhex("4931c3"), 'xor r11,rax'),
    (0x5cae36b, bytes.fromhex("4489c0"), 'mov eax,r8d'),
    (0x5cae36e, bytes.fromhex("48356e74656c"), 'xor rax,0x6c65746e'),
    (0x5cae374, bytes.fromhex("4c09d8"), 'or rax,r11'),
    (0x5cae377, bytes.fromhex("4489e1"), 'mov ecx,r12d'),
    (0x5cae37a, bytes.fromhex("81e100400000"), 'and ecx,0x4000'),
    (0x5cae380, bytes.fromhex("49bdffbffffffffffff9"), 'movabs r13,0xf9ffffffffffbfff'),
    (0x5cae38a, bytes.fromhex("4d21e5"), 'and r13,r12'),
    (0x5cae38d, bytes.fromhex("4809c1"), 'or rcx,rax'),
    (0x5cae390, bytes.fromhex("4489fa"), 'mov edx,r15d'),
    (0x5cae393, bytes.fromhex("4d0f45ec"), 'cmovne r13,r12'),
    (0x5cae397, bytes.fromhex("490f45d7"), 'cmovne rdx,r15'),
]

BRANCHES = [
    (0x5CADD7C, 2, 0x5CADDF3),   # max leaf zero path
    (0x5CADDAA, 2, 0x5CADDFA),   # max leaf below 7 path
    (0x5CADDF5, 5, 0x5CAE39B),   # early b / max leaf zero to suffix
    (0x5CADE30, 2, 0x5CADE43),   # maximum extended leaf zero
    (0x5CADFAD, 2, 0x5CADFCF),   # leaf 0x19 gate (leaf 7.0 ecx bit 23)
    (0x5CADFF9, 2, 0x5CAE016),   # amd vendor match
    (0x5CAE014, 2, 0x5CAE039),   # vendor mismatch to region gate
    (0x5CAE042, 6, 0x5CAE251),   # region gate fail to selection
    (0x5CAE32E, 2, 0x5CAE35E),   # leaf 0x24 gate to selection
]

R12_WRITES = [0x5CADD99, 0x5CADF4B, 0x5CADF4F, 0x5CADF56, 0x5CADF62, 0x5CADF70,
              0x5CADF7D, 0x5CADF80, 0x5CADF83, 0x5CADFDC, 0x5CAE036, 0x5CAE07B,
              0x5CAE09F, 0x5CAE13B, 0x5CAE13E, 0x5CAE142, 0x5CAE146, 0x5CAE149,
              0x5CAE14C, 0x5CAE14F, 0x5CAE1C0, 0x5CAE223, 0x5CAE227, 0x5CAE22A,
              0x5CAE22D, 0x5CAE230, 0x5CAE233, 0x5CAE236, 0x5CAE239, 0x5CAE2AF,
              0x5CAE2F0, 0x5CAE315, 0x5CAE31F, 0x5CAE324, 0x5CAE35B]
R15_WRITES = [0x5CADEBA, 0x5CADEBD, 0x5CADF91, 0x5CADF94, 0x5CADFA2, 0x5CADFCC,
              0x5CAE033, 0x5CAE0BA]
R13_WRITES = [0x5CADD6D, 0x5CADDD8, 0x5CAE380, 0x5CAE38A, 0x5CAE393]
R14_MENTIONS = [0x5CADEB6, 0x5CADEBA, 0x5CADFA6, 0x5CAE051, 0x5CAE054, 0x5CAE067,
                0x5CAE300]
SLOT_STORES = {
    "rbp-0x2c": [0x5CADDA2],
    "rbp-0x38": [0x5CADDE4, 0x5CADE0A],
    "rbp-0x3c": [0x5CADDA6],
    "rbp-0x48": [0x5CAE048],
    "rbp-0x50": [0x5CADDED, 0x5CADE02],
    "rbp-0x58": [0x5CADDDE, 0x5CADDFA],
    "rbp-0x60": [0x5CADE2C],
    "rbp-0x68": [0x5CADEF3],
}
SLOT_LOADS = {
    "rbp-0x2c": [0x5CADFCF, 0x5CAE240, 0x5CAE264],
    "rbp-0x38": [0x5CADF9B, 0x5CAE0BD, 0x5CAE290],
    "rbp-0x3c": [0x5CAE07E, 0x5CAE2B2],
    "rbp-0x48": [0x5CAE23C, 0x5CAE260],
    "rbp-0x50": [0x5CAE1F6, 0x5CAE274],
    "rbp-0x58": [0x5CADEB6, 0x5CAE1D3],
    "rbp-0x60": [0x5CAE110, 0x5CAE268],
    "rbp-0x68": [0x5CAE223],
}
REG64 = {"rax": "rax", "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
         "rbx": "rbx", "ebx": "rbx", "bx": "rbx", "bl": "rbx", "bh": "rbx",
         "rcx": "rcx", "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
         "rdx": "rdx", "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
         "rsi": "rsi", "esi": "rsi", "si": "rsi", "sil": "rsi",
         "rdi": "rdi", "edi": "rdi", "di": "rdi", "dil": "rdi",
         "rbp": "rbp", "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
         "rsp": "rsp", "esp": "rsp", "sp": "rsp", "spl": "rsp"}
for _i in range(8, 16):
    for _s in ("", "d", "w", "b"):
        REG64[f"r{_i}{_s}"] = f"r{_i}"
REG_TOKEN = re.compile(
    r"(?<![a-z0-9])(r1[0-5][dwb]?|r[8-9][dwb]?|rax|eax|ax|al|ah|rcx|ecx|cx|cl|ch|rdx|edx|dx|dl|dh|"
    r"rbx|ebx|bx|bl|bh|rsp|esp|sp|spl|rbp|ebp|bp|bpl|rsi|esi|si|sil|rdi|edi|di|dil)(?![a-z0-9])")
WRITE_MNEMONICS = {"mov", "movabs", "or", "and", "xor", "shl", "shr", "sar", "lea",
                   "add", "sub", "cmove", "cmovne", "cmovb", "cmovae", "cmovo",
                   "cmovno", "cmovs", "cmovns", "cmova", "cmovbe", "cmovg",
                   "cmovge", "cmovl", "cmovle", "xchg", "not", "neg", "inc", "dec"}


def reg_tokens(operands):
    return {REG64[t] for t in REG_TOKEN.findall(operands)}


def dest_reg(mnemonic, operands):
    if mnemonic not in WRITE_MNEMONICS or not operands:
        return None
    first = operands.split(",")[0].strip()
    toks = REG_TOKEN.findall(first)
    if len(toks) == 1 and first == toks[0]:
        return REG64[toks[0]]
    return None


def parse_text(asm):
    """Parse an objdump export into {address: (mnemonic, operands)}."""
    out = {}
    for line in asm.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)(.*)$", line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        rest = m.group(3).strip()
        if not rest:
            continue
        parts = rest.split(None, 1)
        out[addr] = (parts[0], parts[1] if len(parts) > 1 else "")
    return out


def trace(data):
    secs = sections(data)
    owners = {}
    for role, (a, b, digest) in OWNERS.items():
        body = read(data, a, b - a)[1]
        if sha256(body) != digest:
            raise ValueError(f"node115 cpuid field map owner body changed: {role}")
        owners[role] = {"range": f"{a:#x}..{b:#x}", "sha256": digest}
    _, fs, _ = fde_extents(data)
    exts = {(f["start"], f["end"]) for f in fs}
    for role, (a, b, _) in OWNERS.items():
        if (a, b) not in exts:
            raise ValueError(f"node115 cpuid field map owner FDE changed: {role}")
    return owners


def native_censuses(ins):
    a, b = HELPER
    addrs = sorted(x for x in ins if a <= x < b)
    cpuid_sites = [x for x in addrs if ins[x][0] == "cpuid"]
    if cpuid_sites != sorted(SITE_LEAVES):
        raise ValueError("node115 cpuid field map CPUID site census changed")
    stores, loads = {}, {}
    for x in addrs:
        mn, ops = ins[x]
        for idx, op in enumerate(split_ops(ops)):
            k = slot_key(op)
            if not k:
                continue
            if idx == 0 and mn in ("mov", "movabs"):
                stores.setdefault(k, []).append(x)
            else:
                loads.setdefault(k, []).append(x)
    if stores != SLOT_STORES:
        raise ValueError("node115 cpuid field map slot store census changed")
    if loads != SLOT_LOADS:
        raise ValueError("node115 cpuid field map slot load census changed")
    writes = {}
    for name, reg in (("r12", "r12"), ("r15", "r15"), ("r13", "r13")):
        writes[name] = [x for x in addrs if dest_reg(*ins[x]) == reg]
    if writes["r12"] != R12_WRITES:
        raise ValueError("node115 cpuid field map R12 write census changed")
    if writes["r15"] != R15_WRITES:
        raise ValueError("node115 cpuid field map R15 write census changed")
    if writes["r13"] != R13_WRITES:
        raise ValueError("node115 cpuid field map R13 write census changed")
    mentions = [x for x in addrs
                if ins[x][0] not in ("push", "pop") and "r14" in reg_tokens(ins[x][1])]
    if mentions != R14_MENTIONS:
        raise ValueError("node115 cpuid field map R14 mention census changed")
    return {
        "cpuid_sites": [f"{x:#x}" for x in cpuid_sites],
        "slot_stores": {k: [f"{x:#x}" for x in v] for k, v in stores.items()},
        "slot_loads": {k: [f"{x:#x}" for x in v] for k, v in loads.items()},
        "r12_writes": [f"{x:#x}" for x in writes["r12"]],
        "r15_writes": [f"{x:#x}" for x in writes["r15"]],
        "r13_writes": [f"{x:#x}" for x in writes["r13"]],
        "r14_mentions": [f"{x:#x}" for x in mentions],
    }


def call_census(data):
    import struct
    text = next(s for s in sections(data) if s["name"] == ".text")
    body = data[text["offset"]:text["offset"] + text["size"]]
    base = text["address"]
    sites = []
    index = body.find(b"\xe8")
    while index != -1:
        if base + index + 5 + struct.unpack_from("<i", body, index + 1)[0] == XCR0_LEAF[0]:
            sites.append(base + index)
        index = body.find(b"\xe8", index + 1)
    sec = next(s for s in sections(data) if s["name"] == ".rela.dyn")
    rela_hits = 0
    for a, i, v in struct.iter_unpack("<QQq", data[sec["offset"]:sec["offset"] + sec["size"]]):
        if v == XCR0_LEAF[0]:
            rela_hits += 1
    return sites, rela_hits


# ---------------------------------------------------------------------------
# Per-bit provenance fixpoint.
#
# For every register bit and named stack slot the analysis tracks two atom
# sets: value provenance (inputs the bit's value can depend on) and
# condition provenance (inputs that selected the bit through a conditional
# move whose arms' value provenance for that bit differs).  sete writes the
# flag result as data, so its condition input is value provenance.  A known
# constant value is tracked alongside, which keeps and/or/xor with a
# constant operand bit-exact.  add uses the generate/propagate carry rule;
# adding a register to itself keeps only the carry chain, since the two
# operand bits cancel.
# ---------------------------------------------------------------------------

BASES = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"] + [f"r{i}" for i in range(8, 16)]
REGINFO = {}


def _reg(base, names_sizes):
    for name, (w, o) in names_sizes.items():
        REGINFO[name] = (base, w, o)


_reg("rax", {"rax": (64, 0), "eax": (32, 0), "ax": (16, 0), "al": (8, 0), "ah": (8, 8)})
_reg("rbx", {"rbx": (64, 0), "ebx": (32, 0), "bx": (16, 0), "bl": (8, 0), "bh": (8, 8)})
_reg("rcx", {"rcx": (64, 0), "ecx": (32, 0), "cx": (16, 0), "cl": (8, 0), "ch": (8, 8)})
_reg("rdx", {"rdx": (64, 0), "edx": (32, 0), "dx": (16, 0), "dl": (8, 0), "dh": (8, 8)})
_reg("rsi", {"rsi": (64, 0), "esi": (32, 0), "si": (16, 0), "sil": (8, 0)})
_reg("rdi", {"rdi": (64, 0), "edi": (32, 0), "di": (16, 0), "dil": (8, 0)})
_reg("rbp", {"rbp": (64, 0), "ebp": (32, 0), "bp": (16, 0), "bpl": (8, 0)})
_reg("rsp", {"rsp": (64, 0), "esp": (32, 0), "sp": (16, 0), "spl": (8, 0)})
for _i in range(8, 16):
    _reg(f"r{_i}", {f"r{_i}": (64, 0), f"r{_i}d": (32, 0), f"r{_i}w": (16, 0), f"r{_i}b": (8, 0)})

SLOT_RE = re.compile(r"\[rbp-(0x[0-9a-f]+)\]")
SIZE_RE = re.compile(r"(BYTE|WORD|DWORD|QWORD) PTR")
BRANCH_MNEMONICS = {"jmp", "je", "jne", "jb", "jbe", "ja", "jae", "jl", "jle",
                    "jg", "jge", "js", "jns", "jo", "jno", "jp", "jnp", "jcxz", "jecxz"}


def split_ops(ops):
    parts, depth, cur = [], 0, ""
    for ch in ops:
        if ch == "[":
            depth += 1
        if ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts


def slot_key(op):
    m = SLOT_RE.search(op)
    return f"rbp-{m.group(1)}" if m else None


def op_size(op, default=64):
    m = SIZE_RE.search(op)
    return {"BYTE": 8, "WORD": 16, "DWORD": 32, "QWORD": 64}[m.group(1)] if m else default


class ProvState:
    __slots__ = ("V", "C", "vals", "sV", "sC", "zf", "cf")

    def __init__(self):
        self.V = {b: [EMPTY] * 64 for b in BASES}
        self.C = {b: [EMPTY] * 64 for b in BASES}
        self.vals = {b: None for b in BASES}
        self.sV = {}
        self.sC = {}
        self.zf = EMPTY
        self.cf = EMPTY

    def copy(self):
        s = ProvState()
        s.V = {b: list(v) for b, v in self.V.items()}
        s.C = {b: list(v) for b, v in self.C.items()}
        s.vals = dict(self.vals)
        s.sV = {k: list(v) for k, v in self.sV.items()}
        s.sC = {k: list(v) for k, v in self.sC.items()}
        s.zf = self.zf
        s.cf = self.cf
        return s

    def merge(self, other):
        changed = False
        for b in BASES:
            for store, ostore in ((self.V, other.V), (self.C, other.C)):
                for i in range(64):
                    u = store[b][i] | ostore[b][i]
                    if u != store[b][i]:
                        store[b][i] = u
                        changed = True
            if self.vals[b] != other.vals[b]:
                self.vals[b] = self.vals[b] if self.vals[b] == other.vals[b] else None
        for k in other.sV:
            if k not in self.sV:
                self.sV[k] = list(other.sV[k])
                self.sC[k] = list(other.sC[k])
                changed = True
            else:
                for store, ostore in ((self.sV, other.sV), (self.sC, other.sC)):
                    for i in range(64):
                        u = store[k][i] | ostore[k][i]
                        if u != store[k][i]:
                            store[k][i] = u
                            changed = True
        u = self.zf | other.zf
        if u != self.zf:
            self.zf = u
            changed = True
        u = self.cf | other.cf
        if u != self.cf:
            self.cf = u
            changed = True
        return changed


def read_reg(st, name):
    base, w, o = REGINFO[name]
    V = [st.V[base][o + i] for i in range(w)] + [EMPTY] * (64 - w)
    C = [st.C[base][o + i] for i in range(w)] + [EMPTY] * (64 - w)
    val = None
    if st.vals[base] is not None:
        val = (st.vals[base] >> o) & ((1 << w) - 1)
    return V, C, val


def write_reg(st, name, V, C, val):
    base, w, o = REGINFO[name]
    if w == 64:
        st.V[base] = list(V[:64])
        st.C[base] = list(C[:64])
        st.vals[base] = val
    elif w == 32:
        st.V[base] = list(V[:32]) + [EMPTY] * 32
        st.C[base] = list(C[:32]) + [EMPTY] * 32
        st.vals[base] = val
    else:
        for i in range(w):
            st.V[base][o + i] = V[i]
            st.C[base][o + i] = C[i]
        if st.vals[base] is not None and val is not None:
            mask = ((1 << w) - 1) << o
            st.vals[base] = (st.vals[base] & ~mask) | ((val << o) & mask)
        else:
            st.vals[base] = None


def read_op(st, op):
    op = op.strip()
    if op in REGINFO:
        return read_reg(st, op)
    if op.startswith("0x") or op.startswith("-0x") or re.fullmatch(r"-?\d+", op):
        v = int(op, 0) & 0xFFFFFFFFFFFFFFFF
        return [frozenset({CONST}) if (v >> i) & 1 else EMPTY for i in range(64)], [EMPTY] * 64, v
    if "[" in op:
        key = slot_key(op)
        if key is not None:
            w = op_size(op)
            V = st.sV.get(key, [EMPTY] * 64)
            C = st.sC.get(key, [EMPTY] * 64)
            return ([V[i] if i < w else EMPTY for i in range(64)],
                    [C[i] if i < w else EMPTY for i in range(64)], None)
        return [EMPTY] * 64, [EMPTY] * 64, None
    raise ValueError(f"node115 cpuid field map unhandled operand {op!r}")


def write_op(st, op, V, C, val):
    op = op.strip()
    if op in REGINFO:
        write_reg(st, op, V, C, val)
        return
    if "[" in op:
        key = slot_key(op)
        if key is not None:
            w = op_size(op)
            vecV = st.sV.setdefault(key, [EMPTY] * 64)
            vecC = st.sC.setdefault(key, [EMPTY] * 64)
            if w == 64:
                st.sV[key] = list(V[:64])
                st.sC[key] = list(C[:64])
            else:
                for i in range(w):
                    vecV[i] = V[i]
                    vecC[i] = C[i]
                if w == 32:
                    for i in range(32, 64):
                        vecV[i] = EMPTY
                        vecC[i] = EMPTY
            return
        return
    raise ValueError(f"node115 cpuid field map unhandled dest {op!r}")


def can_one(P, val, i):
    return bool(P[i]) or (val is not None and (val >> i) & 1 == 1)


def combine(op, pa, va, pb, vb):
    out = []
    for i in range(64):
        if op == "or":
            if va is not None:
                out.append(frozenset({CONST}) if (va >> i) & 1 else pb[i])
            elif vb is not None:
                out.append(frozenset({CONST}) if (vb >> i) & 1 else pa[i])
            else:
                out.append(pa[i] | pb[i])
        elif op == "and":
            if va is not None:
                out.append(pb[i] if (va >> i) & 1 else EMPTY)
            elif vb is not None:
                out.append(pa[i] if (vb >> i) & 1 else EMPTY)
            else:
                out.append(pa[i] | pb[i] if pa[i] and pb[i] else EMPTY)
        elif op == "xor":
            if va is not None:
                out.append(pb[i] if pb[i] else (frozenset({CONST}) if (va >> i) & 1 else EMPTY))
            elif vb is not None:
                out.append(pa[i] if pa[i] else (frozenset({CONST}) if (vb >> i) & 1 else EMPTY))
            else:
                out.append(pa[i] | pb[i])
    val = None
    if va is not None and vb is not None:
        val = {"or": va | vb, "and": va & vb, "xor": va ^ vb}[op] & 0xFFFFFFFFFFFFFFFF
    return out, val


def lea_prov(st, op):
    inner = op[op.index("[") + 1:op.rindex("]")]
    if "rip" in inner:
        return [EMPTY] * 64, [EMPTY] * 64, None
    V = [EMPTY] * 64
    C = [EMPTY] * 64
    for p in inner.replace("-", "+-").split("+"):
        p = p.strip()
        if not p:
            continue
        if "*" in p:
            reg, scale = p.split("*")
            rp, cp, _ = read_reg(st, reg.strip())
            sh = {1: 0, 2: 1, 4: 2, 8: 3}[int(scale.strip(), 0)]
            for i in range(64):
                if i - sh >= 0:
                    V[i] = V[i] | rp[i - sh]
                    C[i] = C[i] | cp[i - sh]
        elif p in REGINFO:
            rp, cp, _ = read_reg(st, p)
            for i in range(64):
                V[i] = V[i] | rp[i]
                C[i] = C[i] | cp[i]
    return V, C, None


def flag_union(st, opsl):
    out = []
    for op in opsl[:2]:
        V, C, val = read_op(st, op)
        out.append(([V[i] | C[i] for i in range(64)], val))
    return out


def prov_transfer(st, va, mn, ops):
    opsl = split_ops(ops) if ops else []
    if mn in ("mov", "movabs"):
        src = opsl[1]
        if "[" in src and slot_key(src) is None:
            if opsl[0] in REGINFO:
                write_reg(st, opsl[0], [EMPTY] * 64, [EMPTY] * 64, None)
            return
        V, C, val = read_op(st, src)
        if opsl[0] in REGINFO:
            base, w, o = REGINFO[opsl[0]]
            if w == 32 and val is not None:
                val &= 0xFFFFFFFF
            write_reg(st, opsl[0], V, C, val)
        else:
            write_op(st, opsl[0], V, C, val)
        return
    if mn == "movsxd":
        V, C, val = read_op(st, opsl[1])
        oV = V[:32] + [V[31]] * 32
        oC = C[:32] + [C[31]] * 32
        v = None
        if val is not None:
            v = val & 0xFFFFFFFF
            if v & 0x80000000:
                v |= 0xFFFFFFFF00000000
        write_reg(st, opsl[0], oV, oC, v)
        return
    if mn in ("and", "or", "xor"):
        if opsl[0] in REGINFO and opsl[1] == opsl[0] and mn == "xor":
            write_reg(st, opsl[0], [EMPTY] * 64, [EMPTY] * 64, 0)
            return
        Va, Ca, va = read_op(st, opsl[0])
        Vb, Cb, vb = read_op(st, opsl[1])
        V, val = combine(mn, Va, va, Vb, vb)
        C, _ = combine(mn, Ca, va, Cb, vb)
        if opsl[0] in REGINFO:
            base, w, o = REGINFO[opsl[0]]
            if w == 32 and val is not None:
                val &= 0xFFFFFFFF
            write_reg(st, opsl[0], V, C, val)
        else:
            write_op(st, opsl[0], V, C, val)
        return
    if mn in ("shl", "shr"):
        Va, Ca, va = read_op(st, opsl[0])
        cnt = int(opsl[1], 0)
        base, w, o = REGINFO[opsl[0]]
        if mn == "shl":
            V = [Va[i - cnt] if i - cnt >= 0 else EMPTY for i in range(64)]
            C = [Ca[i - cnt] if i - cnt >= 0 else EMPTY for i in range(64)]
            v = (va << cnt) & 0xFFFFFFFFFFFFFFFF if va is not None else None
        else:
            V = [Va[i + cnt] if i + cnt < 64 else EMPTY for i in range(64)]
            C = [Ca[i + cnt] if i + cnt < 64 else EMPTY for i in range(64)]
            v = (va & ((1 << w) - 1)) >> cnt if va is not None else None
        if w == 32 and v is not None:
            v &= 0xFFFFFFFF
        write_reg(st, opsl[0], V, C, v)
        return
    if mn == "add":
        if opsl[0] in REGINFO:
            Va, Ca, va = read_op(st, opsl[0])
            Vb, Cb, vb = read_op(st, opsl[1])
            same = opsl[0] == opsl[1]

            def chain_carry(Pa, Pb, val_a, val_b):
                carry = [EMPTY] * 65
                for i in range(64):
                    c = EMPTY
                    for j in range(i):
                        if can_one(Pa, val_a, j) and can_one(Pb, val_b, j):
                            prov = Pa[j] | Pb[j]
                            ok = True
                            for k in range(j + 1, i):
                                if can_one(Pa, val_a, k) or can_one(Pb, val_b, k):
                                    prov = prov | Pa[k] | Pb[k]
                                else:
                                    ok = False
                                    break
                            if ok:
                                c = c | prov
                    carry[i] = c
                return carry

            carryV = chain_carry(Va, Vb, va, vb)
            carryC = chain_carry(Ca, Cb, va, vb)
            V = []
            C = []
            for i in range(64):
                if same:
                    V.append(carryV[i])
                    C.append(carryC[i])
                else:
                    V.append(Va[i] | Vb[i] | carryV[i])
                    C.append(Ca[i] | Cb[i] | carryC[i])
            v = (va + vb) & 0xFFFFFFFFFFFFFFFF if va is not None and vb is not None else None
            base, w, o = REGINFO[opsl[0]]
            if w == 32 and v is not None:
                v &= 0xFFFFFFFF
            write_reg(st, opsl[0], V, C, v)
        return
    if mn == "sub":
        return
    if mn == "lea":
        V, C, val = lea_prov(st, opsl[1])
        write_reg(st, opsl[0], V, C, val)
        return
    if mn == "test":
        (Pa, va), (Pb, vb) = flag_union(st, opsl)
        zf = EMPTY
        for i in range(64):
            if can_one(Pa, va, i) and can_one(Pb, vb, i):
                zf = zf | Pa[i] | Pb[i]
        st.zf = zf
        st.cf = EMPTY
        return
    if mn == "cmp":
        (Pa, va), (Pb, vb) = flag_union(st, opsl)
        u = EMPTY
        for i in range(64):
            u = u | Pa[i] | Pb[i]
        st.zf = u
        st.cf = u
        return
    if mn.startswith("cmov"):
        cond = {"cmove": st.zf, "cmovne": st.zf, "cmovb": st.cf,
                "cmovbe": st.cf | st.zf, "cmova": st.cf, "cmovae": st.cf,
                "cmovl": st.cf, "cmovle": st.cf | st.zf,
                "cmovg": st.cf, "cmovge": st.cf}.get(mn, st.zf | st.cf)
        Va, Ca, va = read_op(st, opsl[0])
        Vb, Cb, vb = read_op(st, opsl[1])
        V = [Va[i] | Vb[i] for i in range(64)]
        C = []
        for i in range(64):
            differ = Va[i] != Vb[i] or (va is not None and vb is not None
                                        and ((va >> i) & 1) != ((vb >> i) & 1))
            C.append(Ca[i] | Cb[i] | (cond if differ else EMPTY))
        write_reg(st, opsl[0], V, C, None)
        return
    if mn.startswith("set"):
        cond = st.zf if mn in ("sete", "setne") else (st.cf if mn == "setb" else st.cf | st.zf)
        V = [cond] + [EMPTY] * 63
        write_reg(st, opsl[0], V, [EMPTY] * 64, None)
        return
    if mn == "not":
        V, C, val = read_op(st, opsl[0])
        v = (~val) & 0xFFFFFFFFFFFFFFFF if val is not None else None
        write_reg(st, opsl[0], V, C, v)
        return
    if mn == "xchg":
        Va, Ca, va = read_op(st, opsl[0])
        Vb, Cb, vb = read_op(st, opsl[1])
        write_reg(st, opsl[0], Vb, Cb, vb)
        write_reg(st, opsl[1], Va, Ca, va)
        return
    if mn == "cpuid":
        leaf, sub = SITE_LEAVES[va]
        for regname, base in (("eax", "rax"), ("ebx", "rbx"), ("ecx", "rcx"), ("edx", "rdx")):
            st.V[base] = [frozenset({("cpuid", leaf, sub, regname, i)}) for i in range(64)]
            st.C[base] = [EMPTY] * 64
            st.vals[base] = None
        return
    if mn == "call":
        if va != CALL_SITE:
            raise ValueError("node115 cpuid field map unexpected call site")
        st.V["rax"] = [frozenset({("xcr0", i)}) for i in range(64)]
        st.C["rax"] = [EMPTY] * 64
        st.vals["rax"] = None
        for b in ("rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"):
            st.V[b] = [p | {CALL} for p in st.V[b]]
            st.vals[b] = None
        return
    if mn == "push":
        return
    if mn == "pop":
        write_reg(st, opsl[0], [frozenset({CALL})] * 64, [EMPTY] * 64, None)
        return
    if mn == "shld":
        Va, Ca, va = read_op(st, opsl[0])
        Vb, Cb, vb = read_op(st, opsl[1])
        cnt = int(opsl[2], 0)
        V = []
        C = []
        for i in range(64):
            if i - cnt >= 0:
                V.append(Va[i - cnt])
                C.append(Ca[i - cnt])
            else:
                V.append(Vb[64 - cnt + i])
                C.append(Cb[64 - cnt + i])
        write_reg(st, opsl[0], V, C, None)
        return
    if mn in ("ret", "nop", "leave", "ud2") or mn.startswith("j"):
        return
    raise ValueError(f"node115 cpuid field map unhandled mnemonic {mn} at {va:#x}")


def branch_target(ops):
    m = re.match(r"([0-9a-f]+)", ops)
    return int(m.group(1), 16) if m else None


def provenance(ins):
    import collections
    a, b = HELPER
    addrs = sorted(x for x in ins if a <= x < b)
    leaders = {a}
    for x in addrs:
        mn, ops = ins[x]
        if mn in BRANCH_MNEMONICS:
            t = branch_target(ops)
            if t is not None:
                leaders.add(t)
    for i, x in enumerate(addrs[:-1]):
        if ins[x][0] in BRANCH_MNEMONICS or ins[x][0] in ("call", "ret", "ud2"):
            leaders.add(addrs[i + 1])
    leaders = sorted(x for x in leaders if a <= x < b)
    blocks = {}
    for li, start in enumerate(leaders):
        end = leaders[li + 1] if li + 1 < len(leaders) else b
        blocks[start] = [x for x in addrs if start <= x < end]

    def succs(start):
        body = blocks[start]
        if not body:
            return []
        last = body[-1]
        mn, ops = ins[last]
        li = leaders.index(start)
        nxt = leaders[li + 1] if li + 1 < len(leaders) else None
        if mn == "jmp":
            return [branch_target(ops)]
        if mn in BRANCH_MNEMONICS:
            return [t for t in (branch_target(ops), nxt) if t is not None]
        if mn in ("ret", "ud2"):
            return []
        return [nxt] if nxt is not None else []

    entry = {s: None for s in leaders}
    entry[a] = ProvState()
    dq = collections.deque([a])
    n = 0
    while dq:
        s = dq.popleft()
        st = entry[s].copy()
        for x in blocks[s]:
            mn, ops = ins[x]
            prov_transfer(st, x, mn, ops)
        for t in succs(s):
            if t is None or t not in entry:
                continue
            if entry[t] is None:
                entry[t] = st.copy()
                dq.append(t)
            elif entry[t].merge(st):
                dq.append(t)
        n += 1
        if n > 20000:
            raise ValueError("node115 cpuid field map provenance did not converge")
    sel = entry[SELECTION_ENTRY]
    if sel is None:
        raise ValueError("node115 cpuid field map selection entry unreachable")
    expected = {}
    for entries, word in ((FIELD_MAP_A, "a"), (FIELD_MAP_B, "b")):
        for bit, driver, mechanism, support, origin in entries:
            expected[(word, bit)] = frozenset(support)
    ebx_atoms = frozenset(C(7, 0, "ebx", i) for i in range(32))
    detail = {"a": {}, "b": {}}
    for word, base in (("a", "r12"), ("b", "r15")):
        for bit in range(64):
            V = sel.V[base][bit]
            Cc = sel.C[base][bit]
            got = (V | Cc) - {CONST}
            if CALL in got:
                raise ValueError(f"node115 cpuid field map call result reached {word} bit {bit}")
            if (word, bit) == ("a", 25):
                if V - {CONST}:
                    raise ValueError("node115 cpuid field map A bit 25 value provenance changed")
                if not Cc or not got <= ebx_atoms:
                    raise ValueError("node115 cpuid field map A bit 25 condition changed")
            elif got != expected[(word, bit)]:
                raise ValueError(
                    f"node115 cpuid field map provenance mismatch at {word} bit {bit}: "
                    f"got {sorted(fmt(x) for x in got)}, expected "
                    f"{sorted(fmt(x) for x in expected[(word, bit)])}")
            if V or Cc:
                detail[word][str(bit)] = {
                    "value": [fmt(x) for x in sorted(V, key=repr)],
                    "condition": [fmt(x) for x in sorted(Cc, key=repr)],
                }
    return {
        "method": "per-bit value/condition provenance fixpoint over the helper control-flow graph, measured at the selection entry; a conditional-move condition is merged into a bit's condition provenance only where the two arms' value provenance for that bit differs; sete results are value provenance; CPUID sites inject the pinned leaf/subleaf atoms; the single call site injects the XCR0 result of pr #2398",
        "selection_entry": f"{SELECTION_ENTRY:#x}",
        "a": detail["a"],
        "b": detail["b"],
        "constant_bits": {"a": [25, 52, 53, 54, 63], "b": [0, 9]},
        "zero_bits": {"a": [], "b": list(range(12, 64))},
        "asserted": "for every bit of A and B, (value provenance union condition provenance) minus the constant marker equals the support recorded in field_map; A bit 25 is asserted by subset (its compare condition may mention only leaf 7.0 ebx) with empty non-constant value provenance; no call-result atom reaches A or B",
    }


SELECTION = {
    "site": "0x5cae35e..0x5cae39b",
    "a_mask": "0xf9ffffffffffbfff",
    "cleared_bits": [14, 57, 58],
    "condition": "rcx = (r12 bit 14) | (vendor != \"GenuineIntel\" compare residue) is nonzero",
    "a_rule": "A = r12 if the condition holds, else r12 & 0xf9ffffffffffbfff",
    "b_rule": "B = r15 if the condition holds, else zero-extended low 32 bits of r15",
    "source": "pr #2474 (cited): with the complete map, B has no bit at or above 12 on any path, so the b_rule's zero-extension never changes B's value, C1's B-driven bits are confined to 1..12, and C2 = (B >> 62) | H = H on every path",
}
SUFFIX = {
    "entry": "0x5cae39b",
    "cache_slot": "0x64dfa60",
    "equations": "C0 = A | H; C1 = ((B << 1) | (A >> 63)) | H; C2 = (B >> 62) | H; raw rax return = A (merged RE-002 cache-publication packet)",
    "h_assignments": ["0x5cadd70", "0x5cae251", "0x5cae2f3"],
}
EARLY_PATHS = {
    "max_leaf_zero": "0x5caddf3 jumps to the suffix with A = 0 and B = 0; the leaf is never called (pr #2474)",
    "region_gate": "unless cpuid leaf 1 ecx bits 26,27 are both set, 0x5cae042 jumps to 0x5cae251 and then to the selection at 0x5cae35e; the leaf is never called and none of the xcr0 terms executes (pr #2474). on this path A is the early composition alone and B is the early composition alone",
}
LIMITS = ("Complete bit-level source map for the composed words A (R12) and B (R15) at the "
          "selection entry 0x5cae35e of the node #115 refresh helper only. The XCR0-side "
          "attribution, the region gates and the selection/suffix rules are PR #2474's and "
          "the merged RE-002 cache-publication packet's, cited not re-derived; three "
          "byte-level corrections to PR #2474 are recorded under corrections_to_pr_2474. "
          "Feature/ISA names for any bit, runtime CPUID/XCR0 values, the detector's use of "
          "C0-C2 downstream, and the maximum-leaf-zero path (which bypasses the selection) "
          "are not claimed. The provenance is a static may-analysis over the pinned "
          "disassembly: a bit's support lists every input bit its value or its selecting "
          "condition can depend on; for A bit 25 the recorded support names the deciding "
          "bit of the pinned compare, and the tool asserts the condition mentions no input "
          "family other than leaf 7.0 ebx. No captured code executed.")


def analyze(data):
    owners = trace(data)
    for role, (a, b, _) in OWNERS.items():
        owners[role]["bytes"] = b - a
    sites, rela_hits = call_census(data)
    if sites != [CALL_SITE]:
        raise ValueError("node115 cpuid field map leaf call census changed")
    if rela_hits != 0:
        raise ValueError("node115 cpuid field map leaf relocation reference appeared")
    return {
        "target_sha256": sha256(data),
        "owners": owners,
        "call_census": {"direct_call_sites": [f"{x:#x}" for x in sites],
                        "relocation_references": rela_hits},
        "field_map": field_map_records(FIELD_MAP_A, "A") + field_map_records(FIELD_MAP_B, "B"),
        "corrections_to_pr_2474": CORRECTIONS,
        "selection": SELECTION,
        "suffix": SUFFIX,
        "early_paths": EARLY_PATHS,
        "captured_code_executed": False,
        "limits": LIMITS,
    }


def check_pins(ins_bytes):
    for va, raw, name in PINS:
        if ins_bytes.get(va) != raw:
            raise ValueError(f"node115 cpuid field map owner body changed at {va:#x} ({name})")
    for va, length, target in BRANCHES:
        body = ins_bytes[va]
        if length >= 5:
            disp = int.from_bytes(body[length - 4:length], "little", signed=True)
        else:
            disp = int.from_bytes(body[length - 1:length], "little", signed=True)
        if va + length + disp != target:
            raise ValueError(f"node115 cpuid field map branch changed at {va:#x}")


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != 105896032 or hashlib.sha256(data).hexdigest() != \
            "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301":
        raise ValueError("expected pinned node115")
    report = analyze(data)
    output.mkdir(parents=True, exist_ok=True)
    lines = []
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / "node115.elf"
        snapshot.write_bytes(data)
        native = subprocess.check_output(["readelf", "-wf", str(snapshot)], text=True)
        for role, (a, b, _) in OWNERS.items():
            rows = [l for l in native.splitlines() if f"pc={a:016x}..{b:016x}" in l]
            if len(rows) != 1:
                raise ValueError("native cpuid field map FDE disagreement")
            lines.extend(rows)
        asm = subprocess.check_output(
            ["objdump", "-d", "-M", "intel", "--insn-width=16",
             f"--start-address={HELPER[0]:#x}",
             f"--stop-address={HELPER[1]:#x}",
             str(snapshot)], text=True)
        ins_bytes = decode_export(asm, HELPER[0], HELPER[1],
                                  read(data, HELPER[0], HELPER[1] - HELPER[0])[1])
        required = {va for va, _, _ in PINS}
        if not required <= set(ins_bytes):
            raise ValueError("node115 cpuid field map pin site not native instruction start")
        check_pins(ins_bytes)
        ins = parse_text(asm)
        if set(ins) != set(ins_bytes):
            raise ValueError("node115 cpuid field map text decode disagreement")
        report["censuses"] = native_censuses(ins)
        report["provenance"] = provenance(ins)
        (output / "helper.objdump.txt").write_bytes(
            asm.replace(str(snapshot), "<authenticated-node115>").encode("utf-8"))
    (output / "frames.txt").write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    (output / "records.json").write_bytes((json.dumps(report, indent=2) + "\n").encode("utf-8"))
    return report


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, default=TARGET)
    p.add_argument("--output", type=Path, default=ROOT / "work/cpuid-field-map115")
    args = p.parse_args()
    report = generate(args.binary, args.output)
    print(json.dumps({"functions": len(report["owners"]),
                      "bytes": sum(x["bytes"] for x in report["owners"].values()),
                      "executed": False}))
