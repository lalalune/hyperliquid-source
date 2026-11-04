# RE-002: complete the node #115 A/B field map of the refresh helper

## Question

PR #2474 (RE-002 xcr0-composition) attributed every field of the composed
words A (R12) and B (R15) that the XCR0 terms of the refresh helper
`0x5cadd50` drive, and explicitly left the field-by-field CPUID
attribution of the always-on early compositions of R12 and R15 unclaimed;
the merged RE-002 cache-publication packet owns the publication suffix
equations and likewise leaves the prefix feature values unproved. Which
CPUID leaf, subleaf and source bit drives every remaining bit of A and B,
measured at the selection entry `0x5cae35e`?

## Answer

The map is complete: all 64 bits of A and all 64 bits of B are
attributed in `records.json` (`field_map`, one entry per bit with driver,
mechanism, support and origin). 89 of the 128 entries are established
here — the 24 early-composition bits of A (bits 0–13, 30–32, 55, 57–62),
the 9 early-composition bits of B (bits 3–11), the leaf `0x24` block
bits 53/54, A bit 23, A bit 56, and the 52 always-zero bits of B — and
the remaining 39 transcribe PR #2474's gates with the provenance
assertion below. Three byte-level
corrections to PR #2474 fall out of the pins (stage 4). No bit is left
unattributed: A's only constant-valued bits are 25, 52, 53, 54 and 63,
each with its selecting condition recorded; B's bits 12–63 are zero on
every path.

## Stage 1 — intake provenance

Ten CPUID sites execute in the helper (census in `records.json`): leaves
0, 1, 7.0, 7.1, 0x80000000, 0x80000001, 0x19, 0xd.1, 0x1e.1 and 0x24.0,
each pinned by its immediate setup. The register dance around each site
(the saved callee-saved partner is restored by `xchg`, so the partner
register transiently carries the leaf's EBX) gives, on the path with
maximum basic leaf ≥ 7:

- leaf 1 EDX seeds R12 (`mov r12d,edx` at `0x5cadd99`); leaf 1 ECX is in
  ESI and is copied to EBX at `0x5cade46`.
- leaf 7.0 EBX is in R13; leaf 7.0 ECX is stored to `[rbp-0x58]`, leaf
  7.0 EDX to `[rbp-0x50]`, leaf 7.1 EAX to `[rbp-0x38]`, leaf 7.1 EDX to
  `[rbp-0x60]`; leaf 7.1 EBX is discarded by the dance at
  `0x5caddca`–`0x5caddd8`.
- leaf 0 ECX is stored to `[rbp-0x2c]`, the maximum basic leaf to
  `[rbp-0x3c]`, and the vendor pack `(leaf 0 EDX << 32) | leaf 0 EBX` is
  assembled in R11 at `0x5cade15`/`0x5cade43`.
- leaf 0x80000001 ECX is in EDI from `0x5cade41` (zero when the maximum
  extended leaf is 0); leaf 7.0 EDX's transient residence in EDI is
  overwritten at `0x5cade19`/`0x5cade41` and reaches the compositions
  only through the `[rbp-0x50]` slot.

Slot store/load censuses for all eight named slots are re-derived and
asserted in the tool.

## Stage 2 — the early compositions (this packet)

**A seed reduction.** `shr r12d,0x13` / `and r12d,0xc0` at
`0x5cadf4b`/`0x5cadf4f`: of the leaf 1 EDX seed only bits 25 and 26
survive, at A bits 6 and 7.

**A scatters.** Four extraction groups are OR-ed into R12 by
`0x5cadf80`/`0x5cadf83`:

- the leaf 1 ECX scatter at `0x5cade46`–`0x5cade7b` → A bits 8 (ECX 0),
  1 (ECX 1), 9 (ECX 9), 10 (ECX 19), 11 (ECX 20);
- leaf 7.0 EBX extractions → A bit 3 (EBX 18, `0x5cadf59`), A bit 13
  (EBX 29, `0x5cadf65`), A bit 57 (EBX 3, `0x5cadf73`);
- the masked word `0x2000000000000010 & ((leaf 1 ECX << 38) | leaf 1
  EDX)` plus four extractions → A bits 61 (ECX 23), 4 (EDX 4),
  0 (ECX 25), 55 (ECX 29), 2 (ECX 30), 5 (EDX 23), 62 (EDX 24);
- the R15-seed extractions (next paragraph) → A bits 58 (EBX 8 of leaf
  7.0 — via R13, `0x5cadecb`), 30, 31, 32 (leaf 7.0 ECX bits 8, 9, 10).

**B seed and rebuild.** R15 is seeded with `leaf 7.0 ECX << 22` at
`0x5cadeba`–`0x5cadebd`, but the seed is discarded by the rebuild at
`0x5cadf91` (`mov r15,rax`); its bits reach A only (above, and through
the `[rbp-0x68]` store at `0x5cadef3` into PR #2474's bits 33/34). The
rebuild base is the EDX scatter at `0x5cade7e`–`0x5cadeb3` — B bits 3
(leaf 1 ECX 13), 6 (leaf 7.0 EBX 19), 7 (leaf 7.0 EBX 11), 8 (leaf 1
ECX 22) — plus B bit 10 (leaf 7.0 EBX 9, `lea eax,[rdx+rax*2]` at
`0x5cadf8e`). B bit 9 is the constant forced by `or r15,0x200` and
removed by `cmove r15,rax` at `0x5cadfa2` exactly when leaf 7.1 EAX
bit 31 (`test DWORD PTR [rbp-0x38],0x80000000` at `0x5cadf9b`) is clear,
so B bit 9 is set exactly when that input bit is set.

**Leaf 0x19 block** (gated by leaf 7.0 ECX bit 23, `test r14d,0x800000`
at `0x5cadfa6`): B bit 4 = leaf 0x19 EBX bit 0, B bit 5 = leaf 0x19 EBX
bit 2 (`0x5cadfbe`–`0x5cadfcc`).

**Vendor block** (executes only when the stage-1 pack matches AMD or
Hygon): A bit 12 = leaf 0x80000001 ECX bit 6, A bit 60 = leaf
0x80000001 ECX bit 21, B bit 11 = leaf 0x80000001 ECX bit 11
(`0x5cae016`–`0x5cae036`). A bit 59 = leaf 0x80000001 ECX bit 5 is set
unconditionally at `0x5cadfd3`–`0x5cadfdc`.

## Stage 3 — completeness against the cited regions

The XCR0 region (entered only when leaf 1 ECX bits 26/27 are both set;
PR #2474 stages 3–5, cited) adds: the fall-through composition (A bits
14–18, 38–42, 56), the extra block (A bits 19–29, 33–37), the shared
block (A bits 43–47), the leaf 0x1e block (A bits 48–51), the bit-52
term (constant, jointly gated by XCR0 bit 19 and leaf 7.1 EDX bit 21),
H at A bit 63, and the leaf 0xd block's B bits 0–2. The leaf 0xd block
preserves the early B word through RCX (`mov rcx,r15` at `0x5cae096`;
`mov r15,rax` at `0x5cae0ba`), so B bits 3–11 survive on region paths
too; B bits 0–2 exist only on those paths.

**Leaf 0x24 block** (this packet; gated by leaf 7.1 EDX bit 19 at
`0x5cae328`, after the convergence at `0x5cae2f3`): the default word
`movabs rcx,0x60000000000000` at `0x5cae34d` sets A bits 53 and 54;
`cmove rcx,rax` at `0x5cae357` substitutes `0x20000000000000` (bit 53)
when leaf 0x24 EBX bits 1–7 are all zero (`test sil,0xfe` at
`0x5cae33f`). Bit 53 is therefore set on both arms; bit 54 exactly when
those EBX bits are not all zero.

Two consequences of the completed map, through the cited selection and
suffix rules: B has no bit at or above 12 on any path, so the
selection's B arm (zero-extending the low 32 bits) never changes B's
value, C1's B-driven bits are confined to bits 1–12, and
`C2 = (B >> 62) | H = H` on every path. The selection mask clears A bits
14, 57 and 58, i.e. exactly the leaf 1 ECX bit 28, leaf 7.0 EBX bit 3
and leaf 7.0 EBX bit 8 terms, on the non-Intel path.

## Stage 4 — corrections to PR #2474

Recorded in full under `corrections_to_pr_2474` in `records.json`:

1. **Leaf 0x24 reach.** PR #2474 names bits 53, 57 and 58; the pinned
   constant at `0x5cae34d` is `0x60000000000000` (bits 53, 54). Bits 57
   and 58 come only from the early composition.
2. **Leaf 1 ECX bit 12 landing.** PR #2474 lists it as an A bit 44
   driver; `and edx,0x1000` / `shl rdx,0x2c` at
   `0x5cae0d1`/`0x5cae0d7` lands it at A bit 56. A bit 44's only source
   is leaf 7.0 EDX bit 25 (shared block).
3. **Bit 25 compare operand.** PR #2474 describes the `cmp` at
   `0x5cae1cc` as against the saved composed word in RCX; ECX is loaded
   with the constant `0x80000000` at `0x5cae160`, after the saved word
   was consumed by the restore at `0x5cae14f`. The compare therefore
   decides on leaf 7.0 EBX bit 31 alone, and A bit 25 is that bit under
   the extra-block gate.

## Provenance method

`tools/cpuid_field_map_static.py` byte-pins both owner bodies, 223
instruction sites and 9 branch targets, and requires the objdump export
to start exactly at each pin. It then runs a per-bit provenance fixpoint
over the helper's control-flow graph: for every register bit and named
stack slot it tracks the input bits the bit's value can depend on
(value provenance) and the input bits that selected it through a
conditional move (condition provenance, merged only where the two arms'
value provenance for that bit differs; `sete` results are value
provenance, since the flag becomes data). CPUID sites inject atoms for
the pinned leaf/subleaf; the single call site injects the XCR0 result
of PR #2398. At the selection entry, the union of both provenances
minus the constant marker must equal the support recorded for every bit
of A and B (A bit 25 is asserted by subset — its compare condition may
mention only leaf 7.0 EBX — with empty non-constant value provenance).
Censuses re-derived and asserted: 10 CPUID sites, R12 writes (35), R15
writes (8), R13 writes (5), R14 mentions (7), slot stores/loads for the
eight named slots, one direct call site and zero relocation references
to the leaf. `records.json` carries the full per-bit value/condition
provenance under `provenance`. No captured code is executed.

## Boundary and next question

Not claimed: feature/ISA names for any bit (they are not in the binary),
runtime CPUID/XCR0 values, and the maximum-leaf-zero path, which jumps
from `0x5caddf3` to the suffix with A = B = 0 and bypasses the
selection. The XCR0 gates, the selection rule and the publication
equations are PR #2474's and the merged cache-publication packet's,
cited, not re-derived.

Next question: who reads the three published words back — the consumers
of the cache at slot `0x64dfa60` beyond the publication suffix — and
which of the mapped bits each consumer tests.
