# RE-002: node #115 XCR0 composition of the refresh helper — which cache-word fields the XCR0 terms drive

- Component: RE-002 build provenance / runtime-cache provenance — the
  composition, inside the cache refresh helper, of the two raw words
  whose publication the merged RE-002 cache-publication packet pinned.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Question: the RE-002 xcr0-leaf packet (PR #2398) pinned the XCR0 leaf
  `0x5cae3e0..0x5cae3ed`, its sole caller's first branch on the returned
  value and its field extractions, and left as its next question: which
  fields of the composed word do the XCR0-derived terms (the H set, the
  `0xe0` complement, the `0x60000` gate) ultimately drive inside the
  published cache words C0–C2 — i.e., trace the composed word from the
  prefix's stores into the publication suffix's A and B inputs,
  separating the CPUID-derived fields from the XCR0-derived ones.
- Observation: no XCR0 value bit is ever copied into either composed
  word. A forward value-taint analysis over the helper's decoded blocks
  (taint enters only as the leaf call's result) closes with R12, R13,
  R15 and RDX all untainted at the suffix entry, and R12/R15 untainted
  in every block. The XCR0 result is read at exactly three post-call
  sites, and every one of its effects on C0–C2 is control flow: four
  pinned gates. The gates drive exactly these cache fields: the H set
  drives C1 bit 0 (and the raw return's bit 63); XCR0 bit 19, jointly
  with CPUID leaf 7.1 EDX bit 21, drives C0 bit 52; the bits 17–18 gate
  admits the shared block's CPUID fields at C0 bits 43–47 (and, inside
  it, leaf `0x1e` fields at C0 bits 48–51); the bits 1–2 branch admits
  the leaf `0xd` fields at C1 bits 1–3 via B and the fall-through
  composition fields at C0 bits 14–18, 38–42 and 44; and the
  complemented bits 5–7 field drives no cache field at all — its value
  is dead after the OR at `0x5cae157` and only co-gates, with CPUID
  leaf 1 ECX bits 12 and 29, the extra block's CPUID fields at C0 bits
  19–22, 24–29 and 33–37. C2 receives no XCR0-driven field.
- Follow-up: no feature/ISA label for any bit, no runtime XCR0 or CPUID
  value, and no claim about the always-on early CPUID compositions
  outside the XCR0-gated regions (named as boundaries below).

## Why this item, in one paragraph

The merged cache-publication packet proves the suffix equations
`C0 = A | H`, `C1 = ((B << 1) | (A >> 63)) | H`, `C2 = (B >> 62) | H`
with A and B as arbitrary raw inputs and states in its limits that the
prefix's feature values remain unproved; the xcr0-leaf packet measured
the prefix's only non-CPUID input and stopped at its first branch.
Between them, the one question neither answers is the attribution of
A and B: which of their fields the XCR0 terms control and which are
pure CPUID composition. A reimplementation of the detector that gets
an XCR0 term wrong — dropping the H set, say, or treating the
complemented field as data — changes C1 bit 0 or C0 bit 52 with no
failing check anywhere, because no packet recorded the attribution.
This packet records it, field by field, with the XCR0 side separated
from the CPUID side at every step.

## Exact scope

| Role | FDE half-open VA range | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| refresh helper (owner) | `0x5cadd50..0x5cae3da` | 1,674 | 454 |
| XCR0 probe leaf (boundary) | `0x5cae3e0..0x5cae3ed` | 13 | 5 (per PR #2398) |

The measured denominator is **two complete FDEs, 1,687 bytes**. The
helper's complete native export is retained in this packet: unlike in
the xcr0-leaf packet, where the helper was a boundary and a second
copy was deliberately not retained, the trace sites of this packet's
question are distributed across the whole helper body, so the export
is the evidence the pins are validated against. The leaf is retained
only as its `frames.txt` line and its body hash — PR #2398 owns its
export and its result rule, which this packet cites and does not
re-derive. All bodies are hash-pinned without normalization. The
publication equations are the merged cache-publication packet's and
are cited, not re-derived; this packet pins the suffix store sites
only as the composition endpoint. This is not a raw-equal or
normalized cross-function/cross-release equivalence claim.

Slot provenance used below (all pinned): `[rbp-0x58]` holds CPUID
leaf 7 subleaf 0 ECX, `[rbp-0x50]` leaf 7 subleaf 0 EDX, `[rbp-0x38]`
leaf 7 subleaf 1 EAX and `[rbp-0x60]` leaf 7 subleaf 1 EDX, each
zero-extended; when the maximum basic leaf is below 7 the same stores
write 0 instead, and the fields sourced from a slot are then 0.

## Trace stages

1. **Intake: one call, one result register, three post-call reads.**
   The full-`.text` direct-call census and `.rela.dyn` scan (repeated
   here from PR #2398's method) find exactly one call to the leaf, at
   `0x5cae04c`, and zero relocation references. The result moves to
   R14 at `0x5cae051`. A decoded mention census finds R14 mentioned at
   exactly seven sites in the helper (excluding the prologue/epilogue
   push/pop): the pre-call slot load `0x5cadeb6` and its two reads
   (stage 2), the definition `0x5cae051`, and exactly three post-call
   reads — the gate-field extraction `0x5cae054`, the mask-field move
   `0x5cae067` (with the first branch's `not eax` at `0x5cae05d` on
   the result's low half), and the bit-19 test `0x5cae300`. The XCR0
   value has no other consumer: it is never stored to memory and never
   passed to another call.
2. **The R14 seed of B is not XCR0.** Before the call, R14 holds the
   `[rbp-0x58]` slot (CPUID leaf 7.0 ECX). Its two pre-call reads are
   the transfer `mov r15,r14` at `0x5cadeba` — the seed of the
   R15/B composition line — and the CPUID leaf `0x19` gate test at
   `0x5cadfa6`. Both precede the call at `0x5cae04c`, so the value
   they carry is the CPUID slot value, not the leaf result. Any
   attribution of B's seed to XCR0 is excluded by instruction order.
3. **Value-flow verdict: XCR0 bits never enter A or B as values.** A
   forward may-taint analysis over the helper's decoded basic blocks
   (taint enters only as the leaf call's result in RAX, with the
   remaining caller-saved registers conservatively tainted at the
   call; CPUID outputs and immediates are untainted; flag-mediated
   selection — `test`, `sete`, `cmov` — propagates the taint of the
   selected values only, never of the condition) closes with R12,
   R13, R15 and RDX untainted at the suffix entry `0x5cae39b`, and
   with R12 and R15 untainted in every block. So neither composed
   word carries any XCR0 value bit. The single place an XCR0 value
   field is composed at all — the complemented field of stage 4b —
   provably dies there (stage 4b). Every remaining XCR0 effect is a
   branch, a comparison or a flag: the four gates of stage 4.
4. **The four XCR0 gates and the fields they drive.**
   - **(a) Bits 1–2 branch → the H set → C1 bit 0.** The first branch
     (`not eax` / `test al,0x6` / `jne 0x5cae260` at
     `0x5cae05d`/`0x5cae05f`/`0x5cae061`, PR #2398) falls through
     exactly when XCR0 bits 1 and 2 are both set. On the fall-through
     only, `movabs rax,0x8000000000000000` / `or r12,rax` at
     `0x5cae071`/`0x5cae07b` sets bit 63 of R12. A census of all 35
     R12-writing instructions (retained in `records.json`) shows this
     is the only site whose pinned source can set bit 63: every other
     site is a 32-bit operation (which zero-extends), an OR whose
     source is bounded below bit 63 by its own pinned mask/shift
     (the highest, the `0x2000000000000010`-masked OR at `0x5cadf80`,
     reaches bit 61), an AND-masked overwrite (bits 33–34 at
     `0x5cae223`/`0x5cae227`), the bit-52 constant overwrite of stage
     4d, or a preserve of the current R12 value. Once set, the bit is
     carried through both rebuilds by the pinned save/restore pairs
     (`mov rcx,r12` `0x5cae0c1` → `or r12,rcx` `0x5cae14f`;
     `mov rax,r12` `0x5cae1c3` → `or r12,rax` `0x5cae239`;
     `mov rax,r12` `0x5cae2fd` → `or r12,rax` `0x5cae31f`), and the
     selection mask of stage 5 keeps bit 63. Hence **A bit 63 = 1 iff
     XCR0 bits 1 and 2 are both set** (on paths through the XCR0
     region), and by the suffix equations this term drives **C1
     bit 0** and the raw return's bit 63. It cannot change C0: the
     suffix ORs H into C0 on every path regardless of A.
   - **(b) Bits 5–7 field → no cache field; co-gate of the extra
     block.** On the fall-through, `mov r8d,r14d` / `and r8d,0xe0` at
     `0x5cae067`/`0x5cae06a` keeps XCR0 bits 5–7, complemented by
     `xor r8,0xe0` at `0x5cae0c4`. The field's only composition is
     `or rax,r8` at `0x5cae157`, where RAX holds
     `(~CPUID leaf 1 ECX) & 0x20001000` (the copy at `0x5cae0cb`, the
     `and` at `0x5cae152`). A decoded census over the three successor
     ranges (`0x5cae157`–`0x5cae165`, `0x5cae23c`–`0x5cae278`,
     `0x5cae2f3`–`0x5cae2fd`) finds no read of RAX before its first
     write on each path (`0x5cae165`, `0x5cae278`, `0x5cae2fd`
     respectively): the composed value is dead, and only its zero
     flag reaches the `jne 0x5cae23c` at `0x5cae15a`. The field
     therefore drives **no C0–C2 field**; as a control term it
     co-gates the extra block of stage 4e, which executes exactly
     when `(XCR0 & 0xe0) == 0xe0` and CPUID leaf 1 ECX bits 12 and 29
     are both set.
   - **(c) Bits 17–18 gate → the shared block → C0 bits 43–47 (and
     48–51).** Before the branch, `mov edi,r14d` / `and edi,0x60000`
     at `0x5cae054`/`0x5cae057` extracts XCR0 bits 17–18 into EDI. An
     RDI mention census over `0x5cae051`–`0x5cae300` shows the field
     is read only by the two comparisons `cmp edi,0x60000` at
     `0x5cae244` (fall-through arm, `je 0x5cae274`) and `0x5cae26c`
     (taken arm, `jne 0x5cae2f3`); every other RDI mention in the
     range is an H assignment (`0x5cae251`, `0x5cae2f3`) or the
     leaf `0x1e` CPUID partner swap inside the already-entered shared
     block (`0x5cae2c2`, `0x5cae2c7`). When both bits are set, the
     single shared block at `0x5cae274` ORs CPUID fields into R12 —
     leaf 7.0 EDX bits 24, 25, 22 → A bits 43, 44, 45; leaf 7.1 EAX
     bit 21 → A bit 46; leaf 7.1 EDX bit 8 → A bit 47 (RBX is reloaded
     from the `[rbp-0x60]` slot on both arms, at `0x5cae110` and
     `0x5cae268`) — and, when the maximum basic leaf is at least
     `0x1e`, the leaf `0x1e` subleaf 1 block inside it adds EAX bits
     7, 4, 8, 6 → A bits 48, 49, 50, 51. All are CPUID values under
     an XCR0 gate: **C0 bits 43–51**.
   - **(d) Bit 19 test → joint term → C0 bit 52.** At the convergence
     `0x5cae2f3` both arms execute `test r14d,0x80000` / `sete cl` at
     `0x5cae300`/`0x5cae307` and `test ebx,0x200000` / `sete dl` at
     `0x5cae30a`/`0x5cae310`, where EBX is the `[rbp-0x60]` slot
     (leaf 7.1 EDX, reloaded on both arms). The combined condition
     (`or dl,cl` at `0x5cae313`; `movabs r12,0x10000000000000` /
     `or r12,rax` / `cmovne r12,rax` at
     `0x5cae315`/`0x5cae31f`/`0x5cae324`, with RAX the saved R12 from
     `0x5cae2fd`) inserts bit 52 into R12 exactly when **XCR0 bit 19
     and leaf 7.1 EDX bit 21 are both set**. The bounded-source census
     of stage 4a shows no earlier R12 write can set bit 52 (the
     nearest bounded sources reach bits 51 and 53), the leaf `0x24`
     OR that follows reaches only bits 53, 57 and 58, and the stage 5
     mask keeps bit 52: this term drives **C0 bit 52**, a joint
     XCR0×CPUID term — neither input alone suffices.
   - **(e) The branch-gated CPUID regions.** The bits 1–2 branch also
     gates two purely CPUID compositions. On the fall-through only:
     the CPUID leaf `0xd` subleaf 1 block (entered when the maximum
     basic leaf exceeds `0xc`; `0x5cae084`–`0x5cae0ba`) ORs EAX bits
     0, 3, 1 into B bits 0, 1, 2 — **C1 bits 1, 2, 3** — and the
     composition at `0x5cae0bd`–`0x5cae14f` rebuilds R12 from leaf
     7.1 EAX bits 0, 1, 2 → A bits 16, 17, 18; leaf 7.1 EAX bit 23 →
     A bit 38; leaf 7.1 EDX bit 5 → A bit 39; leaf 7.1 EAX bit 4 →
     A bit 40; leaf 7.1 EDX bit 10 → A bit 41; leaf 7.1 EDX bit 4 →
     A bit 42; leaf 1 ECX bit 12 → A bit 44; leaf 1 ECX bit 28 → A
     bit 14; leaf 7.0 EBX bit 5 → A bit 15 — while restoring the
     pre-branch R12 through RCX at `0x5cae14f`. The extra block
     (stage 4b's gate) adds leaf 7.0 EBX bits 16, 28, 27, 26, 17, 21
     → A bits 19, 20, 21, 22, 24, 26; the unsigned-compare outcome at
     `0x5cae1cc` → A bit 25; leaf 7.0 ECX bits 1, 14, 6 → A bits 27,
     28, 29; leaf 7.0 ECX bits 11, 12 → A bits 33, 34 (through
     `[rbp-0x68]` and the `0x600000000` mask at `0x5cae219`); leaf
     7.1 EAX bit 5 → A bit 35; leaf 7.0 EDX bits 8, 23 → A bits 36,
     37 — again restoring the prior R12 through RAX at `0x5cae239`.
     On the taken arm none of these regions executes; R12 keeps only
     its early composition plus the shared, bit-52 and leaf `0x24`
     terms that both arms share.
5. **Selection and suffix.** At `0x5cae35e` the helper compares the
   vendor word in R11/R8 against `GenuineIntel` (the two pinned
   `movabs` constants) and forms the condition
   `RCX = (R12 bit 14) | (vendor residue)`. If it is nonzero, A = R12
   and B = R15 unchanged (`cmovne` at `0x5cae393`/`0x5cae397`);
   otherwise A = R12 & `0xf9ffffffffffbfff` and B = the
   zero-extended low half of R15. The mask clears exactly bits 14, 57
   and 58 — all CPUID-side fields (bit 14 also arrives from the
   stage 4e composition; bits 57–58 from the early composition and
   the CPUID leaf `0x24` block) — and **no XCR0-driven bit (52, 63,
   or any gated field) is among the cleared bits**, so every term of
   stage 4 reaches the suffix unchanged. The suffix itself is pinned
   as the endpoint: RDI is H by the merged packet's reaching
   definitions (assignments at `0x5cadd70`, `0x5cae251`, `0x5cae2f3`,
   all pinned here), the cache base loads through the relocated slot
   at `0x5cae3a1` (target `0x64dfa60`, decoded and checked), and the
   three stores at `0x5cae3a8`, `0x5cae3b6`, `0x5cae3c4` with the
   `shld` at `0x5cae3ae` and `shr` at `0x5cae3bd` realize the cited
   equations with A = R13 and B = RDX; the raw return is R13 at
   `0x5cae3c8`.
6. **Early paths: XCR0 is never read.** If CPUID leaf 0's maximum leaf
   is 0, `0x5caddf3` jumps straight to the suffix with A = 0 and
   B = 0 (R13 zeroed at `0x5cadd6d`, EDX zeroed at `0x5caddf3`). If
   CPUID leaf 1 ECX bits 26 and 27 are not both set, the test at
   `0x5cae03d` routes `0x5cae042` to `0x5cae251` and on to the
   selection, skipping the leaf call and every XCR0 term; A and B are
   then purely the early CPUID compositions. The XCR0 region is
   entered only on the fall-through of that gate.

## Result summary

For every execution that reaches the XCR0 region: **no XCR0 value bit
appears in A, B, C0, C1 or C2.** The complete XCR0 footprint in the
published words is control flow through four gates —

| Gate | Condition | Cache fields driven | Values |
| --- | --- | --- | --- |
| H set | XCR0 bits 1,2 both set | C1 bit 0 (and raw return bit 63) | constant H bit in A bit 63 |
| bit-19 term | XCR0 bit 19 AND CPUID 7.1 EDX bit 21 | C0 bit 52 | constant 2^52 in A |
| shared block | XCR0 bits 17,18 both set | C0 bits 43–47; bits 48–51 if max leaf ≥ 0x1e | CPUID fields |
| branch regions | XCR0 bits 1,2 both set | C1 bits 1–3 (leaf 0xd via B); C0 bits 14–18, 38–42, 44 (fall-through composition) | CPUID fields |
| extra block | (XCR0 & 0xe0) = 0xe0 AND CPUID 1 ECX bits 12,29 set | C0 bits 19–22, 24–29, 33–37 | CPUID fields |
| complemented field | — | none (dead value) | — |

C2 has no XCR0-driven field: B's only XCR0 connection is the leaf
`0xd` gate in the low bits, and `C2 = (B >> 62) | H` draws on B bits
62–63, which no gated region writes. Every other field of A and B is
CPUID composition (boundaries below).

## Explicit boundary and next question

What is **not** established: the field-by-field attribution of the
always-on early compositions — R12's composition at
`0x5cadd99`–`0x5cae036` (seed: CPUID leaf 1 EDX; bounded OR sources
including the bit-61 and bit-60 terms) and R15's at
`0x5cadeba`–`0x5cae033` with its rebuild at `0x5cadf8e`–`0x5cadfa2`
and the leaf `0x19` block — beyond the facts this trace needed from
them (the B seed's pre-call provenance, the bounded sources for bits
52 and 63, and the rebuild that overwrites B's seed). Also not
established: any feature/ISA meaning of any field, the runtime values
of XCR0 or any CPUID leaf, the behaviour of the runtime-tag selector
that reads the published words, and any gate.

Next question: complete the A/B field map by attributing the early
compositions field by field — every remaining bit of A and B to its
CPUID leaf, subleaf and source bit — so the detector's two raw words
are fully attributed from inputs to publication.

## Reproduce and validation

From repository root with the materialized pinned capture and native GNU
tools on PATH:

```sh
python3 -B tools/xcr0_composition_static.py --output research/work-items/RE-002-node115-xcr0-composition
python3 -B -m unittest discover -s tests -p test_xcr0_composition_static.py -v
(cd research/work-items/RE-002-node115-xcr0-composition && sha256sum -c MANIFEST.sha256)
```

The whole capture is authenticated before analysis, output or native
calls. Readelf/objdump receive a private byte-identical snapshot; the
snapshot path is replaced with `<authenticated-node115>` in retained text.
Wrong-release, truncated and same-size modified public inputs are rejected
before output creation.

Focused controls alter the leaf's body bytes, the intake call, the H-set
movabs, the bit-19 test immediate, the selection mask constant, the
suffix `shld` count, and the leaf FDE record; each makes the checker
reject the counterfactual — body mutations are stopped by the owners'
pinned body hashes, a mutated FDE record by the frame check. The byte
pins and the decoded censuses are the checks that name each obligation
inside the pinned bodies. Below the full public digest gate, this checks
the named obligations, not arbitrary-byte error detection or target
execution equivalence.

No captured executable/emulator, live chain/wallet/signing action or
network access is performed. Captured inputs/imported code/pins and all
progress gates are preserved. No hosted-CI result or whole-component
completion is claimed.
