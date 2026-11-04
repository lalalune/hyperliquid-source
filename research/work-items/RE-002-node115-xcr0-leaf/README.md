# RE-002: node #115 XCR0 probe leaf of the cache refresh helper

- Component: RE-002 build provenance / runtime-cache provenance — the
  `XGETBV` leaf called by the refresh helper whose three-word cache
  publication is already pinned by the merged RE-002 cache-publication
  packet.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Question: what value does the separately bounded FDE
  `0x5cae3e0..0x5cae3ed` — the one direct call in the refresh helper's
  probe prefix that the merged cache-publication packet left unmeasured —
  return, and what does its sole caller do with that value first?
- Observation: the leaf is five instructions: it clears ECX, executes
  `XGETBV`, and returns the recomposed 64-bit result `(EDX << 32) | EAX`
  in RAX — with ECX = 0, the full XCR0 value. Its sole caller stores the
  result in R14 and branches on it: unless both bits 1 and 2 of XCR0 are
  set, control skips the H-bit set and the CPUID leaf-`0xd` composition
  block; on the fall-through, bits 5–7 are masked out and later
  complemented into the composed feature word.
- Follow-up: no runtime XCR0 value, no feature/ISA label for any tested
  bit, no CPUID-field composition and no publication-equation claim.

## Why this item, in one paragraph

The merged cache-publication packet closes the refresh helper's
publication suffix and its raw return, but states its own hole in two
places: the prefix "contains ten CPUID instructions and one direct call
to the separately bounded, unmeasured FDE `0x5cae3e0..0x5cae3ed`", and
"its probe results, feature mapping and effects remain unqualified".
This packet measures exactly that FDE and qualifies the XGETBV arm of
the probe: the returned value, the single call site, and the caller's
first branch and field extractions on the result, all byte-pinned. The
loss if this stays unrecorded: a reimplementation of the probe prefix
has no pinned record of its only non-CPUID input, and a substitution
that returns only the low half of XCR0, or reads a different XCR
index, silently changes the caller's branch on bits 1–2 and the
complemented bits 5–7 field — with no failing check anywhere, because
the leaf itself was never in any packet's denominator.

## Exact scope

| Role | FDE half-open VA range | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| XCR0 probe leaf (owner) | `0x5cae3e0..0x5cae3ed` | 13 | 5 |
| refresh helper (boundary) | `0x5cadd50..0x5cae3da` | 1,674 | 454 (per merged packet) |

The measured denominator is **two complete FDEs, 1,687 bytes**. The
leaf's complete native export is retained; the refresh helper is
retained only as its `frames.txt` line and its body hash in
`records.json` — it is the merged cache-publication packet's owner,
already fully exported there, and a second copy is deliberately not
retained. Its trace sites (stage 3) are byte-pinned in `records.json`
and validated as native instruction starts during generation. The two
FDEs are adjacent in both orders: the helper ends at `0x5cae3da`
(int3 padding follows), the leaf starts at `0x5cae3e0`, and their
unwind records are consecutive (FDE VAs `0xfe3804` and `0xfe3830`,
both under the shared CIE at `0xca6ed8`). All bodies are hash-pinned
without normalization. This is not a raw-equal or normalized
cross-function/cross-release equivalence claim.

## Trace stages

1. **The leaf: no input, one returned value.** The complete body is
   `xor ecx,ecx` / `xgetbv` / `shl rdx,0x20` / `or rax,rdx` / `ret`.
   ECX is the XCR index input of `XGETBV` and is unconditionally 0,
   so the instruction reads XCR0 (Intel SDM, `XGETBV` reference: with
   ECX = 0 the processor returns the current XCR0 value in EDX:EAX).
   The leaf recomposes the two halves and returns the full 64-bit
   XCR0 in RAX. It reads no memory, calls nothing and has no branch:
   for every execution the result rule is `RAX = XCR0`. No runtime
   value of XCR0 is observed here — the capture is never executed.
2. **Where the value lives.** A full-`.text` scan finds exactly **one**
   direct E8 call to the leaf, at `0x5cae04c`, inside the refresh
   helper FDE `0x5cadd50..0x5cae3da` — the call the merged
   cache-publication packet counted in the helper's prefix. A
   `.rela.dyn` scan finds **zero** relocation references to the leaf's
   address: it is reached only by that one direct call, never through
   a stored function pointer.
3. **Consumer: returned value → fields → first branch.** The helper
   moves RAX to R14 at `0x5cae051`. Before branching it extracts one
   field: `mov edi,r14d` / `and edi,0x60000` at
   `0x5cae054`/`0x5cae057` (bits 17 and 18), which both arms later
   compare against `0x60000`. The first branch on the value is
   `not eax` / `test al,0x6` / `jne 0x5cae260` at
   `0x5cae05d`/`0x5cae05f`/`0x5cae061`: it is taken exactly when
   `(XCR0 & 0x6) != 0x6`, i.e. unless bits 1 and 2 are both set.
   - **Fall-through (bits 1 and 2 both set):** `mov r8d,r14d` /
     `and r8d,0xe0` at `0x5cae067`/`0x5cae06a` keeps bits 5–7;
     `movabs rax,0x8000000000000000` / `or r12,rax` at
     `0x5cae071`/`0x5cae07b` sets the H bit into the accumulated word
     R12; execution continues into the CPUID leaf-`0xd` block at
     `0x5cae07e`. Later, the kept field is complemented —
     `xor r8,0xe0` at `0x5cae0c4` — and OR'd into the composed word
     at `0x5cae157` (`or rax,r8`), so the field enters the word as
     the complement of the three-bit field: nonzero exactly where
     at least one of bits 5–7 is clear. The fall-through tail then
     reaches the shared comparison at `0x5cae244`
     (`cmp edi,0x60000` / `je 0x5cae274`), else `jmp 0x5cae2f3`.
   - **Taken (some of bits 1–2 clear):** the arm at `0x5cae260`
     reloads its saved registers and skips both the H set and the
     leaf-`0xd` block entirely; `cmp edi,0x60000` / `jne 0x5cae2f3`
     at `0x5cae26c`/`0x5cae272` routes it either to the same shared
     block `0x5cae274` (field equal to `0x60000`) or directly to the
     convergence site `0x5cae2f3` — one of the three H-assignment
     sites the merged packet's reaching-definition analysis pinned,
     reached here without this arm assigning H itself.
   No feature or ISA name is assigned to bits 1, 2, 5, 6, 7, 17 or 18;
   only their positions, masks and control/data flow are recorded.
4. **Relation to the pinned publication (context, not re-derived).**
   The composed word this prefix builds is the input side of the
   merged cache-publication packet's equations: its retained analysis
   tracks the raw words A and B and the three stored words
   C0–C2 with the H bit set. Which composed fields land in A and B is
   that packet's prefix composition question and is not re-derived
   here; this packet pins only the XCR0 leaf's contribution points
   listed in stage 3.

## Result summary

For every execution: the leaf returns `RAX = XCR0` (ECX forced to 0,
halves recomposed). Its sole caller branches at `0x5cae061` on
`(XCR0 & 0x6) != 0x6`; on the both-bits-set fall-through it sets H
into R12 and carries `(XCR0 & 0xe0) ^ 0xe0` into the composed word;
the pre-extracted bits 17–18 field gates the shared block `0x5cae274`
in both arms before convergence at `0x5cae2f3`.

## Explicit boundary and next question

The semantic label of the composed feature word — what its fields
mean, and which of them the XCR0-derived terms (the H set, the
`0xe0` complement, the `0x60000` gate) ultimately drive inside the
published cache words C0–C2 — is **not** established by these bytes.
What is now closed is the last unmeasured FDE of the refresh helper:
its returned value, its single consumer, and that consumer's first
branch and pinned field extractions on the result. The helper's ten
CPUID instructions and their field composition remain the merged
packet's open prefix question; the runtime-tag packet's selector,
which reads the published cache words, is downstream context. No
gate is claimed.

Next question: which fields of the composed word do the XCR0-derived
terms drive in the published cache words — i.e., trace the composed
word from the prefix's stores into the publication suffix's A and B
inputs, separating the CPUID-derived fields from the XCR0-derived
ones.

## Reproduce and validation

From repository root with the materialized pinned capture and native GNU
tools on PATH:

```sh
python3 -B tools/xcr0_leaf_static.py --output research/work-items/RE-002-node115-xcr0-leaf
python3 -B -m unittest discover -s tests -p test_xcr0_leaf_static.py -v
(cd research/work-items/RE-002-node115-xcr0-leaf && sha256sum -c MANIFEST.sha256)
```

The whole capture is authenticated before analysis, output or native
calls. Readelf/objdump receive a private byte-identical snapshot; the
snapshot path is replaced with `<authenticated-node115>` in retained text.
Wrong-release, truncated and same-size modified public inputs are rejected
before output creation.

Focused controls alter the leaf's index-clear, `XGETBV`, shift-immediate
and return bytes, the call-site and branch bytes inside the consumer body
(stopped by its pinned body hash), and the leaf FDE record; each makes the
checker reject the counterfactual. Below the full public digest gate, this
checks the named obligations, not arbitrary-byte error detection or target
execution equivalence.

No captured executable/emulator, live chain/wallet/signing action or
network access is performed. Captured inputs/imported code/pins and all
progress gates are preserved. No hosted-CI result or whole-component
completion is claimed.
