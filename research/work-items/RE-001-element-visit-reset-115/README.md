# RE-001: node #115 element-visit-and-reset routine 0x5f6eac0 with its two call sites

## Task and bounded question

RE-001 (#115 function map, docs/TASKS.md: "Decode FDE ranges, account for
duplicates/missing functions, validate #115 entrypoints and xrefs with
digest-bound records"). Bounded question: what does the whole 83-byte
routine at 0x5f6eac0 do to one object's three qword fields, and what do
its ONLY two direct call sites in the binary do with it? The routine is
modelled end to end, together with both sites — a complete behavior,
not a lone-window fragment. The routine takes an object pointer, visits
each element of the object's range once, then resets the range to
empty; it returns void.

All windows are bound to one artifact: work/hl-node-115.bin,
SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
which hashes exactly to the provenance/artifacts.json entry for
artifacts/node/115/hl-node.

The `endbr64` at the head of the routine window is a genuine
instruction present in the target binary, not a placeholder.
Instruction-level detail lives only in the whole-function verbatim
excerpts in main.txt and the verbatim site excerpts in site1.txt and
site2.txt; the JSON in this packet holds semantic records only. The
objdump command that produced the excerpts is recorded in
export_excerpts.py, which regenerates them byte-for-byte.

## Semantics, stated literally

### Element-visit-and-reset routine 0x5f6eac0 (83 bytes, FDE 0x5f6eac0..0x5f6eb13)

* Takes obj in rdi and returns void. Its only callee is 0x5d516f0
  (FDE 0x5d516f0..0x5d519c5), called once per element; that callee's
  own semantics are NOT claimed here, only its call contract: one
  argument, rdi = the cursor element pointer, and its return value
  is discarded.
* At entry it reads begin = the qword at obj + 0x08 and end = the
  qword at obj + 0x10, then immediately stores 0 at obj + 0x00 —
  before any visit call, and also on the empty path.
* If begin == end it jumps straight to the epilogue: no visit call,
  and obj + 0x10 is left equal to begin (it already is).
* Otherwise it loops from the head at 0x5f6eaf0: each pass calls the
  callee with the cursor, advances the cursor by 0x180 at
  0x5f6eaf3, and repeats while the cursor differs from end (back
  edge 0x5f6eb02). When the cursor equals end it stores the original
  begin at obj + 0x10 (0x5f6eb04) and returns. The qword at
  obj + 0x08 is never written.
* Net effect, for a 0x180-step-aligned range: every element pointer
  begin + k * 0x180, k = 0 .. (end - begin) / 0x180 - 1, is visited
  exactly once in increasing order; afterwards obj + 0x00 is 0 and
  obj + 0x10 equals obj + 0x08, so the range is empty. Nothing else
  is read or written.

Assumption, stated explicitly: the model assumes the range is
0x180-step-aligned (end minus begin is a non-negative multiple of
0x180). The literal loop advances by 0x180 until the cursor equals
end, so an unaligned or inverted range does not terminate on the
first pass in the way the aligned model describes; the tool raises
for such ranges instead of silently modelling them.

### Call site 0x5f76388 (in 0x5f75b10..0x5f763fe)

* The caller loads rdi from [r15 + 0x2c0]. A zero pointer jumps
  away at 0x5f76377 and never reaches the call.
* On a nonzero pointer the caller stores byte 0 at [rdi + 0x321] on
  the unshifted pointer, adds 0x18 to rdi, and calls the routine
  with the shifted pointer — so the routine's obj is the loaded
  pointer plus 0x18, and the routine zeroes that object's + 0x00
  field (the loaded pointer's + 0x18 field) and resets its
  + 0x10 field (the loaded pointer's + 0x28 field).
* After the call the caller jumps at once to 0x5f75fc7; no result
  is read because the routine returns void. Caller semantics beyond
  this site are NOT claimed.

### Call site 0x5fa1796 (in 0x5fa0e40..0x5fa1d4a)

* The caller loads rdi from [rsp + 0x30] — the same object the
  0x5f6ea90 span-count predicate received (open PR #2380) — and
  calls the routine. This site is reached from two edges: the
  empty-range arm 0x5fa1786 when the stack byte at [rsp + 0x70] is
  zero, and the loop-exit edge 0x5fa1791 after the predicate's
  true-arm element loop finishes.
* After the call the caller jumps at once to the shared cleanup
  block 0x5fa129c; no result is read because the routine returns
  void. Caller semantics beyond this site are NOT claimed.

NOT claimed: the 0x5d516f0 callee's semantics or effects, caller
semantics beyond the two sites, any meaning for the + 0x00/+ 0x08/
+ 0x10 fields beyond the rule, and what the visited elements
denote.

Distinct from the open PRs recorded in the state file: no open PR
title or code search hit for 0x5f6eac0; the routine is not the
0x5f6ea90 predicate (open PR #2380, a different function that only
reads the same three fields) nor the drain drivers at
0x5f14000/0x5f14180/0x5f140c0 (open PRs #2236/#2242/#2244, different
functions and addresses).

## Verification

Run from the repository root:
`python3 research/work-items/RE-001-element-visit-reset-115/verify.py`
— digest, provenance, manifest, excerpt regeneration byte-for-byte
from a fresh objdump run, all routine and site instructions
byte-for-byte vs fresh objdump and the raw binary, FDE ranges for
the routine, the callee and both caller functions, census, model
tests. Three extra spot instructions were verified byte-for-byte
against a fresh objdump run and the raw binary: the visit call at
0x5f6eafa, the site-1 call at 0x5f76388 and the site-2 call at
0x5fa1796.
