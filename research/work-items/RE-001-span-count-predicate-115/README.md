# RE-001: node #115 span-count predicate 0x5f6ea90 with its sole call site

## Task and bounded question

RE-001 (#115 function map, docs/TASKS.md: "Decode FDE ranges, account for
duplicates/missing functions, validate #115 entrypoints and xrefs with
digest-bound records"). Bounded question: what does the whole 37-byte
span-count predicate at 0x5f6ea90 compute from one object's three qword
fields, and what does its ONLY direct call site in the binary do with
the result? The predicate is modelled end to end, together with its
sole site, that site's true-arm element loop (head call, step and exit
edge) and the follow-up call the loop exits into — a complete behavior,
not a lone-window fragment. The predicate takes an object pointer,
reads three qwords, and returns one bit; it makes no call and writes
nothing.

All windows are bound to one artifact: work/hl-node-115.bin,
SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
which hashes exactly to the provenance/artifacts.json entry for
artifacts/node/115/hl-node.

The `endbr64` at the head of the predicate window is a genuine
instruction present in the target binary, not a placeholder.
Instruction-level detail lives only in the whole-function verbatim
excerpts in main.txt and the verbatim site/exit/cleanup excerpts in
site.txt, exit.txt and cleanup.txt; the JSON in this packet holds
semantic records only. The objdump command that produced the excerpts
is recorded in export_excerpts.py, which regenerates them
byte-for-byte.

## Semantics, stated literally

### Span-count predicate 0x5f6ea90 (37 bytes, FDE 0x5f6ea90..0x5f6eab5)

* Takes obj in rdi and returns 1 or 0 in al. It makes no call and
  writes nothing.
* Return value, all arithmetic modulo 2**64: let span = (qword at
  obj + 0x10) minus (qword at obj + 0x08), then arithmetic-shifted
  right by 7 (so a negative byte span stays negative); let product
  = span * 0xAAAAAAAAAAAAAAAB modulo 2**64. The predicate returns 1
  exactly when product equals the qword at obj + 0x00, else 0.
* Nothing else is read.

Consequences, stated literally: when the shifted span is a multiple
of 3, the product equals the shifted span divided by 3 (because
0xAAAAAAAAAAAAAAAB is the inverse of 3 modulo 2**64); otherwise the
product is the modular product, not a division — shifted span 4
gives 0xAAAAAAAAAAAAAAAC, not 1, and shifted span 5 gives
0x5555555555555557. A byte span below 128 shifts to 0, so field
0x00 = 0 matches. A byte span of -128 shifts to -1, whose product
is 0x5555555555555555; a byte span of -384 shifts to -3, whose
product is 0xFFFFFFFFFFFFFFFF.

### Sole call site 0x5fa159d (in 0x5fa0e40..0x5fa1d4a)

* The caller loads rdi from [rsp + 0x30] and calls the predicate.
  The result is tested at once: zero jumps to 0x5fa129c, the shared
  cleanup block (cleanup.txt shows its guarded delete[] sequence),
  skipping the loop and the follow-up call entirely.
* Nonzero result: the caller loads begin from [rbx + 0x20] into r12
  and end from [rbx + 0x28], stores end at [rsp + 0x48], and compares
  them. Equal (empty range) reaches the 0x5fa1786 arm: when the byte
  at [rsp + 0x70] is zero the caller falls through to 0x5fa1791,
  which calls the follow-up 0x5f6eac0 with rdi reloaded from
  [rsp + 0x30] — the same object — and then jumps to cleanup
  0x5fa129c; when that byte is nonzero it jumps to the 0x5fa1674
  block, whose semantics are NOT claimed here.
* Nonempty range: the loop head at 0x5fa15e2 issues the virtual call
  at slot +0x18 with (rdi = rbp, rsi = rbx, rdx = r12, rcx =
  [rsp + 0x40], the 0x90(%rsp) buffer address). The back edge at
  0x5fa15d0 advances r12 by 0x180 and compares it against the stored
  end at [rsp + 0x48]; equality exits to 0x5fa1791, the follow-up
  call and then cleanup. The per-iteration post-call block beyond
  the head call is NOT claimed; the step count in the model is the
  head/back-edge arithmetic and assumes a 0x180-step-aligned range.

NOT claimed: the follow-up 0x5f6eac0's semantics, the virtual call's
semantics or target, the 0x5fa1674 block, caller semantics beyond
the site, any meaning for the three fields beyond the rule, and the
wider behavior of the 0x5fa0e40 caller.

Distinct from the open PRs recorded in the state file: no open PR
title or code search hit for 0x5f6ea90 or this site; the predicate
is not the flag-variant leaf 0x5f6b740 (open PR #2379, different
function and rule) nor the record-fill routine 0x5f6eb50 (open PR
#2378, different function and rule).

## Verification

Run from the repository root:
`python3 research/work-items/RE-001-span-count-predicate-115/verify.py`
— digest, provenance, manifest, excerpt regeneration byte-for-byte
from a fresh objdump run, all predicate/site/exit/cleanup
instructions byte-for-byte vs fresh objdump and the raw binary,
FDE ranges for the predicate and the caller, census, model tests.
Three extra spot instructions were verified byte-for-byte against a
fresh objdump run and the raw binary: the movabs at 0x5f6ea94, the
call at 0x5fa159d and the follow-up call at 0x5fa1796.
