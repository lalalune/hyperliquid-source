# RE-001: node #115 visited-element teardown 0x5d516f0

## Task and bounded question

RE-001 (#115 function map, docs/TASKS.md: "Decode FDE ranges, account for
duplicates/missing functions, validate #115 entrypoints and xrefs with
digest-bound records"). Bounded question: what does the whole 981-byte
routine at 0x5d516f0 do to one visited element, end to end? The routine
is modelled as a complete behavior, not a lone-window fragment: it
destroys every heap-owned field of a 0x180-byte element in descending
offset order, through operator delete and one external callee. It is
the callee the 0x5f6eac0 element-visit-and-reset routine calls once
per visited element (open PR #2383); that visit routine's element
step is 0x180, matching this routine's highest field, the string at
+0x160..+0x180.

All windows are bound to one artifact: work/hl-node-115.bin,
SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
which hashes exactly to the provenance/artifacts.json entry for
artifacts/node/115/hl-node.

The `endbr64` at the head of the routine window is a genuine
instruction present in the target binary, not a placeholder.
Instruction-level detail lives only in the whole-function verbatim
excerpt in main.txt and the verbatim consumer excerpt in
consumer.txt; the JSON in this packet holds semantic records only.
The objdump command that produced the excerpts is recorded in
export_excerpts.py, which regenerates them byte-for-byte.

## Semantics, stated literally

The routine takes one element pointer in rdi and returns void. It
never reads obj+0x00, and it writes nothing itself: every effect is
a call to operator delete (PLT 0x63f0d80, `_ZdlPvm`) or to the
0x5d4c8d0 callee. Destruction runs in descending offset order.

### String rule (used at +0x160, +0x138, +0x28, +0x08, and inside loop elements)

A string occupies three qwords: ptr at +0x00, a second qword at
+0x08 (never read by this routine), and cap-or-buffer at +0x10.
The binary compares ptr against the address of the +0x10 slot:
when ptr equals that address the string is in its inline form
and no delete runs; otherwise it calls delete(ptr, cap + 1),
where cap is the qword at the +0x10 slot. The +1 is the
capacity-plus-terminator size the binary passes, not a length.
For the two tail strings (+0x28, +0x08) the delete is a tail
jump: the routine pops its saved registers first and returns
through delete, or returns directly on the inline path.

### Plain-vector rule (at +0x110 and +0xf8)

A plain vector's begin is at +0x00 and its cap-end at +0x10
(the end field at +0x08 is never read). When begin is zero no
delete runs; otherwise it calls delete(begin, cap - begin),
with the subtraction wrapping modulo 2**64.

### Loop-vector rule (at +0xe0, +0xc8, +0x80)

A loop vector's begin is at +0x00, end at +0x08, cap-end at
+0x10. The routine walks begin to end in fixed steps,
destroying each element's strings by the string rule in
descending offset order within the element, then — when begin
is nonzero — calls delete(begin, cap - begin). An empty range
(begin == end) destroys no elements but still deletes the array
when begin is nonzero; a zero begin deletes nothing.

* Vector at +0xe0: step 0x58; each element's strings at +0x38
  then +0x18.
* Vector at +0xc8: step 0x130; each element's strings at
  +0x100, then +0xe0, then +0x50, then +0x30.
* Vector at +0x80: step 0x28; each element's single string at
  +0x08.

### Linked-list rule (at +0xa8)

Head is the qword at +0xa8. For each node in chain order the
routine calls the 0x5d4c8d0 callee with the node's +0x18 qword
(that callee's own semantics are NOT claimed; its return is
discarded), then calls delete(node, 0x30), then follows next
at +0x10, until the next pointer is zero. The next pointer is
loaded before the delete, so the chain survives the free.

### Full destruction order

1. String at +0x160.
2. String at +0x138.
3. Plain vector at +0x110.
4. Plain vector at +0xf8.
5. Loop vector at +0xe0 (step 0x58), then its array delete.
6. Loop vector at +0xc8 (step 0x130), then its array delete.
7. Linked list at +0xa8.
8. Loop vector at +0x80 (step 0x28), then its array delete.
9. String at +0x28 (tail-jumped delete).
10. String at +0x08 (tail-jumped delete).

Assumptions, stated explicitly: loop vectors are valid vectors
(begin <= end, span a multiple of the step, element count
matching the span); the model raises otherwise instead of
silently modelling an invalid range. A zero ptr with a heap
flag is not a realistic string and is given no special case.

### Consumer

The documented consumer is the 0x5f6eac0 visit routine's call
at 0x5f6eafa (excerpted in consumer.txt): the caller passes
the cursor element pointer in rdi and discards the return.
Whole-file census finds 87 direct calls to this routine in
total; the other 86 sites are recorded by address in
callers.tsv and reproduced by census.py, but are NOT
individually excerpted or modelled here — this PR pins the
routine itself, and claims no caller semantics beyond the
visit-routine consumer.

NOT claimed: the 0x5d4c8d0 callee's semantics or effects
beyond its call contract, caller semantics beyond the consumer
site, any meaning for the fields beyond the offsets and rules
above, what the visited elements denote, and any field the
routine never reads (including obj+0x00 and the plain
vectors' end fields).

Distinct from the open PRs recorded in the state file: no open
PR title or code search hit for 0x5d516f0; open PR #2383 is
this routine's consumer, not this routine; open PR #2376 is a
different teardown pair (0x5f78000/0x5f78030) with no address
overlap.

## Verification

Run from the repository root:
`python3 research/work-items/RE-001-element-teardown-115/verify.py`
— digest, provenance, manifest, excerpt regeneration byte-for-byte
from a fresh objdump run, every excerpt instruction byte-for-byte
vs the raw binary, FDE ranges for the routine, the 0x5d4c8d0
callee and the consumer routine, census, model tests. Three extra
spot instructions were verified byte-for-byte against a fresh
objdump run and the raw binary: the string delete call at
0x5d51719, the list-node callee call at 0x5d518cc, and the
tail-jumped delete at 0x5d51974.
