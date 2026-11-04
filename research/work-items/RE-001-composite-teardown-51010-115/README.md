# RE-001: map node #115 composite teardown 0x5d51010

Bounded question: what does the 411-byte routine at 0x5d51010
tear down, in what order, and where is it used?

## Answer, end to end

The routine tears down one composite object in seven phases,
taking a single object pointer in rdi and returning nothing.
In instruction order:

1. Member: if the pointer at object +0x210 is non-null, call
   the destroy routine 0x5d8d820 with it, then operator delete
   it with size 0x290. The +0x210 slot itself is never
   written.
2. First array, backwards: the count at +0x68 is walked down
   to zero (written back on every iteration, ending at 0).
   Each element is 0x30 bytes at the buffer pointed to by
   +0x1f0; each element holds one string with its pointer at
   +0x00, its size at +0x08 (never read), and its
   capacity-or-inline-buffer at +0x10. A pointer equal to the
   element's own +0x10 slot address is inline (SSO) and frees
   nothing; otherwise the pointer is deleted with size
   capacity + 1.
3. Second array, forwards: elements are 0x30 bytes from the
   begin pointer at +0x1f8 to the end pointer at +0x200,
   with the same string layout and the same SSO rule. After
   the walk, +0x200 is reset to +0x1f8.
4. Post-reset re-walk: the binary then re-walks from +0x1f8
   to +0x200, but +0x200 was just reset to +0x1f8 and +0x1f8
   is not written in between, so the walk's entry condition
   is already satisfied and it deletes nothing on any entry
   path. The re-walk instructions (including the delete at
   0x5d51108) are present in the range but execute zero
   iterations; this is recorded as an observed vacuity, not
   smoothed over as a second deletion pass.
5. Second-array buffer: if the +0x1f8 buffer pointer is
   non-null, delete it with size +0x208 minus +0x1f8.
6. Head count: if the qword at +0x00 is non-zero, zero it.
   Nothing is freed here.
7. Pointer vector: if +0x58 differs from +0x50, reset +0x58
   to +0x50 first; then, if +0x50 is non-null, tail-jump to
   operator delete with size +0x60 minus +0x50. A null begin
   with a non-null end still resets the end and returns
   without deleting.

The routine never frees the object itself, never writes the
+0x210, +0x1f8, +0x208, +0x50 or +0x60 slots, and never
writes any element string slot. Its FDE
(0x5d51010..0x5d511ab) carries no landing-pad block in the
frame dump, and the bytes after the range (0x5d511ab to
0x5d511b0) are int3 padding, not a landing-pad block.

## How this differs from the neighbouring teardown 0x5d50de0

The composite destructor at 0x5d50de0 (mapped earlier) also
frees element strings with the same SSO rule, but it is a
different routine with a different shape: it opens with a
virtual-call walk over its elements, uses a chunk-spanning
index rule (indices 0..7 from the first chunk, the rest from
the second), and destroys each pointer-vector element with
0x5d8d820 before deleting it with size 0x290. This routine
has no virtual-call phase, no chunk-spanning index rule (its
two arrays are independent: a counted array at +0x1f0 with
count +0x68, and a begin/end/capacity array at
+0x1f8/+0x200/+0x208), destroys only the single +0x210
member, and frees its pointer vector's buffer without
destroying elements. The destroy callee 0x5d8d820 is shared
with that routine, but only its argument and its position
before the member delete are pinned here.

## Consumers: 27 direct calls and one tail jump

The census (reproduced by census.py, re-run inside verify.py)
finds exactly 27 direct calls, one tail jump, no stored
qwords, and no RELATIVE addends for the routine address.
Callers are recorded site-only in callers.tsv; their wider
behaviour is not claimed here. The tail jump at 0x5d51aaa is
the last instruction of the routine
0x5d519d0..0x5d51aaf, a deleting destructor handing off to
this teardown. The routine's own transfers are exactly six
direct calls (the destroy plus five operator deletes), one
direct tail jump (the pointer-vector delete), and no
indirect transfer of any kind.

## NOT claimed

- What the composite object, its member, its arrays, or its
  strings denote.
- What the destroy callee 0x5d8d820 does beyond being called
  with the +0x210 pointer and preceding its delete.
- The caller functions' wider behaviour beyond sites, FDE
  ranges, and the tail-jump site's position as the last
  instruction of its routine.
- Behaviour on dangling pointers, a null first-chunk buffer
  with a nonzero count, or inconsistent capacities (the
  model raises on those, stated openly).
- Whether the post-reset re-walk is dead code or a compiler
  artifact beyond the observed vacuous entry condition.

## Evidence and verification

All extracted from the digest-verified node #115 work binary
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
work/hl-node-115.bin hashes exactly; provenance entry
artifacts/node/115/hl-node in provenance/artifacts.json).

Packet contents: semantic records.json only (no
per-instruction mnemonic list — instruction-level detail lives
only in the whole-function verbatim excerpt main.txt);
frames.txt with the routine and all caller FDE lines;
relocations.txt empty (no relocation record mentions the
routine address); callers.tsv with all 28 sites; verify.py,
export_excerpts.py, and census.py in the packet. The
mnemonics in the excerpt are genuine instructions from the
target binary, reproduced verbatim by objdump, not
placeholders: verify.py re-checks every excerpt instruction
byte-for-byte against the raw binary and regenerates the
excerpt from a fresh objdump run.

Reproduce from the repository root:

    python3 research/work-items/RE-001-composite-teardown-51010-115/export_excerpts.py
    python3 research/work-items/RE-001-composite-teardown-51010-115/census.py
    python3 research/work-items/RE-001-composite-teardown-51010-115/verify.py
    python3 tests/test_composite_teardown_51010_115.py

Tool versions: GNU objdump/readelf (Binutils 2.42),
Python 3.12.3. Repository-wide gates (make verify / make
test / catalogue-check) are NOT claimed: the baseline on
this VM is affected by missing LFS material and by the
absence of cargo/rustc, as recorded in earlier packets; the
checks claimed here are this packet's verify.py (ALL CHECKS
PASSED) and its model tests.

## Next step

Decompose the tail-jump caller 0x5d519d0..0x5d51aaf: what
object it destroys before handing off to this teardown, and
what its own callers do with the torn-down object.
