# RE-001: map node #115 destructor chain 0x5d519d0

Bounded question: what does the 223-byte routine at 0x5d519d0
destroy, in what order, and where is it used?

## Answer, end to end

The routine destroys one composite object in four phases,
taking a single object pointer in rdi and returning nothing
(it leaves through a tail jump, so control returns directly
to its caller through the teardown). In instruction order:

1. Composite destructor: call 0x5d50de0 with the object
   pointer. That routine was mapped separately (the
   composite destructor); here only its call and its
   position first are pinned.
2. Pointer vector, in index order: the total element count
   is the qword at +0x218 plus (the qword at +0x270 minus
   the qword at +0x268) divided by 8. Index i reads the
   i-th qword of the first chunk (the array pointed to by
   the qword at +0x260) while i <= 7, and the (i - 8)-th
   qword of the second chunk (the array starting at the
   qword at +0x268) once i >= 8. Each non-null element
   pointer is destroyed by calling 0x5f10d40 with it, then
   deleted with operator delete and size 0xd20. Null
   elements are skipped. The chunk switch is literal: it
   happens at index 8 regardless of the +0x218 count, so
   when the second chunk is non-empty but the +0x218
   count is not 8, the walk visits first-chunk slots for
   every index below 8 and second-chunk slots only from
   index 8 on. That is the same index rule the 0x5d50de0
   destructor uses for its own chunked walk.
3. Post-loop field handling, in order: if the +0x218
   qword is non-zero, zero it; if the +0x270 end differs
   from the +0x268 begin, reset +0x270 to +0x268; if the
   +0x268 begin pointer is non-null, delete that buffer
   with operator delete and size +0x278 minus +0x268.
   The end reset precedes the null check, so a null begin
   with a non-null end still resets the end and returns
   without deleting.
4. Teardown tail jump: with the object pointer restored
   in rdi, tail-jump at 0x5d51aaa to the composite
   teardown 0x5d51010 (mapped separately). That teardown
   is the routine this chain hands off to, not a second
   copy of this routine's own work.

The routine never frees the object itself, never writes
the +0x260, +0x268 or +0x278 slots, and never writes any
element slot. Its FDE (0x5d519d0..0x5d51aaf) carries no
landing-pad block, and the byte after the range
(0x5d51aaf) is int3 padding, not a landing-pad block.

## How this differs from its two chained neighbours

The 0x5d50de0 destructor (phase 1 here) destroys a
different part of the object: a virtual-call walk over
0x30-byte elements, backwards/forwards string disposal,
and a pointer-vector teardown with destroy-then-delete
size 0x290. The 0x5d51010 teardown (phase 4 here) frees
strings and buffers in seven phases but never calls
0x5d50de0 and never touches the +0x218/+0x260/+0x268
vector. This routine is the chain that runs the destructor,
then its own pointer-vector phase (destroy 0x5f10d40,
delete size 0xd20 per element, chunk switch at index 8),
then the teardown. The destroy callee 0x5f10d40 and the
delete size 0xd20 belong to this routine alone, not to
either neighbour.

## Consumers: 12 direct calls, no tail jumps in

The census (reproduced by census.py, re-run inside
verify.py) finds exactly 12 direct calls, no tail jumps,
no stored qwords, and no RELATIVE addends for the routine
address. Callers are recorded site-only in callers.tsv;
their wider behaviour is not claimed here. The routine's
own transfers are exactly four direct calls (the
destructor, the destroy, and two operator deletes), one
direct tail jump (the teardown), and no indirect transfer
of any kind.

## NOT claimed

- What the composite object, its pointer-vector elements,
  or the +0x218 count denote.
- What the destructor callee 0x5d50de0 does beyond being
  called first with the object pointer (mapped separately).
- What the destroy callee 0x5f10d40 does beyond being
  called with each non-null element before its delete.
- What the teardown callee 0x5d51010 does beyond being
  the tail-jump target (mapped separately).
- The caller functions' wider behaviour beyond sites and
  FDE ranges.
- Behaviour on dangling pointers, a first-chunk buffer
  shorter than the walked indices, or a second chunk
  inconsistent with the +0x218 count (the model raises).
- Whether the first-chunk buffer at +0x260 is freed
  elsewhere, since this routine never frees it.

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
routine address); callers.tsv with all 12 sites; verify.py,
export_excerpts.py, and census.py in the packet. The
mnemonics in the excerpt are genuine instructions from the
target binary, reproduced verbatim by objdump, not
placeholders: verify.py re-checks every excerpt instruction
byte-for-byte against the raw binary and regenerates the
excerpt from a fresh objdump run.

Reproduce from the repository root:

    python3 research/work-items/RE-001-destructor-chain-519d0-115/export_excerpts.py
    python3 research/work-items/RE-001-destructor-chain-519d0-115/census.py
    python3 research/work-items/RE-001-destructor-chain-519d0-115/verify.py
    python3 tests/test_destructor_chain_519d0_115.py

Tool versions: GNU objdump/readelf (Binutils 2.42),
Python 3.12.3. Repository-wide gates (make verify / make
test / catalogue-check) are NOT claimed: the baseline on
this VM is affected by missing LFS material and by the
absence of cargo/rustc, as recorded in earlier packets; the
checks claimed here are this packet's verify.py (ALL CHECKS
PASSED) and its model tests.

## Next step

Decompose the destroy callee 0x5f10d40 (what a 0xd20-byte
element's destruction does before its delete) and the
twelve caller functions' behaviour around this chain; the
0x5d507d0 ten-field string disposal remains an unbuilt
candidate, distinct from this routine's pointer vector.
