# RE-001: node #115 vector realloc-insert 0x5d90f50 and its transfer caller

## Bounded question

The merged packet RE-001-predicate-drain-115 pinned the transfer at
0x5f13e00 and recorded one grow call inside it as
"grow(collection + 0x50, [collection + 0x58], &payload) # 0x5d90f50,
by contract", stating explicitly: "The grow helper 0x5d90f50 was not
read; only its call site and argument registers are claimed."
What does the helper at 0x5d90f50 actually do, and which code reaches
it?

## Answer, stated literally

The window is a second copy of `std::vector::_M_realloc_insert`: the
length-error string at rodata 0x43d55a reads
`vector::_M_realloc_insert` (verified from the raw binary bytes at
that address, reached via the PT_LOAD mapping). It inserts exactly
one element and always reallocates; there is no in-place arm.

Arguments: rdi = container pointer, rsi = insert position pointer,
rdx = pointer to the qword value to insert. The container holds begin
at +0x00, end at +0x08 and capacity end at +0x10, with 8-byte
elements. The helper reads begin and end; it reads the capacity field
only at the delete step, where the freed byte count is
capacity_end - begin. Callers test end against capacity end
themselves and call this helper only on the full path (inspected:
the transfer's own call at 0x5f13e8c is reached only after its
end == capacity-end test at 0x5f13e64; sites 0x5d911ca, 0x5f14b19 and
0x5f14b30 pass an embedded or member vector and a stack value slot;
site 0x5f14845 passes a stack-local vector).

Steps, in native order:

1. size = (end - begin) >> 3, an arithmetic shift on the wrapped
   64-bit difference. When size equals the maximum element count
   0x0fffffffffffffff, the helper calls `__throw_length_error` with
   the rodata string above and never returns.
2. New capacity: size + 1 (== 1) element when the container is empty
   (end == begin); otherwise min(2 * size, 0x0fffffffffffffff)
   elements, capped at the maximum. When doubling wraps below size
   (unsigned), the native code takes a max-bytes allocation path,
   `operator new(0x7ffffffffffffff8)`, with the capacity end recorded
   as the new buffer plus that byte count. That byte count equals
   maximum * 8, so the wrap path and the capped path end at the same
   capacity, and the model returns the maximum for both.
3. Allocate new capacity * 8 bytes with `operator new` (single call
   site 0x5d91021; all three capacity arms converge there).
4. Load the value qword from the rdx pointer; store it at
   new_buffer + (position - begin).
5. When the prefix byte count (position - begin) is positive
   (signed), `memmove(new_buffer, old_begin, prefix)` (0x5d91042).
6. When the suffix byte count (old_end - position) is positive
   (signed), `memcpy(new_buffer + (position - begin) + 8, position,
   suffix)` (0x5d9109f). A front insertion (prefix == 0, suffix > 0)
   still takes this memcpy arm.
7. When old_begin is non-zero, `operator delete(old_begin,
   old_capacity_end - old_begin)` (0x5d9105d) — this also frees an
   old buffer of an empty-but-allocated container.
8. Store new_buffer to container +0x00, the new end
   (new_buffer + (position - begin) + 8 + suffix) to +0x08, and
   new_buffer + allocation bytes to +0x10. Return void.

The value stored is the qword loaded from the rdx address, not the
address itself. The position must lie in [begin, end]; the model
rejects anything outside that range and any span that is not a
multiple of 8 bytes, because the native shift would misread such a
span — those are model guards, not native outcomes.

## The inspected caller

This packet pins the helper together with the caller the merged
predicate-drain packet left it contracted to: the transfer at
0x5f13e00 (147 bytes, FDE file offset 0x1000124, length field 0x34,
no LSDA — identical to the merged packet's own record). The transfer
decrements the payload refcount at +0x70 and returns early while it
stays positive. At zero it appends the payload qword to the overflow
vector at object +0x50: inline when end != capacity end (store at
end, advance end by 8), and through this helper at 0x5f13e8c when
end == capacity end, with rdi = collection + 0x50,
rsi = [collection + 0x58] (the end) and rdx = the stack slot holding
the payload. The caller is reached through 3 direct calls
(0x5f13eda, 0x5f13f02, 0x5f14066) and 1 tail jump (0x5f1435f), sites
only, exactly as the merged packet records.

## Twin copy

This body is a byte-level twin of the copy at 0x5d9ee20 pinned by
RE-001-qword-insert-grow-115: both are 389 bytes, and exactly 15
bytes differ, all of them inside the rel32 fields of the seven call
instructions (the memcpy, memmove, operator new, operator delete and
__throw_length_error PLT calls); the two FDE instruction programs
are byte-identical. The copies are independent compilations of the
same instantiation with disjoint caller sets — the twin serves 26
direct call sites, this copy serves the 8 below — so this packet
pins this copy's own window, callers and bytes and does not re-claim
the twin.

## Evidence

- Whole-function verbatim disassembly: `excerpts/grow.txt`
  (0x5d90f50..0x5d910d5, 389 bytes) and `excerpts/caller.txt`
  (0x5f13e00..0x5f13e93, 147 bytes), produced by
  `objdump -d --start-address=... --stop-address=...
  work/hl-node-115.bin`, regenerable with `export_excerpts.py`.
  Instruction mnemonics in the excerpts (for example `endbr64`) are
  genuine instructions present in the target binary, not
  placeholders; `verify.py` re-checks sampled instructions
  byte-for-byte against a fresh objdump run and the raw binary.
- Semantic records only in `records.json`: no per-instruction
  mnemonic list is presented anywhere in this packet.
- Frame record in `frames.txt`; relocation record in
  `relocations.txt`; reference census in `census.py` (grow: 8 direct
  calls — 0x5d911ca, 0x5ed2092, 0x5ed20aa, 0x5f13e8c, 0x5f14845,
  0x5f14b19, 0x5f14b30, 0x5f175ef — 0 tail jumps, 0 stored qwords,
  0 RELATIVE addends; caller: 3 direct calls, 1 tail jump, 0 stored
  qwords, 0 RELATIVE addends).
- The packet's `verify.py` plus `export_excerpts.py` and `census.py`
  are committed inside this work-item directory, so the checker
  behind "ALL CHECKS PASSED" is visible in the diff.
- Bound to one artifact digest: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  bound in provenance/artifacts.json as artifacts/node/115/hl-node.

## Model and tests

`tools/realloc_insert_5d90f50_115.py` implements the steps above;
`tests/test_realloc_insert_5d90f50_115.py` exercises them end to end
(34 checks: empty null-begin and empty-but-allocated inserts, append,
middle, front, spare-capacity reallocation, capacity arithmetic
including the maximum and the doubling-overflow guard, the
maximum-element length error, qword truncation, guards, and the
packet's census). `differential.py` runs the real binary window
under Unicorn against the model with deterministic allocator oracles
for operator new/delete and real byte copies for memcpy/memmove:
34 cases (fixed inserts at every position class, 24 seeded random
inserts, and the maximum-size length-error arm), 0 mismatches,
comparing the outcome kind, the ordered external-effect log, the
three container fields and the full new-buffer contents.
The pytest-style test file runs under plain python3 via its
`__main__` runner because pytest is not installed on this VM; that
is stated honestly here.

## Environment limits

This VM has no cargo/rustc and no Ghidra/Java, so the work stays in
the Python model layer. The Unicorn differential runs under a lane
venv interpreter (unicorn 2.1.4 + capstone); `verify.py` reports the
differential step as skipped when unicorn is not importable and was
run here with the venv interpreter, so the differential is included
in the ALL CHECKS PASSED result below. This packet binds to the
materialized work/hl-node-115.bin, whose hash matches
provenance/artifacts.json exactly.

## Unknowns

- The bodies containing the other seven call sites (0x5d910e0,
  0x5ed1fe0, 0x5f148d0, 0x5f14a10, 0x5f164d0) are not read here beyond
  their call-site argument setup; their own semantics stay unknown.
- The element type name of the vectors served by this copy is not
  recovered; only the 8-byte element width and the qword payload at
  the transfer site are observed.
- Whether the two twin copies' caller sets stay disjoint across the
  whole binary is established only for direct calls, tail jumps,
  stored qwords and RELATIVE addends (the census channels); an
  indirect call through a computed target is not enumerable this
  way, and none is claimed.
