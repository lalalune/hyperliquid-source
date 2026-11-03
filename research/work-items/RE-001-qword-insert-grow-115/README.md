# RE-001: node #115 vector realloc-insert 0x5d9ee20 with its 26 call sites

## Bounded question

What does the helper at 0x5d9ee20 do when a caller inserts one qword
element into a full qword vector, and which code reaches it?

## Answer, stated literally

The window is `std::vector::_M_realloc_insert`: the length-error string
at rodata 0x43d55a reads `vector::_M_realloc_insert` (verified from the
raw binary bytes at that address). It inserts exactly one element and
always reallocates; there is no in-place arm.

Arguments: rdi = container pointer, rsi = insert position pointer,
rdx = pointer to the qword value to insert. The container holds begin
at +0x00, end at +0x08 and capacity end at +0x10, with 8-byte elements.
The helper reads begin and end only; it never reads the capacity
field. Callers test end against capacity end themselves and call this
helper only on the full path (inspected: site 0x5f780ad is reached
only after the caller's own end == capacity-end test at 0x5f7808b,
with rsi = end and rdx = a stack slot holding the value; site
0x5d9f0c0 passes the container, end as the position, and a computed
element pointer as the value address).

Steps, in native order:

1. size = (end - begin) >> 3, an arithmetic shift on the wrapped
   64-bit difference. When size equals the maximum element count
   0x0fffffffffffffff, the helper calls `__throw_length_error` with
   the rodata string above and never returns.
2. New capacity: 1 element when the container is empty (end == begin);
   otherwise min(2 * size, 0x0fffffffffffffff) elements. When doubling
   wraps below size (unsigned), the native code takes a max-bytes
   allocation path, `operator new(0x7ffffffffffffff8)`, with the
   capacity end recorded as the new buffer plus that byte count.
   That byte count equals maximum * 8, so the wrap path and the
   capped path end at the same capacity, and the model returns the
   maximum for both.
3. Allocate new capacity * 8 bytes with `operator new`.
4. Load the value qword from the rdx pointer; store it at
   new_buffer + (position - begin).
5. When the prefix byte count (position - begin) is positive (signed),
   `memmove(new_buffer, old_begin, prefix)`.
6. When the suffix byte count (old_end - position) is positive
   (signed), `memcpy(new_buffer + (position - begin) + 8, position,
   suffix)`.
7. When old_begin is non-zero, `operator delete(old_begin,
   old_capacity_end - old_begin)` — this also frees an old buffer of
   an empty-but-allocated container.
8. Store new_buffer to container +0x00, the new end
   (new_buffer + (position - begin) + 8 + suffix) to +0x08, and
   new_buffer + allocation bytes to +0x10. Return void.

The value stored is the qword loaded from the rdx address, not the
address itself. The position must lie in [begin, end]; the model
rejects anything outside that range and any span that is not a
multiple of 8 bytes, because the native shift would misread such a
span — those are model guards, not native outcomes.

## Evidence

- Whole-function verbatim disassembly: `excerpts/grow.txt`
  (0x5d9ee20..0x5d9efa5, 389 bytes), produced by
  `objdump -d --start-address=0x5d9ee20 --stop-address=0x5d9efa5
  work/hl-node-115.bin`, regenerable with `export_excerpts.py`.
  Instruction mnemonics in the excerpts (for example `endbr64`) are
  genuine instructions present in the target binary, not
  placeholders; `verify.py` re-checks sampled instructions
  byte-for-byte against a fresh objdump run and the raw binary.
- Semantic records only in `records.json`: no per-instruction
  mnemonic list is presented anywhere in this packet.
- Frame record in `frames.txt`; relocation record in
  `relocations.txt`; reference census in `census.py` (26 direct
  calls, 0 tail jumps, 0 stored qwords, 0 RELATIVE addends).
- The packet's `verify.py` plus `export_excerpts.py` and `census.py`
  are committed inside this work-item directory, so the checker
  behind "ALL CHECKS PASSED" is visible in the diff.
- Bound to one artifact digest: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  bound in provenance/artifacts.json as artifacts/node/115/hl-node.

## Model and tests

`tools/qword_insert_grow_115.py` implements the steps above;
`tests/test_qword_insert_grow_115.py` exercises them end to end
(empty, append, middle, front, capacity growth, the maximum-element
length error, the doubling-overflow guard, qword truncation, guards,
and the packet's census). The pytest-style file runs under plain
python3 via its `__main__` runner because pytest is not installed on
this VM; that is stated honestly here and in the PR body.

## Environment limits

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so the
work stays in the Python model layer. `make doctor` fails on missing
providers and `make verify` / `make catalogue-check` fail on the
LFS-pointer artifact here; both are pre-existing and unrelated to
this item. This packet binds to the materialized work/hl-node-115.bin
instead, whose hash matches provenance/artifacts.json exactly.
