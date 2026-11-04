# RE-001: node #115 pipeline group pass 0x5f801f0

## Bounded question

What does the pipeline step at 0x5f801f0 do with the object's group
list before the per-group work runs, and which code reaches it?

## Answer, stated literally

The step takes only the object pointer (rdi). It reads the signed
32-bit group count at obj+0x14, prepares one 16-byte record per group,
and then calls the per-group callee 0x5f6a630 once per group, in index
order, with (record, group entry, obj+0x1a0). Its only caller is the
pipeline prologue 0x5f884b0 (site 0x5f8850b), which calls it as
0x5f801f0(obj) — the pipeline-trim item already pinned that call step.

Object layout used by this step:

- obj+0x14: signed 32-bit group count.
- obj+0x30: qword inline-record fill cursor.
- obj+0xb8: eight 16-byte inline record slots (slot i at +0xb8 + i*16).
- obj+0xc0 / obj+0xc8: begin / end of the overflow-record vector,
  one 16-byte slot per group beyond the first 8.
- obj+0xa98: 24-byte group entries (entry i at +0xa98 + i*24).
- obj+0x1a0: passed by address as the callee's third argument.

Steps, in native order:

1. Count branch, decided on count read UNSIGNED (cmp $0x8, %rdx; ja):
   - Count > 8: the heap vector is resized to exactly count-8 slots.
     When its existing slot count is below count-8, the helper
     0x5da8490 is called with (obj+0xc0, count-8 - existing) and the
     count is reloaded afterwards. When it is above count-8, the end
     pointer is set to begin + (count-8)*16. When equal, nothing is
     resized. The inline slots are then zero-filled from the old
     cursor up to slot 7 (a cursor already above 7 fills nothing) and
     the cursor is set to 8.
   - Count <= 8: when the heap begin and end differ, the end is set
     to the begin (the heap is truncated to zero slots). When the
     cursor is below count, the inline slots from the cursor up to
     count-1 are zero-filled and the cursor reaches count. When the
     cursor is above count, the cursor is set down to count (slots
     above count keep their previous content). When equal, nothing
     changes.
2. Group loop, entered only when count is positive under the SIGNED
   test at 0x5f80330: index runs 0..count-1. Slot index <= 7 is the
   inline slot; index >= 8 is heap slot index-8. The callee is called
   as 0x5f6a630(record, group entry, obj+0x1a0). After each call the
   loop returns when count <= index+1 (signed compare).
3. Resulting invariants for a non-negative count: the cursor ends at
   min(count, 8); the heap holds max(count-8, 0) slots when count > 8
   and zero slots otherwise; only slots from the old cursor upward
   are zeroed.

What is NOT claimed here: the per-group callee's own semantics (what
it writes into each record) and whether the grow helper zeroes newly
added heap slots — the model records new heap slots as unpinned
(None). A negative count is out of the model contract: natively it
takes the unsigned >8 branch with a wrapped size, which no valid
group count reaches.

## Evidence

- Whole-function verbatim disassembly: `excerpts/step.txt`
  (0x5f801f0..0x5f8037d, 397 bytes), produced by
  `objdump -d --start-address=0x5f801f0 --stop-address=0x5f8037d
  work/hl-node-115.bin`, regenerable with `export_excerpts.py`.
  Instruction mnemonics in the excerpt (for example `endbr64`) are
  genuine instructions present in the target binary, not
  placeholders; `verify.py` re-checks sampled instructions
  byte-for-byte against a fresh objdump run and the raw binary.
- Semantic records only in `records.json`: no per-instruction
  mnemonic list is presented anywhere in this packet.
- Frame record in `frames.txt`; relocation record in
  `relocations.txt`; reference census in `census.py` (step: 1 direct
  call, 0 tail jumps, 0 stored qwords, 0 RELATIVE addends).
- The packet's `verify.py` plus `export_excerpts.py` and `census.py`
  are committed inside this work-item directory, so the checker
  behind "ALL CHECKS PASSED" is visible in the diff.
- Bound to one artifact digest: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  bound in provenance/artifacts.json as artifacts/node/115/hl-node.
- Model: tools/pipeline_group_pass_115.py; tests:
  tests/test_pipeline_group_pass_115.py (12 model checks).
