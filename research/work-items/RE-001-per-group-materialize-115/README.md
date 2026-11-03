# RE-001: node #115 per-group materialize step 0x5f6a630

## Task and bounded question

RE-001 (#115 function map, docs/TASKS.md: "Decode FDE ranges, account for
duplicates/missing functions, validate #115 entrypoints and xrefs with
digest-bound records"). Bounded question: what does the 455-byte function
at 0x5f6a630 do with one group entry, end to end — how many output records
it allocates, how it initializes them, and what each finished record
contains?

## Windows

* Main 0x5f6a630..0x5f6a7f7 (455 bytes, FDE range as shown in
  frames.txt). The main window of this item.
* Factory 0x5f54680..0x5f5468f (15 bytes). The bit-packing leaf the init
  phase calls once per slot. Referenced in full because it is only 15
  bytes; its contribution to a finished slot is nil (see below), so it
  is not a claim on its own.

Both windows are bound to one artifact: work/hl-node-115.bin,
SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
which hashes exactly to the provenance/artifacts.json entry for
artifacts/node/115/hl-node.

## Semantics, stated literally

The step takes an output record pointer, a group entry pointer and an
allocator owner pointer, and returns nothing claimed (the known callers
continue without reading rax after the call):

1. Span = group end minus group begin (64-bit wrapping difference of
   the entry's first two qwords; the entry's third qword is never
   read). Count = span arithmetic-shifted right by 3, as a signed
   64-bit value. The count is stored at output +0x00 at once.
2. The allocator (a virtual method at offset 0x18 of the owner's
   table, an oracle) is called with size count * 80 mod 2**64 and
   trailing arguments 0, 0. Its result is stored at output +0x08
   after the init phase.
3. When the byte span, read unsigned, is strictly greater than
   0xcccccccccccccc8, the native code throws bad_array_new_length.
   The throw happens AFTER the bulk allocator call above, so a
   failing call still records one allocator call first.
4. Init phase: exactly count slots of 80 bytes each are initialized
   in order (skipped when count is 0). Each slot is ten qwords:
   +0x00 = 0; +0x08 = the factory leaf's result for (0, 0), which is
   0; +0x10 = 0; +0x18 = 0x00FFFFFFFFFFFFFF; +0x20 = 0; +0x28 = 0;
   +0x30 = 0x4376FD; +0x38 = 0; +0x40 = 0x4376FD; +0x48 = 0. The
   constant 0x4376FD is recorded literally; what it points to is
   not claimed. Every init field is overwritten by the fill phase
   when count > 0, so the init pattern is observable only in the
   call log (one factory call per slot), never in a finished slot.
5. Fill phase: skipped entirely when the byte span is 0. Otherwise
   it is a do-while loop: at least one element is processed when the
   span is nonzero, so a 1..7-byte span (count 0) still materializes
   exactly one element; afterwards the index advances while it stays
   below count (unsigned). For each element, in order:
   a. Call the allocator with size = first segment length + second
      segment length (mod 2**64) and trailing arguments (previous
      element pointer, 0) — the previous element pointer is 0 on the
      first fill call, and the element pointer just processed on
      later calls. Whether the allocator reads its trailing
      arguments is its own business and is not pinned.
   b. Copy the first segment bytes, then the second segment bytes,
      into the fresh buffer, in order (two memcpy calls).
   c. Fill the 80-byte slot at buffer + 80 * index: +0x00 =
      element +0x00; +0x08 = element +0x08; +0x10 = element +0x10;
      +0x18 = element +0x18; +0x20 = element +0x20; +0x28 = the
      element pointer; +0x30 = the concatenation buffer pointer;
      +0x38 = the first segment length; +0x40 = the concatenation
      buffer pointer plus the first segment length; +0x48 = the
      second segment length.
   The element fields read are +0x00, +0x08, +0x10, +0x18, +0x20,
   +0x28 (first segment pointer), +0x30 (first segment length),
   +0x48 (second segment pointer) and +0x50 (second segment length).
   The element fields at +0x38 and +0x40, and anything past +0x50,
   are never read here.

   A negative byte span always trips the span limit (its unsigned
   value is at least 2**63, above the limit), so the length throw
   fires before any loop and a negative count never reaches the
   init loop.

## Callers

Census (whole-file scan, reproduced by the packet's census.py):
* Main 0x5f6a630: exactly 2 direct calls — 0x5f8029a inside the
  pipeline group pass 0x5f801f0 (pinned by the earlier RE-001
  pipeline item, which records this call; this item models the
  callee) and 0x5da98b8 inside the 5417-byte function
  0x5da8870..0x5da9d99 (site-only; its surrounding logic is not
  claimed). 0 tail jumps, 0 stored qwords, 0 RELATIVE addends.
* Factory 0x5f54680: 35 direct calls including this item's init
  site 0x5f6a6bf (full list in callers.tsv). 0 tail jumps, 0 stored
  qwords, 0 RELATIVE addends.

## How the packet was built

* Excerpts: `objdump -d --start-address=0x5f6a630
  --stop-address=0x5f6a7f7 work/hl-node-115.bin` for main.txt and
  `objdump -d --start-address=0x5f54680 --stop-address=0x5f5468f
  work/hl-node-115.bin` for factory.txt, via export_excerpts.py.
  Instruction-level detail lives only in those raw excerpts, kept
  verbatim and whole-function; records.json carries semantic records
  only, never a per-instruction list. The mnemonics in the excerpts
  are genuine instructions present in the target binary, not
  placeholders.
* Frames: `objdump --dwarf=frames work/hl-node-115.bin`, filtered
  to the two FDE blocks in frames.txt.
* Census: census.py (full disassembly pass plus a whole-file qword
  scan plus a readelf RELATIVE scan), writing callers.tsv.
* Checker: verify.py re-runs the digest, manifest, excerpt
  regeneration, spot-byte, frame, census, records and model-test
  checks and prints ALL CHECKS PASSED.
* Model and tests: tools/per_group_materialize_115.py and
  tests/test_per_group_materialize_115.py (runnable under plain
  python3; pytest is not installed on this VM).

## Environment limits, stated honestly

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so the
repo's `make verify` / `make test` gates cannot run here (their
baseline on this VM already fails on the missing LFS artifacts);
the packet checker and the model tests above are what was actually
run. The model is Python, following the merged contributors' Python
model + tests pattern for node #115 function maps.
