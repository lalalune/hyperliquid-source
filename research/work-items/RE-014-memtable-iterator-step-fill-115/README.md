# RE-014: validate node #115 memtable iterator step-and-fill (0x5f08790) against the #94 mapping

Task: RE-014 (migration validation). Bounded question: does node #115
run the same step-and-fill — dispatch a step slot, advance the inner
iterator, gate on a predicate, refresh status through the entry reader
when a width is present, and fill one key into a caller slice through
a provider gate or an inline length-prefix parse — that the #94
mapping pins for the memtable iterator, and where do the #115 bytes
differ?

- Component: node #115 memtable iterator step-and-fill. One window,
  extracted from the digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  `0x5f08790..0x5f08a2b` (603 bytes; FDE .eh_frame offset 0x358984,
  length 0x38, CIE 0 — no LSDA). The window is reached only through
  its vtable slot 0x64cc688; the census finds no direct call and no
  tail jump anywhere in the binary, exactly like the neighbouring
  seek-gate window.
- Claim status: observation for the window bounds, the dispatch, the
  perf rule, the inner advance, the predicate gate in both width
  arms, the reader install and report rule, the fill gate, the
  provider gate, the inline parse and varint bound, the out-slice
  layout and the return values, and the caller census; inference for
  the names "step-and-fill", "inner iterator", "provider" and "key"
  (they describe the observed field roles; the reader, the report
  routine, the known step and the varint decoder are pinned only by
  call-site contract here); unresolved for the items listed at the
  end of this README.
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in them (including
  `endbr64` at the window entry) are genuine instructions present
  in the target binary, not placeholders; the packet checker
  re-verifies sampled instructions byte-for-byte against a fresh
  objdump run and the raw binary.
- Relationship to earlier work: no open WalkCrypto PR covers this
  window (checked this cycle: open-PR snapshot, no 0x5f08790 title).
  The seek-loop packet (0x5f09050) pins the same predicate gate,
  fill gate, provider gate, reader install and report inside the
  seek loop, and the seek-gate packet (0x5f08c40) pins the same
  inner advance; this window is a different vtable method (slot
  +0x40, flanked by the step slot 0x64cc680, the advance slot
  0x64cc690 and the provider slot 0x64cc698). Neither earlier
  window takes an out slice, returns a bool, or runs the +0x38
  dispatch, so this is not a duplicate of either.

## Tool versions

- objdump: GNU objdump (GNU Binutils for Ubuntu) 2.42
- Python: 3.12.3
- Invocation: `objdump -d --start-address=<start>
  --stop-address=<end> work/hl-node-115.bin` from the repository root
  with the relative binary path; frames.txt rows are verbatim
  readelf `--debug-dump=frames-interp` header lines for the window
  and the callees listed in records.json.
- Environment limits, stated honestly: `make doctor` reports
  analysis_ready false on this VM (no cargo/rustc, no git-lfs, no
  Ghidra/Java, no pinned REA package); the REA server path in
  AGENTS.md is therefore unavailable and this packet is grounded in
  objdump disassembly plus relocation and FDE records only. pytest
  is not installed, so the pytest-style test file runs under plain
  python3 via its `__main__` runner.

## Answer

`step_fill(this, out_slice) -> bool`. The out slice is a caller
buffer: +0x00 pointer, +0x08 length, +0x10 u16 tag 0x100 on success.

Dispatch: the +0x38 slot of the object at this+0x00 is compared
against the relocated GOT slot 0x64ed7e0 (value 0x5f08600, the known
step implementation, 391 bytes, excerpted whole). Unequal calls the
slot with (this) and rejoins at the shared predicate check,
skipping the perf block and the inline inner advance — the called
slot performs the step itself, so valid and status arrive preset by
it. Equal runs the perf block, then the inline inner advance.

Perf (dispatch-equal path only): the perf_level GLOB_DAT slot
0x64ed2b0 gates only the TLS getter calls; when the TLS perf byte
at fs:0-0x10b0 exceeds 1, helper 0x606dd10 runs and the counter at
TLS-0x350 + 0x148 increments. The dispatch-unequal path skips this
block entirely.

Inner advance: the object at this+0x50 is advanced through its
+0x20 virtual, then its +0x10 virtual; the +0x10 result is stored
to this+0x58 (valid). Its +0x18 virtual supplies the buffer used by
the reader and by the default-provider inline parse.

Predicate gate: the +0x10 slot of the object at this+0x00 is
compared against the known predicate 0x5f04de0 (20 bytes). Unknown
predicate True continues, False returns False — the same direction
the seek-loop packet verified for node #115. Width (this+0x60)
decides the arm:

- Width nonzero: known predicate plus valid True runs the reader;
  known predicate plus valid False returns False at once; unknown
  predicate True runs the reader; unknown predicate False rejoins
  the shared check, which calls the predicate a second time and
  returns False unless that call is True (in which case it goes
  straight to the provider, skipping the reader).
- Width zero: the reader is skipped. Known predicate goes to the
  fill gate; unknown predicate True goes to the provider gate;
  unknown predicate False returns False at once.

Reader: called with (stack record, inner +0x18 buffer, width
this+0x60, flag 0) at 0x5f0896f, installing code -> this+0x68,
subcode -> this+0x6c, detail -> this+0x70; the previous detail is
freed with array delete AFTER the install. Code zero rejoins the
shared check and proceeds to the fill gate; code nonzero is
reported at level 3 via 0x5fceda0 with context this+0x78, format
`[%s:538] In MemtableIterator: %s`, file `db/memtable.cc`, detail
this+0x70, then rejoins the shared check, whose fill gate fails on
the nonzero code — so a reader failure reports once and returns
False.

Fill gate: valid nonzero AND code zero, else return False. On the
unknown-predicate path the +0x10 virtual is called again here and
must be True.

Provider gate: the +0x50 slot of the object at this+0x00 is
compared against the relocated GOT slot 0x64ed7b0 (value 0x5f05e10,
the default key provider, 107 bytes). Equal runs the inline
length-prefix parse of the inner +0x18 buffer: a first byte below
0x80 is the length itself and the slice starts one byte later;
otherwise a bounded LEB128 varint at the buffer start (limit
buffer + 5, via 0x61bd4f0) gives the length and the slice starts
past the varint. Unequal calls the +0x50 slot with (this) and its
(pointer, length) return is the filled slice. Either way out+0x10
is set to 0x100 and the function returns True.

Return values: True when a key was filled into out_slice, False
when no key is available — predicate False, valid False, fill
gate failed, or the reader installed a nonzero code (after
reporting).

## Unresolved

- The names of the vtable methods at slots +0x38 and +0x40 beyond
  their observed roles (step dispatch target and step-and-fill).
- The reader 0x5f07670 internals (record, buffer, width, flag
  contract only).
- The +0x38 slot's behaviour when it is not the known step (called,
  then the shared check runs; its own advance/valid effects are
  not pinned here).
- Whether the second predicate call on the unknown-False rejoin
  can ever observe a different result (the binary re-tests; the
  model treats a second False as the return condition).
