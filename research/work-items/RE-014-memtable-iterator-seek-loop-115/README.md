# RE-014: validate node #115 memtable iterator seek loop (0x5f09050) against the #94 mapping

Task: RE-014 (migration validation). Bounded question: does node #115
seek a memtable iterator to a target internal key through the same
probe filter, inner seek, predicate-gated status copy, fill/compare/
advance loop and report path that the #94 mapping (RE-001, window
0x5168a20) pins — and where do the #115 bytes differ?

- Component: node #115 memtable iterator seek loop. One window,
  extracted from the digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  `0x5f09050..0x5f09850` (2048 bytes — the same size as the #94
  window, FDE .eh_frame offset 0x7455cc, CIE 0x730230). The decoded
  LSDA address is not asserted here; the exception region
  (0x5f097fe..0x5f0984b: detail free, timer destroy, canary check,
  `_Unwind_Resume` at 0x5f0984b) is excerpted whole with the window.
  Correction to the previous cycle's note: the window's FDE offset is
  0x7455cc as readelf reports it (the 0x7456cc figure in the #2030
  cycle note is off by 0x100); the gate window's FDE at 0x745588 with
  length 0x40 is the immediate predecessor, which corroborates
  0x7455cc.
- Claim status: observation for the window bounds, the perf prologue
  and counters, the probe math and gates, the inner seek/valid/
  refresh sequence, the predicate gate in both arms, the status-copy
  mechanics and both rejoin paths, the +0x20 gate and its inline
  reposition sequence, the key-provider gate and length-prefix parse,
  the compare sign-to-action mapping, the trailer check, the advance
  gate and reader install order, the report call and its arguments,
  and the caller census; inference for the names "seek loop", "probe
  table", "prefix object", "comparator holder" and "status copy" (they
  describe the observed field roles; the report format literally names
  MemtableIterator); unresolved for the identity of 0x5fe2680 and its
  +0xa0 virtual's return, the +0x48 object's +0x28 subtrahend, the
  effect of the inner +0x50 virtual in the reposition sequence, the
  inner iterator's Seek positioning, and the provider's varint-failure
  path.
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in them (including
  `endbr64` at the window entry) are genuine instructions present
  in the target binary, not placeholders; the packet checker
  re-verifies sampled instructions byte-for-byte against a fresh
  objdump run and the raw binary.
- Relationship to earlier work: no open WalkCrypto PR covers this
  window (checked this cycle: open-PR snapshot, no 0x5f09050 title).
  The #94 seek-loop packet is migration input only: every address,
  layout and constant below was re-pinned against #115, and the
  mismatches are preserved in records.json instead of inherited. The
  neighbouring #115 seek gate 0x5f08c40 (#2030) is the immediate
  predecessor window; its refresh consumer is this window's 0x5f08b00,
  cited by call site only here beyond the FDE range. The probe hash
  body is byte-identical to #94's (established by the RE-014
  probe-gated-lookup-115 packet); the timer destroy 0x5f05950 and the
  refresh 0x5f08b00 are excerpted whole.

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

`seek(this, target) -> void`. The `this` fields: probe-table object
at +0x28 (or null), prefix object at +0x30, comparator holder at
+0x48, inner iterator at +0x50, ready flag at +0x58, check width at
+0x60, installed check code at +0x68, subcode at +0x6c, detail string
at +0x70, report context at +0x78. The target is a slice (ptr, len)
whose last 8 bytes are the trailer; the user key is the slice minus
the trailer.

Perf prologue. The perf helper 0x606dd10 (107 bytes) runs
unconditionally at entry and again before each counter block. The
perf-level slot 0x64ed2b0 (a GLOB_DAT for the rocksdb perf_level
thread-local) gates only the TLS getter calls (0x63f0fe0), not the
counters: when the slot is nonzero the getter runs at the entry block,
the probe-hit/miss blocks, the fill block and the advance block. The
TLS perf byte (fs:0-0x10b0; #94 used fs:0-0x10a8) above 2 installs a
timer record on the stack: the timer factory 0x5fe2680 (214 bytes)
runs, its +0xa0 virtual supplies the start value, and the counter
block is TLS-0x350 + 0x138. Counters at TLS-0x350: +0x140 entry,
+0x200 probe hit, +0x208 probe miss, +0x0 fill, +0x150 advance, each
gated on the TLS byte above 1. The timer record (rsp+0x30) is
destroyed by 0x5f05950 (91 bytes, excerpted whole) on every exit when
its stored start is nonzero.

Probe (skipped when +0x28 is null or the prefix object's +0xa0
virtual returns false): the probe slice is (target ptr, target len -
8 - the +0x48 object's +0x28 word). The prefix object's +0x98
virtual return (ptr, len) is hashed by 0x61c34a0 with seed
0xbc9f1d34. Base index = (hash * table count) >> 32 with count =
table +0x0 (u32); each round r tests word table[base XOR r] against
a two-bit mask from the hash — bits (hash & 63) and ((hash >> 6) &
63) of hash * 0x9e3779b97f4a7c13; a mask bit clear in the word is a
miss. The hash rotates right 12 (64-bit ror) each round; the loop runs
table +0x4 (u32) rounds but always tests at least the round-0 word,
and prefetches table[base] first. Miss: ready = False, the timer
record is destroyed when its start is set, return. Hit: continue.

Inner seek: inner +0x30 virtual with the target, then inner +0x10
virtual stored to ready; then the refresh handler 0x5f08b00 runs
(308 bytes, excerpted whole).

Predicate gate (vtable +0x10 vs known 0x5f04de0, 20 bytes): known
means ready nonzero AND code zero; unknown calls the +0x10 virtual.
Known clean goes straight to the fill gate. Otherwise the status copy
runs: for the known flavor this is ready False or code set; for the
unknown flavor it is a False return (a True return goes straight to
the fill gate — verified against the #115 jumps at 0x5f09778..
0x5f09789, and the same direction holds in the #94 bytes, where
unknown True jumps to the fill gate at 0x51690ee; the #94 packet's
records.json "when" line states this polarity reversed). The copy
itself: the installed record (code, sub, detail) is copied to a stack
record — the vtable +0x68 slot is a Status() virtual called with
(record out-pointer, this) when it differs from the known
implementation 0x5f05680 (GOT 0x64ed790), otherwise the copy is
inlined, deep-copying the detail string via 0x61cf610 (63 bytes).
Copy code nonzero: the copy's detail is freed and the flow rejoins
the fill gate. Copy code zero: the +0x20 gate runs (any slot other
than the 0x5f08320 handler from GOT 0x64ed7d0 is called with this;
the 0x5f08320 flavor runs the inline sequence: inner +0x50 virtual,
inner +0x10 valid stored to ready, refresh 0x5f08b00) and the flow
rejoins the fill gate.

Fill gate: known re-checks ready AND code == 0, else return;
unknown calls the +0x10 virtual a second time and must be True,
else return. Fill: the key-provider gate (vtable +0x50 vs the
default provider 0x5f05e10, 107 bytes, from GOT 0x64ed7b0) inlines
the length-prefix parse of the inner +0x18 buffer, otherwise calls
the +0x50 virtual; the current slice is (entry ptr, parsed length -
8). The inline parse: first byte below 0x80 is the length (slice
starts one byte later); otherwise a bounded LEB128 varint at the
buffer start (limit buffer + 5) via 0x61bd4f0 (75 bytes).

Compare: the +0x10 virtual of the +0x48 object's +0x20 subobject
is called with the target and current slices; observed
sign-to-action mapping: positive stops the seek, zero falls to the
trailer check, negative advances. Trailer check (only on a zero
compare): the entry trailer qword (8 bytes at entry + user length)
vs the target trailer qword (last 8 bytes of the target),
unsigned; entry trailer below target trailer advances, otherwise
the seek stops.

Advance: the +0x48 gate (vtable +0x48 vs the 0x5f08470 handler from
GOT 0x64ed7d8, 391 bytes) inlines inner +0x28 (next) then inner
+0x10 (valid -> ready) for the known flavor, otherwise calls the
+0x48 virtual. Then, when width is nonzero, the predicate gate runs
again (known: ready and code == 0; unknown: call, and a False first
call rejoins the fill gate, which calls it a second time). On a
passing gate the entry check 0x5f07670 runs as reader(record,
buffer, width, 0) and its code/sub/detail install to +0x68/+0x6c/
+0x70, freeing the previous detail with array delete after the
install. A nonzero installed code reports via 0x5fceda0 (243 bytes)
at level 3, context +0x78, format "[%s:538] In MemtableIterator:
%s", file "db/memtable.cc", detail +0x70, and rejoins the fill gate
— which, for the known predicate, returns at once because the code
is still set, while for an unknown predicate that still returns True
the seek fills and may advance again. A failed check on the initial
seek reports nothing: the fill gate simply returns.

Caller census (per-byte e8/e9 scan + whole-file qword scan +
.rela.dyn parse, reproduced by census.py): 0 direct calls, 0 tail
jumps, exactly one RELATIVE slot at VA 0x64cc678 (entry at file
offset 0x10c068); the single qword file-offset hit 0x10c078 is that
slot's addend field, not a separate reference. Neighbours in the
same vtable region corroborate the slot identities used above:
0x64cc658 -> 0x5f04de0 (predicate), 0x64cc668 -> 0x5f08320
(reposition handler), 0x64cc670 -> 0x5f08c40 (seek gate),
0x64cc690 -> 0x5f08470 (advance handler), 0x64cc698 -> 0x5f05e10
(provider). The window is reached only through its vtable slot.
