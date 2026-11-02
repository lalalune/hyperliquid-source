# RE-001: map node #94 memtable iterator step (0x5168160)

Task: RE-001 (#94 function map). Bounded question: how does one
complete step of a memtable iterator refresh its underlying iterator,
decide whether the current entry passes the checksum check, and fill
the caller's key slice — and what does it return when the entry
fails?

- Component: node #94 memtable iterator step. One window, extracted
  from the digest-verified work binary (SHA-256
  `3b7179cd…c0459f`): `0x5168160..0x51683fb` (667 bytes, FDE
  0xf7d1e4, LSDA 0xce1518). It is the immediate neighbour of the
  #1984 refresh-handler family and drives both pieces that family
  mapped separately: the refresh virtuals, then the #1985 entry
  check as its reader, plus the key-slice fill the handlers lack.
- Claim status: observation for the window bounds, the head gate,
  the inline refresh order, the perf prologue, the width dispatch,
  the predicate gate in both arms, the reader call and install
  order, the report call and its arguments, the key-provider gate,
  the length-prefix parse in both forms, the 0x100 tag value, the
  two rejoin quirks, and the caller census; inference for the
  names "iterator step", "inner iterator", "ready", "tag width"
  and "key slice" (they describe the observed field roles; the
  report format literally names MemtableIterator); unresolved for
  the semantic of the 0x100 tag, the identities of the virtuals
  beyond their observed roles, and exception cleanup beyond the
  stack-canary check.
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in it (including
  `endbr64` at each window entry) are genuine instructions present
  in the target binary, not placeholders; the packet checker
  re-verifies sampled instructions byte-for-byte against a fresh
  objdump run and the raw binary.
- Relationship to earlier work: no open WalkCrypto PR covers this
  window (checked this cycle: open-PR refresh, no 0x5168160 title).
  The five refresh handlers (#1984) return void and install a
  record; this step returns a bool and fills a key slice. The
  entry check (#1985) is used here by contract as the reader; the
  default key provider 0x51657e0 is excerpted whole here because
  the step inlines it when the vtable slot matches.

## Tool versions

- objdump: GNU objdump (GNU Binutils for Ubuntu) 2.42
- Python: 3.12.3
- Invocation: `objdump -d --start-address=<start>
  --stop-address=<end> work/hl-node-94.bin` from the repository root
  with the relative binary path; frames.txt rows are verbatim from
  work/fde94/node-94-fde.tsv.
- Environment limits, stated honestly: `make doctor` reports
  analysis_ready false on this VM (no cargo/rustc, no git-lfs, no
  Ghidra/Java, no pinned REA package); the REA server path in
  AGENTS.md is therefore unavailable and this packet is grounded in
  objdump disassembly plus relocation and FDE records only. pytest
  is not installed, so the pytest-style test file runs under plain
  python3 via its `__main__` runner.

## Answer

`step(this, key_out) -> bool`. The `this` fields: inner iterator
object at +0x50, ready flag at +0x58, tag width at +0x60, installed
check code at +0x68, subcode at +0x6c, detail string at +0x70,
report context at +0x78.

Head: the vtable slot at +0x38 is compared against the relocated
GOT value 0x5167fd0 (the #1984 fd0 handler address). Equal: the
inline path runs the perf prologue (perf-level slot 0x5777ef8
nonzero calls getter 0x56606a0; TLS byte fs:0-0x10a8 above 1 calls
perf helper 0x52cd6e0 and increments the counter at TLS-0x350+0x148),
then calls the inner object's +0x20 virtual, then its +0x10
virtual, storing the result to +0x58. Unequal: that +0x38 virtual
is called instead, its return is taken as the ready flag, and the
inner virtuals are skipped.

Width: width +0x60 zero skips the reader. Otherwise the predicate
gate runs: vtable slot +0x10 compared against the known predicate
0x51647b0. Known: the gate is inlined — ready nonzero and code
zero. Unknown: the +0x10 virtual is called and its bool is the
gate. On a passed gate the reader runs: buffer from the inner
+0x18 virtual, entry check 0x5167040 as
`reader(record, buffer, width, 0)`; its code/sub/detail install
to +0x68/+0x6c/+0x70, and the previous detail string is freed with
array delete after the install. The flow then rejoins the gate:
known gates re-check ready and code == 0; unknown predicates are
called again and must still be true. A failed check (code != 0)
reports first via 0x522e770 at level 3, context +0x78, format
"[%s:538] In MemtableIterator: %s", file "db/memtable.cc",
detail +0x70 — and, for the known gate, returns False after the
report.

Key fill (every True path): the vtable slot at +0x50 is compared
against the relocated GOT value 0x51657e0, the default provider.
Equal: the provider is inlined — buffer from the inner +0x18
virtual, length-prefix parsed (first byte below 0x80 is the
length, slice starts one byte later; otherwise a bounded LEB128
varint at the buffer start, limit buffer + 5, via 0x541cec0,
slice starts past the varint). Unequal: that virtual is called
and its (ptr, len) return is the slice. Every True path writes
the u16 value 0x100 at key +0x10.

Quirks (modelled literally, tested): in the width != 0 path an
unknown predicate returning False is called a second time after
rejoining the gate, and a True second call fills the slice with
no reader call; after a failed check, an unknown predicate that
still returns True reaches the slice, so the step reports and
still returns True, while a predicate mirroring the known gate
returns False there.

Census: 0 direct calls, 0 tail jumps, exactly one RELATIVE slot
at VA 0x575b270 (in the same vtable region as the predicate and
the #1984 handler slots) — this step is reached virtually, not
by direct call.
