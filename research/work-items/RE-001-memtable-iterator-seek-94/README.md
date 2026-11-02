# RE-001: map node #94 memtable iterator seek loop (0x5168a20)

Task: RE-001 (#94 function map). Bounded question: how does a memtable
iterator seek to a target internal key — what pre-filter can reject the
key before any seek, how does it position, fill, compare and advance,
and what happens when a check fails on the first entry versus after an
advance?

- Component: node #94 memtable iterator seek loop. One window, extracted
  from the digest-verified work binary (SHA-256
  `3b7179cd…c0459f`): `0x5168a20..0x5169220` (2048 bytes, FDE
  0x1316ed0, LSDA 0xbd8aef). It is the immediate neighbour of the
  0x5168610 method and the #1989 step, and it drives the pieces those
  mapped separately: the #1984 refresh handler, the #1985 entry check
  as its advance-path reader, the known predicate, and the default key
  provider, plus a hash-table probe and a status copy the step lacks.
- Claim status: observation for the window bounds, the probe math, the
  probe gates, the inner seek/valid/refresh sequence, the predicate
  gate in both arms, the status-copy mechanics and both rejoin paths,
  the +0x20 gate and its inline reposition sequence, the key-provider
  gate and length-prefix parse, the compare sign-to-action mapping,
  the trailer check, the advance gate and reader install order, the
  report call and its arguments, the perf counter offsets, and the
  caller census; inference for the names "seek loop", "probe table",
  "prefix object", "comparator holder" and "status copy" (they describe
  the observed field roles; the report format literally names
  MemtableIterator); unresolved for the identity of 0x5242050 and its
  +0xa0 virtual's return, the +0x48 object's +0x28 subtrahend, the
  effect of the inner +0x50 virtual in the reposition sequence, the
  inner iterator's Seek positioning, and the provider's varint-failure
  path.
- Note on evidence text: the raw disassembly excerpt is verbatim
  objdump output. Instruction mnemonics appearing in it (including
  `endbr64` at the window entry) are genuine instructions present
  in the target binary, not placeholders; the packet checker
  re-verifies sampled instructions byte-for-byte against a fresh
  objdump run and the raw binary.
- Relationship to earlier work: no open WalkCrypto PR covers this
  window (checked this cycle: open-PR refresh, no 0x5168a20 title).
  The refresh handler (#1984), the entry check (#1985) and the step
  (#1989) are used here by contract or as the advance-path reader;
  the probe, the status copy and the compare/advance loop are new.

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

`seek(this, target) -> void`. The `this` fields: probe-table object
at +0x28 (or null), prefix object at +0x30, comparator holder at
+0x48, inner iterator at +0x50, ready flag at +0x58, check width at
+0x60, installed check code at +0x68, subcode at +0x6c, detail string
at +0x70, report context at +0x78. The target is a slice (ptr, len)
whose last 8 bytes are the trailer; the user key is the slice minus
the trailer.

Probe (skipped when +0x28 is null or the prefix object's +0xa0
virtual returns false): the probe slice is (target ptr, target len -
8 - the +0x48 object's +0x28 word). The prefix object's +0x98
virtual return (ptr, len) is hashed by 0x5422e70 with seed
0xbc9f1d34. Base index = (hash * table count) >> 32 with count =
table +0x0 (u32); each round r tests word table[base XOR r] against
a two-bit mask from the hash — bits (hash & 63) and ((hash >> 6) &
63); a mask bit clear in the word is a miss. The hash rotates right
12 (64-bit ror) each round; the loop runs table +0x4 (u32) rounds
but always tests at least the round-0 word, and prefetches
table[base] first. Miss: ready = False, the rsp+0x30 temporary is
destroyed when its pointer slot is set, return. Hit: continue.

Inner seek: inner +0x30 virtual with the target, then inner +0x10
virtual stored to ready; then the refresh handler 0x51684d0 runs.

Predicate gate (vtable +0x10 vs known 0x51647b0): known means ready
nonzero AND code zero; unknown calls the +0x10 virtual. Known clean
goes straight to the fill gate. Otherwise the status copy runs:
the installed record (code, sub, detail) is copied to a stack
record — the vtable +0x68 slot is a Status() virtual called with
(record out-pointer, this) when it differs from the known
implementation 0x5165050 (GOT 0x57783d8), otherwise the copy is
inlined, deep-copying the detail string. Copy code nonzero: the
copy's detail is freed and the flow rejoins the fill gate. Copy
code zero: the +0x20 gate runs (any slot other than the cf0 handler
from GOT 0x5778418 is called with this; the cf0 flavor runs the
inline sequence: inner +0x50 virtual, inner +0x10 valid stored to
ready, refresh 0x51684d0) and the flow rejoins the fill gate.

Fill gate: known re-checks ready AND code == 0, else return;
unknown calls the +0x10 virtual a second time and must be True,
else return. Fill: the key-provider gate (vtable +0x50 vs the
default provider 0x51657e0 from GOT 0x57783f8) inlines the
length-prefix parse of the inner +0x18 buffer, otherwise calls the
+0x50 virtual; the current slice is (entry ptr, parsed length - 8).

Compare: the +0x10 virtual of the +0x48 object's +0x20 subobject
is called with the target and current slices; observed
sign-to-action mapping: positive stops the seek, zero falls to the
trailer check, negative advances. Trailer check (only on a zero
compare): the entry trailer qword (8 bytes at entry + user length)
vs the target trailer qword (last 8 bytes of the target),
unsigned; entry trailer below target trailer advances, otherwise
the seek stops.

Advance: the +0x48 gate (vtable +0x48 vs the e40 handler from GOT
0x5778420) inlines inner +0x28 (next) then inner +0x10 (valid ->
ready) for the known flavor, otherwise calls the +0x48 virtual.
Then, when width is nonzero, the predicate gate runs again (known:
ready and code == 0; unknown: call, and a False first call rejoins
the fill gate, which calls it a second time). On a passing gate the
entry check 0x5167040 runs as reader(record, buffer, width, 0) and
its code/sub/detail install to +0x68/+0x6c/+0x70, freeing the
previous detail with array delete after the install. A nonzero
installed code reports via 0x522e770 at level 3, context +0x78,
format "[%s:538] In MemtableIterator: %s", file "db/memtable.cc",
detail +0x70, and rejoins the fill gate — which, for the known
predicate, returns at once because the code is still set, while
for an unknown predicate that still returns True the seek fills
and may advance again. A failed check on the initial seek reports
nothing: the fill gate simply returns.

Perf: the entry call to 0x52cd6e0 is unconditional; when the TLS
perf byte exceeds 1, further helper calls increment counters at
TLS-0x350 offsets +0x140 (entry path), +0x200 (probe hit), +0x208
(probe miss), +0x0 (fill path) and +0x150 (advance path). When the
perf byte exceeds 2 at entry, the 0x5242050 prologue runs and its
acquired pointer is destroyed via 0x5165320 on exit when non-null.

Caller census (per-byte e8/e9 scan + whole-file qword scan +
.rela.dyn parse): 0 direct calls, 0 tail jumps, exactly one
RELATIVE slot at VA 0x575b260 (neighbours 0x575b258 -> 0x5168610
and 0x575b270 -> 0x5168160); the single qword file-offset hit
0x189240 is that slot's addend field, not a separate reference.
The window is reached only through its vtable slot.
