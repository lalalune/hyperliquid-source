# RE-014: validate node #115 batch lookup (0x5f0d740) against the #94 mapping

Task: RE-014 (migration validation). Bounded question: does node #115
run the same batch lookup — gate, range-set collection, probe filter,
per-entry driver calls with member-feed, both status installs and the
sweep — that the #94 mapping (RE-001, window 0x516d110, PR #2023)
pins, and where do the #115 bytes differ?

- Component: node #115 batch lookup. One window, extracted from the
  digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  `0x5f0d740..0x5f0e2c7` (1415 bytes — smaller than the #94 window's
  2951 bytes, same phase structure in tighter code; FDE .eh_frame
  offset 0x745964, CIE 0x730230). The window's landing pads
  (0x5f0e2af/0x5f0e2bb) tail-jump into the shared cleanup stub
  0x5f0d704..0x5f0d73f (own FDE 0x7459a0: member release, canary
  check, timer destroy, `_Unwind_Resume`), which sits immediately
  after the #2025 probe-gated-lookup window; the stub is excerpted
  whole with the window.
- Claim status: observation for the window bounds, the gate, the flag
  rule, the range-set layout, the collection arrays and pre-init, the
  collection direct/predicate gates, the probe math and counters, the
  driver-phase skip word, the 14 driver arguments, the three driver
  outcomes, the sweep move/callback/fill/limit, the member-feed
  sequence, the perf gating and counters, the epilogue order and the
  caller census; inference for the names "batch lookup", "range set",
  "probe table", "member" and "driver" (they describe the observed
  field roles; the driver, sharded access and transform are pinned
  only by call-site contract here); unresolved for the items listed
  at the end of this README.
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in them (including
  `endbr64` at the window entry) are genuine instructions present
  in the target binary, not placeholders; the packet checker
  re-verifies sampled instructions byte-for-byte against a fresh
  objdump run and the raw binary.
- Relationship to earlier work: no open WalkCrypto PR covers this
  window (checked this cycle: open-PR snapshot, no 0x5f0d740 title).
  The #94 batch-lookup packet is migration input only: every address,
  layout and constant below was re-pinned against #115, and the
  mismatches are preserved in records.json instead of inherited. The
  neighbouring #115 probe-gated lookup 0x5f0d050 (#2025) is the
  immediate predecessor window; its driver 0x5f0ce10 is this
  window's per-entry driver, cited by call site only here beyond the
  FDE range. The probe hash body is byte-identical to #94's
  (established by the RE-014 probe-gated-lookup-115 packet); the
  timer destroy 0x5f05950 is excerpted whole.

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

`batch_lookup(host, options, range_set, arg3, flag_byte) -> void`.
The range set: base object at +0x00 (entry pointer table +0xe00,
skip bitset +0xf08, counter +0xf10), start at +0x08, end at +0x10,
mask words at +0x18/+0x20.

Gate: host +0xc18 null returns 0 at once, nothing else done.
Otherwise the perf helper 0x606dd10 runs unconditionally, the
perf_level GLOB_DAT slot 0x64ed2b0 gates only the TLS getter calls,
and the TLS perf byte at fs:0-0x10b0 decides the timer install
(installed when the byte exceeds 2, via factory 0x5fe2680 with its
+0xa0 virtual start and counter block TLS-0x350 + 0x118).

Flag: stack -0x561 holds options +0x35 when nonzero, else 1 when
host +0xa60 is nonzero, else 0. Zero runs the member-feed before
each driver call; nonzero calls the driver directly.

First scan: the range is scanned for a clear bit under the skip
word (range +0x18 OR range +0x20 OR base +0xf08). Collection plus
probe run only when the flag is nonzero AND host +0xc60 (the probe
table) is non-null AND a clear bit exists; otherwise the driver
phase runs directly.

Collection: 32 empty views are pre-initialised at stack -0x240
(first qword 0x4376fd, the NUL padding just past the .rodata path
string ending `se/src/chain_ext.rs`, second qword 0). Each clear
entry contributes its 16-byte view from entry +0x20 to the views
array (stack -0x240, stride 16) and its index to the indices array
(stack -0x440, stride 8); the count lives at stack -0x570.
Direct-copy gate: stack -0x578 is 1 when host +0xc58 is null, else
the host +0x30 byte. Nonzero copies the view directly; zero calls
the host +0xc58 object's +0xa0 predicate with (object, entry
+0x20) — False skips the entry, True replaces the view with the
+0x98 transform result (rax:rdx pair). This is the main
collection difference from the #94 packet, which describes
collection as gated by the driver flag.

Probe filter: the probe table at host +0xc60 holds count +0x00,
words +0x08, rounds +0x04. Each collected view is hashed with
0x61c34a0 (seed 0xbc9f1d34); base = (count * hash32) >> 32 with
words[base] prefetched. Round k tests words[base XOR k] against
the two-bit mask of hash32 * 0x9e3779b97f4a7c13, ror 12 per round;
every tested round must contain both mask bits, and round 0 is
always tested even when rounds is 0. Results land in a per-entry
byte array (stack -0x4e0; hash32 array -0x4c0, base array -0x340).
Probe-pass entries increment the +0x200 counter; probe-fail
entries are marked done in stack -0x540 and increment +0x208
(both gated on the TLS perf byte exceeding 1).

Driver phase: the range is scanned again under the skip word
(base +0xf08 OR range +0x20 OR stack -0x540, which is range +0x18
on the no-probe path and range +0x18 plus probe-fail bits after
the probe). For each clear entry the driver context pointer is
stack -0x520, the result byte at -0x522 is zeroed, and the flag
byte at -0x521 is 1 when the entry +0x48 object's first byte
equals 6. The driver 0x5f0ce10 (503 bytes, same size as #94's
driver) is called with 14 arguments: host, entry +0x08, entry
+0x68, 1, the original rcx argument, entry +0x71 address, the
entry +0x80 slot +0x50 target (or null), entry +0x88, entry +0x90,
entry +0x48 object, entry +0x50 address, the context pointer, the
result pointer and the flag pointer.

Outcomes: result byte nonzero runs the sweep; result zero with
the flag byte set installs {6, 0, null} into the entry +0x48
record (old +0x08 detail freed with array delete); both zero
advances to the next clear entry.

Sweep: the entry +0x80 pair is moved — its second word is added
to base +0xf10 and its bit is set in base +0xf08; the host +0x50
object's +0xb0 virtual is called with (object, 0x19, 1) when
non-null. When base +0xf10 reaches options +0x78 the fill is
skipped and the driver loop resumes; otherwise every later clear
entry gets {10, 0, null} into its +0x48 record (old detail freed),
and reaching the range end ends the function via the epilogue.

Member-feed (flag zero only): sharded access 0x5f0a9c0 is called
with (host, options, (entry +0x08 object +0x10 field -8 qword) >>
8, the original r8b flag byte); it is the #115 counterpart of #94
0x516a390 at exactly the same size (1676 bytes). The
trailer-stripped slice (start, length - 8) is written to stack
-0x520/-0x518 and passed to transform 0x5f32900 with the member;
the result max-updates entry +0x68 (only when larger) and, when
entry +0x90 is non-null, replaces the string wholesale via
_M_replace with the pair looked up from the member +0x68 table
at index (member +0x90 - (table + 0x18)) / 8, stride 16 into the
table +0x30 pair array. The member is then released via its +0x8
virtual, and control joins the driver call.

Epilogue: the +0x120 counter is incremented when the TLS perf
byte exceeds 1 (perf helper first), the timer is destroyed by
0x5f05950 when its stored start is nonzero, the stack canary is
checked, and the function returns. An empty range, a null probe
table on the no-clear-bit path, and a probe count of zero all
reach the same epilogue.

Census: 2 direct calls (0x5d53d46, 0x5f12a7b, each confirmed as
a real call instruction in objdump output), 0 tail jumps, 0 qword
hits, 0 RELATIVE slots — the window is reached through direct
calls only.

## Unresolved

- Why the host +0x30 byte gates collection direct-copy while the
  driver flag gates the driver path.
- The internals of the sharded access, transform and driver beyond
  their call-site contracts (each is a separate larger item; the
  driver and sharded access match the #94 sizes exactly).
- The consumer width of the moved entry +0x80 pair's second word
  added to base +0xf10.
- The meaning of the original rcx argument passed as the driver's
  5th argument and the original r8b flag passed to sharded access.
