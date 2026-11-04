# RE-014: validate node #115 memtable iterator seek gate (0x5f08c40) against the #94 mapping

Task: RE-014 (migration validation). Bounded question: does node #115
seek a memtable iterator to a target internal key through the same
prefix-chain gate, probe filter and inner seek that the #94 mapping
(RE-001, window 0x5168610) pins — and where do the #115 bytes differ?

- Component: node #115 memtable iterator seek gate. One window,
  extracted from the digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  `0x5f08c40..0x5f09047` (1031 bytes — the same size as the #94
  window, FDE .eh_frame offset 0x745588, length 0x40, CIE 0x730230,
  augmentation bytes `d7 83 02 ff`). The decoded LSDA address is not
  asserted here; the in-window cleanup region (0x5f0900f: timer
  destroy when the start value is nonzero, canary check,
  `_Unwind_Resume` at 0x5f09042) is excerpted whole with the window.
- Claim status: observation for the window bounds, the field layout,
  the perf prologue and counters, the four chain levels and their
  slice lengths, the known-function shortcut, the probe math (base,
  mask, rotation, rounds rule, prefetch), the miss outcome, the inner
  seek/valid/refresh sequence, the timer record layout and its
  destructor, and the caller census; inference for the names "seek
  gate", "prefix chain", "probe table" and "comparator holder" (they
  describe the observed field roles; the #94 packet's report format
  literally names MemtableIterator); unresolved for the identity of
  the known function 0x5f06550 beyond the shortcut role, the perf
  helper 0x606dd10 and the timer factory 0x5fe2680 beyond their
  roles, the hash 0x61c34a0 and refresh 0x5f08b00 internals, the
  decoded LSDA address, and the count-0 / null-chain-object edges.
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in them (including
  `endbr64` at the window entry) are genuine instructions present
  in the target binary, not placeholders; the packet checker
  re-verifies sampled instructions byte-for-byte against a fresh
  objdump run and the raw binary.
- Relationship to earlier work: no open WalkCrypto PR covers this
  window (checked this cycle: open-PR refresh, only #2025 open, no
  0x5f08c40 title). The #94 seek-gate packet is migration input
  only: every address, layout and constant below was re-pinned
  against #115, and the mismatches are preserved in records.json
  instead of inherited. The probe hash body is byte-identical to
  #94's (established by the RE-014 probe-gated-lookup-115 packet);
  the refresh consumer here is 0x5f08b00, cited by its call site
  only — its internals are not claimed. The neighbouring #115
  function 0x5f09050..0x5f09850 (FDE 0x7456cc, 2048 bytes) is the
  seek-loop counterpart candidate and is not built here.

## Tool versions

- objdump: GNU objdump (GNU Binutils for Ubuntu) 2.42
- Python: 3.12.3
- Invocation: `objdump -d --start-address=<start>
  --stop-address=<end> work/hl-node-115.bin` from the repository root
  with the relative binary path; frames.txt rows are verbatim
  readelf `--debug-dump=frames-interp` header lines for the window
  and timer FDEs.
- Environment limits, stated honestly: `make doctor` reports
  analysis_ready false on this VM (no cargo/rustc, no git-lfs, no
  Ghidra/Java, no pinned REA package); the REA server path in
  AGENTS.md is therefore unavailable and this packet is grounded in
  objdump disassembly plus relocation and FDE records only. pytest
  is not installed, so the pytest-style test file runs under plain
  python3 via its `__main__` runner.

## Answer

`seek(this, target) -> void`. The target is a slice pointer (ptr at
+0x0, len at +0x8) whose last 8 bytes are the trailer. The `this`
fields: probe-table object at +0x28 (or null), prefix-chain object at
+0x30, comparator holder at +0x48, inner iterator at +0x50, ready
flag at +0x58.

Perf prologue. The perf helper 0x606dd10 runs unconditionally at
entry and again before each counter block. The perf-level slot
0x64ed2b0 (a GLOB_DAT for the rocksdb perf_level thread-local) gates
only the TLS getter calls (0x63f0fe0), not the counters: when the
slot is nonzero the getter runs at the entry block, the
perf-level-1 block, and the hit/miss blocks. The TLS perf byte
(fs:0-0x10b0) above 2 installs a timer record on the stack: the
object from 0x5fe2680 goes to rsp+0x48, the start value from that
object's +0xa0 virtual goes to rsp+0x50, the perf counter block
(TLS-0x350) goes to rsp+0x58, and rsp+0x40 holds the flag byte 1 with
rsp+0x41, rsp+0x44 and rsp+0x60 zero. When the perf byte is above 1,
the +0x140 counter increments at entry, +0x200 on a probe hit, and
+0x208 on a probe miss.

Probe-table gate. A null table at +0x28 skips the chain and the probe
entirely and runs the inner seek. Otherwise the probe length is
`target_len - 8 - comparator_holder+0x28`.

Prefix chain. Up to four objects linked via +0x20, consulted on
progressively 8-byte-shorter slices sharing the target pointer:
probe_len, probe_len - 8, probe_len - 16, probe_len - 24. At each of
the first three levels, when the object's +0xa0 virtual is exactly
the known function 0x5f06550 (the R_X86_64_RELATIVE addend at slot
0x64ed7b8), the call is skipped and the chain descends; any other
virtual is called on that level's slice, and a called predicate
returning True goes straight to the probe. The fourth level always
calls its +0xa0 virtual. A called predicate returning False sends
control to the inner seek with no probe.

Probe. The first prefix object's +0x98 virtual transforms the first
slice (target_ptr, probe_len); the result is hashed by 0x61c34a0
with seed 0xbc9f1d34. With table count `n` (u32 at +0x0), rounds `r`
(u32 at +0x4) and words at +0x8, the base index is
`(n * hash32) >> 32` and words[base] is prefetched. Round `k` tests
word `words[base XOR k]` against the two-bit mask from the rotated
hash: bits `(h & 63)` and `((h >> 6) & 63)`; the hash is the 64-bit
product `hash32 * 0x9e3779b97f4a7c13`, rotated right 12 after each
non-final round. Round 0 is always tested, even when `r` is 0. A mask
bit clear in the word is a miss: ready (+0x58) is set to False and
the function returns with no inner seek and no refresh; the timer
record is destroyed first when its start value is nonzero.

Inner seek (probe hit, predicate False, or null table). The inner
iterator's +0x30 virtual positions it on the target slice, its +0x10
virtual result is stored to +0x58 (ready), and the refresh step
0x5f08b00 runs on `this`. The timer record, when its stored start
value is nonzero, is then destroyed by 0x5f05950 (whole-function
excerpt timer-5f05950.objdump.txt): with the record flag byte at +0x01
zero, the end value comes from the object's +0xa0 virtual, and the
elapsed value (end minus start) is added to the +0x138 counter when
the record flag byte at +0x00 is nonzero (it is 1 exactly when the
timer was installed). The record's +0x20 object call is dead for
this caller (rsp+0x60 is zero), and the start slot is zeroed after
the destroy.
