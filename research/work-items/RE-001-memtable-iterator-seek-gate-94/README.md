# RE-001: map node #94 memtable iterator seek gate (0x5168610)

Task: RE-001 (#94 function map). Bounded question: how does a memtable
iterator seek to a target internal key when a prefix chain and a probe
table are present — what gates run before any positioning, what does a
probe miss do, and what does a probe hit do?

- Component: node #94 memtable iterator seek gate. One window, extracted
  from the digest-verified work binary (SHA-256
  `3b7179cd…c0459f`): `0x5168610..0x5168a17` (1031 bytes, FDE
  0x1316e8c, CIE 0x1301ae8, LSDA 0xbd8ac4). It is the immediate
  neighbour of the #1991 seek loop and the #1989 step, and it drives
  pieces those mapped separately: the #1984 refresh handler as its
  post-seek step, and the probe machinery the seek loop shares.
- Claim status: observation for the window bounds, the field layout,
  the perf prologue and counters, the four chain levels and their
  slice lengths, the known-function shortcut, the probe math (base,
  mask, rotation, rounds rule, prefetch), the miss outcome, the inner
  seek/valid/refresh sequence, the timer record layout and its
  destructor, and the caller census; inference for the names "seek
  gate", "prefix chain", "probe table" and "comparator holder" (they
  describe the observed field roles; the report format in the
  neighbouring packets literally names MemtableIterator); unresolved
  for the identity of 0x5242050 and its +0xa0 virtual beyond the timer
  role, why the known function 0x5165f20 passes a chain level without
  a call, the identity of the perf helper 0x52cd6e0, the hash
  0x5422e70 internals, the constant 8 in the .rodata table rows, and
  the count-0 / null-chain-object edges.
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in them (including
  `endbr64` at the window entry) are genuine instructions present
  in the target binary, not placeholders; the packet checker
  re-verifies sampled instructions byte-for-byte against a fresh
  objdump run and the raw binary.
- Relationship to earlier work: no open WalkCrypto PR covers this
  window (checked this cycle: open-PR refresh, no 0x5168610 title).
  The refresh handler (#1984) is used here as the post-seek step; the
  seek loop (#1991) shares the probe machinery (same +0x98 transform
  slot, same hash seed 0xbc9f1d34, same table layout) but has a
  compare/advance loop and a status copy this window lacks, while this
  window has the four-level chain gate the seek loop lacks; the entry
  check (#1985) is reached only through the refresh handler, not
  directly from here. The known function 0x5165f20 is referenced by
  relocation only and is not analysed here.

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

`seek(this, target) -> void`. The target is a slice pointer (ptr at
+0x0, len at +0x8) whose last 8 bytes are the trailer. The `this`
fields: probe-table object at +0x28 (or null), prefix-chain object at
+0x30, comparator holder at +0x48, inner iterator at +0x50, ready
flag at +0x58.

Perf prologue. The perf helper 0x52cd6e0 runs unconditionally. The
perf-level slot 0x5777ef8 (a GLOB_DAT for the rocksdb perf_level
thread-local) gates only the TLS getter calls (0x56606a0), not the
counters: when the slot is nonzero the getter runs at the entry block,
the perf-level-1 block, and the hit/miss blocks. The TLS perf byte
(fs:0-0x10a8) above 2 installs a timer record on the stack: the
object from 0x5242050 goes to rsp+0x48, the start value from that
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
the known function 0x5165f20 (the R_X86_64_RELATIVE addend at slot
0x5778400), the call is skipped and the chain descends; any other
virtual is called on that level's slice. The fourth level always
calls its +0xa0 virtual. A called predicate returning False sends
control to the inner seek with no probe.

Probe. The first prefix object's +0x98 virtual transforms the first
slice (target_ptr, probe_len); the result is hashed by 0x5422e70
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
virtual result is stored to +0x58 (ready), and the refresh handler
0x51684d0 runs on `this`. The timer record, when its stored start
value is nonzero, is then destroyed by 0x5165320 (whole-function
excerpt timer-destructor.txt): with the record flag byte at +0x41
zero, the end value comes from the object's +0xa0 virtual, and the
elapsed value (end minus start) is added to the +0x138 counter when
the record flag byte at +0x40 is nonzero (it is 1 exactly when the
timer was installed). The record's +0xb0 arm and its +0x20 object
call are dead for this caller (rsp+0x41 and rsp+0x60 are both zero).

Census (per-byte e8/e9 scan + whole-file qword search + .rela.dyn
parse): 0 direct calls, 0 tail jumps, exactly one qword hit at file
offset 0x189228 — the function field of the (slot, 8, function)
.rodata table row starting at 0x189218, which pairs RELATIVE slot
0x575b258 with this window — and exactly one RELATIVE slot at VA
0x575b258, in the same vtable-region slot sequence as the #1984
refresh family. The window is therefore reached virtually, not by
direct call.
