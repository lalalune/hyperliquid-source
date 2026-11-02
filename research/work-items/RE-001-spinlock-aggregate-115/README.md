# RE-001: map node #115 spinlock-guarded aggregate total (0x5f0e2d0)

Task: RE-001 (#115 function map). Bounded question: what does the
function at 0x5f0e2d0 do end to end — how does it guard its table
read, what does it aggregate, what total does it compute and store,
and who calls it?

- Component: node #115 spinlock-guarded aggregate total. One window,
  extracted from the digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  `0x5f0e2d0..0x5f0e51b` (587 bytes; FDE .eh_frame offset 0x358c14,
  length 0x44, CIE 0 — no LSDA asserted). The window immediately
  follows the RE-014 batch-lookup window (0x5f0d740..0x5f0e2c7) after
  int3 padding, and the next function starts at 0x5f0e520.
- Claim status: observation for the window bounds, the lock protocol,
  the aggregate loop, the release point, the value0 formula, the two
  virtual queries, the buffer-size formula, the overflow-checked
  total, the store, the cleanup branch shape and the caller census;
  inference for the names "spinlock", "aggregate" and "total" (they
  describe the observed roles: a 0/1 byte claimed with LOCK CMPXCHG,
  a summed table field, and an overflow-checked sum stored to
  this+0xcd0); unresolved for the items listed at the end of this
  README.
- Note on evidence text: the raw disassembly excerpt is verbatim
  objdump output. Instruction mnemonics appearing in it (including
  `endbr64` at the window entry) are genuine instructions present
  in the target binary, not placeholders; the packet checker
  re-verifies sampled instructions byte-for-byte against a fresh
  objdump run and the raw binary.
- Relationship to earlier work: no open PR covers this window
  (checked this cycle: open-PR snapshot, no 0x5f0e2d0 title). It is
  not a duplicate of the neighbouring RE-014 packets: the seek-gate,
  seek-loop, step-fill, probe-lookup and batch-lookup windows are
  memtable-iterator / lookup methods, while this window takes no
  slice, returns a total (or -1), and is reached by 11 direct calls
  rather than through a vtable slot. Its two +0x78 virtuals are
  pinned by slot only and are not identified with any earlier
  window's callees.

## Tool versions

- objdump / readelf: GNU Binutils for Ubuntu 2.42
- Python: 3.12.3
- Invocation: `objdump -d --start-address=<start>
  --stop-address=<end> work/hl-node-115.bin` from the repository root
  with the relative binary path; frames.txt rows are verbatim
  readelf `--debug-dump=frames-interp` header lines for the window.
- Environment limits, stated honestly: `make doctor` reports
  analysis_ready false on this VM (no cargo/rustc, no git-lfs, no
  Ghidra/Java, no pinned REA package); the REA server path in
  AGENTS.md is therefore unavailable and this packet is grounded in
  objdump disassembly plus relocation and FDE records only. pytest
  is not installed, so the pytest-style test file runs under plain
  python3 via its `__main__` runner.

## Answer

`aggregate_total(this) -> total or -1`. The function takes only the
host object in rdi and returns in rax; the total is also stored to
this+0xcd0 on success.

Lock: the byte at this+0x9f0 is a binary spinlock. A nonzero byte
means held: the loop executes PAUSE and re-checks; once the pause
counter passes 100, each further pause round calls sched_yield
(PLT 0x63f0b20) before re-checking — the first yield happens on the
pause round entered with counter 101. A zero byte is claimed with
LOCK CMPXCHG of 1; losing the race between the read and the cmpxchg
pauses and retries without resetting the counter. The lock is held
only for the aggregate below.

Aggregate: the trip count is 1 << (byte at this+0xf0, masked to 6
bits as x86 shift counts are). The loop sums the +0x38 field of each
of that many 64-byte entries of the table at this+0xe8, wrapping at
64 bits. The lock is then released at once (store 0 to this+0x9f0);
everything after this point runs unlocked.

Value0: from host pointer fields, all wrapping at 64 bits with
arithmetic shifts of wrapped signed differences:
`n960 = (this+0x960 - this+0x940) >> 3`;
`rax = n960 - 1`, except `rax = n960` when this+0x960 is 0 (the adc
after cmp $1 adds the carry of this+0x960 < 1);
`value0 = (this+0x9e0 - this+0x9d0)
  + 8 * ((rax << 6) + ((this+0x948 - this+0x950) >> 3)
  + ((this+0x938 - this+0x928) >> 3)) - sum38`.

Queries: the +0x78 virtual of the object at this+0xa50 is called,
then the +0x78 virtual of the object at this+0xa58. Only the
receiver is deliberately set; both callees are pinned by slot only.

Buffer size: `8 * (this+0xc88 + 4 * this+0xc98 + 7)`.

Total: the overflow-checked sum over [value0, first query result,
second query result, buffer size], in that order, starting from 0.
A value passes only if it is below the bitwise NOT of the running
sum (unsigned); otherwise the function returns -1 at once, stores
nothing to this+0xcd0, and skips the cleanup. On success the total
is stored to this+0xcd0 and returned.

Cleanup: a stack triple (pointer, stored, end), zeroed in-window and
never written otherwise, so in-window it is a no-op: if pointer
differs from stored, stored becomes pointer; if pointer is nonzero,
a sized delete of (end - pointer) bytes fires. The branch shape is
recorded literally and modelled separately; it never fires from
this window's own writes.

Census: 11 direct calls (0x5d9115f, 0x5ecc153, 0x5ecc18c,
0x5eccb2a, 0x5ed0c0d, 0x5ed0de1, 0x5ed19d5, 0x5ed29d0, 0x5f127e2,
0x5f13404, 0x5f13e49), each confirmed as a real call instruction in
objdump output; no tail jump, no whole-file qword hit, no RELATIVE
slot. The window is reached by direct calls only.

## Unresolved

- The semantic identity of the host object and of its +0xe8 table,
  +0x928..+0x9e0 pointer fields, +0xa50/+0xa58 sub-objects,
  +0xc88/+0xc98 counters and +0xcd0 store: only offsets,
  arithmetic and control flow are pinned, not names.
- The bodies of the two +0x78 virtuals and whether their return
  values are sizes, counts or something else.
- The caller functions at the 11 direct call sites: only the call
  sites are pinned, not the callers' purposes.
- Why the stack triple exists when it is always zero in-window
  (dead cleanup from a moved-from or never-filled temporary is the
  plausible shape, not a claim).
