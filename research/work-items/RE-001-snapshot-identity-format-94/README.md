# RE-001: snapshot identity-format 0x514ed50 (node #94)

Task ID: RE-001. Bounded question: what does node #94 function 0x514ed50
do with its destination object, its source wrapper and its third
argument — how is the destination initialized, how is its identity
string formatted, how are its two chain dispatches resolved, what are
its two conditional side-effect dispatches, and which caller consumes
it?

## What is pinned

Function 0x514ed50..0x514f223 (1235 bytes, FDE 0x00634030) takes a
destination object in rdi, a source wrapper in rsi and a value in rcx
(preserved in r15 before rcx is reused as a rep-stos count). It builds
a 0x130-byte snapshot object:

- Initialization: +0x00..+0x1f zeroed, +0x20 set to an empty stack
  string by the move-assign callee 0x514b4f0, +0x40..+0x128 zeroed by
  vector copies from the zeroed stack area. +0x120 is then overwritten
  with the old destination +0x120 value (read before zeroing) plus 1
  as a 32-bit increment, and +0x128 with the rcx argument verbatim.
- Identity string (dest+0x20): an ostringstream is constructed at
  rsp+0x30. The name comes from calling the inner object's +0x10 slot
  with the wrapper. When it returns a non-null string pointer, the
  stream receives that string, then `@` (one byte at 0x1eeec9), then
  the wrapper pointer itself via `_M_insert<PKv>`, then `#` (one byte
  at 0x1e7f65), then (long)getpid() via the 0x5335850 callee (getpid
  plus cltq) and `_M_insert<long>`. The stream content is copied into
  a fresh string and move-assigned into dest+0x20. So the text is
  `name@pointer#pid`, with the pointer in libstdc++ void* form (`0`
  for null, otherwise lowercase hex with a `0x` prefix).
- Null name: when the +0x10 call returns null, the stream state is set
  with badbit (basic_ios::clear with the old state or 1), so the later
  insertions are no-ops and the formatted string is empty. That sentry
  behavior and the pointer format were cross-checked against the local
  libstdc++ (g++ 13.3), not by executing the target binary.
- Chain dispatches: dest+0x00 is the first non-sentinel +0x70 dispatch
  of the source wrapper chain, and dest+0x08 the first non-sentinel
  +0x78 dispatch. Each walk compares the first node's slot against its
  sentinel cell (0x5777a28 for +0x70, 0x5777a78 for +0x78 — the same
  cells the chain-dispatch getters of RE-001-chain-dispatch-94 compare
  against, shared, not re-claimed), skips while the slot equals the
  sentinel (later comparisons against the previous node's slot value,
  which provably equals the cell on skipped paths), at most four
  skips, and calls the fifth node unconditionally. The wrapper chain
  links through +0x38, the inner object through +0x00, exactly as in
  the chain-dispatch getters.
- Side-effect dispatches: after the walks, the head inner's +0x88 slot
  is called with the wrapper when it differs from cell 0x5777950, and
  then its +0x80 slot is called with the wrapper when it differs from
  cell 0x5777948. Both return values are discarded, and dest+0x10 is 0
  and dest+0x18 is -1 on every path that reaches the tail.
- The function is stack-canary protected (canary slot rsp+0x1a8,
  `__stack_chk_fail` on mismatch). Its exception entries are the two
  landing stubs at the tail of its own range (0x514f20b jumping to the
  full entry 0x514ed1c of the cleanup routine, 0x514f217 jumping to
  the control entry 0x514ed24), each moving the exception object from
  rax to rbx first. The cleanup routine 0x514ed1c..0x514ed4c (48
  bytes, FDE 0x00634084, 4 int3 padding to the window) is cited as the
  window's exception consumer, not claimed as a standalone function:
  its full entry disposes the r13 string and destroys the
  ostringstream, its control entry destroys only the ostringstream,
  and it ends with the canary check and `_Unwind_Resume`.
- Caller census: exactly one direct caller, 0x514f381 in enclosing
  0x514f270..0x514f719, which passes dest = rbx+0x188,
  source = [rbx+0x2d0] and, in rcx, an elapsed value (the +0x98
  dispatch result minus [rbx+0x2c8]). No tail jump or absolute
  pointer to 0x514ed50 exists.

Distinct from the move-assign packet, which cites this window only as
a caller site (census only), and from the chain-dispatch getters,
which model the same walk pattern on different slots but not this
window's formatting, initialization, side-effect dispatches or caller.

## Evidence format

This packet follows the semantic-record format: records.json holds
semantic records only (window, callees, cleanup routine, landing
stubs, walks, format, censuses, composed rule, unknowns). It holds no
per-instruction mnemonic list. Instruction-level detail lives only in
the raw objdump excerpt text files, which are verbatim whole-function
exports produced by export_excerpts.py (the objdump command for each
file is the script itself), except caller.objdump.txt, which is a
sample of the enclosing function around its call site. The mnemonics
in those files — including `endbr64` at the window entry and at both
landing stubs — are genuine instructions present in the target
binary, not placeholders; verify.py re-checks every excerpt
byte-for-byte against a fresh objdump run on the digest-verified
binary.

## Files

- records.json — semantic records (no mnemonic list).
- window.objdump.txt — the whole 1235-byte window plus its 1 int3
  padding byte, ending exactly at the next FDE.
- cleanup.objdump.txt — the shared cleanup routine plus its int3
  padding.
- moveassign.objdump.txt, getpid.objdump.txt — callee excerpts, cited
  as callees only.
- caller.objdump.txt — sample of the enclosing function around the
  sole direct call site (elapsed computation, argument setup, call,
  following constructor call).
- frames.txt — the four FDE lines for the window, cleanup routine and
  two callees, as readelf --debug-dump=frames prints them.
- relocations.txt — PLT stub to GOT resolutions, verified from stub
  bytes.
- verify.py — runnable checker for the records against a node #94
  binary.
- export_excerpts.py — regenerates the excerpts from a node #94
  binary.

## Target binding

All results bind to the node #94 binary SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
(artifacts/node/94/hl-node; work copy work/hl-node-94.bin on checkouts
where that path is still an LFS pointer).

## Unknowns (kept separate from observations)

- The identity and contents of the source wrapper and its inner
  object, and what the dispatch results mean to the caller (they are
  stored verbatim).
- The meaning of the dest fields beyond the observed values: why
  +0x10 is 0 and +0x18 is -1, what the +0x120 counter counts, and what
  the +0x128 value means in general (at the sole direct call site it
  is an elapsed value).
- The streambuf extraction pointer arithmetic at rsp+0x50/0x58/0x60
  is not separately pinned; the observable pinned is that the full
  stream content ends up in dest+0x20.
- The `_M_dispose` call at 0x514eeb9 does not reload its argument
  register in the window (the value is carried from the preceding
  move-assign call); the model does not depend on which string it
  disposes.
- Which call site each landing stub serves (LSDA mapping, not pinned
  from the window bytes).
- The reaching path beyond the sole direct caller: no tail jump or
  absolute pointer to 0x514ed50 exists, so indirect reaching paths
  are left unclaimed.

## Environment limits (stated honestly)

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so no Rust
reconstruction or binary execution was attempted. All claims are
static: disassembly bytes, FDE records, rip-relative resolutions and
the digest-verified binary. The libstdc++ stream and pointer-format
behaviors were cross-checked against the locally installed libstdc++
(g++ 13.3), which validates the library algorithm, not an execution
of the target binary. The repository's `make verify` / `make test`
suites were not re-run for this change: they fail on pre-existing
LFS-pointer baselines in this environment, and this change adds only
new files (a Python model, its tests and an evidence packet) that do
not touch existing code.
