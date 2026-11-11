# RE-001: pin node #115's SystemClockWrapper vtable installers and the entry thunks' mode-1 callers

## Bounded question

What are the exact roles of node #115's five SystemClockWrapper
vtable installer routines (0x5fd0090, 0x6029110, 0x6029230,
0x6029500, 0x6029620), the shared helpers they call, and the
three FactoryEntry entry thunks' mode-1 callers (0x5fcc5d0,
0x5fcc600, 0x5fcc630)? This resolves the open unknowns the
RE-001-canonical-lea-sites-115 packet left behind (its installer
question) and answers the question that packet posed about
which caller passes what pointer to mode 1.

## The five installers

The wrapper is 0x30 bytes: +0x00 vtable, +0x08..+0x18 the
options vector, +0x20/+0x28 the wrapped-clock shared_ptr.

- **V1 0x5fd0090 (ctor C1)**: installs the wrapper vtable
  0x64cdd88, zeroes +0x08..+0x18, copies the wrapped-clock
  shared_ptr into +0x20/+0x28 with a use-count bump, and
  appends the record `{"", this+0x20, 0x6504b80}` via the
  append helper at 0x5fd0124. Sole caller: the Emulated C1
  at 0x60293b6.
- **V2 0x6029110 (Emulated D2, slot 0)**: releases the +0x28
  shared_ptr via the last-use helper, installs the base
  vtable 0x64d3420+0x10, and destroys the +0x08 options
  vector (string-dispose each 0x30-byte record, then free
  the buffer). No direct callers; installed by the RELATIVE
  record at 0x64d1650 (emulated vtable slot 0).
- **V3 0x6029230 (wrapper D2)**: byte-identical to V2. Sole
  caller: the Emulated C1 landing pad at 0x6029357.
- **V4 0x6029500 (wrapper D0)**: the D2 body plus operator
  delete 0x30. Completely unreferenced: no direct caller,
  no qword hits, no RELATIVE slot. This explains why the
  wrapper vtable slots 0 and 1 are null.
- **V5 0x6029620 (Emulated D0, slot 1)**: the D2 body plus
  operator delete 0x50. No direct callers; installed by
  the RELATIVE record at 0x64d1658 (emulated vtable slot 1).

## The shared helpers

- **Append 0x6099ce0**: appends one 0x30-byte
  `{std::string, qword, qword}` record to the vector at
  owner+0x08..+0x18. SSO copy for len<=15, `_M_create`
  for longer names, grows via 0x6099790 at capacity. 37
  direct callers binary-wide (shared Configurable
  machinery); the clock sites are the wrapper ctor
  (0x5fd0124) and the emulated ctor (0x6029454,
  0x6029494).
- **Grow 0x6099790**: doubles the capacity
  (0xaaaaaaaaaaaaaaab divide-by-48, max check against
  0x2aaaaaaaaaaaaaa, overflow allocation
  0x7fffffffffffffe0), move-constructs the records (SSO
  strings copied inline, heap strings moved with the
  source nulled), frees the old buffer. Sole caller
  0x6099e0a.
- **Last-use helper 0x5d35070**: control-block slot 0x10
  dispose, weak-count decrement at +0x0c (lock xadd iff
  the byte at 0x64ed290 is 0), old weak count 1 tail-jumps
  to slot 0x18 destroy. 654 direct calls and 36 tail
  jumps binary-wide (shared libstdc++ machinery); the
  clock sites are 0x6029221, 0x6029341, 0x6029611,
  0x6029731, 0x60298d3 and 0x5fe295d.
- **Landing pad 0x602934c**: `_M_dispose` temp string
  (r12 = rsp+0x30), calls the wrapper D2, checks the
  stack canary, `_Unwind_Resume`. Jumped to from
  0x60294d8 in the emulated ctor.

## The Emulated ctor

**0x6029390 (EmulatedSystemClock ctor C1)**: calls the
wrapper ctor, installs the emulated vtable 0x64d1650,
reads the wrapped clock's slot-24 GetCurrentTime
(rdi=rsp+0x20 out, rsi=wrapped, rdx=rsp+0x18 value_out;
rsp+0x18 preloaded with the constant 0x4fb647d0), stores
the value at +0x30, duplicates the mode byte at
+0x48/+0x49, zeroes +0x38/+0x40, and appends two records
(`{"", this, 0x6505960}` and `{"", this, 0x6505920}`).
Exactly two callers: the TimeEmulatedSystemClock
invoker 0x5fcd550 (mode 0) and the factory 0x60297a0
(mode 1).

## The three entry thunks and the mode-1 answer

The thunks (0x5fcc5d0 MockEnv, 0x5fcc600 CompositeEnv,
0x5fcc630 TimeEmulatedSystemClock) share one body: the
manager takes (dest rdi, src rsi, op edx); op 0 installs
the vtable at (%rdi), op 1 stores rsi at (%rdi), op 2
clones the 8-byte functor storage, op 3 destroys the
functor (a no-op for a plain function pointer). No direct
calls — only the lea sites 0x5fd280c, 0x5fd288f and
0x5fd2124.

**The mode-1 answer: no caller passes a mode-1 pointer
through the thunks.** A binary-wide scan found no real
manager invocation with op 1 (the single edx=1
candidate at 0x2320375 is a GOT call at 0x64e00a0, not
a manager call), and no edx=0 invocation either. Only
ops 2 and 3 are exercised: op-2 clone in the registry
insert 0x5fd24c0 at 0x5fd2526 and in the registry find
0x61c9d70 (per #3764); op-3 destroy in reg-sysclocks
0x5fd27c0 (0x5fd2874, 0x5fd28ea), in default-init
0x5fd20d0 (0x5fd22fe) and in the registry node D2
0x5fcc700 (0x5fcc72b). Mode 1 reaches the emulated
clock through the factory 0x60297a0, not through a
thunk.

## The registrations

- **0x5fd27c0 RegisterBuiltinSystemClocks**: builds the
  {manager=thunk1, invoker=0x5fcd5b0} function named
  "MockEnv" and the {manager=thunk2, invoker=0x5fcf450}
  function named "CompositeEnv", inserts each via
  0x5fd24c0 (0x5fd2848, 0x5fd28c3), destroys the temps
  with op 3, then calls 0x61f8700.
- **0x5fd20d0 default initializer**: builds the
  {manager=thunk3, invoker=0x5fcd550} function named
  "TimeEmulatedSystemClock" and inserts it inline (same
  shape as insert: new 0x30 function node, new 0x70
  entry, op-2 clone, mutex lock, 0x5fd1da0 at 0x5fd22b4,
  op-3 destroy at 0x5fd22fe, 0x61f8700 at 0x5fd2310).
  The 0x30-byte function node's vtable pointer is
  0x64cde88 (node vtable slot 2, 0x5fcc7e0); that slot's
  role is an open unknown.
- **0x5fd24c0 insert**: new(0x30) function node (vtable
  0x64cde68), op-2 clone of the caller's function,
  new(0x70) entry (vtable 0x64d8ed0), name string copied
  via 0x5fcd6f0, mutex lock, calls 0x5fd1da0 under the
  lock, frees the temp node on failure and destroys the
  entry on the duplicate path.
- **0x5fcc700 registry node D2**: installs the node base
  vtable 0x64cde68, destroys the stored function via
  manager op 3 (0x5fcc72b), then tail-jumps to the
  entry's D0 (slot 1 of the entry object at node+0x08).

## The invokers and the factory

- **0x5fcd550 TimeEmulatedSystemClock invoker**: new(0x50)
  + Emulated C1 (mode 0, wrap the PosixClock). Lea'd at
  0x5fd211d.
- **0x5fcd5b0 MockEnv invoker**: holder accessor
  0x5fe2860, then the factory 0x60297a0 (mode-1 emulated
  clock), stores the holder in the cell. Lea'd at
  0x5fd2805.
- **0x5fcf450 CompositeEnv invoker**: new(0x60), holder
  accessor, 0x5fcf430, 0x5fcf390, builder 0x5fd7360
  (FDE 0x5fd7360..0x5fd7466; calls append 3x). Lea'd at
  0x5fd2885.
- All three share the swap shape: replace the *(*rdx)
  cell, D0-delete the old clock if non-null.
- **0x60297a0 factory**: make_shared<EmulatedSystemClock>
  — new(0x60), in-place control block (vtable 0x64d1c38,
  counts 0x100000001), Emulated C1 (mode 1, wrapped =
  0x5fcf430(holder)), installs the shared_ptr into the
  holder via 0x6028d80. Sole caller: the MockEnv invoker
  at 0x5fcd5c0.
- **0x5fcf430 accessor**: 9 bytes, returns arg+0x38
  (the holder's wrapped-clock shared_ptr slot). 19
  callers.

## Corrections to #3352

- The canonical-address qwords at file offsets 0x10f9f0
  and 0x15d270 are .rela.dyn RELATIVE addends (r_offset
  0x64cde48 wrapper slot 24, and 0x64ed3e8 GOT slot), not
  .eh_frame data.
- Record third fields 0x6504b80/0x6505960/0x6505920 are in
  .bss (runtime-initialized); their contents are not
  recoverable statically. 0x6504b80 is also lea'd at
  0x5fd1bb8 (static initializer 0x5fd19a0..0x5fd1c56);
  0x6505960/0x6505920 are also lea'd at 0x6029e50/
  0x6029fe0 inside the factory.

## What this packet contains

- `append-6099ce0.objdump.txt`, `grow-6099790.objdump.txt`,
  `emu-ctor-6029390.objdump.txt`,
  `lastuse-5d35070.objdump.txt`,
  `landing-602934c.objdump.txt`,
  `reg-sysclocks-5fd27c0.objdump.txt`,
  `default-init-5fd20d0.objdump.txt`,
  `insert-5fd24c0.objdump.txt`,
  `invoker-mockenv-5fcd5b0.objdump.txt`,
  `invoker-timeemu-5fcd550.objdump.txt`,
  `invoker-composite-5fcf450.objdump.txt`,
  `factory-60297a0.objdump.txt`,
  `accessor-5fcf430.objdump.txt`,
  `node-dtor-5fcc700.objdump.txt`: whole-function verbatim
  excerpts of the new windows.
- `vtable_install_1.txt` .. `vtable_install_5.txt` and
  `entry_install_1.txt` .. `entry_install_3.txt`:
  re-shipped byte-identical from
  RE-001-canonical-lea-sites-115 (SHA-256 pinned in
  records.json and checked by verify.py).
- `frames.txt`: the 22 FDE ranges.
- `callers.tsv`: 798 rows — every direct call, tail jump
  and lea reference for the pinned routines, with the
  smallest enclosing FDE as the caller.
- `relocations.txt`: 47 RELATIVE records — the
  FactoryEntry vtable headers (5), the wrapper vtable
  header + slots 2..25 (24), the registry node vtable
  (4), the emulated slots 0-1 (2), the make_shared
  control-block vtable (6), the holder vtable (2), the
  registry entry vtable (3) and the GOT canonical slot (1).
- `records.json`: semantic records only — the installer
  roles, the append/grow/last-use rules, the emulated
  ctor, the thunk manager op table and the mode-1 answer,
  the registrations, the invokers, the factory, the
  holder, the relocations, the literals, the census, the
  corrections to #3352 and the open unknowns. No
  per-instruction mnemonic list: instruction-level detail
  lives only in the raw excerpt text files, kept verbatim
  and whole-function.
- `verify.py`, `census.py`, `export_excerpts.py`,
  `gen_records.py` in the packet. The objdump command
  recorded here is
  `objdump -d --start-address=<start>
  --stop-address=<stop> work/hl-node-115.bin`.
  The mnemonics in the excerpts (endbr64 included) are
  genuine instructions present in the target binary, not
  placeholders.

## Verification

`python3 research/work-items/RE-001-systemclock-installers-115/verify.py`
reports ALL CHECKS PASSED: digest, manifest (31 files),
excerpts (22 windows), 19 spot instructions byte-for-byte
vs fresh objdump and the raw binary (including 3 seeded
random gate spots — 0x5fd27cf, 0x5fd23f1, 0x5fd20e3),
frames, relocations, 8 literals, census (798 rows),
semantic records re-derived, model tests.

`python3 tests/test_systemclock_installers_115.py` — 135
checks, 0 failed (run directly, pytest is not installed
on this VM).

## Open unknowns

- Holder class (vtable 0x64ce2d8) and its methods beyond
  slot 2 GetOption.
- Holder initializer 0x5fe2860 full body (cited by contract).
- CompositeEnv builder 0x5fd7360 full body (cited by contract).
- Registry helpers 0x5fd1da0, 0x5fd17c0, 0x61f8b60, 0x61f8700
  exact signatures and the "Environment" string's role in
  insert.
- Node vtable slot 2 (0x5fcc7e0), used as the 0x30-byte
  function node's vtable pointer (0x64cde88) in default-init.
- Factory control-block dispose 0x6025950 / destroy
  0x6025b90 bodies (cited by contract).
- Entry D0 0x5ff2150 body (cited by contract).
- Wrapper vtable slot 14 stays null; its intended target,
  if any, is unknown.

## Environment limits

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java.
All evidence is static disassembly of the materialized
node #115 binary (work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301)
plus `readelf -r` and `objdump --dwarf=frames`. The
`make verify` / `make test` / `make catalogue-check`
gates were not run: they need the Rust toolchain and
the LFS-backed evidence this VM cannot fetch. The packet
ships its own runnable verify.py and the model tests
instead, both run here.
