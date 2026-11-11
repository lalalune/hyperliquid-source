# RE-001: flag-gated drain-and-wait routine 0x5d51ab0 (node #115)

## Bounded question

What does the routine at `0x5d51ab0` do to the holder it takes in
`rdi`, and where is that routine used?

## Answer (established semantics)

The routine `0x5d51ab0` takes one argument, a holder pointer in
`rdi`, and returns nothing. It is a complete behaviour end to end,
not a lone-window fragment: the whole 357-byte routine is pinned
(including its landing pads), its entry no-op stub is pinned, and
its 4 direct callers across 2 caller functions are censused.

### Entry

The routine first calls `0x60d5390` with `H+0x700`. That callee is
a five-byte no-op stub (its whole body is in `stub.txt`): it returns
immediately with no observable effect, and the routine ignores its
return value. The entry call is therefore recorded as a no-op, not
as a lock: the lock-shaped calls in this routine are `0x606ca40`
and `0x60d52f0`, used below.

### Drain path (flag byte at H+0x489)

While the byte at `H+0x489` reads nonzero, the routine repeats this
cycle, then re-tests both flags:

1. call `0x60d52f0` on `H+0x700` (the unlock-shaped call);
2. call `0x5fcbe20` on `H+0xd40` (the teardown; its return value
   is ignored, and its internals are not pinned here);
3. call `0x606ca40` on `H+0x700` (the lock-shaped call).

The three `0x5e8e4a0`-caller sites lock `H+0x700` via `0x606ca40`
immediately before calling this routine, so the drain cycle releases
a lock its callers hold and re-acquires it before re-testing. The
drain flag is written by other threads; this packet pins the
routine's own cycle, not the timing of those writes.

### Wait path (flag byte at H+0x48a)

The wait path is tested only after the drain flag reads zero:

- If the byte at `H+0x48a` reads zero, the routine returns.
- If it reads nonzero and the watched field at `H+0x1508` is zero,
  the routine returns without locking.
- Otherwise it locks the mutex at `H+0x14e0`. A nonzero lock result
  reaches the landing at `0x5d51be6`, which checks the stack
  canary and then calls the system-error thrower with the lock error
  code; that path does not return normally.
- While the watched field at `H+0x1508` reads nonzero, it waits on
  the condition variable at `H+0x14b0` with the `H+0x14e0` lock.
- When the watched field reads zero, it unlocks the mutex and
  returns.

### Returns and failure edges

Every normal return passes through the canary check at `0x5d51af4`
(a mismatch reaches the stack-failure handler at `0x5d51be1`). The
landing at `0x5d51bc1` unlocks the `H+0x14e0` mutex when the wait
frame owns it, then resumes unwinding. The routine has a stack
canary, three landing-pad fragments, and a single normal return at
`0x5d51b10` (reached via the shared epilogue at `0x5d51af4`).

### Inferred readings (separate from the observations above)

- The `0x606ca40` / `0x60d52f0` pair reads as lock / unlock of the
  `H+0x700` slot, from their call shape and argument; their
  internals are not pinned here.
- The `H+0x14b0` / `H+0x14e0` / `H+0x1508` triple reads as a
  condition variable, its mutex, and the watched field the wait
  loop tests; which thread clears the watched field is not pinned.
- The holder's source-level name and owning class are not pinned.

### Consumers

Census (executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by the packet's census.py and re-run inside
verify.py): exactly 4 direct calls + 0 tail jumps across 2 caller
functions (see callers.tsv for the site list and caller FDEs); 0
stored qwords, 0 RELATIVE relocations — reached only by code, never
by data. Note the tokens that appear in the verbatim disassembly
excerpts (for example `endbr64` at the routine entry) are genuine
instructions present in the target binary, not placeholders: the
excerpts are unmodified objdump output and verify.py checks every
excerpt line byte-for-byte against the raw binary.

## Packet contents

- `main.txt`: whole-function verbatim objdump excerpt
  (`0x5d51ab0..0x5d51c15`), header normalized to the bare binary
  name only.
- `stub.txt`: whole-function verbatim objdump excerpt of the entry
  no-op stub (`0x60d5390..0x60d5395`).
- `frames.txt`: the routine's FDE line, the stub's FDE line, and
  the 2 caller FDEs.
- `callers.tsv`: the 4 confirmed call sites with caller FDEs.
- `relocations.txt`: header only — no stored references found.
- `records.json`: semantic records only (control flow, flag and
  field map, failure edges, inferences kept separate).
- `verify.py`, `export_excerpts.py`, `census.py`: the packet's own
  runnable checker, excerpt generator, and census.
- `MANIFEST.sha256`: hashes of every other packet file.

## Model and tests

`tools/flag_drain_wait_51ab0_115.py` models the routine's control
flow end to end: the entry no-op, the drain cycle (unlock, teardown,
relock, re-test), the wait path (skip when the watched field is
already zero, lock-failure throw, wait loop until the watched field
clears, unlock), with hooks standing in for the other threads that
clear flags and the watched field. `tests/test_flag_drain_wait_51ab0_115.py`
checks the no-op-only return, single and repeated drains, the
unlock-teardown-relock order, drain-then-wait, the already-clear
wait skip, the wait loop count and unlock, the lock-failure throw
with no wait and no unlock, that the wait path is not entered while
the drain flag is set, the pinned offsets, and that normal returns
are void.

## Verification

- Binary SHA-256 matches `provenance/artifacts.json`
  (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  for node #115).
- `verify.py` prints ALL CHECKS PASSED (digest, provenance,
  manifest, excerpt regeneration byte-for-byte from fresh objdump
  runs, all excerpt lines byte-for-byte vs the raw binary, all FDE
  lines, census including the exact site list, empty relocation
  census, records, model spot checks, and the model tests).
- Three extra spot checks byte-for-byte vs fresh objdump and the
  raw binary, beyond verify.py's own checks: the drain-flag test at
  `0x5d51ade`, the condvar-wait call at `0x5d51b66`, and the entry
  stub return at `0x60d5394`.
- Environment limits, stated honestly: this VM has no cargo/rustc,
  no git-lfs, no Ghidra/Java, and pytest is not installed, so the
  test functions are invoked directly by verify.py. The repository
  gates `make verify` / `make test` / `make catalogue-check` were
  not run here and are left for a tooled environment.
