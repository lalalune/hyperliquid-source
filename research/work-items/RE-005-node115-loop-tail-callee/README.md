# RE-005 node 115 — the dispatcher loop's tail callee (lazy thread-local getter)

This packet answers the third question the
thunk / checker-windows packet (#2755) carried
over, for the authenticated hl-node 115 artifact
only (105,896,032 bytes, SHA-256 `a6e2897c…5301`):
what does the body called at 0x2ae21f7 in the
dispatcher 0x2ae1690 compute, what does it return
null vs non-null on, what state does it read and
write per call, and does anything inside it bound
the dispatcher loop's iteration count?

Two bodies are exported in full (`loop_getter`,
`dtor_glue`); every other body is extent/digest
pinned in `records.json` and `frames.txt`.
Reproduce with `tools/loop_tail_callee_static.py`
(`--generate` regenerates; plain run verifies
against `records.json`).

## Verdict: a shared lazy thread-local getter; it bounds nothing

**`loop_getter` 0x5cdf300..0x5cdf3df (223 bytes,
exported)** is the lazy getter for one
thread-local key. Its cell is `{value pointer at
+0x0, state byte at +0x8}`. Its own unreachable
arm is pinned by the compiler to std's native
lazy thread-local implementation: the panic call
at 0x5cdf3d9 (through slot 0x64df730 → panic shim
0x1680e60) passes the 40-byte message
"internal error: entered unreachable code" at
0x94c9db and the Location static 0x64c5748 —
`/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/thread_local/native/lazy.rs`,
line 98, column 36.

Return value, by the entry state byte
`[cell+0x8]` (loaded at 0x5cdf308):

- **state 1 (live)** — returns the cell pointer
  itself (0x5cdf317), reading nothing else and
  writing nothing.
- **state 0 (uninitialised)** — slow path, always
  returns the cell pointer on success:
  - *Adoption arm* (0x5cdf320): if `rsi` is
    non-null and `*rsi` is non-null, the pointer
    is taken out of the slot (slot zeroed at
    0x5cdf328), installed at 0x5cdf334, state set
    to 1 at 0x5cdf337, and control joins the
    registration arm.
  - *Allocation arm* (0x5cdf33d): allocates
    0x28 bytes through slot 0x64df480 (→ alloc
    shim 0x6355830, pinned) and initialises the
    value in place — qwords +0x0 and +0x8 := 1
    (0x5cdf34d / 0x5cdf354), +0x10..+0x1f := 0
    (0x5cdf35f), byte +0x20 := 0 (0x5cdf363) —
    then installs it (0x5cdf373) and sets state 1
    (0x5cdf376). The state byte is reloaded
    (0x5cdf367) before the install: if it is
    meanwhile 1, the displaced old pointer is
    `lock dec`remented at its first qword
    (0x5cdf37f, the body's only locked operation)
    and dropped through slot 0x64e17f8 (→ drop
    helper 0x5ce9190, pinned) if the count reaches
    zero; if it is 0, control joins registration;
    anything else reaches the unreachable panic.
  - *Registration arm* (0x5cdf39d): registers the
    per-key destructor glue (lea at 0x5cdf39d)
    through slot 0x64e0510 (→ registrar 0x5ca0d20,
    pinned) with rdi = cell, then returns the
    cell.
  - Allocation failure does not return: it
    diverges through slot 0x64df490 (target
    0x141e251) with the (size 8, size 0x28) layout
    pair at 0x5cdf3b6.
- **any other state** — returns null
  (`xor ebx,ebx` at 0x5cdf315), touching nothing.
  In practice this is state 2, *destroyed*.

**The destructor glue `dtor_glue`
0x5cdf3e0..0x5cdf40b (43 bytes, exported)** is
what produces state 2: it stores 2 to the state
byte first (0x5cdf3e5), then, if the old state
was 1, loads the value pointer, `lock dec`s its
first qword (0x5cdf3f0) and drops it through the
same drop-helper slot when the count reaches
zero. (The FDE extent also carries the trap tail
shared with the neighbouring TLS bodies — a call
to 0x5cdf270 and a trap-slot call — after the
glue's `ret` at 0x5cdf3fd.)

**No iteration bound.** The body contains no
counter, no increment, and no backward branch
except jumps to its shared epilogue at
0x5cdf317 (backward-target census over its own
disassembly, machine-checked). Per call it reads
or writes only the cell, the optional adopt slot,
the value it creates, and the displaced pointer
on the racing arm. The dispatcher loop can
therefore leave through the tail call only when
the key is no longer live — once the glue has
run on the dispatcher's own thread.

## The cell: one key for the whole artifact

Whole-.text rel32 census (every hit re-verified
against its containing body's disassembly):
**exactly 20 direct call sites in 9 bodies, no
tail jumps, and every site passes `rsi = 0`**
(`xor esi,esi` in the setup block, verified per
site). The adoption arm is therefore never
exercised by a direct caller — a bounded
negative: the getter also has no RELATIVE
reference, no rip-relative lea/mov naming it, and
no absolute qword/u32 occurrence in the file.
(The glue is named exactly once, by the getter's
own registration lea at 0x5cdf39d.)

Every caller body forms the same cell address —
TLS base minus 0x418 (state byte at TLS base
minus 0x410). The cell sits at PT_TLS template
offset 0xd68 (filesz 0xb20, memsz 0x1180), inside
the zero-initialised tail past the file-backed
template, so each thread starts with
`{pointer 0, state 0}`.

## The dispatcher's four sites

The dispatcher 0x2ae1690 (4,386 bytes, pinned)
calls the getter **four** times — #2755 named
only the tail site. Each call is the slow path
of an open-coded `state == 1` guard on the same
byte (`cmpb $0x1, fs:-0x410` at 0x2ae1962,
0x2ae1ab2, 0x2ae1dfa, 0x2ae1f63), with the cell
pointer in r15 (`mov %fs:0x0,%rax` /
`lea -0x418(%rax),%r15` at 0x2ae195b and
0x2ae1d7b), rdi = r15 and rsi zeroed at every
setup:

- **0x2ae1ad6** — before the driver_a phase;
  non-null jumps to the fast-use block at
  0x2ae1ac0, null falls into a log-and-exit
  block.
- **0x2ae1fea** — inside the driver_c phase;
  non-null jumps to 0x2ae1f71, null jumps to the
  dispatcher exit block at 0x2ae2442.
- **0x2ae20a1** — later in the same phase;
  non-null jumps to 0x2ae1e0c, null falls into a
  log-and-exit block.
- **0x2ae21f7** — the loop tail: `test` at
  0x2ae21fc, `jne` at 0x2ae21ff back to the loop
  head 0x2ae1974 on non-null; null falls through
  to the final cleanup call at 0x2ae2205.

So per iteration each gate driver re-runs under
a live key, and the tail call is a liveness
check on the thread-local, not a counter: with
the key live it always returns the cell, and the
loop ends through it only after thread-local
destruction.

## Open edges

1. The source-level name of this thread-local
   key is not recorded in the artifact. The
   0x28-byte value is identified only by its
   uses: two refcount-shaped leading qwords (the
   dispatcher lock-incs the first and
   lock-cmpxchgs the word at +0x10), zeroed
   +0x10..+0x1f at creation, a zero byte at
   +0x20.
2. Whether the dispatcher loop ever exits
   through the tail call at runtime — which
   requires the glue to have run on the
   dispatcher's own thread — is dynamic and not
   decidable from the static trace.
3. The adoption arm is traced inside the getter
   but has no censused caller; a caller holding
   the getter's address in a form outside this
   packet's censuses is not excluded.

## Overlap / duplicate disclosure

- Open-PR sweep on 2026-11-04 (111 open PRs,
  full list plus targeted searches for
  0x5cdf300 / cdf300 / loop callee / loop tail /
  dispatcher loop / thread-local / RE-005): no
  open PR traces this body or answers this
  question. The RE-005 hits are this chain's own
  packets — #2755 (which carries the question),
  #2741, #2701, #2651 — and Jonas's #2656
  (signable append guards, a different body).
  WalkCrypto's "lazy" PRs (#2678, #2685) map
  RE-001 bodies 0x5d548a0 / 0x5d56120, not this
  getter. No overlap with the in-flight lanes
  hl-n5-drain (RE-015 drain callees),
  hl-n5-r006edges (RE-006 edges 3–5),
  hl-n8-grow (RE-015 map grow 0x4742aa0) or
  hl-n8-signexit (RE-002 sign exit 0x5bbb630).
- The dispatcher is pinned here by citation to
  #2741 / #2755; this packet adds no second
  export of it. The neighbouring `tls_dtor`
  0x5cdf410 (the *other* TLS cell's destructor,
  #2741) is pinned only to keep the cluster
  boundary explicit — it is not this key's glue.

## Files

- `loop_getter.objdump.txt`, `dtor_glue.objdump.txt`
  — full Intel-syntax disassembly of the two
  exported bodies (path line normalised).
- `records.json` — artifact identity,
  extents/digests, slots, instruction pins, the
  call census with per-site setup verification,
  the four dispatcher sites and guards, getter /
  glue structure censuses, the PT_TLS record, the
  panic Location, all reference censuses,
  findings, open edges.
- `frames.txt` — the `readelf -wf` FDE lines for
  all exported and pinned bodies.
- `MANIFEST.sha256` — checksums of the above.
