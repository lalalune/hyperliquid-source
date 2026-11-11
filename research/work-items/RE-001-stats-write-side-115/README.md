# RE-001: node #115 StatisticsImpl write side — record, set, get-and-reset, record-histogram and reset

- Component ID: RE-001 (node #115 function map)
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json, `artifacts/node/115/hl-node`; local copy
  `work/hl-node-115.bin` hashes exactly)
- Source commit / reference commit: upstream main `05bc2de30`
- Claim status: observation for everything below except the items listed
  under Unknowns, which are inference boundaries, not claims.

## Bounded question

#3392 left slot `0xb0` (`0x606fba0`) unmapped — the record/tick write
path — and its hash/index helper `0x60d5cd0`. What is the complete
write side of `StatisticsImpl`: how do slots `0xb0`/`0xb8`/`0xc0`/
`0xd0`/`0xd8`/`0xe0` record, set, reset and forward ticks and
histograms, how is the per-CPU shard picked (and what happens when
CPUID is unavailable), what is the delegate at `+0x28`, and what
does the ctor/dtor do with it?

## Answer, pinned to the target

The six write slots sit in the primary vtable `0x64d2d88` (typeinfo
`N7rocksdb14StatisticsImplE`, base `N7rocksdb10StatisticsE`, 32 slots).
None of the six has any direct call, tail jump or `lea` anywhere in
the binary: they are reached only through their vtable slots.
Indirect calls through the slot displacements across the whole binary
— `call *0xb0(%r..)` 400 sites, `*0xb8` 36, `*0xc0` 42, `*0xd0` 14,
`*0xd8` 48, `*0xe0` 31 (full lists in `dispatch.tsv`) — are
displacement-wide, not type-attributed: any class with a slot at that
displacement contributes, so these are upper bounds on
`StatisticsImpl` dispatches, not exact caller counts.

### The enable byte and the shard store

- The byte at `this+0x20` is a record level, written as `3` by the
  ctor: `0` records nothing, `1` records ticks only, `>= 2` records
  ticks and histograms. Slot `0xb0` requires it nonzero; slots
  `0xd8`/`0xd0` require it `> 1`. The locked slots `0xb8`/`0xc0`/
  `0xe0` do not consult it at all.
- One store at `*(this+0x60)` serves both counters and histograms:
  ticker counters at `shard + id*8`, histogram records at `shard +
  0x598 + id*0x3c8`, one `0xce40`-byte shard per CPU slot
  (`1 << u8 at this+0x68` shards). Valid ids are tickers `0..0xb1`
  (178) and histograms `0..0x33` (52, slot `0xf8`); the areas
  physically hold one slot more (179 ticker slots, 53 histogram
  records — `0x598 + 53*0x3c8 == 0xce00`, leaving the `0x40` tail
  per shard whose contents are still open).

### Slot 0xb0 — the lock-free tick record, 0x606fba0 (441 B)

`(this, ticker_id: u32, value: u64) -> void`. Gate: the enable byte
must be nonzero and `id <= 0xb1`, else return silently. Shard pick:
call the CPU picker `0x60d5cd0` (`0x606fbc4`); a negative return
jumps to the fallback at `0x606fc20` (call `0x61c4080` for the thread
seed, one Park-Miller step, store back, mask). The picked index is
masked with `(1 << shard_bits) - 1` and the value is added with a
single `lock add %r12,(%rax)` (`0x606fbf1`) into `shard + id*8` — no
mutex is taken on this path. Then `rdi = *(this+0x28)`; if null,
return; otherwise tail-jump to the delegate's slot `0xb0` with the
same `(id, value)` — the delegate re-runs its own gate and shard
pick.

### The CPU picker 0x60d5cd0 (32 B) and the LCG seed 0x61c4080 (151 B)

- `0x60d5cd0` is not a hash: `cpuid` leaf 0, and when the reported
  max leaf is 0 it returns `-1`; otherwise `cpuid` leaf 1 and it
  returns `EBX >> 24` — the APIC id (`0..255`). Six direct callers:
  the three write-side routines (`0x606fbc4`, `0x606ff0c`,
  `0x6070003`) plus three other per-CPU-shard users (`0x5f0aa40`,
  `0x605e17b`, `0x61c1e24`), not mapped here.
- `0x61c4080` returns the address of this thread's Park-Miller
  state. `%fs:0` is the pthread pointer; the TLS slot at `-0x10`
  holds a pointer to the seed cell at `-0x20`. On first use the
  seed is `_Hash_bytes(pthread_self, 8, 0xc70f6907) & 0x7fffffff`,
  or `1` when that is 0. Seventeen direct callers, three of them
  the write-side fallback paths. The fallback step in each record
  routine is `state = state * 0x41a7 mod 0x7fffffff` via the
  `(x & m) + (x >> 31)`, subtract-`m`-once reduction; from seed 1
  it produces `16807, 282475249, 1622650073, 984943658, 1144108930`
  — the classic Park-Miller sequence, which validates the reduction.

### The delegate at +0x28

`+0x28`/`+0x30` hold a `shared_ptr<Statistics>` — the delegate (or
parent) object the record is forwarded to. **Correction to #3386**,
which called this field a string: the ctor moves a 16-byte
`{ptr, control}` pair from its 2nd argument into `+0x28`/`+0x30`
and zeroes the source; the record routines dereference
`*(this+0x28)` as a vtable-bearing object and call its slot
`0xb0`/`0xb8`/`0xd8`; the dtor releases the control block at
`+0x30` (fast path when the counts are exactly `0x100000001`);
slot `0x88` (`0x606fa30`, 9 B) returns the pointer. Slot `0x70`
(`0x606fa20`, 12 B) returns the name `"BasicStatistics"`
(`0x432248`, which also starts the ticker-name table).

### Slot 0xb8 — the locked tick set, 0x6070dc0 (218 B)

`(this, ticker_id: u32, value: u64) -> void`. Lock `this+0x38`,
call the set core `0x6070ac0(this, id, value)`, unlock. No
enable-byte or id-bound check happens before the set. Then walk
the delegate chain: if the delegate is null or `id > 0xb1`,
return. The delegate's vtable slot `0xb8` is compared against the
local `0x6070dc0`: if it differs, tail-jump to the delegate's slot
`0xb8` (override branch `0x6070e78`); otherwise lock the delegate,
`set_core(delegate, id, value)`, unlock, and tail-jump to the next
delegate's slot `0xb8` (a pure virtual call, no second
devirtualization check). The chain is unrolled two levels inline,
then virtual. Its exception cleanup is the fragment at
`0x6070d92..0x6070db2` (two identical entries: unlock the mutex at
`r13`, `_Unwind_Resume`), reached from the landing pads at
`0x6070e82`/`0x6070e8e`.

### The set core 0x6070ac0 (91 B)

`(this, ticker_id: u32, value: u64) -> void`. `xchg value` into
shard 0's counter for the id, then `xchg 0` into every other
shard's counter for the id (the old values are discarded; the
first `xchg` leaves the old shard-0 value in `rdx` but no caller
reads it). When `shard_bits` is 0 the loop is skipped. No bound
check, no enable-byte check, no lock — callers hold the mutex and
pass ids they already bounded. Exactly five direct callers: reset
(`0x6070b67`), get-reset (`0x6070d04`/`0x6070d3f`), set-ticker
(`0x6070dea`/`0x6070e32`).

### Slot 0xc0 — get-and-reset ticker, 0x6070c50 (338 B)

`(this, ticker_id: u32) -> u64`. Lock `this+0x38`; loop over the
shards with `xchg 0` per shard, accumulating the old values into
`rbx` (u64 wrap); unlock; return the sum. Then reset the delegate
chain via slot `0xb8` with value `0`: the same devirtualization
check as set-ticker, an inline lock + `set_core(delegate, id, 0)`
+ unlock, a second inline level, then a virtual **call** (not a
tail jump — the sum in `rbx` must survive) to the third delegate's
slot `0xb8`. Its exception cleanup is the shared fragment at
`0x6070c2a..0x6070c4a` (two identical entries: unlock the mutex at
`r13`, `_Unwind_Resume`), reached from the landing pads at
`0x6070d7a`/`0x6070d86`.

### Slot 0xd8 — the lock-free histogram record, 0x606fef0 (222 B)

`(this, hist_id: u32, value: u64) -> void`. Gate: the enable byte
must be `> 1` (`cmp $0x1, jbe ret`). Shard pick exactly as slot
`0xb0` (CPU picker `0x606ff0c`, LCG fallback `0x606ff90`). The
record address is `shard + 0x598 + id*0x3c8`; its vtable is loaded
and `call *0x20(%rax)` records the value (`0x606b130`). Then, if
`id <= 0x33` and the delegate is non-null, tail-jump to the
delegate's slot `0xd8` with the same `(id, value)`. Note the `0x33`
bound gates only the forward, not the local record: there is no
`hist_id` bound check before the record call.

### Slot 0xd0 — the devirtualized twin, 0x606ffd0 (244 B)

`(this, hist_id: u32, value: u64) -> void`. If this object's own
slot `0xd8` is not the local `0x606fef0`, restore the registers
and `jmp *%rax` (`0x6070078`) — a virtual dispatch to the
overriding `0xd8`. Otherwise the same body as slot `0xd8` is
inlined (gate `> 1`, CPU pick `0x6070003` or LCG fallback
`0x6070088`, record call `*0x20`, forward to the delegate's slot
`0xd8` when `id <= 0x33`).

### Slot 0xe0 — reset, 0x6070b30 (250 B)

`(out: Status*, source: StatisticsImpl*) -> void`. Lock the
**source's** mutex (`rsi+0x38`). For `id` in `0..0xb1` call
`set_core(source, id, 0)` — every ticker on every shard becomes
0. For `hist_id` in `0..0x33`, for each shard, call the record's
vtable slot `0x10` (locked init/clear, `0x606b0c0`) — `call
*0x10(%rax)` at `0x6070bb4`. Write `Status{0}` (code 0, subcode 0,
state null) into `out`, unlock, return. No delegate walk, no
enable-byte check. Its exception cleanup is the fragment at
`0x6070b1c..0x6070b2e` (unlock the source mutex from the saved
pointer at `0x18(%rsp)`, resume), reached from the landing pad at
`0x6070c1e`. The neighbouring fragment at `0x6070c2a..0x6070c4a`
serves slot `0xc0`, not reset (see `reset_cleanup2.txt`).

### The histogram record side

- **Record** `0x606b130` (slot `0x20`, 131 B): bucket index via
  `0x606afa0`, `buckets[index]++` at `record+0x28+index*8`,
  `min`/`max` by u64 compare, `count++`, `sum += value`,
  `sum_sq += value*value` (u64 wrap). The value is a u64
  throughout — integer compares, adds and multiply, no float
  conversion on this path. Reached by tail jump from the `+8`
  thunk `0x606b1c0` and by virtual dispatch through slot `0x20`
  (in-packet call sites `0x606ff52`, `0x6070047`).
- **Bucket index** `0x606afa0` (115 B): lower_bound over the 109
  boundaries at `0x6505d20`; at or above the ceiling (the qword at
  holder `+0x18`, `13000000000000000000`) it returns the last
  index `108`; otherwise the first boundary `>= value`. Exactly
  one direct caller (`0x606b147`).
- **Locked init** `0x606b0c0` (slot `0x10`, 74 B): locks the
  record's mutex at `+0x3a0` (plain `pthread_mutex_lock`, throwing
  `system_error` on failure), calls the shared init on `record+8`,
  unlocks. Eight direct callers on builder/merge paths; reset
  reaches it only through the record's vtable slot `0x10`.
- **Shared init** `0x606b020` (92 B): `min := *(0x6505d38)` (the
  ceiling), `max`/`count`/`sum`/`sum_sq := 0`, `buckets[0..N-1]
  := 0` where `N` is read from `record+0x390` (never written
  here).
- **Boundary generator** `0x606bf10` (548 B): seeds `[1, 2]` from
  `.rodata 0x453950`; `cur` (a double, starting at 2.0) `*= 1.5`
  each step until `cur >= 2**64`; each value truncated toward zero
  to a u64 (the `>= 2**63` path subtracts `2**63` then xors the
  sign bit back in); values above 109 truncated to 3 significant
  digits; on exit the last boundary is stored at holder `+0x18`
  (the ceiling) and the first at `+0x20`. Result: 109 boundaries,
  first `1`, last `13000000000000000000` — re-derived by the model
  and matching #3371's pinned values (including `B[100] =
  540000000000000000`). Run once by the static init `0x606c140`
  (`.init_array` at `0x63f3978`).

### Lifecycle

- **Ctor** `0x6071a00` (352 B): vptr, enable byte `3` at `+0x20`,
  options vector zeroed, delegate `shared_ptr` moved in from the
  2nd argument (see the correction above), mutex init via
  `0x60d50c0`, shard store via `0x60716d0`, and the
  `"StatisticsOptions"` record via `0x6099ce0(this, name,
  &this+0x28, 0x6506200)` — the name is built on the stack from
  `.rodata 0x4539e0` plus `'s'`. Exactly two direct callers: the
  creator `0x6071ba0` (`0x6071bda`) and the create-by-name host
  `0x6077820` (`0x6077b74`).
- **Dtor** `0x6070ea0` (412 B, slot `0x0`): restores the base
  vptr, destroys the shard store (each histogram record's dtor
  through its vtable unless it is the shared `0x5d89570`, then
  `free` via `0x60d5db0`), destroys the mutex via `0x60d5170`,
  releases the delegate `shared_ptr` (control at `+0x30`; fast
  path when the counts are exactly `0x100000001`), then destroys
  the options vector. Five direct callers, including the deleting
  dtor `0x6071040` (`0x6071048`).

## Evidence format

- `records.json` holds semantic records only — step lists, census
  counts, vtable slot tables, literal addresses and the boundary
  table. There is no per-instruction mnemonic list.
- Instruction-level detail lives only in the whole-function
  verbatim excerpts (24 files, byte-checked). The mnemonics in the
  excerpts (`endbr64` included) are genuine instructions present
  in the target binary, not placeholders.
- `verify.py` in this directory re-checks everything: the target
  digest, the manifest, byte-for-byte excerpt regeneration from a
  fresh objdump run, every excerpt line against the raw binary,
  fixed + 3 seeded random gate spots, FDE ranges, RELATIVE
  records, literals, census reproduction (`callers.tsv` +
  `dispatch.tsv`), vtable re-derivation, boundary re-derivation
  and the model tests.
- `tools/stats_write_side_115.py` models the six slots, the set
  core, the CPU picker, the LCG seed, the histogram record and
  the boundary generator end to end (gate levels, id bounds,
  shard distribution, delegate-chain forwarding, set/get-reset
  round trips, histogram updates, reset clearing);
  `tests/test_stats_write_side_115.py` runs 143 checks directly
  (pytest is not installed on this VM).

## Unknowns

- The public C++ names of the six write routines are not
  established from the stripped binary; they are described by
  observed behaviour, signatures and vtable slots, not by
  source-level names.
- Which routine writes the enable byte at `+0x20` besides the
  ctor (a setter is the natural candidate; the unmapped slots
  `0x10..0x90` except `0x70`/`0x88` and `0xc8` are not mapped
  here).
- The `0x40` tail at the end of each `0xce40`-byte shard
  (`0xce00..0xce40`) is not examined; its contents are open
  (carried from #3392).
- The `bucket_count` field at `record+0x390` is read by the shared
  init and never written by it; its writer is an open unknown
  (likely the shard-store builder `0x60716d0` or the bucket-count
  init `0x606b080`).
- The exact `_Hash_bytes` output for a given `pthread_self` is not
  byte-verified against a live run (the seed is thread-dependent);
  the model implements the documented libstdc++ MurmurHash64A
  algorithm and only its determinism and range are tested.
- The other three direct callers of the CPU picker (`0x5f0aa40`,
  `0x605e17b`, `0x61c1e24`) and the other 14 direct callers of the
  LCG seed accessor are other per-CPU / per-thread users; their
  routines are not mapped here.
- Which landing pad covers which call site inside the locked
  routines is inferred from the register and mutex state, not read
  from the LSDA; the fragments' shapes and jump targets are
  pinned.
- The histogram record path treats its third argument as a u64
  throughout (integer compares, adds, multiply); no caller that
  passes a double's bit pattern was examined.
- `set_core` performs no bound check: ids `>= 179` index past the
  ticker area into the histogram records (observed addressing, not
  exercised).
- The remaining `StatisticsImpl` vtable slots (`0x10..0x90` except
  `0x70`/`0x88`, `0xc8`) are not mapped here.
- The ctor's trailing cleanup fragment at `0x6071b60` (outside the
  ctor FDE) is not excerpted.
- The `+0x28` delegate is moved in from the creator's options
  struct; which construction paths install a non-null delegate
  (beyond the factory host, which passes its own options through)
  is not traced here.
