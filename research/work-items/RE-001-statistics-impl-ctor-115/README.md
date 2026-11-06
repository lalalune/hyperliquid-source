# RE-001: pin node #115 StatisticsImpl construction: the ctor 0x6071a00, the shard-store builder 0x60716d0 and the HistogramImpl record init

Task: RE-001 (#115 function map). Bounded question: how is a
`rocksdb::StatisticsImpl` built — what does its constructor install,
how is its shard store of `rocksdb::HistogramImpl` records built, and
what happens when construction fails halfway?

- Component: node #115 StatisticsImpl construction, extracted from the
  digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  windows `0x6071a00..0x6071b60` (ctor),
  `0x6071952..0x60719f2` (ctor cold cleanup partition),
  `0x60716d0..0x6071952` (shard-store builder),
  `0x606b020..0x606b07c` (shared init),
  `0x606b080..0x606b0a2` (bucket-count init),
  `0x606b0c0..0x606b10a` (locked init),
  `0x60d5d50..0x60d5db0` (aligned allocator),
  `0x60d5db0..0x60d5db9` (free wrapper),
  `0x606fd30..0x606fd94` (shard-store destroyer),
  `0x5d89570..0x5d89575` (no-op record dtor),
  `0x60d50c0..0x60d5157` (mutex init wrapper),
  `0x60d5170..0x60d5200` (mutex destroy wrapper).
- Claim status: observation for the window bounds, the field writes,
  the bucket-count derivation, the shard/record layout, the
  per-record init order, the destroyer walk and the dead release;
  inference for the names "StatisticsImpl", "HistogramImpl" (both
  read verbatim from their typeinfo name strings), "level byte",
  "shard" and "record" (they describe the observed roles, not proven
  source names); unresolved for the items listed in records.json.
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in them (including
  `endbr64` at the window entries and at each landing pad) are
  genuine instructions present in the target binary, not
  placeholders; the packet checker re-verifies sampled instructions
  byte-for-byte against a fresh objdump run and the raw binary.
- Relationship to earlier work: no open PR covers the ctor, the
  builder or the destroyer (checked this cycle: open-PR snapshot of
  90 open WalkCrypto PRs, no title hit; `gh search issues
  --include-prs` in lalalune/hyperliquid-source returns 0 hits for
  60716d0, 6071a00, 606fd30, 60d5d50, 60d50c0 and 60d5170). The three
  record-init routines are pinned in open PR #3371
  (RE-001-histogram-stats-family-115) and are re-shipped here
  byte-identical as the builder's per-record init callees; the
  excerpts were regenerated from the same binary and ranges.
  `options_record_append` 0x6099ce0 is the centerpiece of open PR
  #3257: the ctor calls it, it is not re-shipped. The StatisticsImpl
  vtable slots are pinned by open PRs #3396 (write side), #3392
  (locked read accessors), #3378 (slot-0xf0) and #3362 (produce
  0x6070810); this packet pins only the constructor that installs
  the vtable 0x64d2d88.

## The constructor 0x6071a00, stated literally

Arguments: rdi = this (uninitialized storage), rsi = pointer to a
16-byte argument struct holding two pointers. Steps, in order:

1. `*(this) = 0x64d2d88` — the StatisticsImpl vtable
   (typeinfo `N7rocksdb14StatisticsImplE`, `rocksdb::StatisticsImpl`).
2. `byte this+0x20 = 3` — the level byte. The recorder's level gate
   (mapped in the withheld slot-0xc8 note) is: level 0 records
   nothing, 1 ticks only, 2 ticks plus histograms, 3 additionally
   forwards through slot 0xc8. The constructor installs the maximum.
3. `this+0x08 = 0`, `this+0x10 = 0`, `this+0x18 = 0` — an empty
   vector (begin/end/capacity) of 48-byte elements beginning with a
   std::string.
4. `this+0x30 = 0`, then `this+0x28 = *(args)`,
   `this+0x30 = *(args+8)`, and the 16-byte argument struct is
   zeroed — the two pointers are moved out of the argument.
5. Mutex init at `this+0x38` via 0x60d50c0. The constructor reads a
   byte from 0x97877c (value 0x00) and passes it as the second
   argument, but 0x60d50c0 ignores its second argument and always
   calls `pthread_mutex_init(mutex, NULL)`.
6. Shard-store build via the builder 0x60716d0(`this+0x60`).
7. A 17-byte std::string "StatisticsOptions" is built (16 bytes
   "StatisticsOption" copied from 0x4539e0, byte 0x73 's' at +0x10,
   NUL at +0x11) and `options_record_append(this, this+0x28, name)`
   (0x6099ce0) registers it.

Callers of the constructor: 0x6071bda and 0x6077b74 (see
callers.tsv). The landing pad at 0x6071b30 tail-jumps to the cleanup
partition on any exception.

## The shard-store builder 0x60716d0, stated literally

Arguments: rdi = out, a 16-byte struct: `+0x00` records base,
`+0x08` bucket exponent.

1. `*out = 0` (0x60716e2).
2. `ncpu = std::thread::hardware_concurrency()`. If `ncpu <= 8`:
   exponent 3, bucket count 8, allocation size 0x67240. Otherwise
   the smallest exponent `e >= 4` with `(1 << e) >= ncpu`;
   bucket count `1 << e`; allocation size `count * 0xce40 + 0x40`.
   If `count > 0x9ee009ee009e`, `__cxa_throw_bad_array_new_length`.
3. Allocate via 0x60d5d50 (posix_memalign, 64-byte alignment).
   Store `bucket_count` at `alloc+0x38`, records base
   `alloc+0x40`; store the exponent at `out+0x08`, the records base
   at `out+0x00`.
4. For each of the `count` shards (stride 0xce40): zero 0x598 bytes
   at the shard start (`rep stos`, 0xb3 qwords), then initialize 53
   records of 0x3c8 bytes at `shard+0x598 .. shard+0xce00`. The
   53 count is the loop counter: ebp starts at 0x34 (52) and the
   `sub $1,%rbp; jae` back-edge runs the body for rbp = 52..0, i.e.
   53 times; the destroyer independently walks 53 records per
   shard (see below). The last 0x40 bytes of each shard
   (`shard+0xce00 .. shard+0xce40`) are never touched.
5. Per record, in order: `*(rec) = 0x64d2b80` (HistogramImpl
   vtable, typeinfo `N7rocksdb13HistogramImplE`); call
   0x606b080(`rec+8`); zero `rec+0x3c0` (qword) and
   `rec+0x3a0..rec+0x3b0` (32 bytes, movups); call
   0x606b0c0(`rec`).

### The record-init trio (re-shipped from #3371)

- 0x606b080(`rec+8`): writes `rec+0x398 =
  (*(0x6505d28) - *(0x6505d20)) >> 3` — the bucket count from two
  runtime globals (a pointer range divided by 8) — then tail-jumps
  to 0x606b020.
- 0x606b020(`rec+8`): writes `*(rec+8) = *(0x6505d38)` (the "min"
  pointer) and zeroes `rec+0x10, +0x18, +0x20, +0x28`; if
  `rec+0x398 != 0`, zeroes the first qword of each of `count`
  buckets at `rec+0x30 + i*0x28` (bucket stride 40 bytes).
- 0x606b0c0(`rec`): locks the pthread mutex at `rec+0x3a0`, calls
  0x606b020(`rec+8`), unlocks; a lock failure throws a system
  error.

Note the double run: shared init 0x606b020 executes twice per
record — once unlocked via 0x606b080's tail jump, once locked via
0x606b0c0. Both runs write the same values, so the second run is a
redundant re-zero. The mutex is zeroed by the builder (step 5)
before 0x606b0c0 locks it; a zeroed pthread_mutex_t is a valid
unlocked default mutex. The bucket array must end by the mutex at
`rec+0x3a0`, so the runtime bucket count satisfies `count <= 22`.

### The dead old-store release

The builder contains a full old-store release loop
(0x60717eb..0x607186d: walk the old shards back to front, call each
record's vtable slot 0 unless it equals 0x5d89570, then free) and an
unwind path that calls the destroyer 0x606fd30 (0x60718f8). Both are
dead code in this binary: the entry zeroes `*out` at 0x60716e2
before the release test at 0x60717fa reads `*out`, so the test
always sees 0 and jumps to the return. The model records
`builder_release_reachable() == False`.

## The destroyer 0x606fd30, stated literally

Arguments: rdi = records base (`alloc+0x40`). If base is 0, return.
`count = *(base-8)` (the bucket count at `alloc+0x38`). Walk the
shards last to first; within a shard, walk records from
`shard+0xca38` down to `shard+0x598` in steps of 0x3c8 (53 records).
For each record, load its vtable slot 0 and compare it against
`*(GOT 0x64ed2b8)` — which the RELATIVE entry resolves to
0x5d89570, the no-op dtor — calling the slot only when it differs.
HistogramImpl records always have slot 0 = 0x5d89570, so the walk
calls nothing for them. Then `free(base-0x40)`.

The destroyer's only live caller is the ctor cleanup partition
(0x60719b9); the builder's unwind call at 0x6071904 is dead (see
above).

## The ctor cleanup partition 0x6071952, stated literally

This is the constructor's cold cleanup partition, not a callable
function: it has its own FDE (0x6071952..0x60719f2) but no endbr64,
is entered only by the tail jump from the ctor landing pad at
0x6071b37, and shares the ctor frame (canary slot 0x38(%rsp),
rbx = this, r13 = this+0x38, rbp = the partial string,
r12 = the exception). Steps: dispose the partial
"StatisticsOptions" string; rbp = the exception; if `this+0x60 !=
0`, destroy the shard store via 0x606fd30; destroy the mutex via
0x60d5170(`this+0x38`); if `this+0x30 != 0`, release it via
counted_release 0x5d350c0; install the base vtable 0x64d3430
(Configurable) at `*(this)`; destroy the vector at `+0x08/+0x10/
+0x18` (48-byte elements beginning with a std::string, each freed
via `_ZdlPvm` unless SSO); free the vector buffer; then
`_Unwind_Resume(exception)`.

## The allocator, the free wrapper and the mutex wrappers

- 0x60d5d50(size): `posix_memalign(&out, 0x40, size)`; returns the
  pointer on success, NULL on failure, and stores the error code
  in `*errno` (via `__errno_location`). Stack-protector guarded.
- 0x60d5db0(ptr): tail-jumps to `free@plt`.
- 0x60d50c0(mutex): `pthread_mutex_init(mutex, NULL)`; 0x60d5170
  (mutex): `pthread_mutex_destroy(mutex)`. Both accept return codes
  0, 16 and 110 and otherwise print via `__fprintf_chk` and abort.

## The HistogramImpl vtable 0x64d2b80

Sixteen slots, resolved from .rela.dyn RELATIVE entries (see
vtables.tsv): slot 0x00 = 0x5d89570 (no-op dtor, `endbr64; ret`),
0x08 = 0x5d8b3b0, 0x10 = 0x606b0c0 (locked init), 0x18 =
0x606b120, 0x20 = 0x606b1c0 (the outer record thunk; its callers
are 0x606004c, 0x6198ae7, 0x6198e2a), 0x28 = 0x606be40, 0x30 =
0x606bc90, 0x38 = 0x606af40, 0x40 = 0x606af50, 0x48 = 0x606af60,
0x50 = 0x5eeb2e0, 0x58 = 0x606b520, 0x60 = 0x606b530, 0x68 =
0x606b5c0, 0x70 = 0x606b6b0, 0x78 = 0x606bdd0. Only slots 0x00 and
0x10 are used by this packet's routines; the rest are other
HistogramImpl methods and stay open.

## Verification

`python3 research/work-items/RE-001-statistics-impl-ctor-115/verify.py`
prints ALL CHECKS PASSED (digest, manifest, excerpt regeneration,
fixed + 3 seeded random gate spots byte-checked against a fresh
objdump run and the raw binary, frames, census reproduction for all
12 targets, relocations and vtables re-derived, literals, model
tests). `python3 tests/test_statistics_impl_ctor_115.py` runs the
model tests under plain python3.
