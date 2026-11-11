# RE-001: pin node #115 the StatisticsImpl vtable slots — the complete 32-slot map

Task RE-001, node #115 (SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
provenance `artifacts/node/115/hl-node`, base commit `7ff06a097`).

## Bounded question

What does each of the 32 slots of the node #115 `StatisticsImpl`
primary vtable (stored pointer `0x64d2d88`, Itanium base
`0x64d2d78`, typeinfo `N7rocksdb14StatisticsImplE` at `0x64d2cf8`,
base `N7rocksdb10StatisticsE` at `0x64d2ce0`) implement — the 13
shared `Configurable`/`Customizable` base slots, the
Statistics-specific reads and writes, the level-3-only `0xc8`
forwarder, the deleting dtor, and the delegate chains — and how
are the slots reached?

## Answer, pinned to the target

The whole map, re-derived from the `R_X86_64_RELATIVE` records in
`.rela.dyn` (see `relocations.txt` and `vtables.tsv`); every slot
target below is a RELATIVE addend, and the file bytes at the
vtable offsets are not the qwords. The slot count (32) matches
the ctor packet's note exactly.

| slot | target | role |
| --- | --- | --- |
| 0x00 | 0x6070ea0 | D1 destructor (412 B) |
| 0x08 | 0x6071040 | D0 deleting destructor (27 B; sized delete, 0x70) |
| 0x10 | 0x609d760 | Customizable::GetOption (shared, 63 vtables) |
| 0x18 | 0x609dc40 | Customizable::AreEquivalent (shared, 63) |
| 0x20 | 0x5d32560 | returns empty std::string (shared, 66; name open) |
| 0x28 | 0x6095e70 | base Configurable::PrepareOptions (shared, 50) |
| 0x30 | 0x6096790 | Configurable::ValidateOptions (shared, 64) |
| 0x38 | 0x5d2e090 | Customizable::GetOptionsPtr (shared, 62) |
| 0x40 | 0x60956f0 | returns empty Status (shared, 68; name open) |
| 0x48 | 0x609d0e0 | Configurable::ConfigureOptions (shared, 66) |
| 0x50 | 0x60986b0 | Configurable::ParseOption (shared, 67) |
| 0x58 | 0x6095710 | Configurable::OptionsAreEqual (shared, 65) |
| 0x60 | 0x609de80 | base Customizable::SerializeOptions (shared, 50) |
| 0x68 | 0x609d980 | Customizable::GetOptionName (shared, 63) |
| 0x70 | 0x606fa20 | Name() -> "BasicStatistics" (12 B) |
| 0x78 | 0x5d32a30 | GetId (shared, 55; Name() as std::string) |
| 0x80 | 0x5d2e770 | IsInstanceOf (shared, 44; Name or NickName) |
| 0x88 | 0x606fa30 | delegate getter: *(this+0x28) (9 B) |
| 0x90 | 0x5d2ca10 | NickName() -> "" (shared, 45) |
| 0x98 | 0x6070490 | locked ticker read, getTickerCount (66 B) |
| 0xa0 | 0x6070610 | locked histogram percentiles, getHistogramData (185 B) |
| 0xa8 | 0x6070700 | locked histogram text, getHistogramString (193 B) |
| 0xb0 | 0x606fba0 | record tick (185 B) |
| 0xb8 | 0x6070dc0 | locked set ticker, setTickerCount (218 B) |
| 0xc0 | 0x6070c50 | get-and-reset ticker, getAndResetTickerCount (322 B) |
| 0xc8 | 0x5d48960 | level-3-only histogram forward (25 B) |
| 0xd0 | 0x606ffd0 | record histogram, devirtualized twin (244 B) |
| 0xd8 | 0x606fef0 | record histogram (222 B) |
| 0xe0 | 0x6070b30 | reset (250 B; Status OK) |
| 0xe8 | 0x6070810 | StatisticsImpl::ToString (677 B) |
| 0xf0 | 0x6076030 | ticker-map fill, getTickerMap (1509 B) |
| 0xf8 | 0x606fa40 | histogram-id check, HistEnabledForType (11 B) |

This closes two open unknowns: #3396's "The remaining
StatisticsImpl vtable slots (0x10..0x90 except 0x70/0x88, 0xc8)
are not mapped here" and #3392's "The remaining StatisticsImpl
vtable slots (0x10..0x90, 0xb8..0xe0 except 0xe8/0xf0) are not
mapped". The 13 shared base slots are mapped here (roles from
#3902, targets re-verified by this packet's RELATIVE
enumeration) and slot `0xc8` is mapped here.

### The object and the shard store

`sizeof(StatisticsImpl)` is `0x70` (112 bytes): the D0 dtor
passes `0x70` to `_ZdlPvm`, and the `_Sp_counted_ptr<StatisticsImpl>`
deleter `0x6071060` does the same. Layout: `+0x00` vtable pointer,
`+0x08..+0x20` options vector, `+0x20` the level byte
(`std::atomic<StatsLevel>`, default 3 = `kExceptDetailedTimers`),
`+0x28` the delegate `Statistics*` (with the shared_ptr control
block at `+0x30`), `+0x38` the mutex, `+0x60` the shard-store
pointer, `+0x68` the shard exponent byte. The ctor (`0x6071a00`)
is the single writer of the level byte — #4142's whole-binary
census (16,889 `movb +0x20` stores) proves it — so
`set_stats_level`/`get_stats_level` are non-virtual inlines and
no vtable slot writes `+0x20`. That answers #3396's open unknown
about which routine writes the enable byte besides the ctor:
none does.

The shard store is `1 << shard_bits` shards of `0xce40` bytes:
ticker `id` is the u64 at `shard + id*8`, histogram `id` is the
`0x3c8`-byte record at `shard + 0x598 + id*0x3c8`. Valid ids:
tickers `0..0xb1` (178), histograms `0..0x33` (52, slot `0xf8`).
Physical capacity is one slot wider on both sides (179 ticker
slots, 53 histogram records per shard).

### Level gates

The enable byte at `+0x20` gates the writes, and each slot gates
differently:

- record tick (`0xb0`): enabled != 0 and ticker id <= `0xb1`.
- record histogram (`0xd8`): enabled > 1. No hist-id bound check
  before the local record; the `0x33` bound gates only the
  delegate forward.
- measure time (`0xc8`): enabled > 2, then slot `0xd8`.
- set ticker / get-and-reset / reset: no gate at all.

### The shared base slots (0x10..0x68, 0x78, 0x80, 0x90)

These 13 slots are the shared `Configurable`/`Customizable` base
methods, installed by 44–68 vtables each (RELATIVE counts in
`records.json`, re-derived by `census.py`). Their contracts are
pinned in #3902 (SystemClockWrapper's 26-slot map, which shares
every one of them) and in the RE-001-delegate-vtable-115 packet,
and re-verified here by target and by the census:

- `0x10` GetOption: if the name is exactly `"id"`, return the
  delegate's own name (its slot-`0x78` string) and a zeroed Status;
  otherwise forward to `Configurable`'s slot `0x10` (`0x6099030`).
- `0x18` AreEquivalent: return 1 when the value's `+0x2c` byte is
  <= 1, when out == delegate, or (return 0) when the delegate is
  null. Otherwise compare names via slot `0x78`; on mismatch
  rewrite the option name to `"id"`, then forward to
  `Configurable`'s slot `0x18` (`0x60996a0`) when the value's
  `+0x2c` byte is > 2, else return 1.
- `0x20`: initialize a `std::string` at `rdi` (pointer `rdi+0x10`,
  length 0, NUL at `+0x10`); returns `rdi`. C++ name open.
- `0x28` base PrepareOptions (1964 B, the largest shared slot):
  walk the `0x30`-byte (name, value) records, copy each name
  (SSO-aware) and the `0x20`-byte value struct, then walk the
  `+0x18` entry chain and materialize five sub-values through the
  `+0x40/+0x60/+0x80/+0xa0/+0xc0` copy function pointers (tag 2).
  Eight direct callers are other classes' overrides calling the
  base (e.g. `SystemClockWrapper::PrepareOptions` at `0x5fcf5b7`).
- `0x30` ValidateOptions: the same record walk, but the worker is
  `0x60b9f50` (six arguments) and the kind gate has no `0x40`
  flag-byte check.
- `0x38` GetOptionsPtr: the shared resolver `0x60958c0` scans the
  `0x30`-byte record array at `*(rdi+0x08)..*(rdi+0x10)` for the
  name (length then memcmp, SSO-aware) and returns the matching
  record's `+0x20` field, or null. Otherwise call this object's
  slot `0x88` and, when non-null, tail-jump to the wrapped
  object's slot `0x38`.
- `0x40`: write a zeroed 16-byte Status (u32 0, u16 0, u64 0) into
  `*(rdi)` and return `rdi`. C++ name open.
- `0x48` ConfigureOptions: the merge/apply host every slot-`0x48`
  override calls first; it returns a Status in `*(rdi)` and the
  overrides return early when its first byte is non-zero.
- `0x50` ParseOption (SetOption, string value): when the value
  kind byte (`+0x04`) is 0, forward (name, value) to worker
  `0x60bedc0`. When kind != 0 and the changeable flag at
  `name+0xb1` is set, copy the value struct (shared_ptr
  refcounted) and call `0x60bedc0`. When kind != 0 and the flag is
  clear, build the error string `"Option not changeable: " + name`
  and report it through `0x61cf670` with code 4.
- `0x58` OptionsAreEqual: validate (name, value) — call kind
  validator `0x60bf980`; if it accepts, return 1. Otherwise call
  `0x60bf7c0`; if it rejects too, blank the target name string.
  Always returns 1.
- `0x60` base SerializeOptions (1054 B): call the delegate's slot
  `0x78` for its name. When the value kind (`+0x28`) is 1 or the
  delegate name is empty, compose the out string as `<options
  name> + "id" + "=" + <delegate name> + <value name>`; when the
  delegate name string is also empty, assign the delegate name
  directly. Otherwise forward to `Configurable`'s slot `0x60`
  (`0x60985e0`, call at `0x609e0a9`) and copy its output. Three
  direct callers are other classes' overrides calling the base.
- `0x68` GetOptionName: call the delegate's slot `0x70` (Name());
  if the input name starts with that name followed by `'.'`,
  strip the prefix and return the remainder; if Name() is null,
  throw `std::logic_error`. Otherwise fall back to
  `Configurable`'s slot `0x68` (`0x6095a60`).
- `0x78` GetId: Name() as a `std::string` — call the delegate's
  slot `0x70` and assign the returned C string through
  `0x5d32940`. For `StatisticsImpl` the name is
  `"BasicStatistics"`.
- `0x80` IsInstanceOf: return 1 when the input string matches this
  object's Name() (slot `0x70`) or its NickName() (slot `0x90`)
  by length then memcmp; else 0. Verified in this packet's
  excerpt: Name() via `call *0x70(%rax)` at `0x5d2e792`, `memcmp`
  at `0x5d2e7ee`; NickName() via `call *0x90(%rax)` at
  `0x5d2e7b0`, `memcmp` at `0x5d2e826`. For `StatisticsImpl`:
  Name() is `"BasicStatistics"`, NickName() is `""` — so
  `IsInstanceOf("BasicStatistics")` and `IsInstanceOf("")` both
  return 1. One tail jump: the MockEnv/CompositeEnvWrapper
  override at `0x5fd624b` tail-jumps here.
- `0x90` NickName: returns the address `0x4376fd`, which holds an
  empty string (the byte there is `0x00`; the preceding string
  `"base/src/chain_ext.rs"` ends at `0x4376fc`).

### The identity slots (0x70, 0x88, 0xf8)

- `0x70` Name: `lea 0x432248(%rip), %rax; ret` — the string
  `"BasicStatistics"` at `0x432248`. The same address holds the
  start of the ticker-name table (`"rocksdb.l1.hit"`,
  `"rocksdb.number.keys.updated"`, ... follow it).
- `0x88` delegate getter: `mov 0x28(%rdi), %rax; ret` — the
  delegate pointer, or null. (The delegate packet records the
  same shape for the other wrappers: `SystemClockWrapper`
  returns `*(obj+0x20)`, `MockEnv` `*(obj+0x48)`.)
- `0xf8` histogram-id check: `cmp $0x33, %esi; setbe %al; ret` —
  hist id <= `0x33` (52 valid ids, 0..51).

### The locked reads (0x98, 0xa0, 0xa8)

All three lock the mutex at `this+0x38` (`0x60d5230` /
`0x60d52f0`), do their work, and unlock; their landing pads jump
to cleanup fragments that unlock and resume. None has a direct
call, tail jump or lea anywhere in the binary: reached only
through the vtable.

- `0x98` locked ticker read: lock, call the ticker getter
  `0x6070430` (sum over `2**(u8 at this+0x68)` shards of the u64
  at `*(this+0x60) + shard*0xce40 + ticker*8`), unlock, return
  the sum. Exception path: the landing pad at `0x60704c6` jumps
  to the fragment at `0x607047e..0x607048e`, which unlocks and
  calls `_Unwind_Resume`.
- `0xa0` locked histogram percentiles: lock, build a fresh
  `0x3c8`-byte `HistogramImpl` temp via the builder `0x6070500`
  (which merges every shard's record for the id), fill the
  caller's struct through the temp's vtable slot `0x78` (thunk
  `0x606bdd0`, percentile struct `0x606bce0` — the 9-field record
  P50/P95/P99/average/stddev/P100/count/sum/min pinned in
  #3371), destroy the temp, unlock. The destroy compares the
  temp's vtable slot 0x8 against GOT `0x64ed2f0` (sized delete
  `0x5d8b3b0`): equal means `_ZdlPvm(temp, 0x3c8)`, else the
  deleting dtor. Exception cleanup is the fragment at
  `0x60705d8..0x607060c` (own FDE) with two entries: the head
  `0x60705d8` (delete temp + unlock + resume, from the landing
  pad at `0x60706b8`) and the interior `0x60705e7` (unlock only,
  from the landing pad at `0x60706c4`).
- `0xa8` locked histogram text: the stats object arrives in `rsi`,
  not `rdi` — the routine returns a `std::string` by value, so
  `rdi` is the hidden return-value pointer (the out string,
  returned unchanged) and `rsi` is `this`. Lock, build the temp
  via `0x6070500`, render into the out string through the temp's
  vtable slot `0x30` (entry `0x606bc90`, renderer `0x606b6f0` —
  the Count / Min-Median-Max / Percentiles / dashes /
  bucket-rows text pinned in #3371), destroy the temp the same
  way as slot `0xa0`, unlock, check the stack canary and return
  `rdi`. Exception cleanup is the fragment at
  `0x60706ca..0x60706fe` (own FDE), the mirror of slot `0xa0`'s.

### The write side (0xb0, 0xb8, 0xc0, 0xd0, 0xd8, 0xe0)

Pinned in #3396 and re-shipped here byte-identical; the short
form, with the two size corrections in the next section:

- `0xb0` record tick: gate (enabled != 0, id <= `0xb1`), per-CPU
  shard pick (`0x60d5cd0`) or LCG fallback (`0x61c4080`),
  `lock add` into the picked shard's counter, then tail-jump to
  the delegate's slot `0xb0`.
- `0xb8` set ticker: lock, `set_core` (`0x6070ac0`: shard 0
  counter := value, every other shard's := 0), unlock, then walk
  the delegate chain — a devirtualization check on the delegate's
  slot `0xb8`, an inline level, then a virtual call to the third
  delegate's slot `0xb8`.
- `0xc0` get-and-reset ticker: lock, sum all shards with
  `xchg`-0, unlock, return the sum, then reset the delegate chain
  via slot `0xb8` with value 0 (calls, not tail jumps, because
  the sum must survive to the return).
- `0xd8` record histogram: gate (enabled > 1), shard pick,
  `call *0x20(%rax)` on the record (the `HistogramImpl` record
  slot `0x606b130`, reached via the thunk `0x606b1c0`), then
  tail-jump to the delegate's slot `0xd8` when id <= `0x33`.
- `0xd0` devirtualized twin: if this's slot `0xd8` != local
  `0x606fef0`, tail-jump to it; else the identical record body.
- `0xe0` reset: lock the source mutex, `set_core(source, id, 0)`
  for tickers `0..0xb1`, the record's vtable slot `0x10`
  (`0x606b0c0`) per shard for histograms `0..0x33`, write a
  16-byte zero Status to out, unlock. No delegate walk, no
  enable-byte check.

### Slot 0xc8 — the level-3-only forwarder, 0x5d48960 (25 B)

The one slot #3396 left unmapped. Its whole body:

```
movzbl 0x20(%rdi), %eax   ; level byte
cmp    $0x2, %al
jbe    0x5d48978          ; level 2 or below: return silently
mov    (%rdi), %rax
jmp    *0xd8(%rax)        ; tail-jump to this's slot 0xd8
```

Installed twice: the vtable slot at `0x64d2e50` and the GOT slot
at `0x64ecf50` (both `R_X86_64_RELATIVE` with addend
`0x5d48960`). No direct call anywhere in the binary; one lea
site at `0x5e08495`, inside the host FDE `0x5e080f0..0x5e095ed`,
which devirtualizes slot `0xc8` (compare at `0x5e084a3`,
override branch at `0x5e0943d`) and, when the slot is the local
forwarder and the level byte is > 2, calls slot `0xd8` with hist
id 2 (`0x5e084ba`) and, for a second statistics object, hist id
3 (`0x5e084f1`) — a timer recording two histogram ids through
this slot. That makes the slot the timer-recording method
(`measureTime`): it is the only Statistics write method gated at
level > 2 (the detailed-timers level), its caller host records
histogram ids 2 and 3 through it, and its body is exactly the
level-gated forward to recordHistogram (slot `0xd8`). The C++
name is inference, not binary-established; see Unknowns.
Dispatch count for `0xc8` is 29 (new; includes the `0x5d2d363`
thunk-family site and `0x164a01e`/`0x164a072`).

### Lifecycle (0x00, 0x08) and the remaining slots

- D1 (`0x6070ea0`, 412 B): reinstalls the vptr, destroys the 53
  histogram records per shard (skipping the no-op dtor
  `0x5d89570`), frees the store via `0x60d5db0`, destroys the
  mutex `0x60d5170`, releases the delegate shared_ptr at `+0x30`
  (the release half of the ctor's move-in), destroys the options
  vector at `+0x08`. Five direct callers.
- D0 (`0x6071040`, 27 B, new in this packet): calls D1, then
  `_ZdlPvm(this, 0x70)` — the sized delete that proves
  `sizeof(StatisticsImpl) == 0x70`. One direct caller
  (`0x6077773`); four lea sites compare against it (the
  `_Sp_counted_ptr<StatisticsImpl>` deleter `0x6071060`,
  `0x60710c1`, and the two factory hosts `0x6071bf0` and
  `0x6076d04`).
- `0xe8` ToString (`0x6070810`, 677 B): locks, reserves 20000
  bytes in the out string, appends one `"%s COUNT : %lu\n"` line
  per ticker (format at `0x44fd60`) using the ticker-name table
  at `0x432248` and the shard-sum getter, then one `"%s P50 : %f
  P95 : %f P99 : %f P100 : %f COUNT : %lu SUM : %lu\n"` line per
  histogram (format at `0x9609a0`) using the histogram builder
  and the percentile struct. Each line is appended only when
  `0x3fffffffffffffff - len(out) >= len(line)`, else
  `__throw_length_error`. `shrink_to_fit` before return.
- `0xf0` ticker-map fill (`0x6076030`, 1509 B): locks, fills the
  caller's `std::map<std::string, uint64_t>` with one entry per
  ticker (name from the ticker-name table, value from the
  shard-sum getter), unlocks. No direct call anywhere: reached
  only through the vtable.

### The helpers

- `set_core` `0x6070ac0` (91 B): shard 0 counter := value, every
  other shard's := 0 (`xchg`, no bound check, no lock — callers
  hold the mutex). Five direct callers.
- CPU picker `0x60d5cd0` (32 B): `cpuid` leaf 0; if max leaf is 0
  return -1, else leaf 1 EBX[31:24] (the APIC id). Six direct
  callers: the three record routines plus `0x5f0aa40`,
  `0x605e17b`, `0x61c1e24` (other per-CPU users, not mapped here).
- LCG seed `0x61c4080` (151 B): the calling thread's Park-Miller
  seed cell; the record fallbacks advance it with a Park-Miller
  step and store it back. 17 direct callers: the three record
  fallbacks plus 14 other per-thread users.
- Ticker getter `0x6070430` (77 B): sum over shards of the u64
  counter. Exactly three direct callers: `0x60704ae` (locked
  read), `0x6070895` (ToString), `0x6076133` (slot-`0xf0` fill).
- Histogram builder `0x6070500` (216 B): build a fresh `0x3c8`
  byte `HistogramImpl` for a histogram id by merging every
  shard's record. Exactly three direct callers: `0x607064c`,
  `0x607073c`, `0x60709d8`.
- Histogram record `0x606b130` (131 B): bucket index via
  `0x606afa0`, bucket count++, min/max by integer compare,
  count++, sum += value, sum-of-squares += value*value. The
  value is a u64 throughout. Reached via the thunk `0x606b1c0`
  (13 B), which has exactly three direct callers: `0x606004c`,
  `0x6198ae7`, `0x6198e2a`.
- Mutex lock `0x60d5230` (149 B) / unlock `0x60d52f0` (149 B):
  `pthread_mutex_lock`/`unlock` wrappers; return codes 0 and
  `0x6e` are accepted, any other prints `'pthread %s: %s'` and
  aborts. They never throw a C++ exception, so the accessors'
  landing pads cover the builder/delegate calls, not the lock.
  157 calls + 1 tail jump (lock); 669 calls + 5 tail jumps
  (unlock).

### The following vtables

The records at primary `+0x108/+0x138/+0x170` are the typeinfo
slots of the following group vtables (restated from #3392), not
`StatisticsImpl` slots:

- `0x64d2e98`: `N7rocksdb13ObjectLibrary12FactoryEntryINS_10StatisticsEEE`
  (typeinfo `0x64d2d10`), first slots `0x606fad0`, `0x606fda0`,
  `0x606fb40`, `0x606fb50`, gap at `+0x20`.
- `0x64d2ec8`: `St15_Sp_counted_ptrIPN7rocksdb14StatisticsImplELN9__gnu_cxx12_Lock_policyE2EE`
  (typeinfo `0x64d2d48`), first slots `0x606fac0`, `0x606fb80`,
  `0x60710b0`, `0x606fb90`, `0x606fb30`, gap at `+0x28`.
- `0x64d2f00`: `St15_Sp_counted_ptrIPN7rocksdb10StatisticsELN9__gnu_cxx12_Lock_policyE2EE`
  (typeinfo `0x64d2d60`), first slots `0x606fab0`, `0x606fb60`,
  `0x6071060`, `0x606fb70`, `0x606fb20`, gap at `+0x28`.

Only their identities are recorded; their functions are not
mapped here.

## Corrections to #3396

Two size numbers in #3396's `records.json` do not match its own
excerpts (their excerpt files use the correct ranges; only their
`records.json` size numbers are stale). The true FDE sizes:

- record tick `0x606fba0`: FDE `0x606fba0..0x606fc59` = **185 B,
  not 441**. (#3396's README heading also says 441 B.)
- get-and-reset ticker `0x6070c50`: FDE `0x6070c50..0x6070d92` =
  **322 B, not 338**.

And one open unknown from #3396 is answered here: the enable
byte at `+0x20` has a single writer, the ctor (`0x6071a00 movb
$0x3` at `0x6071a32`) — #4142's whole-binary census proves it; no
vtable slot writes `+0x20`.

## Evidence format

- `records.json` holds semantic records only — step lists, census
  counts, vtable slot tables, literal addresses, the boundary
  table, shared-slot RELATIVE counts and dispatch counts. There
  is no per-instruction mnemonic list.
- Instruction-level detail lives only in the whole-function
  verbatim excerpts (52 files, byte-checked). The mnemonics in
  the excerpts (`endbr64` included) are genuine instructions
  present in the target binary, not placeholders.
- `census.py` counts direct calls, tail jumps, leas, qword hits
  and RELATIVE records for every slot target and helper, and
  counts displacement-wide indirect dispatches per slot
  (`dispatch.tsv`, 17,488 rows). The dispatch counts are upper
  bounds, not exact caller counts: any class with a slot at that
  displacement contributes.
- `verify.py` in this directory re-checks everything: the target
  digest, the manifest, byte-for-byte excerpt regeneration from a
  fresh objdump run, every excerpt line against the raw binary,
  fixed + 3 seeded random gate spots (plus 4 spots from the
  slot-`0xc8` host fragment, checked against a fresh objdump run
  on the host FDE), FDE ranges, RELATIVE records, literals,
  census reproduction (`callers.tsv` + `dispatch.tsv`, including
  qword hits and RELATIVE counts), vtable re-derivation, boundary
  re-derivation and the model tests.
- `tools/statisticsimpl_vtable_115.py` models all 32 slots, the
  helpers, the shard store and the delegate chain end to end
  (level gates, id bounds, shard distribution, delegate-chain
  forwarding, locked reads, percentiles and text, ToString and
  the ticker map, reset clearing, destruction);
  `tests/test_statisticsimpl_vtable_115.py` runs 130 checks
  directly (pytest is not installed on this VM).

Re-shipped excerpts (regenerated fresh from the binary by
`export_excerpts.py`, byte-identical to the source packets;
`verify.py` regenerates every excerpt fresh and requires
byte-equality, which subsumes the re-ship check): 11 from
#3902 (the shared base slots), 22 from #3396 (write side, dtors,
name/delegate/hist-id stubs, ctor, helpers), 10 from #3392
(locked reads, cleanups, ticker getter, histogram builder, mutex
wrappers), ToString from #3362 (`main.txt`, renamed here to
`tostring.txt`), `slotf0.txt` from #3378. New in this packet:
the deleting dtor `0x6071040`, the slot-`0xc8` forwarder
`0x5d48960`, the base PrepareOptions `0x6095e70` and
SerializeOptions `0x609de80`, IsInstanceOf `0x5d2e770`, the
empty-string slot `0x5d2ca10`, and the record thunk
`0x606b1c0`.

## Unknowns

- The public C++ names of slots `0x20`, `0x40` and `0x88` (the
  empty-string, empty-Status and delegate-getter slots) are not
  established from the stripped binary; they are described by
  observed behaviour, signatures and vtable slots, not by
  source-level names.
- The `0xc8`/`0xd0`/`0xd8` mapping to
  measureTime/recordInHistogram/recordHistogram is inference from
  the level gates (`0xc8` requires level > 2, the detailed-timers
  level; `0xd0` is implemented in terms of `0xd8`) and from the
  `0x5e080f0` host, which records histogram ids 2 and 3 through
  slot `0xc8`; it is not binary-established.
- The histogram record path treats its third argument as a u64
  throughout (integer compares, adds, multiply); no caller that
  passes a double's bit pattern was examined.
- `set_core` performs no bound check: ids >= 179 index past the
  ticker area into the histogram records (observed addressing, not
  exercised).
- The `0x40` tail at the end of each `0xce40`-byte shard
  (`0xce00..0xce40`) is not examined; its contents are open
  (carried from #3392).
- The `bucket_count` field at `record+0x390` is read by the shared
  init and never written by it; its writer is an open unknown
  (likely the shard-store builder `0x60716d0` or the bucket-count
  init `0x606b080`).
- The `+0x28` delegate is moved in from the creator's options
  struct; which construction paths install a non-null delegate
  (beyond the factory host, which passes its own options
  through) is not traced here.
- The exact `_Hash_bytes` output for a given `pthread_self` is not
  byte-verified against a live run (the seed is thread-dependent);
  the model implements the documented libstdc++ MurmurHash64A
  algorithm and only its determinism and range are tested.
- The other three direct callers of the CPU picker (`0x5f0aa40`,
  `0x605e17b`, `0x61c1e24`) and the other 14 direct callers of
  the LCG seed accessor are other per-CPU / per-thread users;
  their routines are not mapped here.
- Which landing pad covers which call site inside the locked
  routines is inferred from the register and mutex state, not read
  from the LSDA; the fragments' shapes and jump targets are
  pinned.
- The `0x5e080f0` host FDE (`0x5e080f0..0x5e095ed`) is pinned only
  for its slot-`0xc8` devirtualization fragment
  (`0x5e08488..0x5e084f7`) and the two slot-`0xd8` calls (hist ids
  2 and 3); the rest of the `0x14fd`-byte FDE is not mapped here.
- The ctor's trailing cleanup fragment at `0x6071b60` (outside the
  ctor FDE) is not excerpted.

## Environment limits

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so
`make verify`, `make test` and `make catalogue-check` cannot run
here; the packet carries its own runnable `verify.py` and the
model tests instead, both run with the system Python 3. `work/hl-node-115.bin`
is the materialized node #115 binary (its SHA-256 matches
`provenance/artifacts.json`).
