# RE-001: node #115 StatisticsImpl locked read accessors — slots 0x98/0xa0/0xa8

- Component ID: RE-001 (node #115 function map)
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json, `artifacts/node/115/hl-node`; local copy
  `work/hl-node-115.bin` hashes exactly)
- Source commit / reference commit: upstream main `05bc2de30`
- Claim status: observation for everything below except the items listed
  under Unknowns, which are inference boundaries, not claims.

## Bounded question

#3378 left the routine at FDE `0x6070490..0x60704d2` unmapped — the
third direct caller of the ticker getter `0x6070430`. What is it, what
do its two neighbouring vtable slots compute, how do the three share
the mutex and the histogram builder, and how are they reached?

## Answer, pinned to the target

The three routines are the locked read side of `StatisticsImpl`,
installed in its primary vtable `0x64d2d88` (typeinfo
`N7rocksdb14StatisticsImplE`, base `N7rocksdb10StatisticsE`, 32 slots)
at slots `0x98`, `0xa0` and `0xa8`. None of the three has any direct
call, tail jump or `lea` anywhere in the binary: they are reached
only through their vtable slots. All three share one discipline —
lock the mutex at `this+0x38`, delegate to an unlocked helper, unlock
— and each has its own exception cleanup that unlocks (destroying the
built temp first when one exists) and resumes unwinding.

### Slot 0x98 — the locked ticker read, 0x6070490 (66 B)

`(this, ticker_id: u32) -> u64`. Locks `this+0x38` via `0x60d5230`
(call site `0x60704a4`), calls the ticker getter `0x6070430`
(`0x60704ae`), unlocks via `0x60d52f0` (`0x60704b9`) and returns the
sum. Its landing pad at `0x60704c6` jumps to the fragment at
`0x607047e..0x607048e` (own FDE), which unlocks and calls
`_Unwind_Resume`. The getter makes no calls, so in practice the pad
covers the lock call. This closes #3378's open unknown: the third
direct caller of the getter is the locked read, and the other two
callers (ToString `0x6070810`, slot-0xf0 fill `0x6076030`) call the
getter directly because they already hold the lock.

### Slot 0xa0 — the locked histogram percentiles, 0x6070610 (185 B)

`(this, hist_id: u32, out: HistogramData*) -> void`. Locks `this+0x38`
(`0x607063e`), builds a fresh `0x3c8`-byte `HistogramImpl` temp via
the builder `0x6070500(rsp, this, edx)` (`0x607064c`), fills the
caller's struct through the temp's vtable slot `0x78` (`call
*0x78(%rax)` at `0x607065b`; thunk `0x606bdd0`, percentile struct
`0x606bce0` — the 9-field record P50/P95/P99/average/stddev/P100/
count/sum/min pinned in #3371), destroys the temp, unlocks
(`0x6070684`) and returns. The destroy compares the temp's vtable
slot `0x8` against GOT `0x64ed2f0` (which holds the sized delete
`0x5d8b3b0`): equal means `_ZdlPvm(temp, 0x3c8)`, else the deleting
dtor is called. Its exception cleanup is the fragment at
`0x60705d8..0x607060c` (own FDE) with two entries: the head
`0x60705d8` (delete temp + unlock + resume, from the landing pad at
`0x60706b8`) and the interior `0x60705e7` (unlock only, from the
landing pad at `0x60706c4`).

### Slot 0xa8 — the locked histogram text, 0x6070700 (193 B)

`(out: string*, stats, hist_id: u32) -> string*`. The stats object
arrives in `rsi`, not `rdi`: the routine returns a `std::string` by
value, so `rdi` is the hidden return-value pointer (the out string,
returned unchanged) and `rsi` is `this`. It locks `rsi+0x38`
(`0x607072e`), builds the temp via `0x6070500(rsp, rsi, edx)`
(`0x607073c`), renders into the out string through the temp's vtable
slot `0x30` (`call *0x30(%rax)` at `0x607074b`; entry `0x606bc90`,
renderer `0x606b6f0` — the Count / Min-Median-Max / Percentiles /
dashes / bucket-rows text pinned in #3371), destroys the temp the
same way as slot `0xa0`, unlocks (`0x6070774`), checks the stack
canary and returns `rdi`. Its exception cleanup is the fragment at
`0x60706ca..0x60706fe` (own FDE), the mirror of slot `0xa0`'s: head
`0x60706ca` (delete + unlock, from `0x60707b0`) and interior
`0x60706d9` (unlock only, from `0x60707bc`).

### The shared helpers

- **Ticker getter `0x6070430`** (77 B, re-shipped from #3378):
  the sum over `2**(u8 at this+0x68)` shards of the u64 at
  `*(this+0x60) + shard*0xce40 + ticker*8` (ticker zero-extended
  from u32). Exactly three direct callers: `0x60704ae` (here),
  `0x6070895` (ToString), `0x6076133` (slot-0xf0 fill).
- **Histogram builder `0x6070500`** (216 B, re-shipped from #3362):
  allocates a fresh `0x3c8`-byte `HistogramImpl`, initialises it
  (`0x606b080`/`0x606b0c0`, mutex zeroed), publishes `*out`, then
  merges each shard's record at `shard_base + shard*0xce40 + 0x598
  + id*0x3c8` via the merge wrapper `0x606bdf0`. Exactly three
  direct callers: `0x607064c` (slot 0xa0), `0x607073c` (slot 0xa8),
  `0x60709d8` (ToString).
- **Shard layout.** One store at `*(this+0x60)` serves both: ticker
  counters at `shard + id*8`, histogram records at `shard + 0x598 +
  id*0x3c8`. `0x598 + 53*0x3c8 == 0xce00`, leaving a `0x40` tail per
  shard whose contents are an open unknown.
- **Mutex wrappers `0x60d5230`/`0x60d52f0`** (re-shipped from
  #3362/#3378): `pthread_mutex_lock`/`unlock`; return codes `0` and
  `0x6e` are accepted, any other prints `pthread %s: %s` and aborts.
  They never throw a C++ exception, so the accessors' landing pads
  cover the builder/delegate calls, not the lock. Lock: 157 direct
  calls + 1 tail jump (`0x606ca04`); unlock: 669 calls + 5 tail
  jumps.
- **Reachability.** The three routines have zero direct calls and
  are reached only through the vtable. Indirect calls through the
  slot displacements across the whole binary — `call *0x98(%r..)`
  241 sites, `*0xa0` 522 sites, `*0xa8` 54 sites (full lists in
  `dispatch.tsv`) — are displacement-wide, not type-attributed: any
  class with a slot at that displacement contributes, so these are
  upper bounds on `StatisticsImpl` dispatches, not exact caller
  counts.

### The vtable around them

The primary vtable's 32 slots are in `vtables.tsv`, re-derived from
the RELATIVE records in `relocations.txt`. Neighbours of note: slot
`0xb0` (`0x606fba0`) is the record/tick write path (byte at
`this+0x20`, index `<= 0xb1`, `lock add` into the shard) — not a
read, not mapped here; slots `0xe8`/`0xf0` are ToString and the
ticker-map fill (#3362/#3378). The records at primary `+0x108`/
`+0x138`/`+0x170` are the typeinfo slots of the vtables that follow
in the group — `ObjectLibrary::FactoryEntry<Statistics>` at
`0x64d2e98`, `_Sp_counted_ptr<StatisticsImpl>` at `0x64d2ec8`,
`_Sp_counted_ptr<Statistics>` at `0x64d2f00` — not `StatisticsImpl`
slots; only their identities are recorded.

## Evidence format

- `records.json` holds semantic records only — branch site→target
  pairs, census counts, vtable slot tables, literal addresses and
  the step lists above. There is no per-instruction mnemonic list.
- Instruction-level detail lives only in the whole-function verbatim
  excerpts (`locked_ticker.txt`, `landing_pad.txt`,
  `locked_percentiles.txt`, `locked_histogram_text.txt`,
  `cleanup_a0.txt`, `cleanup_a8.txt`, plus the four re-shipped
  excerpts). The mnemonics in the excerpts (`endbr64` included)
  are genuine instructions present in the target binary, not
  placeholders.
- `verify.py` in this directory re-checks everything: the target
  digest, the manifest, byte-for-byte excerpt regeneration from a
  fresh objdump run, every excerpt line against the raw binary,
  fixed + 3 seeded random gate spots, FDE ranges, RELATIVE records,
  literals, census reproduction (`callers.tsv` + `dispatch.tsv`),
  vtable re-derivation and the model tests.
- `tools/locked_ticker_read_115.py` models the three accessors, the
  getter, the builder and the HistogramImpl snapshot end to end
  (lock discipline including the exception paths, temp lifecycle,
  shard sums, percentile struct and rendered text);
  `tests/test_locked_ticker_read_115.py` runs 111 checks directly
  (pytest is not installed on this VM).

## Unknowns

- The public C++ names of the three routines are not established
  from the stripped binary; they are described by observed
  behaviour, signatures and vtable slots, not by source-level
  names. (The arg shapes match the documented RocksDB Statistics
  interface — a u64 ticker count, a HistogramData fill, and a
  by-value string return — but that match is inference, not a
  binary-established name.)
- Which landing pad covers which call site inside `0x6070610`/
  `0x6070700` is inferred from the temp's lifetime (the builder-call
  pad must be the unlock-only one, since no temp exists yet; the
  delegate-call pad must be the delete+unlock one), not read from
  the LSDA; the two fragments' shapes and their jump targets are
  pinned.
- The `0x40` tail at the end of each `0xce40`-byte shard
  (`0xce00..0xce40`, after the last histogram record) is not
  examined; its contents are open.
- Slot `0xb0` (`0x606fba0`) is the record/tick write path, not a
  read; its hash/index helper `0x60d5cd0` and the exact ticker-id
  bound (`0xb1` vs the 179 counter slots) are not mapped here.
- The remaining `StatisticsImpl` vtable slots (`0x10..0x90`,
  `0xb8..0xe0` except `0xe8`/`0xf0`) are not mapped; only their
  RELATIVE-backed addresses are recorded.
