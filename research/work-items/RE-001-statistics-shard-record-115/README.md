# RE-001: StatisticsImpl shard record (node #115)

## Task and bounded question

Task: RE-001. Bounded question: how does StatisticsImpl pick a shard
and record a ticker or a histogram sample — the CPU-count picker, the
per-thread seed fallback, the level gates, the shard arithmetic, and
the delegate forwards — and which vtable slots do it?

Artifact: `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(provenance/artifacts.json). All evidence below is bound to that digest.

## Windows

| window | FDE | file |
|---|---|---|
| CPUID picker | 0x60d5cd0..0x60d5cf0 | picker-60d5cd0.objdump.txt |
| ticker record (StatisticsImpl slot 0xb0) | 0x606fba0..0x606fc59 | ticker-record-606fba0.objdump.txt |
| histogram record (StatisticsImpl slot 0xd8) | 0x606fef0..0x606ffce | histogram-record-606fef0.objdump.txt |
| histogram wrapper (StatisticsImpl slot 0xd0) | 0x606ffd0..0x60700c4 | histogram-wrapper-606ffd0.objdump.txt |
| per-thread seed | 0x61c4080..0x61c4117 | thread-seed-61c4080.objdump.txt |
| record thunk (HistogramImpl slot 0x20) | 0x606b1c0..0x606b1cd | record_thunk.txt |
| record impl | 0x606b130..0x606b1b3 | record.txt |
| StatisticsImpl ctor | 0x6071a00..0x6071b60 | ctor-6071a00.objdump.txt |
| shard-store builder | 0x60716d0..0x6071952 | builder-60716d0.objdump.txt |

Excerpts were produced with, e.g.:

```
objdump -d --start-address=0x606fba0 --stop-address=0x606fc59 work/hl-node-115.bin
```

Mnemonics such as `endbr64` are genuine instructions present in the
target binary, not placeholders. The excerpts are verbatim objdump output,
whole-function. `export_excerpts.py` (committed here) regenerates them and
`frames.txt` from the binary. The seed, record thunk, record impl and
boundaries are re-shipped byte-identical from open PR #3575 (the record
family originally pinned in open PR #3371); the ctor and builder are
re-shipped byte-identical from open PR #3572. `verify.py` re-derives
every excerpt from the binary, so a re-ship that drifted would fail
the packet check.

## Claim status

### Observations (read directly from the disassembly)

- The picker 0x60d5cd0 runs `cpuid` leaf 0; when eax is 0 it returns
  -1, otherwise it runs `cpuid` leaf 1 and returns EBX >> 24 (the
  maximum number of addressable logical-processor IDs). It has exactly
  6 direct call sites (see records.json `census`).
- The per-thread seed 0x61c4080 returns a pointer to the cached seed
  at thread-0x20 (pointer at thread-0x10): first use computes
  `_Hash_bytes(&pthread_self, 8, 0xc70f6907) & 0x7fffffff`, or 1 when
  that is 0. It has 17 direct call sites.
- Shard pick (shared by all three record slots): `shard = source &
  ((1 << exp) - 1)` where exp is the bucket exponent at this+0x68.
  When the picker returns a negative count, the seed is advanced once
  (`seed = seed * 0x41a7 mod 0x7fffffff`, the mersenne fold) and the
  advanced seed picks the shard. The seed is advanced in place, so a
  record call that also forwards to a delegate advances it twice.
- Ticker record, StatisticsImpl vtable slot 0xb0 (0x606fba0), is
  reached only through the vtable (RELATIVE slot 0x64d2e38, no direct
  call sites). Args: (this, ticker_id, value). Gates: id > 0xb1
  returns without recording; the level byte at this+0x20 == 0 returns
  without recording. Otherwise the value is atomically added
  (`lock add`) to the ticker counter at
  `base + shard*0xce40 + id*8`, where base is the records base at
  this+0x60. When the delegate at this+0x28 is non-null, the same
  (id, value) is tail-dispatched to the delegate's slot 0xb0.
- Histogram record, StatisticsImpl vtable slot 0xd8 (0x606fef0), is
  reached only through the vtable (RELATIVE slot 0x64d2e60). Args:
  (this, hist_id, value). Gate: the level byte at this+0x20 <= 1
  returns without recording. Otherwise the sample is recorded into
  the picked shard's record `hist_id` — the record at
  `base + shard*0xce40 + hist_id*0x3c8 + 0x598` — through its vtable
  slot 0x20, the record thunk 0x606b1c0 (HistogramImpl vtable
  0x64d2b80 slot 0x20, RELATIVE slot 0x64d2ba0; the thunk tail-jumps
  to the record impl 0x606b130). When hist_id <= 0x33 and the delegate
  at this+0x28 is non-null, the same (id, value) is tail-dispatched
  to the delegate's slot 0xd8.
- Histogram wrapper, StatisticsImpl vtable slot 0xd0 (0x606ffd0), is
  reached only through the vtable (RELATIVE slot 0x64d2e58). It first
  compares this object's vtable slot 0xd8 against the canonical
  0x606fef0; when they differ it tail-dispatches to that slot with
  (this, hist_id, value) without consulting the level gate; when they
  match it runs the canonical histogram-record body above.
- Shard-store layout (from the re-shipped ctor and builder, open PR
  #3572): the ctor writes the level byte 3 at this+0x20, moves the
  delegate pointer from its argument into this+0x28, and calls the
  builder with out = &this+0x60; the builder stores the records base
  at out+0x00 and the bucket exponent at out+0x08. Each shard is
  0xce40 bytes: a 0x598-byte header holding 178 ticker counters
  (ids 0..0xb1, 8 bytes each), then 53 HistogramImpl records of
  0x3c8 bytes at shard+0x598..shard+0xce00.
- The record impl 0x606b130 bucketizes the value by the 109 generated
  boundaries (boundaries.tsv, from open PR #3371) and updates
  count/min/max/sum/sumSq; the model follows #3371/#3575 here.

### Inferences

- Slot 0xb0 is the ticker-record virtual (`RecordTick` in rocksdb
  terms), slot 0xd8 the histogram-record virtual, slot 0xd0 the
  histogram-entry virtual that honours overrides: the wrapper's
  canonical check is the same shape as the transform-chain and
  canonical chain-walk checks pinned in #3585 and #3352, and the
  three slots sit in the StatisticsImpl vtable exactly where the
  delegate forwards land (0xb0 for tickers, 0xd8 for histograms).
- The level gates encode the rocksdb stats levels: tickers record
  whenever recording is enabled at all (level != 0), histograms only
  when the level exceeds 1 (the ctor's level 3 enables both).
- The picker/seed pair is shared with other shard systems: the
  census lists three more picker consumers (0x5f0a9c0, 0x605e170,
  0x61c1e10) that use a 0x40-byte stride and different field offsets;
  they are cited in records.json, not pinned — they belong to other
  components' work items.

### Unknowns

- The C++ names of slots 0xb0/0xd0/0xd8 (inferred from behaviour).
- Which construction paths install a non-null +0x28 delegate: the
  ctor moves it from its argument, but no caller in this binary
  passes a non-null argument (both ctor callers pass a zeroed
  argument struct); the delegate is installed later by the parse
  workers (see #3572). The forward paths are pinned here; the
  installer is still open.
- Histogram ids 53..0x33 are recorded locally (53 records exist per
  shard) but only ids <= 0x33 are forwarded; whether ids 52..0x33
  name real histograms is not established by this packet.
- The enable-byte setter: the level byte at +0x20 is written 3 by
  the ctor; no setter was found in this binary (see #3572).

## Model and tests

`tools/statistics_shard_record_115.py` implements the picker, the
seed, the shard pick and the three record slots end to end (inputs
through the model to observable outputs: shard counters, histogram
samples, delegate forwards, seed advances).
`tests/test_statistics_shard_record_115.py` runs 49 checks, all
passing, covering the picker values, the seed hash/cache/advance,
the shard mask, the ticker and histogram gates (including the
boundary ids 0xb1/0xb2 and 0x33/0x34), the delegate forwards, the
wrapper's canonical check and override bypass, and the seed-fallback
path (including the double advance when a delegate is present).
