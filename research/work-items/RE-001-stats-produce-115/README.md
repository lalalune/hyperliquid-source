# RE-001: node #115 slot-0xe8 produce callee 0x6070810 (StatisticsImpl::ToString) with its installer

- Component ID: RE-001 (node #115 function map)
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json, `artifacts/node/115/hl-node`; local copy
  `work/hl-node-115.bin` hashes exactly)
- Source commit / reference commit: upstream main `05bc2de30`
- Claim status: observation for everything below except the items listed
  under Unknowns, which are inference boundaries, not claims.

## Bounded question

#3037 left this open: what is the virtual produce callee behind slot
`0xe8` in the stats-emit routine `0x5d52020`, what writes the producer
object at `DB+0x548`, and which vtable does it carry?

## Answer, pinned to the target

The producer is a `rocksdb::StatisticsImpl`. Its vtable is `0x64d2d88`
(typeinfo `N7rocksdb14StatisticsImplE`, base `N7rocksdb10StatisticsE`),
and vtable slot `0xe8` holds `0x6070810`, the `StatisticsImpl::ToString`
that renders the full statistics string. The slot is installed by one
RELATIVE record (`0x64d2e70 -> 0x6070810`); there are no direct calls
to `0x6070810` anywhere in the binary. The call in the stats-emit
routine passes the hidden return slot in `rdi` and the producer in
`rsi` (a by-value `std::string` return), which is why the callee's
first argument is the output string and not `this`.

`ToString` (`0x6070810`, `rdi=&out, rsi=this`) runs, in order:

1. **Lock.** `pthread_mutex_lock` on `this+0x38` via the lock wrapper
   `0x60d5230` (re-shipped from RE-001-mutex-wrappers-115).
2. **Setup.** The output string is initialised empty (SSO) and
   `reserve(0x4e20)` (20000 chars) is called on it.
3. **Tickers.** The BSS vector at `0x6506260` (`{begin, end}` of
   `0x28`-byte entries) is walked in order. Each entry holds a u32
   ticker id at `+0x00` and a name pointer at `+0x08`. The count
   comes from `0x6070430(this, id)`: the sum over `2***(this+0x68)`
   shards of the u64 at `*(this+0x60) + shard*0xce40 + id*8`. Each
   line is formatted with `"%s COUNT : %lu\n"` (format at `0x44fd60`)
   and appended after the length check
   `0x3fffffffffffffff - len(out) >= len(line)`, else
   `__throw_length_error`.
4. **Histograms.** The BSS vector at `0x6506240` is walked the same
   way (`0x28`-byte entries: u32 histogram id at `+0x00`, name at
   `+0x08`). Per entry, `0x6070500` allocates a `0x3c8`-byte
   `HistogramImpl` (vtable `0x64d2b80`), initialises it, and merges
   every shard's histogram at
   `*(this+0x60) + shard*0xce40 + 0x598 + id*0x3c8` into it. The
   merged object is then asked for its percentile struct through
   vtable slot `0x78` (the thunk `0x606bdd0`, which adds 8 to `rdi`
   and tail-jumps to `0x606bce0`): the struct at the stack slot
   holds P50 at `+0x00`, P95 at `+0x08` (constant `95.0` at
   `0x459640`), P99 at `+0x10` (constant `99.0` at `0x459258`),
   average at `+0x18`, stddev at `+0x20`, P100 at `+0x28`,
   count at `+0x30` (u64), sum at `+0x38` (u64), min at `+0x40`.
   The histogram object is then destroyed: when its vtable slot 1
   equals the value in GOT slot `0x64ed2f0` (`0x5d8b3b0`, the
   HistogramImpl deleting destructor), a plain sized delete of
   `0x3c8` bytes runs; otherwise slot 1 is called virtually. The
   line is formatted with
   `"%s P50 : %f P95 : %f P99 : %f P100 : %f COUNT : %lu SUM : %lu\n"`
   (format at `0x9609a0`) from the struct fields `+0x00`, `+0x08`,
   `+0x10`, `+0x28`, `+0x30`, `+0x38` — average, stddev and min are
   computed but not printed — and appended under the same length
   check.
5. **Epilogue.** `reserve()` with no size argument (shrink to fit),
   unlock `this+0x38` via `0x60d52f0`, return the output string.

The installer: the statistics `shared_ptr` at `DB+0x548` (raw
pointer) / `DB+0x550` (control) is written by the copy site in the
struct-copy routine `0x5d57770` (window `0x5d58249..0x5d5828c`).
The site copies the destination's `+0x530..0x540` from the source's
`+0x2a0..0x2b0`, the bool at `+0x540` from the source's `+0x2b0`,
the raw pointer at `+0x548` from the source's `+0x2b8`, and the
control at `+0x550` from the source's `+0x2c0` through the
`shared_ptr` copy helper `0x5d35c00`, which copies the control
pointer and bumps the control's use count at `+8` by one (plain
`addl` when single-threaded, `lock addl` otherwise). The copy
routine has exactly two callers: the mutex-guarded rebuild
`0x5d58720` (at `0x5d5879d`) and the routine at `0x5d74aa0`
(at `0x5d753d4`). The rebuild locks `db+0x700` through the
instrumented acquire `0x606ca40`, calls virtual slot `0x30` of the
source object, builds a temp options struct with `0x60c2e20`,
runs the copy, cleans up, unlocks `db+0x700` with `0x60d52f0`,
and returns the destination. The rebuild itself has no direct
calls: it is reached only through four vtable slots holding the
same implementation (`0x64c9638`, `0x64cb3b0`, `0x64cb890`,
`0x64cbe90`).

The emit end is re-shipped whole: the stats-emit routine
`0x5d52020` gates on `DB+0x548` (null: nothing), calls slot `0xe8`
and emits `"[%s:774] STATISTICS:\n %s"` with the file
`"db/db_impl/db_impl.cc"` through the log dispatch `0x5fcf060`.

## Callees pinned whole in this packet

| address | FDE range | size | what it is |
| --- | --- | --- | --- |
| 0x6070810 | 0x6070810..0x6070ab5 | 677 B | StatisticsImpl::ToString |
| 0x6070430 | 0x6070430..0x607047d | 77 B | sharded ticker sum |
| 0x6070500 | 0x6070500..0x60705d8 | 216 B | HistogramData build |
| 0x606b080 | 0x606b080..0x606b0a2 | 34 B | histogram bucket-count init |
| 0x606b0c0 | 0x606b0c0..0x606b10a | 74 B | histogram locked shared init |
| 0x606bdf0 | 0x606bdf0..0x606be3d | 77 B | histogram shard merge |
| 0x606bce0 | 0x606bce0..0x606bdcd | 237 B | histogram percentile struct |
| 0x606bdd0 | 0x606bdd0..0x606bddd | 13 B | slot-0x78 thunk |
| 0x5d8b3b0 | 0x5d8b3b0..0x5d8b3be | 14 B | histogram sized delete |
| 0x5d35c00 | 0x5d35c00..0x5d35c26 | 38 B | shared_ptr control copy + bump |
| 0x5d58720 | 0x5d58720..0x5d58809 | 233 B | mutex-guarded rebuild caller |
| 0x5d52020 | 0x5d52020..0x5d520c1 | 161 B | stats emit (re-shipped) |
| 0x5fcf060 | 0x5fcf060..0x5fcf153 | 243 B | level-gated log dispatch (regenerated; byte-identical to #3037's) |
| 0x60d5230 | 0x60d5230..0x60d52c5 | 149 B | mutex lock (re-shipped) |
| 0x60d52f0 | 0x60d52f0..0x60d5385 | 149 B | mutex unlock (re-shipped) |
| 0x606ca40 | 0x606ca40..0x606cc6a | 554 B | instrumented acquire (re-shipped) |

The stats-copy site `stats_copy_site.txt` is the window
`0x5d58249..0x5d5828c` inside the copy routine `0x5d57770`
(FDE `0x5d57770..0x5d586e3`); only that site is claimed, the
rest of the `0xf73`-byte struct copy is not modelled.

The re-shipped excerpts are byte-identical to their source
packets (`RE-001-stats-emit-52020-115/main.txt`,
`RE-001-mutex-wrappers-115/lock.txt` and `unlock.txt`,
`RE-001-instrumented-acquire-6ca40-115/main.txt`); verify.py
diffs them against the sources. The log dispatch excerpt is
regenerated fresh from the binary and is byte-identical to
#3037's `log_dispatch.txt`.

## Callee notes (pinned semantics)

- **0x6070430 ticker sum** (`rdi=this, esi=ticker`): zero-extends
  the ticker id, then loops `2***(this+0x68)` shards accumulating
  `*(base + shard*0xce40 + ticker*8)` where `base = *(this+0x60)`,
  and returns the u64 sum. The loop count is `1 << *(this+0x68)`
  (the byte at `+0x68` is read as a u32 and shifted by its low 8
  bits). Two other routines also call it (`0x6070490..0x60704d2`
  and the StatisticsImpl vtable slot `0xf0` routine
  `0x6076030..0x6076615`); they are not pinned.
- **0x6070500 histogram build** (`rdi=&obj, rsi=this, edx=type`):
  `operator new(0x3c8)`, installs vtable `0x64d2b80`, calls
  `0x606b080(obj+8)` (bucket count at `+0x390` from the BSS
  range `0x6505d20..0x6505d28`), zeroes `+0x3c0` and `+0x3a0..0x3c0`,
  calls `0x606b0c0(obj)` (locked shared init), stores the object
  at `*out`, then merges each shard's histogram at
  `*(this+0x60) + shard*0xce40 + 0x598 + type*0x3c8` via
  `0x606bdf0(obj, shard_hist)`. Returns `out`.
- **0x606b080** (`rdi=obj+8`): sets `obj+0x390` to
  `(*0x6505d28 - *0x6505d20) / 8`, then tail-jumps to the shared
  init `0x606b020`.
- **0x606b0c0** (`rdi=obj`): locks the histogram's own mutex at
  `+0x3a0` with a raw `pthread_mutex_lock` (throwing
  `__throw_system_error` on failure), calls `0x606b020(obj+8)`,
  unlocks.
- **0x606bdf0** (`rdi=obj, rsi=shard_hist`): locks the histogram's
  mutex at `+0x3a0`, merges via `0x606b1d0(obj+8, shard_hist+8)`,
  unlocks.
- **0x606bce0** (`rdi=hist+8, rsi=&struct`): fills the 9-field
  struct. `0x606b500` gives P50 into `+0x00`; `0x606b260` with
  the double constants `95.0` (`0x459640`) and `99.0`
  (`0x459258`) gives P95/P99 into `+0x08`/`+0x10`; `0x606b540`
  gives `+0x18` and `0x606b5d0` gives `+0x20` (average and
  stddev by size and position — inference, see Unknowns);
  `+0x28` is `(double)*(hist+0x08)` (max, i.e. P100), `+0x30`
  is `*(hist+0x10)` (count, u64), `+0x38` is `*(hist+0x18)`
  (sum, u64), `+0x40` is `(double)*(hist+0x00)` (min). The
  two u64-to-double conversions use the unsigned fixup
  (`shr $1` + `or` + `addsd` doubling) for values with the
  high bit set.
- **0x606bdd0** (`rdi=obj, rsi=&struct`): adds 8 to `rdi` and
  tail-jumps to `0x606bce0`. It is HistogramImpl vtable slot
  `0x78` (RELATIVE record at `0x64d2bf8`).
- **0x5d8b3b0** (`rdi=obj`): `endbr64; mov $0x3c8,%esi;
  jmp _ZdlPvm` — a sized delete of a `0x3c8`-byte object. It is
  HistogramImpl vtable slot `0x08` (RELATIVE record at
  `0x64d2b88`) and the value GOT slot `0x64ed2f0` holds.
- **0x5d35c00** (`rdi=&dst_control, rsi=&src_control`):
  `*(rdi) = *(rsi)`; when the control is non-null, `+1` to
  the use count at `control+8` (plain `addl` when
  `__libc_single_threaded` is nonzero, `lock addl`
  otherwise). No release of the destination's old control.
- **0x5d58720** (`rdi=dst, rsi=db, rdx=src2`): locks `db+0x700`
  via `0x606ca40`, calls virtual slot `0x30` of `*src2`, fills
  a stack buffer via `0x5d8bce0`, builds a temp struct with
  `0x60c2e20(rsp+0x300, db+0x330, db+0x5a0)`, runs the copy
  `0x5d57770(dst, temp, src2)`, cleans up with `0x5d354b0`
  and `0x5d35770`, unlocks `db+0x700` with `0x60d52f0`, and
  returns `dst`.

## Consumers

Census (executable-LOAD-segment exhaustive E8/E9 scan with
objdump confirmation, reproduced by `census.py` and re-run
inside `verify.py`): ToString 0 direct calls — reached only
through the StatisticsImpl vtable slot `0xe8` (RELATIVE record
at `0x64d2e70`); ticker getter 3 direct calls (0x6070895 here,
0x60704ae, 0x6076133); histogram builder 3 direct calls
(0x60709d8 here, 0x607064c, 0x607073c); histogram init-a 7
direct calls; histogram init-b 8 direct calls + 1 vtable
RELATIVE (slot `0x10`); histogram merge 1 direct call
(0x6070595 here) + 1 tail jump; percentile struct 0 direct
calls + 1 tail jump (0x606bdd8, the thunk); thunk 0 direct
calls + 1 vtable RELATIVE (slot `0x78`); histogram delete 0
direct calls + 2 RELATIVE records (vtable slot `0x08` and
GOT `0x64ed2f0`); shared_ptr copy 162 direct calls + 2 tail
jumps (including the statistics site at `0x5d58287`); copy
routine 2 direct calls (0x5d5879d, 0x5d753d4); rebuild caller
0 direct calls + 4 vtable RELATIVE records; stats emit 1
direct call (0x5d7e339, in #3037's dump caller); log dispatch
252 direct calls + 1 tail jump; mutex lock 157 direct calls
+ 1 tail jump; mutex unlock 669 direct calls + 5 tail jumps;
instrumented acquire 244 direct calls + 8 tail jumps.

## NOT claimed

What the percentile/average/stddev helpers (`0x606b500`,
`0x606b260`, `0x606b540`, `0x606b5d0`) and the shared init
(`0x606b020`) and bucket merge (`0x606b1d0`) compute
internally — the model takes their outputs as oracle inputs
and pins only the wiring; whether the struct fields at `+0x18`
and `+0x20` are average and stddev in that order (inferred
from the helpers' sizes and positions, not from their bodies);
the contents of the BSS ticker/histogram vectors at
`0x6506260`/`0x6506240` and of the BSS bucket range at
`0x6505d20..0x6505d28` (not present in the file; only the
access pattern is pinned); the rest of the `0x5d57770`
struct-copy routine beyond the statistics site; what the
rebuild caller's four vtables are (their classes are not
identified); who first creates the StatisticsImpl shared_ptr
control that the copy site only copies; what the rebuild
caller's virtual slot-`0x30` call, the temp builder
`0x60c2e20`, and the cleanups `0x5d354b0`/`0x5d35770` do
internally; the other 31 StatisticsImpl vtable slots and the
other 15 HistogramImpl vtable slots beyond their addresses.

## Ruled out

The installer `0x5d356e0` writes `+0x548` too, but it is NOT
the statistics writer: it installs the object built by the
factory `0x60dbd80` under a `_Sp_counted_ptr` control whose
vtable `0x64c8748` has typeinfo
`St15_Sp_counted_ptrIPN7rocksdb12TableFactoryE` — a
TableFactory shared_ptr, not a Statistics shared_ptr. Same
offset, different object type. Its only reference is the data
slot at `0x64eab50` (RELATIVE record); it has no direct calls.

## Next step

- Pin the percentile helper `0x606b260` whole (662 bytes, 7
  direct calls + 2 tail jumps): it is the only unpinned helper
  on the ToString path whose output reaches the emitted text.
- Pin the StatisticsImpl vtable slot `0xf0` routine `0x6076030`
  (0x5e5 bytes, calls the ticker getter at `0x6076133`): it is
  the sibling renderer next to ToString.
- Resolve the rebuild caller's four vtables: identify the four
  owning classes from their typeinfo names.
- Pin the copy routine `0x5d57770`'s other shared_ptr sites
  only as part of a work item that needs the whole options
  struct, not as a standalone series.

## Reproduce

- `python3 research/work-items/RE-001-stats-produce-115/export_excerpts.py`
  regenerates the 13 new excerpts from `work/hl-node-115.bin`.
- `python3 research/work-items/RE-001-stats-produce-115/census.py`
  reproduces the caller census into `callers.tsv`.
- `python3 research/work-items/RE-001-stats-produce-115/verify.py`
  checks the digest, manifest, excerpt regeneration, spot
  instructions, FDE ranges, relocation set, literals, census
  and semantic records, then runs the model tests.
- `python3 tests/test_stats_produce_115.py` runs the 30
  model-test checks directly (pytest is not installed here).
