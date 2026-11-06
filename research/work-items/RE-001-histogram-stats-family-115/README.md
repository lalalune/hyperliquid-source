# RE-001: node #115 HistogramImpl statistics family

Bounded question: what is the complete `HistogramImpl` statistics
family on node #115 — how are the bucket boundaries generated, how
are values recorded and merged, how are percentile / average /
stddev computed, and what does the full text renderer emit?

Target: node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`). Base commit
`05bc2de303c05525b71e7e257426e741bc66a390`.

This packet closes the open unknown left by #3362 (the
`RE-001-stats-produce-115` packet): the percentile helper
`0x606b260` and the average / stddev helpers were census targets
only there. It pins them whole, together with every caller and
callee that makes the behaviour observable end to end — the
boundary generator, the record / merge path, the `HistogramImpl`
vtable surface, and the full text renderer that
`StatisticsImpl::ToString` (`0x6070810`, #3362) prints through
the percentile struct.

## The object

`HistogramImpl` is a `0x3c8`-byte object built by `0x6070500`
(#3362): vtable `0x64d2b80` at `+0x00`, typeinfo
`N7rocksdb13HistogramImplE` (`0x64d2b58`, base
`N7rocksdb9HistogramE`), a statistics struct at `+0x08`, and a
`pthread_mutex_t` at `+0x3a0`. The vtable thunks add 8 to `this`,
so the implementations take the *inner* pointer (`outer+0x08`);
the name / min / max accessors take the outer pointer. Field
offsets below are inner-relative:

| offset | field |
| --- | --- |
| `+0x00` | min (u64, initialised to the last boundary) |
| `+0x08` | max (u64, initialised to 0) |
| `+0x10` | count (u64) |
| `+0x18` | sum (u64) |
| `+0x20` | sum of squares (u64) |
| `+0x28` | buckets `[0..108]` (u64 each) |
| `+0x390` | bucket count (u64, 109) |

`0x28 + 109*8 == 0x390`: the buckets end exactly where the
bucket-count field begins.

## Bucket boundaries (`0x606bf10`, `0x606c140`, `0x606af70`)

The boundaries are not a static table: they are generated once
at static-init time (`0x606c140`, registered in `.init_array` at
`0x63f3978`) into the vector at `0x6505d20` (begin / end /
capacity, plus the last boundary at `+0x18` and the first at
`+0x20`; freed by the dtor `0x606af70` via `__cxa_atexit`).

Seeds `[1, 2]` from `.rodata 0x453950`; then `cur` starts at
`2 * 1.5 = 3.0` and each iteration pushes `(u64)cur`, rounds the
pushed value, and multiplies `cur` by `1.5` until
`cur * 1.5 >= 2**64`. A pushed value above 109 is divided by 10
while the pre-division value exceeds 1099, counting a factor of
10 each time, then multiplied back — i.e. truncated to the top
2–3 digits (`115 -> 110`, `1099 -> 1090`, `1234 -> 1200`).
Result: 109 boundaries, first `1`, last `13000000000000000000`
(the ceiling, also the initial min). `boundaries.tsv` lists all
109; `tools/histogram_stats_115.py:generate_boundaries`
reproduces the generator exactly, including the `2**63`
unsigned-conversion branch.

## Record and merge

- **Bucket index `0x606afa0`**: first index `j` with
  `BOUNDARIES[j] >= value` (`std::lower_bound`); values at or
  above the ceiling go to the last bucket. One direct caller:
  the record routine.
- **Record `0x606b130`** (vtable slot `0x20` via thunk
  `0x606b1c0`): `buckets[index]++`, min/max by comparison,
  count / sum / sum-of-squares by wrapping u64 addition.
- **Shared init `0x606b020`**: min = ceiling, max / count / sum
  / sumSq = 0, buckets zeroed. **Bucket-count init `0x606b080`**
  (re-shipped): count = `(*0x6505d28 - *0x6505d20) / 8`.
  **Locked init `0x606b0c0`** (re-shipped, slot `0x10`): the
  same init under the histogram mutex.
- **Merge entry `0x606be40`** (slot `0x28`): merges only when
  the two histograms share a name — fast path when the other's
  vtable slot `0x38` is `0x606af40`, otherwise each side's
  slot-`0x38` name accessor is called and the results are
  `strcmp`'d against `"HistogramImpl"` (`0x43fa67`); a mismatch
  returns without merging. **Merge wrapper `0x606bdf0`**
  (re-shipped): the merge under the destination mutex.
  **Merge inner `0x606b1d0`**: min / max by `lock cmpxchg`,
  count / sum / sumSq / buckets by `lock add`.
- **Accessors**: name `0x606af40` (slot `0x38`) returns
  `"HistogramImpl"`; min `0x606af50` (slot `0x40`) and max
  `0x606af60` (slot `0x48`) return the fields; empty check
  `0x606b110` (slot `0x18` via thunk `0x606b120`) is
  `count == 0`.

## Percentile, average, stddev

- **Percentile core `0x606b260`**: `threshold = count *
  (pct / 100.0)` (`100.0` at `0x459498`); walk buckets until the
  running total reaches the threshold; then `value = lower +
  ((threshold - prev_cum) / bucket_count) * (upper - lower)`
  with `lower = BOUNDARIES[i-1]` (`0` for `i == 0`) and `upper =
  BOUNDARIES[i]`; an empty bucket returns its lower boundary;
  past the last bucket returns `(double)max`; the result is
  clamped to `[min, max]`. u64-to-double conversions use the
  unsigned fixup (`shr $1` + `or` + `addsd` doubling) wherever a
  value may have the high bit set.
- **Median `0x606b500`** (slot `0x58` via thunk `0x606b520`):
  percentile with `50.0` (`0x459950`). **Percentile thunk
  `0x606b530`** (slot `0x60`): percentile with the caller's
  `xmm0`.
- **Average `0x606b540`** (slot `0x68` via thunk `0x606b5c0`):
  `0.0` when count is 0, else `sum / count`.
- **Stddev `0x606b5d0`** (slot `0x70` via thunk `0x606b6b0`):
  `0.0` when count is 0, else
  `sqrt(max(0, (count*sumSq - sum*sum) / count*count))`.
- **Percentile struct `0x606bce0`** (slot `0x78` via thunk
  `0x606bdd0`, re-shipped): the 9-field struct — P50, P95
  (`95.0` at `0x459640`), P99 (`99.0` at `0x459258`), average,
  stddev, P100 = max, count, sum, min — that
  `StatisticsImpl::ToString` prints.

## The renderer (`0x606b6f0`, entry `0x606bc90`)

`0x606bc90` (vtable slot `0x30`) adds 8 to the histogram
argument and calls the renderer, which builds the full text
form into a fresh string:

1. `Count: %lu Average: %.4f  StdDev: %.2f\n`
2. `Min: %lu  Median: %.4f  Max: %lu\n` — the min/max fields
   when count is non-zero, literal `0`/`0` when empty.
3. `Percentiles: P50: %.2f P75: %.2f P99: %.2f P99.9: %.2f
   P99.99: %.2f\n` — P99.99 from `99.99` (`0x459080`), P99.9
   from `99.9` (`0x459ce8`), P99 from `99.0`, P75 from `75.0`
   (`0x459c50`), P50 from `50.0`.
4. The 55-byte dashes separator.
5. One row per non-empty bucket:
   `%c %7lu, %7lu ] %8lu %7.3f%% %7.3f%% ` — `'['` with lower
   `0` for bucket 0, `'('` with lower `BOUNDARIES[i-1]`
   otherwise; upper `BOUNDARIES[i]`; the bucket count; the
   bucket percent and the cumulative percent (`100.0 / count`
   per unit) — then `'#'` repeated `round(bucket_pct / 5)`
   times, then `'\n'`.

Before each append, `0x3fffffffffffffff - len(out) < len(chunk)`
throws `__throw_length_error("basic_string::append")`
(message at `0x4474d2`). The pad `0x606b6be..0x606b6e6`
disposes the output string and resumes unwinding on exception.

## Routines pinned

| routine | FDE | role |
| --- | --- | --- |
| `0x606af40` | `0x606af40..0x606af4c` | name accessor (slot `0x38`) |
| `0x606af50` | `0x606af50..0x606af59` | min accessor (slot `0x40`) |
| `0x606af60` | `0x606af60..0x606af69` | max accessor (slot `0x48`) |
| `0x606af70` | `0x606af70..0x606af91` | boundaries vector dtor |
| `0x606afa0` | `0x606afa0..0x606b013` | bucket index |
| `0x606b020` | `0x606b020..0x606b07c` | shared init |
| `0x606b080` | `0x606b080..0x606b0a2` | bucket-count init (re-shipped) |
| `0x606b0c0` | `0x606b0c0..0x606b10a` | locked init (re-shipped) |
| `0x606b110` | `0x606b110..0x606b11f` | empty check |
| `0x606b120` | `0x606b120..0x606b12d` | empty thunk (slot `0x18`) |
| `0x606b130` | `0x606b130..0x606b1b3` | record |
| `0x606b1c0` | `0x606b1c0..0x606b1cd` | record thunk (slot `0x20`) |
| `0x606b1d0` | `0x606b1d0..0x606b253` | lock merge inner |
| `0x606b260` | `0x606b260..0x606b4fe` | percentile core |
| `0x606b500` | `0x606b500..0x606b511` | P50 |
| `0x606b520` | `0x606b520..0x606b52d` | median thunk (slot `0x58`) |
| `0x606b530` | `0x606b530..0x606b53d` | percentile thunk (slot `0x60`) |
| `0x606b540` | `0x606b540..0x606b5b9` | average |
| `0x606b5c0` | `0x606b5c0..0x606b5cd` | average thunk (slot `0x68`) |
| `0x606b5d0` | `0x606b5d0..0x606b6ae` | stddev |
| `0x606b6b0` | `0x606b6b0..0x606b6bd` | stddev thunk (slot `0x70`) |
| `0x606b6be` | `0x606b6be..0x606b6e6` | renderer string-dispose pad |
| `0x606b6f0` | `0x606b6f0..0x606bc8d` | full text renderer |
| `0x606bc90` | `0x606bc90..0x606bcd3` | ToString entry (slot `0x30`) |
| `0x606bce0` | `0x606bce0..0x606bdcd` | percentile struct (re-shipped) |
| `0x606bdd0` | `0x606bdd0..0x606bddd` | struct thunk (slot `0x78`, re-shipped) |
| `0x606bdf0` | `0x606bdf0..0x606be3d` | merge wrapper (re-shipped) |
| `0x606be40` | `0x606be40..0x606bed5` | merge entry (slot `0x28`) |
| `0x606bf10` | `0x606bf10..0x606c134` | boundary generator |
| `0x606c140` | `0x606c140..0x606c16b` | boundaries static init |

Census-only (cited by contract, not excerpted): the vector-grow
helper `0x5dde8e0`, the histogram builder `0x6070500` and
`StatisticsImpl::ToString` `0x6070810` (both #3362).

## Evidence format

- `records.json` holds semantic records only — no
  per-instruction mnemonic list. Instruction-level detail lives
  only in the whole-function verbatim excerpts (`.txt`), kept
  exactly as `objdump` emitted them; the mnemonics in the
  excerpts (`endbr64` included) are genuine instructions present
  in the target binary, not placeholders.
- `verify.py` is committed in the packet; it regenerates every
  excerpt from a fresh `objdump` run, checks the raw bytes
  against the binary, re-derives the census, the FDE ranges,
  the relocation set, the literals and the boundary list, and
  runs the model tests.
- `census.py` reproduces `callers.tsv` (63 rows); `frames.txt`
  holds the raw `readelf` FDE lines; `relocations.txt` holds the
  RELATIVE records for the vtable, the typeinfo chain and the
  `.init_array` entry; `boundaries.tsv` lists all 109
  boundaries; `MANIFEST.sha256` covers the packet.

## Model and tests

`tools/histogram_stats_115.py` reimplements the family in
Python (boundary generation, bucket index, record, merge,
percentile / median / average / stddev, the percentile struct,
the full renderer); `tests/test_histogram_stats_115.py` checks
it with 90 hand-computed checks (run directly — pytest is not
installed on this VM). The render test pins the exact output
for values `[1, 2, 6]` and for the empty histogram, including
the `'#'` bars and the literal-`0` Min/Max line.

## Environment limits

This VM has no cargo / rustc, no git-lfs and no Ghidra, so
`make verify` / `make test` / `make catalogue-check` cannot run
here; the packet's own `verify.py` plus the model tests are the
verification performed. The boundary values are a deterministic
consequence of the generator's transcription (seed qwords,
constants and loop structure all read from the binary); they
were not observed from a live run.

## Unknowns

See `records.json` (`unknowns`): vtable slot `0x50`
(`0x5eeb2e0`) is unexamined; the statics `+0x20` first-boundary
slot has no pinned reader yet; the three direct callers of the
ToString entry and the record thunk's callers are cited by FDE
only; the vector-grow helper is generic STL machinery; the
renderer model uses plain string concatenation where the binary
uses the `std::string` SSO / `_M_mutate` paths.
