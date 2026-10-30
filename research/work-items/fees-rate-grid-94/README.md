# fees: the rate grid behind a node #94 fee schedule update

- Component ID: `fees` (first task: maker/taker fee formulas; this packet fixes the integer fee split the node tests a schedule against).
- Target release and full SHA-256: hl-node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` /
  can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23` (used as leads only).
- Claim status: observation for bytes, decoded instructions and evaluated outcomes; inference where marked;
  unresolved items are listed at the end.
- Scope included: the grid point `0x36e2d90` in full, and the leaf path above it: `0x3404030`, `0x343a460`, `0x3b7ef60`,
  `0x3bc9050`, `0x343d230`, with the floors `0x3c05c30` as caller. Scope excluded: the rayon split and join path, the other
  two callers of the point, the fee code that runs at trade time, and any fee charged to a real order.

## Reproduce

```sh
python3 tools/fees_rate_grid.py --out research/work-items/fees-rate-grid-94
python3 -m unittest tests.test_fees_rate_grid
(cd research/work-items/fees-rate-grid-94 && sha256sum -c MANIFEST.sha256)
```

Run from the repository root on Linux x86-64 with Python 3 and no third-party package. The tool checks the input
SHA-256 first and fails on any other file. It starts no external program, so no binutils version can change its
output. Sections and FDEs come from `tools/elf_index.py` and `tools/fde_extents.py`. It does not run the node or
visor: decoded instructions are interpreted in Python. A full run takes about 100 seconds.

## Evidence

All addresses are ELF virtual addresses. Function ranges come from `.eh_frame`, and the decoder must land on each
FDE end (`evidence.json`, `functions`). A byte `0x40` in the node's format text is written `[at]` in this packet.

### The grid

When its eight float floors pass, `0x3c05c30` calls `0x3404030` at `0x3c06001`. That is the only direct call of
`0x3404030` in `.text`.

| Level | Function | What the bytes do |
|---|---|---|
| scale list | `0x3404030`, `0x343a460`, `0x3b7ef60` | go through four f64 from `.rodata`, in order: `1.0`, `0.2`, `6.0`, `0.1` |
| ntli range | `0x3b7f0c3`, `0x3b7f0cc`, `0x3b7f0d5` | build a `RangeInclusive`: start 1, end `0x989680` = 10,000,000, exhausted 0 |
| range driver | `0x3bc9050` | length `end + 1 - start`; `0x3bc9130` takes the `u64::MAX` end |
| leaf | `0x343d230` | calls the point with `start + index` as `rdx`, scale as `xmm0`, stops once the folder holds an item |
| point | `0x36e2d90` | the checks below |

So one floors call tests up to 40,000,000 points and the fee schedule update makes two floors calls, perp and spot. A
full acceptance is up to 80,000,000 points. Running the unpatched bound in this Python evaluator is not practical, so the
evidence is:

- `range_runs`: `0x3bc9050` run with start 9,999,991 and end 10,000,000 makes 10 calls and the last `ntli` is 10,000,000;
  the bound is inclusive.
- `chain.tsv`, `patched_bound=True`: the immediate at `0x3b7f0cc` is patched to a small number in an overlay, and the real
  chain visits every scale in list order and every `ntli` from 1 up, exactly `4 * bound` calls.
- `chain.tsv`, `patched_bound=False`: on the real bound a failing vector stops at the point the model predicts (for example
  scale 1.0, `ntli` 1112).

### The point

Signature as read from the registers: `0x36e2d90(out, folder, ntli: u64, scale: f64)`. `folder + 0x40` holds six pointers.
Names come from the format text and from the floors that fill them (`evidence.json`, `formats`, and `chain.tsv` compares
each value with the floors input).

| Slot | Name here | Filled from |
|---|---|---|
| `+0x00` | `L`, lowest cross rate | floors `+0x48` word times the last cross rate |
| `+0x08` | `r`, referral | floors `+0x28` |
| `+0x10` | `k`, printed as `max_keep` | floors `+0x38` |
| `+0x18` | argument block | only read by the formatter, on a reject |
| `+0x20` | `a`, lowest add rate | the lower of the last add rates, times the `+0x50` word if negative |
| `+0x28` | `c`, first cross rate | first element of the cross list |

`t(x)` below is one repeated instruction shape: a non-finite `x` gives 0, otherwise the value truncates toward zero and
saturates to `i64`.

```text
ntli > i64::MAX               -> panic, unwrap of TryFromIntError, l1/src/qtys/mod.rs:843:1
D  = t((1 - r) * L * scale * ntli)            discounted fee
K  = t(D * k)
K < 0                         -> reject 1, prints args, k, D
A  = t(a * scale * ntli)                      add part, negative for a rebate
N  = D - K + A, each step i64 saturating, reports to l1/src/qtys/impl_ntl.rs:16:1 on overflow
N < 0                         -> reject 3, prints args, ntli, scale
F  = t(scale * c * ntli)                      undiscounted fee
FK = t(F * k)
FK < 0                        -> reject 2, prints args, k, F
S  = FK + max(F, 0) + |A|, u64 saturating, the last add reports to l1/src/qtys/impl_ntl.rs:6:1
S >= ntli                     -> reject 4, prints args, ntli, scale
otherwise pass, the folder comes back unchanged
```

| Reject | Format text | Variant word |
|---|---|---|
| 1 | `invalid fees [at][at] [args: {}] [at] [max_keep: {}] [at] [discounted_fee: {}]` | 0 |
| 2 | `invalid fees [at][at] [args: {}] [at] [max_keep: {}] [at] [max_fee: {}]` | 0 |
| 3 | `invalid fees [at][at] [args: {}] [at] [ntli: {}] [at] [scale: {}]` | 1 |
| 4 | `invalid fee rounding [at][at] [args: {}] [at] [ntli: {}] [at] [scale: {}]` | 1 |

Evaluated order is the order above: 3 comes before 2. The `max_keep` printed is the share `k`, not a computed amount: the
format argument is the pointer at slot `+0x10`. The floors read tag 2 as a pass, and for tags 0 and 1 free the text and return
false, so the text never leaves the node's update path.

On a reject the point then acts as a rayon find folder: an item already held on the leftmost search stays and the new text is
freed; otherwise the best word at `folder + 0x28` is moved to the boundary at `folder + 0x30` by `lock cmpxchg`, with a retry
on a lost race, and the new item replaces the old one, whose text is freed. The vectors cover all three tags, both positions,
three boundary relations and a forced race.

The stake discount is not an input: the grid has no slot for it and the strict memory shows no other read. The floors use
it; the grid does not.

## Implementation and comparison

Implementation: not yet implemented. `tools/fees_rate_grid.py` holds a closed-form model for test use only.

Method: a table decoder (no external program) gives the instructions, and a Python evaluator runs them. Memory is strict:
reading a byte nobody set is a fault. Stubs spoil caller-saved registers. Each format call is checked for text, formatter
functions and the three values; each text block must be freed once with its size.

| Measure | Value |
|---|---|
| point vectors | 2749, 0 mismatches |
| point exits | pass 1049, reject 1 496, reject 2 308, reject 3 543, reject 4 351, panic 2 |
| point instructions executed | 429 of 435 |
| mutants of the point | 58: 46 killed, 12 equivalent |
| chain runs | 6 from `0x3404030`, 6 from the floors, 4 of the range driver |

The six unexecuted instructions are a `ud2` after the panic call and the unwind cleanup. The tool fails on any other.

The evaluator and the model agreed on the first run, which alone proves little, so each conditional jump, conditional move
and `set` was flipped and four constants changed. All 12 survivors are one fact: the clamp before each conversion is dead
code. Without it, `cvttsd2si` gives `i64::MIN` for a value below the range and the following `cmova` gives `i64::MAX` above it,
so ten flips and the changes to both limits alter nothing. Their reasons are in `mutations.tsv`.

`reference-diff.tsv` compares with the reference tree, which has no grid, none of the four texts and no `ntli` loop.

## Results and limitations

Inferences, not observations:

- `D`, `F`, `K`, `FK` and `A` are the integer fee split the node expects at trade time, and the grid proves that split cannot go
  wrong for small notionals. The names in the format text support this; no trade path was compared.
- Given the rest of the admission ladder, a grid reject is rare. Assume finite inputs, `k` and `r` in [0, 1], `L >= 0`,
  `0 <= c <= 0.001`, `|a| <= 0.001`, and the two floors `(1 - k)(1 - r)L + a >= 5e-06`. Then no point rejects: `D`, `F`, `K` and `FK`
  are not negative, so rejects 1 and 2 stay shut. For `N`, write `x = (1 - r)L * scale * ntli` and `y = (1 - k)x`. Then
  `D - K >= D(1 - k) > y - 1`, an integer, so `D - K >= floor(y)`, while for a negative `a`, `|A| <= floor(y)` by the floor (a
  positive `a` only adds). For reject 4,
  `S <= 0.018 * ntli < ntli`. Rounding of doubles does not close the gap, since the floor leaves a margin of `5e-06 * scale * ntli`
  on products of at most `0.006 * ntli`. This is a written argument, not a machine proof. The study below tests it.
- `study` in `evidence.json` runs the closed-form model, which the vectors tie to the bytes, on 1310 rate sets placed on the
  floor edge, 4,487,539 points in the places truncation can bite: all `ntli` to 320, both sides of each multiple of a product,
  and the bound. No point rejected. Its control is the same search with the margin taken away: 149 of 200 rate sets reject, all
  with reject 3, so the search can find such a failure.
- What is left for the grid: a negative word at floors `+0x48`. The admission ladder has an upper limit on that word and no
  lower one, so `L` can go below 0 while cross and add rates all stay in range. With word -0.01, last cross 3e-4, referral 0.04,
  `k` 0.25 and `a` 1e-4, the bytes pass at `ntli` 1,388,888 and reject 1 at 1,388,889 (`ladder_gap`). A one-off run of the unmerged
  evaluator of `fees-schedule-admission-94` accepted that schedule with its grid stub passing, and it is not part of this
  packet's output. With `k` 0 and a negative word no reject 1 fires, and the floors vector `negative_word90_no_keep` passes.

Unresolved or not covered:

- A real grid splits work across threads through `0x38203e0` and `0x382dca0`, and two more callers reach the point from
  `0x383a464` and `0x38c0930`. The worker stub reports 0 threads, so all of that, and the reduce step that picks the left result,
  was not evaluated. The result may differ in which text wins, which nobody outside the update reads; a reject stays a reject.
- The full bound was not run. 40,000,000 points were not evaluated from bytes in one run: the bound is shown by the immediate,
  the inclusive tail and the patched runs together.
- The vectors use illustrative rates, not Hyperliquid's schedule. Non-finite rates are in the point vectors, but the argument
  above excludes them. No differential run against a live node was made, there is no Rust implementation, and node #115 was not
  checked.
- The floors `+0x48` and `+0x50` words come from the fee schedule in the ladder, and their names are still unknown.

Next question: which function computes `D`, `K` and `A` for a real fill, and does it use the same truncation order?
