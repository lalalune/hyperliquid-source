# RE-006: block step cancel_aggressive_orders_at_oi_cap: at-cap test, reference price, 1% sweep, reason 8

- Component ID: RE-006 (book state transitions), one cancel path from the block step to the book
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included with mutants are the sweep `0x26e48c0` (copies `0x4305490`, `0x43060a0`), the step `0x2228130` (copies `0x47180e0`, `0x470d770`) from entry to its timing tail at `+0x408`, and the at-cap test `0x3713f20`. Real bytes without mutants: the order collector `0x27e6fe0` (copy `0x4450680`) with its iterators and bulk build, and the time helpers `0x15206e0`, `0x151f870`. Stubbed at the edge, with arguments compared: order cancel `0x26de150` family, book accessor `0x2755c70` family, flush `0x24fb610` family, sum fold `0x3be6660`, list growth, allocator, sort and panic calls. Excluded: the bodies of those stubs, the timing tail of the step, and the other hosts of `0x3713f20`.

## Reproduce

From the repository root:

```
python3 tools/oi_cap_aggressive_sweep.py --out research/work-items/RE-006-oi-cap-aggressive-cancel-94
python3 -m unittest tests.test_oi_cap_aggressive_sweep
```

The tool takes about 40 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `call_sites.tsv`, `cases.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs (`functions` in `evidence.json`).

### The step and its name

Each of the three callers `0x22297c0`, `0x47162d0`, `0x470e9a0` builds an argument block just before the call (`step_sites`):

| Offset | Value |
| --- | --- |
| `+0x00/+0x08` | pointer and length `0x22` of the text `cancel_aggressive_orders_at_oi_cap` (`0x3efab7`, and `0x714eb8` for the other two) |
| `+0x10/+0x18` | doubles `0.01`, `0.05`, used only in the timing tail |
| `+0x20` | byte: new bucket above the stored bucket |

The bucket is block time in ms divided by state `+0x38b0` (`+0x4330` in the second copy). The stored bucket at `+0x38b8` (`+0x4338`) is raised at the same place. The step does nothing unless the byte is exactly 1.

### Which assets

The step walks the dex row list (state `+0x5c0`, `+0x1040` in the second copy, stride `0x2f0`). For each index below row `+0x10`, the asset id is `10000 * row[+0x30] + index`, with checked multiply and add. It calls `0x3713f20` through slot `0x5773a48` and keeps the ids that return true. Only after that walk does it touch any book.

`0x3713f20(dex row, asset)`:

```
if row[+0x230] == 3: return asset in the set at row[+0x1e8]
cap = map at row[+0x208] -> +0x30, lookup asset
if cap present:
    price = asset row (asset % 10000)[+0x20], bound at l1/src/clearinghouse/oracle/oracle.rs:197:18
    size = map at row[+0x170], lookup asset, or 0
    if price < 0 as i64, or price * size overflows i64: return true
    if cap < 0 as i64: panic at l1/src/qtys/mod.rs:843:1
    if price * size > floor(cap as f64 * 0.9): return true
sum = fold 0x3be6660 over row
if sum is none: return true
if row[+0x1b0] < 0 as i64: panic at l1/src/qtys/mod.rs:843:1
return sum > floor(row[+0x1b0] as f64 * 0.9)
```

So a dex in mode 3 uses a stored set of assets and reads no price at all. A false result needs both tests to pass.

### Which price

For each kept id, `id / 10000` indexes the same list (panic at `l1/src/dex_registry/clearinghouses.rs:11:29` when past its end) and `id % 10000` picks an asset row of stride `0x60`, bound at `l1/src/clearinghouse/oracle/oracle.rs:202:18`.

- Mode 3: the price is row `+0x00`.
- Otherwise: the stored time at `+0x50` (date, seconds, nanoseconds) plus 1800 s is compared with block time. Block time at or before that limit takes row `+0x40`. Later takes row `+0x00`. The equal case takes `+0x40`, one nanosecond past takes `+0x00`.

The time arithmetic is the real `0x15206e0` and `0x151f870`, including the day wrap.

The step then calls the sweep with the book, that price, and two context arguments, and then the flush `0x24fb610` family with the same vector.

### The sweep

`0x26e48c0(book, reference, a, b)` walks the user tree at book `+0xb8`, count at `+0xc8`. Each value holds a set of slab indexes at `+0x20` and a second tree at `+0x38`. For one user:

1. The collector chains the two: a slab index gives slot `+0xd8` when it is in bounds and the slot is not vacant, and a second tree key stands for itself. It sorts, removes duplicates and builds a set.
2. For each order id, ascending: look it up in the hash at book `+0x28`. A missing key, an index past book `+0x10`, or a slot with state 2 is skipped.
3. `value = (slot[+0xa0] as f64) / (reference as f64) + (-1.0)`. When byte slot `+0xc2` is not 0, the value is negated.
4. `value > 0.01` keeps `(order id, user)` in a local list of `0x20` byte rows.

Only after every user is walked, each kept row goes to `0x26de150(book, user, order id, a, b, 8)`. A case clears the slab inside the first cancel, and the later rows still run with their ids.

The test is in `f64`, so it is not an integer percent:

- Exact 1% over or under cancels: `101/100` and `99/100` both give `0.010000000000000009` (`worked_boundaries`).
- One unit under, as `1009999 / 1000000`, does not.
- Reference 0: side 0 with a nonzero price gives `+inf` and cancels, side nonzero gives `-inf` and stays. Price 0 gives NaN and stays on both sides.

### Reason 8

Jump table `0x7038dc` in the status writer `0x4a9a1a0` gives value 8 the name `openInterestCapCanceled` (`status_names`). `fields` in `evidence.json` lists every offset above.

## Inferences

- Value 8 passed to the cancel is that status. The bytes show the argument and the table, not the path between them.
- Side byte 0 is a bid. With that, the sweep cancels bids more than 1% above the reference and asks more than 1% below it, which fits the word `aggressive` in the step name.
- The map at row `+0x170` is open interest by asset, so the test reads as notional above 90% of a cap. The file `qtys/mod.rs:843` panic only says the cap must not be negative.
- The mode 3 set could be the one set by the vote the reference labels `AssetsAtOpenInterestCap`. No writer of `+0x1e8` was read.
- Row `+0x00` and `+0x40` are both prices from the oracle row (Location file). Which source each one is, is unresolved.
- The period at state `+0x38b0`: its value and writer are unresolved.

## Implementation and comparison

Not yet implemented in Rust. The comparison here is byte evaluator against a written specification, written from a full instruction read and kept apart from the evaluator.

The reference has no step of this name and no sweep by distance from a price (`reference_claims`). Its `collect_perps_at_open_interest_cap` walks a size map, and has a different shape from `0x2228130`.

The first run over all cases had 7 mismatches, none in the rules: 6 were panic Location words that differ per copy, and 1 was my own unsigned read of `imul` in the specification. The first mutation pass then showed harness gaps, closed with more cases: small order ids hid the low bits of the hash constant, filler keys hid node length mutants, and a vacant slot was filtered before the sweep saw it.

Mutants flip each branch, `set`, `cmov`, immediate and field offset, one at a time, over the cases that reach them. They run on the first copy of the sweep and the step, and on the at-cap test. The other two copies run every case with no mutants.

| Metric | Value |
| --- | --- |
| Cases | 456 |
| Mismatches | 0 |
| Instructions stepped | 392,525 |
| Stepped / total: sweep, first copy | 387 / 665 |
| Stepped / total: step up to its timing tail, first copy | 212 / 215 |
| Stepped / total: at-cap test | 194 / 206 |
| Mutants killed / survived / unreached | 278 / 36 / 126 |

## Results and limitations

- The sweep result is exact only for the stubbed edges. What the cancel does with reason 8 is in other packets and is not re-run here.
- The step ends at its second clock read. The tail only reports timing. It takes a lock and the evaluator does not model that, so it is not run.
- The 126 unreached and 36 surviving rows each have a reason in `mutations.tsv`.
- Same address rows, stated for the reviewer. `0x4305490` and `0x43060a0` appear in #108 and #161 as call sites of the cancel family. `0x2228130`, `0x47180e0`, `0x470d770` appear in the #131 and #184 inventories, `0x3713f20` and `0x3be6660` in #184, the accessor copies in #131, and `0x26de150` family, `0x24fb610` and `0x286b520` in packets that stub or run them for other questions. None of them states this rule. `0x26e48c0` has no row in any PR.
- The three step copies load slot `0x5773a48` into `rbp` before the walk. `call_sites.tsv` lists six other direct slot calls of `0x3713f20`. Those hosts are not read.
- Each mutant runs over the cases that reach it, leaving out cases above 3000 steps unless nothing smaller reaches the row. So a surviving row may fall to a large tree. Survivor reasons are by class, not one by one.
- No progress gate is requested.

Next question: what do the other hosts of `0x3713f20` do with a true result, and who writes the mode 3 set at dex row `+0x1e8`?
