# RE-008: node #115 shared value observer `0x1547530` (20th stage): where the day totals go, and the first sampler's collect

- Component ID: abci. Question: the 19th stage (open PR #5940) found that observer `+0x200` sums the count argument and `+0x208` counts record calls for the current UTC day (`+0x240`). It left open what reads `+0x200` at `0x1547f78`, the readers of `+0x208`, `+0x210` and `+0x218`, and the two other callers of the B-tree iterator `0x51360a0`.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5854 and #5940. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, strings and call censuses are observations. "Day", "sum", "mean", "count", "collect" and "freed unread" are inferred labels from the arithmetic and data flow. The binary was not executed.
- Scope included: the day-field updates and the window-record use of them in `0x1547530`; the two record copies; the two serializer field names; the second collect `0x5b70cf0` and its two call sites. Scope excluded: the range check between the `+0x210` add and its store, the rest of the window record, the body of `0x51360a0`, and the minute arithmetic after the first sampler's collect. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/observer_day_totals_115.py --check
python3 -m unittest tests.test_observer_day_totals_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: the three day fields

- Reset: `0x1547562` compares `+0x240` with the wall-clock date; on a change `0x154756d` zeroes `+0x200` and `+0x208` (16 bytes) and `0x1547574` zeroes `+0x210`.
- `+0x200`: `0x154770d..0x1547729` adds the count argument `r14` (multiplied by 50 when `+0x25c` is 1, `0x15475b1`) and saturates at `u64::MAX`.
- `+0x208`: `0x1547730..0x154773e` adds 1 and saturates. The record entry has no other `[rbx+0x208]` operand.
- `+0x210`: an f64. The count is converted to f64 and multiplied by the value argument (`mulsd` at `0x15475fd`); the product is added to `+0x210` (`0x1547658`, `0x1547660`) and the result stored at `0x1547758`. The branchy range check between the add and the store is not mapped here.
- `+0x218`: the record entry has no `[rbx+0x218]` operand.

## Evidence 2: the window record uses the day sum and count

Once the window holds at least 10 samples (`0x1547f4b`):

1. `0x1547f55` loads `+0x210`; `0x1547f72` skips the record when it is not finite.
2. `0x1547f78` loads `+0x200`.
3. A sum between `-1e-15` (`0x458fa0`) and 0 becomes 0 (`0x1547f93`). A count of 0, or a sum still below 0, skips the record (`0x1547fb0`).
4. `0x1547fdd` divides the sum by the count converted to f64; `0x1547ff6` skips the record when the quotient is not finite.
5. The count goes to `rsp+0x1c8` and the quotient to `rsp+0x58`, then to `rsp+0x128` and `rsp+0x130` (`0x15487d8..0x15487ee`).

The record passed to the line writer `0x14c3370` is `rsp+0xd8` (`0x15489b0`, as in #5854). So the count is record `+0x50` and the quotient is record `+0x58`. The serializer `0x1548f40` writes `+0x50` under `total_n` (`0x466de5`, 7 bytes, u64 helper `0x159b710`) and `+0x58` under `total_mean` (`0x466dec`, 10 bytes, f64 helper `0x159c0f0`).

Inference: `total_n` is the day's count total and `total_mean` is the day's value-weighted mean, the sum of count times value divided by the summed count.

## Evidence 3: the first sampler's collect is also freed unread

The four direct callers of `0x51360a0` are in two functions: `0x5b926e0` (#5940) and `0x5b70cf0`. `0x5b70cf0` has the same shape: tag 2 at `[rsi]` walks two runs of 0x20-byte elements, any other tag calls `0x51360a0`; minimum capacity 4; growth through `0x5963a10` with element size 8, align 8.

Its only direct callers are `0x5b29cba` and `0x5b29e02`, both in the first block-step sampler `0x5b298d0` (#5931). After each call the sampler reads the result's capacity (`[rsp+0x8]`) and pointer (`[rsp+0x10]`), frees `capacity * 8` bytes (`0x5b29cd4`, `0x5b29e1c`), and does not read the vector. This mirrors #5940's finding for the second sampler.

## Implementation and comparison

The tool pins 54 instruction byte runs, 10 call targets, three RIP-relative references, two field names and the `-1e-15` constant, and recomputes the iterator and collect caller censuses and the `[rbx+disp32]` operand sites for `+0x200..+0x218` in the record entry. Tests mutate one byte at a time in a copy of the image and expect rejection (9 mutation tests).

## Results and limitations

- Result: the observer's day totals feed the `total_n` and `total_mean` fields of each JSON line. `+0x208` (the day's record-call count) is never read in the record entry. Both samplers build and immediately free their collected vectors.
- Limits: the operand census matches `[rbx+disp32]` only; reads through another base register or a copied observer are not covered. The f64 range check before the `+0x210` store, the minute arithmetic after the first sampler's collect, and whether anything outside the record entry reads `+0x208` are not mapped.
- Next lead: find any reader of observer `+0x208` outside the record entry, and map the range check `0x1547601..0x1547754`.
