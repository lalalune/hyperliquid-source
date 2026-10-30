# RE-006: mid-price market order path on node #94

- Component ID: `orderbook` (task RE-006, book transitions)
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (labels used as leads only, nothing copied)
- Claim status: observation for every offset, branch, constant and count below; inference where the section says so; unresolved items are listed at the end
- Scope included and excluded: included are the row producer `0x37052b0`, the two row loops `0x4cdc540` and `0x4cdcd60`, the four order builders `0x4304010`, `0x43043e0`, `0x43047b0` and `0x4304b80`, the best-key reader `0x4a07680` and `round` at `0x565f410`. The tick helper `0x42c7600` runs as real bytes but is not a subject here. Excluded are everything behind the builders (`0x4311140`, `0x4314da0`, stubbed), the post-trade calls `0x4cd84f0`, `0x432a100` and `0x4329870` (stubbed), the third loop `0x26f7280`, and the callers of the loops and of builders 2 and 3.

## Reproduce

Run from the repository root. The tool starts no external program and never runs the binary.
The tool takes about 40 s; `test_static_files_regenerate` runs the same pass without mutations.
Author environment: Python 3.12.3, Linux x86-64. It reads only `artifacts/node/94/hl-node`, and uses the repository's
`tools/elf_index.py` and `tools/fde_extents.py` for section and FDE parsing.

```sh
python3 tools/artifacts.py verify
python3 tools/mid_market_order.py --out work/mid-market-check
diff -r work/mid-market-check research/work-items/RE-006-mid-market-order-94 -x README.md -x MANIFEST.sha256
python3 -m unittest tests.test_mid_market_order
```

Generated files: `functions.tsv`, `copy_differences.tsv`, `callers.tsv`, `order_record.tsv`, `mutations.tsv`,
`evidence.json`. Every number there comes from `struct` reads of the ELF or from the evaluator in the tool.

## Evidence

Coordinates are virtual addresses. Offsets marked `+` are from the named structure's start. Each function in
`functions.tsv` was decoded to its exact FDE end; `executed` there is how many of its instructions ran.

### Call path

```text
0x4d421f0 / 0x4d46130, after 0x4cdd580 / 0x4cde380, when a flag bit is set
  row loop 0x4cdc540 / 0x4cdcd60 (user, f64 fraction)
    producer 0x37052b0, through GOT slot 0x57748c8     rows of (asset, side byte, size), or nothing
    per-asset context 0x4df3680                        0x60-byte rows, u64 at +0x20
    for each row: notional test, then
      order builder 0x4304010 / 0x43043e0              midpoint, factor, tick, fixed record
        insert 0x4311140 / 0x4314da0
      0x4cd84f0 on success, then 0x432a100 / 0x4329870 on every path
builders 0x43047b0 / 0x4304b80 have one direct caller each, 0x4cff140 / 0x4cff8f0
```

### Producer `0x37052b0`

- `rsi` is one clearinghouse row, `rdx` the 20-byte user, `xmm0` the fraction. It looks the user up with `0x36f57f0` at
  row `+0xf8` and walks a B-tree in key order: keys `+0x2c8`, values `+0x00` with stride 0x40, parent `+0x2c0`, parent
  index `+0x320`, length `+0x322`, edges `+0x328`.
- A fraction at or below 0, or at or above 1, returns the none word `0x8000000000000000`. NaN passes both tests and gives
  an empty vector.
- For each entry the i64 at value `+0x10` becomes f64, is multiplied by the fraction and is cast toward zero. Zero
  results are dropped. A positive result writes side byte 1 and a negative one writes side byte 0, with the magnitude
  as the row's size.

### Row loops

Rows are 0x18 bytes: asset `+0x00`, side byte `+0x08`, size `+0x10`. A side byte of 2 ends the walk. The asset splits by
10000 into dex and local index.

1. A local index at or past the context length panics at `l1/src/clearinghouse/oracle/oracle.rs:197:18`.
2. Notional is size times the context `+0x20` value, as a full 64 x 64 product. If it overflows 64 bits or its low word
   exceeds `0x7ffffffffffffffe`, the row goes on. Otherwise a low word at or below `0x98967f` (9,999,999) skips the row:
   10,000,000 acts and 9,999,999 does not.
3. A dex at or past the collection count panics at `l1/src/dex_registry/perp_dex.rs:30:33`, and a local index at or
   past the book count at `l1/src/books.rs:19:47`. A row under the floor reaches neither check.
4. The builder gets the book, user, side byte, size, the outer object and an empty vector.
5. A builder error skips `0x4cd84f0`, and frees the error's buffer only when its capacity word is positive as a signed
   value. So the no-price word `0x800000000000000a` frees nothing.
6. The finishing call runs after success and after failure, with the vector the builder may have filled.

When the list is done the rows' buffer is freed (0x18 bytes each) and `0x4db32e0` runs. When the producer gives none,
the loop returns at once, and neither the context nor the final drop runs.

### Order builders

| Builder | Fields | Factor, side 0 | Factor, side nonzero | Record `+0x70` | Record `+0xcc` | Insert |
| --- | --- | --- | --- | --- | --- | --- |
| `0x4304010` | `+1048` | 1.03 | 0.97 | 6 | 1 | `0x4311140` |
| `0x43043e0` | `+5c8` | 1.03 | 0.97 | 6 | 1 | `0x4314da0` |
| `0x43047b0` | `+5c8` | 1.2 | 0.8 | 1 | 4 | `0x4314da0` |
| `0x4304b80` | `+1048` | 1.2 | 0.8 | 1 | 4 | `0x4311140` |

Each factor is read from `.rodata` (`evidence.json`, with bits). `copy_differences.tsv` lists every row where two copies
differ after branch targets are made relative and rip operands absolute. Nothing else differs.

1. Asset is book `+0xb0`. A dex at or past the market count panics at `l1/src/dex_registry/clearinghouses.rs:11:29`.
2. `0x4a07680` reads the first key of the trees at book `+0x80` and `+0x98` and returns each through its absolute value,
   or 0 when the root is null or the length is 0. So a key's sign plays no part, and no value above 2^63 can arrive.
3. If either value is 0 the builder writes `0x8000000000000000`, `0x800000000000000a` to its result and calls nothing.
4. The midpoint is `(a & b) + ((a ^ b) >> 1)`, the floor of the mean with no overflow.
5. The price is the midpoint as f64, times the factor, rounded half away from zero by `0x565f410`, then cast to u64.
6. `0x42c7600` gives the tick. With `q = price / tick`, side 0 uses `q * tick`, and any other side byte uses
   `(q + 1) * tick`. **A sell adds a whole tick even when the price is already a multiple**: midpoint 2500000 at 0.97 is
   exactly 2425000 with tick 100, and the limit is 2425100. `evidence.json` holds more examples. At midpoint 1 a side 1
   limit is 2, above the midpoint.
7. The block time at outer `+0x60` (year and ordinal word, seconds, nanoseconds) becomes milliseconds, clamped at 0.
8. The record is written as in `order_record.tsv` and passed in `rdx`, with `ecx` 0, the outer object in `r9` and the
   vector on the stack. `r8` is not set, which fits an `Option` tagged by `ecx`.

Only the low byte of the side argument is read. Panics inside the tick helper come from `l1/src/perp_meta.rs:194:38`
(dex or local index) and `l1/src/perp_meta.rs:319:28` (decimals of 7 or more).

### Inferences

- Value `+0x10` is the signed position size, and the producer's map is the user's positions by asset. The size's sign
  chooses the side and its magnitude becomes the order size.
- So side 1 is a sell that reduces a long, and side 0 a buy that reduces a short. That fits the factors: 0.97 is below
  the midpoint, 1.03 above. It also fits the reference's `Side` order, and it means this path closes a fraction of every
  position.
- 9,999,999 is one below 10 USD at six decimals, so rows under 10 USD of notional are left open. The context `+0x20` value
  is an oracle price, from the panic Location. The bytes show only a u64.
- Record `+0xcc` is the time in force. The reference's `InsertTif::from_raw` names 1 `ImmediateOrCancel` and 4
  `LiquidationMarket`, and `0x4311376` loads the byte into the insert frame. This packet does not follow it further.
  That reading pairs the wider 1.2 and 0.8 factors with liquidation orders.
- The fraction and flag at `0x4d42959` and `0x4d429b6` come from a result returned through slot `0x5774b50`. What the
  caller is, was not established.

## Implementation and comparison

Rust implementation: not yet implemented.

The comparison here is the original bytes against a specification written from the claim above. `spec_builder()`
predicts the whole record byte for byte, including bytes left unwritten, the error drop and any panic with its Location.
`spec_loop()` predicts the ordered list of calls with their arguments. `spec_positions()` predicts the rows, and
`spec_round()` the exact bits of the result. Copies are compared with the same specification, with only the table row changed.

Real bytes run for the builders, the loops, the producer, `0x4a07680`, `0x565f410` and `0x42c7600`. Stubs replace the
insert monomorphs, the error drop `0x3379490`, context `0x4df3680`, record `0x3987cb0`, `0x4cd84f0`, the map iterator
`0x4948400`, the finishing calls, `0x4db32e0`, user lookup `0x36f57f0`, vector growth, free, the `Once` call and the
panic entries. Stubs poison volatile registers and all xmm registers, and callee-saved registers are checked on exit. Trees are real
memory, with heights to 17 on the leftmost path and stale keys beyond each node's length.

Controls: every condition was inverted and bit 0 of every immediate flipped, one at a time, in builder 0, `0x4a07680`,
`0x565f410`, loop 0 and the producer, on copy 0. A mutant that spins stops at a step limit and counts as detected.
Separate tests change a factor constant, the side branch, the floor and its branch, the expected factors, insert target
and record constants, corrupt the digest, and pass a NOBITS address. The other copies have no mutation pass;
`copy_differences.tsv` ties them to copy 0.

The reference file `l1/books.rs` differs from the bytes as follows:

| Point | Reference lead | Bytes |
| --- | --- | --- |
| `0x4CDCD60`/`0x4CDC540` | `sweep_large_matches`: candidates with their own price, opposite side, `remove_liquidity` | rows come from a position map, the price from a context table, the side is not inverted here, and an order record goes to the insert path |
| Removal | takes resting size off the top of the book | no removal in these functions; matching is the insert path's work |
| Threshold type | `u128` product compared to `0x98967f` | low 64 bits compared, with overflow and values above `0x7ffffffffffffffe` taken as large |
| Midpoint | `(bid & ask) + ((bid ^ ask) >> 1)` | the same, confirmed |

## Results and limitations

| Metric | Value |
| --- | --- |
| Builder cases per copy | 1075, 4 copies |
| Loop cases per copy | 82, 2 copies |
| Producer cases | 57 |
| Direct `round` values | 112 |
| Mismatches, all copies | 0 |
| Builder outcomes | insert 4196, no price 40, panic 64 |
| Instructions stepped | 1,357,907 |
| Mutants killed / survived / unreached | 209 / 25 / 13 |

All 25 survivors are explained row by row in `mutations.tsv`. They are not sampling gaps: the first pass had real gaps
(drop word, panic message length, empty vector words, `round` seen only through a cast), and those are now checked.
The survivors are ranges the path cannot reach, for example the year 0 arm, whose times all clamp to 0, or stores read only on unwind.
`0x565f43e` is the one flip with no effect on any value. The 13 unreached rows are unwind cleanup, plus one repeated
market count check that cannot fail after the entry check.

No progress gate is requested. Limits:

- Stubs are contracts. Whether the insert path fills, rests or rejects these records is not shown here, and #47 and the
  match packet cover that ground. The meaning of record `+0x70`, `+0x10`, `+0x90` and `+0xa8` is unresolved.
- Bytes `+0x18` to `+0x1f`, `+0x28` to `+0x2f`, `+0x50` to `+0x6f`, `+0x78` to `+0x7f`, `+0x92` to `+0xa1`, `+0xa3` to
  `+0xa7`, `+0xb0` to `+0xb7` and from `+0xcd` on are not written by the builder. `order_record.tsv` lists only what is
  written, and the comparison requires the rest to stay untouched. `0x43112fa` onward does read `+0x78` and `+0xb0`, which
  fits payloads behind the tags at `+0x70` and `+0xa8`, but this packet does not follow them.
- The time arm for year 0 and earlier cannot show its arithmetic, because every result clamps to 0.
- Saturating arms (limit above u64, cast above i64) are unreachable from these callers, so they ran only under mutation.
- The third caller of the producer, `0x26f7280`, is not stepped. By hand reading it has the same head and floor as the
  loops but inlines its book work, with a call to `0x27ae040` for the context.
- Callers came from `E8`/`E9` and `FF 15` byte patterns. A pointer built at run time would not appear.

Next question: what calls `0x4cff140` and its sibling `0x4cff8f0`? By hand reading, `0x4cff140` gates on notional at 10^10
or 10^11 by the byte at outer `+0x8f2`, multiplies a signed size by 0.2 (`0x20a768`) and reaches builder 2.
