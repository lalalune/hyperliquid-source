# RE-014: mid-price market order builders on node #115

This packet lets the mid-price market order builder be reconstructed for node #115. It covers six builder copies, two tick helpers and `round`, from the best bid/ask pair to the exact 0xe0-byte order record handed to insert, every panic included. The reconstruction is an executable pure-Python function. It matches the original bytes on 6,810 builder runs, 896 direct tick runs and 112 `round` values. Twelve deliberately wrong reconstructions are each caught.

The merged node #94 packet `RE-006-mid-market-order-94` was removed in the #115-only migration (`8fd8db680`). Here its builder claim is re-derived on #115 bytes. No #94 address is reused: every #115 address below was found by the tool from the factor constants. The differences between the two releases are listed under Evidence.

- Component ID: `orderbook` (task RE-014, migration validation; the builders belong to RE-006 book transitions)
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: `05bc2de303c05525b71e7e257426e741bc66a390`. The historical #94 claim comes from `8fd8db680^:research/work-items/RE-006-mid-market-order-94/README.md`, release #94 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, and is used as a lead only.
- Claim status:
  - Observation: every address, offset, constant, branch and count below.
  - Inference: only where a paragraph says so.
  - Unresolved: the items listed at the end.
- Scope:
  - Included:
    - builders `0x58f4c70`, `0x58f5060`, `0x58f5450`, `0x58f5840`, `0x23e3b40`, `0x23e3f40`;
    - tick helpers `0x5a01110` and `0x2891f50`;
    - `round` at `0x63efe40`, reached through slot `0x64e1890`.
  - Excluded:
    - the best-pair readers `0x50eaf10` and `0x22f6370` (a contract stub returns the pair);
    - the insert monomorphs `0x5901dd0`, `0x5909b30` and `0x23ebea0` (stubbed, record captured);
    - the error drop `0x44e0810` (stubbed, word captured);
    - the callers of the builders and the row loops that feed them.

## Reproduce

Run from the repository root. The tool starts no external program and never runs the binary. It reads only
`artifacts/node/115/hl-node`, checks its SHA-256 first, and uses `tools/elf_index.py` and `tools/fde_extents.py` for
section and FDE parsing. Author environment: Python 3.12.3, Linux x86-64. A full run takes about 30 s.

```sh
python3 tools/artifacts.py verify
python3 tools/mid_market_order_builder_115.py --out work/mid-market-builder-check
diff -r work/mid-market-builder-check research/work-items/RE-014-mid-market-order-builder-115 -x README.md -x MANIFEST.sha256
python3 -m unittest tests.test_mid_market_order_builder_115
```

Generated files:
- `functions.tsv`, `copy_differences.tsv`, `callers.tsv`, `factor_loads.tsv`;
- `order_record.tsv`, `builder_cases.tsv`, `tick_cases.tsv`;
- `negative_controls.tsv`, `mutations.tsv`, `evidence.json`.

Every number in them comes from `struct` reads of the ELF or from the evaluator in the tool.

## Evidence

Coordinates are virtual addresses. Offsets marked `+` are from the named structure's start.

### Finding the builders on #115

`factor_loads.tsv` lists every function that loads one of the four factor doubles with `movsd`/`mulsd [rip]`:
- 1.03 at `0x4592c0`;
- 0.97 at `0x459790`;
- 1.2 at `0x4592c8`;
- 0.8 at `0x459bf0`.

Six functions load both doubles of a pair and are each about 0x3f0 bytes long: these are the builders. The other pair users (`0x2dd34f0`, `0x5a305e0` family) are much larger and are not builders. `callers.tsv` gives one direct caller per builder, plus every direct caller of both tick helpers.

| Builder | Factors (side 0 / nonzero) | Record `+0x48` | Record `+0xdc` | Market fields (list, count) | Best pair | Tick | Insert |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `0x58f4c70` | 1.03 / 0.97 | 6 | 1 | `+0x7c8`, `+0x7d0` | `0x50eaf10` | `0x5a01110` | `0x5901dd0` |
| `0x58f5060` | 1.03 / 0.97 | 6 | 1 | `+0x1338`, `+0x1340` | `0x50eaf10` | `0x5a01110` | `0x5909b30` |
| `0x58f5450` | 1.2 / 0.8 | 1 | 4 | `+0x7c8`, `+0x7d0` | `0x50eaf10` | `0x5a01110` | `0x5901dd0` |
| `0x58f5840` | 1.2 / 0.8 | 1 | 4 | `+0x1338`, `+0x1340` | `0x50eaf10` | `0x5a01110` | `0x5909b30` |
| `0x23e3b40` | 1.03 / 0.97 | 6 | 1 | `+0x7c8`, `+0x7d0` | `0x22f6370` | `0x2891f50` | `0x23ebea0` |
| `0x23e3f40` | 1.2 / 0.8 | 1 | 4 | `+0x7c8`, `+0x7d0` | `0x22f6370` | `0x2891f50` | `0x23ebea0` |

`builder_pins()` checks each row of this table against the decoded bytes: both factor loads, the first four direct callees, the single slot call, and the immediates written to `rsp+0x78`, `rsp+0x10c` and `rsp+0x110`. `copy_differences.tsv` lists every row where copies differ after in-function branch targets are made relative. Builders 1 to 3 differ from builder 0 only in those fields. Builder 5 differs from builder 4 only in the factors and the two record constants. The two tick helpers have the same size (507 bytes) and both run every direct tick case with the same results.

### Builder rule (arguments: `rdi` out, `rsi` book, `rdx` user, `ecx` side, `r8` size, `r9` outer, stack vector)

1. **Market lookup.** `dex = book[+0x110] / 10000` (multiply by `0x346dc5d63886594b`, shift 75). If `dex >=` the market count, `0x64df6a0` panics with error word `0x156`, message length `0x2b` and Location `l1/src/dex_registry/clearinghouses.rs:11:29`. The market row is `markets + dex * 0x510`.
2. **Error drop.** `0x44e0810` drops a stack value tagged `0x156`. This happens on every path past step 1.
3. **Best pair.** The reader is called with `book + 0xa8` and writes the pair `(a, b)` to `rsp+0x110`. If either is 0, the result is `0x8000000000000000`, `0x800000000000000a` and nothing else is called.
4. **Midpoint.** `mid = (a & b) + ((a ^ b) >> 1)`, the floor of the mean with no overflow, over full u64 values.
5. **Price.** `mid` becomes f64 (exact u64 conversion), is multiplied by the factor and rounded half away from zero by `round` (`0x63efe40`), then:
   - clamped at 0 by `maxsd` (NaN also goes to 0);
   - `+inf` maps to 0;
   - anything above `2^64` maps to `2^64`;
   - cast with the u64 saturating idiom (`0x459360` = 2^63, `0x458d58` = the largest double below 2^64);
   - finally raised to 1.
6. **Tick** (`0x5a01110` or `0x2891f50`, arguments: market row, asset, price):
   - Base tick is `10^max(digits(price) - 5, 0)`, from a compare ladder with shifted compares from 10^10 up; a price of 10^19 or more gets 10^15.
   - If `asset / 10000 != row[+0x50]` or `asset % 10000 >= row[+0x10]`, it panics through `0x64df830` at `l1/src/perp_meta.rs:163:38`.
   - Decimals is the byte at `row[+0x08] + local * 0x20 + 0x1d`. A value of 7 or more panics through `0x64df848` at `l1/src/perp_meta.rs:287:28`.
   - Result: `min(base, 10^(6 - decimals))`.
7. **Limit.** `q = price / tick`. Side byte 0 keeps `q`. Any other side byte uses `q + 1`, saturating at `u64::MAX`. `q * tick` saturates on overflow, and the limit is raised to 1. **A sell adds a whole tick even when the price is already a multiple**: midpoint 2,500,000 at 0.97 is exactly 2,425,000 with tick 100, and the limit is 2,425,100.
8. **Time.** The block time at outer `+0x60` (packed year/ordinal word, seconds, nanoseconds) becomes milliseconds since 1970, clamped at 0.
9. **Insert call.** The record at `rsp+0x30` (`order_record.tsv`) goes to insert with `ecx` 0, `r9` the outer object, and the caller's vector as the stack argument. Only the low byte of the side argument is read.

### Differences from the #94 claim

| Point | #94 (`RE-006-mid-market-order-94`) | #115 (this packet) |
| --- | --- | --- |
| Best pair | real tree reader `0x4a07680` returns each first key through its absolute value | separate readers `0x50eaf10` and `0x22f6370` take `book + 0xa8` and return the pair; the builder uses full u64 values, so `mid` can reach `u64::MAX` |
| Asset | book `+0xb0` | book `+0x110` |
| Market row | stride 0x2f0, assets `+0x08`/`+0x10`, dex `+0x30`, asset row 0x30 with decimals `+0x2a` | stride 0x510, dex `+0x50`, asset row 0x20 with decimals `+0x1d` |
| Field sets | `+0x1048` / `+0x5c8`, 0xa80 apart | `+0x7c8` / `+0x1338`, 0xb70 apart |
| Copies | 4 builders | 6 builders: a third pair with its own tick helper and insert |
| Error word | `0x141` | `0x156` |
| Record | 0xd0 bytes, limit `+0x80`, time `+0x88`, side `+0xa2`, user `+0xb8`, tif byte `+0xcc`, kind `+0x70` | 0xe0 bytes, limit `+0x90`, time `+0x98`, side `+0xb2`, user `+0xc8`, byte `+0xdc`, kind `+0x48`, plus `+0x58` = `0x8000000000000000` |
| Price, tick, sell rule, time | factors, rounding, tick ladder and cap, whole-tick sell | **the same rule holds**, confirmed by the same reconstruction on #115 bytes |

### Inferences

- Factors 1.03/0.97 move the price 3% against the taker. Side byte 0 is a buy and a nonzero side byte is a sell, as in the #94 reading; the bytes show only the byte test.
- Record `+0xdc` is the time-in-force byte, by the #94 reading of the same constants 1 and 4 (`ImmediateOrCancel`, `LiquidationMarket` in the reference's `InsertTif`). This packet does not follow the insert path to confirm it.
- The two field sets (`+0x7c8` and `+0x1338`) are two copies of the clearinghouse state inside one outer object, as in #94.

## Implementation and comparison

Rust implementation: not yet implemented. The reconstruction is the Python functions `spec_builder`, `spec_limit`, `spec_price`, `spec_tick`, `spec_millis` and `spec_round` in `tools/mid_market_order_builder_115.py`. They are written from the rule above and do not read the evaluator.

**Comparison.** The original bytes of all six builders, both tick helpers and `round` run in the tool's x86-64 evaluator.
- The edges are stubs: best pair, error drop, insert, and the three panic slots. Each checks its arguments.
- Stubs poison every volatile register and all xmm registers. Callee-saved registers and stack balance are checked on return.
- Unwritten record bytes must keep the stack fill byte `0xa5`.
- For each case the evaluator's result must equal the reconstruction exactly: the whole record byte for byte, the drop words, the no-price words, or the panic kind with its Location.

**Cases** (`builder_cases.tsv`):
- empty sides; extreme keys up to `u64::MAX`;
- high side bits, side bytes 2 and 0xff;
- every market, dex and decimals panic, and the order of two panics;
- every power of ten ±1 and every power of two from 2^31;
- targets that land on each tick rung from both sides with both factor pairs;
- every decimals value;
- years 0, -1, -400, 1970, the century rules and a late year;
- 160 generated cases.

`tick_cases.tsv` runs both tick helpers directly on every rung ±1 for decimals 0..6, and on every panic arm, including local index 0 on dex 1 and 3.

**Negative controls** (`negative_controls.tsv`). Twelve wrong reconstructions run against the same machine results, and each must mismatch at least one case:
- factors swapped; whole side word;
- sell rounds up only off-tick; half-to-even rounding;
- decimals checked first; time ignores nanoseconds;
- tick ladder one digit early; cap 10^(7-d);
- wrapping mean; time not clamped;
- kinds swapped; one empty side still prices.

**Mutation controls** (`mutations.tsv`). Every conditional jump, `setcc` and `cmov` is inverted and bit 0 of every immediate is flipped, one at a time, in builder 0, tick helper 0 and `round`. The other five builders are tied to builder 0 by `copy_differences.tsv`. A mutant that spins stops at a step limit and counts as detected.

The unit tests also cover:
- a corrupted digest, a NOBITS address and a non-FDE start;
- a corrupted factor byte (the pins must fail);
- a flipped side branch;
- byte-identical regeneration of the static files;
- the MANIFEST.

## Results and limitations

| Metric | Value |
| --- | --- |
| Builder cases | 1,135 per copy, 6 copies, 6,810 runs |
| Builder outcomes | insert 6,726; no price 36; unwrap panic 12; market-row panic 24; decimals panic 12 |
| Tick runs | 896 (448 per helper): 880 values, 16 panics |
| `round` values | 112 |
| Mismatches, all runs | 0 |
| Negative controls caught | 12 of 12 |
| Mutants killed / survived / unreached | 110 / 41 / 0 |
| Instructions stepped (comparison pass) | 1,892,784 |
| Builder instructions executed | 209 of 216 (copies 0-3), 211 of 218 (copies 4-5); the 7 left are the `ud2` after the unwrap call, the unwind cleanup and the abort call |

Every survivor has a reason in `mutations.tsv`:
- 29 are tick-ladder rungs at or above 10^11. They always meet the cap `10^(6 - decimals) <= 10^6` in the `min`, so they cannot change the tick.
- The rest are equivalent arms:
  - the year 0 and earlier arm, whose times all clamp to 0;
  - two raise-to-1 clamps that never act;
  - the saturation word;
  - the sign-mask shift on prices of at least 2^63;
  - the year sign bit;
  - a decimals compare that decimals 3 never reaches;
  - one `round` exponent mask.

An earlier pass left the divide-by-10000 magic alive. The cases now include local index 0 on dex 1 and 3, which kill it.

No progress gate is requested. Limits:

- Stubs are contracts. Whether insert fills, rests or rejects these records is not shown. The best-pair readers `0x50eaf10` and `0x22f6370` are new #115 code (a different shape from the #94 tree reader) and are not reconstructed here, so the meaning of the pair is an inference: the first word is the bid side, the second the ask side.
- Which callers reach the builders, and with what side, size and vector, is not followed. `callers.tsv` lists one direct `E8` caller per builder: `0x55988f0`, `0x5594f60`, `0x54dc210`, `0x54db9a0`, `0x2c3f5e0` and `0x2bf8d70`.
- The saturation arms (`q + 1` at `u64::MAX`, `q * tick` overflow, `+inf`) cannot be reached through these builders, because a sell price stays under 0.97 * 2^64. They run only under mutation.
- Callers came from `E8`/`E9` byte patterns. A pointer built at run time would not appear.

Next question: what do the best-pair readers `0x50eaf10` and `0x22f6370` read at `book + 0xa8`? Their entry stride is 0x88 and they test the first word's sign with `neg`/`jno`. And which row loops call the six builders on #115?
