# RE-004: how node #94 prices generated outcome legs in 0x4d17fa0 and 0x4d18dc0

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for the bytes, the decisions, the row fields, the bit pattern pieces and the census counts; inference for the role of the two lists and for every name not taken from a string; unresolved items are listed under limits
- Scope included and excluded: included are functions `0x4d17fa0` (FDE `0x4d17fa0..0x4d18dba`) and `0x4d18dc0` (FDE `0x4d18dc0..0x4d19bda`), 711 instructions each, run from entry as real bytes. One small helper runs as real bytes too, and every other call is a recording stub. Excluded are what the stubbed calls compute, the row appliers and the callers of the wrappers.

## Reproduce

```
python3 tools/outcome_leg_pricing.py --out research/work-items/RE-004-outcome-leg-pricing-94
python3 -m unittest tests.test_outcome_leg_pricing
```

Run from the repository root with Python 3 and the standard library; no external program is used, and the output hashes are in `MANIFEST.sha256`. The tool reads ELF bytes in Python through `tools/elf_index.py` and `tools/fde_extents.py`. It parses no objdump or readelf output and it does not execute the binary. A run takes about 40 s.

## Evidence

Coordinates are virtual addresses in the first copy; the second copy sits `0xe20` higher. Rows come from the tool's own decoder (`function-rows.tsv`).

Copies. Joined row by row, with rip displacements compared as absolute targets, the two functions differ in one row (`copy-diff.tsv`): `0x4d18b00` reads state `+0x1372`, `0x4d19920` reads state `+0x8f2`. Direct call targets are listed in `copy-calls.tsv`. Each has one direct caller: wrapper `0x4c34bc0` at `0x4c34c4c`, wrapper `0x4c34a30` at `0x4c34abc`.

Arguments: `rdi` state, `rsi` a 20-byte user, `rdx` payload, `rcx` an output vector of `0x268`-byte rows. The result byte is `al`, and `0x27` means success. The payload holds two lists, at `+0x70` and `+0x88`, of 24-byte legs `(id, tok, size)`.

First pass, for each list, in order. List 1 gets its first pass after the legs of list 0 have run, so a failure there comes after those leg calls:

1. Map count `[state+0x178] == 0`, or `id` absent from the hash table at `[state+0x160]` (stride `0x90`): status 4.
2. Helper `0x3c18fb0` reads two side tokens from the entry (`+0x28`, `+0x50`). It gives one parent word per side. A side whose spot row has a token vector length other than 1 gives status 0.
3. The two parent words differ: status `0xf`.
4. `tok` differs from the parent word: saturating `n += 1`.

Then, per list:

- `S = 1.0 / n as f64` (`0x4d18298`).
- No record when payload `+8 == 2` as a 64-bit word, or for the second list, or when `n == 0`. Otherwise amount word `+0x58` with the top bit set panics in `Result::unwrap` with the Location at `0x5714c10`, `l1/src/qtys/mod.rs:843:1`. The record then holds `trunc(amount as f64 * S)`, with the floor and ceiling below, beside payload words `+0x60` and `+0x68`.
- `f = (S + -1.0) + 1.0` (`0x4d18448`, `0x4d18450`).

Second pass, for each leg of the same list:

5. Leg cost starts at 0. A leg with `tok` equal to the parent word, or on neither side of its entry, goes straight to step 11.
6. `v` is entry `+0x20` for side A and `+0x48` for side B. `px = max(1, sat(round(v as f64 * f)))`, through slot `0x576f6d8`.
7. Spot row `tok`: token vector length other than 1 goes to step 11 with cost 0.
8. Token `t` is word 0 of that vector. Scale comes from the B-tree at `[state+0x250]`, keyed by the parent word of `t`, or from slot `0x5774548` on a miss.
9. `cost = 0x3281190(scale, px, t, state+0x90)`; 0 goes to step 11.
10. Slots `0x5774790` and `0x5774a80` give `quote`, and `0x4a03180` runs twice. The gate at `0x4d18a18` is: 128-bit `px * quote` above `0x7ffffffffffffffe`, or side word equal to 2. If the gate trips, cost returns to 0 and no row is written. No error is raised. If it passes, a row is pushed and the leg keeps `cost`.
11. `0x4d11b70(state, user, id, list index, tok, size, 2, cost)`. Any result other than `0x27` ends the function with that byte.

End: payload `+8 == 2` returns `0x27`. Otherwise `0x445d4a0` runs first. Each list buffer with a non-zero capacity is freed on every return. The fixtures always use a non-zero capacity.

Row fields written here:

| Offset | Value |
|---|---|
| `+0x1f0` | `t` |
| `+0x1f8`, `+0x238` | `px` |
| `+0x200` | `quote` |
| `+0x208` | product |
| `+0x210` | 0 |
| `+0x218..+0x224` | 12 bytes of state `+0x60` |
| `+0x224`, `+0x242` | list index xor 1 |
| `+0x228` | 1 |
| `+0x230` | value from the map behind slot `0x5773170` (0 when absent) |
| `+0x240` | tag 10 |
| `+0x241` | payload byte `+0xa0` |
| `+0x243` | 1 |
| `+0x244..+0x264` | 32 bytes from `0x3987cb0` when `[state] == 1`, else zero |

Rows after each multiply, split over all 2^64 bit patterns:

- Amount (`amount-pieces.tsv`, 12 pieces): NaN, infinities and values at or below 0 give 0, values below 1 give 0, and values above the largest double below 2^63 give `i64::MAX`. The double just below 2^63 gives `0x7ffffffffffffc00`.
- Price (`px-pieces.tsv`, 12 pieces): NaN, +inf, zero and negatives give 1, values above the largest double below 2^64 give `u64::MAX`. The largest finite double gives `u64::MAX` because it clamps to 2^64 first.

The bound `0x7ffffffffffffffe` appears once in each function as an 8-byte word (`bound_movabs`) and 0 times in the row appliers `0x432a990` and `0x432b440` (`bound_in_row_appliers`). Constants are pinned by bytes in `constants.tsv`.

## Implementation and comparison

Rust implementation: not yet implemented.

Comparison with `references/can1357-hl` (a clue, not a source):

- `l1/spot_clearinghouse/impl_outcome.rs` returns status 18 from `apply_generated_spot_outcome_batch` when `safe_generated_product` fails. The bytes here use the same bound with no status: the row is skipped and the leg goes on with cost 0 (`reference-compare.tsv`). The check in these functions is on `px * quote`, before any row exists, and the two appliers do not hold the bound. A different form of check in an applier is not excluded.
- Neither reference outcome file has a `1/n` leg rule, and `0x4d17fa0` has no named counterpart there. `GENERATED_ORDER_ROW_TAG = 10` agrees with `+0x240`.
- `(1/n - 1) + 1` is not `1/n` in f64. `factor.tsv` shows it for n up to 32 and some larger values: `n = 3` gives `0x1.5555555555554p-2`, one step below `1/3`. Over n up to 65536 the two differ for 65519 values, and for value 1e8 the price differs at 2 of them. The first is `n = 2560`: 39062 against 39063, a tie at 39062.5.

## Results and limitations

Results from `evidence.json`:

- 83 named cases and 800 generated cases (400 per copy) run from entry, with 0 mismatches against a separately written specification. Events, stub arguments, every defined row byte and the result byte are compared. Both copies give the same named outcomes (`outcomes.tsv`).
- Unreached rows: the two second-pass bound panics and the landing pads, `0x4d18d26..0x4d18db5` (`unreached_rows`). Everything else in the first copy ran.
- `even-share.tsv`: for n from 2 to 1000 and exact shares 1, 2, 3 and 1000, 297 pairs truncate one below the exact share. `amount = 49`, `n = 49` gives 0, because `49 * (1/49)` is just below 1.
- `mutations.tsv`: 136 byte edits on reached rows in the arithmetic windows of the first copy, 123 killed, 13 survived, each with a recorded reason. An unexplained survivor stops the tool. An unedited image must also pass under the mutant step limit, or the tool stops. A first sweep with a lower limit reported every edit killed, and that was false, since the 49-leg case alone hit the limit.

Limits:

- `0x399c4a0`, `0x4a03180`, `0x3281190`, `0x3987cb0`, `0x4d11b70`, `0x445d4a0` and the slot calls are stubs. Their fixtures show how they are called, not what they do. The stub `round` is a Python model of `f64::round`.
- What a leg with cost 0 does inside `0x4d11b70` is not read. "Skipped" here means no row in this vector.
- The bound panics and the second `a != b` test are unreachable only while the leg calls leave the tables unchanged. That was not proved.
- `v as f64 * f` is not enumerated over both inputs. The pieces cover the rows after the multiply. The u64 to f64 lanes are checked by vectors.
- The row applier census looks only for the 8-byte bound.
- Layouts come from these rows. Field names `tok`, `quote`, `cost`, `parent` and `scale` are labels of this packet, not strings from the binary.

Inferences, not generated evidence: read by eye, `0x3726750` and `0x3726ed0` fill a payload with word `+8 = 2`, so they make no record. The first builds one leg in list 0 and two legs in list 1, one per side of an entry. The second puts N legs in list 1 with the same size. So `n` looks like the number of side tokens taking part, and `f` an even split of `v` among them. The callers of the wrappers dispatch on an action enum, and the `OutcomeDeploy` variant strings and `settleFraction` keys sit in rodata, but the link from a builder to a variant is unresolved.

The analysis ran to completion for the scope above. No progress gate is requested.

Next question: which builder sets payload `+8` to a value other than 2, what fills the amount at `+0x58`, and what does `0x4d11b70` do with cost 0?
