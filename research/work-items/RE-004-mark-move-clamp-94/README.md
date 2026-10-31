# RE-004: how node #94 bounds and clamps an oracle price update

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for the bytes, the float decision, the stored results, the message texts, the kind texts and the band word writers; inference for the words previous, daily and band and for the meaning of config byte 3; unresolved items are listed under limits
- Scope included and excluded: included are the two copies `0x21ff400` and `0x42d0250`, which run as real bytes, and the writers `0x235e840`, `0x4cbbde0`, `0x4cbc720` of the band word. Stubbed as edges: the reference oracle check at slot `0x5773998`, the round helper at slot `0x576f6d8`, the formatter, the Vec growth, the free and the error guard record. Callers appear only as call sites. What the enclosing functions do is not claimed here.

## Reproduce

Working directory is the repository root. Platform Linux x86-64, Python 3.12.3, standard library only. The binary is read as bytes and never run. No external program is called, so the binutils version cannot change a result.

```
python3 tools/artifacts.py verify
python3 tools/mark_move_clamp.py --out research/work-items/RE-004-mark-move-clamp-94
python3 -m unittest tests.test_mark_move_clamp
```

The tool refuses any input whose SHA-256 differs. It uses `tools/elf_index.py` for sections and `tools/fde_extents.py` for FDE records. Output is byte-identical between runs.

## Evidence

Addresses are virtual addresses.

### Boundaries and reach

`targets.tsv` gives the FDEs: `0x21ff400..0x22001d1` and `0x42d0250..0x42d1021`, 691 instructions each. The tool decodes both and compares them row by row. All rows match with a fixed shift of `0x20d0e50`, except that rip-relative displacements (73 rows) are not compared.

`call-sites.tsv`: `0x21ff400` has one direct call and `0x42d0250` has two. `site-context.tsv` pins, before each call, a `lea` of `+0x60` (the first argument), a `lea` of `+0x1a8` (the config word), and near the caller's head a `cmpb $3,+0x230`.

Log text: `Price moved too far asset=` at `0x1e52ad` and `Price moved too far, new price is clamped asset=` at `0x1e7579`. Each has exactly two `lea` sites, one per copy (`evidence.json`). The reference tree has neither text; its `Price moved too far from reference oracle` is a different string with a different function.

### Inputs

The second argument is a struct with three Vecs of `(asset, price)` pairs, one per kind, read in the order 0, 1, 2. `kinds.tsv` reads the text table of each copy: 0 `Spot`, 1 `Mark`, 2 `ExternalPerp`.

The first argument holds a table with stride 0x60, three 0x20-byte entries per asset, indexed by `asset % 10000`. An entry is `+0` price, `+8` a second price, `+0x10` three u32 time words. I call the two prices `previous` and `daily`. `daily` is printed as `daily_price=` and `previous` as `previous_price=`. Neither copy writes `daily`.

The config word at `+0`, here `band`, and the config byte at `+0x88`, here `mode`, are the `+0x1a8` and `+0x230` fields of the caller's struct.

### One update

For each pair, in order:

1. `local = asset % 10000`. If `local` is past the table, the pair is skipped with no error and no call.
2. A B-tree at `+0x18` gives a reference word per kind, or 0. A second B-tree at `+0x48` gives optional overrides, falling back to the f64, u64 and byte at `+0x60`, `+0x68`, `+0x70`. Both go to the check at slot `0x5773998`.
3. If the check returns an error string, the time words are stored, the price is not, and the string is pushed.
4. If `mode == 3`, price and time are stored. No band and no clamp.
5. Band: with `r = float(new)/float(daily)`, the update is refused unless `!(band < r) && !(r < 1.0/band)`. A refusal stores the time words, keeps the price, logs and pushes a string.
6. Kind `Mark` only: with `q = float(new)/float(previous) - 1.0`, if `0.010000000000001 >= |q|` the price is stored raw.
7. Otherwise the stored price is `max(1, round(previous * (1 + clamp(q, -0.01, 0.01))))`, saturated to u64. The time words are stored, a second log is made, and its string is pushed as well. So a clamped update changes state and still reports an error.

Kinds `Spot` and `ExternalPerp` have no step 6 or 7. They are stored raw once inside the band.

A branch for `flag == 0 && |r - 1| > 0.5` (the flag is `+0x28` of a 0x30-byte asset row) builds a String holding the kind text and frees it. The tool shows it has no effect on the outcome: the paths are equal with and without it.

`paths.tsv` is the output of a symbolic walk over the real instructions from the first compare to the exits, in each copy. It stops at any row it does not model. There are 20 raw paths. Dropping the labels of that empty branch and of the panics leaves 5, equal to a list written separately in the tool. Both copies give the same 5. This covers all `new`, `daily`, `previous` and `band`, because each condition keeps the IEEE meaning of its compare.

`constants.tsv` pins the words. The gate at `0x20a188` is `0x3f847ae147ae16bb`, and the clamp at `0x20a2f8` is `0x3f847ae147ae147b`. They are different doubles, and the gate is the larger.

The end of the function: if the out Vec is empty, `+0x80` and `+0x8c` are cleared. If it is not empty and `mode == 3`, the time goes to `+0x8c` and, when `+0x80` is 0, to `+0x80`, and a record naming `base/src/err_dur_guard.rs` line 0x17 is passed to slot `0x576e8c0`. With `mode != 3` and a non-empty Vec, neither happens.

Printed prices are `value / 10^(6 - digits)`, with `digits` the byte at `+0x2a` of the asset row and a pinned f64 table per copy. `digits >= 7` panics (Location `perp_meta.rs:319:28`). A dex mismatch or a row past the table panics (`perp_meta.rs:194:38`), but only on paths past step 4, so an update under `mode == 3` never tests the dex. The asset id printed follows the wire rule: up to 9999 as is, up to 99899999 plus 100000, else `0xffffffff`.

### Rounding

- `clamp(q)` is always `+0.01` or `-0.01` for `previous >= 1`, because step 7 needs `|q|` above a gate that is above 0.01. So the result depends only on `previous` and the side.
- `fixed-points.tsv` runs the real bytes for `previous` from 1 to 160 in both directions. A rise first moves the price at `previous = 50` (`round(50.5) = 51`). A fall first moves it at `previous = 51`. For `previous <= 49` a rise, and for `previous <= 50` a fall, stores `previous` again while still logging and pushing a string. An integer sweep of the closed form to 200000 finds no later fixed point.
- `gate-edges.tsv` gives the last raw `new` on each side for 10 values of `previous`. For 123456789 the last raw rise is 124691356 and the clamped result is 124691357, so rounding puts the clamp one unit past the last raw value. From `previous = 10^15` in that table the gate is wider than the exact 1 percent, by 1 unit there, 9 at `2^53` and 959 at `10^18`.
- Saturation at `u64::MAX` is in the bytes but not reachable from u64 inputs. A rise needs `new > 1.01 * previous`, so the product stays below `new`. The mutant of that constant survives for this reason.

### The band word

`band-writers.tsv` lists three writers with two state layouts. They were read and run as real bytes, 81 runs. With no name, the state word (`+0x3908` or `+0x4388`) takes the value and every dex with `mode != 3` gets `band = max(band, value)`. With a name, a length past 100 is tag 0x143, a failed lookup returns the lookup's tag, `mode == 3` is tag 0x141, and otherwise that dex gets the value with no max. Each writer has one direct call. By eye the callers look like the vote dispatch copies; that reading is not in the generated evidence.

## Implementation and comparison

not yet implemented

Reference check: `l1/clearinghouse/oracle/oracle.rs:421` `apply_hip3_set_oracle` stores each mark price after a positive check, with no band and no clamp. `OracleKindEntry` there has `p`, `d`, `u` at the same offsets as `previous`, `daily` and the time words, which supports those readings. `SetPerpDexDailyPxRange` in `l1/action/vote_global.rs:438` has a `daily_px_range <= 0.01`, a similar size, but it is an f64 per vote, and these bytes read a fixed constant. So this packet does not tie the two together.

## Results and limitations

- Real runs: 125 named, 12696 grid and 2500 random cases on `0x21ff400`, a subset of 125, 1814 and 500 on `0x42d0250`, plus the edge and fixed point runs, all equal to a separately written specification. Events across the sets: 15330 checks, 11414 band refusals, 1639 clamps, 17 panics.
- 655 of 691 rows of the first copy were reached.
- Mutation controls on the first copy: each condition, immediate and non-stack field displacement in reached rows, and eight rodata constants, 249 in all. 232 killed. The 17 survivors are in `mutations.tsv`, each with its reason. They are iterator slots never read back, padding copies, low bits next to infinity, an unreachable saturation and a repeated bound.
- Stack slot displacements are left out of the sweep, because moving one half of a spill says little.
- The round helper is stubbed with half-away-from-zero. Its bytes are not run here.
- The check at slot `0x5773998` is a stub that answers ok or error. So which inputs reach step 4 is not covered, and that includes zero prices. The formula's results for `previous = 0` or `daily = 0` are outcomes of the bytes, and whether such a state can occur was not traced.
- The fixture for the id boundaries uses a shifted table base so that only the one row exists.
- The reference word's meaning, what writes `daily`, and what the state word means have no binary name yet. The word `band` is mine.
- That `mode == 3` means a dex without this config is an inference from tag 0x141 `Invalid perp DEX` in the writers.
- Stubs show the calls made, not what a stubbed callee computes.
