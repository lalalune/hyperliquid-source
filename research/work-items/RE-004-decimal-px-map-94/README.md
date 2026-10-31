# RE-004: raw price to Decimal map and the exactness of its f64 route in node #94

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for the bytes, the loop order, the panics and the value of every run; inference for the field names and for the error bound argument behind the windows; unresolved items are listed under limits
- Scope included and excluded: included is the map builder `0x3bb7280` run as real bytes, with the real conversion callee at `0x4eac740` (not mutated here, it is an edge). Stubs here: the book price helper `0x32781c0`, the map insert `0x3395550`, the map drain `0x33ba470`, the error drop `0x3762510` and the panics. Excluded: how `0x32781c0` picks its price, the callers' use of the map, and the median routine that reads it.

## Reproduce

```
python3 tools/decimal_px_map.py --out research/work-items/RE-004-decimal-px-map-94
python3 -m unittest tests.test_decimal_px_map
```

Run from the repository root with Python 3 and the standard library; no external program is used, and the output hashes are in `MANIFEST.sha256`. The tool reads ELF bytes in Python through `tools/elf_index.py` and `tools/fde_extents.py`. It parses no objdump or readelf output and it does not execute the binary. A run takes about a minute.

## Evidence

Coordinates are virtual addresses. Rows come from the tool's own decoder (`function-rows.tsv`). The FDE extent is exact: `0x3bb7280..0x3bb7671` (217 instructions). Slot `0x5774be0` has this function as its RELATIVE target and three indirect call sites, `0x27449aa`, `0x4d5d41c`, `0x4d5dcdc` (`call-sites.tsv`). There is no direct call. `0x32781c0` has this function as its only caller (`0x3bb7331`).

Arguments: `rdi` output, `rsi` perp meta `M`, `rdx` book list `B`.

| Word | Used as |
|---|---|
| `M+0x08`, `M+0x10` | pointer and length of asset rows, stride `0x30` |
| asset row `+0x2a` | byte `sz` |
| `M+0x30` | dex number |
| `B+0x08`, `B+0x10` | pointer and length of book rows, stride `0xd8` |

Steps:

1. An empty book list returns tag `0x186` with an empty map, before any multiply. So a dex number that would overflow is not tested on this path.
2. `base = dex * 10000` with a panic on overflow (`mul; jo`, Location `l1/src/asset/pdi.rs:30:14`).
3. For each book row `i`, in order: `id = base + i`, panic if it wrapped (same Location). Call `0x32781c0` on the row, giving a u64 `x`. Then `id / 10000 != dex` or `id % 10000 >= len(asset rows)` panics (Location `l1/src/perp_meta.rs:194:38`), and `sz >= 7` panics (Location `l1/src/perp_meta.rs:319:28`). Division is by the multiply constant `0x346dc5d63886594b` with `>> 11`, and the `sz` read uses `-0x75300` per quotient to step back to row `i`. The price call comes before both bound tests, so the helper has already run on the row that panics.
4. `v = f64(x) / table[6 - sz]`, where the conversion is the `punpckldq`, `subpd`, `addsd` u64 idiom and the table at `0x584b08` holds `1.0 .. 1e6` (`divisors.tsv`).
5. `|v|` at or above infinity gives tag `0xac`. Biased exponent 0 with fraction 0 gives a zero Decimal keeping the sign, from twelve zero bytes at `0x207da4`. Otherwise `0x4eac740` gets `(fraction | hidden bit, exponent - 1075, sign, 1, 1)`; a subnormal gets `-1074` and no hidden bit. A failed conversion gives tag `0xac`.
6. Insert `(id, Decimal)` through `0x3395550`. Ids are strictly rising.

Success writes tag `0x186`, then root, height and length at `+8`, `+0x10`, `+0x18`. Failure writes only tag `0xac` ("Invalid decimal number", `constants.tsv`) and drains the map. Every Decimal is 16 bytes: flags (scale `<< 16`, sign bit 31), high, low, mid.

Conversion `0x4eac740`, as run. With `m` the 96-bit mantissa and `e` the power of two:

- `e > 0`: `e` times, `m /= 5` if bit 95 is set, else `m <<= 1` and the power of ten falls by 1. Here `e <= 12` (`evidence.json`), so only the shift runs and `m` stays at or below `2^64`.
- `e < 0`: `-e` times, if `m` is even halve it, else multiply by 5 if that fits 96 bits, else halve and lose the low bit. Each halving raises the power of ten by 1.
- A positive power of ten multiplies by 10 and fails on overflow. Below `-28`, divide by 10 with half-up rounding of the single digit.
- Excess bits: while the power is negative and `m >= 2^52`, divide by 10 with half-up rounding of the single digit. This is a chain, one digit at a time, so a tail like `...4445` can carry up.
- Trailing zeros: while the power is negative and `m % 10 == 0`, drop one.

Range. Over all `2^64` values of `x` and the seven divisors, `v` is 0 or in `1e-6 ..= 2^64` (`evidence.json`, `quotient_range`). So `v` is never infinite, NaN, negative or subnormal, the mantissa cannot overflow, and with the real table neither tag `0xac` row can be reached. `x = TOP` gives `18446744073709551616`, which is above u64. The non-finite, negative and subnormal rows run only with a divisor word replaced in the fixture (`fault_*` rows in `outcomes.tsv`).

Exactness. `x / 10^k` with `k = 6 - sz` is not always what comes out:

| k | First raw `x` that differs | Exact | Decimal |
|---|---|---|---|
| 2 | 419430423 | 4194304.23 | 4194304.230000001 |
| 3 | 4096029 | 4096.029 | 4096.029000000001 |
| 4 | 40960254 | 4096.0254 | 4096.025400000001 |
| 5 | 409602504 | 4096.02504 | 4096.025040000001 |
| 6 | 4096000004 | 4096.000004 | 4096.000004000001 |

The same rows are in `inexact-witnesses.tsv`, and each one is a real run of the bytes. Take `x = 4096029`, `k = 3`: the f64 is `4096.02900000000045110...`, so the tail past the 12th decimal is `0.4511`. One rounding of that tail would give `4096.029`. The chain rounds one digit at a time, `...4511` to `...45` to `...5`, and that carries up to `4096.029000000001`. For `k = 1` no value differs in the part of the windows that was scanned (9087329 values, capped at 3500000 per window, `first-inexact.tsv`). `k = 0` has no fraction.

Why. For `x < 10^15` the true value `t` is a whole number of kept digits, because the chain stops with `m` between `2^52/10` and `2^52`, which is at least 15 digits. `x`, `10^k` and the divide are each exact or once rounded, so `|v - t|` is at most half an ulp of `v`. In units of the last kept digit that is `2^(n-53) * 10^s` for binade `n` and kept scale `s`. The single-digit chain lands on `t` when that error is below about `4/9` (a fraction `0.4444...` is the most that still rounds down at each step; the tool uses `0.4444`). `error-bound.tsv` lists every binade and scale of the domain. Exactly four pass the bound:

| Quotient range | Binade | Kept scale | Half ulp in last digit |
|---|---|---|---|
| `4096 .. 4503.6` | `2^12` | 12 | 0.4547 |
| `4194304 .. 4503599.6` | `2^22` | 9 | 0.4657 |
| `4294967296 .. 4503599627.4` | `2^32` | 6 | 0.4768 |
| `4398046511104 .. 4503599627370.5` | `2^42` | 3 | 0.4883 |

The next closest is `4 .. 4.5036` at 0.44409, just below the bound. Outside the four windows, `x < 10^15` gives exactly `x / 10^k`. In a window some values differ and most do not.

Short prices. Every `x` below `10^15` with at most 5 significant digits (22008 values in the windows) and with at most 6 (201760 values) came out exact, so a price with a fraction that passes the 5-digit tick rule of `RE-004-px-tick-ladder-94` is not affected. Above `10^15` the Decimal keeps what the f64 kept, so `x = 2^53 + 1` at `k = 0` gives `2^53` (`sample-values.tsv`).

Reference compare, `l1/perp_meta.rs`. `raw_px_to_display_px` has the same quotient as step 4. `split_asset_id` and `check_sz_decimals` return `Err` there; on this path the bytes panic with those Locations. `l1/exchange/handlers/23_validator_l1_update_reference_oracle.rs` calls the caller's function `build_external_perp_pxs` and holds `RawPx` u64 values in its map; the map built here holds 16-byte Decimals keyed by asset id, filled from books and not from the action. The reference has no text for this builder, and no Decimal conversion in the file.

## Implementation and comparison

not yet implemented. The tool holds a rule list `spec_run` and an integer model `convert`, written apart from the bytes, that predict the events and output of each run.

## Results and limitations

- 74 named cases and 300 generated cases of four rows each: 0 mismatches, comparing the Out block, all fixture words outside it, stub arguments and event order. All rows of the builder are reached except the jump rows after three panic calls and the cold rows from `0x3bb7652` (`evidence.json`). 313 of 407 rows of `0x4eac740` are reached; the rest include the 32-bit excess path, which this caller's flags never select, and the overflow panics; they were not listed row by row.
- 73 byte edits on reached rows of the builder: 66 killed, 7 survived, each with a recorded reason (`mutations.tsv`). An unedited image must pass under the same step limit first.
- The rule sample ran 11839 values outside the windows below `10^15`, with 0 inexact, and 68 inside.

Limits:

- `convert` is held to the bytes by vectors, not by a proof for all f64 values. `0x4eac740` is not mutated here.
- The `4/9` argument is a reasoned bound; the tool checks the table and samples the rule, it does not prove the chain over all `x`. The 96-bit truncation in the `e < 0` loop is treated as negligible at `2^-38` of the last digit.
- The first inexact values are the smallest in the scanned part, and the windows are walked upward, so for `k >= 2` they are the true minimum given the bound. For `k = 1` the windows from `2^32` on are capped.
- `0x32781c0` is a stub. Its rule and whether `x` can land in a window are not claimed here. Which prices the book path produces with more than 6 significant digits is unresolved.
- Names `dex`, `sz` and "perp meta" rest on the Locations in `perp_meta.rs` and `pdi.rs` and on use of the words. The serializer of the asset row was not read.
- Callers are pinned only as call sites.

Next question: the median routine `0x3bb7680` sorts these Decimals with validator lists; does it average the two middle values, and with which rounding?
