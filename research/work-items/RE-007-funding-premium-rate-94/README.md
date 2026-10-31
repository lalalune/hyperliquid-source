# RE-007: funding premium `0x3750ce0` and funding rate `0x3750610`

- Component ID: RE-007 (risk, oracles, liquidation), price path of the perp funding step
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985 / 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for bytes, layout, order of operations and constants; inference for units and for which book side is which; unresolved items are listed under Results and limitations
- Scope included and excluded: included are the two FDEs `0x3750ce0..0x37511c0` and `0x3750610..0x3750a07`, plus the field map of their shared struct from serializer `0x3751850`. Excluded are the impact price walk `0x3c027d0` and the map hash `0x399c4a0`, which are stubbed at the call edge, and the callers that store samples and apply the rate.

## Reproduce

From the repository root, on Linux with Python 3 and the pinned binary in place:

```
python3 tools/artifacts.py verify
python3 tools/funding_premium_rate.py --out research/work-items/RE-007-funding-premium-rate-94
python3 -m unittest tests.test_funding_premium_rate
sha256sum -c MANIFEST.sha256   # inside the folder
```

The tool takes about 30 s on an idle machine and checks the input SHA-256 first. It reads ELF bytes in Python through `tools/elf_index.py` and `tools/fde_extents.py`, with no objdump or readelf output. It never runs the binary. All numbers below come from `evidence.json` and `mutations.tsv`.

## Evidence

Coordinates are virtual addresses.

### Boundaries and callers

| Function | FDE range | Bytes | Reached by |
|---|---|---|---|
| Premium | `0x3750ce0..0x37511c0` | 1248 | data slot `0x57745a8`, indirect calls at `0x251c586`, `0x4765737`, `0x476aad7` |
| Rate | `0x3750610..0x3750a07` | 1015 | data slot `0x5774d48`, indirect calls at `0x275eeec`, `0x4d8b87c`, `0x4d8bb2c` |

Neither function has a direct E8 or E9 caller.

### FundingTracker layout

The string `struct FundingTracker with 8 elements` is at `0x3afc25`. Serializer `0x3751850` touches names and offsets in this order, and the tool reads them from its bytes:

| Offset | Field | Shape |
|---|---|---|
| +0x00 | `override_impact_usd` | hash map asset to u64: control, mask, items +0x18, hasher +0x20, 16-byte slot |
| +0x30 | `perp_to_funding_multiplier` | hash map asset to f64, same shape |
| +0x60 | `perp_to_funding_interest_rate` | hash map asset to f64, same shape |
| +0x90 | `asset_to_premiums` | B-tree asset to Vec of f64: root, +0x98 height; node keys +0x08, vectors +0x60 stride 24, length +0x16a, edges +0x170 |
| +0xa8 | `clamp` | f64 |
| +0xb0 | `default_impact_usd` | u64 |
| +0xb8 | `hl_only_perps` | B-tree set of asset: root, +0xc0 height; node keys +0x08, length +0x62, edges +0x68 |
| +0xd0 | `use_binance_formula` | byte |

The serialized order is `asset_to_premiums`, `override_impact_usd`, `clamp`, `default_impact_usd`, `hl_only_perps`, `use_binance_formula`, `perp_to_funding_multiplier`, `perp_to_funding_interest_rate`.

### Premium `0x3750ce0`

Arguments: rdi output, rsi tracker, rdx asset, rcx oracle u64, r8 book, r9 perp meta.

1. `asset / 10000` must equal meta +0x30, and `asset % 10000` must be below meta +0x10. Otherwise it panics at `l1/src/perp_meta.rs:194:38`.
2. `sz_decimals` is the byte at row +0x2a, stride 0x30, rows at meta +0x08. A value of 7 or more panics at `l1/src/perp_meta.rs:319:28`, which is the `6 - sz_decimals` subtraction.
3. `oracle = u64 as f64 / 10^(6 - sz_decimals)`, table at `0x584b08`. If that is 0.0 it returns None (out+8 = 0) without touching the book.
4. The impact notional is the `override_impact_usd` value, else `default_impact_usd`. An override of 0 is used as 0.
5. `0x3c027d0` runs twice with the same notional: first on book +0x80, then on book +0x98. Both run even if the first returns 0. Either result 0 gives None.
6. Both results are divided the same way as the oracle.
   - `use_binance_formula` nonzero: `(max(first - oracle, 0) - max(oracle - second, 0)) / oracle`
   - otherwise: `((first + second) * 0.5) / oracle + (-1.0)`
7. If the asset is in `hl_only_perps`, the premium is divided by 100.0.
8. A finite premium is clamped to [-0.5, 0.5].
9. Output: out+0 premium f64, out+8 first raw u64, out+16 second raw u64.

### Rate `0x3750610`

Arguments: rdi tracker, rsi asset. It returns rax 1 with the rate in xmm0, or rax 0 for None.

1. No B-tree entry, or an empty vector, gives None.
2. `mean = sum / len`. The sum starts at -0.0 and adds in vector order, 8 at a time then the tail. The length converts through signed `cvtsi2sd`.
3. `rate = perp_to_funding_interest_rate[asset]`, default 0.0001 from `0x20b020`.
4. `gap = rate - mean`. If `gap` and `clamp` are both finite, `gap` is clamped to `[min(c, -c), max(c, -c)]`, so the sign of `clamp` does not matter. If either is not finite, `gap` is left as it is.
5. `value = (gap + mean) * multiplier`, with multiplier default 1.0 from `0x20a730`.
6. A finite `value` is clamped to [-0.32, 0.32], from `0x20a980` and `0x20ad50`.
7. The result is `value * 0.125`, from `0x20a6d8`. That step also runs on NaN and infinity.

The rate's f64::clamp assert at `0x37509bd` cannot fire: the bounds are min and max of finite values.

### Worked values from the real bytes

| Input | Real bytes | Reference text |
|---|---|---|
| Mid, oracle 1000000, 1010000 / 1020000 | 0.014999999999999902 | 0.015 |
| Impact gap, same book | 0.01 | 0.015 |
| hl only, 70 percent mid gap | 0.006999999999999999 | 0.005 |
| hl only, 7000 percent mid gap | 0.5 | 0.005 |
| Oracle 0 | None | 0.0 |
| Rate: premium 0, default rate, clamp 0.0005 | 1.25e-05 | no formula |
| Rate: mean 0.002, clamp 0.0005 | 0.0001875 | no formula |
| Rate: mean 0.5 or -0.5 | 0.04 or -0.04 | no formula |

### Reference comparison

`references/can1357-hl` was treated as a lead only. `evidence.json` lists each claim:

- `l1/perp_meta.rs:470` has one formula. The binary has two, and its mid formula rounds differently (`mid / oracle - 1`, not `(mid - oracle) / oracle`).
- `l1/perp_meta.rs:482` clamps and then divides by 100. The binary divides first.
- `l1/perp_meta.rs:481` gives 0.0 for oracle 0. The binary gives None.
- `FundingTracker` in `l1/dex_registry/perp_dex.rs:183` and `l1/dex_registry/dex_registry.rs:154` has one field each. The binary has 8.
- The funding rate formula has no counterpart in the reference.

## Implementation and comparison

Rust implementation: not yet implemented.

A byte-level evaluator in the tool runs both real FDEs. Only `0x399c4a0`, `0x3c027d0`, the panic slots and one side call are stubbed. A separately written specification in the same tool predicts the option, the result bits and every stub argument. NaN results compare as NaN.

| Metric | Value |
|---|---|
| Cases | 560 |
| Mismatches | 0 |
| Instructions stepped | 78,806 |
| Stepped / total: funding premium | 287 / 291 |
| Stepped / total: funding rate | 227 / 241 |
| Mutants killed / survived / unreached | 232 / 12 / 3 |

Mutants flip every condition, `set` and `cmov`, immediate, field displacement, constant load and float opcode choice. Cases include prices above 2^63, stale keys past a node's length, split tag matches and third-group probes.

The 12 survivors and 3 unreached rows all have a reason in `mutations.tsv`: tag fill bytes, the unused half of a sign mask, a bit that cannot change a compare, ranges u64 prices cannot reach, or dead assert code.

Negative controls in `tests/test_funding_premium_rate.py` change the digest, an FDE start, a serializer offset, the struct name, the scale table, a constant and a slot address. Each must be refused or seen.

## Results and limitations

Observed: everything under Evidence. No progress gate is requested.

Inference:

- `first` is the impact bid and `second` the impact ask, so book +0x80 is the bid side. This rests on the name `use_binance_formula` and the shape of the gap formula, not on book bytes.
- 0.125 is one eighth, so the stored rate would be per hour from an 8-hour formula, and the hourly cap would be 0.04. The bytes show only the factors.
- `clamp` as read here is the interest clamp. No live value is pinned, and 0.0005 in the tables is only a test input.

Unresolved:

- The side call at `0x375116b` runs when the word at `0x577ab98` is nonzero and the oracle is 0, through slot `0x576e8b8` with arguments (word, 1, closure, vtable, location). The location argument `0x5669f50` is `library/std/src/sync/once.rs:219:20`, so this is a `std::sync::Once` slow path. The word lies in `.data`, stores 3 in the file, and 613 rip-relative `lea` sites name it, so it is shared process state and not funding state. The result stays None either way. The closure was not read, so what it initialises stays unresolved.
- `0x3c027d0` is stubbed, so its return is taken as given here. It tests the same word at `0x3c02c2d`. Only its call order, book offsets, notional and the zero test are pinned.
- This packet does not show how often samples are stored, when the vector is cleared, or how the rate is applied to positions.
- Evaluator float operations use Python doubles on x86-64 semantics as written in the tool, and NaN payload bits are not compared.

Next question: the host at `0x251c420` stores the premium with a flag and falls back to an oracle-word value on None. Which step of `update_funding_rates` writes `asset_to_premiums`, and how does `0x275eda0` treat a None rate for assets below 10000 and in the set at dex row +0x270?
