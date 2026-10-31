# RE-007: `apply_bole_liquidations` block step: bucket gate, token refresh, interest index, debt flag, user sweep

This packet maps the whole `apply_bole_liquidations` block step around its two liquidation bodies, so a reconstruction can now write when the step runs, how each BOLE token gets its interest index and price, when the system user's debt flag moves, and which users the bounded sweep hands to liquidation.

- Component ID: RE-007 (risk, oracles, liquidation), BOLE liquidation path
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985 / 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for bytes, layouts, order of operations, constants and rounding; inference for what the words and modes mean; unresolved items are listed under Results and limitations
- Scope included and excluded: included are the bucket gate in 3 block hosts, 3 copies of the step body up to their second clock read, the token refresh `0x373b060`, the index writer `0x3740990`, the median `0x359ca70`, the row collector `0x3739ef0` and `0x3733d70`, 3 copies of the user sweep, and the range helpers. Excluded are the bodies of the system user pass `0x2739d70`, the shortfall sweep `0x2765600`, the health report `0x28db540` and the per-user entry `0x272de40`, which are stubbed with checked arguments. `0x37400c0` is the subject of #782 and is stubbed the same way. The rate curve is already in `RE-004-bole-borrow-rate-curve-94` (our draft), and the rate arms here are checked only as part of the writer.

## Reproduce

From the repository root, on Linux with Python 3 and the pinned binary in place:

```
python3 tools/artifacts.py verify
python3 tools/bole_liquidation_step.py --out research/work-items/RE-007-bole-liquidation-step-94
python3 -m unittest tests.test_bole_liquidation_step
sha256sum -c MANIFEST.sha256   # inside the folder
```

The tool takes about 50 s on an idle machine and checks the input SHA-256 first. It reads ELF bytes in Python through `tools/elf_index.py` and `tools/fde_extents.py`, with no objdump or readelf output. It never runs the binary. All numbers below come from the generated files.

| File | Content |
|---|---|
| `evidence.json` | functions with hashes, call map, constants, token rows, error strings, field sites, Locations, stubs, case outcomes |
| `path-map.tsv` | the step in order |
| `accrual-samples.tsv` | index writer runs over one day |
| `debt-flag.tsv` | flag before and after, for gaps around 80 percent and the cap |
| `mutations.tsv` | every flipped branch, condition, immediate and offset, with a reason for each that stayed |

## Evidence

Coordinates are virtual addresses. Offsets marked `exchange` are from the state pointer passed to the step. The BOLE state sits at exchange +0x498.

### Path

`path-map.tsv` lists the order. All 3 block hosts load `"apply_bole_liquidations"` (length 0x17) with thresholds 0.01 and 0.05, then call the step body, then the user sweep.

| Copy | Block host | Step body | User sweep | Mode byte | Dex rows | Budget | Cursor Option |
|---|---|---|---|---|---|---|---|
| primary | `0x22297c0` | `0x222caf0` | `0x26fdf20` | `+0x8f2` | `+0x5c0` | `+0x3a68` | `+0x3acc` |
| second | `0x470e9a0` | `0x4714080` | `0x4ce64c0` | `+0x8f2` | `+0x5c0` | `+0x3a68` | `+0x3acc` |
| recording | `0x47162d0` | `0x47121b0` | `0x4ce6db0` | `+0x1372` | `+0x1040` | `+0x44e8` | `+0x454c` |

The recording host wraps its sweep in two marker calls to `0x4925220`, tags 0x10 and 0x11, gated on dword `+0x5f0 == 1`. The token refresh, index writer and median exist once and all copies reach them. Every other callee of the step has one row per copy in `evidence.json`.

### Gate

Block time becomes Unix millis, clamped at 0. `bucket = millis / [+0x4d8]`. When `bucket > [+0x4e0]` the word is stored, and byte +0x20 of the step record says so. The step body does nothing unless that byte is 1, and returns it. The divide has no zero test.

### Step body

In order, for byte +0x20 equal to 1:

1. The dex count must be nonzero, else an `unwrap` panic.
2. Token refresh: `0x373b060(exchange +0x498, mode, block time, exchange +0x250, exchange +0x80, first dex row)`.
3. `0x2739d70(exchange, 0xbb x 20)`. The address is built from the 16 bytes at `0x204560` and an immediate. A result other than 0x11 clears byte `+0x5b3`, the direct gate read by the spot sell preprocess in #565.
4. `0x2765600(exchange)`, same rule.
5. Look the system address up in the tree at `+0x598`, with height `+0x5a0`. A miss uses the static default at `0x5786350`.
6. Report: `0x28db540(out, user, exchange +0x560, exchange +0x90, 0)`. A failed report clears `+0x5b3` and skips the flag.
7. Words `w8 = report +8` and `w10 = report +0x10`, and cap `[+0x590]`, must all fit i64, else an `unwrap` panic (Location `l1/src/qtys/mod.rs:843:1`).

### Debt flag

```
gap = w8 - w10
gap <= 0                           flag +0x5b4 = 0
gap > cap                          flag = 1
gap <= trunc(f64(cap) * 0.8)       flag = 0
otherwise                          flag unchanged
```

So the flag sets strictly past the cap and releases at 80 percent of it. Between those it holds. #565 reads this byte: spot sell takes its direct path only with `+0x5b3` equal to 1 and bit 0 of `+0x5b4` clear, so this step can turn that path off. `debt-flag.tsv` shows cap 1000 from real bytes: gap 801 keeps either state, 800 clears, 1000 keeps, 1001 sets. The 0.8 is the f64 at `0x20b0c0`. A failed report leaves the flag alone.

### Token refresh

For each token in key order, in the tree at BOLE +0xd0 (height +0xd8, values 0xb0 wide):

1. Index writer on the row, even for token 0. Token 0 stops here and keeps its price.
2. Start an empty price list and an empty error list.
3. Look the token up in the tree at exchange +0x250. A hit adds that word; a miss adds `spot px`.
4. Pick a perp by the mode byte, through the 4 row jump table at `0x597440`:

| Mode | Token | Perp |
|---|---|---|
| 0 | 3 | 0 |
| 1 | any | none |
| 2 | 1, 0x451 | 0x7d, 0x87 |
| 2 | 0x59b, 0x5df, 0x607, 0x608 | not needed, spot only |
| 3 | 0x96, 0xc5 | 0x9f, 0 |
| 3 | 0x168 | not needed, spot only |

Any other token gives `missing perp`. So does a perp where the dex id at dex row +0x30 is nonzero or the index is at or past the count at +0x10. A perp past the price table at +0x70 panics (`l1/src/clearinghouse/oracle/oracle.rs:197:18`), and `szDecimals` above 6 panics (`l1/src/perp_meta.rs:319:28`). The compare rows and the bit mask `0x30000000001` over 0x5df are in `evidence.json`.

5. With a perp, `d = 10^(6 - szDecimals)` and the two price words sit at +0x20 and +0 of a 0x60 wide row. Each goes through `0x37400c0(token, table, x0, x1)`:

| Token | Second price | Third price |
|---|---|---|
| native (id at exchange +0x88, byte exchange +0x80 set) | `+0x20 / d`, x1 = 1.0 | BOLE +0xf0, x1 = BOLE +0xe8 |
| other | `+0x20 / d`, x1 = BOLE +0xe8 | `+0 / d`, x1 = BOLE +0xe8 |

A zero result adds `mark px`, `native oracle px` or `oracle px` and no price.

6. If the list is not 3 long, `unexpected length` is added, unless it holds 1 price and the token is one of the spot only tokens of mode 2 or 3.
7. In every mode but 2, `f64(max) / f64(min) > 1.01` adds `unexpected range`. The price is still written.
8. The median is the middle value, or `(a & b) + ((a ^ b) >> 1)` for 2 values. A median of 0 adds `missing median` and leaves the price.
9. Otherwise, with band words +0x30 and +0x38, each used only if nonzero: `f64(m)/f64(low) - 1 < 0` gives `m = low`, then `f64(m)/f64(high) - 1 > 0` gives `m = high`. The test is in floats, so at 2^60 a median one below the band stays. A crossed band ends at `high`. The result goes to row +0x10 (`oraclePx`).
10. The error list goes into a local map keyed by token. The whole map is dropped when the function ends. Nothing in this path reads it.

### Index writer

`0x3740990(row, block time, reserve share)` is the writer of the two index words. The share is BOLE +0xc8. If the row time at +0xa0 equals the block time word for word, it goes straight to the settle step. Otherwise:

```
B = ceil(a * ia / 1e14), S = floor(b * ib / 1e14), u = min(B * 1e14 / S, 1e14), r = rate(u)
elapsed = max(now, 0) - max(last, 0)
grown  = floor(floor(r * elapsed / 31557600000) * ia / 1e14)
share  = b ? floor(a * 1e14 / b) : 0
supply = floor(grown * share / 1e14)
fee    = floor(supply * keep / 1e14)
tokens = floor(fee * b / 1e14)
ia += grown, ib += supply - fee, row time = block time, pending +0x28 += tokens
```

Settle: `m = min(pending +0x28, balance +0x18)`, balance and pending fall by `m`, paid +0x20 rises by `m`. The two adds saturate after a log row (`l1/src/qtys/mod.rs:831:1`).

- The year is 31557600000 ms, 365.25 days, immediate at `0x3740d6d`.
- `elapsed` above one year returns with no change at all: no index, no stamp, no settle. The next call sees a larger gap, so the row stays frozen. A row with time word 0 is in that state from the first call.
- A last time ahead of the block time also returns with no change.
- Each 128 bit product has a guard that the quotient by 1e14 fits 64 bits. A fired guard returns with no change, and no settle. `supply < fee`, which needs `keep > 1e14`, returns the same way.
- `reserve share = 1e14` leaves `ib` unmoved and turns the whole supply side into `pending`. `accrual-samples.tsv` shows one day at 4 use levels.

### Row collector

`0x3739ef0(out, BOLE)` looks the system address up, then `0x3733d70` walks that user's token rows (keys at +0x168, values 0x20 wide, tree at user +0x18). Each row gives `(token, ceil(word8 * ia / 1e14), floor(word18 * ib / 1e14))`. A token not in the table gives error code 9. A first value past 64 bits or a failed second guard gives code 3 and frees the rows.

### User sweep

The budget is the word serialized under key `pmn` (`0x275c13a`). The cursor is an `Option<address>` serialized just before it.

```
if budget == 0: return
mark = cursor or 20 zero bytes
order = users after mark, then users up to and including mark
visited = first budget of order
cursor = last visited
picked = visited users with any token row where word +8 is nonzero
for each picked user: 0x272de40(out, exchange, user, 0, 1)
```

The budget counts every visited user, debt or not. The picks run after the walk, so the cursor is already stored. A 0-address user with no cursor comes last. Row word +8 is the same word the collector multiplies by the borrow index.

### Cases and mutants

| Metric | Value |
|---|---|
| Cases | 374 |
| Mismatches | 0 |
| Instructions stepped | 219,317 |
| Stepped / total: gate primary | 75 / 81 |
| Stepped / total: gate second | 75 / 81 |
| Stepped / total: gate recording | 69 / 69 |
| Stepped / total: step primary | 164 / 170 |
| Stepped / total: step second | 164 / 170 |
| Stepped / total: step recording | 164 / 170 |
| Stepped / total: refresh | 646 / 741 |
| Stepped / total: index writer | 419 / 420 |
| Stepped / total: median | 87 / 103 |
| Stepped / total: collector | 88 / 96 |
| Stepped / total: row collector | 250 / 339 |
| Stepped / total: sweep primary | 357 / 468 |
| Stepped / total: sweep second | 357 / 468 |
| Stepped / total: sweep recording | 357 / 468 |
| Stepped / total: range front | 192 / 537 |
| Stepped / total: range back | 123 / 165 |
| Stepped / total: tree step | 24 / 29 |
| Mutants killed / survived / unreached | 1210 / 180 / 388 |

180 mutants survived and 388 were not reached. Each has a reason in `mutations.tsv`. Reference: `references/can1357-hl` has no step body for this name, and `l1/exchange/impl_bole.rs` holds only order builders (`reference_claims` in `evidence.json`).

## Implementation and comparison

not yet implemented. The comparison object is a Python specification written from the code, run against the real bytes in an evaluator. It is a cross-check of the reading, not an independent source.

## Results and limitations

Inferences, not proven by bytes:

- `word8 * ia` is a debt and `word18 * ib` a deposit, because the rounding and the row names match `totalBorrowed` and `totalSupplied`.
- `+0x28` is a fee waiting for cash and `+0x20` the fee paid, by the settle shape. No serde name is checked here.
- The mode byte is a network choice. The ids of mode 3 look like main network listings (native token 0x96, BTC perp 0), but no string in this path names a mode.
- The 0xbb address is a system account for BOLE liquidation. Only its use here supports that.
- BOLE +0xe8 and +0xf0 are price factors; here they are only x1 and x0 of the stub.
- The log hook `0x358dcd0` reports and returns, since the code continues with the saturated value.

Unresolved:

- Bodies of `0x2739d70`, `0x2765600`, `0x272de40`, `0x28db540`. The system user pass reads `+0x5b3` first and spends the collector rows. Its order logic is not modelled.
- The meaning of report words +8 and +0x10, the live cap, budget and bucket width.
- Mode bytes above 3 read past the table's 4 rows. No fixture sets one, and the writer of that byte is not pinned.
- Which copy runs in which node mode.
- The shared timing tail after the second clock read is not stepped.
- The specification comes from reading the same code, so a shared misreading would not show.
