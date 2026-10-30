# RE-006: node #94 `0xfe` user spot buy cycle and its block step

- Component ID: orderbook (task RE-006)
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / can1357 `999556f6e0a474b8312db96ec3149e1c44e97c23`
- Claim status: observation for everything under Evidence; inference only where the Inferences section says so; open points are listed under Results and limitations
- Scope included and excluded: included are the cycle `0x1e83350` (whole function), its driver `0x26fed00` (whole function), and the top-of-book reader `0x23978c0` as a real callee. Excluded are the insides of every other callee: the book cancel, the order path, the tick, the price conversion, the elapsed helper, the transfer path, the hyperliquidity order step `0x26cb280`, and whatever fills the config tree.

## Reproduce

From the repository root, on Linux with Python 3 and the pinned artifact in place:

```sh
python3 tools/system_buy_order.py --out research/work-items/RE-006-system-buy-order-94
python3 -m unittest tests.test_system_buy_order
```

In `research/work-items/RE-006-system-buy-order-94`, `sha256sum -c MANIFEST.sha256` checks the files. The tool checks the binary digest first and fails on any other input. It reads ELF bytes through `tools/elf_index.py` and `tools/fde_extents.py`. It parses no objdump or readelf output, calls no external program and never executes the binary. It takes about 25 s. Only the standard library is used.

Generated files: `evidence.json`, `call_sites.tsv`, `mutations.tsv`.

## Evidence

Coordinates are virtual addresses in node #94. Function bounds are FDE extents.

### Path

| Step | Address | Size in bytes |
| --- | --- | --- |
| Per-block caller, passes flag 0 (`xor esi, esi`) | `0x222a0f5` in `0x22297c0` | |
| Action path, after `0x274fd60` returns status `0x186`, passes flag 1 (`mov esi, 1`) | `0x23e85e8` in `0x23e7d10` | |
| Driver | `0x26fed00` | 1158 |
| Span wrapper, runs its body only when its flag byte is 1 | `0x22293c0` | 1019 |
| Hyperliquidity order step, stubbed | `0x26cb280` | 5292 |
| Cycle, one direct call, at `0x26ff0f1` | `0x1e83350` | 2767 |

`call_sites.tsv` lists every direct call of the cycle, the driver, the reader and five callees.

### Driver

In order:

1. A nonzero byte at `+0x3ac8` returns at once.
2. If the config tree at `+0x3a00` has entries and `+0x5c8` markets exist, the user `0xfe` * 20 is swept. The market array (`+0x5c0`, stride `0x2f0`) is walked once to read an amount per market through the slot at `0x5774660` and to subtract 1000000000, saturating at 0. Then `0x270f6f0` runs for each market with the id at market `+0x30`, the user, 1 and the amount. It runs at amount 0 too. A status other than `0x186` drops the error and goes on.
3. The map at `+0x80` is read for user `0xff` * 20, and a tree walk looks for key 0. Every arm of that walk falls through to the same address, so the result is unused.
4. Flag 1 calls `0x26cb280` directly. Flag 0 divides the block time in milliseconds by `+0x38d0`. If the quotient exceeds `+0x38d8`, it is stored and the span flag is 1, otherwise 0. `0x22293c0` gets the name `hyperliquidity_ensure_orders` (`0x3ef968`, 28 bytes) and that flag.
5. The cycle runs with `+0x3a00`, the spot books at `+0x3380`, the exchange and a fresh event vector. It also gets byte `+0x8f2` in `esi`, which it never reads: the first thing it does to `esi` is `setne sil`, and all 147 cases give the same result with the argument set to 1.
6. The vector goes to `0x24fc8a0`.

### Cycle

The tree holds up to 11 entries per node: u64 keys at `+0x08`, values at `+0x60` with stride `0x48`, parent at `+0x00`, parent index at `+0x378`, length at `+0x37a`, edges at `+0x380`. The key is never read.

| Value field | Type | Meaning |
| --- | --- | --- |
| `+0x00` | f64 | sum |
| `+0x08` | f64 | weight |
| `+0x10` | f64 | window |
| `+0x18` | u64 | samples since reset, saturating |
| `+0x20` | 12 bytes | last time; a zero first word means none |
| `+0x30` | u64 | index into both the spot books and the pairs |
| `+0x38` | u64 | amount |
| `+0x40` | f64 | cap |

For each entry, in tree order:

1. An index at or past the book count panics at `l1/src/books.rs:19:47`.
2. `0x26e4240` cancels the user's orders in book `index` with flag 1 and reason 2.
3. `0x23978c0` reads the first key of the trees at book `+0x80` and `+0x98` and returns their absolute values. Only the first is used. No key, or a key of 0, ends this entry with its state untouched.
4. `sample = key / 10^d`, where `d` is byte `+0x49` of the quote token minus byte `+0x48` of the base token. The pair is 0x20 bytes at exchange `+0x1f8`, base first, and the token row is 0xe8 bytes at `+0x210`. A negative `d` panics at `l1/src/spot_meta.rs:984:9`. The table `0x3e0e90` holds powers of ten, checked to 10^22.
5. `seconds` is 1.0 with no last time, otherwise the result of the slot at `0x576e8c0` (target `0x1447130`, which also gets location `l1/src/time.rs` line 84).
6. If `seconds > window`: sum, weight and count become 0, the first time word becomes 0, the window becomes `max(10, window)`, and the sample is dropped.
7. Otherwise, with `f = 1 - 1/window`: `sum = sample * seconds + f * sum`, `weight = seconds + f * weight`, the time is stored and the count goes up by 1, saturating.
8. Gates, all of which only end the entry: `window > count`, then `1e-15 > weight`, then a sum below zero. A negative sum strictly inside `-1e-15` counts as 0 first.
9. `price = min(sum / weight, sample)`. `price > cap` ends the entry.
10. The slot at `0x57731f0` (target `0x375e190`) turns `price` into a raw price with the spot metadata. A status other than `0x186` drops the error and ends the entry.
11. `0x230b590` gives the tick. `limit = raw / tick * tick`, and a limit of 0 becomes 1.
12. The map at exchange `+0x80` is read for the user, and its balance tree for the quote token. The first word of the value is the balance, 0 if the tree or key is missing. `amount > balance` ends the entry.
13. An order record goes to `0x26cc730`: `size = amount / limit`, floored, with the limit, the time in milliseconds clamped at 0, and the user. `evidence.json` key `record_map` names the fields, and the harness compares all 0xd0 bytes against unwritten stack marks. The side byte `+0x90` is 0.
14. The result is dropped: a capacity word of `1 << 63` is a rejection and frees nothing. Otherwise fills are freed at stride `0x228`, and a map walked with `0x286ada0` frees its 8-byte vectors.

So an amount of 0 passes the balance test with no balance at all and places a record of size 0.

### Reference comparison

`l1/books.rs:984` labels this address `ImpactState::observe`. Its text does `alpha = (elapsed / window).clamp(0, 1)`, then blends with `alpha`. The bytes do not. In the case "previous time, gates pass" (sum 4, weight 2, window 30, 2.5 s, sample 2500) the real bytes give sum 6253.866666666667 and weight 4.433333333333334. The reference formula gives 211.99999999999997 and 1.9166666666666665. `evidence.json` key `reference_claims` has each difference. The reference holds neither the `0xfe` literal nor the span name.

## Inferences

- Bytes `+0x48` and `+0x49` are the base `szDecimals` and the quote `weiDecimals`, which answers the next question of `RE-004-spot-token-decimals-94` for this path. `d` then scales a raw price to a decimal one, and `amount / limit` turns quote wei into base size.
- The side byte 0 is a buy, as in the reading of `RE-006-mid-market-order-94` (#197). It fits spending the quote balance.
- Together this looks like a capped buyer: it spends a fixed quote amount per block, at no more than a decaying average of the top of the book, and removes its last order first. So an order rests for one block unless it matches.
- `window` does three jobs: longest gap in seconds, least number of samples, and the decay denominator. The decay is per sample, not per second, so with an even block time the weight settles at `seconds * window`.
- Outside the binary: public documentation gives `0xfefefefefefefefefefefefefefefefefefefefe` as the Assistance Fund address, so this may be its buyback. No byte here says so.
- Step 2 of the driver looks like a move of that user's perp balance to spot, keeping a floor. `0x270f6f0` is the class transfer only by the reference's label (`l1/exchange/handlers/59_system_usd_class_transfer.rs:93`), and its body is not evaluated here. The slot `0x5774660` (target `0x36f7560`) reads like a movable amount, by hand reading only.

## Implementation and comparison

Rust implementation: not yet implemented. Comparison here is between the real function bytes in a Python evaluator and a separately written Python specification.

Edges are stubs that record every argument. `0x23978c0` runs real. Trees are laid out in the node shapes above; some cases use keyless interior nodes to reach walks up to height 17, and the live tree never has that shape. The specification predicts every edge call, the order record, all 0x48 bytes of each entry and any panic Location.

Every conditional, set, cmov, immediate and non-stack field displacement of the cycle and the driver was then flipped, one at a time, and the cases rerun.

## Results and limitations

| Metric | Value |
| --- | --- |
| Cycle cases | 147 |
| Driver cases | 41 |
| Mismatches, all runs | 0 |
| Cycle outcomes | balance short 6, gates closed or no key 23, order placed 105, panic 10, price conversion failed 3 |
| Runs with the network argument set to 1 that differ | 0 |
| Instructions stepped | 73,757 |
| Stepped / total, cycle | 539 / 555 |
| Stepped / total, driver | 234 / 250 |
| Stepped / total, top of book reader (not mutated) | 69 / 124 |
| Mutants killed / survived / unreached | 277 / 25 / 4 |

The 25 survivors and 4 unreached rows each have a reason in `mutations.tsv`, in five groups:

- The unused `0xff` walk in the driver.
- The two copies of the `year <= 0` arm of the time conversion, since such a time clamps to 0.
- The sign shift after that arm.
- The bound `cmp rsi, 8` of the tree descent, which height 8 never reaches.
- The overflow arm of `limit`, since `raw / tick * tick` cannot exceed `raw`.

The first mutation pass found real gaps that later cases closed: the first time word against the nanos word, operands just over 32 bits for three divisions, a wrong balance node length, the initial event vector, and a leap-century year.

Open points:

- All states are built by the harness. No live config, entry or book was seen, and no live rate of this path is known.
- Which user-facing action or state fills the tree at `+0x3a00` is not traced.
- Whether the tree at book `+0x80` holds bids or asks is open, so the sample's side is too. `0x26e0570` tags the first value with byte 0 and the second with byte 1, which does not settle it.
- The stubbed callees are not checked here. `0x230b590` is one of the copies in the open RE-004 tick ladder packet (#36), `0x1447130` appears in `RE-001-heartbeat-status-94`, and `0x375e190` was read by hand only: a non-finite input gives status `0xac`.
- The transfer's flag 1, the span's timing body and `+0x38d0`'s value are not read.
- The lookup `0x371b3a0` is stubbed, so what a missing user returns is not settled.

No progress gate is requested.

Next question: which handler writes the tree at exchange `+0x3a00`, and what are its key and wire fields? A byte scan for displacement `0x3a10` gives `0x4d78460`, `0x3751e80` and `0x4ce8310` as leads, unchecked.
