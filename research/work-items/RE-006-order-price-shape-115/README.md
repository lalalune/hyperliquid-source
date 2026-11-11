# RE-006: node #115 order price shaping function (0x5a21510 and two copies): reference move, 1.1/0.9 tick-grid limit, value tests and the accepted record

This packet lets the Rust reconstruction write the whole order price shaping step of node #115 from a table: how a stored order request is turned into a limit price (reference choice, move by amount or by fraction, 1.1 or 0.9 factor, tick grid), which tests refuse it with which status word (`0x19c`, `0xde`, `0x6d`, `0x6c`, `0xc8`, `0x78`, `0x63`) and which payload, and which fields the accepted record carries, because the function bytes were run as real instructions over 21,618 cases against a separately written specification with 0 mismatches, and 179 negative controls were all either separated or shown equivalent. It also answers the next question of the merged band-gate packet (`RE-004-order-band-gates-115`): the three other writers of status `0x63` are this function and its two copies, and the band they run is the same ratio test, applied to the final limit price against the shaped reference.

- Component ID: RE-006 (book state transitions: the order path before `insert`); touches RE-004 (price band, minimum value)
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference tree text was used.
- Claim status: observation for the bytes, the status words, the field offsets and the arithmetic; inference for every name (side, size, reference, tick, available amount, system user); unresolved items are listed below.
- Scope included and excluded: included, run as whole functions with real instructions, are `0x5a21510` (first copy), `0x5a21ed0` (second copy) and `0x2d3a160` (third copy). Stubbed at the edge, each checking its arguments: the user test (slot `0x64e6a80`, target `0x421a3c0`), the reference lookup (`0x5aed270`, `0x5aed4a0`, `0x2753840`), the market and second-table drop calls (`0x44e0810`, `0x42320d0`), the step drop (`0x5a4a6f0`, `0x2df6730`), the tick function (`0x5a01110`, `0x2891f50`), the available-amount slot (`0x64e4e88`, target `0x3d19870`), the second lookup (`0x5aed180`, `0x5aed090`, `0x2753750`), the gate slot (`0x64e5a98`, target `0x44881b0`), the band exemption slot (`0x64e5ae8`, target `0x421a520`), the stamp slot (`0x64e8100`, target `0x3d4f3e0`), `round` (slot `0x64e1890`, target `0x63efe40`) and the two panic slots. Excluded: the bodies of all of those, and the callers of the function. No progress gate is requested.

## Reproduce

Working directory is the repository root. Platform Linux x86-64, Python 3.12, standard library only. The binary is read as bytes and never run.

```
python3 tools/artifacts.py verify
python3 tools/order_price_shape_115.py --out research/work-items/RE-006-order-price-shape-115
python3 -m unittest tests.test_order_price_shape_115
```

The tool refuses an input whose SHA-256 differs. It uses `tools/elf_index.py` and `tools/fde_extents.py` through the copied evaluator, calls no external program, and its output is byte-identical between runs and output folders. About 130 s and under 1 GB. `MANIFEST.sha256` lists every file here except itself.

## Evidence

Addresses are virtual addresses; `.text` and `.rodata` equal file offsets. Function ends come from the FDE of each start (`evidence.json` `functions`): first `0x5a21510..0x5a21ed0` (2,496 bytes, 527 instructions), second `0x5a21ed0..0x5a22890` (527), third `0x2d3a160..0x2d3ab3b` (2,523 bytes, 534).

### Copies

`copies.tsv`: the second copy has the same instruction sequence as the first; 10 rows differ, all of them a state displacement or a call target. The state fields move as follows (first copy / second copy): market list pointer `+0x7c8` / `+0x1338`, market count `+0x7d0` / `+0x1340`, second table count `+0x3ad0` / `+0x4640`, date triple `+0x4294..` / `+0x4e04..`, limit `+0x4228` / `+0x4d98`, band value `+0x4220` / `+0x4d90`; the reference lookup is `0x5aed270` / `0x5aed4a0` and the second lookup `0x5aed180` / `0x5aed090`. The third copy is a recompilation with other register use (534 instructions) and the state offsets of the first copy; its callees are `0x2753840`, `0x2753750`, `0x2df6730`, `0x2891f50`, and its system-user byte strings sit at `0x5f7170` and `0x5f7184` instead of `0x93e30b` and `0x93eb11`. All three give identical results on all 7,206 cases each.

### The rule (arguments: `rdi` out, `rsi` request, `rdx` user, `rcx` state)

Request words: `+0x00` flag byte (the whole word is copied to the accepted record), `+0x08` amount or fraction, `+0x10` asset id, `+0x18` size, `+0x20` optional reference (0 = absent), `+0x28` side byte, `+0x29` second flag byte. Output word `+0x00` is 1 for every refusal and 0 for the accepted record; the status word is at `+0x10`.

1. User test (slot `0x64e6a80`): nonzero gives status `0x19c`.
2. Market index `asset / 10000` must be below the market count (else a panic with the text at `0x7d3212`). The reference lookup runs with the market, a copy of the user, the asset, the size, the second flag and the state (stack argument). A first word other than `0x1a2` is passed through: the 0x70 byte lookup record is copied to `out+0x10`.
3. The second table must also cover the market index (panic text `0x7c95fa`), then the mark row `asset % 10000` is read (stride 0x60, market `+0x150` rows, `+0x158` count, panic through slot `0x64df620` past the count); its price at row `+0x20` is `row`.
4. `ref = optional reference or row`. The row is taken as stop price and as reference when `ref == row` or `((row < ref) xor side) & 1`; else the reference is `ref` and the stop price 0.
5. Move: flag byte nonzero = by amount. Side nonzero: `ref - amount`, status `0xde` when that is zero or negative; side zero: `ref + amount`, `0xde` on overflow. The `0xde` record copies the stale lookup record around the status word. Flag byte zero = by fraction: `ref' = round_away((amount / (+-100000.0) + 1.0) * float(ref))`, minus for side nonzero, then NaN and negative to 0, infinity to 0, values above 2^64 to 2^64, saturating u64, at least 1.
6. Limit: `price = same cast chain of (1.1 for side 0, 0.9 otherwise) * float(ref')`; `q = price / tick`; side nonzero adds one whole tick (`q + 1`, saturating), side zero keeps `q`; `price = q * tick`, all-ones on overflow, at least 1. The tick function is called with the market, the asset and the pre-grid price.
7. `top = max(row, price, ref')`. `top * size` above `0x1999999999999999` (or overflowing) gives status `0x6d`; the payload at `+0x18` is a stale register after the tick call and is not compared.
8. Available amount (slot `0x64e4e88`, called with the market, 1 + user bytes, the asset and 10): `price * size` above it gives status `0x6c` with payload `float(available) / 1000000.0` at `+0x18`. The extra caps `price * size > 0x7ffffffffffffffe` in this test are dominated by step 7.
9. Second lookup, then the gate slot (`0x64e5a98`, with side). If the gate returns zero: `chosen = max(price, q0)` for side nonzero, `min(price, q1)` for side zero, taken only when that word is nonzero, else `price`; `chosen * size` overflowing, above `0x7ffffffffffffffe`, or at most `9,999,999` (`0x98967f`) refuses with status `0xc8`, unless the user is 20 bytes of `0xff` or of `0xee` and the product fits and is at most `9,999,999`. The `0xc8` record: `+0x14` asset word (`asset` up to `0x270f`, `asset + 100000` up to `0x5f45a5f`, else `0xffffffff`), `+0x18` = `0x8000000000000001`, `+0x20` = 10.0. A gate of 1 skips this test.
10. Time test: the date triple at state `+0x60` (signed first word) against the one at `+0x4294` (lexicographic), then `now` (`+0x28`) against the limit `+0x4228`. If the first is below the second, or now is below the limit, the status is `0x78` and byte `+0x12` is `now >= last + 5000` (`last` at `+0x10`, saturating).
11. Band (value `p` at `+0x4220`; exemption slot `0x64e5ae8`): unless exempt, `r = float(price) / float(ref') - 1.0`; accepted when `p > |r|`, or when `r > 0`, `1.0 > p` and `1.0/(1.0 - p) - 1.0 >= r`; else status `0x63` with payload `p * 100.0`. This is the ratio test of the merged band-gate packet, applied to the final limit price and the shaped reference.
12. Accepted record (`out+0x00` = 0): `+0x08` 1, `+0x10` size, `+0x40` 8, `+0x50` 10, `+0x60` `0x8000000000000000`, `+0x98` price, `+0xa0` the stamp slot result (called with the first 12 bytes of the state triple), `+0xa8` second flag, `+0xba` side, `+0xc0` request word 0, `+0xc8` amount, `+0xd0` optional reference, `+0xd8` stop price; words `+0x18`, `+0x28`, `+0x38`, `+0x48` are 0.

### Constants

`evidence.json` `constants` lists the doubles (1.1 at `0x459400`, 0.9 at `0x459788`, +-100000.0, 1.0, 1000000.0, -1.0, 100.0, 2^64, 2^63, the largest double below 2^64) and the two system user byte strings.

## Implementation and comparison

`tools/order_price_shape_115.py` holds an x86-64 evaluator (the shared node #115 evaluator family, copied unchanged), the specification (`spec`, with 24 named wrong variants), a harness that lays out the state, markets, mark rows, request, user and output in the evaluator heap, and the case groups. Each run compares the 0x100 output bytes, the return word, and the ordered log of every edge call with its arguments. A stub that receives a wrong market, asset, size, tag or stack argument fails the run. Rust path: not yet implemented; the specification is Python and is the reference for a later port.

Case groups (per copy, 7,206 each): named 26, step 252, fraction 180, tick 156, value 322, available 144, gate 1,344, asset word 12, time 800, band 448, zero size 1,728, top 48, equal band 62, cap edge 20, zero reference 64, random 1,600.

## Results and limitations

Unit tests: 55, 0 skipped (`tests/test_order_price_shape_115.py`: arithmetic, specification tables, exact output records on all three copies, group samples, negative controls).

| Metric | Value |
| --- | --- |
| Cases (real-byte runs, three copies) | 21,618 |
| Mismatches | 0 |
| Negative controls | 179 |
| Separated | 169 |
| Equivalent (reason in `equivalent-mutants.tsv`) | 10 |
| Not separated | 0 |

Controls: 120 byte mutants of reached instructions in the first copy (condition flips and immediate bit flips; 112 killed, 8 equivalent), 24 wrong specifications (`wrong-implementations.tsv`), 30 corrupted constants (flip in 15 constants; 28 separated, 2 equivalent), 5 rejected inputs (wrong digest, unknown case field, address outside every section, function start plus one, `.bss` address). Three further instructions are not mutated because their effect needs a market index near 9,996 that the harness cannot place (`not-mutated.tsv`).

Limits:

- All callees are stubs. In particular the reference lookup, the tick function, the available-amount slot, the gate slot, the exemption slots and the stamp slot are not read here; the names "available", "gate" and "system user" are inferences from how the function uses them.
- The payload of status `0x6d` is a stale register after the tick call and is not compared. The stale bytes around the `0xde` and pass-through records come from the lookup stub's fill and are compared.
- Mutants run on the first copy only; the other two copies run the same cases against the same specification.
- Side bytes above 1 are run (bit 0 decides the reference choice, nonzero decides everything else) but are probably not produced by the caller.
- Which callers reach this function and what the status words mean to the user were not traced.

Next question: read the gate slot target `0x44881b0` and the lookup `0x5aed270`, which decide the second word pair `q0`/`q1` and the reference record that this function consumes.
