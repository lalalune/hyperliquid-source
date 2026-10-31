# RE-007: `distribute_funding` step: bucket gate, rate map, per-dex residual and premium reset

This packet shows what the block step `distribute_funding` does around the per-user worker, so a reconstruction can now write the step's gate, its rate map, the order of work per dex, and the rule that charges the sum of all user rows to one user: the row with the largest value in address order, on cross balance or isolated margin.

- Component ID: RE-007 (risk, oracles, liquidation), funding settlement path
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985 / 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for bytes, layouts, order of operations and constants; inference for the meaning of summary row fields and for units; unresolved items are listed under Results and limitations
- Scope included and excluded: included are the bucket gate in 3 block hosts, 3 step hosts up to their second clock read, 3 rate map builders, the shared per-dex body `0x3703f20` with its summary map, row vector and flatten helpers, and the row consumer `0x4856fc0`. Excluded is the per-user worker behind the rayon bridge `0x38dc6a0`. That worker, `0x3757610`, has an open byte-binding PR (#753), so this packet does not model it and takes its output as given summary rows. Also excluded are the shared timing tail after the second clock read and the rate formula, which is in #860.

## Reproduce

From the repository root, on Linux with Python 3 and the pinned binary in place:

```
python3 tools/artifacts.py verify
python3 tools/distribute_funding.py --out research/work-items/RE-007-distribute-funding-94
python3 -m unittest tests.test_distribute_funding
sha256sum -c MANIFEST.sha256   # inside the folder
```

The tool takes about 120 s on an idle machine and checks the input SHA-256 first. It reads ELF bytes in Python through `tools/elf_index.py` and `tools/fde_extents.py`, with no objdump or readelf output. It never runs the binary. All numbers below come from `evidence.json` and `mutations.tsv`.

## Evidence

Coordinates are virtual addresses.

### Path and copies

The block host loads `"distribute_funding"` (length 0x12) into a step record and calls the step host. The next call in all 3 block hosts is a function that names `update_funding_rates`.

| Copy | Block host | Gate | Step host | Rate map | Dex list | Tracker list | Guard |
|---|---|---|---|---|---|---|---|
| primary | `0x22297c0` | `0x22298f6..0x2229a2e` | `0x222bef0` | `0x275eda0` | +0x5c0 | +0x3370 | +0x37c0 |
| second | `0x470e9a0` | `0x470ead6..0x470ec0e` | `0x4715000` | `0x4d8b730` | +0x5c0 | +0x3370 | +0x37c0 |
| recording | `0x47162d0` | `0x4716415..0x471654d` | `0x4712940` | `0x4d8b9e0` | +0x1040 | +0x3df0 | +0x4240 |

The per-dex body `0x3703f20` has no direct caller. It is reached through data slot `0x5773a78` from `0x222c04d`, `0x471515d` and `0x4712ad8`. The rate `0x3750610` is reached through slot `0x5774d48`.

### Names from serializer bytes

- `funding_distribute_guard` names the guard: `lea 0x37c0(%rbx),%rcx` at `0x275ba19` sits directly before the name at `0x275ba20`. The recording copy has the same pair at `0x4d86329` and `0x4d86330` with +0x4240.
- The serializer `0x36f59f0` names the user state block at dex +0xf8:

| Dex offset | Field | Used here |
|---|---|---|
| +0xf8 | `user_to_state` | hash map read by the collect stub and `0x3596940` |
| +0x128 | `open_order_tracker` | not used |
| +0x158 | `users_with_positions` | closure capture, insert and remove arms |
| +0x170 | `asset_to_oi_sz` | passed to `0x36f7350` |
| +0x188 | `aru` | one insert per residual |
| +0x1a0 | `check_all_users_for_liquidatables` | closure capture |

### Bucket gate

1. Block time at exchange +0x60 is three u32 words: chrono date word, seconds of the day, nanoseconds.
2. `millis = days * 86400000 + secs * 1000 + frac / 1000000`, with epoch ordinal 719163 (`0xfff506c5`). Years below 1 shift by 400-year cycles. A value at or below 0 becomes 0.
3. `bucket = millis / bucket_millis` (guard +0). The divide has no zero test, so a width of 0 faults in both the 32-bit and the 64-bit arm.
4. If `bucket > last_bucket` (guard +8), `last_bucket` takes `bucket`.
5. The step record gets the same comparison as its run flag at +0x20. Its +0x10 and +0x18 words are f64 0.25 and 0.05 from `0x206880`, and only the timing tail receives them.

### Step host

1. Flag other than 1: return with no work and no clock read.
2. Build the rate map once for all dexes.
3. If the tracker and dex lists differ in length, call the log hook with code 5 at `l1/src/dex_registry/dex_registry.rs:35:48`, in both the builder and the host. The loops use the shorter length.
4. For each paired dex in list order: clone the map (empty map: pass a null root), call `0x3703f20(out, dex, byte, &time, &map)`, handle the returned rows, then empty every vector in the tracker's `asset_to_premiums` tree at tracker +0xd8. Node vectors are at +0x60 stride 24, and only the length word at +0x70 is zeroed. Capacity and keys stay. The walk visits every entry of a tree of any depth the cases build, up to 2.
5. The third argument is dead: `0x3703f20` overwrites rdx at `0x3703f47` before any read.

Rows differ by copy:

- primary and second free the row vector right after the call.
- recording passes it to `0x4856fc0` through slot `0x5776ad8`, with exchange +0x5b8, the 12 time bytes and the dex.
- `0x4856fc0` tests the word at its first argument +0x808. The value `0x8000000000000000` means no writer: rows are freed. Otherwise it reads a wall clock through slot `0x576e8a0`, converts the rows in `0x454dd50`, and calls `0x47ed710` with variant word `0x8000000000000005`, also when the row list is empty.

### Rate map `0x275eda0`

For each paired dex and each index `j < dex +0x10`:

1. `asset = 10000 * dex_id + j`, with dex id at +0x30. Both steps are checked and panic on overflow.
2. Call the rate at tracker +0x48.
3. Insert `(asset, rate)`. A None rate inserts 0.0.
4. For a None rate with `asset <= 9999` not in the set at dex +0x270 (root) and +0x278 (height), the asset is also pushed to a local vector. That vector is freed unread.

So every asset of every dex has an entry, and None is not kept. The map spans all dexes, and each dex gets its own clone.

### Per-dex body `0x3703f20`

1. Collect user pointers from the hash map, then run the rayon bridge with 5 captures: +0x158, +0x1a0, time, +0x60, rate map.
2. Worker output is inserted into a B-tree keyed by the 20-byte address (`0x33c5500`, `0x33077d0`, `0x33a5e70`, `0x2f646d0`), so all later walks are in unsigned byte order of the address, not in hash or thread order.
3. `0x3bb1150` turns the tree into a vector of 0x50-byte rows: +0x00 cap, +0x08 pointer, +0x10 length of a vector of 0x48-byte rows, +0x18 signed sum, +0x20 tag, +0x28 asset, +0x30 u64 largest value, +0x38 address.
4. `total` is the sum of +0x18 over all rows, also tag 0 rows. On overflow it saturates and calls the log hook with code 0 at `l1/src/qtys/mod.rs:830:1`.
5. `best` is the first row with tag 1 that has the highest +0x30 (unsigned). The first tag 1 row is taken even with value 0, and later rows must be strictly larger.
6. `0x3bafb90` flattens all row vectors in address order. A row with word +0x3c equal to 0 ends its vector. The result is the return value.
7. If there is a best row and `total != 0`:
   - look up the user at +0xf8 and insert the address into `aru` (+0x188)
   - find the position by asset (`0x33bd420`)
   - if position word +0 is 1, subtract `total` from position +0x08; otherwise subtract it from user word +0
   - subtraction saturates and logs at `l1/src/qtys/impl_ntl.rs:62:1`
   - call `0x36f7350(asset, size, size, user +0x20, dex +0x170)`
8. The rate map is dropped on all paths.

Three steps after the subtraction cannot change anything in this path, because the size passed in and out is the same word:

- the leverage compare at `0x370448b` compares a value with itself, so `0x370e6a0` is never called
- the two arms that remove or insert `users_with_positions` run only if the count at user +0x20 moves. The cases force that count through the stub to step both arms.

### Worked values from the real bytes

| Rows (sum, largest) | Largest row | Result |
|---|---|---|
| a -1000 / 40000, b +1500 / 70000, c -493 / 30000 | b, cross | total +7, b balance 6000 to 5993 |
| a +3 / 40000, b -5 / 70000 | b, isolated | total -2, b margin 900 to 902, b balance unchanged |
| a +2 / 70000, b +2 / 70000 | tie | total +4, a balance 5000 to 4996 |

### Reference comparison

`references/can1357-hl` was treated as a lead only. `evidence.json` lists each claim:

- `l1/dex_registry/dex_registry.rs:402` copies values into accumulators. The binary clones a rate map per dex, moves balances and empties premium vectors.
- `l1/dex_registry/dex_registry.rs:487` makes funding due when seconds / 1000 changes. The binary uses the guard.
- `l1/dex_registry/dex_registry.rs:489` updates mark prices next. The binary calls the function naming `update_funding_rates` next.
- `base/bucket_guard.rs:23` puts `last_bucket` first. In memory the divisor word is first and the stored word second.
- `base/bucket_guard.rs:53` has the same stored-bucket rule as the gate.

## Implementation and comparison

Rust implementation: not yet implemented.

A byte-level evaluator in the tool runs the code listed under Scope. A separately written specification in the same tool predicts every stub call and argument, the rows, balances, margins, sizes, premium vectors and the guard. Edge stubs are listed in `evidence.json`.

| Metric | Value |
|---|---|
| Cases | 195 |
| Mismatches | 0 |
| Instructions stepped | 139,020 |
| Stepped / total: gate primary | 71 / 71 |
| Stepped / total: gate second | 71 / 71 |
| Stepped / total: gate recording | 71 / 71 |
| Stepped / total: host primary | 163 / 199 |
| Stepped / total: host second | 163 / 199 |
| Stepped / total: host recording | 172 / 208 |
| Stepped / total: rate map primary | 137 / 157 |
| Stepped / total: rate map second | 137 / 157 |
| Stepped / total: rate map recording | 137 / 157 |
| Stepped / total: per-dex body | 356 / 399 |
| Stepped / total: row vector | 109 / 168 |
| Stepped / total: row flatten | 278 / 401 |
| Stepped / total: row consumer | 77 / 88 |
| Stepped / total: summary map collect | 71 / 124 |
| Stepped / total: summary map extend | 63 / 96 |
| Stepped / total: summary map insert | 139 / 184 |
| Stepped / total: summary map split | 483 / 951 |
| Stepped / total: summary map next | 146 / 224 |
| Stepped / total: position entry | 17 / 104 |
| Mutants killed / survived / unreached | 676 / 113 / 168 |

Mutants flip every condition, `set` and `cmov`, immediate and field displacement. Of these, 113 survive and 168 are unreached. Each row has its reason in `mutations.tsv`.

Negative controls in `tests/test_distribute_funding.py` change the digest, an FDE start, an unmapped section, a field row, a guard offset, a slot, single code bytes and the specification. Each must be refused or seen.

## Results and limitations

Observed: everything under Evidence. No progress gate is requested.

Inference:

- Row field +0x18 is one user's funding sum, and +0x30 is the size of that user's largest position. Then `total` is the rounding left over after all users, and one user absorbs it so the step sums to zero. This rests on the shape of this path. The worker that fills these fields is not modelled here.
- `aru` marks users touched by the step. The name is 3 letters in the serializer and nothing here explains it.
- The log hook `0x358dcd0` reports and returns, because the code after it continues with the saturated value.
- Because the vectors are emptied here and the next call is the rate update, samples of one bucket feed one distribution. This was not traced through the rate update.

Unresolved:

- The live value of `bucket_millis`. The 4-byte immediate 3600000 does not occur in `.text`, so it may come from state. The cases use 3600000 only as an input.
- Which host copy runs in which node mode, and what `0x47ed710` writes.
- What the worker does with the +0x158 and +0x1a0 captures and the rate map. This path only passes them.
- Whether a tie or a sum overflow can happen with real worker output.
- The vacant arm of `0x33bd420`, since the best row names a position of its own user. It is unreached.
- The `std::sync::Once` word at `0x577ab98`. It stores 3 in the file and is process state, so the cases set it to 0, and one case sets it to nonzero to step the side call.

Next question: when #753 lands, what are the exact rules in `0x3757610` for the row sum, and does `+0x30` hold notional or size? Separately, how does the function at `0x2702420` write `asset_to_premiums` under its own guard?
