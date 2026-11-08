# RE-006: node #115 open-interest at-cap test 0x44883f0 with its sum fold 0x37c1480 and ring search 0x45547e0, rebuilt and checked on the real bytes

This packet lets a reconstruction decide, for one dex row and one asset id, whether node #115 treats the asset (or the whole dex) as at its open-interest cap: a stored asset set when the mode word is the niche value, otherwise a per-asset notional test against `floor(0.9 * cap)` followed by a dex-wide notional sum tested against `floor(0.9 * total cap)`, including every early `true`, both panics, and the iterator side effect of the sum fold. The rule is an executable Python specification that matches the real instruction bytes of all three functions on 12,600 cases with 0 mismatches, and 52 of 52 negative controls are detected.

- Component ID: RE-006 (book state transitions; the test is the predicate behind the block step named `cancel_aggressive_orders_at_oi_cap`)
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: `0781ce04826eeefd89fe336cb8ea073be0c1de30` / none used. `references/can1357-hl` was not consulted for this packet.
- Claim status: observation for everything in Evidence (ELF bytes, and an evaluator of those bytes against a separately written specification). Inferences and unresolved items are marked as such.
- Scope included and excluded: included, run as real bytes with no stubs except the four panic entry slots: the at-cap test `0x44883f0` (254 instructions), the sum fold `0x37c1480` (147), and the sorted ring-buffer search `0x45547e0` (92). Excluded: the step hosts (`0x2bdf8f0`, `0x54a9c70`, `0x54b66b0`, each 46-52 KB with the test inlined around it), the sweep that runs after the test (`0x23e4c80`), the other callers of the test, and every writer of the fields the test reads.

## Reproduce

From the repository root:

```
python3 tools/oi_cap_predicate_115.py --out research/work-items/RE-006-oi-cap-at-cap-test-115
python3 -m unittest tests.test_oi_cap_predicate_115
```

The tool takes about 30 s and under 300 MB. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output, and the binary is never executed: it is only read. Two runs under different hash randomisation and time zone settings gave identical bytes.

Generated files: `evidence.json`, `call_sites.tsv`, `cases.tsv` (every 25th case), `mutations.tsv`, `controls.tsv`, `measure.json`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs (`functions` in `evidence.json`).

### Where the test is called

Slot `0x64e5a78` holds the RELATIVE relocation target `0x44883f0` (`slot` in `evidence.json`). `call_sites.tsv` lists six `call [slot]` sites in five caller FDEs and three `mov reg, [slot]` loads, which are the step hosts. The name text `cancel_aggressive_orders_at_oi_cap` is loaded by one `lea` in each of the same three hosts, `0x2bdf8f0`, `0x54a9c70` and `0x54b66b0` (`step_name_sites`). The sum fold has two direct callers, the test itself at `0x4488769` and a second function `0x44868f0` at `0x4487492`. The ring search has 86 direct callers, listed in `call_sites.tsv`.

### The rule (arguments: `rdi` = dex row, `rsi` = asset id; result in `al`)

```
if row[+0x378] == 0x8000000000000000:            # niche word: the stored set is used
    return asset in B-tree set at root row[+0x3d0], height row[+0x3d8]
cap = lookup(cap map at row[+0x4a0] + 0x30, asset)
if cap exists:
    local = asset % 10000
    price = asset_rows[local][+0x20]              # panic bounds at oracle.rs:433:18 when local >= row[+0x158]
    size  = lookup(size map at row + 0xf0, asset) or 0
    if price < 0 as i64:            return true
    if price * size overflows i64:  return true
    if cap < 0 as i64:              panic at qtys/mod.rs:847:1 (message length 0x2b)
    if price * size > floor(cap * 0.9):  return true
sum = fold(row)                                   # None on any failure inside the fold
if sum is None:                     return true
if row[+0x478] < 0 as i64:          panic at qtys/mod.rs:847:1
return sum > floor(row[+0x478] * 0.9)
```

`floor(x * 0.9)` is the double product truncated by `cvttsd2si`, clamped by two double constants (`doubles` in `evidence.json`: 0.9 at `0x459788`, top `2^63` at `0x459360`, low `2^63 - 1024` at `0x458e50`). For a non-negative i64 the product never reaches either clamp, so those two arms and the infinity and NaN guards around them cannot fire (inference from the arithmetic; the survivors below include exactly these guards).

### The sum fold `0x37c1480(iterator, init, context)`

The iterator is three words (row, position, length); the context holds a cache pair and the row. For each position below the length the iterator word is advanced first, then:

1. `asset = row[+0x50] * 10000 + position` with checked multiply and add (panics at pdi.rs:32:14 for both).
2. Price: the cache word when it is non-zero and its key equals the asset, otherwise `asset_rows[asset % 10000][+0x20]` (panic bounds at oracle.rs:433:18).
3. Size from the same size map; an absent size adds nothing and is not tested further.
4. A price that is negative as i64 stops the fold, as does a signed product overflow or a signed sum overflow. The result is then `rax = 0`, and `rdx` holds the running sum, which is the already wrapped sum when the add overflowed.
5. After the last position `rax = 1` and `rdx` holds the sum.

The test calls it with position 0, length `row[+0x10]`, initial sum 0 and a cache price word initialised to 0 (`mov qword [rsp+0x40], 0` at `0x448872e`), so the cache arm cannot be reached through the test. The direct fold cases exercise it.

### Map shapes

Both the cap map and the size map are the same two-form enum, read from the bytes by the test and the fold:

| Form | Marker | Fields |
| --- | --- | --- |
| B-tree map | first word equals `0x8000000000000000` | root at `+8`, height at `+0x10`; node: 11 keys at `+0x08`, 11 values at `+0x60`, length u16 at `+0xba`, 12 edges at `+0xc0`, size `0x120` |
| Sorted ring buffer | first word is any other value (the capacity) | buffer at `+8`, head at `+0x10`, length at `+0x18`; 16 byte entries (key, value) searched by `0x45547e0` as two slices |

The stored set is a B-tree of keys only (keys `+0x08`, length u16 `+0x62`, edges `+0x68`, size `0xc8`). `fields` in `evidence.json` lists every offset above.

## Implementation and comparison

Rust implementation: not yet implemented. The reconstruction here is the Python specification `spec_pred` / `spec_fold` in the tool, written from a full instruction read and kept apart from the evaluator. The evaluator `Machine` runs the real bytes of the three functions; `Harness.build` lays out the dex row, both map forms (B-trees of height 0 to 2, rings with wrap and spare slots), the asset rows and the iterator from the offsets above, filling unused slots with the searched key or `u64::MAX - 2` so a wrong length field is visible. Each run checks the result word, the panic Location words, the iterator position, the fold's second return word, and that no byte of the heap image other than the iterator position changed.

| Family | Cases | Content |
| --- | --- | --- |
| predicate | 7,200 | random worlds: set mode, cap maps, size maps, prices and caps at special values (0, 2^62, 2^63-1, 2^63, u64 max), dex numbers that overflow the id arithmetic |
| fold | 3,600 | direct runs with a start position, a length past the row count, an initial sum near i64 max, a live cache pair |
| edge | 1,200 | one asset whose notional is within two units of `floor(0.9 * cap)`, and a dex total within two units of its own line |
| far | 600 | assets whose index inside the dex is 1000 to 1499, which separates `% 10000` from smaller moduli |

Negative controls (52): 33 deliberately wrong specifications (cap factor 0.8, 0.95 and 1.0, round and ceil instead of floor, `>=` for `>`, signed and unsigned compares, skipped panics, wrong map key, wrong row, fold start and length shifts, ignored cache, absent size priced, wrapped product or sum, and others; `controls.tsv`), 12 corrupted code bytes (an inverted branch picked evenly from the killed branch mutants) and 7 out-of-range inputs (flipped digest, address outside every section, non-FDE start, address before every FDE, decode that ends inside an instruction, step limit, write outside heap and stack). All 52 are detected.

A separate sweep flips every branch, `set`, `cmov`, immediate and field displacement of the three functions one at a time (221 mutants), each over the first 24 cases that reach it.

## Results and limitations

| Metric | Value |
| --- | --- |
| Cases | 12,600 |
| Mismatches | 0 |
| Instructions stepped | 2,490,481 |
| Stepped / total: at-cap test | 247 / 254 |
| Stepped / total: sum fold | 142 / 147 |
| Stepped / total: ring search | 92 / 92 |
| Negative controls detected | 52 / 52 |
| Mutants killed / survived / unreached | 200 / 21 / 0 |

The 21 surviving mutants (`mutations.tsv`) were not probed one by one. By class: the infinity and NaN guards of the double cast (`0x44886e6`, `0x4488721`, `0x448870d`, `0x44887bd`) cannot change a result for a non-negative i64, as above; the cache word store `0x448872e` only matters if the uninitialised key word at `rsp+0x48` equals an asset, which the harness leaves at the stack mark; the rest are search start and position immediates of the ring search (`0x4554836`, `0x4554874`, `0x45548aa`, `0x45548e5`, `0x4554872`) and field displacements and immediates whose alternate value was not separated by the sampled cases. They carry no claim of this packet.

Limits:

- The three step hosts are 46-52 KB functions with the test inlined around the call, and the sweep `0x23e4c80` walks a different B-tree node layout (`0x4b8` byte nodes, edge arrays at `+0x4b0`). Neither is run or modelled here, so which ids the step keeps and what the sweep cancels is not reconstructed by this packet.
- Five other caller FDEs of the test (`0x23e0ef0`, `0x2eec960`, `0x44868f0`, `0x58ef750`, `0x58f1c20`) and the second fold caller `0x44868f0` are listed but not read.
- Writers of the mode word, the cap map, the size map and the stored set are not identified, so what the fields mean in game terms is inference only: the size map is probably open interest by asset and the fold the dex-wide notional, from the arithmetic alone.
- Trees of height 3 or more are not built, and map and set sizes stay below 25 items.
- The earlier #94 packet RE-006-oi-cap-aggressive-cancel-94 (no longer in main) was used only as a clue for the question; no address, offset or behaviour was carried over, and every one above was read from the #115 bytes.

No progress gate is requested.

Next question: what do the step hosts do with a true result for each asset, and what fills the cap map and the size map?
