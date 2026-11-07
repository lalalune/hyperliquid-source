# RE-014: funding premium body 0x44d9060 on node #115, rebuilt as a rule list and proven against the bytes

This packet makes the premium half of the #115 funding step reconstructible: the 1,188-byte body at `0x44d9060` (asset check against the perp
metadata, size-decimals scaling of the oracle word, impact notional choice, mid or impact-gap formula, hl-only divide by 100, clamp to
plus or minus 0.5, three-word output record) is now written as an executable rule list (`spec_premium`) that agrees with the real bytes on 14,019 cases,
and the funding owner object that this body and the rate body of the previous packet (`0x44d8590`) both read is mapped field by field.

- Component ID: RE-014 (validate a bounded reusable implementation against #115)
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: 7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6 / none used (the #94 funding premium packet, deleted by the migration commit, was
  only a lead; every address, constant, offset and branch below was re-read from #115 bytes)
- Claim status: observation for the rule list agreeing with the instruction bytes on the generated inputs and for every table; inference for the names of
  fields and for what the two stubbed helpers compute; unresolved items are listed under Results and limitations
- Scope included and excluded: included is the one FDE `0x44d9060..0x44d9504` and the field accesses of the rate body `0x44d8590..0x44d8a0f` (table
  only). Excluded and stubbed at the call edge: hash `0x47172c0`, index probe `0x3ed2180`, book impact walk `0x46a6370`, and the panic and
  `std::sync::Once` slots. The caller (only a stored pointer) is unresolved.

## Reproduce

From the repository root on Linux with Python 3 and the pinned binary in place:

```
python3 tools/artifacts.py verify
python3 tools/funding_premium115.py --out research/work-items/RE-014-funding-premium-115
python3 -m unittest tests.test_funding_premium115
(cd research/work-items/RE-014-funding-premium-115 && sha256sum -c MANIFEST.sha256)
```

The tool checks the input SHA-256 first, never runs the binary, calls no external program, and reads ELF bytes through `tools/elf_index.py`
and `tools/fde_extents.py`. It takes about 80 s and about 280 MB of resident memory. Cases are built, run and compared one at a time; only counters and
every third sample row are kept. Two runs with different hash seeds and time zones write byte-identical files. The tool also takes `--cases N`
(default 14000) and `--no-mutants`.

## Evidence

Coordinates are virtual addresses of the #115 image.

### Boundaries and reachability

| Item | Value |
|---|---|
| Premium body FDE | `0x44d9060..0x44d9504` (1,188 bytes, 274 decoded instructions) |
| Pointer slot | `.got` `0x64e5f70` holds the entry (the rate body's slot is `0x64e7898`); see `pointer-slots.tsv` |
| Direct callers of the body | none (`direct-callers.tsv`), so it is reached through the stored pointer like the rate body |
| Book impact walk `0x46a6370` | two direct call sites, both inside this body (`0x44d91ec`, `0x44d9201`) |
| Index probe `0x3ed2180` | 43 direct call sites in total, one inside this body (`0x44d9185`) |
| Panic locations | decoded from Location records: `l1/src/perp_meta.rs:163:38` (asset not in metadata), `l1/src/perp_meta.rs:287:28` (six minus size decimals), `z_vendor/indexmap/src/map.rs:762:26` (map entry out of range) |

### Rule list read from the instructions (all constants are read from the bytes, `constants.tsv`)

Arguments: rdi output record, rsi owner, rdx asset, rcx oracle word, r8 book, r9 perp metadata. Return value is the output pointer.

1. `dex = asset / 10000`, `local = asset % 10000`. The body needs `dex == meta[+0x50]` and `local < meta[+0x10]`, otherwise the panic at
   `0x64768a8` (through slot `0x64df830`). The division is the multiply-high by `0x346dc5d63886594b` then `shr 11`.
2. `sz = byte at meta[+0x08] + local * 0x20 + 0x1d`. `sz >= 7` panics at `0x6478258`. The scale is the double at `0x7bb520 + 8 * (6 - sz)`,
   which holds 1, 10, ... 10^6.
3. `oracle = f64(oracle word as unsigned) / scale`. The unsigned conversion is the exact two-lane magic-constant sequence (constants listed). If the oracle is
   `0.0` the result is None (output word 1 set to 0, words 0 and 2 untouched); when the process-wide Once word `0x64f01d8` is nonzero the `Once` slow path
   slot `0x64df9f0` is called first (closure chain checked by the stub).
4. Impact notional: owner index map (entries at owner `+0x08`, length `+0x10`, 24-byte entries with the key at +8 and the value at +16, hasher words at
   `+0x38/+0x40`). Length 0 gives the default at owner `+0x148`; length 1 compares the single key without hashing; length 2 or more hashes and probes, and a
   probe index at or beyond the length panics at `0x6493b30`. A missing key gives the default (an override of 0 is used as 0).
5. The book walk runs twice with the same notional, first on `book+0xa8` then on `book+0xc8`, even when the first returns 0. Either result 0 gives
   None (word 1 = 0).
6. Owner byte `+0x168` selects the formula.
   - nonzero: `(max(first - oracle, 0) - max(oracle - second, 0)) / oracle`, where `first` and `second` are the raw words converted and divided by the scale;
   - zero: `((first + second) * 0.5) / oracle + (-1.0)`; the sum is formed as `(a + b) * 0.5` when both magnitudes are at most `0x7fdfffffffffffff`, else
     `a * 0.5 + b * 0.5` (the two arms are arithmetic-equivalent for u64 inputs, so the selector is never visible).
7. If the asset is in the hl-only set (B-tree set of u64 at owner `+0x150`, height `+0x158`, keys at node `+0x08`, length u16 at `+0x62`, edges
   at `+0x68`) the premium is divided by 100.0, before the clamp.
8. A finite premium is clamped to `[-0.5, 0.5]` (`maxsd` with -0.5, then `minsd` with 0.5).
9. Output record: word 0 premium bits, word 1 first impact word, word 2 second impact word.

### Shared funding owner layout

`owner-fields.tsv` lists every register-plus-displacement access of this body and the rate body. Read together: the rate body's three index maps sit at
`+0x48`, `+0x90`, `+0xd8` and its sample store at `+0x120` with the default clamp at `+0x140`; this body's override map is at `+0x00` (entries `+0x08`,
length `+0x10`), the default impact at `+0x148`, the hl-only set at `+0x150/+0x158` and the formula byte at `+0x168`. The two bodies therefore read one
owner object of at least `0x170` bytes. (Inference: the object is the funding tracker; names come from the previous packet's reading and the #94 packet's
struct string, which was not re-checked on #115.)

## Implementation and comparison

Python rule list, no Rust yet ("Rust implementation: not yet implemented"). The evaluator in `tools/funding_premium115.py` decodes and runs the real
body bytes (x86-64 integer, scalar and packed SSE2 subset) on a heap and stack it owns; hash, probe, book walk, panic and `Once` slots are recording stubs that
check their arguments (registers, key bytes, side offset, location, closure chain) and return model values. A separately written rule list predicts the output
record, the panic, and the exact sequence of stub calls.

| Metric | Value |
|---|---|
| Cases (18 named + 14,001 generated) | 14,019 |
| Mismatches | 0 |
| Distinct instructions reached | 270 of 274 |
| Negative controls (24 wrong readings + 15 structural) | 39, all detected |
| Byte mutants (conditions, immediates, field displacements of reached instructions) | 87 edited, 85 killed |
| Unit tests | 29 |

Cases cover the asset check (wrong dex, local equal to the row count, 64-bit asset), decimals 0..8, oracle words including 0, 1, 2^53 ± 1, 2^63, 2^64 - 1, both formulas,
override maps of length 0, 1 and 2..5 with hit, miss and out-of-range probe index, hl-only sets from empty to height 2 with stale slots past a node length,
impact values near, above and below the oracle, zero on either side, and the Once word zero or nonzero.

The 24 wrong readings (each changes at least one case, listed with refusal counts in `variants.tsv`) include the reference-style `(mid - oracle) / oracle`,
clamp before the hl divide, no clamp, a wider band, oracle zero giving a zero premium, ignoring the size decimals, inverted formula selector, no floor in the
gap formula, swapped sides, skipping the second walk after a zero, ignoring overrides, first-entry-only lookup, swapped output words, asset checks relaxed,
decimals limit 8, divisor 10, signed oracle conversion, and the Once call made unconditionally. The 15 structural controls cover a wrong digest, a
mid-function address, a NOBITS address, a truncated window and section table, missing stub models, an int3 entry byte, four tampered constants, and out-of-range
inputs.

Mutant survivors: the two edits at `0x44d9377` (`cmp ecx,3`) and `0x44d937a` (`jne`) only move the finite-sum selector between two arithmetic-identical arms for u64 inputs.

## Results and limitations

Observed: everything under Evidence and the counters above (machine-readable in `measure.json` and `evidence.json`). No progress gate is requested.

Inference: field names; that `first` and `second` are the impact bid and ask prices; that 0.125 and 0.04 style factors of the rate body make the
premium an 8-hour quantity, which this body does not show.

Unresolved:

- The book impact walk `0x46a6370` (1,260 bytes, only called from this body), the hash `0x47172c0` and the probe `0x3ed2180` are stubbed; their return
  values are model values.
- The caller: only the `.got` slot `0x64e5f70` (and `0x64e7898` for the rate body) is known; who stores the premium and who builds the owner object is not shown.
- The `Once` closure body is not read; the result is None either way.
- Evaluator floats use Python doubles with x86 NaN rules for scalar arithmetic; NaN is unreachable here (all intermediate values are finite for u64 inputs).
- #94 comparison: the #94 premium body had the same structure with different addresses, panic lines (194/319 there, 163/287 here) and helper addresses.
  Nothing from #94 is counted as a #115 finding.

Next question: reconstruct the book impact walk `0x46a6370` (its two call sites are both here) and the writer of the owner object behind
slot `0x64e5f70`, then connect both bodies to the step that stores the returned premium words.
