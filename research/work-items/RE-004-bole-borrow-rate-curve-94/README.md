# RE-004: BOLE utilization and the kinked borrow rate: fixed point arms, rounding, overflow words, info row

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included are the whole functions `0x3741520`, `0x37412a0`, `0x3741010`, `0x3741160`, `0x2a32d40`, `0x2a290f0`, with mutants. The 128 bit divide (slot `0x576e1a8`) is a stub with its arguments compared. Excluded: who writes the share and index words, how the four rate strings become words, what `0x324bdf0` does with the two integer results.

## Reproduce

From the repository root:

```
python3 tools/bole_borrow_rate.py --out research/work-items/RE-004-bole-borrow-rate-curve-94
python3 -m unittest tests.test_bole_borrow_rate
```

The tool takes about 40 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `function-rows.tsv`, `call-sites.tsv`, `constants.tsv`, `power-tables.tsv`, `field-names.tsv`, `writer-site.tsv`, `reciprocals.tsv`, `shadowed-guards.tsv`, `fault-only-rows.tsv`, `curve-samples.tsv`, `ratio-edges.tsv`, `outcomes.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs.

| Function | Rows | Reached through | Result |
| --- | --- | --- | --- |
| `0x3741520` | 176 | slot `0x5774b68`, 4 sites | xmm0 = rate as f64 |
| `0x37412a0` | 174 | one direct call | rax = rate / 1e10 |
| `0x3741010` | 104 | one direct call | out: byte 0 tag, byte 1 code, `+8` u / 1e10 |
| `0x3741160` | 102 | slot `0x5775520`, 1 site | out: byte 0 tag, byte 1 code, `+8` u as f64 |
| `0x2a32d40` | 269 | slot `0x5774f28`, 2 sites | out: `0x60` byte row |
| `0x2a290f0` | 103 | one direct call, from `0x2a32d40` | out: two tagged f64 totals |

The first four take a token record. Fields read:

| Offset | Role in the code | Serde name |
| --- | --- | --- |
| `+0x40`, `+0x58` | a, ia: product gives the borrowed total | `totalBorrowed` |
| `+0x60`, `+0x78` | b, ib: product gives the supplied total | `totalSupplied` |
| `+0x80` | rate at u = 0 | `min_rate` (inference, below) |
| `+0x88` | rate at u = 1e14 | `max_rate` (inference) |
| `+0x90` | rate at u = k | `kink_rate` (inference) |
| `+0x98` | k | `kink_utilization` (inference) |
| `+0`, `+8` | tag, ltv word; word is read when the 32 bit tag is 1 | `ltv` |
| `+0x10` | price word | `oraclePx` |
| `+0x18` | balance word | `balance` |

### Utilization

```
B = ceil(a * ia / 1e14)        128 bits
S = floor(b * ib / 1e14)       the function leaves first if b * ib >= 1e14 * 2^64, so S < 2^64
u = min(floor(B * 1e14 / S), 1e14)
```

The borrowed side rounds up and the supplied side rounds down. `ceil` is written as quotient plus a remainder test, so an exact product adds nothing.

The rows that do not reach the last line differ by function (`ratio-edges.tsv`):

| Input | `0x3741520`, `0x37412a0`: u | `0x3741010`, `0x3741160` | `0x2a32d40` row |
| --- | --- | --- | --- |
| S = 0, B < 2^64 | 0 | ok, 0 | u = 0.0 |
| B >= 2^64 | 0 | code 3 | absent (word 2) |
| b * ib >= 1e14 * 2^64 | 0 | code 3 | absent |
| B * 1e14 / S >= 2^64 | 0 | code 3 | absent |

So with S = 1, a borrow of 184467 gives u = 1e14 and the top rate, and 184468 gives u = 0 and `min_rate`. The cut is `2^64 / 1e14 = 184467.44`. `ratio-edges.tsv` prints both, from real runs.

### Rate

```
if u == k:  r = kink_rate
if u <  k:  f = floor(u * 1e14 / k)
            r = min_rate + floor(f * (kink_rate - min_rate) / 1e14)
if u >  k:  f = floor((u - k) * 1e14 / (1e14 - k))
            r = kink_rate + floor(f * (max_rate - kink_rate) / 1e14)
```

- `kink_rate < min_rate`: every `u < k` gives `kink_rate`.
- `max_rate < kink_rate`: every `u > k` gives `max_rate`.
- `k = 0`: the high arm for every nonzero u. `k >= 1e14`: the low arm for every u below it.
- Both floors round the rate down (`curve-samples.tsv`).

`0x3741520` returns `f64(r) / 1e14`, with the u64 to f64 conversion in two lanes. `0x37412a0` returns `r / 1e10`, by multiply `0xdbe6fecebdedd5bf` and shift 97. `0x3741010` returns `u / 1e10`, by multiply `0x6df37f675ef7` and shift 80. `reciprocals.tsv` proves both for their whole input range: `spare * max_input < 2^shift`, with spare = multiplier * 1e10 - 2^shift.

For `0x3741160`: `f64(u) / 1e14`. Worked example with `min 0, kink 5e12 at 8e13, max 1e14`: 50 borrowed per 100 supplied gives 0.03125, 90 gives 0.525, 100 and 150 give 1.0.

### Guards that plain input cannot reach

The rate function carries overflow branches that its own limits shut, because `u <= 1e14` (`shadowed-guards.tsv`):

- `f` is at most 1e14 in both arms, so its high word is 0.
- `f * span` is at most `1e14 * (2^64 - 1)`, so the guard at `1e14 * 2^64` never fires.
- The sum is at most the arm's end, so the add cannot wrap.
- The high arm needs `k < u <= 1e14`, so `k > 1e14 - 1` never holds there.

The same applies to `a = 0` with a nonzero total and `b = 0` with a nonzero total. To read what those rows do, cases inject a false quotient through the divide stub. Each falls back to: the bend word on the low arm, `max_rate` on the high arm, u = 0 in the rate functions, code 2 in the Result functions, absent in the row. `mutations.tsv` marks edits that only an injected quotient kills. `fault-only-rows.tsv` lists rows that plain runs never reach. A flipped branch is caught by plain input anyway, so neither list is the full set of shadowed guards.

### Info row

`0x2a32d40(out, token, owner, meta)` looks the token up in a B-tree at `owner +0xd0` (height `+0xd8`, value stride `0xb0`, keys `+0x798`, length `+0x7f2`, edges `+0x7f8`). A miss gives word 2. Otherwise:

| Row offset | Key | Value |
| --- | --- | --- |
| `+0`, `+8` | `utilization` | 1, f64(u) / 1e14 |
| `+0x10`, `+0x18` | `oraclePx` | tag, f64(word) / 10^(token 0 `+0x49` - base `+0x48`); token 0 gives 1.0 |
| `+0x20`, `+0x28` | `totalSupplied` | tag, f64(floor(b*ib/1e14)) / 10^(token `+0x49`) |
| `+0x30`, `+0x38` | `totalBorrowed` | tag, f64(floor(a*ia/1e14)) / 10^(token `+0x49`) |
| `+0x40` | `borrowYearlyRate` | `0x3741520` |
| `+0x48` | `supplyYearlyRate` | (1 - f64(`owner +0xc8`) / 1e14) * (rate * utilization) |
| `+0x50` | `balance` | f64(word) / 10^(token `+0x49`) |
| `+0x58` | `ltv` | f64(word) / 1e14, or 0 |

`totalBorrowed` here is a floor, while `B` above is a ceil of the same product. A total has tag 0 when its product is at or above `1e14 * 2^64`. Those products also make the row absent, so with plain input a row that exists has both tags 1. The base token for `oraclePx` is the first row of the token's spot list with `+8` equal to 0 (table stride `0x20`, list at token `+0x58`, `+0x60`). No such row gives tag 0.

Panics: token past the table (slot `0x576e470`), spot id past the table (slot `0x576dfc8`), token 0 `+0x49` below base `+0x48` (slot `0x576e150`).

### Results

| Measure | Value |
| --- | --- |
| Named cases | 302 |
| Vector cases | 750 |
| Mismatches | 0 |
| Rows not reached | 0 of all six functions |
| Mutants killed / survived | 288 / 1 of 289 |
| Unit tests | 58 |

Every run compares the result bytes, the rest of the fixture and the list of divide requests, so a mutant that changes one request dies even when the result stays the same.

### Comparison with the reference

`rg -il kink references/can1357-hl docs` finds nothing, and neither did `research` at the source commit. `l1/exchange/handlers/56_system_bole.rs` covers the action path and `l1/bole/user_state.rs` the user side, and neither holds these rates. This packet is new against it.

### Inferences

These are readings of the observations above, not observations.

- The four rate words are `min_rate`, `max_rate`, `kink_rate`, `kink_utilization`. The serializer `0x1e85a90` writes four strings in that order (`field-names.tsv`, with `max_rate` made by adding `0x9f800` to the `min_rate` word), and `0x3741c4c` copies 32 bytes to record `+0x80` in one step (`writer-site.tsv`). The roles in the code match that order. No read here links the strings to the words.
- `+0x40` and `+0x60` are shares and `+0x58` and `+0x78` are indices in 1e14 units. Only the products are named by keys.
- `owner +0xc8` is a share kept back from borrowers' interest, in 1e14 units. Its name is unknown. A value above 1e14 gives a negative `supplyYearlyRate`, and no guard in these functions stops that.
- The words are yearly rates, because the info key says so and the function applies no time scale.
- `rate / 1e10` and `u / 1e10` are in units of 1e4, likely basis points.
- The name BOLE and the reading as a borrow and lend market come from the reference and the key names.

## Implementation and comparison

Not yet implemented in Rust. The comparison is real bytes against a rule list written from an instruction read. Tree spare key slots hold the searched key, sibling values differ from the target, and filler is a non-periodic ramp. Tests hold literal expected numbers, not calls to the rule list.

## Results and limitations

- The survivor is one dead store, with its reason in `mutations.tsv`.
- Mutants edit branch conditions, immediates and field offsets. They do not swap arithmetic operators. Those rest on the vectors and on divide request compares.
- The vectors are samples, not a proof over all eight words. The two reciprocals and the shadowed guard bounds do hold for the whole domain.
- Bytes for a total or a price with tag 0 are stale registers and are not compared.
- The divide is a stub, so the real `__udivti3` bytes do not run here.
- Pairing of serde keys to row offsets was read from rows `0x2a35be5` to `0x2a35cd1`. The tool pins the key text, not the pairing.
- Trees in the fixtures have height 0 and 1.
- Which values real records hold is not known, so reachability of the cut, of inverted configs and of a share above 1e14 is not claimed.

Next question: which writer moves the index words `+0x58` and `+0x78`, how does it use the yearly rate, and what does `0x324bdf0` compute from `rate / 1e10` and the two utilization results?
