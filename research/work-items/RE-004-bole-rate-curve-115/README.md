# RE-004: reconstruct node #115 BOLE utilization and the kinked borrow rate from the ELF bytes, with 11,076 compared cases and 164 negative controls

This packet lets a reconstruction write the #115 BOLE utilization and borrow rate as plain 128 bit integer arithmetic (borrowed side rounds up, supplied side rounds down, ratio capped at 1e14, a two slope rate with a bend), including which refusal code each overflow gives and in what order the 128 bit divides are asked, and it shows that the rule list written for the #94 bodies is wrong for #115 in two places: the supply divide now always runs, and the zero-supply-shares refusal is gone.

- Component ID: RE-004 (quantities and rounding), BOLE token arithmetic
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: workspace head `7ff06a097` / reference `references/can1357-hl`, used only as a list of labels to check. The #94 packet `RE-004-bole-borrow-rate-curve-94` (deleted by migration commit `8fd8db680`, read with `git show 8fd8db680^:...`) is a clue and is bound to its own release; nothing of it is claimed for #115 until the rows below show it on #115 bytes.
- Claim status: observation for everything in Evidence (ELF bytes plus an evaluator that runs them); inference where marked; unresolved where marked
- Scope included and excluded: included are the whole functions `0x36a08b0` (utilization, word / 1e10), `0x36a09f0` (utilization, f64), `0x36a0b30` (rate / 1e10), `0x36a0d80` (rate, f64) with 142 byte edits, 16 wrong rule-list switches and 8 structural controls. The 128 bit divide (GOT slot `0x64dfaf8`) is a recording stub that checks its arguments. Excluded: the caller `0x38e64b0` (it calls three of the four, see Inferences), who writes the share and index words, how the four rate strings become words, and the token info row (the #94 row builder has no body of this shape in #115 that this packet could identify). No component gate is requested.

## Reproduce

From the repository root on Linux with Python 3 and the connected `artifacts/node/115/hl-node`. No network, no key, and the binary is never executed.

```sh
python3 tools/bole_rate115.py --out research/work-items/RE-004-bole-rate-curve-115
python3 -m unittest tests.test_bole_rate115
cd research/work-items/RE-004-bole-rate-curve-115 && sha256sum -c MANIFEST.sha256
```

The tool checks the input SHA-256 first, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, calls no external program, parses no objdump or readelf output, and took about 22 s with a peak of 385 MB on this server. Two runs into different folders are byte equal.

Generated files: `evidence.json`, `measure.json`, `function-rows.tsv`, `call-sites.tsv`, `constants.tsv`, `reciprocals.tsv`, `shadowed-guards.tsv`, `curve-samples.tsv`, `ratio-edges.tsv`, `fault-only-rows.tsv`, `delta-against-94-rules.tsv`, `model-variants.tsv`, `structural-controls.tsv`, `outcomes.tsv`, `grid-outcomes.tsv`, `vector-outcomes.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses of the ELF. Function ends are FDE extents (`tools/fde_extents.py`); the decoder must land exactly on each end.

| Function | Bytes | Instructions | Reached through | Result |
| --- | --- | --- | --- | --- |
| `0x36a08b0` | 312 | 99 | direct call at `0x38e6845` | out: byte 0 tag, byte 1 code, `+8` u / 1e10 |
| `0x36a09f0` | 309 | 97 | GOT slot `0x64e8d50`, call at `0x38e686a` | out: byte 0 tag, byte 1 code, `+8` f64(u) / 1e14 |
| `0x36a0b30` | 578 | 165 | direct call at `0x38e6830` | rax = rate / 1e10 |
| `0x36a0d80` | 598 | 167 | GOT slot `0x64e7198`, calls at `0x2a89978`, `0x2f0f6cc`, `0x55a0c58`, `0x55a1758` | xmm0 = f64(rate) / 1e14 |

(`call-sites.tsv` lists these and the divide call sites inside each body; `function-rows.tsv` holds every decoded row with its bytes.)

The first two take `(out, record)` and the last two `(record)`. Fields read from the token record (the same offsets as the #94 packet; the field roles are inference, below):

| Offset | Role in the code |
| --- | --- |
| `+0x40`, `+0x58` | a, ia: product gives the borrowed total |
| `+0x60`, `+0x78` | b, ib: product gives the supplied total |
| `+0x80` | rate at u = 0 (min) |
| `+0x88` | rate at u = 1e14 (max) |
| `+0x90` | rate at u = k (bend rate) |
| `+0x98` | k (bend utilization) |

### Utilization

```
T = ceil(a * ia / 1e14)                  128 bits: q = divide(a*ia, 1e14), plus 1 when a*ia - q*1e14 != 0
err = 3 if T has a high word; else 2 if a == 0 and T != 0; else none
P = b * ib                               128 bits
S = divide(P, 1e14)                      ALWAYS asked, even when P is too big
too_big = (P >> 64) > 1e14 - 1
too_big            -> code err or 3
err                -> code err
low(S) == 0        -> ok, u = 0
q = divide(low(T) * 1e14, S)             S is the full 128 bit quotient
high(q) != 0       -> code 3
else               -> ok, u = min(low(q), 1e14)
```

`0x36a08b0` returns `u / 1e10` by multiply `0x6df37f675ef7` and shift 80, `0x36a09f0` returns `f64(u) / 1e14`. `reciprocals.tsv` proves both reciprocals for their whole input range (`spare * max_input < 2^shift`).

### What differs from the #94 rule list (observation on #115 bytes)

`delta-against-94-rules.tsv` runs the #94 rule list (kept as switch `old94`) against the #115 bytes for the 284 named cases. It disagrees on 24 case-entry pairs:

- the #94 list asked the supply divide only when `P` fitted; the #115 bodies ask it first and test afterwards (the divide count is one higher on `supply one past the word`, `supply just past the word`, `supply product exactly at the guard` and `borrow overflow with supply overflow`, for all four entries; the result bytes are the same);
- the #94 list refused `b == 0` with a non-zero supply quotient (code 2 in the Result bodies, 0 in the rate bodies). The #115 bodies have no such test: with `b = 0` and an injected non-zero quotient they go on to the ratio divide (`result differs` rows). Plain input cannot reach it, because `b = 0` makes `P = 0` and the stub answers 0.

### Rate

```
u = ratio as above, but 0 on any error, on too_big, on low(S) == 0, on high(q) != 0
if u == k:  r = bend_rate
if u <  k:  f = divide(u * 1e14, k)            ; r = min + floor(f * (bend - min) / 1e14)
if u >  k:  f = divide((u - k) * 1e14, 1e14-k) ; r = bend + floor(f * (max - bend) / 1e14)
```

- bend < min: every `u < k` gives bend. max < bend: every `u > k` gives max.
- k = 0 sends every non-zero u to the high arm (k = 0 with u = 0 is `u == k`: the bend rate); k = 1e14 with u = 1e14 is `u == k` too.
- A quotient with a high word, a product at or above `1e14 * 2^64`, or a sum that carries past 2^64 returns the arm's end rate (bend on the low arm, max on the high arm). `model-variants.tsv` shows each reading of these tests refused by a run.
- `0x36a0b30` returns `r / 1e10` by multiply `0xdbe6fecebdedd5bf` and shift 97; `0x36a0d80` returns `f64(r) / 1e14`, with the u64-to-f64 conversion in two lanes (constants `0x4530000043300000`, `0x4330000000000000` in `constants.tsv`).
- `curve-samples.tsv` prints rate words and f64 values for 8 borrowed-per-100-supplied points on two curve shapes; the worked example min 0, bend 5e12 at 8e13, max 1e14 gives 0.03125 at 50 per 100 and 0.525 at 90.

### Guards that plain input cannot reach

`shadowed-guards.tsv`: since `u <= 1e14`, `f <= 1e14`, `f * span <= 1e14 * (2^64 - 1) < 1e14 * 2^64`, so the product guard, the high word test on `f`, the add carry, and (high arm) `k > 1e14 - 1` never fire from plain records. Cases inject a false quotient through the divide stub to read what those rows do. `fault-only-rows.tsv` lists the 6 rows that no plain input reaches (`0x36a092b`, `0x36a092e`, `0x36a0a6b`, `0x36a0a6e`, `0x36a0cd0`, `0x36a0f22`); all other rows of all four bodies are reached by plain input.

### Block walk of two bodies (observation; raw rows in `function-rows.tsv`)

`0x36a08b0` (utilization word), `rdi` = out, `rsi` = record:

| Range | What the bytes do |
| --- | --- |
| `0x36a08b0..0x36a08bb` | push six callee-saved registers and one slot; `r14 = record` |
| `0x36a08be..0x36a08e7` | `r12 = a` (`+0x40`); `a * ia` (`mulq +0x58`) into `rdx:rax`; divide by `0x5af3107a4000` (1e14) through slot `0x64dfaf8`; first divide call at `0x36a08e7` |
| `0x36a08ed..0x36a0917` | `q * 1e14` subtracted from the product, remainder tested (`setne`), added to the quotient low word, carry into the high word (`adc`): the ceil; `bpl = 1` as the refusal flag |
| `0x36a091a..0x36a0930` | high word set: code 3 (`r13b`); else `a == 0` with a non-zero total: code 2; else flag cleared |
| `0x36a0932..0x36a0952` | `ib * b` (`mulq +0x60`), second divide call at `0x36a0952`, always taken: nothing before it tests the flag |
| `0x36a0958..0x36a0981` | `high(P) > 0x5af3107a3fff` (1e14 - 1) into `dil`; or-ed with the flag; `esi` = code (flag ? code : 3) |
| `0x36a0983..0x36a0986` | `low(S) == 0` jumps to the ok-with-zero exit (no b-is-zero test) |
| `0x36a0988..0x36a099a` | `low(T) * 1e14` divided by the 128 bit `S`: third divide call at `0x36a099a`; `sil = 3`, high word of the quotient tested at `0x36a09a3` |
| `0x36a09b4..0x36a09cb` | `min(q, 1e14)` by `cmovb`; multiply by `0x6df37f675ef7`, shift right 16 of `rdx` (total shift 80): u / 1e10 |
| `0x36a09a8..0x36a09ac`, `0x36a09ce..0x36a09d4` | error exit stores the code at `out+1`, tag 1; ok exit stores the word at `out+8`, tag 0; `rax = out` |

`0x36a0b30` (rate word), `rdi` = record:

| Range | What the bytes do |
| --- | --- |
| `0x36a0b30..0x36a0b64` | same borrowed product and first divide (call at `0x36a0b64`) |
| `0x36a0b6a..0x36a0ba6` | ceil, then `r15b` = refusal flag: set when the total has a high word, or `a == 0` and the total is non-zero |
| `0x36a0ba9..0x36a0bcc` | supplied product and second divide (call at `0x36a0bcc`), before the flag is looked at |
| `0x36a0bd2..0x36a0bfb` | flag set: `u = 0` path at `0x36a0c3d` (loads `r15 = 1e14 - 1`, `r13 = -1`, `rbp = 1e14`, leaves `r12 = 0`); else the 128 bit compare of the product against `(1e14 - 1):2^64-1`, too big goes to `0x36a0c4e` with `u = 0` |
| `0x36a0bfd..0x36a0c3b` | `low(S) == 0` keeps `u = 0`; else third divide (`0x36a0c21`) of `low(T) * 1e14` by `S`; a quotient with a high word keeps `u = 0`; else `u = min(low(q), 1e14)` (`cmovae`) |
| `0x36a0c58..0x36a0c6c` | bend rate (`+0x90`) into `rbx`, k (`+0x98`) into `rcx`, `u - k`; equal jumps to the exit with the bend |
| `0x36a0c6e..0x36a0cde` | low arm (`u < k`): `u * 1e14 / k` (divide at `0x36a0c88`), `bend - min` must not borrow and the quotient high word must be 0, product against `1e14 * 2^64` (`sbb`), divide by 1e14 (`0x36a0cc5`), add `min`, carry keeps the bend |
| `0x36a0cd2..0x36a0d64` | high arm (`u > k`): `max` from `+0x88`; `k > 1e14 - 1` returns max; `(u - k) * 1e14 / (1e14 - k)` (divide at `0x36a0d1e`); `max - bend` must not borrow; guard; divide by 1e14 (`0x36a0d5b`); add bend; carry returns max |
| `0x36a0ce1..0x36a0cf4` | exit: `rax = (rate * 0xdbe6fecebdedd5bf) >> 64 >> 33` = rate / 1e10 |

`0x36a09f0` has the shape of `0x36a08b0` (same three divide calls at `0x36a0a27`, `0x36a0a92`, `0x36a0ada`, same guard constant) and ends with a double divide by the f64 pool value at `0x459378` (1e14); `0x36a0d80` has the shape of `0x36a0b30` and ends with the two-lane u64-to-f64 conversion and a divide by the same pool value. Both are shown to match the rule list by the 11,076 compared cases, not by this table.

## Implementation and comparison

The implementation is a pure-Python rule list in `tools/bole_rate115.py` (`ceil_total`, `supply_of`, `ratio_or_zero`, `curve`, `util_result`, `result_bytes`, `spec_run`) written separately from the evaluator that runs the bytes. No Rust path is claimed. The evaluator is the #94-era x86-64 subset interpreter (decoder raises on any unknown form; calls through the divide slot go to a recording stub; every byte outside the result is compared after each run).

Cases (each compared: result bytes or register, the ordered list of divide requests, and all other fixture bytes):

| Group | Cases |
| --- | --- |
| Named records x 4 entries (edges, ceil, overflow, kink, 25 injected-quotient cases) | 284 |
| Exhaustive share grid a, b in 0..10 x 4 entries, and two percent sweeps across the bend x 4 entries | 1,292 |
| Pseudo-random vectors (`lcg` seed `0x1234abcd`, word / shifted / near-1e14 / power-of-two draws) | 9,500 |
| Total compared | 11,076 |
| Mismatches | 0 |
| Rows not reached | 0 of 4 (6 only through injection) |

Negative controls (all detected; `negative_controls` and `negative_detected` in `measure.json`):

| Kind | Count | Detected |
| --- | --- | --- |
| Wrong rule-list switches (`model-variants.tsv`: old94, floor_total, no_cap, ge_kink, ceil_low, e10_rate, util_e10, f64_scale, err_swap, no_high_q, no_a_zero, top_below_off, guard_off, add_wrap, supply_high_off, low_arm_top) | 16 | 16 |
| Structural (`structural-controls.tsv`: changed digest, interior / earlier / data / out-of-file address as function start, slot holding another target, wrong entry against a rule) | 8 | 8 |
| Byte edits of reached rows (`mutations.tsv`: condition flips, immediate bit, displacement bit) | 142 | 140 killed; 10 of the kills need an injected quotient |
| Total | 164 | 164 |

Two byte edits survive and are not counted as controls: `0x36a0c4e` and `0x36a0ea0` (the `movabs` of 1e14 on the error path, where u is 0: it only multiplies 0 in the low arm, and the high arm that reads it is unreachable with u = 0). That makes them equivalent edits, not missed ones.

Tests: `tests/test_bole_rate115.py`, 56 tests (three classes: comparison with the rule list, properties of the bytes stated without it, and a closed-form statement in exact fractions checked on 840 plain records per entry), including a regeneration test that rebuilds all evidence and compares it with the committed files.

## Results and limitations

- Passed: 11,076 of 11,076 cases; 164 of 164 negative controls; reciprocal bounds hold; the factor pair `EDGE_LEFT * EDGE_RIGHT = 1e14 * 2^64 - 1` hits the supply and curve guard edges.
- Limits: the divide is a stub whose contract (128 bit unsigned quotient/high word in rax:rdx from rdi:rsi / rdx:rcx) is read from the call sites and checked with a non-zero divisor test, not run from the library. The other callee of the record fields is not claimed. Only these four bodies are claimed; the caller `0x38e64b0` is not.
- Inferences (not observations): the four rate words are `min_rate`, `max_rate`, `kink_rate`, `kink_utilization` and the share pairs are `totalBorrowed` / `totalSupplied` as in the #94 packet's serde reading; that reading was made on #94 bytes and is not re-checked here. `0x38e64b0` (2,191 bytes, which takes a count up to `0x7d0` and has an "Invalid input" refusal) calls `0x36a0b30`, `0x36a08b0` and, through the slot, `0x36a09f0`; whether it is the info handler is unresolved.
- No component gate is requested.

Next question: what `0x38e64b0` does with the rate word, the two utilization results and the token tree (B-tree at owner `+0xd0`) when it builds its reply, and where the #115 row for `supplyYearlyRate` (`(1 - reserve factor) * rate * utilization` in #94) is formed.
