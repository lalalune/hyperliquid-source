# l1-shared: decimal-to-u64 amount scaler 0x421e9d0 and its five decimal helpers (node #115)

With this packet the amount scaler of node #115 can be rebuilt as a pure function: a 96-bit decimal (sign, scale 0..28,
96-bit magnitude) times 10^digits, optionally snapped to an integer in one of two modes, returned as a u64 that must not
exceed 0x7ffffffffffffffe, with every refusal rule and the one side effect (a touch of a lazily initialised global) pinned
to the bytes. The same run proves behaviour models for the five rust_decimal-style helper bodies the scaler calls (checked
multiply, round-to-integer, fractional part, subtraction, comparison).

- Component ID: l1-shared (decimal helpers shared by exchange amount paths); cross-reference `abci` is not claimed
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: 0781ce04826eeefd89fe336cb8ea073be0c1de30 (repository main when the tool was written)
- Claim status: observation (bytes executed in the shared evaluator) plus inference (the Python specification, checked on every case)
- Scope included and excluded: functions 0x421e9d0 (scaler, 193 instructions), 0x5c457a0 (multiply, 266), 0x5c442f0 (round, 432),
  0x5c448a0 (fractional part, 79), 0x5c46bb0 (subtraction, 238), 0x5c456c0 (comparison, 78), all with their FDE extents.
  Excluded: callers of 0x421e9d0, the lazy-global getter 0x1560a40 behind the touch (only its occurrence is observed),
  inputs whose flag word is not a valid decimal (scale above 28 or stray bits), and any component gate request.

## Reproduce

Working directory: repository root, Python 3 standard library only, no external programs, the binary is never executed.

```
python3 tools/decimal_amount_scaler_115.py --out research/work-items/l1-shared-decimal-amount-scaler-115
python3 -m unittest tests.test_decimal_amount_scaler_115
```

The tool checks the SHA-256 above first and fails on any other input. One `--out` run takes about four minutes and under
0.7 GB; evidence files are byte-identical across runs (checked twice with `diff -r`). `MANIFEST.sha256` lists every file
here except itself. The ELF is read with the repository helpers `tools/fde_extents.py` and the shared evaluator
`tools/decimal_scaled_u64.py`; the evaluator gets three small additions in the tool (pand, pshufd, movd).

## Evidence

Coordinates are virtual addresses of the ELF image. All numbers come from `measure.json` and the TSV files, generated from
ELF bytes by the tool.

Observations from the bytes (call sites in `calls.tsv`):

- Entry arguments: rdi result slot, rsi pointer to a 16-byte decimal (flags, hi, lo, mid words), dl mode byte, cl digits byte.
  Result slot: tag u16 `0x1a2` plus u64 at +8 on success, tag `0xac` on refusal.
- Step 1: 10^digits is built from the bits of `cl` (1, 10, 100, 10^4, 10^8 and a checked 10^16 multiply); the product must fit
  a u64, so digits above 19 refuse (digits 0 skips the multiply and uses 1).
- Step 2: helper 0x5c457a0 multiplies the decimal by that integer. Observed through the call taps: a zero product comes back
  as +0 with scale 0 whatever the input sign and scale; an overflowing 96-bit product is reduced by whole powers of ten
  (always exact here, because the product is the input magnitude times 10^d) and refuses only if scale 0 is reached.
- Step 3, mode byte: 0 leaves the product alone; 1 (tolerant) rounds half-to-even with 0x5c442f0, subtracts it
  (0x5c46bb0), compares the absolute difference with 0.001 (0x5c456c0, constant 0x30000 flags / 1) and only when the
  difference is strictly below 0.001 does it keep the rounded value, calling the lazy getter at 0x421eb74 first when the
  difference is not zero; any mode above 1 always rounds half-to-even (`0x5c442f0`, scale 0, strategy 0).
  Rounding a negative value to zero clears the sign.
- Step 4: the fractional part (0x5c448a0, truncate then subtract) must be zero or the call refuses; a set sign bit refuses
  (so a negative value that does not round to zero refuses); the magnitude is divided by 10^scale by repeated division by ten,
  the top word must be zero and the u64 must not exceed 0x7ffffffffffffffe.
- `coverage.tsv`: reached instructions per body over all cases. The two unreached instructions of the scaler (0x421ec74,
  0x421ec76) are the "zero magnitude with non-zero scale" branch, which the multiply makes unreachable (zero is returned at
  scale 0). Unreached parts of the helpers (rounding to non-zero decimals, subtraction with mixed signs or overflow,
  non-integer multipliers) cannot be reached through this caller and are not claimed.
- `helper_taps.tsv`: 42,415 helper calls compared against the Python models of their inputs and outputs, 0 mismatches.

## Implementation and comparison

`tools/decimal_amount_scaler_115.py` runs the six bodies from the ELF bytes (call-site taps record each helper's inputs and
outputs) and compares:

- the scaler result and the number of touches of the lazy global with `spec_scaler`, an independent Python specification;
- each helper call with `model_mul`, `model_round`, `model_fract`, `model_sub`, `model_cmp` on canonical (sign if non-zero,
  scale, magnitude) values.

10,300 deterministic cases in 11 classes (small, wide, decimal_places, near_integer, tie, tolerance_edge, limit_edge,
overflow_reduce, digits_edge, negative, zero) give 4,100 accepted amounts, 6,200 refusals, 883 touches, 0 mismatches.
`tests/test_decimal_amount_scaler_115.py` repeats directed cases, known values and a corrupted helper model.

Negative controls (53, all detected; `controls.tsv`): 21 wrong specifications (digits limit 18/20, no overflow reduction,
mode confusion, rounding variants, tolerance 0.01/0.0001/inclusive, touch always/never, sign of zero, truncating the
fraction, negative accepted, bound off by one, u64 bound), 12 byte corruptions in the scaler, 12 condition flips in the
helpers, 6 out-of-range inputs, 2 damaged-binary digests. Eight more of the 20 sampled helper condition flips survive the 284-case battery
(listed in `flip_survivors.tsv`; most sit in code that `coverage.tsv` shows is not reached through this caller, the rest are
flips the battery does not distinguish); they are not counted as controls.

## Results and limitations

- Cases 10,300, mismatches 0; controls 53/53 detected; helper calls 42,415, mismatches 0 (`measure.json`).
- Not covered: valid-layout restriction on the input flag word (scale above 28 is refused by the tool, not studied);
  rust_decimal-style behaviour of the helpers outside this caller (general multiply, other rounding strategies,
  subtraction overflow); callers of 0x421e9d0 and the meaning of the mode byte at call sites; the body of the lazy
  getter 0x1560a40. No progress gate is requested.
- Next question: the callers of 0x421e9d0 (which mode byte and digits each passes) and the getter behind the touch.
