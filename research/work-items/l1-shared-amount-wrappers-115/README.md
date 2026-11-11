# l1-shared: node #115 price/size wrappers around the decimal scaler slot (executed, 24,000 cases)

This packet lets a reimplementation decide how eight node #115 function bodies feed the decimal-to-u64 scaler 0x421e9d0: which rounding mode and digit count each caller passes, how the pair-table and asset-id variants derive `6 - szDecimals`, which inputs panic instead of returning, and how the scaler's `0xac` error and a zero result are folded into the wrapper's `0xad` error tag. Every body is executed for real, scaler and helpers included, and compared with a Python model on 24,000 generated cases; 66 negative controls (19 model mutants, 44 patched wrapper bytes, 3 out-of-domain inputs) are all detected.

- Component ID: l1-shared
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository commit 0781ce04826eeefd89fe336cb8ea073be0c1de30; no reference source was copied
- Claim status: observation (executed behaviour) with inference limited to the names in "Inferences"
- Scope included: the eight wrapper bodies below, executed over the captured bytes with the real scaler 0x421e9d0 and its five decimal helpers reached through the GOT slot. Scope excluded: the other thirty-odd callers of the slot, the scaler's own internal reconstruction (covered by a separate open packet), the drop routine 0x277e390 beyond running it, and every call-site context outside the wrapper arguments.

## Reproduce

```
python3 tools/amount_wrappers_115.py --out research/work-items/l1-shared-amount-wrappers-115
python3 -m unittest tests.test_amount_wrappers_115
python3 tools/artifacts.py verify
```

The tool checks the binary SHA-256 first, never executes the binary and uses only `tools/decimal_scaled_u64.py` (a concrete x86-64 evaluator over file bytes). It keeps no per-case lists; each case is built, run and compared at once, and the evidence files are written line by line. Output is deterministic (fixed LCG seeds, no clocks).

## Evidence

Coordinates are virtual addresses. The GOT slot `0x64e6468` carries an `R_X86_64_RELATIVE` addend `0x421e9d0` (checked from `.rela.dyn`). A rip-relative `call *slot` scan of `.text` finds 46 call sites in 41 distinct FDEs, 136 to 3,084 bytes; this packet takes the eight bodies whose argument setup is fully visible in the body itself.

| body | entry | size | digits argument | mode | wrapper result |
|---|---|---|---|---|---|
| w1 | 0x46aa250 | 136 | constant 6 | 2 | scaler struct copied through (tag 0x1a2 ok, 0xac error) |
| w2a / w2b | 0x274b760 / 0x57c70c0 | 297 | low byte of the third argument | 2 | ok non-zero value, else tag 0xad |
| w3a / w3b | 0x2891af0 / 0x5a00b00 | 436 | `table[pair[idx].1][0x49] - table[pair[idx].0][0x48]` (u8, borrow panics) | 2 | as w2 |
| w4a / w4b | 0x3be28a0 / 0x5a00cc0 | 423 | `6 - size_decimals[id % 10000]`, panics if the byte is 7 or more | 2 | as w2 |
| w5 | 0x3c42660 | 542 | as w4, but the decimal is read from a record (context pointer at +0, decimal copy at +8) | 2 | record: tag at +0, asset id at +8 and value at +16 on ok; tag 0xad otherwise |

Observed details (all confirmed by execution, not only by reading):

- Scaler argument convention at the slot: `rdi` result buffer, `rsi` pointer to a 16-byte decimal (flags, hi, lo, mid words), `dl` mode, `cl` digit count. Result: tag word at +0 (`0x1a2` ok, `0xac` error), u64 at +8.
- Mode 2 is half-even rounding of `mantissa * 10^digits / 10^scale`; digits above 19 are refused; results above `0x7ffffffffffffffe` are refused; a negative decimal is refused only when the rounded result is non-zero (a negative that rounds to zero returns ok 0).
- w2/w3/w4 return tag `0x1a2` with the value only for a non-zero ok result. A zero result and any scaler error both return tag `0xad`; the error struct is passed to the drop routine 0x277e390 first.
- w4 splits the asset id with the multiply-high constant `0x346dc5d63886594b` and shift 11 (division by 10,000): the quotient must equal the context's number at +0x50 and the remainder must be below the vector length at +0x10, otherwise the body reaches a panic call (slots 0x64df830/0x64df848).
- w3 indexes the pair vector (32-byte entries, length at +0x10) and the asset table (stride 0x158, length at +0x28); a bad index reaches slot 0x64df620 and a subtraction borrow reaches 0x64df848.
- The twin bodies (w2a/w2b, w3a/w3b, w4a/w4b) are byte-for-byte equal in behaviour over every generated case.
- w5 stores the asset id at +8 and the value at +16 on an ok result; on a scaler error the +8 word is overwritten with the scaler's error payload (uninitialised stack), so the tool compares only the tag there. It panics under the same conditions as w4.

## Implementation and comparison

`tools/amount_wrappers_115.py` holds `scaler_model` (decimal arithmetic), one model per wrapper class and the executor that builds registers and memory, runs the real bytes from the entry until the return mark and reads the result. Cases: 3,000 per body (eight bodies), mixing zero mantissas, ties at the output digit, values around the u64 bound, 96-bit mantissas, scales 0 to 28, sign bits, out-of-range indices and wrong dex numbers. The expected result of every case is computed by the model and must equal the executed result. `wrapper-cases.tsv` gives per-body outcome counts, `wrapper-samples.tsv` every twentieth case with its inputs, result and step count, `controls.tsv` the 66 controls, `measure.json` the totals.

Controls: 19 model mutants (half-up instead of half-even, digits 7, swapped pair fields, division by 1,000, digits plus one, zero passed through, error tag kept), 44 single-byte patches inside the wrapper bodies (mode immediates, digit immediates, the zero-test branch, the ok-tag compare, the wrapper error tag, the borrow branch, the table offset, the size limit, the dex-number offset, and for w5 the record id slot, value slot and decimal pointer) each run on the patched image, and 3 out-of-domain decimals rejected by the model. Equivalent mutants (mode 3 behaves as mode 2; the w1 tag compare is observably redundant) were removed rather than counted.

## Results and limitations

- 24,000 of 24,000 cases equal the model; 66 of 66 negative controls detected (measure.json). Evaluator steps over the run: 11,327,191.
- Limitations: the evaluator is concrete; inputs outside the generated domain (non-canonical decimals, scale above 28) are not modelled. The wrapper names are descriptive; the `6 - szDecimals` reading of w3/w4 is an inference from the constants (the field offsets 0x1d, 0x48 and 0x49 are observed, their meaning is not).
- No component gate is requested.
- Next question: the remaining call sites of slot 0x64e6468 (for example 0x3c4a730 with mode 0, 0x3c426e0 and 0x44c83f0 with constant digits) and what the callers do with tag 0xad.
