# RE-004: Decimal to scaled integer conversion at 0x3750350

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94,
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985 /
  references/can1357-hl 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for the bytes, constants, call sites and evaluated results; inference for
  mode names, field meanings and the reference mapping; unresolved items are listed under Results
  and limitations
- Scope included: the function 0x3750350..0x3750604, the Decimal helpers it reaches, the mode and
  exponent byte at all 35 calls through slot 0x5773848.
- Scope excluded: what callers do with the result, how the Decimal is parsed, the meaning of error
  tag 0xa8, helper 0x14385c0 beyond its discarded return, and node #115.

## Reproduce

Platform: Linux x86-64, Python 3.12.3, standard library only. No disassembler is called. Run from
the repository root. The target is read, never executed. Generation takes about 150 s.

```
python3 tools/artifacts.py verify
python3 tools/decimal_scaled_u64.py --out research/work-items/RE-004-decimal-scaled-u64-94
python3 -m unittest tests.test_decimal_scaled_u64
(cd research/work-items/RE-004-decimal-scaled-u64-94 && sha256sum -c MANIFEST.sha256)
```

The tool checks the input SHA-256 first and fails on a mismatch. It also fails if any vector
disagrees with the model. It has no side effects beyond the output folder.

## Evidence

Addresses are virtual addresses in node #94. Function bounds come from `.eh_frame_hdr` and the FDEs.
The tool reads every listed number from ELF bytes. Files: `evidence.json` (summary), `vectors.tsv`
(every input and result), `coverage.tsv` (instructions reached per function), `call-sites.tsv`.

Signature, observed from register use: `rdi` is the output, `rsi` points to a 16-byte Decimal
(flags, high, low, mid), `dl` is the mode, `cl` is the exponent. The evaluator marks all other bits
of `rdx` and `rcx` unknown, and no run needed them.

Observed steps:

1. 0x3750366..0x37503e4: an inline ladder builds 10^cl in a u64. cl 0..=19 pass. Any other value
   takes tag 0xa8.
2. 0x3750413: slot 0x5775e38 (0x4eadc80) multiplies the Decimal by 10^cl. Failure gives tag 0xa8.
3. The mode byte picks one of three paths at 0x3750440 and 0x375044d.
   - dl == 0: no adjustment.
   - dl == 1: 0x375046a rounds to 0 places, 0x375047e subtracts, 0x37504c5 compares the absolute
     difference with the constant at 0x206d30. Those 16 bytes are the Decimal 0.001 (flags 0x30000,
     mantissa 1). Strictly below it, the rounded value replaces the input. Otherwise the input stays.
   - any other dl: 0x37504e8 rounds to 0 places.
4. Rounding is 0x4eacde0 with places 0 and strategy 0. Entry 0 of the jump table at 0x7c6058 is
   0x4ead2c0, which goes up only above half, or at half when the kept low bit is odd: half to even.
5. 0x37504ff: slot 0x5775e48 (0x4ead3d0) takes the fractional part. Non-zero gives tag 0xa8.
6. 0x3750532: a negative sign bit gives tag 0xa8.
7. 0x3750570..0x37505c0 divides out the remaining scale. A non-zero high word, or a value above
   0x7ffffffffffffffe (0x37505e4), gives tag 0xa8.
8. Success writes tag 0x186 and the u64 at output + 8. Every failure in this function is tag 0xa8.

Evaluated results, from real bytes:

| Input | Mode | Exponent | Result |
| --- | --- | --- | --- |
| 2.5 | 2 | 0 | 2 |
| 3.5 | 2 | 0 | 4 |
| 1.7 | 2 | 0 | 2 |
| 2.5 | 0 or 1 | 0 | tag 0xa8 |
| 1.0005 | 1 | 0 | 1 |
| 1.001 | 1 | 0 | tag 0xa8 |
| -0.4 | 2 | 0 | 0 |
| -1 | 0 | 0 | tag 0xa8 |
| 0.1 | 0 | 19 | 10^18 |
| 1 | 0 | 19 | tag 0xa8 (above the cap) |
| 2^63-2 | 0 | 0 | 2^63-2 |
| 2^63-1 | 0 | 0 | tag 0xa8 |

The multiply step cannot round in this function. The mantissa is below 2^96, so reducing
mantissa*10^e to fit 96 bits only drops zeros. If the scale runs out first, the multiply fails. The
model asserts this on every vector, and 347 accepted vectors passed through a scale reduction.

The 35 calls sit in 32 functions. Modes: 11 use 0, 9 use 1, 15 use 2. Immediate exponents: 14 (5
calls), 6 (9), 5 (3), 8 (1), 3 (1). The other 16 are computed. Of those, 15 read a field at +0x48
or +0x49 within the previous 12 instructions; `call-sites.tsv` lists each one. 0x3760278 is the only
one of them with mode 0. The last one, 0x36f307d, uses 6 minus a byte.

Inferences, not observations:

- The merged spot-wei-scale packet reads +0x48 as size decimals and +0x49 as wei decimals, so the
  computed exponents are likely token decimal counts.
- Mode 0 with exponent 8 at 0x33304df matches the reference path that passes `RejectFractional`
  with `FP_DECIMALS` = 8.

Comparison with reference `l1/qtys/mod.rs` `decimal_to_scaled_i64`, which is a label source only:

| Point | Reference | Node #94 bytes |
| --- | --- | --- |
| First mode | `RejectFractional` | matches |
| Second behaviour | `Round`, unconditional | rounds only within 0.001, else rejects a fractional value |
| Third behaviour | `Truncate` | half-even rounding; no truncating path exists here |
| Exponent limit | `10_i64.checked_pow`, stops at 18 | u64 ladder accepts 19 |
| Errors | separate variants | one tag, 0xa8 |
| Cap | `i64::MAX - 1` | matches |

## Implementation and comparison

Rust implementation: not yet implemented. Binary comparison: not yet measured.

The tool has a pure-Python x86-64 instruction length decoder and a concrete evaluator. Registers
carry a known-bit mask, and a branch on unknown flags or a jump through an unknown value stops the
run. Every run ends with a check that callee-saved registers and `rsp` are restored. The model in
`model` is plain integer arithmetic and shares no code with the evaluator.

Two calls are not followed. Slot 0x576f488 (0x14385c0) returns with all caller-saved registers
marked unknown, so any later use of its result would stop the run; none did. Six panic slots end a
run as a panic. No vector reached one.

One processor assumption: `bsr` with a zero source keeps its destination. 0x4eae576 presets the
destination, then 0x4eae57b scans. Intel documents the destination as undefined in this case.

## Results and limitations

- 25325 vectors, 0 mismatches, 0 panics, 1749 calls to 0x14385c0, each predicted by the model.
- Exhaustive only in one byte at a time: all 256 exponents at two fixed inputs and all 256 modes at
  two fixed inputs. Mantissa, scale and sign are sampled in `vectors.tsv`, not proved over the whole
  domain. Sampling covers edges (ties, 0.001 tolerance, cap, 2^96), a grid and 3000 mixed rows from a
  fixed SplitMix64 stream.
- Scale is limited to 0..=28, the range rust_decimal keeps. Other flag values were not tried.
- `separating_vectors` in `evidence.json` counts vectors that refute three readings: truncation in
  mode 2 (773), unconditional rounding in mode 1 (1717), and exponent 19 being refused (809 accepted).
- Coverage: 188 of 190 entry instructions were reached. The two others (0x37505c4, 0x37505c6) are
  the zero-mantissa exit of the scale loop. Inference: the earlier fractional check shadows them.
  Helper coverage is in `coverage.tsv` and is partial (for example 66 of 166 at 0x4eaef40).
- Byte controls in the tests patch the tolerance, cap, mode compare, round table, tie test, ladder
  step, sign guard, subtract flag and scale divisor. Each one produces a mismatch.
- Call-site rows use a linear sweep from the FDE start. A misaligned start can resynchronise, so
  an exact stop at the FDE end does not prove alignment. A mode or exponent is reported only when
  the path from setter to call is straight.
- Unresolved: the meaning of tag 0xa8, what 0x14385c0 is for here (its return is discarded), and why
  each caller picks its mode. No progress gate is requested.

Next question: which callers pass Decimals parsed from wire strings, and do callers in mode 1 treat
the tolerance as float noise from an earlier conversion?
