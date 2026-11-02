# RE-004: binary64 quantity multiplication and complement conversion in node #94

These two quantity conversion paths require separate binary64 rounding before integer conversion: nonfinite products return zero, and the complement path preserves negative results, so reconstruction must retain their operation order and distinct final clamps.

- Component ID: RE-004, quantities and rounding.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `e5c9b6436876b2a4a39daef813171f9879317699` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. The latter is an unlicensed lead, not an authoritative source.
- Claim status: instruction bytes, branch destinations, constants and the error-location records are observations; the arithmetic formulas are deductions from those bytes under the floating-point assumptions below. Quantity type, units, caller intent and helper effects are unresolved.
- Scope included and excluded: the two complete FDE-described extents, their normal-return branches and the entry to each error path. This does not cover their callers, the error helper, the provenance or reachability of inputs, other inlined conversions, other targets, or a reconstructed Rust build.

## Reproduce

Run at repository root on Linux x86-64 with Python 3.12.3 and its standard library. The generator imports the repository ELF section and FDE parsers, checks the complete target digest before analysis, reads file-backed bytes only, and does not execute the target or use network access or external programs. The only output side effects are files in the selected output directory.

```sh
python3 tools/qty_float_scale94.py --out research/work-items/RE-004-float-quantity-scale-94
python3 -m unittest tests.test_qty_float_scale94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-004-float-quantity-scale-94 && sha256sum -c MANIFEST.sha256)
python3 tools/qty_float_scale94.py --out <tmp-dir>/first
python3 tools/qty_float_scale94.py --out <tmp-dir>/second
diff -r <tmp-dir>/first <tmp-dir>/second
```

The generated `evidence.json` records original input and code hashes, extents and counts; `instructions.tsv` preserves every FDE byte with the manually reviewed interpretation; `operands.tsv` and `branches.tsv` decode RIP-relative operands and direct branch targets from bytes. `vectors.tsv` and `walk-coverage.tsv` record the instruction-model runs; `tail-classes.tsv` partitions the complete binary64 encoding space; `tail-intervals.tsv` records the branch-result intervals; and `rounding-order.tsv` contains a distinguishing arithmetic example. The program checks the full code hash before accepting the instruction map, and stops on unknown operations or inconsistent results. It uses exact integer and rational arithmetic for binary64 modelling, never the host's floating-point operations. The tests also compare the software arithmetic with host binary64 on finite samples as a separate check.

## Evidence

All code, FDE, constant and location addresses below are **ELF virtual addresses**. File offsets are recorded separately in `evidence.json` and `constants.tsv`.

| Path | FDE start | FDE end, exclusive | FDE record | Input and output observed |
| --- | --- | --- | --- | --- |
| Direct, nonnegative result | `0x3c06160` | `0x3c0620a` | `0xe9e3c0` | integer word in `rdi`, factor in low `xmm0`, result in `rax` |
| Complement, signed result | `0x4cda1a0` | `0x4cda253` | `0xf4775c` | the same register roles |

The entry `test rdi,rdi; js` in each function diverts any word with bit 63 set to its error block before floating arithmetic. Both error blocks load the literal ``called `Result::unwrap()` on an `Err` value`` and a relocated source-location record whose suffix is `l1/src/qtys/mod.rs:843:1`, then call through the same slot. The error helper is not followed: the record and text do not establish its externally observable effects.

For the other integer words, each path converts the signed integer to binary64, then performs the following operations. Let `RN` denote an individual binary64 operation rounded to nearest, ties to even; `q` is the input integer, `f` the input factor, and `y` the product:

| Path | Byte-backed operation order | Finite-product return | Nonfinite-product return |
| --- | --- | --- | --- |
| Direct | `y = RN(f * RN(q))` | `max(0, clamp_i64(trunc_toward_zero(y)))` | 0 |
| Complement | `y = RN(RN(q) * RN(1.0 - f))` | `clamp_i64(trunc_toward_zero(y))` | 0 |

Here `clamp_i64` limits the integer to `[-2^63, 2^63-1]`. Each `RN` is a separate rounding step; the expression is not fused. For example, with `q = 7` and factor `1.5`, the direct result is 10 and the complement result is -3. With `q = 1` and factor `2^63`, the direct result is `2^63-1`; with `q = 2` and the largest finite positive factor, multiplication overflows to infinity and the result is 0. These are results of a byte-anchored software model, not captured node executions.

The difference in operation order is observable even for finite values. `rounding-order.tsv` gives `q = 8791338280601638520` and factor bits `3fee1506db4daeb5`: the complement sequence returns `526893509556257408`, while first rounding `q * f` and then subtracting it from the separately rounded `q` would return `526893509556257792`. The latter is a comparison model, not a second target path.

### Conversion and branch proof

Each function clears the product sign bit and compares its bits with the largest finite binary64 encoding. An absolute encoding above `0x7fefffffffffffff` selects the preloaded positive zero. Every finite product proceeds through comparisons with the stored binary64 constants `-2^63` at `0x20acb8` and `+2^63` at `0x20a7f0`, with out-of-range values clamped to those endpoints. The `cvttsd2si` instruction truncates toward zero. For the positive endpoint the conversion would produce the x86 indefinite integer; the immediately following comparison against the largest binary64 below `2^63`, at `0x20a2c8`, selects `2^63-1` instead. The negative endpoint gives `-2^63`. The direct path finally changes every nonpositive signed result to zero; the complement path does not. Both contain self-comparisons for unordered results, but the preceding finite check leaves their candidate finite.

This reasoning covers every product encoding, conditional on the decoded instruction semantics and stated processor environment. `tail-classes.tsv` independently counts the disjoint sign/exponent/fraction classes: biased exponents 0 through 1085 have magnitude below `2^63`; exponent 1086 contains the two exact endpoints and larger magnitudes; exponents 1087 through 2046 exceed the endpoint; exponent 2047 is nonfinite. Their counts sum to `2^64`. The generator additionally checks eight contiguous sign-and-magnitude intervals against the immediate finite bound and the loaded endpoint encodings and records their terminal result forms in `tail-intervals.tsv`. The full-domain argument is the class partition plus the monotone comparisons and `cvttsd2si` semantics; the 32,768 sampled post-product checks are a control, not an exhaustive execution of all bit patterns.

For inspection, these are selected original instructions from the pinned byte stream (`instructions.tsv` contains the complete extents):

```text
0x3c06163  787f                  js error
0x3c0616a  f20f59c1              multiply factor by converted quantity
0x3c06191  7f2e                  jg convert: nonfinite product selects zero
0x3c061c1  f2480f2cc1            convert candidate toward zero to i64
0x4cda1b6  f20f5cd0              subtract factor from one
0x4cda1ba  f20f59ca              multiply converted quantity by complement
0x4cda228  480f4bc1              cmovnp converted value
```

### Inferences and unresolved inputs

The common source-location suffix supports associating both guards with quantity code, but does not establish a specific Rust newtype, monetary unit, valid factor range, or that both functions serve the same caller. The labels in this packet describe observed arithmetic only. We did not follow or attribute caller functions, which have separate research coverage. Source comments and inferred reference implementations are not used as target authority.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No Cargo lockfile, build, raw/normalized machine-code comparison, relocation closure, or target execution is claimed.

The static walker uses a pinned map of 74 original instruction byte ranges, actual decoded direct-branch displacements, and an exact-rational binary64 model. It walks 2,856 combinations of integer and factor bits and compares each return or error edge with a separate post-product arithmetic model: 2,380 return cases and 476 error-edge cases, with zero mismatches. It visits all 60 instructions on the modelled paths and stops before the 14 error-block instructions; those 14 are recorded and pinned but the error helper is not simulated. The vectors exercise both directions of every conditional direct branch and all 10 direct branches; `walk-coverage.tsv` also records conditional-move outcomes. The self-unordered conditional-move outcome is absent on each path because its candidate is already finite in this model.

The 25 focused tests include altered input digest and function bytes, modified or duplicate FDE bounds, an out-of-range or NOBITS address, malformed branch opcodes, a corrupted RIP-relative displacement, a missing source relocation, a changed interpreted branch, subnormal and tie cases, signed bounds, infinities, NaNs, integer-to-binary64 precision loss and the rounding-order counterexample. The tests regenerate all evidence twice and compare it with the retained files. These are controls for this analysis, not target differential tests.

## Results and limitations

Within the stated scope, the packet pins 2 FDE extents, 74 instruction ranges, 15 RIP-relative operands, 10 direct branches, and 4 binary64 constants. The two functions' floating arithmetic is modelled under round-to-nearest-even, masked floating-point exceptions and disabled denormal flushing. Different MXCSR modes or unmasked exceptions can change intermediate results or cause traps, and the active target environment is not established here. The exact rational model's NaN handling assumes the usual masked x86 SSE behavior; no hardware target execution validates payload propagation.

An FDE extent is unwind metadata, not independent proof that every source-level function or call site has been recovered. The name and range of `q` and `f`, the live reachability of extreme factors, error helper effects, external side effects and caller-level meaning remain unknown. No component progress gate is requested.

Next question: on an independently scoped caller, establish the admissible factor range and the meaning of the resulting signed or nonnegative quantity, then compare an independently authored Rust implementation with an authorized offline target harness.
