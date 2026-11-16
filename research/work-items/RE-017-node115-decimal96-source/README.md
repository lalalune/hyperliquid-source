# Full valid-domain source for the digest decimal conversion boundary

Target: node/115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, size 105896032. Static ELF/FDE evidence and source-only fixtures; no captured execution or emulation.

## What is new and what is reused

#6751 establishes the two parsed inputs used by the digest factor path. #6754 owns scale-zero conversion, #6755 owns divisor and quotient/remainder setup, and #6756 owns the fractional rescale/round/sign sequence. Those arithmetic findings are credited prerequisites, not rediscoveries here.

#5123 (`RE-008-node115-fee-trial-source`, `src/node115-fee-trial`) implements a combined short decimal parser/converter with a u64 coefficient, scale at most 16 and at most 17 input bytes. It does not provide a raw 96-bit conversion interface for all valid scales. The new `src/node115-decimal96-conversion` fills that source gap with an explicit `(low64, high32, scale, negative)` input and 3,632 independently generated bit fixtures across the full valid coefficient width and all scales 0–28. It leaves the existing parser and its fixtures unchanged.

The downstream consumer is the already identified `0x421e4e0` factor conversion boundary after a successful decimal parse. This crate can implement that stage without inventing string grammar or input authority. It is not yet an implementation of the complete public action, its parser, or the later factor normalization/store.

## Input domain and exact operation order

The converter `0x5c44b40` reads flags at input+0, high coefficient word at +4 and low 64 bits at +8. The sign is bit 31; scale is bits 16–23. The source accepts a normalized sign and scale 0–28 plus the two coefficient words, so its coefficient is always in `[0, 2^96-1]`. Rejecting scale 29–255 is a source adapter guard, not a claim about the native handling of malformed flags or reserved bits.

For scale zero, the native path converts the signed coefficient directly to binary64. For nonzero scale, let D=10^scale, Q=floor(coefficient/D) and R=coefficient−Q*D. The selected valid-domain arithmetic is:

1. Convert R and D separately to binary64 and divide to obtain the fractional value; convert Q separately.
2. If the fractional value is zero, apply the final sign directly to the converted Q.
3. Otherwise add the converted Q and fraction, multiply by a binary64 10^scale obtained in the native multiply/square order, round, then divide by that same multiplier.
4. Apply the sign last.

The native source of the floating multiplier is `0x63f0080`, which accumulates selected powers from low to high exponent bits. This matters because replacing the multiplier computation with a different power routine need not preserve every intermediate bit pattern. All required decimal integer powers fit in u128 for the valid domain; the scale-32 integer-overflow branch is not needed.

The selected rounding helper `0x63efe40` combines the input sign with binary64 constant `0x3fdfffffffffffff`, adds it, and clears fractional bits according to the result exponent. For the finite nonnegative values at this call site, the equivalent source operation is `(scaled + f64::from_bits(0x3fdfffffffffffff)).trunc()`. The constant is the immediately preceding binary64 value below one half, not exactly 0.5. Source arithmetic keeps these steps separate and does not use fused operations or replace the algorithm with a single rational conversion.

Raw negative zero is a useful boundary case. At scale 0, forming the signed integer zero and converting yields +0. At scales 1–28, the final sign operation yields −0. These raw input distinctions do not assert that the upstream text parser preserves both representations.

The wrapper `0x421e4e0` only supplies this stage after parser tag `0x1a2`, copies the 16-byte decimal representation into the converter call, requires return tag 1, then stores XMM0 as its floating output. The existing wrapper's error propagation remains owned by prior work.

## Independent source fixtures

`fixture_oracle.py` uses exact rational arithmetic and integer nearest/even rounding to construct binary64 results after each required operation. It does not call the Rust implementation, use the captured executable, or obtain target outputs by emulation. Its power expression is evaluated as a tree of exact-rational operations rounded at binary64 boundaries; truncation is integer division of the resulting exact rational. The frozen TSV contains 3,632 expected bit patterns.

Coverage includes every scale 0–28 and both signs; zero; decimal divisor boundaries; integer conversion boundaries around 2^32, 2^53, 2^64 and 2^95; the maximum 96-bit coefficient; and deterministic additional 96-bit values. Separate source tests exercise negative-zero behavior for every valid scale and reject each unsupported scale 29–255.

The fixtures distinguish the implemented native order from plausible simplifications: among positive fixture inputs, 122 results differ from converting the coefficient and divisor once then dividing, and 193 differ from rounding the exact decimal rational directly. For example:

| Coefficient | Scale | Native-order model bits | Single-division bits |
| --- | --- | --- | --- |
| 18014398509481983 | 1 | `4319999999999999` | `431999999999999a` |
| 4503599627370495 | 2 | `42c47ae147ae147b` | `42c47ae147ae147a` |
| 9007199254740993 | 2 | `42d47ae147ae147c` | `42d47ae147ae147b` |

These are independently calculated source fixtures supported by static instruction evidence, not observed native outputs. They test the full implemented domain's important boundaries and operation order; they are not exhaustive over all 2^96 coefficients and do not alone prove native equivalence.

## Reproduction

```sh
python3 research/work-items/RE-017-node115-decimal96-source/verify.py --target artifacts/node/115/hl-node
python3 research/work-items/RE-017-node115-decimal96-source/fixture_oracle.py --fixtures src/node115-decimal96-conversion/tests/fixtures.tsv
cargo test --manifest-path src/node115-decimal96-conversion/Cargo.toml
cargo test --release --manifest-path src/node115-decimal96-conversion/Cargo.toml
```

The static verifier requires Capstone 5.0.7 and pyelftools 0.32. Seven complete FDEs retain 438 instructions and 102 selected witnesses, six helper relocations and four numeric constants. Ten negative controls cover artifact identity, exact-half substitution, wrong coefficient/scale fields, removing the quotient/fraction split, rescaling or round step, wrong sign placement and wrong power operation order. Retained helper transcripts support review; the prior packets remain the source of the established arithmetic contracts.

Unclosed boundaries include decimal/floating fallback grammar, parsing normalization, invalid native flags, named input producer/authority, complete action acceptance and later factor semantics. Native allocator, error representation and runtime floating-environment changes are excluded. The source assumes ordinary IEEE binary64 nearest/even arithmetic, as in the selected scalar instruction path, and does not claim whole-component completion.
