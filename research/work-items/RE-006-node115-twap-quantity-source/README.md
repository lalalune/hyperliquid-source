# Node 115 perpetual TWAP scheduled quantity

This scoped Rust contribution advances issue #3915 with the selected perpetual
TWAP quantity calculation. It leaves the issue and all completion gates open.
It implements duration normalization, target scheduling with optional fused
jitter, filled-quantity guards, notional thresholds, minimum/cap composition,
and final significant-digit size rounding as one connected calculation.

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `0781ce04826eeefd89fe336cb8ea073be0c1de30`; addresses are linked ELF VAs,
and FDE ends are exclusive.

## Prior work and selected boundary

Merged #4238 (`RE-006-twap-slice-115`) already models the selected TWAP owners;
this work credits that research and adds independently authored Rust source.
It does not claim new discovery of those owners. #4264 concerns the separate
advance step, and #4329 the separate finish step. Neither is implemented here.
The midpoint-market planner in #4371 is also separate: this crate accepts an
already computed positive limit price and does not repeat the book/price/tick
path. The reference is independently authored from the original static contract;
no captured instruction evaluator was run or ported into source.

The selected owner is `0x5a305e0..0x5a31262`. The public boundary is a logical
selected state (`total`, `filled`, `slice_index`, raw binary64 `duration`, and
`jitter`), a `NonZeroU64` limit price, and a checked clamped epoch-millisecond
timestamp. Selection from the outer user/TWAP maps, pause handling, book lookup,
metadata, calendar decoding and price construction are outside this API.
The caller must supply the values reaching the native size-calculation region.
`None` denotes the calculation's no-slice/advance decision; it neither calls nor
pretends to implement native advance or finish behavior.

## Observed calculation

Duration at native state `+0x10` is divided by 60. Negative and non-finite values
normalize to zero for conversion; finite nonnegative values truncate and
saturate to u64. The count is saturating `2 * quotient + 1`. In particular,
positive infinity produces count 1, not `u64::MAX`; a sufficiently large finite
duration produces `u64::MAX`. The count is always nonzero.

The saved total (`+0x08`) and count are converted to binary64 and divided to form
an average. For `slice_index == count`, target is the original integer total,
bypassing float conversion and jitter. Otherwise the non-jitter target is
`floor(average * float(slice_index))`, with finite unsigned saturation.

With jitter enabled (`+0x21`), the target is
`floor(fma(average, float(slice_index), phase * average))`, where
`phase = float(timestamp_ms % 40) / 100 - 0.2`. The offset multiplication rounds
before the single fused multiply-add. The FMA therefore cannot be replaced by
separate multiply and add operations. Both target calls use the actual floor
helper `0x63effe0`; it is not a round-to-nearest or ceiling helper.

`TimestampMs` accepts `0..2^53-1`. This includes the clamped timestamps produced
by the native checked calendar domain. Within this bound the reciprocal/high-word
sequence at `0x5a30cf1..0x5a30d0a` equals modulo 40: its reciprocal error is below
`2^-10`, smaller than the `1/20` remainder spacing before the final divide by two.
The wrapper bound makes this phase equivalence explicit without duplicating the
existing calendar implementation. The source does not accept negative timestamps;
those must already have undergone the caller's observed clamp to zero.

Target below filled (`+0x30`) yields no slice. Otherwise remaining total uses
saturating subtraction, modeling continuation when the native diagnostic
helper returns. If `remaining * price <= 30,000,000`, the result is the whole
remaining quantity, even when the scheduled target is zero. Products larger
than u64 also enter the large-notional path, modeled exactly with u128.

The large-notional path computes:

- minimum = `ceil(12,000,000 / price)` using integer quotient and remainder;
- cap = saturating `3 * floor(average) + 1`;
- quantity = `min(remaining, max(min(target-filled, cap), minimum))`.

When index is below count, quantity is rounded down to five significant decimal
digits. At or beyond count, that rounding is skipped, though the cap still
applies. Zero quantity yields no slice. The output exposes the quantity, target
and slice count; it is not the native order/option ABI or the rest of the order
record. Business-side labels, submission and live scheduling are not inferred.

## Helper evidence and limits

The FMA wrapper `0x63f0210` reads slot `0x64ffe00`, initially relocated to
`0x63f06a0`. Its initialized dispatch selects hardware bodies `0x63f0680`
(FMA3) and `0x63f0690` (FMA4), both computing `x0*x1+x2` with one rounding.
The crate's `mul_add` matches these selected branches. The software fallback
at `0x63f0230` and CPU detection are explicitly outside the equivalence claim;
this packet does not infer them from a familiar function name. The floor
helper is retained and checked through its fraction masks, sign handling and
negative-unit data. Native diagnostics and allocator/collection ABI are excluded.

`records.json` retains six complete FDEs, 3,493 bytes and 790 instructions,
including the enclosing owner for boundary/field context. Its selected contract
has 470 instruction/data/edge facts and 45 corruption controls. Controls alter
duration/count handling, state fields, jitter phase and operator, FMA/floor
targets, filled guards, notional threshold, minimum rounding, average cap,
terminal behavior, size step, floor sign and fused operator. Each is rejected
by fact checks with global digest/window checks bypassed. Counts are over this
selected contract, not whole-owner or component equivalence.

Four Rust integration tests pass in debug and release, including 12,000
independent deterministic reference cases (5,814 emitted slices and 6,186
no-slice outcomes). The Python reference uses exact rationals and explicit
binary64 rounding, including a single rounding for FMA. It differs under 251
ceil-target corruptions, 1,160 unfused-target corruptions and 360 forced-terminal-
rounding corruptions. Those counts compare the selected `(count,target,quantity)`
calculation, even when a quantity change is masked by a later bound.
Fixture SHA-256:
`c9f4c281da9ec99944e13aff17c2720118e579b634467d124dfde3d3a9a4dc38`.

```sh
python3 research/work-items/RE-006-node115-twap-quantity-source/verify.py
python3 research/work-items/RE-006-node115-twap-quantity-source/reference.py
cargo +1.95.0 test --offline --locked --manifest-path src/node115-twap-quantity/Cargo.toml
cargo +1.95.0 test --offline --release --locked --manifest-path src/node115-twap-quantity/Cargo.toml
cargo +1.95.0 clippy --offline --locked --all-targets --manifest-path src/node115-twap-quantity/Cargo.toml -- -D warnings
cargo +1.95.0 fmt --manifest-path src/node115-twap-quantity/Cargo.toml -- --check
shasum -a 256 -c research/work-items/RE-006-node115-twap-quantity-source/MANIFEST.sha256
make doctor verify catalogue-check reproduce
```

Python 3.14.7/Capstone 5.0.7 and Rust 1.95.0 were already installed. The crate
uses std and no external dependencies. Full unfiltered `make test` is excluded
because discovery includes captured instruction emulation; the validation record
lists the safe focused tests actually run. No captured target was executed or
emulated, no live endpoint was used for behavioral validation, and no unlicensed
inferred source was copied.

Implementation, original artifact analysis and reference: OpenAI `gpt-6-astra` /
`codex-desktop`. GitHub/browser reads, independent review and publication:
OpenAI `gpt-6.1-terra` / `codex-desktop`. New source and documentation are MIT.
