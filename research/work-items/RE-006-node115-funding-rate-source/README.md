# Node 115 logical funding-rate calculation

This independently authored Rust contribution advances issue #3913 with the
selected per-key sample-to-rate calculation. It implements sample lookup,
ordered aggregation, configuration defaults/overrides, finite correction bounds,
multiplier and final output band as one logical operation. The issue remains open
and component completion gates stay false.

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `0781ce04826eeefd89fe336cb8ea073be0c1de30`. Coordinates are linked ELF
virtual addresses, with exclusive FDE ends.

## Prior work and input boundary

Merged #4316 already maps node115 owner `0x44d8590..0x44d8a0f` and deque lookup
`0x45562e0..0x4556401` as static research and a Python model. This work credits
that discovery and adds independently authored Rust source. Node94 PR #1579 is
a separate target; this crate does not adopt its numeric contract. PR #4373
computes a premium from book depth and is a separate function and input boundary.
This crate consumes already stored samples and does not repeat that book walk.

The public `rate` API takes a key, a `BTreeMap<u64, Vec<f64>>` sample store, and
three logical per-key config maps. These enforce unique keys and execute real
lookups. A sample vector preserves the native stored order. This is an owned
logical representation, not a replacement for the native tree/deque or IndexMap
memory layout. Physical hash probing, allocator behavior, invalid container
panic paths and concurrent state access are outside the equivalence claim.

## Observed native operation

The native sample store is rooted at state `+0x120..+0x138`. Missing keys and
empty vectors return absence. A nonempty vector is folded from **negative zero**
using sequential `addsd`, in groups of eight and then a tail. It is not a
pairwise, reordered or compensated sum. The valid allocation-sized `Vec<f64>`
length is compatible with the native signed count conversion and unroll mask.

The baseline map at `+0x90` defaults to the exact binary64 literal `0.0001`.
The correction-bound map at `+0xd8` falls back to state `+0x140`.
The sum is divided by the count, then correction is `baseline - mean`.
Only when both the bound and correction are finite does the native normalize
`bound` and its sign-toggled counterpart into lower/upper bounds and clamp the
correction. The MINSD/MAXSD operations take their second operand on equal or
unordered comparisons. The crate implements those comparisons explicitly;
using an abstract absolute-value clamp can lose the signed-zero behavior.

The multiplier map at `+0x48` defaults to `1.0`. The result is computed in order
as `(mean + correction) * multiplier`. If that result is finite, it is clamped
to the literal interval `[-0.04, 0.04]`. Finally it is multiplied by `0.125`.
Non-finite intermediates bypass the relevant finite-only clamp, so cancellation
of infinity can produce NaN and an infinite multiplier can produce infinity.
Rearranging the expression to the baseline or always clamping changes behavior.

The native return flag and floating result are represented as `Option<f64>`.
Finite result bits, infinity sign and signed zero are projected. NaN
classification is preserved; NaN payload/sign and floating exception flags are
not claimed. Ordinary nontrapping binary64 round-to-nearest-even is a premise.
The crate is `no_std` with `alloc` and no external dependencies.

## Evidence and validation

`records.json` retains the complete owner and deque lookup FDEs: 1,440 bytes and
364 instructions. The verifier authenticates the original digest, FDE and
instruction boundaries, all retained rows, 228 selected instruction/data/edge
facts and 41 semantic corruption controls. Controls alter sample fields, empty
handling, unroll/tail order, config fields/defaults, negative-zero seed, mean and
correction operators, finite guards, symmetric and final bounds, multiplier and
output scale. Corruptions must fail fact checks with global digest/window checks
bypassed. These counts concern the selected logical contract, not full component
coverage or runtime equivalence.

Four Rust integration tests pass in debug and release. They include missing and
empty sample maps, unrelated keys, all override combinations, positive/negative
zero bounds, cancellation-sensitive sample order, non-finite guards and the
exact final band. A separate Python reference generates 12,000 deterministic
cases: 6,189 finite results, 147 infinities, 4,144 NaNs and 1,520 absences. Lengths
0, 1, 2, 7, 8, 9, 15, 16, 17 and 25 cover both sides of the native unroll
boundaries. NaN results are compared by classification; other results by bits.

The synthetic reference differs in 120 cases when the fold starts from positive
zero, 763 when sample order is reversed, 2,506 with the wrong final band, and
758 when finite guards are removed. It uses ordered host Python binary64
operations and is not an independent native execution oracle.
Fixture SHA-256:
`e03a17552cc0642d97e48f3143136bbbea96850e278becc6c9a6d0b5880e3aca`.

```sh
python3 research/work-items/RE-006-node115-funding-rate-source/verify.py
python3 research/work-items/RE-006-node115-funding-rate-source/reference.py
cargo +1.95.0 test --offline --locked --manifest-path src/node115-funding-rate/Cargo.toml
cargo +1.95.0 test --offline --release --locked --manifest-path src/node115-funding-rate/Cargo.toml
cargo +1.95.0 clippy --offline --locked --all-targets --manifest-path src/node115-funding-rate/Cargo.toml -- -D warnings
cargo +1.95.0 fmt --manifest-path src/node115-funding-rate/Cargo.toml -- --check
shasum -a 256 -c research/work-items/RE-006-node115-funding-rate-source/MANIFEST.sha256
make doctor verify catalogue-check reproduce
```

Existing Python 3.14.7/Capstone 5.0.7 and Rust 1.95.0 are used. Full unfiltered
`make test` is excluded because discovery includes captured instruction emulation;
the validation record lists the focused safe repository tests actually run.
No captured binary was executed or emulated, no live endpoint was used for
behavioral validation, and no unlicensed inferred source was copied. Funding
settlement, sample insertion/history maintenance and live state changes are not
implemented.

Implementation, original artifact analysis and reference: OpenAI `gpt-6-astra` /
`codex-desktop`. GitHub/browser reads, independent review and publication:
OpenAI `gpt-6.1-terra` / `codex-desktop`. New source and documentation are MIT.
