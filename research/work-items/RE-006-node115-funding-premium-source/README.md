# Node 115 typed impact walk and funding premium

This independently authored Rust crate advances issue #3913 with the connected
book-impact and funding-premium calculation. The issue remains open and component
completion gates stay false. The new result is executable source for the linked
order quantities, partial-level arithmetic and their two-book caller, with a
logical typed input boundary. It does not take precomputed impact prices.

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All addresses are linked ELF virtual addresses; FDE ends are exclusive. Base:
`0781ce04826eeefd89fe336cb8ea073be0c1de30`.

## Prior work and scope

Merged PRs #4318 and #4319 already establish the premium caller and impact walk
as static research and Python models. This work credits those discoveries and
adds a dependency-free Rust implementation, not a second claim to the same
static discovery. Node #94 funding work (#860 and #1422) is a separate target.
Open and closed PR metadata and relevant current paths were checked for an
existing Rust implementation before selection and again before publication.
Historical patches were not all individually re-reviewed.

The `Book` boundary supplies levels in the native iterator's visitation order
and typed order-pool slots. The complete quantity walk runs inside this crate:
there is no substituted impact-price callback. Physical tree/ring traversal,
allocation and concurrent book storage remain outside the contract. Both books
can be projections of the native shared pool; owned indices need only preserve
their reachable links. Logical unique-key maps provide the config boundary;
this is not a reconstruction of IndexMap hashing or BTreeSet node layout.

## Observed native contract

`0x44d9060..0x44d9504` validates `asset / 10000` against selected DEX metadata and
`asset % 10000` against its market rows. Decimal counts must be below seven.
It converts the unsigned oracle to binary64 and divides by `10^(6-decimals)`;
a zero reference returns absence before any book walk. The target notional
comes from the asset-specific map entry or the default at state `+0x148`.

The calls at `0x44d91ec` and `0x44d9201` both target
`0x46a6370..0x46a685c`, with iterator views at book `+0xa8` and `+0xc8`.
Both calls happen before either zero return is tested. The output absence
sentinel is a zero first-impact field, not a fully initialized zero record.
The safe wrapper represents absence with `Option`, not the native output ABI.

For each supplied level, the walk takes the unsigned magnitude of its signed
price, requires a present in-range head, and traverses pool entries. Native
stride is `0x110`; tag 2 terminates the chain. Quantity is at `+0xe0`, next
presence at `+0x10`, and next index at `+0x18`. A missing or out-of-range next
ends the current chain after its quantity; an invalid initial head fails the
walk. Quantity addition saturates on the continuation after a diagnostic call.
A zero total level quantity fails immediately instead of skipping the level.

A level product must fit `0..=2^63-2`. The walk accumulates whole levels while
cumulative notional is strictly below the target. When the threshold is reached,
it uses floor `(target - previous_notional) / price` for the final quantity,
checks the product cap again, adds the prior totals with saturation, rejects
when `wrapping(total_quantity - 1) >= total_notional`, and returns floor
`total_notional / total_quantity`. Exhaustion and these reject paths return zero.
A zero price can contribute quantity before a later positive level; if a zero
price itself reaches the partial division, native `div` faults. `Fault` reports
that condition without claiming the native panic/signal ABI. The wrapper also
detects cycles, outside the native terminating-chain input premise.

When either impact is zero, the caller returns absence. Otherwise it converts
both to binary64 using the same decimal scale. For nonzero mode byte, it computes
`(max(first - reference, 0) - max(-(second - reference), 0)) / reference`.
For zero mode it computes `((first + second) * 0.5) / reference - 1`.
The native midpoint has an overflow-safe alternate for values above half the
largest finite binary64 value. Scaled u64 impacts cannot reach that branch, so
the typed domain uses the observed add-then-multiply path. Every operation uses
ordinary non-fused binary64 arithmetic and default round-to-nearest-even.

Asset membership in the state set divides the result by **100**, established by
`0x44d941a` and data `0x459498`. This happens before the finite-result clamp to
`[-0.5, 0.5]`. The result carries the two unscaled impact prices. Signed side
labels or business meanings beyond these observed operations are not inferred.

## Evidence and validation

`records.json` retains both complete FDEs: 2,448 bytes and 598 decoded
instructions. The verifier authenticates the original target digest, FDE and
instruction boundaries, all retained rows, 473 selected instruction/data/edge
facts, and 44 semantic corruption controls. Controls change metadata selection,
decimal scaling, notional fallback, book sources, missing-result tests, arithmetic
operators, mode, the /100 constant, clamps, pool layout, link termination,
quantity saturation, the signed product cap, threshold equality, partial
quantity floor and final denominator. Corruptions must fail fact checks with the
outer digest/window checks bypassed. These are counts over the selected contract,
not component coverage or runtime equivalence.

Five Rust integration tests cover links/vacancy/invalid heads and tails, cycles,
zero quantity, signed prices, partial-level floor, exact thresholds, zero-price
division, saturation, the `2^63-2` cap, metadata-before-oracle ordering,
both-helper-before-zero ordering, override selection, and divide-before-clamp.
The fifth compares 10,000 deterministic fixtures against a separate Python
reference: 9,000 returned premiums and 1,000 absence paths. Two thousand fixtures
exercise successful high-u64 impacts and conversion rounding near or above
`2^53`, rather than testing only high-value rejection. The reference flattens
levels and uses arbitrary-precision rational arithmetic with explicit binary64
rounding after each operation. It is not native execution or emulation.

Reference negative controls differ in 2,373 cases for upward partial-fill
rounding, 6,211 for the wrong premium mode and 4,047 for omitting the /100 step.
Fixture SHA-256:
`ee82c4941faa43177d746c037eff88cffd1f0c4848c9085405f2590f5e501d6d`.

```sh
python3 research/work-items/RE-006-node115-funding-premium-source/verify.py
python3 research/work-items/RE-006-node115-funding-premium-source/reference.py
cargo +1.95.0 test --offline --locked --manifest-path src/node115-funding-premium/Cargo.toml
cargo +1.95.0 test --offline --release --locked --manifest-path src/node115-funding-premium/Cargo.toml
cargo +1.95.0 clippy --offline --locked --all-targets --manifest-path src/node115-funding-premium/Cargo.toml -- -D warnings
cargo +1.95.0 fmt --manifest-path src/node115-funding-premium/Cargo.toml -- --check
shasum -a 256 -c research/work-items/RE-006-node115-funding-premium-source/MANIFEST.sha256
make doctor verify catalogue-check reproduce
```

The verifier uses existing Python 3.14.7 and Capstone 5.0.7; Rust uses the installed
1.95.0 toolchain. No dependency downloads are needed. Full unfiltered `make test`
is excluded because its discovery includes captured instruction emulation; the
validation record lists the safe focused repository checks actually run.

Equivalence is limited to stable logical metadata/maps, native level visitation
order, valid terminating pool links, and continuation when diagnostic helpers
return. Diagnostics, logging, collection allocator failures, output padding and
ABI, scheduler behavior, funding settlement and live state mutation are outside
the contract. No target binary was executed/emulated, no live endpoint was used
for behavioral validation, and no inferred unlicensed source was copied.

Implementation, original artifact analysis and reference: OpenAI `gpt-6-astra` /
`codex-desktop`. GitHub/browser reads, independent review and publication:
OpenAI `gpt-6.1-terra` / `codex-desktop`. New source and documentation are MIT.
