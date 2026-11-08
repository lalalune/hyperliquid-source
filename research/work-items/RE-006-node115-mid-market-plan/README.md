# Node 115 selected midpoint-market order plan

This scoped work advances #3915 with independently authored `no_std` Rust for
the typed plan produced by the selected successful midpoint-market builders.
The issue remains open; no component completion gate changes. The plan takes
the best pair, market metadata and timestamp as inputs. It does not perform book
lookup, mutation or insertion, and does not expose the native record ABI.

Target: node #115 ELF, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

Merged #3417 (`RE-014-mid-market-order-builder-115`) previously mapped the six
builders, tick helper and selected record fields. This contribution credits
that packet and provides a typed offline composition of the arithmetic and
active record values; it does not claim discovery of those native bodies.

The selected narrow and wide owners begin at `0x58f4c70` and `0x58f5450`.
They check the asset's market index before calling the supplied book lookup;
either zero price gives no plan. The midpoint is computed without overflowing
the two input u64 values. Side byte zero selects the first multiplier, and any
nonzero byte selects the second: 1.03/0.97 for narrow, 1.2/0.8 for wide.
After binary64 multiplication and the selected round helper `0x63efe40`, the
integer is saturated, then the `0x5a01110` tick helper applies the metadata
limits. Nonzero side increments the quotient even for an exact tick multiple;
the final multiplication saturates and the limit is at least one. The typed
result preserves the selected size, asset, user and side fields and family
kind/source values (6/1 narrow, 1/4 wide).

The timestamp projection uses the selected owner's Gregorian day calculation
and converts to milliseconds, clamping pre-epoch results to zero. The API
accepts checked Gregorian date/time inputs and reports `InvalidTime` locally;
that error is an owned API decision, not a claim that native validates raw
date bits. Likewise, reported metadata errors stand for the observed guard
boundaries, not a reconstruction of native panic or error object formatting.
The `u64` midpoint and positive finite family factors guarantee a finite
nonnegative floating-point input to the local rounding projection.

`records.json` retains four complete FDE windows (2,632 bytes, 568 decoded
instructions). The verifier checks the authenticated target, instruction
partition and selected field, arithmetic, helper and literal facts, together
with in-memory semantic corruption controls. These observations are bounded
to selected normal paths and do not establish whole order-book semantics.
The exact Fraction-based reference independently models each binary64 rounding
step, then integer tick arithmetic; the calendar reference uses Python
`datetime`. Neither is a native execution oracle. Native allocator behavior,
concurrent state, best-pair retrieval, insertion and unwinding are excluded.

```sh
python3 research/work-items/RE-006-node115-mid-market-plan/verify.py
python3 research/work-items/RE-006-node115-mid-market-plan/reference.py
python3 research/work-items/RE-006-node115-mid-market-plan/date-reference.py
cargo +1.95.0 test --offline --locked --manifest-path src/node115-mid-market-plan/Cargo.toml
cargo +1.95.0 test --offline --release --locked --manifest-path src/node115-mid-market-plan/Cargo.toml
cargo +1.95.0 clippy --offline --locked --all-targets --manifest-path src/node115-mid-market-plan/Cargo.toml -- -D warnings
cargo +1.95.0 fmt --manifest-path src/node115-mid-market-plan/Cargo.toml -- --check
shasum -a 256 -c research/work-items/RE-006-node115-mid-market-plan/MANIFEST.sha256
make doctor verify catalogue-check reproduce
```

The verifier uses an existing Capstone 5.0.7/Python 3.14.7 installation and
the already installed Rust 1.95.0 toolchain. Full unfiltered `make test` is
excluded because test discovery includes captured-instruction emulation. No
captured target was executed or emulated.

Implementation and GitHub work: OpenAI `gpt-6.1-terra` / `codex-desktop`.
Independent static native review: OpenAI `gpt-6-astra` / `codex-desktop`.
