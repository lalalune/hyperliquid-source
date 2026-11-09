# Node115 fee-trial action

Independent owned Rust source for the fee-trial state action at `0x3c18390`, bounded to the actual short decimal parser described below. This advances the fee area of issue #3913; it does not implement the issue's maker/taker window-to-ledger path or close the fee tracker.

The source accepts actual user keys, strings, ordered template/discount rows and affiliate keys. It performs user lookup/default selection, the active/disabled gate, template admission, 90-day cooldown, 14-day end-date calculation, discount selection and per-lane benefit/minimum calculation. On success it replaces the custom trial for affiliates in supplied order and then the caller. It retains each user's last-trial date. Duplicate affiliate keys and caller aliases are supported. The two special all-`ff`/all-`fe` addresses use the native zero baseline and zero tail.

`fees` is in converter output order: native input offsets `+0x18,+0x00,+0x48,+0x30`. The real selected parser accepts at most 17 UTF-8 bytes, an optional sign, at least one ASCII digit before an optional decimal point, and optional digits after it. Its integer coefficient, decimal-to-binary64 quotient/remainder, scaling and rounding path is reconstructed; it does not delegate to Rust's general float parser. Other native forms (leading dot, underscores, exponent, longer strings, fallback) return explicit owned `UnsupportedString`. A reached string of more than 100 bytes produces native status `0x158`. Early active/disabled rejection precedes parsing.

Dates are valid CE-day projections using the existing `node115-daycount-date` source, not caller-supplied calendar results. Native date overflow panics are represented by `DateOverflow` before mutation. The template fallback requires a matching primary pair before comparing the secondary row's second value with both other requested lanes. Discount rows retain native iteration order; the source does not sort them. A raw disabled byte is retained in the status formula, including values other than one.

The owned maps retain only fields observed or modified by this action. Physical collection representation, allocation failures, outer authentication, action decoding, native error payload ABI and live behavior are excluded. Broader native parser branches remain unsupported. This is not full-component coverage or a native-runtime equivalence claim.

Validation: six tests pass in debug and release, including 16,000 independent Python Decimal/integer decimal bit-pattern cases and 4,500 independent state cases. Explicit tests cover admission ordering, secondary-tier prefix requirements, cooldown equality, overflow before benefit checking, special accounts and affiliate aliases. No captured code is run or emulated.

```sh
python3 src/node115-fee-trial/tests/reference.py
cargo test --offline --manifest-path src/node115-fee-trial/Cargo.toml
cargo test --release --offline --manifest-path src/node115-fee-trial/Cargo.toml
cargo clippy --offline --manifest-path src/node115-fee-trial/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path src/node115-fee-trial/Cargo.toml -- --check
python3 research/work-items/RE-008-node115-fee-trial-source/verify.py
```

Static verifier requires Capstone 5.0.7 and the pinned original artifact. Evidence and native dataflow are in `research/work-items/RE-008-node115-fee-trial-source`. Prior #2231 established static fee-trial evidence; #286 concerns node94 and is not treated as node115 source.
