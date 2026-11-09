# Node 115 per-user funding settlement source

Scoped contribution toward [#3913](https://github.com/lalalune/hyperliquid-source/issues/3913).
Independent Rust implements the selected normal-return contract of
`0x4205370..0x4205dde` using actual owned maps, oracle vector, mutable balances,
funding accumulators and output records. Before this contribution main had no
owned implementation of this helper. This does not close the broad issue or
change any component acceptance gate.

## Target and discovery

Original `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The serial user mapper binds positions, cross balance at user +0x48, the 20-byte
user address at +0x80, timestamp, oracle vector and rate map before the direct
call at `0x391419a`. The caller is evidence of invocation, not an implementation
of its outer collection or postprocessing.

`records.json` includes four complete FDE windows: the helper, position iterator
`0x45050e0`, rate lookup `0x4551d60`, and serial caller `0x3914040`.
They contain 4,527 bytes / 1,022 instructions, 727 checked semantic facts and 39
negative controls. Native branches, record offsets and floating constants are
verified against the original ELF. Control mutations are checked with outer
hash/window checks bypassed, so rejection must come from semantic evidence.
Static verification is not a claim of native runtime equivalence.

## Recovered behavior

1. Walk positions in ascending unsigned asset-key order. Look up rates by the
   complete key; missing rates and both signed zeros skip the position. NaNs
   proceed. The oracle index is `asset % 10_000`.
2. Check oracle index **before** testing zero size. For nonzero size, price must
   fit nonnegative `i64`, and price times signed size must fit `i64` (including
   the negative endpoint). These validations also run when timestamp is absent.
   Without a timestamp there are no state writes or records.
3. With a timestamp, convert signed notional to binary64 and multiply by rate.
   A nonfinite product becomes zero. Finite products clamp to [-2^63, 2^63],
   then truncate with signed saturation. Constants at `0x459808`, `0x459360`
   and `0x458e50` bind the interval and positive overflow threshold. Rust's
   saturating float-to-i64 cast yields the same finite result.
4. Payment is saturating negation of that converted amount; charge is negative
   payment. Payment cannot be `i64::MIN`. Subtract charge with signed saturation
   from cross balance for raw margin byte zero, otherwise from isolated balance.
   Add charge with signed saturation into all three funding accumulators.
5. Append asset, payment, original signed size, unchanged rate bits, signed
   notional, user address and unchanged three-word timestamp. Zero payments
   from NaN/infinite rates still produce records when the preceding gates pass.
6. Empty records return zero total and absent largest. Otherwise reduce payments
   in record order with signed saturation at every step; this is not a wide sum
   followed by one clamp. Select greatest unsigned absolute notional, retaining
   the first record on a tie. `i64::MIN` has absolute notional 2^63.

`Timestamp` carries native words, with a nonzero date word for presence. This
helper never validates or constructs calendar values. Native Vec/hybrid-map
memory layouts are replaced by Rust-owned collections, not reproduced as ABI.

## Validation

The source is independent of captured instructions. `tests/reference.py` uses
Python arbitrary-precision integers for notional bounds, signed saturation and
sequential state updates, and binary64 for the two floating operations. It
creates 7,000 deterministic cases: 3,218 normal returns, 3,283 oracle-index faults,
499 notional-range faults and 3,745 returned records. The fixture SHA-256 is
`e8c7300d1ae468014107929c7f11bab62e1727b2e7e50995222c0359cd9195d3`.
Rust compares complete mutated position state, cross balance, all record fields
(including rate bits), totals, largest selection and fault categories. Explicit
checks cover minimum signed notional, stable ties, sequential saturation and
index-before-zero ordering with absent time.

```sh
python3 src/node115-funding-settlement-user/tests/reference.py
cargo test --offline --locked --manifest-path src/node115-funding-settlement-user/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-funding-settlement-user/Cargo.toml
cargo fmt --check --manifest-path src/node115-funding-settlement-user/Cargo.toml
cargo clippy --offline --locked --all-targets --manifest-path src/node115-funding-settlement-user/Cargo.toml -- -D warnings
python3 research/work-items/RE-006-node115-funding-user-source/verify.py
make doctor verify catalogue-check reproduce
```

All four focused tests pass in debug/release. The verifier rejects all 39
semantic corruptions. Use the already inspected safe Python repository tests;
do not run the unfiltered suite that discovers captured-instruction emulation.
Neither the original target nor captured code was executed or emulated.

## Overlap and limits

All-state exact-address and semantic PR searches, current main source/README
inspection, and the changed paths of all 54 open PRs found no matching owned
per-user settlement. These checks cover metadata and relevant artifacts, not
individual inspection of every historical patch. Premium [#4373](https://github.com/lalalune/hyperliquid-source/pull/4373)
and rate [#4378](https://github.com/lalalune/hyperliquid-source/pull/4378) are distinct
inputs to settlement and are not reimplemented here. Node 94 is a separate
binary and is not used to infer this contract.

Premises: valid unique-key ordered native logical maps, successful allocation,
ordinary binary64 rounding, and diagnostic callbacks returning normally.
`OracleIndex`/`NotionalRange` are owned diagnostics for native panic premises,
not native return tags or panic/unwind equivalence. Earlier position mutations
remain visible on a later local fault; there is no rollback claim. Allocation
failure, diagnostics, outer parallel collection, cross-user redistribution,
persistence, event delivery and live network behavior are excluded.
