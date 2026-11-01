# Node #94 margin and risk component

This directory contains an independently authored, offline Rust library for
the bounded margin path established for Linux x86-64 node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
It does not execute the captured node or use the unlicensed reference tree as
implementation source.

The crate is standalone, dependency-free, and deliberately absent from a root
Cargo workspace because the repository does not yet have a recovered workspace
contract. The API uses raw integer units: the evidence establishes widths and
operations inside this path, but not the external decimal exponents.

## Public contract

`MarginTable::try_from(RawMarginTable)` preserves the observed constructor
order. It admits a UTF-8 description of at most 250 bytes and one through three
tiers. The first lower bound must be zero. Every lower bound is below
`0x0ccccccccccccccc`; later lower bounds are also at most
`1_000_000_000_000_000`. Leverage is at most 50, strictly decreases, and lower
bounds strictly increase. The constructor retains the target's exact
prevalidation order, including checking the next lower bound before comparing
the current lower bound with its predecessor.

For a tier boundary `B`, current leverage `Lc`, previous leverage `Lp`, and
accumulated prior contribution `P`, the stored value is:

```text
P = P.saturating_add(B / (2 * Lc))
     .saturating_sub(B / (2 * Lp))
```

A single tier with zero leverage is admitted, as in the target. Any later
calculation that reaches its divisor returns a typed fault; the library does
not silently choose a value or panic.

Tier selection uses the last lower bound less than or equal to unsigned
notional. The two requirement functions preserve target u64 operation order:

```text
initial = floor(notional / (2 * leverage))
          .saturating_sub(prior_contribution)

maintenance_numerator = notional.saturating_mul(2).saturating_sub(
    prior_contribution.saturating_mul(4 * leverage)
)
maintenance = floor(maintenance_numerator / (6 * leverage))
```

`calculate_position_margin` implements the five verified raw modes:

| Mode | Requirement |
| ---: | --- |
| 0 | zero |
| 1 | absolute notional divided by the position's u32 divisor |
| 2 | tiered initial requirement |
| 3 | tiered maintenance requirement |
| 4 | absolute notional divided by `min(position divisor, u8 cap)` |

The function rejects negative signed-i64 prices, checks signed-i64
`size * price`, and converts the result to unsigned magnitude. Consequently,
`i64::MIN` has magnitude `2^63`. For modes 2 and 3, selectors below 50 form the
observed single tier; selectors at least 50 require a caller-supplied,
already-resolved custom table. The surrounding lookup map is not invented.

The record's raw accounting byte is represented by `AccountingMode`: zero is
cross and every nonzero value is isolated. Cross output retains signed
notional, requirement, and unsigned magnitude. Isolated output saturating-adds
signed notional to prior margin, clamps effective margin at zero, and retains
the prior margin and computed requirement.

Cross-account aggregation accepts explicit signed-equity and unsigned
maintenance contributions and saturates each raw field independently. The
caller's starting equity remains explicit because its account-state ownership
is outside this component. Isolated surplus uses the position result directly.
The requirement must fit the signed comparison path; surplus uses signed
saturating subtraction and eligibility is exactly `surplus < 0`. Zero surplus
is ineligible.

Candidate admission returns either `CandidateAdmission::Admitted` or an
explicit `Rejected` value. The admitted logical record retains the proved
scope, signed surplus, opaque 20-byte subject, and isolated-only context word.
Node #94 appends records at a 48-byte stride, but the Rust type is deliberately
not an ABI mirror or serializer: four padding bytes and the ownership of the
isolated context word remain unresolved.

### Qualified row selection after hashing

`row_selector::select_row_after_hash` accepts an externally supplied hash,
logical controls, 20-byte key slots, query and late observed state word. It
returns an owned bucket index or shared-default marker and the state's nonzero
predicate. It implements the bounded numeric relation from
`0x36f57f0..0x36f5948`; native hashing, row pointers and Once remain external.

For nonzero count, capacity `N` is a power of two of at least 16, native mask
is `N-1`, and native control byte `C+j` equals `controls[j & (N-1)]` through
the 15-byte mirrored prefix. The state argument is the word observed at native
`0x36f58df` or `0x36f5901`; an entry snapshot requires stability through that
late load. Synthetic fixed-hash cases establish a conditional posthash
relation and do not prove the query's native hash result.

The checked entry returns new `SelectorInputError` labels for control shape,
key coverage and exhaustion of one complete group cycle. These are chosen
safe-API policy, with no native fault/error claim. Count zero bypasses table
validation and element access. The evidence packet
`research/work-items/RE-007-row-selector-rust-94/` separates 894 qualified
posthash cases from seven policy cases and their mutation controls.

## Evidence map

The implementation is grounded in
`research/work-items/RE-007-margin-path-94/`, merged in PR #50. The retained
packet authenticates every admitted target range, instruction control, call
edge, source-location record, and arithmetic vector.

| Module | Established target range or record |
| --- | --- |
| `src/tiers.rs` | tier admission `0x3335590..0x3335c40` |
| `src/requirements.rs` | lookup `0x33331a0..0x3333276`, maintenance `0x3333670..0x33337f9`, initial `0x3333800..0x3333915` |
| `src/position.rs` | position margin by mode `0x3717480..0x37179c5` |
| `src/surplus.rs` | surplus `0x37d77e0..0x37d79e0` and the consumed aggregate pair from `0x37d79e0..0x37d7f0c` |
| `src/candidate.rs` | negative-only candidate branches and fixed record writes in `0x37d7360..0x37d77d8` |
| `src/row_selector.rs` | conditional posthash selection at `0x36f57f0..0x36f5948`, external hash and Once excluded |
| `tests/fixtures/*.tsv` | packet `boundaries.tsv` plus the five mode branches |
| `tests/boundary_contract.rs` | all 24 rows from the maintained packet `boundaries.tsv` |
| `tests/adversarial.rs`, `tests/negative_controls.rs` | bounded input mutations and formula/admission mutants |

The relevant RE-004 packets and `src/node94-fixed-point/` were reviewed for
type compatibility. This path needs checked signed price-size multiplication,
unsigned `i64::MIN` magnitude, and raw-width margin records not exposed by that
crate, so no artificial dependency was introduced.

## Validation

Run from the repository root with at most two build jobs and test threads:

```sh
CARGO_BUILD_JOBS=2 cargo +1.94.1 build --locked \
  --manifest-path src/node94-margin-risk/Cargo.toml
CARGO_BUILD_JOBS=2 cargo +1.94.1 build --release --locked \
  --manifest-path src/node94-margin-risk/Cargo.toml
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 cargo +1.94.1 test --locked \
  --manifest-path src/node94-margin-risk/Cargo.toml
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 cargo +1.94.1 test --release --locked \
  --manifest-path src/node94-margin-risk/Cargo.toml
CARGO_BUILD_JOBS=2 cargo +1.94.1 clippy --locked \
  --manifest-path src/node94-margin-risk/Cargo.toml --all-targets -- -D warnings
cargo +1.94.1 fmt --manifest-path src/node94-margin-risk/Cargo.toml -- --check
python3 -m unittest tests.test_margin_path_static -v
```

Authenticate the target and retained packet before interpreting these tests.
Repository-level verification remains `make verify`, `make test`,
`make catalogue-check`, and `make reproduce`; it must not overlap another
full-suite run.

## Deliberate limits

This component does not claim a complete risk engine, account aggregation,
custom-table storage lookup, oracle conversion, decimal scaling, serialization,
ABI or owned-layout equivalence, the meaning of the isolated context word,
candidate ordering, liquidation sizing, transfers, execution, persistence, or
live node behavior. The 48-byte candidate append and its bounded writes are
established, but unresolved padding and ownership prevent serialization.

Target panic and recorder paths are exposed as typed errors rather than
reproducing abort payloads. No socket, signing, production state, or networking
code is present. No completion gate is advanced by this bounded component.
