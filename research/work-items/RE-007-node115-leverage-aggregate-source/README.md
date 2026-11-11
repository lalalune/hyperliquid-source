# Node 115 leverage aggregate source

Scoped progress for [#3916](https://github.com/lalalune/hyperliquid-source/issues/3916).
Main had no owned source for `0x44831a0..0x44834f3`. This contribution implements
that complete selected normal-return helper using actual user/asset maps,
integer arithmetic and state writes. It does not implement the broader position
transition or advance a component acceptance gate.

## Original evidence

Pinned `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The actual caller `0x4203847` binds the leverage update after its distinct size
notification. Four full FDEs cover the helper, user lookup `0x4717860`, user
bucket predicate `0x3ee6af0`, and asset lookup `0x3ed2d10`; a fifth window binds
the caller. `records.json` retains 1,665 bytes / 464 instructions, 469 semantic
facts and 36 corruption controls. The verifier authenticates the original ELF,
FDE ranges, instructions and relocation. Semantic controls bypass outer digest
and window checks. Static inspection is not native runtime equivalence.

## Logical state and arithmetic

`User` owns a map of asset rows plus the native aggregate at +0x48. A row carries
price (+0), two side values (+8/+0x10), two side quantities (+0x18/+0x20), signed
size (+0x28), and u32 leverage (+0x30); its unsigned asset key is at native +0x40.
These conservative field names do not infer additional business meaning.

Missing user or asset and equal old/new leverage return without writes. For a
present changed row, let `base` be side value 0 if size is positive, otherwise
side value 1. Let `N` and `Q` be the opposite side's value and quantity. Let
`S = unsigned_abs(size)` and `P = S * price` using a wide integer.

- Start with selected value `base`. Keep it if `Q == 0`, `Q > N`, or
  `P > 2^63-2` (including a product that does not fit u64).
- Otherwise calculate `Q' = Q - saturating_u64(2*S)` and `N' = N - 2*P`.
  Either unsigned underflow keeps `base`.
- Calculate `C = floor(N/Q) * Q'`. If `C > 2^63-2` (including u64 overflow),
  keep `base`; otherwise select `max(base, min(N', C))`.

The old contribution is floor(selected / old leverage). Then the leverage field
is written. The new contribution is floor(selected / new leverage). Native code
computes the same selection before and after that field write; selection does
not read leverage, so the independent implementation shares the pure calculation.
The final aggregate is `sat_add(sat_sub(old aggregate, old contribution), new
contribution)`, with two distinct unsigned saturations, not a signed net delta.

Zero size follows the nonpositive side. `i64::MIN` magnitude is 2^63; twice that
magnitude saturates to u64::MAX on the selected diagnostic-return path. Zero
leverage can be a no-op if old equals new; otherwise old zero faults before the
write and new zero faults after the write, with aggregate unchanged.

## Validation

`tests/reference.py` independently evaluates the branch algebra with Python
arbitrary-precision integers, generating 12,000 cases: 9,817 normal returns,
1,110 old-zero and 1,073 new-zero local faults. Among changed present rows,
3,362 use a value above the base and 5,459 retain it. Fixture SHA-256:
`66e4360f29d2b8bd11b58abb8b698370b47ecfa99ffffb54b036fb1e1ef12ad4`.
Rust checks the complete row and aggregate, untouched unrelated assets, key
absence, and fault write order. Explicit tests cover directional selection,
zero size, aggregate underflow then credit, aggregate overflow, and both zero
leverage boundaries. Three tests pass in debug and release; fmt and clippy pass.

```sh
python3 src/node115-leverage-aggregate/tests/reference.py
cargo test --offline --locked --manifest-path src/node115-leverage-aggregate/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-leverage-aggregate/Cargo.toml
cargo fmt --check --manifest-path src/node115-leverage-aggregate/Cargo.toml
cargo clippy --offline --locked --all-targets --manifest-path src/node115-leverage-aggregate/Cargo.toml -- -D warnings
python3 research/work-items/RE-007-node115-leverage-aggregate-source/verify.py
make doctor verify catalogue-check reproduce
```

The verifier rejects all 36 semantic corruptions. Only the inspected safe Python
repository tests are used; the unfiltered suite includes captured-code emulation.
No target instructions were executed or emulated.

## Overlap and boundaries

Current main source/README inspection, all-state exact-address and semantic PR
searches, and all 54 open PR paths found no matching owned leverage aggregate
implementation. This does not imply individual inspection of every closed patch.
The existing quantity-change source and [#2880](https://github.com/lalalune/hyperliquid-source/pull/2880)
/ [#2204](https://github.com/lalalune/hyperliquid-source/pull/2204) cover the distinct
`0x4206f70` size bookkeeping hook, which is not duplicated here.

Premises are valid logical keyed maps and normally returning diagnostics. Native
hash seeds/probing/storage ABI, malformed internal indices, diagnostic effects,
allocator behavior, and division-fault/panic ABI are excluded. `Fault` is an
owned diagnostic for excluded divisor premises. Caller position insertion,
raw-value mutation, size notification and broader margin enforcement remain
outside this helper. This packet keeps broad acceptance gates unchanged.
