# Node 115 set-referrer core source

Scoped progress for [#3912](https://github.com/lalalune/hyperliquid-source/issues/3912).
The earlier [#2189](https://github.com/lalalune/hyperliquid-source/pull/2189)
packet mapped decoder/state boundaries but did not implement this core in
independent Rust. This contribution implements the selected logical state
contract of `0x3c17590..0x3c17fb9` with actual keyed lookup, quota mutation,
history writes and user assignment. Broad acceptance gates remain unchanged.

## Original evidence

Pinned `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Nine complete FDEs cover the core, exact string code lookup `0x455c290`, referrer
lookup `0x4556550`, history lookup `0x455a260`, history insertion `0x3705790`,
user entry `0x4717c50`, user bucket equality `0x3ee6280`, daycount/calendar
conversion `0x1628f50`, and selected local cleanup `0x3d08df0`.
The packet retains 6,218 bytes / 1,531 instructions, 1,139 semantic facts and 39
corruption controls. Date tables, imported bytewise comparison and the cleanup
jump-table target are bound to the original ELF. The local `0xa5` cleanup at
`0x3c17ae6` resolves through table word `0x7b8b78` to the direct-return arm
`0x3d08faa`; it supplies no omitted business result.

The verifier checks original digest, FDEs, instructions and static data.
Corruption controls bypass outer digest/window checks and must fail semantic
validation. Static evidence is not a native runtime-equivalence claim.

## Recovered ordered behavior

1. Look up the exact case-sensitive code string. Missing code returns `0xa6`
   without creating a user. The stored 20-byte referrer equal to the user returns
   `0xa2`, also before user creation.
2. Resolve/create the actual user. The native default referral flag is zero.
   Any existing referral returns `0xa3` before quota or referrer-record checks.
3. Look up the referrer's record. If absent, return `0x1a2` with the resolved
   user left unassigned. In particular a new user entry already exists by then.
4. A zero configured period returns `0xa5`. Otherwise convert the canonical
   timestamp to Unix milliseconds, clamping negative results to zero, and divide
   by period. Compare the resulting bucket with the record's stored bucket.
5. Equal bucket and zero remaining quota returns `0xa5`. Any different bucket
   (including moving backward) stores the new bucket and refreshes remaining
   quota to `max(configured_quota, 1000)`. Decrement the selected remaining quota
   once before writing history.
6. Insert or replace this user's history timestamp, then set the user's referrer
   and return `0x1a2`. Existing history does not avoid the quota debit.

`Moment` stores CE days, seconds and nanoseconds, validated through existing
`node115-daycount-date` and canonical non-leap-second bounds. The native inline
Gregorian arithmetic produces the same CE day, so Unix milliseconds can be
calculated directly from the owned day count. The record/history maps and user
referral flag are logical projections; unrelated native user/referrer fields are
excluded rather than synthesized.

## Validation

`tests/reference.py` independently compares proleptic Gregorian CE-day algebra
with the recovered inline negative-year cycle arithmetic, then evaluates the
state transitions. It generates 8,000 deterministic cases over years -262143
through 262142, century/leap boundaries, pre-epoch values, nanosecond truncation,
zero/large periods, missing maps, all gates and quota boundaries.
Outcomes: 4,110 accepted (3,442 actual assignments), 1,236 already-set,
1,132 quota failures, 823 missing-code and 699 self-referral. Fixture SHA-256:
`08493f13f2e3f25f6d23739ae99eacdd11002aea0aa077d1d823ac9aba523b41`.
Rust compares status and entire state, including untouched unrelated entries,
remaining quota, bucket, history and referral assignment. Explicit tests cover
case sensitivity, missing-referrer success without assignment, user creation
before quota failure, old-history replacement, and zero-clamped pre-epoch time.

```sh
python3 src/node115-set-referrer/tests/reference.py
cargo test --offline --locked --manifest-path src/node115-set-referrer/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-set-referrer/Cargo.toml
cargo fmt --check --manifest-path src/node115-set-referrer/Cargo.toml
cargo clippy --offline --locked --all-targets --manifest-path src/node115-set-referrer/Cargo.toml -- -D warnings
python3 research/work-items/RE-010-node115-set-referrer-source/verify.py
make doctor verify catalogue-check reproduce
```

All four tests pass in debug/release; formatting and clippy pass. All 39 semantic
corruptions are rejected. Only inspected safe Python repository tests are used,
excluding the unfiltered suite's captured-instruction emulation. No target
execution/emulation or live exchange operation was performed.

## Overlap and limits

All-state set-referrer PR metadata searches, current source inspection, and all
57 open PR titles/paths found no matching independent source. Prior #2189 is
credited above; [#372](https://github.com/lalalune/hyperliquid-source/pull/372)
concerns node94, a separate release. These checks do not individually read every
closed historical patch.

Premises: valid logical maps, canonical non-leap-second dates and successful
allocation. Physical hybrid-map/hash/probe ABI, malformed timestamps, allocator
failure and unwinding are excluded. Outer decoder, code normalization, action
authorization, live state and downstream exchange effects remain outside scope.
This is complete selected core behavior, not the full referral subsystem.
