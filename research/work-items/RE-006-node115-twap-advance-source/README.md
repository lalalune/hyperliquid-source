# Node 115 logical TWAP advance and heap insertion

This independently authored typed source advances #3915 with the selected
post-slice TWAP transition. It maintains logical user/order maps and an ordered
queue, advances a valid due moment, catches it up at most once, and updates
the counter before deciding between a finish handoff and rescheduling. The
issue remains open; no component completion gate changes.

Target: node #115 ELF, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

Merged #4264 (`RE-006-twap-advance-115`) maps the advance owners and their
selected user/order and time paths. This work credits that packet and adds
typed source plus the previously delegated queue insertion ordering. Open
#4329 addresses the separate finish step; #4375 handles a different sizing
calculation. Neither is reproduced here.

For a missing user, the logical tracker creates an empty order map and then
returns a missing-order outcome. An existing order advances its due time by
30 seconds. Invalid date arithmetic selects the original maximum-date
fallback. If the new moment is strictly before `now`, the nonnegative gap is
converted to binary64, divided by 30, rounded up, multiplied by 30 and capped
at `i64::MAX` nanoseconds before a single further time addition. This cap can
leave the result before `now`; there is no catch-up loop. The counter is
incremented with saturation and both fields are stored before the finish
test. `filled >= total` or `counter > 2*saturate(duration/60)+1` chooses
finish. Otherwise the selected queue entry is inserted.

The queue helper `0x4ecb990` inserts and sifts 40-byte entries. Its order is
ascending signed packed date, unsigned seconds, unsigned nanos, 20-byte user
comparison and unsigned order ID. For the supported canonical date domain,
CE day count has the same order as the native packed date. The source uses a
typed min heap and the existing `node115-daycount-date` conversion; at the
stated base its `Cargo.toml` SHA-256 is
`e16a26dc33ee9a43a02e7465b656f141cf8e126ac0d2b9e35471809c0dfc16d8`
and `src/lib.rs` is
`1c886a59338eba55c204105527505e47f8e6247b7bc86e9e67b77be069567087`.

`Finish` is the observable state **at handoff**, before the separate native
finish function removes or updates anything. The crate does not implement
that callee, lookup/hash/tree ABI, ring-to-tree promotion, native allocation,
diagnostics or concurrency. Inputs and existing queue entries must be valid,
canonical non-leap-second moments, and logical keys must be unique. The owned
API rejects invalid moments; that is not a claim about invalid native inputs.
Floating arithmetic assumes default nontrapping binary64 round-to-nearest.

The authenticated packet retains the selected advance owner, queue helper,
user resolver and five time/date/ceil/duration helpers as eight complete FDEs
(4,388 bytes / 1,083 instructions), 66 selected facts and corruption controls.
The helper pins include nanosecond carry, day scaling, date-cycle arithmetic,
ceiling behavior and their actual relocation bindings. Counts do not imply full component
equivalence. Seven tests include 6,000 independent Python calendar/binary64
cases, queue tie breaks, missing-user insertion, maximum-date fallback, a
century-scale one-pass cap, and the saturated-counter finish boundary. The
reference uses Python `datetime` validation and binary64 ceiling; it is not a
native execution oracle. No captured instructions were executed or emulated.

```sh
python3 research/work-items/RE-006-node115-twap-advance-source/verify.py
python3 research/work-items/RE-006-node115-twap-advance-source/reference.py
cargo +1.95.0 test --offline --locked --manifest-path src/node115-twap-advance/Cargo.toml
cargo +1.95.0 test --offline --release --locked --manifest-path src/node115-twap-advance/Cargo.toml
cargo +1.95.0 clippy --offline --locked --all-targets --manifest-path src/node115-twap-advance/Cargo.toml -- -D warnings
cargo +1.95.0 fmt --manifest-path src/node115-twap-advance/Cargo.toml -- --check
shasum -a 256 -c research/work-items/RE-006-node115-twap-advance-source/MANIFEST.sha256
make doctor verify catalogue-check reproduce
```

Static verification uses installed Python 3.14.7 and Capstone 5.0.7; Rust uses
the installed 1.95.0 toolchain. Full unfiltered `make test` is excluded because
test discovery includes captured-instruction emulation.

Implementation and GitHub work: OpenAI `gpt-6.1-terra` / `codex-desktop`.
Independent native review: OpenAI `gpt-6-astra` / `codex-desktop`.
