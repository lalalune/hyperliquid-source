# Node 115 scheduled-cancel admission and timer state

This independently authored Rust contribution advances issue #3912 with the
selected scheduled-cancel request core, due-entry collection and counter reset.
It operates on actual owned user-volume and schedule maps. Due users are returned
as a key set at the cancellation handoff; no order cancellation is claimed.
The issue remains open and component completion gates remain false.

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `0781ce04826eeefd89fe336cb8ea073be0c1de30`. Addresses are ELF virtual
addresses; all ends are exclusive.

## Prior work and API boundary

Merged #2138 (`RE-010-schedule-cancel-core-115`) mapped the request/expiry logic;
#2194 mapped the enclosing loader/root. This contribution credits that work and
adds independently authored Rust that owns the relevant map mutations. Merged
#4128 covers the separate optional-time wrapper at `0x55052a0`. Its bounds are
not substituted for the selected core `0x2c2cb40..0x2c2cf4a` here.

`Volumes` holds a vector of logical per-DEX user maps plus the spot user map.
Each 20-byte address maps to two u64 lanes. `Tracker` holds unique user keys and
`Entry { fired_count, deadline }`. Real lookups and writes are performed; no
callback supplies aggregate volume, an admission decision or a state result.
These are typed projections of valid native collections, not replacements for
the native IndexMap/hybrid deque/tree memory layouts or their allocator paths.

`Moment` accepts canonical non-leap-second date/time values. It uses the existing
`node115-daycount-date` dependency to validate the target calendar's CE day-count
domain. Unix milliseconds are converted by integer division/remainder, including
millisecond-to-nanosecond scaling. Out-of-range dates return an owned error
category with native tag `0x89`; native error formatting/allocation is excluded.
The dependency is pinned in the evidence manifest. Its source is reused rather
than claiming another standalone day-count contribution.

## Native operation

The request core calls `0x2a8ae60..0x2a8b095`. That function walks the actual
perpetual DEX vector (stride `0x510`), looks up the user via `0x4716be0`, and
accumulates payload fields `+0x50/+0x58`. It then looks up the spot user through
`0x4716cc0` and adds `+0x40/+0x48`. Both lanes saturate independently at u64 max.
Absent records use zero fields proved by default initializers `0x44e9f40` and
`0x3d25c00`. The owned source performs both lanes even though admission consumes
only the first. Native saturation diagnostics are excluded; their callbacks
are assumed to return normally.

Every request first requires the first aggregate lane to be at least
`100_000_000`. Failure is tag `0x11d` with binary64 payload `aggregate / 100.0`.
The `/100` divisor is the actual literal at `0x459498`; it is not inferred from
a public notional unit. This guard runs even for a request to clear a schedule.

For an absent requested timestamp, an existing deadline is cleared while its
counter is retained. A missing schedule record is not inserted. This returns
`0x1a2` and does not consume a trigger count. For a present timestamp, conversion
happens before the deadline/counter checks. The deadline must be **strictly later
than now plus five seconds**. Addition uses time helper `0x162a9a0` and checked
date helper `0x16290d0`; overflow falls back to the maximum representable date,
23:59:59.999999999, whose 12-byte constant is retained at `0x4679d0`.
Equality or an earlier deadline returns `0x11b`.

Only after those guards does the core resolve/insert the keyed schedule entry
(`0x2db4460 -> 0x2422570`). A new entry has counter zero and absent date. Existing
counter greater than 9 returns `0x11c`; otherwise the new deadline replaces the
old one and returns `0x1a2`. Setting, replacing and clearing do not increment the
counter. Raw internal malformed option discriminants are outside the typed API.

The selected driver block `0x2be22c0..0x2be239d` visits schedules, skips absent or
future deadlines, collects each due key, saturates its counter increment and
clears its deadline. Due includes equality in date, seconds and nanoseconds.
`collect_due` performs these writes and returns a **set projection** of the keys.
It does not claim native iterator/invocation order. The actual downstream call
at `0x2be2411 -> 0x2bf9910` cancels orders and is explicitly outside this source.
A returned key is a pending handoff, not proof that cancellation succeeded.

The driver later compares its stored date marker with the current date and calls
`0x2dceaf0..0x2dcf026` on date advance. That helper, including deque branch
`0x24c0ee0..0x24c109c`, zeros counters, removes entries without a deadline and
retains active schedules. `reset_counts` implements that logical operation.
It is explicit rather than automatically folded into collection: the native
cancellation handoffs occur between collection and reset. Date-marker updates,
other driver work and any handoff effects are not invented by this API.

## Evidence and validation

`records.json` retains 12 complete helper/core FDEs and three selected driver
windows: 6,188 bytes and 1,463 decoded instructions. The verifier authenticates
the original digest, enclosing FDEs and instruction starts, retained rows,
790 selected facts and 43 corruption controls. These cover volume lanes and
saturation, thresholds, exact five-second rejection, default insertion, counter
and deadline writes, due comparison and saturation, reset/retain behavior,
calendar tables, actual helper relocations and default initializers. Controls
must fail selected fact checks with image/window hash checks bypassed. Retaining
a full FDE does not claim implementation of its excluded physical-container,
leap-second, panic, diagnostic or allocation paths.

Five Rust integration tests pass in debug and release. They check guard priority,
clear-without-insert, independent volume lanes and unrelated keys, exact lead-time
boundaries, trigger cap, saturation, repeated expiry, explicit reset, Gregorian
year crossing, fractional nanoseconds and maximum-date fallback.
A separate arbitrary-precision Python timer/state model generates 14,000 cases:
1,957 accepted, 7,507 insufficient-volume, 2,697 too-soon, 395 trigger-cap and
1,444 timestamp-range outcomes. Every case checks both aggregate lanes, result
and report bits, state after admission, due membership and state after collection
and optional reset. It is a synthetic reference, not native execution.
Allowing exact deadline equality differs in 180 cases; bypassing volume on clear
in 830; retaining inactive entries on reset in 3,071.
Fixture SHA-256:
`225bc511bd80225bd716fd18a1d37559667cab34f7c9995a8180c395eb5e317d`.

```sh
python3 research/work-items/RE-010-node115-schedule-cancel-source/verify.py
python3 research/work-items/RE-010-node115-schedule-cancel-source/reference.py
cargo +1.95.0 test --offline --locked --manifest-path src/node115-schedule-cancel/Cargo.toml
cargo +1.95.0 test --offline --release --locked --manifest-path src/node115-schedule-cancel/Cargo.toml
cargo +1.95.0 clippy --offline --locked --all-targets --manifest-path src/node115-schedule-cancel/Cargo.toml -- -D warnings
cargo +1.95.0 fmt --manifest-path src/node115-schedule-cancel/Cargo.toml -- --check
shasum -a 256 -c research/work-items/RE-010-node115-schedule-cancel-source/MANIFEST.sha256
make doctor verify catalogue-check reproduce
```

The validation record lists the exact checks run using existing Python 3.14.7,
Capstone 5.0.7 and Rust 1.95.0. Full unfiltered `make test` is excluded because
its discovery includes captured-instruction emulation. No captured target was
executed or emulated; no live endpoint, signing or chain action was used for
behavioral validation. Successful allocations and stable valid maps are premises.

Implementation, original-artifact analysis and reference: OpenAI `gpt-6-astra` /
`codex-desktop`. GitHub/browser reads, independent review and publication:
OpenAI `gpt-6.1-terra` / `codex-desktop`. New source and documentation are MIT.
