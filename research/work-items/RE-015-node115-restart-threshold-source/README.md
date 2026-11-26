# Restart threshold selected-state source (node115)

`src/node115-restart-threshold` reconstructs the selected restart counter,
threshold and pending/resume behavior inside `2aeaef0`. It supplies an executable
Rust consumer of the established static contract in
[RE-015-restart-threshold-115](../RE-015-restart-threshold-115/README.md), introduced
by [PR #2128](https://github.com/lalalune/hyperliquid-source/pull/2128).
That packet owns the discovery and Python conditional model; this PR adds the
missing Rust state slice, normal-path message-release effects and tests of
resume behavior, with explicit opaque prerequisites. It does not claim the
old threshold arithmetic as a new discovery or duplicate the JSON parser.

The downstream use is startup/restart reconstruction: a consumer can carry the
counter state across pending polls without accidentally incrementing it or
rereading the threshold on every resume. The existing full lifecycle and
component gates remain open. Fresh current-main/source and open/closed PR
checks found the earlier packet and its historical duplicate, but no existing
Rust implementation of this selected slice.

Target: `artifacts/node/115/hl-node`, 105896032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All addresses below are image VAs. Evidence is static; no target execution or
emulation occurred. Synthetic Rust tests validate the source contract, not a
running node or the real configuration file.

## Entry, data, and exit boundaries

The native outer state byte is F+71. Its table at `6041ec` maps state3 to
`2aeb1cd`; that block dispatches nested byte F+120 through table `604294`.
Nested state3 enters `2aefee7`, polls `2a91280`, and on pending sets nested3,
outer3 and returns pending at `2af0229..023d`. It bypasses the updates below.
Nested state4 instead enters `2af016e`, directly at the later wait.

`Machine::receiving(Counters)` enters the selected nested3 slice. It takes
supplied F+b0 / F+b8 values rather than asserting a universal initializer.
One earlier conditional path is visible: after the mode check F+11c==1 at
`2aeb317`, the path reaching `2aeb42f..433` clears both counters together.
This observation is confined to that path; it does not prove every constructor
or lifetime. A caller can supply zero for that established path.

`Ports::poll_receive` supplies Pending or successful `ReadyInputs`, combining
opaque preparation outputs needed for this slice:

- `elapsed_for_comparison`: xmm1 **at `2aeffc2`**, after the native timestamp
  subtraction/normalization sequence. It is not raw wall-clock duration.
- `setting`: the successful parsed u64 before the threshold wrapper's zero
  clamp. Config retrieval, integer parsing and failure behavior are providers.
- `message_allocated`: whether the newly formatted message's capacity at
  F+138 is nonzero. Text/formatting/allocation semantics are not implemented.

Combining these supplied values is a host abstraction; it does not reproduce
interleaving or failure behavior of the native clock, formatter and config
calls. The ports must return normally without unwinding or mutating the
modeled counters through another path.

## Counter and threshold decisions

`2aeffc2` compares xmm1 with constant600.0 at `459568`. The unsigned-above
branch after `ucomisd` selects reset F+b0=0 only for an **ordered greater**
comparison. Equality takes the increment path. A conditional NaN input also
takes increment, but this does not prove a NaN can survive the actual elapsed
producer. All source tests involving nonfinite supplied inputs are explicitly
conditional branch tests.

The increment path at `2aeffcc..ffe1` saturates at u64::MAX: increment wraps
zero at MAX and `cmovne` retains MAX in that case. F+b8 independently uses the
same saturation at `2aeffe8..fffd` on every ready entry to this slice.

After successful message preparation, `2af010c` sets F+11e=1. The call through
slot `64e1200` is ELF-relocated to `1562300`. That wrapper obtains the setting
for `/hyperliquid_data/n_restarts_to_page.json`, calls parser `1501b80`, then
`cmp rax,1; adc rax,0` at `1562372` changes only zero to one. The Rust model
accepts the parser result and implements this clamp; it performs no file I/O.

At `2af0120..128`, an unsigned below branch retains the incremented F+b8 and
live-message flag. Equality **does** cross the threshold. At or above it:

1. Clear F+11e at `2af012a`.
2. If message capacity F+138 is nonzero, invoke release for pointer F+140.
3. Reset F+b8 to zero at `2af014c`.

`Ports::release_message` represents that selected effect, not an allocator
implementation. The API neither exposes nor duplicates raw native ownership.
Zero-capacity messages still have a live flag on the below-threshold branch,
but do not invoke a release effect.

## Pending/resume and the second cleanup point

A ready receive continues into `2a90a50` at `2af017d` within the same native
poll. `Machine::poll` likewise calls `poll_wait` in the same call after updating
the counters and handling any threshold release.

A pending later wait stores nested state4 at `2af022d..0234`. Subsequent polls
enter `2af016e`, skipping receive, elapsed/config work, counter increments,
message creation and threshold cleanup. The Rust Wait phase preserves those
values across arbitrarily many pending polls and never calls `poll_receive`.

On later-wait Ready, the native selected cleanup at `2af01d8..01fc` releases
the message only if both F+11e and capacity F+138 are nonzero, then clears the
flag. Thus a threshold-crossed message is not released twice. Further native
cleanup and the jump to `2aefb4c` are outside the model. `SlicePoll::NextLoop`
means **exit this selected slice**, not completion of the enclosing future or
process. Its terminal no-op behavior is a host convenience; enter a new slice
only with the next valid native preconditions supplied by a caller.

## Validation

The packet retains both complete FDEs (3886 instructions), 90 selected
witnesses, the threshold-wrapper relocation, both dispatch tables, the exact
600.0 bytes and config-path literal. Eighteen negative controls reject wrong
target/table/state byte, updates on receive-pending, equality reset at600,
wrapping counters, omitted zero clamp, strict-greater threshold, retained
flags/counters, free of empty message, re-increment on state4 resume, omitted
wait-pending, double release, missing final clear, or wrong resume state.
These are evidence-consistency controls, not target execution tests.

Six Rust tests cover:

- 65,536 small counter/setting pairs against an independently written widened
  u128 arithmetic oracle, plus full-u64 boundaries and zero/one thresholds.
- Both allocation states and exactly one eventual release when allocated.
- Exactly600, adjacent f64 values, saturation and conditional nonfinite inputs.
- Repeated receive-pending with unchanged state and no wait poll.
- Ready-to-wait in the same call, 100 state4 pending resumes, changed unused
  receive/config inputs, and release ordering on both threshold branches.
- Explicit selected-slice completion instead of a scheduler/outer-future claim.

```sh
PYTHONPATH=/path/to/capstone-5.0.7-and-pyelftools python3 research/work-items/RE-015-node115-restart-threshold-source/verify.py --target artifacts/node/115/hl-node
cargo test --manifest-path src/node115-restart-threshold/Cargo.toml
cargo test --release --manifest-path src/node115-restart-threshold/Cargo.toml
cargo clippy --manifest-path src/node115-restart-threshold/Cargo.toml --all-targets -- -D warnings
```

JSON grammar, configuration freshness/errors, actual elapsed-clock provenance,
backoff computation, timer scheduling, other nested states, message formatting,
release/unwind mechanics, all counter producers and the complete +11e lifetime
remain outside scope. This is a normal-return selected-state source contract,
not a reconstruction of the whole restart manager.
