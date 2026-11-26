# Restart counter to first timer, node 115

`src/node115-restart-delay` lets the startup/restart consumer calculate the selected wait from the updated counter at `F+b0` and the cap at `F+a8`. The result distinguishes immediate completion, construction of a timer with a duration, and the native out-of-range branch. On the path initializing the cap to 30, counters 0 through 6 yield delays of 0, 1, 3, 7, 15, 29 and 29 seconds.

The [prior threshold packet](../RE-015-restart-threshold-115/README.md) records the power input, and [PR #7068](https://github.com/lalalune/hyperliquid-source/pull/7068) implements the counter and resume decisions. Its `poll_wait` port leaves the delay calculation open. This crate supplies the calculation and identifies the first timer constructor's arguments. It accepts the updated counter to avoid repeating that state machine. Downstream polling, clock availability and wakeup behavior remain open.

## Evidence chain

The input is node 115 `artifacts/node/115/hl-node`, 105896032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses are image VAs. All observations are static.

- `2aeb41e..2aeb43b` stores the initial cap 30 on one branch. `2af0004..2af002f` bounds the unsigned updated `F+b0` by `i32::MAX`, selects base 2.0 and calls through `64e7460 -> 63f0080`. The helper multiplies by squaring. For this base and exponent, binary64 represents every result through exponent 1023 exactly. Larger exponents produce positive infinity. This permits constructing the exact binary64 power directly.
- `2af002f..2af007e` selects the minimum of the power and cap, taking the power for an unordered cap. It adds the constant -1.0, shifts the result bits right by 52, and accepts only values below `0x7ff` in that unsigned comparison. This also rejects a set sign bit. The fallback is positive zero. The result goes to `F+130`.
- The first-wait path copies that result to `F+150`, initializes `F+1e0` to zero, and calls `2a90a50`. A numeric zero returns directly. Positive inputs enter the binary64 duration splitter. The exponent cutoffs are `0x3e0`, `0x3ff`, `0x433` and `0x43f`. Subsecond inputs and fractional seconds round to the nearest nanosecond, using the low quotient bit at an exact tie. A rounded billion nanoseconds carries into seconds. Integral values at or above 2^64 take the range-error path. The `(seconds, nanos)` pair is passed to the timer constructor through `64e13a0 -> 5cf2150` at `2a90c51`.
- A positive duration that rounds to zero still reaches the constructor. The source uses `Duration::try_from_secs_f64` for this selected valid-input conversion and exposes the earlier zero branch separately. It models the native range error as a typed outcome. Input provenance for alternate caps, elapsed-clock production and allocator/runtime effects are outside scope.

## Reproduction

```sh
python3 research/work-items/RE-015-node115-restart-delay-timer/verify.py --target artifacts/node/115/hl-node
cargo test --manifest-path src/node115-restart-delay/Cargo.toml
```

Use Capstone 5.0.7 and pyelftools for the first command. The verifier checks 295 instructions, both relocation targets, table/constant bytes and containing FDEs against the pinned artifact. Reused caller and timer context appears under `cited_only_not_claimed`. The tests check the cap-30 sequence, equality and overflow boundaries, NaN and signed caps, and the different results for immediate zero versus a rounded zero timer. A separate integer oracle checks 4,095 durations across even/odd half-nanosecond ties and whole-second boundaries. Fixtures are mathematical expectations. The native executable was never run or emulated.
