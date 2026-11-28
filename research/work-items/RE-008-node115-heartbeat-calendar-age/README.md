# Calendar inputs for the node #115 heartbeat classifier

The selected heartbeat row classifier now accepts the current time and a recorded
time through `heartbeat::classify_at`. This connects the existing clock producer
to the ratio/age decision in the dependency-free Rust component. Construct a
`HeartbeatTime` with `HeartbeatTime::from_datetime`, then pass `None` for a
missing row or a `TimedSample` with its numerator, denominator and recorded
time. The original `classify` API still accepts an already calculated age.

For a row recorded at second 59 with 1,500,000,000 nanoseconds, the elapsed time
at second 240 of the same day is 180.5 seconds under Chrono's representation
of a leap second. The age branch returns tag 1. Omitting the extra second gives
179.5 seconds and tag 3. Across midnight, 180 seconds returns tag 3 while
180 seconds plus one nanosecond returns tag 1.

## Evidence for the connection

The authenticated Linux #115 classifier occupies `[0x5a30130,0x5a305da)`.
The current-clock provider called at `0x5a71e54` resolves to `0x1629690`.
For a row that reaches the age branch, the caller copies the current tuple
and the row's tuple from offsets `+0x58` and `+0x60`. It sets RDI to the
current tuple and RSI to the recorded tuple. The call at `0x5a3047d`
resolves through GOT `0x64e0fc0` to `[0x162a290,0x162a42b)`.

The existing [vendor overflow census](../RE-002-node115-vendor-overflow-census/)
qualified the whole 411-byte helper against Chrono's
`NaiveDateTime::signed_duration_since` in both 0.4.38 and 0.4.41. The verifier
compares the 399 fixed source bytes and the recorded three four-byte
relocation fields, resolves the captured Gregorian prefix table, and checks
each of its 400 bytes. The caller converts whole seconds and the fractional
remainder separately, clamps negative elapsed time to positive zero and selects
the age branch on a strict comparison with 180. The public implementation
computes the date difference in days, adjusts for a leap-second operand by
time-of-day ordering and adds the nanosecond difference. See the
[Chrono datetime implementation](https://github.com/chronotope/chrono/blob/v0.4.41/src/naive/datetime/mod.rs)
and [time implementation](https://github.com/chronotope/chrono/blob/v0.4.41/src/naive/time/mod.rs).

The classifier and its supplied-age reference cases come from [#4144](https://github.com/lalalune/hyperliquid-source/pull/4144).
Earlier work recovered the channel carrying times in [#2896](https://github.com/lalalune/hyperliquid-source/pull/2896),
the [calendar producer](../RE-012-time-producer-115/) and the
[standalone packed date difference](https://github.com/lalalune/hyperliquid-source/tree/c9b2eb38f4a929809686b855331a611a710b6a5f/research/work-items/RE-014-packed-date-difference-115).
This work tests their composition at the selected consumer.

## Replay

Use Python 3 and Rust 1.95.0. Materialize the pinned #115 artifact through the
repository's ordinary setup. The reference crate pins Chrono 0.4.41 and its
registry checksums. From the repository root, provision the reference build
inputs once, then run the evidence check offline.

```sh
packet=research/work-items/RE-008-node115-heartbeat-calendar-age
cargo +1.95.0 fetch --locked --manifest-path "$packet/reference/Cargo.toml"
python3 "$packet/verify.py"
```

`--static-only` requires only Python and the repository artifacts. The complete
replay runs independently built debug and release profiles on 12,334 generated
input rows. These cover a complete Gregorian leap cycle, extreme supported
years, both operand orders, same-day and cross-day leap operands, fractional
thresholds, and each selected ratio/configuration branch. The program calls the
component and the pinned Chrono reference on each input. A second comparison
reconstructs the signed nanosecond delta and checks reached age payload bits.
The replay verifies both frozen input/output hashes in [results.json](results.json).

| Changed operation | Rows with a different tag or payload |
| --- | ---: |
| Omit the leap adjustment | 4,448 |
| Drop the fractional seconds | 8,278 |
| Reverse the two times | 12,142 |
| Convert total nanoseconds to floating point before division | 252 |
| Use an inclusive 180-second threshold | 12 |

Inputs use canonical calendar values from the component's date range, including
the public leap-second representation on second 59 of a minute. The clock
producer itself returns a normal fraction; the wider calendar comparison tests
the helper's domain. Row timestamp authorship, map lookup, logging, exceptional
control flow and native data layout beyond the two observed inputs remain open.
The only code executed by the replay is the independently built Rust and the
public Chrono dependency.
