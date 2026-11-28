# RE-017 · Decode the archive timestamp into the #115 replay clock

The replica timestamp string carries the three words consumed by replay begin-block. This packet adds an offline bridge from that string to the existing `AdmittedTimestamp` type, so a first-block fixture can supply a clock with the archive's original nanosecond precision.

Linux x86-64 #115 artifact SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `2da45cb0a761cff6b478e40421699857d87a94df`.

[Replica JSON schema](../RE-017-node115-replica-json-schema/README.md) locates `abci_block.time` at block `+0x38`. [Timing in the replay wrappers](../RE-017-node115-replay-block-clock/README.md) established the 12-byte ingress tuple and the selected state clock rotation. [Native timestamp admission](../RE-001-node115-client-block-timestamp-admission/README.md) established the packed-date constructor and independent second-of-day and nanosecond fields. This work joins those contracts through the actual replica text formatter.

| Archive clock component | Format source | Replay position |
| --- | --- | --- |
| Civil date | The quoted formatter callback calls the date formatter at `0x1628bc0`, which reads its first dword and extracts the signed year with `sar 13`. | Block `+0x38`; first dword, compared signed. |
| Civil hour, minute, second | The callback emits `T` and advances its input pointer by 4. The time formatter at `0x162a760` then reads its first dword. | Block `+0x3c`; second of day, compared unsigned. |
| Fraction | The time formatter reads the adjacent dword and tests against one billion. | Block `+0x40`; nanoseconds, compared unsigned. |

The compact and expanded wrappers load the same qword plus dword and pass them to their matching begin helpers. The two helpers' first `0x83` bytes are identical. A timestamp's fraction can advance the clock within the same second. The result of parsing the archive's text is the **incoming** block clock. The begin helper can retain a later stored clock, so that result alone does not establish the post-begin state clock.

[decode_replica_clock](../../../src/node115-client-block-success/src/replica_clock.rs) parses the zone-free ISO timestamp shown in the [Quicknode](https://www.quicknode.com/docs/hyperliquid/datasets/blocks) and [Dwellir](https://www.dwellir.com/docs/hyperliquid/data-catalog/node-feeds/blocks) archive examples. It computes integer civil seconds using Gregorian day lengths and scales the fractional decimal digits directly to nanoseconds. Reusing `admit_timestamp` supplies the previously bound CE-day helper, packing and range checks. A displayed second of 60 uses the existing leap-second representation with base second 59 and a nanosecond value at or above one billion. Values are checked structurally by the native admission model; the parser does not consult a leap-second date table. The archive examples supply format and calendar references, not pinned raw blocks.

## Reproduce

```sh
python3 -B research/work-items/RE-017-node115-replica-replay-clock/verify.py
cargo test --locked --offline --manifest-path src/node115-client-block-success/Cargo.toml
```

The Python verifier checks the selected native spans and relocation slots and independently verifies the test calendar coordinates. The Rust test compares the text projection with the already reconstructed native scalar conversion for negative-epoch, leap-day, nanosecond and leap-second examples. Zone suffixes, over-precise timestamps, invalid calendar entries and out-of-range dates exercise the explicit error cases. [offline-log.txt](offline-log.txt) records the actual runs. Verification reads the pinned ELF as data and executes only the independently authored Rust and Python.
