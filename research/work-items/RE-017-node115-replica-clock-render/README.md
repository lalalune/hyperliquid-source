# RE-017 · Render the decoded #115 Block clock in the native archive format

The [decoded replay header projection](https://github.com/lalalune/hyperliquid-source/pull/7370) carries the clock words to the normal replica header. The [replica line writer](https://github.com/lalalune/hyperliquid-source/pull/7535) takes already rendered clock text. This packet connects those stages using the existing checkpoint clock formatter.

The decoded packed date and second-of-day words occupy eight contiguous bytes. Nanoseconds follow them as a dword. The normal converter copies the three unchanged words from owner `+0x120..+0x12b` to the Block clock at `+0x38..+0x43`. The replica JSON writer passes that clock to a date display, writes literal `T`, and then advances by four bytes to the time display. The existing [checkpoint string trace](../RE-009-node115-context-clock-string-writer/README.md) uses the same two relative formatter slots, separator and offset. It can therefore supply the replica clock spelling without a second date/time implementation.

`DecodedPrefix::render_replica_time` reuses the existing Rust clock renderer. It returns text for a renderable decoded Block and leaves the ordinary conversion decision to the caller. The decoded wire fixtures check zero, millisecond, microsecond and nanosecond precision, a negative Unix second, and a leap second. Another fixture distinguishes the opaque Tx alternative. The result is archive clock text and does not describe the clock retained by post-begin state when a later stored timestamp wins.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source base `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

```sh
python3 -B research/work-items/RE-017-node115-replica-clock-render/verify.py
cargo test --locked --offline --manifest-path src/node115-replay-completed-payload/Cargo.toml
```

The [raw offline run](offline-log.txt) records the captured-byte checks and tests.
