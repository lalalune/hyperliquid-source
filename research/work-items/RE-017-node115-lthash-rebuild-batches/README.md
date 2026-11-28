# RE-017 #115 EVM LtHash rebuild batch records

[The EVM constructor block fixture](https://github.com/lalalune/hyperliquid-source/pull/7480) consumes three native records from the cache-hit path. This patch implements the corresponding cache-miss accumulation after the scan helpers have already produced their batch summaries. Each lane starts with a zero record, accumulates full and optional final summaries, and yields the same `0x810`-byte record type for assembly.

The [native checkpoint hash analysis](../RE-011-evm-db-checkpoint-hashes-115/README.md) maps the three scans. The absent-option initializers at `0x3c27fc6`, `0x3c28586` and `0x3c282a6` each zero a complete record before dispatching to the scan. All six selected full and tail accumulation arms add the two qwords at `+0x800/+0x808` with unsigned saturation. Their vector loop byte-swaps both inputs, uses packed 16-bit wrapping addition, and byte-swaps the result across 1,024 lanes. The empty-tail branches bypass the second fold and copy the existing accumulator to the destination.

`LtHash::from_rebuild_batches` reuses the existing lane arithmetic on independently supplied fixed-width summaries. `LtHash::to_record_bytes` emits the payload bytes in native order followed by both little-endian counters. Empty input returns the zero record. The focused tests exercise wrap in every lane, independent saturation, the exact record bytes and the full-plus-tail grouping.

```sh
python3 -B research/work-items/RE-017-node115-lthash-rebuild-batches/verify.py
cargo test --offline --locked --manifest-path src/node115-abci/Cargo.toml
```

The offline log includes the Rust suite and a composition that passes synthetic fold results through #7480, the compact assembler, and the independent lane comparator. Raw database iteration, value encodings, batch summary production, real checkpoint provenance, and root parity remain open. No captured instructions are executed.
