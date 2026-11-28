# RE-017 #115 native named LtHash checkpoint sidecar writer

The reconstructed ABCI library gains an explicit writer for the selected EVM checkpoint `lt_hashes.json` shape. [#7495](https://github.com/lalalune/hyperliquid-source/pull/7495) produces LtHash values from precomputed rebuild summaries. [#7337](https://github.com/lalalune/hyperliquid-source/pull/7337) reads the native named form into binary records but supplies no writer. The existing local ABCI bundle keeps its own hex representation for compatibility with its earlier snapshots.

The [#115 checkpoint hash evidence](../RE-011-evm-db-checkpoint-hashes-115/README.md) links the selected JSON route `0x422f030 → 0x38c2230` to the three outer fields `accounts_hash`, `contracts_hash`, `storage_hash` in that order. The inner serializer at `0x36c5cf0` emits `n_elements` and `n_bytes` from the two counters before `hash`. The selected array serializer at `0x4670ae0` reads exactly `0x800` payload bytes and emits their unsigned decimal representations. The Rust writer produces that data shape with deterministic compact formatting.

Use `LtHashes::write_native_checkpoint_sidecar` with a local output stream. The Rust regressions check the full 256-byte value range, ordering of all fields, u64 counter limits and propagation of a write failure. The existing pinned-native evidence suite checks the binary route and decimal-byte vectors. The offline composition passes an actual Rust-generated JSON file through the independent sidecar reader, EVM block builder, compact assembler and lane comparator.

```sh
python3 -B -m unittest tests.test_re011_evm_checkpoint115 -v
cargo test --offline --locked --manifest-path src/node115-abci/Cargo.toml
```

This verifies the native-compatible field shape. It does not assert exact full-document bytes from a native writer run, native persistence or real checkpoint/root parity. No captured instructions were executed.
